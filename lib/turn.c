/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2014, Guilherme Balena Versiani, <guibv@yahoo.com>.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_PROXY) \
    && !defined(CURL_DISABLE_TURN) \
    && !defined(CURL_DISABLE_CRYPTO_AUTH)

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "strequal.h"
#include "select.h"
#include "connect.h"
#include "timeval.h"
#include "socks.h"
#include "turn.h"
#include "stun_msg.h"
#include "sockaddr.h"
#include "hostip.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"


/*
 * Internal structure to ease the memory allocate/destroy.
 */
struct TURN {
  char *realm;
  size_t realm_len;
  char *nonce;
  size_t nonce_len;
  uint8_t key[16];
  uint8_t tsx_id[12];
  struct stun_msg_hdr *req;
  struct stun_msg_hdr *resp;
  struct connectdata *conn;
  uint32_t connection_id;
};

/* Initialize/destroy */
static void TURN_init(struct TURN *turn, struct connectdata *conn);
static void TURN_destroy(struct TURN *turn);

/* Core function */
static CURLcode doit(const char *username,
                     const char *password,
                     const char *hostname,
                     int remote_port,
                     struct TURN *turn);

/* Send the ALLOCATE request on the FIRSTSOCKET */
static CURLcode send_alloc_req(struct TURN *turn,
                               const char *username,
                               const char *password);

/* Send the CONNECT request on the FIRSTSOCKET */
static CURLcode send_connect_req(struct TURN *turn,
                                 const char *username,
                                 const char *hostname,
                                 int remote_port);

/* Send the CONNECTION-BIND request on the SECONDARYSOCKET */
static CURLcode send_connection_bind_req(struct TURN *turn,
                                         const char *username);

/*
 * Sends a given STUN request to the remote host, authenticating if needed.
 * The passed STUN message will be destroyed before the function returns.
 */
static CURLcode stun_send_req(struct TURN *turn,
                              int sockindex);

/*
 * Receives a STUN response from the remote host.
 */
static CURLcode stun_recv(struct TURN *turn,
                          int sockindex);

/*
 * Dump the STUN response using failf.
 */
static void failf_dump(struct SessionHandle *data,
                       const char *text,
                       struct stun_msg_hdr *resp);

/*
 * This function logs in to a TURN proxy and sends the specifics to the final
 * destination server.
 */
CURLcode Curl_TURN(const char *proxy_name,
                   const char *proxy_password,
                   const char *hostname,
                   int remote_port,
                   int sockindex,
                   struct connectdata *conn)
{
  struct TURN turn;
  CURLcode result;

  if (sockindex == SECONDARYSOCKET) {
    struct SessionHandle *data = conn->data;
    failf(data, "Secondary socket will be used by data channel, aborted.");
    return CURLE_COULDNT_CONNECT;
  }

  TURN_init(&turn, conn);

  result = doit(proxy_name, proxy_password, hostname, remote_port, &turn);

  TURN_destroy(&turn);

  return result;
}

static void TURN_init(struct TURN *turn, struct connectdata *conn)
{
  memset(turn, 0, sizeof(struct TURN));
  turn->conn = conn;
}

static void TURN_destroy(struct TURN *turn)
{
  if (turn->realm)
    free(turn->realm);
  if (turn->nonce)
    free(turn->nonce);
  if (turn->req)
    free(turn->req);
  if (turn->resp)
    free(turn->resp);
}

static CURLcode doit(const char *username,
                     const char *password,
                     const char *hostname,
                     int remote_port,
                     struct TURN *turn)
{
  CURLcode code;
  curl_socket_t sock;

  code = send_alloc_req(turn, username, password);
  if (code)
    return code;

  code = send_connect_req(turn, username, hostname, remote_port);
  if (code)
    return code;

  code = send_connection_bind_req(turn, username);
  if (code)
    return code;

  /* Exchange data sockets */
  sock = turn->conn->sock[FIRSTSOCKET];
  turn->conn->sock[FIRSTSOCKET] = turn->conn->sock[SECONDARYSOCKET];
  turn->conn->sock[SECONDARYSOCKET] = sock;
  return CURLE_OK;
}

static CURLcode send_alloc_req(struct TURN *turn,
                               const char *username,
                               const char *password) {
  struct SessionHandle *data = turn->conn->data;
  size_t username_len;
  CURLcode code;
  uint16_t buf_len;
  uint16_t msg_type;
  void *buf;

  /* Send the ALLOCATE request */
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_VARSIZE_SIZE(4)
    + STUN_ATTR_UINT32_SIZE
    + STUN_ATTR_UINT8_SIZE;
  turn->req = (struct stun_msg_hdr *)malloc(buf_len);
  if (!turn->req)
    return CURLE_OUT_OF_MEMORY;
  ++turn->tsx_id[11];
  stun_msg_hdr_init(turn->req, STUN_ALLOCATE_REQUEST, turn->tsx_id);
  stun_attr_varsize_add(turn->req, STUN_SOFTWARE,
      (uint8_t*)"curl", 4, 0);
  stun_attr_uint32_add(turn->req, STUN_LIFETIME, 1*60*60); /* 1h */
  stun_attr_uint8_add(turn->req, STUN_REQUESTED_TRANSPORT, 6); /* TCP */
  
  code = stun_send_req(turn, FIRSTSOCKET);
  if (code != CURLE_OK) {
    failf(data, "Failed send TURN allocate request.");
    return code;
  }

  /* Authenticate if needed */
  if(STUN_IS_ERROR_RESPONSE(stun_msg_type(turn->resp))) {
    struct stun_attr_errcode *errcode = NULL;
    struct stun_attr_varsize *realm = NULL, *nonce = NULL;
    struct stun_attr_hdr *attr = NULL;
    int status;

    while ((attr = stun_msg_next_attr(turn->resp, attr)) != NULL) {
      switch (stun_attr_type(attr)) {
      case STUN_ERROR_CODE:
        errcode = (struct stun_attr_errcode *)attr;
        break;
      case STUN_REALM:
        realm = (struct stun_attr_varsize *)attr;
        break;
      case STUN_NONCE:
        nonce = (struct stun_attr_varsize *)attr;
        break;
      }
    }
    status = stun_attr_errcode_status(errcode);
    if(status != STUN_ERROR_UNAUTHORIZED) {
      failf(data, "TURN server returned %d, disconnected.", status);
      return CURLE_COULDNT_CONNECT;
    }
    if(!realm || !nonce) {
      failf(data, "TURN server returned 401, but"
          "response doesn't contain a challenge.", status);
      return CURLE_COULDNT_CONNECT;
    }
    if(!username || !*username) {
      failf(data,
            "TURN server challenged the allocate request, but no"
            " username/password was supplied.");
      return CURLE_COULDNT_CONNECT;
    }

    /* Save realm and nonce */
    turn->realm_len = stun_attr_len(&realm->hdr);
    turn->realm = (char*)malloc(turn->realm_len+1);
    if (!turn->realm)
      return CURLE_OUT_OF_MEMORY;
    memcpy(turn->realm, stun_attr_varsize_read(realm), turn->realm_len);
    turn->realm[turn->realm_len] = '\0';

    turn->nonce_len = stun_attr_len(&nonce->hdr);
    turn->nonce = (char*)malloc(turn->nonce_len+1);
    if (!turn->nonce)
      return CURLE_OUT_OF_MEMORY;
    memcpy(turn->nonce, stun_attr_varsize_read(nonce), turn->nonce_len);
    turn->nonce[turn->nonce_len] = '\0';

    /* Append authentication attributes and send request again */
    username_len = strlen(username);
    buf_len = stun_msg_len(turn->req)
        + STUN_ATTR_VARSIZE_SIZE(username_len)
        + STUN_ATTR_VARSIZE_SIZE(stun_attr_len(&realm->hdr))
        + STUN_ATTR_VARSIZE_SIZE(stun_attr_len(&nonce->hdr))
        + STUN_ATTR_MSGINT_SIZE;
    buf = realloc(turn->req, buf_len);
    if (!buf)
      return CURLE_OUT_OF_MEMORY;
    turn->req = (struct stun_msg_hdr *)buf;
    ++turn->req->tsx_id[11]; /* Increment transaction number */
    stun_attr_varsize_add(turn->req, STUN_USERNAME,
        (uint8_t*)username, username_len, 0);
    stun_attr_varsize_add(turn->req, STUN_REALM,
        (uint8_t*)turn->realm, turn->realm_len, 0);
    stun_attr_varsize_add(turn->req, STUN_NONCE,
        (uint8_t*)turn->nonce, turn->nonce_len, 0);
    stun_key(username, username_len, turn->realm, turn->realm_len,
             password, strlen(password), turn->key);
    stun_attr_msgint_add(turn->req, turn->key, 16);

    code = stun_send_req(turn, FIRSTSOCKET);
    if(code != CURLE_OK) {
      failf(data, "Failed to send TURN allocate request.");
      return code;
    }
  }

  /* Handle the STUN response */
  msg_type = stun_msg_type(turn->resp);
  if(!STUN_IS_SUCCESS_RESPONSE(msg_type)
     || msg_type != STUN_ALLOCATE_RESPONSE) {
    failf_dump(data, "While allocating, TURN server returned", turn->resp);
    return CURLE_COULDNT_CONNECT;
  }

  return CURLE_OK;
}

static CURLcode send_connect_req(struct TURN *turn,
                                 const char *username,
                                 const char *hostname,
                                 int remote_port) {
  int rc;
  struct Curl_dns_entry *dns;
  Curl_addrinfo *hp=NULL;
  struct SessionHandle *data = turn->conn->data;
  struct Curl_sockaddr_storage remote_addr;
  struct stun_attr_uint32 *connection_id;
  CURLcode code;
  uint16_t msg_type;
  size_t username_len;
  uint16_t buf_len;
  void *buf;

  rc = Curl_resolv(turn->conn, hostname, remote_port, &dns);

  if(rc == CURLRESOLV_ERROR)
    return CURLE_COULDNT_RESOLVE_PROXY;

  if(rc == CURLRESOLV_PENDING)
    /* ignores the return code, but 'dns' remains NULL on failure */
    (void)Curl_resolver_wait_resolv(turn->conn, &dns);

  if(dns)
    hp=dns->addr;
  if(hp) {
    char local_buf[64];
    memcpy(&remote_addr, hp->ai_addr, hp->ai_addrlen);
    Curl_printable_address(hp, local_buf, sizeof(local_buf));
    infof(data, "TURN connect to %s (locally resolved)\n", local_buf);
    Curl_resolv_unlock(data, dns); /* not used anymore from now on */
  } else {
    failf(data, "Failed to resolve \"%s\" for TURN connect.",
          hostname);
    return CURLE_COULDNT_RESOLVE_HOST;
  }

  /* Send the CONNECT request */
  username_len = strlen(username);
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_VARSIZE_SIZE(4)
    + STUN_ATTR_SOCKADDR_SIZE(STUN_IPV4);
  if (turn->realm) {
    buf_len += STUN_ATTR_VARSIZE_SIZE(username_len)
      + STUN_ATTR_VARSIZE_SIZE(turn->realm_len)
      + STUN_ATTR_VARSIZE_SIZE(turn->nonce_len)
      + STUN_ATTR_MSGINT_SIZE;
  }
  buf = realloc(turn->req, buf_len);
  if (!buf)
    return CURLE_OUT_OF_MEMORY;
  turn->req = (struct stun_msg_hdr *)buf;
  ++turn->tsx_id[11];
  stun_msg_hdr_init(turn->req, STUN_CONNECT_REQUEST, turn->tsx_id);
  stun_attr_varsize_add(turn->req, STUN_SOFTWARE,
      (uint8_t*)"curl", 4, 0);
  stun_attr_xor_sockaddr_add(turn->req, STUN_XOR_PEER_ADDRESS,
      (struct sockaddr *)&remote_addr);
  if (turn->realm) {
    stun_attr_varsize_add(turn->req, STUN_USERNAME,
        (uint8_t*)username, username_len, 0);
    stun_attr_varsize_add(turn->req, STUN_REALM,
        (uint8_t*)turn->realm, turn->realm_len, 0);
    stun_attr_varsize_add(turn->req, STUN_NONCE,
        (uint8_t*)turn->nonce, turn->nonce_len, 0);
    stun_attr_msgint_add(turn->req, turn->key, 16); /* Already calculated */
  }

  code = stun_send_req(turn, FIRSTSOCKET);
  if (code != CURLE_OK) {
    failf(data, "Failed send TURN connect request.");
    return code;
  }

  /* Handle the STUN response */
  msg_type = stun_msg_type(turn->resp);
  if(!STUN_IS_SUCCESS_RESPONSE(msg_type)
     || msg_type != STUN_CONNECT_RESPONSE) {
    failf_dump(data, "While connecting, TURN server returned", turn->resp);
    return CURLE_COULDNT_CONNECT;
  }

  connection_id = (struct stun_attr_uint32 *)
      stun_msg_find_attr(turn->resp, STUN_CONNECTION_ID);
  if(!connection_id) {
    failf(data, "TURN connect response doesn't contain CONNECTION-ID.");
    return CURLE_COULDNT_CONNECT;
  }

  turn->connection_id = stun_attr_uint32_read(connection_id);
  return CURLE_OK;
}

static CURLcode send_connection_bind_req(struct TURN *turn,
                                         const char *username)
{
  int rc;
  struct Curl_dns_entry *dns;
  struct SessionHandle *data = turn->conn->data;
  CURLcode code;
  bool connected = FALSE;
  uint16_t msg_type;
  size_t username_len;
  uint16_t buf_len;
  void *buf;

  /*
   * TODO: if there are multiple addresses for the same host, it won't work.
   * We have to find a way to use getpeername here.
   */

  rc = Curl_resolv(turn->conn, turn->conn->proxy.name,
                   (int)turn->conn->port, &dns);

  if(rc == CURLRESOLV_PENDING)
    /* BLOCKING, ignores the return code but 'addr' will be NULL in
        case of failure */
    (void)Curl_resolver_wait_resolv(conn, &addr);

  if(!dns) {
    failf(data, "Can't resolve TURN host %s:%hu",
          turn->conn->proxy.name, turn->conn->port);
    return CURLE_FTP_CANT_GET_HOST;
  }

  turn->conn->bits.tcpconnect[SECONDARYSOCKET] = FALSE;
  code = Curl_connecthost(turn->conn, dns);

  Curl_resolv_unlock(data, dns); /* we're done using this address */

  if(code != CURLE_OK)
    return code;

  /*
   * Creates a new connection to the TURN server and sends a CONNECTION-BIND
   * request using the CONNECTION-ID returned by the CONNECT request, also
   * authenticating accordingly. On success, there will be two sockets opened,
   * one for the control channel, another for the data channel. On success,
   * the (initial) control channel will be stored in FIRSTSOCKET, and the new
   * data channel will be stored on the SECONDARYSOCKET. For simplicity, the
   * control channel won't send REFRESH-CONNECTION requests to the server.
   */

  /* perform a busy wait... */
  for (;;) {
    code = Curl_is_connected(turn->conn, SECONDARYSOCKET, &connected);
    if (code != CURLE_OK || connected)
      break;
    /* Curl_is_connected will check for timeout */
    Curl_wait_ms(1);
  }
  if (code != CURLE_OK)
    return code;

  /* Send the CONNECTION-BIND request */
  username_len = strlen(username);
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_VARSIZE_SIZE(4)
    + STUN_ATTR_UINT32_SIZE;
  if (turn->realm) {
    buf_len += STUN_ATTR_VARSIZE_SIZE(username_len)
      + STUN_ATTR_VARSIZE_SIZE(turn->realm_len)
      + STUN_ATTR_VARSIZE_SIZE(turn->nonce_len)
      + STUN_ATTR_MSGINT_SIZE;
  }
  buf = realloc(turn->req, buf_len);
  if (!buf)
    return CURLE_OUT_OF_MEMORY;
  turn->req = (struct stun_msg_hdr *)buf;
  ++turn->tsx_id[11];
  stun_msg_hdr_init(turn->req, STUN_CONNECTION_BIND_REQUEST, turn->tsx_id);
  stun_attr_varsize_add(turn->req, STUN_SOFTWARE,
      (uint8_t*)"curl", 4, 0);
  stun_attr_uint32_add(turn->req, STUN_CONNECTION_ID, turn->connection_id);
  if (turn->realm) {
    stun_attr_varsize_add(turn->req, STUN_USERNAME,
        (uint8_t*)username, username_len, 0);
    stun_attr_varsize_add(turn->req, STUN_REALM,
        (uint8_t*)turn->realm, turn->realm_len, 0);
    stun_attr_varsize_add(turn->req, STUN_NONCE,
        (uint8_t*)turn->nonce, turn->nonce_len, 0);
    stun_attr_msgint_add(turn->req, turn->key, 16); /* Already calculated */
  }
  
  code = stun_send_req(turn, SECONDARYSOCKET);
  if (code != CURLE_OK) {
    failf(data, "Failed send TURN connection-bind request.");
    return code;
  }

  /* Handle the STUN response */
  msg_type = stun_msg_type(turn->resp);
  if(!STUN_IS_SUCCESS_RESPONSE(msg_type)
     || msg_type != STUN_CONNECTION_BIND_RESPONSE) {
    failf_dump(data, "While binding connection, TURN server returned", turn->resp);
    return CURLE_COULDNT_CONNECT;
  }

  return CURLE_OK;
}

static CURLcode stun_send_req(struct TURN *turn,
                              int sockindex)
{
  CURLcode code;
  curl_socket_t sock = turn->conn->sock[sockindex];
  size_t req_len;
  long written;

  req_len = stun_msg_len(turn->req);
  code = Curl_write_plain(turn->conn, sock, turn->req, req_len, &written);
  if((code != CURLE_OK) || (written != req_len))
    return CURLE_COULDNT_CONNECT;

  code = stun_recv(turn, sockindex);
  if(code != CURLE_OK)
    return code;

  return CURLE_OK;
}

static CURLcode stun_recv(struct TURN *turn,
                          int sockindex) {
  uint8_t *buf;
  size_t buf_len;
  int result;
  struct stun_msg_hdr *resp;
  curl_socket_t sock = turn->conn->sock[sockindex];
  long actualread;

  /* Receive header first */
  buf_len = sizeof(struct stun_msg_hdr);
  buf = (uint8_t *)malloc(buf_len);
  if (!buf)
    return CURLE_OUT_OF_MEMORY;
  resp = (struct stun_msg_hdr *)buf;
  result = Curl_blockread_all(turn->conn, sock, (char*)buf, buf_len, &actualread);
  if((result != CURLE_OK) || (actualread != buf_len)) {
    free(buf);
    return CURLE_COULDNT_CONNECT;
  }

  /* Receive attributes, if available */
  if (stun_msg_len(resp) > sizeof(struct stun_msg_hdr)) {
    buf_len = stun_msg_len(resp);
    buf = (uint8_t *)realloc(buf, buf_len);
    if (!buf) {
      free(resp);
      return CURLE_OUT_OF_MEMORY;
    }
    resp = (struct stun_msg_hdr *)buf;
    result = Curl_blockread_all(turn->conn, sock,
        (char*)(buf + sizeof(struct stun_msg_hdr)),
        buf_len - sizeof(struct stun_msg_hdr), &actualread);
    if((result != CURLE_OK)
       || (actualread != buf_len - sizeof(struct stun_msg_hdr))) {
      free(buf);
      return CURLE_COULDNT_CONNECT;
    }
  }

  if (turn->resp)
    free(turn->resp);
  turn->resp = resp;

  return CURLE_OK;
}

static void failf_dump(struct SessionHandle *data,
                       const char *text,
                       struct stun_msg_hdr *resp) {
  uint16_t msg_type = stun_msg_type(resp);
  if(STUN_IS_ERROR_RESPONSE(msg_type)) {
    struct stun_attr_errcode *errcode;
    errcode = (struct stun_attr_errcode *)
        stun_msg_find_attr(resp, STUN_ERROR_CODE);
    if(errcode) {
      int status = stun_attr_errcode_status(errcode);
      failf(data, "%s: %s %s (%d %*s)", text,
            stun_method_name(msg_type), stun_class_name(msg_type), status,
            stun_attr_errcode_reason_len(errcode),
            stun_attr_errcode_reason(errcode));
      return;
    }
  }
  failf(data, "%s: %s %s", text,
        stun_method_name(msg_type), stun_class_name(msg_type));
}

#endif
