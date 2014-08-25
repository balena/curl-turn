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
 * req_conn() sends a CONNECT request to the TURN server, and authenticates
 * accordingly. The CONNECTION-ID returned by the server is stored in the
 * parameter conn_id on success. The hostname is always resolved locally.
 */
static CURLcode req_conn(struct connectdata *conn,
                         int sockindex,
                         const char *hostname,
                         int remote_port,
                         const char *proxy_name,
                         const char *proxy_password,
                         unsigned long *conn_id);

/*
 * bind_conn() creates a new connection to the TURN server and sends a
 * CONNECTION-BIND request using the CONNECTION-ID returned by the CONNECT
 * request, also authenticating accordingly. On success, there will be two
 * sockets opened, one for the control channel, another for the data channel.
 * On success, the (initial) control channel will be stored in
 * conn->tempsock[0], and the new data channel will be stored on the
 * conn->sock[sockindex]. For simplicity, the control channel won't send
 * REFRESH-CONNECTION requests to the server.
 */
static CURLcode bind_conn(struct connectdata *conn,
                          int sockindex,
                          unsigned long conn_id,
                          const char *proxy_name,
                          const char *proxy_password);

/*
 * Sends a given STUN request to the remote host, authenticating if needed.
 * The passed STUN message will be destroyed before the function returns.
 */
static CURLcode stun_send_req(struct connectdata *conn,
                              int sockindex,
                              struct stun_msg_hdr *req,
                              const char *proxy_name,
                              const char *proxy_password,
                              struct stun_msg_hdr **p_resp);

/*
 * Receives a STUN response from the remote host.
 */
static CURLcode stun_recv(struct connectdata *conn,
                          int sockindex,
                          struct stun_msg_hdr **p_resp);

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
  CURLcode code;
  unsigned long conn_id;

  if (sockindex == SECONDARYSOCKET) {
    struct SessionHandle *data = conn->data;
    failf(data, "Secondary socket will be used by data channel, aborted.");
    return CURLE_COULDNT_CONNECT;
  }

  code = req_conn(conn, sockindex, hostname, remote_port,
                  proxy_name, proxy_password, &conn_id);
  if (code != CURLE_OK)
    return code;

  code = bind_conn(conn, sockindex, conn_id,
                   proxy_name, proxy_password);
  if (code != CURLE_OK)
    return code;

  return CURLE_OK; /* TURN connection was successful! */
}

static CURLcode req_conn(struct connectdata *conn,
                         int sockindex,
                         const char *hostname,
                         int remote_port,
                         const char *proxy_name,
                         const char *proxy_password,
                         unsigned long *conn_id)
{
  size_t buf_len;
  uint8_t *buf;
  uint8_t tsx_id[12] = {0};
  struct stun_msg_hdr *req, *resp;
  struct SessionHandle *data = conn->data;
  struct Curl_dns_entry *dns;
  Curl_addrinfo *hp=NULL;
  struct Curl_sockaddr_storage remote_addr;
  struct stun_attr_uint32 *connection_id;
  uint16_t msg_type;
  CURLcode code;
  int rc;

  if(Curl_timeleft(data, NULL, TRUE) < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  rc = Curl_resolv(conn, hostname, remote_port, &dns);

  if(rc == CURLRESOLV_ERROR)
    return CURLE_COULDNT_RESOLVE_PROXY;

  if(rc == CURLRESOLV_PENDING)
    /* ignores the return code, but 'dns' remains NULL on failure */
    (void)Curl_resolver_wait_resolv(conn, &dns);

  if(dns)
    hp=dns->addr;
  if(hp) {
    char local_buf[64];
    memcpy(&remote_addr, hp->ai_addr, hp->ai_addrlen);
    Curl_printable_address(hp, local_buf, sizeof(buf));
    infof(data, "TURN connect to %s (locally resolved)\n", local_buf);
    Curl_resolv_unlock(data, dns); /* not used anymore from now on */
  } else {
    failf(data, "Failed to resolve \"%s\" for TURN connect.",
          hostname);
    return CURLE_COULDNT_RESOLVE_HOST;
  }

  /* Send the CONNECT request */
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_SOCKADDR_SIZE(STUN_IPV4)
    + STUN_ATTR_VARSIZE_SIZE(4);
  buf = (uint8_t*)malloc(buf_len);
  req = (struct stun_msg_hdr *)buf;
  ++tsx_id[11];
  stun_msg_hdr_init(req, STUN_CONNECT_REQUEST, tsx_id);
  stun_attr_varsize_add(req, STUN_SOFTWARE,
      (uint8_t*)"curl", 4, 0);
  stun_attr_xor_sockaddr_add(req, STUN_XOR_PEER_ADDRESS,
      (struct sockaddr *)&remote_addr);
  code = stun_send_req(conn, sockindex, req,
                       proxy_name, proxy_password, &resp);
  if (code != CURLE_OK)
    return code;

  /* Handle the STUN response */
  msg_type = stun_msg_type(resp);
  if(!STUN_IS_SUCCESS_RESPONSE(msg_type)
     || msg_type != STUN_BINDING_RESPONSE) {
    struct stun_attr_errcode *errcode;
    errcode =
      (struct stun_attr_errcode *)stun_msg_find_attr(resp, STUN_ERROR_CODE);
    if(errcode) {
      int status = stun_attr_errcode_status(errcode);
      failf(data, "TURN server returned %s %s (%d %s).",
          stun_method_name(msg_type), stun_class_name(msg_type), status,
          stun_err_reason(status));
    } else {
      failf(data, "TURN server returned %s %s.",
          stun_method_name(msg_type), stun_class_name(msg_type));
    }
    free(resp);
    return CURLE_COULDNT_CONNECT;
  }

  connection_id =
    (struct stun_attr_uint32 *)stun_msg_find_attr(resp, STUN_CONNECTION_ID);  
  if(!connection_id) {
    free(resp);
    failf(data, "TURN connect response doesn't contain CONNECTION-ID.");
    return CURLE_COULDNT_CONNECT;
  }

  *conn_id = stun_attr_uint32_read(connection_id);
  free(resp);
  return CURLE_OK;
}

static CURLcode bind_conn(struct connectdata *conn,
                          int sockindex,
                          unsigned long conn_id,
                          const char *proxy_name,
                          const char *proxy_password)
{
  size_t buf_len;
  uint8_t *buf;
  struct stun_msg_hdr *req, *resp;
  uint16_t msg_type;
  struct SessionHandle *data = conn->data;
  curl_socket_t ctrl_sock = conn->sock[sockindex];
  curl_socket_t data_sock;
  struct Curl_dns_entry *addr;
  CURLcode result;
  bool connected = FALSE;
  uint8_t tsx_id[12] = {0};
  int rc;

  rc = Curl_resolv(conn, conn->proxy.name, (int)conn->port, &addr);
  if(rc == CURLRESOLV_PENDING)
    /* BLOCKING, ignores the return code but 'addr' will be NULL in
        case of failure */
    (void)Curl_resolver_wait_resolv(conn, &addr);

  if(!addr) {
    failf(data, "Can't resolve proxy host %s:%hu",
          conn->proxy.name, conn->port);
    return CURLE_FTP_CANT_GET_HOST;
  }

  conn->bits.tcpconnect[SECONDARYSOCKET] = FALSE;
  result = Curl_connecthost(conn, addr);

  Curl_resolv_unlock(data, addr); /* we're done using this address */

  if(result != CURLE_OK)
    return result;

  /* perform a busy wait... */
  for (;;) {
    result = Curl_is_connected(conn, SECONDARYSOCKET, &connected);
    if (result != CURLE_OK || connected)
      break;
    /* Curl_is_connected will check for timeout */
    Curl_wait_ms(1);
  }
  if (result != CURLE_OK)
    return result;

  /* Send the CONNECTION-BIND request */
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_SOCKADDR_SIZE(STUN_IPV4)
    + STUN_ATTR_VARSIZE_SIZE(4);
  buf = (uint8_t*)malloc(buf_len);
  req = (struct stun_msg_hdr *)buf;
  ++tsx_id[11];
  stun_msg_hdr_init(req, STUN_CONNECTION_BIND_REQUEST, tsx_id);
  stun_attr_varsize_add(req, STUN_SOFTWARE,
      (uint8_t*)"curl", 4, 0);
  stun_attr_uint32_add(req, STUN_CONNECTION_ID, conn_id);
  result = stun_send_req(conn, SECONDARYSOCKET, req,
                         proxy_name, proxy_password, &resp);
  if (result != CURLE_OK)
    return result;

  /* Handle the STUN response */
  msg_type = stun_msg_type(resp);
  if(!STUN_IS_SUCCESS_RESPONSE(msg_type)
     || msg_type != STUN_CONNECTION_BIND_RESPONSE) {
    struct stun_attr_errcode *errcode;
    errcode =
      (struct stun_attr_errcode *)stun_msg_find_attr(resp, STUN_ERROR_CODE);
    if(errcode) {
      int status = stun_attr_errcode_status(errcode);
      failf(data, "TURN server returned %s %s (%d %s) for the data channel.",
            stun_method_name(msg_type), stun_class_name(msg_type), status,
            stun_err_reason(status));
    } else {
      failf(data, "TURN server returned %s %s for the data channel.",
            stun_method_name(msg_type), stun_class_name(msg_type));
    }
    free(resp);
    return CURLE_COULDNT_CONNECT;
  }

  /* Exchange data sockets */
  data_sock = conn->sock[SECONDARYSOCKET];
  conn->sock[FIRSTSOCKET] = data_sock;
  conn->sock[SECONDARYSOCKET] = ctrl_sock;

  free(resp);
  return CURLE_OK;
}

static CURLcode stun_send_req(struct connectdata *conn,
                              int sockindex,
                              struct stun_msg_hdr *req,
                              const char *proxy_name,
                              const char *proxy_password,
                              struct stun_msg_hdr **p_resp)
{
  CURLcode code;
  curl_socket_t sock = conn->sock[sockindex];
  struct SessionHandle *data = conn->data;
  struct stun_msg_hdr *resp;
  uint8_t *buf;
  size_t req_len;
  size_t proxy_name_len;
  long written;
  int status;

  req_len = stun_msg_len(req);
  code = Curl_write_plain(conn, sock, req, req_len, &written);
  if((code != CURLE_OK) || (written != req_len)) {
    free(req);
    failf(data, "Failed to send TURN connect request.");
    return CURLE_COULDNT_CONNECT;
  }

  code = stun_recv(conn, sockindex, &resp);
  if(code != CURLE_OK) {
    free(req);
    failf(data, "Failed to receive TURN connect response.");
    return code;
  }

  /* Authenticate if needed */
  if(STUN_IS_ERROR_RESPONSE(stun_msg_type(resp))) {
    struct stun_attr_errcode *errcode = NULL;
    struct stun_attr_varsize *realm = NULL, *nonce = NULL;
    struct stun_attr_hdr *attr = NULL;
    while ((attr = stun_msg_next_attr(resp, attr)) != NULL) {
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
      free(req);
      free(resp);
      failf(data, "TURN server returned %d, disconnected.", status);
      return CURLE_COULDNT_CONNECT;
    }
    if(!realm || !nonce) {
      free(req);
      free(resp);
      failf(data, "TURN server returned 401, but"
          "response doesn't contain a challenge.", status);
      return CURLE_COULDNT_CONNECT;
    }

    /* Append authentication attributes and send request again */
    proxy_name_len = strlen(proxy_name);
    req_len = stun_msg_len(req)
        + STUN_ATTR_VARSIZE_SIZE(proxy_name_len)
        + STUN_ATTR_VARSIZE_SIZE(stun_attr_len(&realm->hdr))
        + STUN_ATTR_VARSIZE_SIZE(stun_attr_len(&nonce->hdr))
        + STUN_ATTR_MSGINT_SIZE;
    buf = (uint8_t*)realloc(req, req_len);
    req = (struct stun_msg_hdr *)buf;
    ++req->tsx_id[11]; /* Increment transaction number */
    stun_attr_varsize_add(req, STUN_USERNAME,
        (uint8_t*)proxy_name, proxy_name_len, 0);
    stun_attr_varsize_add(req, STUN_REALM,
        stun_attr_varsize_read(realm), stun_attr_len(&realm->hdr), 0);
    stun_attr_varsize_add(req, STUN_NONCE,
        stun_attr_varsize_read(nonce), stun_attr_len(&nonce->hdr), 0);
    stun_attr_msgint_add(req,
        (uint8_t*)proxy_password, strlen(proxy_password));

    free(resp);

    code = Curl_write_plain(conn, sock, req, req_len, &written);
    if((code != CURLE_OK) || (written != req_len)) {
      free(req);
      failf(data, "Failed to send authenticated TURN connect request.");
      return CURLE_COULDNT_CONNECT;
    }

    code = stun_recv(conn, sockindex, &resp);
    if(code != CURLE_OK) {
      free(req);
      failf(data, "Failed to receive TURN connect response"
          "after authentication.");
      return code;
    }
  }

  free(req);
  *p_resp = resp;
  return CURLE_OK;
}

static CURLcode stun_recv(struct connectdata *conn,
                          int sockindex,
                          struct stun_msg_hdr **p_resp) {
  uint8_t *buf;
  size_t buf_len;
  int result;
  struct stun_msg_hdr *resp;
  curl_socket_t sock = conn->sock[sockindex];
  struct SessionHandle *data = conn->data;
  long actualread;

  /* Receive header first */
  buf_len = sizeof(struct stun_msg_hdr);
  buf = (uint8_t *)malloc(buf_len);
  resp = (struct stun_msg_hdr *)buf;
  result = Curl_blockread_all(conn, sock, (char*)buf, buf_len, &actualread);
  if((result != CURLE_OK) || (actualread != buf_len)) {
    free(buf);
    return CURLE_COULDNT_CONNECT;
  }

  /* Receive attributes, if available */
  if (stun_msg_len(resp) > sizeof(struct stun_msg_hdr)) {
    buf_len = stun_msg_len(resp);
    buf = (uint8_t *)realloc(buf, buf_len);
    resp = (struct stun_msg_hdr *)buf;
    result = Curl_blockread_all(conn, sock,
        (char*)(buf + sizeof(struct stun_msg_hdr)),
        buf_len - sizeof(struct stun_msg_hdr), &actualread);
    if((result != CURLE_OK)
       || (actualread != buf_len - sizeof(struct stun_msg_hdr))) {
      free(buf);
      return CURLE_COULDNT_CONNECT;
    }
  }

  *p_resp = resp;
  return CURLE_OK;
}

#endif

