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
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"


/*
 * req_conn() sends a CONNECT request to the TURN server, and authenticates
 * accordingly. The CONNECTION-ID returned by the server is stored in the
 * parameter conn_id on success. The hostname is always resolved locally.
 */
static CURLcode req_conn(const char *proxy_name,
                         const char *proxy_password,
                         const char *hostname,
                         int remote_port,
                         int sockindex,
                         struct connectdata *conn,
                         unsigned long *conn_id);

/*
 * bind_conn() creates a new connection to the TURN server and sends a
 * CONNECTION-BIND request using the CONNECTION-ID returned by the CONNECT
 * request, also authenticating accordingly. On success, there will be two
 * sockets opened, one for the control channel, another for the data channel.
 * On success, the (initial) control channel will be stored in
 * conn->tmpsock[0], and the new data channel will be stored on the
 * conn->sock[sockindex]. For simplicity, the control channel won't send
 * REFRESH-CONNECTION requests to the server.
 */
static CURLcode bind_conn(unsigned long conn_id,
                          const char *proxy_password,
                          int sockindex,
                          struct connectdata *conn);

/*
 * Sends a given STUN request to the remote host, authenticating if needed.
 * The passed STUN message will be destroyed before the function returns.
 */
static CURLcode send_stun_req(struct stun_msg_hdr *req,
                              const char *proxy_name,
                              const char *proxy_password,
                              struct stun_msg_hdr **resp,
                              curl_socket_t sock);

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

  code = req_conn(proxy_name, proxy_password, hostname, remote_port,
                  sockindex, conn, &conn_id);
  if (code != CURLE_OK)
    return code;

  code = bind_conn(conn_id, proxy_password, sockindex, conn);
  if (code != CURLE_OK)
    return code;

  return CURLE_OK; /* TURN connection was successful! */
}

static CURLcode req_conn(const char *proxy_name,
                         const char *proxy_password,
                         const char *hostname,
                         int remote_port,
                         int sockindex,
                         struct connectdata *conn,
                         unsigned long *conn_id)
{
  size_t buf_len;
  uint8_t *buf;
  uint8_t tsx_id[12] = {0};
  struct stun_msg_hdr *req, *resp;
  struct SessionHandle *data = conn->data;
  curl_socket_t sock = conn->sock[sockindex];
  struct Curl_dns_entry *dns;
  Curl_addrinfo *hp=NULL;
  struct sockaddr_in remote_addr;
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

  /*
   * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
   * returns a Curl_addrinfo pointer that may not always look the same.
   */
  if(dns)
    hp=dns->addr;
  if(hp) {
    char local_buf[64];
    unsigned short ip[4];
    Curl_printable_address(hp, local_buf, sizeof(buf));

    if(4 == sscanf( local_buf, "%hu.%hu.%hu.%hu",
                    &ip[0], &ip[1], &ip[2], &ip[3])) {
      memset(&remote_addr, 0, sizeof(remote_addr));
      remote_addr.sin_port = htons(remote_port);
      memcpy(&remote_addr.sin_addr, ip, 4);
    }
    else
      hp = NULL; /* fail! */

    infof(data, "TURN connect to %s (locally resolved)\n", buf);

    Curl_resolv_unlock(data, dns); /* not used anymore from now on */
  }
  if(!hp) {
    failf(data, "Failed to resolve \"%s\" for TURN connect.",
          hostname);
    return CURLE_COULDNT_RESOLVE_HOST;
  }

  /* Compose the CONNECT request */
  buf_len = sizeof(struct stun_msg_hdr)
    + STUN_ATTR_SOCKADDR_SIZE(STUN_IPV4)
    + STUN_ATTR_VARSIZE_SIZE(4);
  buf = (uint8_t*)malloc(buf_len);
  req = (struct stun_msg_hdr *)buf;
  ++tsx_id[11];
  stun_msg_hdr_init(req, STUN_CONNECT_REQUEST, tsx_id);
  stun_attr_xor_sockaddr_add(req, STUN_XOR_PEER_ADDRESS,
      (struct sockaddr *)&remote_addr);
  code = send_stun_req(req, proxy_name, proxy_password, &resp, sock);
  if (code != CURLE_OK)
    return code;

  /* TODO: Handle the STUN response */

  return CURLE_FAILED_INIT;
}

static CURLcode bind_conn(unsigned long conn_id,
                          const char *proxy_password,
                          int sockindex,
                          struct connectdata *conn)
{
  return CURLE_FAILED_INIT;
}

static CURLcode send_stun_req(struct stun_msg_hdr *req,
                              const char *proxy_name,
                              const char *proxy_password,
                              struct stun_msg_hdr **resp,
                              curl_socket_t sock)
{
  free(req);
  return CURLE_FAILED_INIT;
}

#endif

