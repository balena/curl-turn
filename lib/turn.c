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

/* The last #include file should be: */
#include "memdebug.h"


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
  /*
    GBV: In order to attend all the prerequisites of the build, I'm gonna
    just copy the SOCKS5 implementation here.
  */

  unsigned char socksreq[600]; /* room for large user/pw (255 max each) */
  ssize_t actualread;
  ssize_t written;
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[sockindex];
  struct SessionHandle *data = conn->data;
  long timeout;
  bool socks5_resolve_local = (conn->proxytype == CURLPROXY_SOCKS5)?TRUE:FALSE;
  const size_t hostname_len = strlen(hostname);
  ssize_t len = 0;

  /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
  if(!socks5_resolve_local && hostname_len > 255) {
    infof(conn->data,"SOCKS5: server resolving disabled for hostnames of "
          "length > 255 [actual len=%zu]\n", hostname_len);
    socks5_resolve_local = TRUE;
  }

  /* get timeout */
  timeout = Curl_timeleft(data, NULL, TRUE);

  if(timeout < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  curlx_nonblock(sock, TRUE);

  /* wait until socket gets connected */
  result = Curl_socket_ready(CURL_SOCKET_BAD, sock, timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5: no connection here");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5: connection timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CURL_CSELECT_ERR) {
    failf(conn->data, "SOCKS5: error occurred during connection");
    return CURLE_COULDNT_CONNECT;
  }

  socksreq[0] = 5; /* version */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  socksreq[1] = (char)(proxy_name ? 3 : 2); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 1; /* GSS-API */
  socksreq[4] = 2; /* username/password */
#else
  socksreq[1] = (char)(proxy_name ? 2 : 1); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 2; /* username/password */
#endif

  curlx_nonblock(sock, FALSE);

  code = Curl_write_plain(conn, sock, (char *)socksreq, (2 + (int)socksreq[1]),
                          &written);
  if((code != CURLE_OK) || (written != (2 + (int)socksreq[1]))) {
    failf(data, "Unable to send initial SOCKS5 request.");
    return CURLE_COULDNT_CONNECT;
  }

  curlx_nonblock(sock, TRUE);

  result = Curl_socket_ready(sock, CURL_SOCKET_BAD, timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5 nothing to read");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5 read timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CURL_CSELECT_ERR) {
    failf(conn->data, "SOCKS5 read error occurred");
    return CURLE_RECV_ERROR;
  }

  curlx_nonblock(sock, FALSE);

  result=Curl_blockread_all(conn, sock, (char *)socksreq, 2, &actualread);
  if((result != CURLE_OK) || (actualread != 2)) {
    failf(data, "Unable to receive initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }
  if(socksreq[1] == 0) {
    /* Nothing to do, no authentication needed */
    ;
  }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  else if(socksreq[1] == 1) {
    code = Curl_SOCKS5_gssapi_negotiate(sockindex, conn);
    if(code != CURLE_OK) {
      failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
      return CURLE_COULDNT_CONNECT;
    }
  }
#endif
  else if(socksreq[1] == 2) {
    /* Needs user name and password */
    size_t proxy_name_len, proxy_password_len;
    if(proxy_name && proxy_password) {
      proxy_name_len = strlen(proxy_name);
      proxy_password_len = strlen(proxy_password);
    }
    else {
      proxy_name_len = 0;
      proxy_password_len = 0;
    }

    /*   username/password request looks like
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */
    len = 0;
    socksreq[len++] = 1;    /* username/pw subnegotiation version */
    socksreq[len++] = (unsigned char) proxy_name_len;
    if(proxy_name && proxy_name_len)
      memcpy(socksreq + len, proxy_name, proxy_name_len);
    len += proxy_name_len;
    socksreq[len++] = (unsigned char) proxy_password_len;
    if(proxy_password && proxy_password_len)
      memcpy(socksreq + len, proxy_password, proxy_password_len);
    len += proxy_password_len;

    code = Curl_write_plain(conn, sock, (char *)socksreq, len, &written);
    if((code != CURLE_OK) || (len != written)) {
      failf(data, "Failed to send SOCKS5 sub-negotiation request.");
      return CURLE_COULDNT_CONNECT;
    }

    result=Curl_blockread_all(conn, sock, (char *)socksreq, 2, &actualread);
    if((result != CURLE_OK) || (actualread != 2)) {
      failf(data, "Unable to receive SOCKS5 sub-negotiation response.");
      return CURLE_COULDNT_CONNECT;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] != 0) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    /* Everything is good so far, user was authenticated! */
  }
  else {
    /* error */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(socksreq[1] == 255) {
#else
    if(socksreq[1] == 1) {
      failf(data,
            "SOCKS5 GSSAPI per-message authentication is not supported.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(socksreq[1] == 255) {
#endif
      if(!proxy_name || !*proxy_name) {
        failf(data,
              "No authentication method was acceptable. (It is quite likely"
              " that the SOCKS5 server wanted a username/password, since none"
              " was supplied to the server on this connection.)");
      }
      else {
        failf(data, "No authentication method was acceptable.");
      }
      return CURLE_COULDNT_CONNECT;
    }
    else {
      failf(data,
            "Undocumented SOCKS5 mode attempted to be used by server.");
      return CURLE_COULDNT_CONNECT;
    }
  }

  /* Authentication is complete, now specify destination to the proxy */
  len = 0;
  socksreq[len++] = 5; /* version (SOCKS5) */
  socksreq[len++] = 1; /* connect */
  socksreq[len++] = 0; /* must be zero */

  if(!socks5_resolve_local) {
    socksreq[len++] = 3; /* ATYP: domain name = 3 */
    socksreq[len++] = (char) hostname_len; /* address length */
    memcpy(&socksreq[len], hostname, hostname_len); /* address str w/o NULL */
    len += hostname_len;
  }
  else {
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp = NULL;
    int rc = Curl_resolv(conn, hostname, remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return CURLE_COULDNT_RESOLVE_HOST;

    if(rc == CURLRESOLV_PENDING) {
      /* this requires that we're in "wait for resolve" state */
      code = Curl_resolver_wait_resolv(conn, &dns);
      if(code != CURLE_OK)
        return code;
    }

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if(hp) {
      struct sockaddr_in *saddr_in;
#ifdef ENABLE_IPV6
      struct sockaddr_in6 *saddr_in6;
#endif
      int i;

      if(hp->ai_family == AF_INET) {
        socksreq[len++] = 1; /* ATYP: IPv4 = 1 */

        saddr_in = (struct sockaddr_in*)hp->ai_addr;
        for(i = 0; i < 4; i++) {
          socksreq[len++] = ((unsigned char*)&saddr_in->sin_addr.s_addr)[i];
          infof(data, "%d\n", socksreq[len-1]);
        }
      }
#ifdef ENABLE_IPV6
      else if(hp->ai_family == AF_INET6) {
        socksreq[len++] = 4; /* ATYP: IPv6 = 4 */

        saddr_in6 = (struct sockaddr_in6*)hp->ai_addr;
        for(i = 0; i < 16; i++) {
          socksreq[len++] = ((unsigned char*)&saddr_in6->sin6_addr.s6_addr)[i];
        }
      }
#endif
      else
        hp = NULL; /* fail! */

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */
    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            hostname);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  socksreq[len++] = (unsigned char)((remote_port >> 8) & 0xff); /* PORT MSB */
  socksreq[len++] = (unsigned char)(remote_port & 0xff);        /* PORT LSB */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(conn->socks5_gssapi_enctype) {
    failf(data, "SOCKS5 GSS-API protection not yet implemented.");
  }
  else
#endif
    code = Curl_write_plain(conn, sock, (char *)socksreq, len, &written);

  if((code != CURLE_OK) || (len != written)) {
    failf(data, "Failed to send SOCKS5 connect request.");
    return CURLE_COULDNT_CONNECT;
  }

  len = 10; /* minimum packet size is 10 */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(conn->socks5_gssapi_enctype) {
    failf(data, "SOCKS5 GSS-API protection not yet implemented.");
  }
  else
#endif
    result = Curl_blockread_all(conn, sock, (char *)socksreq,
                                len, &actualread);

  if((result != CURLE_OK) || (len != actualread)) {
    failf(data, "Failed to receive SOCKS5 connect request ack.");
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[0] != 5) { /* version */
    failf(data,
          "SOCKS5 reply has wrong version, version should be 5.");
    return CURLE_COULDNT_CONNECT;
  }
  if(socksreq[1] != 0) { /* Anything besides 0 is an error */
    if(socksreq[3] == 1) {
      failf(data,
            "Can't complete SOCKS5 connection to %d.%d.%d.%d:%d. (%d)",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    else if(socksreq[3] == 3) {
      failf(data,
            "Can't complete SOCKS5 connection to %s:%d. (%d)",
            hostname,
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    else if(socksreq[3] == 4) {
      failf(data,
            "Can't complete SOCKS5 connection to %02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%d. (%d)",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned char)socksreq[8], (unsigned char)socksreq[9],
            (unsigned char)socksreq[10], (unsigned char)socksreq[11],
            (unsigned char)socksreq[12], (unsigned char)socksreq[13],
            (unsigned char)socksreq[14], (unsigned char)socksreq[15],
            (unsigned char)socksreq[16], (unsigned char)socksreq[17],
            (unsigned char)socksreq[18], (unsigned char)socksreq[19],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    return CURLE_COULDNT_CONNECT;
  }

  /* Fix: in general, returned BND.ADDR is variable length parameter by RFC
     1928, so the reply packet should be read until the end to avoid errors at
     subsequent protocol level.

    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

     ATYP:
     o  IP v4 address: X'01', BND.ADDR = 4 byte
     o  domain name:  X'03', BND.ADDR = [ 1 byte length, string ]
     o  IP v6 address: X'04', BND.ADDR = 16 byte
     */

  /* Calculate real packet size */
  if(socksreq[3] == 3) {
    /* domain name */
    int addrlen = (int) socksreq[4];
    len = 5 + addrlen + 2;
  }
  else if(socksreq[3] == 4) {
    /* IPv6 */
    len = 4 + 16 + 2;
  }

  /* At this point we already read first 10 bytes */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(!conn->socks5_gssapi_enctype) {
    /* decrypt_gssapi_blockread already read the whole packet */
#endif
    if(len > 10) {
      len -= 10;
      result = Curl_blockread_all(conn, sock, (char *)&socksreq[10],
                                  len, &actualread);
      if((result != CURLE_OK) || (len != actualread)) {
        failf(data, "Failed to receive SOCKS5 connect request ack.");
        return CURLE_COULDNT_CONNECT;
      }
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  }
#endif

  curlx_nonblock(sock, TRUE);
  return CURLE_OK; /* Proxy was successful! */
}

#endif

