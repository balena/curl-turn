#ifndef HEADER_CURL_TURN_H
#define HEADER_CURL_TURN_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef CURL_DISABLE_PROXY
#define Curl_TURN(a,b,c,d,e,f) CURLE_NOT_BUILT_IN
#else
/*
 * This function logs in to a TURN proxy and sends the specifics to the
 * final destination server.
 */
CURLcode Curl_TURN(const char *proxy_name,
                   const char *proxy_password,
                   const char *hostname,
                   int remote_port,
                   int sockindex,
                   struct connectdata *conn);

#endif /* CURL_DISABLE_PROXY */

#endif  /* HEADER_CURL_TURN_H */

