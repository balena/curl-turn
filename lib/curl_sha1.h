#ifndef HEADER_CURL_SHA1_H
#define HEADER_CURL_SHA1_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if !defined(CURL_DISABLE_PROXY) \
    && !defined(CURL_DISABLE_TURN) \
    && !defined(CURL_DISABLE_CRYPTO_AUTH)
#include "curl_hmac.h"

#define SHA1_DIGEST_LEN  20

typedef void (* Curl_SHA1_init_func)(void *context);
typedef void (* Curl_SHA1_update_func)(void *context,
                                      const unsigned char *data,
                                      unsigned int len);
typedef void (* Curl_SHA1_final_func)(unsigned char *result, void *context);

typedef struct {
  Curl_SHA1_init_func    sha1_init_func;   /* Initialize context procedure */
  Curl_SHA1_update_func  sha1_update_func; /* Update context with data */
  Curl_SHA1_final_func   sha1_final_func;  /* Get final result procedure */
  unsigned int           sha1_ctxtsize;    /* Context structure size */
  unsigned int           sha1_resultlen;   /* Result length (bytes) */
} SHA1_params;

typedef struct {
  const SHA1_params     *sha1_hash;      /* Hash function definition */
  void                  *sha1_hashctx;   /* Hash function context */
} SHA1_context;

extern const SHA1_params Curl_DIGEST_SHA1[1];
extern const HMAC_params Curl_HMAC_SHA1[1];

void Curl_sha1it(unsigned char *output,
                 const unsigned char *input);

SHA1_context * Curl_SHA1_init(const SHA1_params *sha1params);
int Curl_SHA1_update(SHA1_context *context,
                     const unsigned char *data,
                     unsigned int len);
int Curl_SHA1_final(SHA1_context *context, unsigned char *result);

#endif

#endif /* HEADER_CURL_SHA1_H */
