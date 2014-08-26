/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_sha1.h"
#include "curl_hmac.h"
#include "warnless.h"

#include "curl_memory.h"

#if defined(USE_GNUTLS_NETTLE)

#include <nettle/sha1.h>
/* The last #include file should be: */
#include "memdebug.h"

typedef struct sha1_ctx SHA1_CTX;

static void SHA1_Init(SHA1_CTX * ctx)
{
  sha1_init(ctx);
}

static void SHA1_Update(SHA1_CTX * ctx,
                       const unsigned char * input,
                       unsigned int inputLen)
{
  sha1_update(ctx, inputLen, input);
}

static void SHA1_Final(unsigned char digest[20], SHA1_CTX * ctx)
{
  sha1_digest(ctx, 20, digest);
}

#elif defined(USE_GNUTLS)

#include <gcrypt.h>
/* The last #include file should be: */
#include "memdebug.h"

typedef gcry_md_hd_t SHA1_CTX;

static void SHA1_Init(SHA1_CTX * ctx)
{
  gcry_md_open(ctx, GCRY_MD_SHA1, 0);
}

static void SHA1_Update(SHA1_CTX * ctx,
                        const unsigned char * input,
                        unsigned int inputLen)
{
  gcry_md_write(*ctx, input, inputLen);
}

static void SHA1_Final(unsigned char digest[20], SHA1_CTX * ctx)
{
  memcpy(digest, gcry_md_read(*ctx, 0), 20);
  gcry_md_close(*ctx);
}

#elif defined(USE_SSLEAY)
/* When OpenSSL is available we use the SHA1-function from OpenSSL */

#  ifdef USE_OPENSSL
#    include <openssl/sha.h>
#    define SHA1_CTX SHA_CTX
#  else
#    include <sha1.h>
#  endif

#elif (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
              (__MAC_OS_X_VERSION_MAX_ALLOWED >= 1040)) || \
      (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && \
              (__IPHONE_OS_VERSION_MAX_ALLOWED >= 20000))

/* For Apple operating systems: CommonCrypto has the functions we need.
   These functions are available on Tiger and later, as well as iOS 2.0
   and later. If you're building for an older cat, well, sorry.

   Declaring the functions as static like this seems to be a bit more
   reliable than defining COMMON_DIGEST_FOR_OPENSSL on older cats. */
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1_CTX CC_SHA1_CTX

static void SHA1_Init(SHA1_CTX *ctx)
{
  CC_SHA1_Init(ctx);
}

static void SHA1_Update(SHA1_CTX *ctx,
                        const unsigned char *input,
                        unsigned int inputLen)
{
  CC_SHA1_Update(ctx, input, inputLen);
}

static void SHA1_Final(unsigned char digest[20], SHA1_CTX *ctx)
{
  CC_SHA1_Final(digest, ctx);
}

#elif defined(_WIN32)

#include <wincrypt.h>

typedef struct {
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
} SHA1_CTX;

static void SHA1_Init(SHA1_CTX *ctx)
{
  if(CryptAcquireContext(&ctx->hCryptProv, NULL, NULL,
                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    CryptCreateHash(ctx->hCryptProv, CALG_SHA1, 0, 0, &ctx->hHash);
  }
}

static void SHA1_Update(SHA1_CTX *ctx,
                        const unsigned char *input,
                        unsigned int inputLen)
{
  CryptHashData(ctx->hHash, (unsigned char *)input, inputLen, 0);
}

static void SHA1_Final(unsigned char digest[20], SHA1_CTX *ctx)
{
  unsigned long length = 0;
  CryptGetHashParam(ctx->hHash, HP_HASHVAL, NULL, &length, 0);
  if(length == 20)
    CryptGetHashParam(ctx->hHash, HP_HASHVAL, digest, &length, 0);
  if(ctx->hHash)
    CryptDestroyHash(ctx->hHash);
  if(ctx->hCryptProv)
    CryptReleaseContext(ctx->hCryptProv, 0);
}

#else
/* When no other crypto library is available we use this code segment */

/* Implementation of SHA1 hash function.
 * Original author:  Steve Reid <sreid@sea-to-sky.net>
 * Contributions by: James H. Brown <jbrown@burgoyne.com>, Saul Kravitz
 * <Saul.Kravitz@celera.com>, and Ralph Giles <giles@ghostscript.com>
 * Modified by WaterJuice retaining Public Domain license.
 *
 * This is free and unencumbered software released into the public domain
 * June 2013 waterjuice.org
 */

#include <memory.h>
/* The last #include file should be: */
#include "memdebug.h"

typedef struct _SHA1_CTX {
  unsigned long state[5];
  unsigned long count[2];
  unsigned char buffer[64];
} SHA1_CTX;

typedef union {
  unsigned char c[64];
  unsigned long l[16];
} CHAR64LONG16;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999ul+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999ul+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1ul+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDCul+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6ul+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA1Transform(unsigned long state[5], const unsigned char buffer[64])
{
  unsigned long a, b, c, d, e;
  unsigned char workspace[64];
  CHAR64LONG16 *block = (CHAR64LONG16 *) workspace;

  memcpy(block, buffer, 64);

  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a, b, c, d, e,  0); R0(e, a, b, c, d,  1); R0(d, e, a, b, c,  2); R0(c, d, e, a, b,  3);
  R0(b, c, d, e, a,  4); R0(a, b, c, d, e,  5); R0(e, a, b, c, d,  6); R0(d, e, a, b, c,  7);
  R0(c, d, e, a, b,  8); R0(b, c, d, e, a,  9); R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13); R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17); R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21); R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25); R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29); R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33); R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37); R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41); R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45); R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49); R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53); R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57); R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61); R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65); R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69); R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73); R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77); R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

/* SHA1Init - Initialize new context */
void SHA1_Init(SHA1_CTX *context)
{
  /* SHA1 initialization constants */
  context->state[0] = 0x67452301ul;
  context->state[1] = 0xEFCDAB89ul;
  context->state[2] = 0x98BADCFEul;
  context->state[3] = 0x10325476ul;
  context->state[4] = 0xC3D2E1F0ul;
  context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */
void SHA1_Update(SHA1_CTX *context, const unsigned char *data, unsigned int len)
{
  unsigned int i, j;

  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3))
    context->count[1]++;
  context->count[1] += (len >> 29);
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64 - j));
    SHA1Transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64)
      SHA1Transform(context->state, &data[i]);
    j = 0;
  } else
    i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */
void SHA1_Final(unsigned char digest[20], SHA1_CTX *context)
{
  unsigned int i;
  unsigned char finalcount[8];

  for (i = 0; i < 8; i++) {
    finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)]
                    >> ((3 - (i & 3)) * 8)) & 255); /* Endian independent */
  }
  SHA1_Update(context, (unsigned char *) "\x80", 1);
  while ((context->count[0] & 504) != 448)
    SHA1_Update(context, (unsigned char *) "\0", 1);
  SHA1_Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++) {
    digest[i] =
      (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }
}

#endif /* CRYPTO LIBS */

/* The last #include file should be: */
#include "memdebug.h"

const HMAC_params Curl_HMAC_SHA1[] = {
  {
    (HMAC_hinit_func) SHA1_Init,          /* Hash initialization function. */
    (HMAC_hupdate_func) SHA1_Update,      /* Hash update function. */
    (HMAC_hfinal_func) SHA1_Final,        /* Hash computation end function. */
    sizeof(SHA1_CTX),                     /* Size of hash context structure. */
    64,                                   /* Maximum key length. */
    20                                    /* Result size. */
  }
};

const SHA1_params Curl_DIGEST_SHA1[] = {
  {
    (Curl_SHA1_init_func) SHA1_Init,     /* Digest initialization function */
    (Curl_SHA1_update_func) SHA1_Update, /* Digest update function */
    (Curl_SHA1_final_func) SHA1_Final,   /* Digest computation end function */
    sizeof(SHA1_CTX),                    /* Size of digest context struct */
    20                                   /* Result size */
  }
};

void Curl_sha1it(unsigned char *outbuffer, /* 20 bytes */
                 const unsigned char *input)
{
  SHA1_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, input, curlx_uztoui(strlen((char *)input)));
  SHA1_Final(outbuffer, &ctx);
}

SHA1_context *Curl_SHA1_init(const SHA1_params *sha1params)
{
  SHA1_context *ctxt;

  /* Create SHA1 context */
  ctxt = malloc(sizeof *ctxt);

  if(!ctxt)
    return ctxt;

  ctxt->sha1_hashctx = malloc(sha1params->sha1_ctxtsize);

  if(!ctxt->sha1_hashctx) {
    free(ctxt);
    return NULL;
  }

  ctxt->sha1_hash = sha1params;

  (*sha1params->sha1_init_func)(ctxt->sha1_hashctx);

  return ctxt;
}

int Curl_SHA1_update(SHA1_context *context,
                     const unsigned char *data,
                     unsigned int len)
{
  (*context->sha1_hash->sha1_update_func)(context->sha1_hashctx, data, len);

  return 0;
}

int Curl_SHA1_final(SHA1_context *context, unsigned char *result)
{
  (*context->sha1_hash->sha1_final_func)(result, context->sha1_hashctx);

  free(context->sha1_hashctx);
  free(context);

  return 0;
}

#endif

