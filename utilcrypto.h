
/* Copyright(c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef UTILCRYPTO_H
#define UTILCRYPTO_H

#include <openssl/evp.h>
#include "list.h"

const EVP_MD *md5digest(void);
const EVP_MD *sha256digest(void);

EVP_MD_CTX *mdctxcreate(const EVP_MD *digest);

int pwdcrypt(char encrypt_flag, uint8_t *in, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt, uint8_t saltlen);
int pwdrecrypt(uint8_t *pwd, uint8_t len, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth,
               uint8_t *oldsalt, uint8_t oldsaltlen, uint8_t *newsalt, uint8_t newsaltlen);
int recryptattrs(struct list *attrs, uint8_t *oldsecret, int oldsecret_len, uint8_t *newsecret, int newsecret_len, uint8_t *oldauth, uint8_t *newauth);

#endif /*UTILCRYPTO_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
