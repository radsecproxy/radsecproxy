
/* Copyright(c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef UTILCRYPTO_H
#define UTILCRYPTO_H

#include <openssl/evp.h>

const EVP_MD *md5digest(void);
const EVP_MD *sha256digest(void);

EVP_MD_CTX *mdctxcreate(const EVP_MD *digest);

int pwdcrypt(char encrypt_flag, uint8_t *in, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt, uint8_t saltlen);
int msmppencrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt);
int msmppdecrypt(uint8_t *text, uint8_t len, uint8_t *shared, uint8_t sharedlen, uint8_t *auth, uint8_t *salt);

#endif /*UTILCRYPTO_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
