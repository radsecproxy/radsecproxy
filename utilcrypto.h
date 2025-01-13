
/* Copyright(c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef UTILCRYPTO_H
#define UTILCRYPTO_H

#include <openssl/evp.h>

const EVP_MD *md5digest(void);
const EVP_MD *sha256digest(void);

EVP_MD_CTX *mdctxcreate(const EVP_MD *digest);

#endif /*UTILCRYPTO_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
