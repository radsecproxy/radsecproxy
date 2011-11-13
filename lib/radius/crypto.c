/*
Copyright (c) 2011, Network RADIUS SARL
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file crypto.c
 *  \brief Data obfuscation and signing, using MD5.
 *
 *  The "encryption" methods defined here are export-safe.  The
 *  technical cryptography name for these functions is "obfuscation".
 *  They cannot properly be called "encryption", in the same way that
 *  DES or AES performs encryption.
 */

/** \cond PRIVATE */

#include	"client.h"


ssize_t nr_password_encrypt(uint8_t *output, size_t outlen,
			   const uint8_t *input, size_t inlen,
			   const char *secret, const uint8_t *vector)
{
	size_t i, j, len;
	uint8_t digest[16];
	RS_MD5_CTX ctx, secret_ctx;

	if (!output || (outlen < 16) || !input || (inlen == 0) ||
	    !secret || !vector) {
		return -RSE_INVAL;
	}

	len = inlen;
	if (len > 128) return -RSE_ATTR_OVERFLOW;

	len = (len + 0x0f) & ~0x0f; /* round up to 16 byte boundary */

	if (outlen < len) return -RSE_ATTR_OVERFLOW;

	memcpy(output, input, len);
	memset(output + len, 0, 128 - len);

	RS_MD5Init(&secret_ctx);
	RS_MD5Update(&secret_ctx, (const uint8_t *) secret, strlen(secret));

	for (j = 0; j < len; j += 16) {
		ctx = secret_ctx;

		if (j == 0) {
			RS_MD5Update(&ctx, vector, 16);
			RS_MD5Final(digest, &ctx);
		} else {
			RS_MD5Update(&ctx, &output[j - 16], 16);
			RS_MD5Final(digest, &ctx);
		}

		for (i = 0; i < 16; i++) {
			output[i + j] ^= digest[i];
		}
	}

	return len;
}

#ifdef FLAG_ENCRYPT_TUNNEL_PASSWORD
ssize_t nr_tunnelpw_encrypt(uint8_t *output, size_t outlen,
			    const uint8_t *input, size_t inlen,
			    const char *secret, const uint8_t *vector)
{
	size_t i, j, len;
	RS_MD5_CTX ctx, secret_ctx;
	uint8_t digest[16];

	if (!output || (outlen < 18) || !input || (inlen == 0) ||
	    !secret || !vector) {
		return -RSE_INVAL;
	}

	len = ((inlen + 1) + 0x0f) & ~0x0f;
	if (len > 251) return -RSE_ATTR_OVERFLOW;

	output[0] = (nr_rand() & 0xff) | 0x80;
	output[1] = nr_rand() & 0xff;
	output[2] = inlen;

	memcpy(output + 3, input, inlen);
	memset(output + 3 + inlen, 0, len - inlen - 1);

	RS_MD5Init(&secret_ctx);
	RS_MD5Update(&secret_ctx, (const uint8_t *) secret, strlen(secret));

	for (j = 0; j < len; j += 16) {
		ctx = secret_ctx;

		if (j == 0) {
			RS_MD5Update(&ctx, vector, 16);
			RS_MD5Update(&ctx, output, 2);
			RS_MD5Final(digest, &ctx);
		} else {
			RS_MD5Update(&ctx, &output[j + 2 - 16], 16);
			RS_MD5Final(digest, &ctx);
		}

		for (i = 0; i < 16; i++) {
			output[i + j + 2] ^= digest[i];
		}
	}

	return len + 2;
}

ssize_t nr_tunnelpw_decrypt(uint8_t *output, size_t outlen,
			    const uint8_t *input, size_t inlen,
			    const char *secret, const uint8_t *vector)
{
	size_t i, j, len, encoded_len;
	RS_MD5_CTX ctx, secret_ctx;
	uint8_t digest[16];

	if (!output || (outlen < 1) || !input || (inlen < 2) ||
	    !secret || !vector) {
		return -RSE_INVAL;
	}

	if (inlen <= 3) {
		output[0] = 0;
		return 0;
	}

	len = inlen - 2;

	if (outlen < (len - 1)) return -RSE_ATTR_OVERFLOW;

	RS_MD5Init(&secret_ctx);
	RS_MD5Update(&secret_ctx, (const uint8_t *) secret, strlen(secret));

	ctx = secret_ctx;

	RS_MD5Update(&ctx, vector, 16); /* MD5(secret + vector + salt) */
	RS_MD5Update(&ctx, input, 2);
	RS_MD5Final(digest, &ctx);

	encoded_len = input[2] ^ digest[0];
	if (encoded_len >= len) {
		return -RSE_ATTR_TOO_LARGE;
	}

	for (i = 0; i < 15; i++) {
		output[i] = input[i + 3] ^ digest[i + 1];
	}

	for (j = 16; j < len; j += 16) {
		ctx = secret_ctx;

		RS_MD5Update(&ctx, input + j - 16 + 2, 16);
		RS_MD5Final(digest, &ctx);

		for (i = 0; i < 16; i++) {
			output[i + j - 1] = input[i + j + 2] ^ digest[i];
		}
		

	}

	output[encoded_len] = '\0';
	return encoded_len;
}
#endif

void
nr_hmac_md5(const uint8_t *data, size_t data_len,
	    const uint8_t *key, size_t key_len,
	    uint8_t digest[16])
{
        size_t i;
        uint8_t k_ipad[64];
        uint8_t k_opad[64];
        uint8_t tk[16];
        RS_MD5_CTX ctx;

        if (key_len > 64) {
                RS_MD5Init(&ctx);
                RS_MD5Update(&ctx, key, key_len);
                RS_MD5Final(tk, &ctx);

                key = tk;
                key_len = 16;
        }

        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);

        for (i = 0; i < sizeof(k_ipad); i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }

        RS_MD5Init(&ctx); 
        RS_MD5Update(&ctx, k_ipad, sizeof(k_ipad));
        RS_MD5Update(&ctx, data, data_len);
        RS_MD5Final(digest, &ctx);

        RS_MD5Init(&ctx);
        RS_MD5Update(&ctx, k_opad, sizeof(k_opad));
        RS_MD5Update(&ctx, digest, 16);
        RS_MD5Final(digest, &ctx);
}

/** \endcond */
