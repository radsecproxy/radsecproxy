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
/*
 * Copyright (c) 2006 Kungliga Tekniska HAÎåÎÝgskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** \file custom.c
 *  \brief Functions which should be customized for your local system.
 */

#include "client.h"

#include	<unistd.h>
#include	<fcntl.h>

#ifdef WIN32
#include <wincrypt.h>

volatile static HCRYPTPROV nr_cryptprovider = 0;

static HCRYPTPROV
nr_CryptProvider(void)
{
    BOOL rv;
    HCRYPTPROV cryptprovider = 0;

    if (nr_cryptprovider != 0)
        return nr_cryptprovider;

    rv = CryptAcquireContext(&cryptprovider, NULL,
                              MS_ENHANCED_PROV, PROV_RSA_FULL,
                              0);

    if (GetLastError() == NTE_BAD_KEYSET) {
        if(!rv)
            rv = CryptAcquireContext(&cryptprovider, NULL,
                                      MS_ENHANCED_PROV, PROV_RSA_FULL,
                                      CRYPT_NEWKEYSET);
    }

    if (rv &&
        InterlockedCompareExchangePointer((PVOID *) &nr_cryptprovider,
                                          (PVOID) cryptprovider, 0) != 0) {

        CryptReleaseContext(cryptprovider, 0);
        cryptprovider = nr_cryptprovider;
    }

    return cryptprovider;
}

ssize_t nr_rand_bytes(uint8_t *data, size_t data_len)
{
	if (CryptGenRandom(nr_CryptProvider(), data_len, data))
		return 0;
	return data_len;
}
#else
ssize_t nr_rand_bytes(uint8_t *data, size_t data_len)
{
	static int fd = -1;
	
	if (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			nr_strerror_printf("Error opening randomness: %s",
					   strerror(errno));
			return 0;
		}
	}

	return read(fd, data, data_len);
}
#endif /* WIN32 */

uint32_t nr_rand(void)
{
	uint32_t lvalue;

	nr_rand_bytes((void *)&lvalue, sizeof(lvalue));
	return lvalue;
}


#ifndef USEC
#define USEC (1000000)
#endif

void nr_timeval_add(struct timeval *t, unsigned int seconds, unsigned int usec)
{
	t->tv_sec += seconds;
	t->tv_sec += usec / USEC;
	t->tv_usec += usec % USEC;
	if (t->tv_usec > USEC) {
		t->tv_sec++;
		t->tv_usec -= USEC;
	}
}

int nr_timeval_cmp(const struct timeval *a, const struct timeval *b)
{
	if (a->tv_sec > b->tv_sec) return +1;
	if (a->tv_sec < b->tv_sec) return -1;

	if (a->tv_usec > b->tv_usec) return +1;
	if (a->tv_usec < b->tv_usec) return -1;

	return 0;
}

