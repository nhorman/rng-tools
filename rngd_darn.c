/*
 * Copyright (c) 2017, Neil Horman 
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"


#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/auxv.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

#define min(x,y) ({ \
	typeof(x) _x = (x);     \
	typeof(y) _y = (y);     \
	(void) (&_x == &_y);    \
	_x < _y ? _x : _y; })

static uint64_t get_darn();
static int refill_rand(struct rng *ent_src, bool allow_reinit);
static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied);

#define AES_BLOCK 16
#define CHUNK_SIZE AES_BLOCK * 8
#define RDRAND_ROUNDS		512		/* 512:1 data reduction */

static unsigned char key[AES_BLOCK] = {
	0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
	0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0
}; /* AES data reduction key */

#define THRESH_BITS 14

static EVP_CIPHER_CTX *ctx = NULL;
static unsigned char iv_buf[AES_BLOCK];

static unsigned char darn_rand_buf[CHUNK_SIZE];
static size_t darn_buf_avail = 0;
static size_t darn_buf_ptr = CHUNK_SIZE - 1;

static size_t rekey_thresh = 0;
static size_t rand_bytes_served = 0;

static int init_openssl(struct rng *ent_src)
{
	unsigned char xkey[AES_BLOCK];
	int i;
	uint64_t darn_val;

	/*
	 * Use stack junk to create a key, shuffle it a bit
	 */
	for (i=0; i< sizeof(key); i++)
		key[i] ^= xkey[i];

	darn_val = get_darn();
	if (darn_val == ULONG_MAX)
		return 1;
	memcpy(&iv_buf[0], &darn_val, sizeof(uint64_t));
	
	darn_val = get_darn();
	if (darn_val == ULONG_MAX)
		return 1;
	memcpy(&iv_buf[8], &darn_val, sizeof(uint64_t));

	if (ctx != NULL) {
		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);
	}
        if(!(ctx = EVP_CIPHER_CTX_new()))
                return 1;

	rand_bytes_served = 0;
	if (refill_rand(ent_src, false))
		return 1;
	if (copy_avail_rand_to_buf((unsigned char *)&rekey_thresh, sizeof(size_t), 0) < sizeof(size_t))
		return 1;
	rekey_thresh &= ((1 << THRESH_BITS)-1);
	
	return 0;
}

static int osslencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
        int len;

        int ciphertext_len;

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                return 0;
        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                return 0;

        ciphertext_len = len;

        /*
        * Finalise the encryption. Further ciphertext bytes may be written at
        * this stage.
        */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                return 0;
        ciphertext_len += len;

	return ciphertext_len;
}

static inline int openssl_mangle(unsigned char *tmp, size_t size, struct rng *ent_src)
{
        int ciphertext_len;

        /*
        * Buffer for ciphertext. Ensure the buffer is long enough for the
        * ciphertext which may be longer than the plaintext, depending on the
        * algorithm and mode.
        */
        unsigned char ciphertext[CHUNK_SIZE * RDRAND_ROUNDS];

        /* Encrypt the plaintext */
        ciphertext_len = osslencrypt (tmp, size, key, iv_buf,
                              ciphertext);
        if (!ciphertext_len)
                return -1;

        memcpy(tmp, ciphertext, size);
        return 0;
}

static int refill_rand(struct rng *ent_src, bool allow_reinit)
{
	int i;

	if (darn_buf_avail)
		return 0;
	if (ent_src->rng_options[DARN_OPT_AES].int_val) {
		if (allow_reinit && (rand_bytes_served >= rekey_thresh)) {
			message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "rekeying DARN rng\n");
			if (init_openssl(ent_src))
				return 1;
		}

		if (openssl_mangle(darn_rand_buf, CHUNK_SIZE, ent_src)) {
			return 1;
		}
	} else {
		uint64_t *ptr = (uint64_t *)darn_rand_buf;
		for (i = 0; i < CHUNK_SIZE/sizeof(uint64_t); i++) {
			*ptr = get_darn();
			ptr++;
		}
	}

	darn_buf_avail = CHUNK_SIZE;
	darn_buf_ptr = 0;
	return 0;
}

static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied)
{
	size_t left_to_copy = size - copied;
	size_t to_copy = min(left_to_copy, darn_buf_avail);

	memcpy(&buf[copied], &darn_rand_buf[darn_buf_ptr], to_copy);

	darn_buf_avail -= to_copy;
	darn_buf_ptr += to_copy;
	rand_bytes_served += to_copy;
	return to_copy;
}

/*
 * Runs the get_darn instruction, returns ULONG_MAX on error
 */
static uint64_t get_darn()
{
	uint64_t darn_val;
	darn_val = 0;
	int i;

	/*
	 * For loop is taken from PowerISA_public.v3.0B 
	 * programming guide
	 */
	for (i=0; i < 10; i++){
		asm volatile("darn %0, 1" : "=r" (darn_val) );
		if (darn_val != ULONG_MAX)
			break;
	}

	return darn_val;
}


int xread_darn(void *buf, size_t size, struct rng *ent_src)
{
	uint64_t *darn_ptr =(uint64_t *)buf;
	size_t copied = 0;

	while (copied < size) {
		if (refill_rand(ent_src, true)) {
			return 1;
		}
		copied += copy_avail_rand_to_buf(buf, size, copied);
	}
	return 0;
}

/*
 * Confirm DARN capabilities for drng entropy source
 */
int init_darn_entropy_source(struct rng *ent_src)
{

	if (!(getauxval(AT_HWCAP2) & PPC_FEATURE2_DARN)) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "No HW SUPPORT\n");
		return 1;
	}

	if (refill_rand(ent_src, true))
		return 1;

	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Enabling power DARN rng support\n");
	return 0;
}
