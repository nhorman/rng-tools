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

#ifndef HAVE_LIBGCRYPT
#error power DARN support requires libgcrypt!
#endif

#include <stdlib.h>
#include <limits.h>
#include <sys/auxv.h>
#include <gcrypt.h>


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
static int refill_rand(struct rng *ent_src);
static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied);

#define AES_BLOCK 16
#define CHUNK_SIZE AES_BLOCK * 8
#define THRESH_BITS 14

static gcry_cipher_hd_t gcry_cipher_hd;
static unsigned char iv_buf[AES_BLOCK];

static unsigned char darn_rand_buf[CHUNK_SIZE];
static size_t darn_buf_avail = 0;
static size_t darn_buf_ptr = CHUNK_SIZE - 1;

static size_t rekey_thresh = (1 << THRESH_BITS);
static size_t rand_bytes_served = 0;

static int init_gcrypt(struct rng *ent_src)
{
	unsigned char key[AES_BLOCK];
	unsigned char xkey[AES_BLOCK];
	int i;
	uint64_t darn_val;
	gcry_error_t gcry_error;

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

	gcry_error = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
				      GCRY_CIPHER_MODE_CBC, 0);

	if (!gcry_error)
		gcry_error = gcry_cipher_setkey(gcry_cipher_hd, key, AES_BLOCK);

	if (!gcry_error) {
		/*
		 * Only need the first 16 bytes of iv_buf. AES-NI can
		 * encrypt multiple blocks in parallel but we can't.
		 */
		gcry_error = gcry_cipher_setiv(gcry_cipher_hd, iv_buf, AES_BLOCK);
	}

	if (gcry_error) {
		message(LOG_DAEMON|LOG_ERR,
			"could not set key or IV: %s\n",
			gcry_strerror(gcry_error));
		gcry_cipher_close(gcry_cipher_hd);
		return 1;
	}

	rand_bytes_served = 0;
	if (refill_rand(ent_src))
		return 1;
	if (copy_avail_rand_to_buf((unsigned char *)&rekey_thresh, sizeof(size_t), 0) < sizeof(size_t))
		return 1;
	rekey_thresh &= ((1 << THRESH_BITS)-1);
	
	return 0;
}

static int refill_rand(struct rng *ent_src)
{
	gcry_error_t gcry_error;
	int i;

	if (darn_buf_avail)
		return 0;
	if (ent_src->options[DARN_USE_AES].int_val) {
		if (rand_bytes_served >= rekey_thresh) {
			message(LOG_DAEMON|LOG_DEBUG, "rekeying DARN rng\n");
			gcry_cipher_close(gcry_cipher_hd);
			if (init_gcrypt(ent_src))
				return 1;
		}

		gcry_error = gcry_cipher_encrypt(gcry_cipher_hd, darn_rand_buf,
						CHUNK_SIZE, NULL, 0);

		if (gcry_error) {
			message(LOG_DAEMON | LOG_ERR,
				"gcry_cipher_encrypt_error: %s\n",
				gcry_strerror(gcry_error));
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
	uint64_t darn_val;
	size_t copied = 0;

	while (copied < size) {
		if (refill_rand(ent_src)) {
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
		return 1;
	}

	if (init_gcrypt(ent_src))
		return 1;
	message(LOG_DAEMON|LOG_INFO, "Enabling power DARN rng support\n");
	return 0;
}
