/*
 * Copyright (c) 2021, Benjamin Herrenschmidt and
 *                     Balbir Singh, Amazon.com, Inc. or its affiliates
 *
 * Loosely based on rngd_darn.c: Copyright (c) 2017, Neil Horman
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
#include <unistd.h>
#include <sys/auxv.h>


#include "rngd.h"
#include "rngd_entsource.h"
#include "ossl_helpers.h"

/* Kernel headers may be too old */
#ifndef HWCAP2_RNG
#define HWCAP2_RNG          (1 << 16)
#endif

static struct ossl_aes_ctx *ossl_ctx;
static unsigned char key[AES_BLOCK];
static unsigned char iv_buf[AES_BLOCK];

#define CHUNK_SIZE (AES_BLOCK*8)
static unsigned char aes_buf[CHUNK_SIZE];
static size_t aes_buf_pos;
#define REKEY_BITS 8
static int rekey_count;

/*
 * Runs the get_rndr instruction, returns false on failure
 */
static bool get_rndr(uint64_t *rndr_val)
{
	bool ok;
	int i;

	/* Let's try 10 times, that should be enough, before we give up */
	for (i=0; i < 10; i++){
		asm volatile("mrs %0, s3_3_c2_c4_0\n"
			     "\tcset %w1, ne\n"
			     : "=r" (*rndr_val), "=r" (ok)
			     :
			     : "cc");
		if (ok)
			break;
		/*
		 * The spec implies we should wait some milliseconds for HW
		 * to recover... Let's try up to 10 times with 1ms delay
		 */
		usleep(1000);
	}
	return ok;
}

static int get_random_key(unsigned char *out_key)
{
	uint64_t val1, val2;

	if (!get_rndr(&val1) || !get_rndr(&val2))
		return 1;
	memcpy(&out_key[0], &val1, sizeof(uint64_t));
	memcpy(&out_key[8], &val2, sizeof(uint64_t));
	return 0;
}

static int rekey(struct rng *ent_src)
{
	uint64_t thr;

	message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Rekeying...\n");

	/* Grab new key & iv_buf from HW */
	if (get_random_key(key) || get_random_key(iv_buf))
		return 1;

	/* Grab a new 8 bits random rekey threshold, we thus
	 * rekey every 1 to 255 refills
	 */
	memcpy(&rekey_count, key, sizeof(rekey_count));
	rekey_count &= ((1 << REKEY_BITS)-1);
	return 0;
}

static int refill(struct rng *ent_src)
{
	message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Refilling...\n");
	if (--rekey_count < 0 && rekey(ent_src)) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG,
			       "failed to get AES seed randomness\n");
		return 1;
	}

	/* Re-mangle the buffer */
	aes_buf_pos = 0;
	return ossl_aes_mangle(ossl_ctx, aes_buf, CHUNK_SIZE) < 0;
}

static int fill_from_aes(struct rng *ent_src, void *buf, size_t size)
{
	size_t chunk, avail, i;

	for (i = 0; i < size; i += chunk) {
		avail = CHUNK_SIZE - aes_buf_pos;
		chunk = size <= avail ? size : avail;
		memcpy(buf + i, &aes_buf[aes_buf_pos], chunk);
		aes_buf_pos += chunk;
		if (aes_buf_pos == CHUNK_SIZE && refill(ent_src))
			return 1;
	}
	return 0;
}

static int init_openssl(struct rng *ent_src)
{
	ossl_ctx = ossl_aes_init(key, iv_buf);
	if (ossl_ctx == NULL) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG,
			       "openssl initialization failed\n");
		return 1;
	}
	return refill(ent_src);
}

static int fill_from_rndr(void *buf, size_t size)
{
	uint64_t r;
	size_t chunk;

	while (size) {
		/* Grab 64-bits */
		if (!get_rndr(&r))
			return 1;

		/* This is endian-broken but who cares for random
		 * numbers ?
		 */
		chunk = size > 8 ? 8 : size;
		memcpy(buf, &r, chunk);
		size -= chunk;
		buf += chunk;
	}
	return 0;
}

int xread_rndr(void *buf, size_t size, struct rng *ent_src)
{
	if (ent_src->rng_options[DRNG_OPT_AES].int_val)
		return fill_from_aes(ent_src, buf, size);
	else
		return fill_from_rndr(buf, size);
}

/*
 * Confirm RNDR capabilities for drng entropy source
 */
int init_rndr_entropy_source(struct rng *ent_src)
{
	if (!(getauxval(AT_HWCAP2) & HWCAP2_RNG)) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "No HW SUPPORT\n");
		return 1;
	}
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Enabling aarch64 RNDR rng support\n");
	if (ent_src->rng_options[DRNG_OPT_AES].int_val && init_openssl(ent_src))
		return 1;
	return 0;
}
