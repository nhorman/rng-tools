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

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"
#include "ossl_helpers.h"

#define min(x,y) ({ \
	typeof(x) _x = (x);     \
	typeof(y) _y = (y);     \
	(void) (&_x == &_y);    \
	_x < _y ? _x : _y; })

static uint64_t get_darn();
static int refill_rand(struct rng *ent_src, bool allow_reinit);
static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied);

#define CHUNK_SIZE		(AES_BLOCK*8)
#define RDRAND_ROUNDS		512		/* 512:1 data reduction */
#define THRESH_BITS		14

/* ossl AES context */
static struct ossl_aes_ctx *ossl_ctx;
static unsigned char key[AES_BLOCK];
static unsigned char iv_buf[AES_BLOCK];

static unsigned char darn_rand_buf[CHUNK_SIZE];
static size_t darn_buf_avail = 0;
static size_t darn_buf_ptr = CHUNK_SIZE - 1;

static size_t rekey_thresh = 0;
static size_t rand_bytes_served = 0;

static int init_openssl(struct rng *ent_src)
{
	uint64_t darn_val;

	ossl_aes_random_key(key, NULL);

	darn_val = get_darn();
	if (darn_val == ULONG_MAX)
		return 1;
	memcpy(&iv_buf[0], &darn_val, sizeof(uint64_t));
	
	darn_val = get_darn();
	if (darn_val == ULONG_MAX)
		return 1;
	memcpy(&iv_buf[8], &darn_val, sizeof(uint64_t));

	if (ossl_ctx != NULL)
		ossl_aes_exit(ossl_ctx);
	ossl_ctx = ossl_aes_init(key, iv_buf);
	if (!ossl_ctx)
		return 1;
	rand_bytes_served = 0;
	if (refill_rand(ent_src, false))
		return 1;
	if (copy_avail_rand_to_buf((unsigned char *)&rekey_thresh, sizeof(size_t), 0) < sizeof(size_t))
		return 1;
	rekey_thresh &= ((1 << THRESH_BITS)-1);
	
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

		if (ossl_aes_mangle(ossl_ctx, darn_rand_buf, CHUNK_SIZE) < 0)
			return 1;
	} else {
		uint64_t *ptr = (uint64_t *)darn_rand_buf;
		for (i = 0; i < CHUNK_SIZE/sizeof(uint64_t); i++) {
			*ptr = get_darn();
			if (*ptr == ULONG_MAX)
				return 1;
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
 * Runs get_darn_impl(), returns ULONG_MAX on error
 */

extern uint64_t get_darn_impl();

static uint64_t get_darn()
{
	uint64_t darn_val;
	int i;

	/*
	 * For loop is taken from PowerISA_public.v3.0B
	 * programming guide
	 */
	for (i=0; i < 10; i++) {
		darn_val = get_darn_impl();
		if (darn_val != ULONG_MAX)
			break;
	}

	return darn_val;
}


int xread_darn(void *buf, size_t size, struct rng *ent_src)
{
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
