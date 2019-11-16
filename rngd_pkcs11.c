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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <libp11.h>
#include "rngd.h"
#include "rngd_entsource.h"

static PKCS11_CTX *ctx = NULL;
static PKCS11_SLOT *slots, *slot;
static unsigned int nslots;

int xread_pkcs11(void *buf, size_t size, struct rng *ent_src)
{
	int rc;
	int count = ent_src->rng_options[PKCS11_OPT_CHUNK].int_val;
	int chunk_len = size / count;
	size_t left = size;
	void *ptr = buf;

	/* If our count is greater than our size */
	if (!chunk_len)
		chunk_len = left;

	while (left > 0) {
		if (left > chunk_len) {
			rc = PKCS11_generate_random(slot, ptr, chunk_len);
			ptr += chunk_len;
			left -= chunk_len;
		} else {
			rc = PKCS11_generate_random(slot, ptr, left);
			left = 0;
		}

		if (rc < 0)
			return 1;
	}

	return 0;
}

int validate_pkcs11_options(struct rng *ent_src)
{
	struct stat sbuf;

	if (stat(ent_src->rng_options[PKCS11_OPT_ENGINE].str_val, &sbuf) == -1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "PKCS11 Engine %s Error: %s\n",
			ent_src->rng_options[PKCS11_OPT_ENGINE].str_val,
			strerror(errno));
		return 1;
	}

	if (!ent_src->rng_options[PKCS11_OPT_CHUNK].int_val) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "PKCS11 Engine chunk size cannot be 0\n");
		return 1;
	}
	
	if (ent_src->rng_options[PKCS11_OPT_CHUNK].int_val > FIPS_RNG_BUFFER_SIZE) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "PKCS11 Engine chunk size cannot be larger than %d\n",
			FIPS_RNG_BUFFER_SIZE);
		return 1;
	}
	
	return 0;
}

/*
 * Init PKCS11
 */
int init_pkcs11_entropy_source(struct rng *ent_src)
{
	ctx = PKCS11_CTX_new();
	int rc;

	if (validate_pkcs11_options(ent_src))
		return 1;

	if (!ctx) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "Unable to allocate new pkcs11 context\n");
		return 1;
	}

	rc = PKCS11_CTX_load(ctx, ent_src->rng_options[PKCS11_OPT_ENGINE].str_val);
	if (rc) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "Unable to load pkcs11 engine: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		rc = 1;
		goto free_ctx;
	}

	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rc < 0) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "No pkcs11 slots available\n");
		rc = 1;
		goto unload_engine;
	}

	slot = PKCS11_find_token(ctx, slots, nslots);
	if (slot == NULL || slot->token == NULL) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "No pkcs11 tokens available\n");
		rc = 1;
		goto release_slots;
	}

	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot manufacturer......: %s\n", slot->manufacturer);
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot description.......: %s\n", slot->description);
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot token label.......: %s\n", slot->token->label);
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot token manufacturer: %s\n", slot->token->manufacturer);
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot token model.......: %s\n", slot->token->model);
	message_entsrc(ent_src,LOG_DAEMON|LOG_INFO, "Slot token serial......: %s\n", slot->token->serialnr);

	rc = 0;
	goto out;

release_slots:
	PKCS11_release_all_slots(ctx, slots, nslots);
unload_engine:
	PKCS11_CTX_unload(ctx);
free_ctx:
	PKCS11_CTX_free(ctx);
out:
	return rc;
}

void close_pkcs11_entropy_source(struct rng *ent_src)
{
	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);
	return;
}

