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

#include <jitterentropy.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

struct rand_data *ec = NULL;

int xread_jitter(void *buf, size_t size, struct rng *ent_src)
{
	size_t ret;
	ret = jent_read_entropy(ec, buf, size);
	if (ret < 0) {
		message(LOG_DAEMON|LOG_DEBUG, "JITTER rng fails with code %d\n", ret);
		return 1;
	}
	return 0;
}

/*
 * Init JITTER
 */
int init_jitter_entropy_source(struct rng *ent_src)
{
	int ret = jent_entropy_init();
	if(ret) {
		message(LOG_DAEMON|LOG_WARNING, "JITTER rng fails with code %d\n", ret);
		return 1;
	}

	ec = jent_entropy_collector_alloc(1, 0);
	if (!ec) {
		message(LOG_DAEMON|LOG_WARNING, "JITTER RNG COULD NOT BE ALLOCATED\n");
		return 1;
	}
	
	message(LOG_DAEMON|LOG_INFO, "Enabling JITTER rng support\n");
	return 0;
}

void close_jitter_entropy_source(struct rng *ent_src)
{
	if (ec) {
		jent_entropy_collector_free(ec);
		ec = NULL;
	}
	return;
}

