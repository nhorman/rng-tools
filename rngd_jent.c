/*
 * Copyright (c) 2018, Stephan Mueller
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

#include <jitterentropy.h>

#include "rngd.h"
#include "rngd_entsource.h"

#define JENT_OSR	1

static struct rand_data *jent = NULL;

int xread_jent(void *buf, size_t size, struct rng *ent_src)
{
printf("JENT %u\n", size);
	int ret = jent_read_entropy(jent, (char *)buf, size);

	(void)ent_src;

	if (ret < 0)
		return ret;
	return 0;
}

int init_jent_entropy_source(struct rng *ent_src)
{
	int rc;

	(void)ent_src;
	rc = jent_entropy_init();
	if (rc) {
		message(LOG_DAEMON|LOG_WARNING, "WARNING: CPU Jitter RNG "
						"non-operational as CPU does "
						"not provide expected "
						"capabilities\n");
	}

	jent = jent_entropy_collector_alloc(JENT_OSR, 0);
	if (!jent)
		return -ENOMEM;

	return rc;
}
