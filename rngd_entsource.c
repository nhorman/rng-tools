/*
 * rngd_entsource.c -- Entropy source and conditioning
 *
 * Copyright (C) 2001 Philipp Rumpf
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"


/* Logic and contexts */
static int rng_fd;			/* rng data source */
fips_ctx_t fipsctx;			/* Context for the FIPS tests */


/* Read data from the entropy source */
void xread(void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size > 0) {
		do {
			r = read(rng_fd, buf + off, size);
		} while ((r == -1) && (errno == EINTR));
		if (r <= 0)
			break;
		off += r;
		size -= r;
	}

	if (size) {
		message(LOG_DAEMON|LOG_ERR, "read error\n");
		exit(1);
	}
}

/* Initialize entropy source */
static int discard_initial_data(void)
{
	/* Trash 32 bits of what is probably stale (non-random)
	 * initial state from the RNG.  For Intel's, 8 bits would
	 * be enough, but since AMD's generates 32 bits at a time...
	 * 
	 * The kernel drivers should be doing this at device powerup,
	 * but at least up to 2.4.24, it doesn't. */
	unsigned char tempbuf[4];
	xread(tempbuf, sizeof tempbuf);

	/* Return 32 bits of bootstrap data */
	xread(tempbuf, sizeof tempbuf);

	return tempbuf[0] | (tempbuf[1] << 8) | 
		(tempbuf[2] << 16) | (tempbuf[3] << 24);
}

/*
 * Open entropy source, and initialize it
 */
void init_entropy_source(const char* sourcedev)
{
	rng_fd = open(sourcedev, O_RDONLY);
	if (rng_fd == -1) {
		message(LOG_DAEMON|LOG_ERR, "can't open %s: %s",
			sourcedev, strerror(errno));
		exit(EXIT_FAIL);
	}

	/* Bootstrap FIPS tests */
	fips_init(&fipsctx, discard_initial_data());
}

