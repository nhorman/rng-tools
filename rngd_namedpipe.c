/*
 * rngd_namedpipe.c -- Named pipe entropy input
 *
 * Copyright (C) 2023 Gerd v. Egidy
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
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
#include <stddef.h>
#include <sys/select.h>
#include <sys/time.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"


/* Read data from named pipes, with timeout & reopening */
int xread_namedpipe(void *buf, size_t size, struct rng *ent_src)
{
	size_t off = 0;
	ssize_t r;
	int sr;
	
	fd_set readfds;
	int maxfds;

	// we init the timeout structure once, select will reduce it when it was waiting
	struct timeval tval;
	tval.tv_sec = ent_src->rng_options[NAMEDPIPE_OPT_TIMEOUT].int_val;
	tval.tv_usec = 0;
    
	while (size > 0) {
		// prepare fd set for select
		FD_ZERO(&readfds);
		if (ent_src->rng_fd >= FD_SETSIZE) {
			message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "file descriptor exceeds FD_SETSIZE limit\n");
			return -1;
		}
		FD_SET(ent_src->rng_fd, &readfds);
		maxfds = ent_src->rng_fd + 1;

		sr = select (maxfds, &readfds, NULL, NULL, &tval);
		if (sr == 1) {
			// our fd has something to read
			r = read(ent_src->rng_fd, buf + off, size);
			
			if (r > 0) {
				// we could read something
				off += r;
				size -= r;
				continue;
			} else if (r == 0) {
				// EOF: try to re-open the pipe
				message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "EOF, reopening named pipe\n");
				close(ent_src->rng_fd);
				ent_src->rng_fd = open(ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val, O_RDONLY | O_NOCTTY | O_NONBLOCK);
				if (ent_src->rng_fd == -1) {
						message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "Unable to open named pipe (%i): %s\n", errno, 
								ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val);
					ent_src->disabled = true;
					return -1;
				}
				continue;
			} else {
				// read error
				if (errno == EINTR || errno == EAGAIN)
					continue;
				message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "read error (%i)\n", errno);
				return -1;
			}
		} else if (sr == 0) {
			message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "timeout\n");
			return -1;
		} else {
			// select error
			if (errno == EINTR)
				continue;
			
			message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "select error %i\n", errno);
			return -1;
		}
	}
	return 0;
}

/*
 * init named pipe entropy source: check option and open pipe
 */
int init_namedpipe_entropy_source(struct rng *ent_src)
{
	char buf[16];
    
	if (!ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val ||
		strlen(ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val) == 0)
	{
		message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "No named pipe path configured\n");
		return 1;
	}

	ent_src->rng_fd = open(ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val, O_RDONLY | O_NOCTTY | O_NONBLOCK);
	if (ent_src->rng_fd == -1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "Unable to open named pipe (%i): %s\n", errno, 
			       ent_src->rng_options[NAMEDPIPE_OPT_PATH].str_val);
		return 1;
	}

	/* Try to read some data from the entropy source. */
	if (ent_src->xread(buf, sizeof(buf), ent_src) != 0)
		return -1;

	/* the read didn't return an error -> assume its ok to use */
	
	/* Bootstrap FIPS tests */
	ent_src->fipsctx = malloc(sizeof(fips_ctx_t));
	return 0;
}

