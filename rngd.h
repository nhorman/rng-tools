/*
 * rngd.h -- rngd globals
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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
 */

#ifndef RNGD__H
#define RNGD__H

#define _GNU_SOURCE

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>

#include "fips.h"

enum {
	MAX_RNG_FAILURES		= 25,
	RNG_OK_CREDIT			= 1000, /* ~1:1250 false positives */
};

/* Command line arguments and processing */
struct arguments {
	char *random_name;
	char *pid_file;

	int random_step;
	int fill_watermark;

	bool quiet;
	bool verbose;
	bool daemon;
	bool ignorefail;
	bool enable_drng;
	bool enable_tpm;
	int entropy_count;
};
extern struct arguments *arguments;

/* structures to store rng information */
struct rng {
	char *rng_name;
	int rng_fd;
	bool disabled;
	int failures;
	int success;

	int (*xread) (void *buf, size_t size, struct rng *ent_src);
	fips_ctx_t *fipsctx;

	struct rng *next;
};

/* Background/daemon mode */
extern bool am_daemon;			/* True if we went daemon */


/*
 * Routines and macros
 */
#define message(priority,fmt,args...) do { \
	if (am_daemon) { \
		syslog((priority), fmt, ##args); \
	} else { \
		fprintf(stderr, fmt, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

extern void src_list_add(struct rng *ent_src);
extern int write_pid_file(const char *pid_fn);
#endif /* RNGD__H */

