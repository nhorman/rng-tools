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

#define NSECS_IN_SECOND	1.0e9
#define MEGABITS		1048576
#define KILOBITS		1024

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

	bool debug;
	bool daemon;
	bool test;
	bool list;
	bool ignorefail;
	bool enable_drng;
	bool enable_tpm;
	int entropy_count;
	int force_reseed;
};
extern struct arguments *arguments;

/*
 * DRNG (RDRAND) Options
 */
enum {
	DRNG_OPT_AES = 0,
	DRNG_OPT_MAX,
};

/*
 * DARN Options
 */
enum {
	DARN_OPT_AES = 0,
	DARN_OPT_MAX,
};

/*
 * JITTER options
 */
enum {
	JITTER_OPT_THREADS = 0,
	JITTER_OPT_BUF_SZ = 1,
	JITTER_OPT_REFILL = 2,
	JITTER_OPT_RETRY_COUNT = 3,
	JITTER_OPT_RETRY_DELAY = 4,
	JITTER_OPT_USE_AES = 5,
	JITTER_OPT_MAX,
};

/*
 * PKCS11 options
 */
enum {
	PKCS11_OPT_ENGINE = 0,
	PKCS11_OPT_CHUNK = 1,
};

/*
 * NIST options
 */
enum {
	NIST_OPT_USE_AES = 0,
	NIST_OPT_MAX,
};

/*
 * RTLSDR options
 */
enum {
	RTLSDR_OPT_DEVID = 0,
	RTLSDR_OPT_FREQ_MIN = 1,
	RTLSDR_OPT_FREQ_MAX = 2,
	RTLSDR_OPT_SRATE_MIN = 3,
	RTLSDR_OPT_SRATE_MAX = 4,
	RTLSDR_OPT_MAX,
};

enum option_val_type {
	VAL_INT = 0,
	VAL_STRING = 1,
};

struct rng_option { 
	char *key;
	enum option_val_type type;
	union {
		int int_val;
		char *str_val;
	};
};

/* structures to store rng information */
struct rng {
	char *rng_name;
	char *rng_sname;
	char *rng_fname;
	int rng_fd;
	bool disabled;
	int failures;
	int success;
	size_t ent_gathered;
	struct flags {
		/* Slow sources - takes a long time to produce entropy */
		unsigned int slow_source : 1;
	} flags;
	int (*xread) (void *buf, size_t size, struct rng *ent_src);
	int (*init) (struct rng *ent_src);
	void (*close) (struct rng *end_src);
	fips_ctx_t *fipsctx;
	struct rng_option *rng_options;
};

/* Background/daemon mode */
extern bool am_daemon;			/* True if we went daemon */

extern bool msg_squash;

extern bool quiet;
/*
 * Routines and macros
 */
#define message(priority,fmt,args...) do { \
	if (quiet) \
		break;\
	if (arguments->debug == false && LOG_PRI(priority) == LOG_DEBUG) \
		break;\
	if (am_daemon) { \
		syslog((priority), fmt, ##args); \
	} else if (!msg_squash) { \
		fprintf(stderr, fmt, ##args); \
		fflush(stderr); \
	} \
} while (0)

#define message_entsrc(src, priority, fmt, args...) do { \
	if (quiet) \
		break; \
	size_t ____neededpfx = snprintf(NULL, 0, "[%-6s]: ", src->rng_sname); \
	size_t ____neededmsg = snprintf(NULL, 0, fmt, ##args) + 1; \
	char *____buf = malloc(____neededpfx + ____neededmsg); \
	sprintf(____buf, "[%-6s]: " fmt, src->rng_sname, ##args); \
	message(priority, "%s", ____buf); \
	free(____buf); \
} while (0)

extern bool do_reseed;
extern volatile bool server_running;
extern int write_pid_file(const char *pid_fn);
#endif /* RNGD__H */

