/*
 * rngd.c -- Random Number Generator daemon
 *
 * rngd reads data from a hardware random number generator, verifies it
 * looks like random data, and adds it to /dev/random's entropy store.
 * 
 * In theory, this should allow you to read very quickly from
 * /dev/random; rngd also adds bytes to the entropy store periodically
 * when it's full, which makes predicting the entropy store's contents
 * harder.
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

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/types.h>
#include <linux/random.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include <syslog.h>

#include "fips.h"

/*
 * argp stuff
 */


const char *argp_program_version = "rngd " VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] = "rngd";

static struct argp_option options[] = {
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for random number output (default: /dev/random)" },

	{ "rng-device", 'r', "file", 0,
	  "Kernel device used for random number input (default: /dev/hwrandom)" },

	{ "random-step", 's', "nnn", 0,
	  "Number of bytes written to random-device at a time (default: 64)" },

	{ "timeout", 't', "nnn", 0,
	  "Interval written to random-device when the entropy pool is full, in seconds (default: 60)" },

	{ 0 },
};

struct arguments {
	char *random_name;
	char *rng_name;
	
	int random_step;
	double poll_timeout;

	int daemon;
};

static struct arguments default_arguments = {
	.rng_name	= "/dev/hwrandom",
	.random_name	= "/dev/random",
	.poll_timeout	= 60,
	.random_step	= 64,
	.daemon		= 1,
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	
	switch(key) {
	case 'o':
		arguments->random_name = arg;
		break;
	case 'r':
		arguments->rng_name = arg;
		break;
	case 't': {
		float f;
		if (sscanf(arg, "%f", &f) == 0)
			argp_usage(state);
		else
			arguments->poll_timeout = f;
		break;
	}

	case 'f':
		arguments->daemon = 0;
		break;
	case 'b':
		arguments->daemon = 1;
		break;
	case 's':
		if (sscanf(arg, "%i", &arguments->random_step) == 0)
			argp_usage(state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

/* Logic and contexts */
static fips_ctx_t fipsctx;		/* Context for the FIPS tests */


/*
 * daemon abstraction
 */


static int am_daemon;

#define message(priority,fmt,args...) do { \
	if (am_daemon) { \
		syslog((priority), fmt, ##args); \
	} else { \
		fprintf(stderr, fmt, ##args); \
	} \
} while (0)



static void xread(int fd, void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size > 0) {
		do {
			r = read(fd, buf + off, size);
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

static void random_add_entropy(int fd, void *buf, size_t size)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;

	entropy.ent_count = size * 8;
	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(fd, RNDADDENTROPY, &entropy) != 0) {
		message(LOG_DAEMON|LOG_ERR, "RNDADDENTROPY failed: %s\n",
			strerror(errno));
		exit(1);
	}
}

static void random_sleep(int fd, double poll_timeout)
{
	struct {
		int ent_count;
		int pool_size;
	} pool = { 0, };
	struct pollfd pfd = {
		fd:	fd,
		events:	POLLOUT,
	};

	if (ioctl(fd, RNDGETPOOL, &pool) == 0 &&
	    pool.ent_count/8 < pool.pool_size*4)
		return;
	
	poll(&pfd, 1, 1000.0 * poll_timeout);
}

static void do_loop(int rng_fd, int random_fd, int random_step,
		    double poll_timeout)
{
	unsigned char buf[FIPS_RNG_BUFFER_SIZE];
	unsigned char *p;
	int fips;

	for (;;) {
		xread(rng_fd, buf, sizeof buf);

		fips = fips_run_rng_test(&fipsctx, buf);

		if (fips) {
			message(LOG_DAEMON|LOG_ERR, "failed fips test\n");
			sleep(1);
			continue;
		}

		for (p = buf; p + random_step <= &buf[sizeof buf];
		     p += random_step) {
			random_add_entropy(random_fd, p, random_step);
			random_sleep(random_fd, poll_timeout);
		}
	}
}


/* Initialize entropy source */
static int discard_initial_data(int fd)
{
	/* Trash 32 bits of what is probably stale (non-random)
	 * initial state from the RNG.  For Intel's, 8 bits would
	 * be enough, but since AMD's generates 32 bits at a time...
	 * 
	 * The kernel drivers should be doing this at device powerup,
	 * but at least up to 2.4.24, it doesn't. */
	unsigned char tempbuf[4];
	xread(fd, tempbuf, sizeof tempbuf);

	/* Return 32 bits of bootstrap data */
	xread(fd, tempbuf, sizeof tempbuf);

	return tempbuf[0] | (tempbuf[1] << 8) | 
		(tempbuf[2] << 16) | (tempbuf[3] << 24);
}


int main(int argc, char **argv)
{
	int rng_fd;
	int random_fd;
	struct arguments *arguments = &default_arguments;

	argp_parse(&argp, argc, argv, 0, 0, arguments);

	rng_fd = open(arguments->rng_name, O_RDONLY);

	if (rng_fd < 0) {
		message(LOG_DAEMON|LOG_ERR, "can't open RNG file %s: %s\n",
			arguments->rng_name, strerror(errno));
		exit(1);
	}
	
	random_fd = open(arguments->random_name, O_RDWR);

	if (random_fd < 0) {
		message(LOG_DAEMON|LOG_ERR, "can't open random file %s: %s\n",
			arguments->random_name, strerror(errno));
		exit(1);
	}

	if (arguments->daemon) {
		am_daemon = 1;

		if (daemon(0, 0) < 0) {
			fprintf(stderr, "can't daemonize: %s\n",
				strerror(errno));
			return 1;
		}

		openlog("rngd", 0, LOG_DAEMON);
	}

	/* Bootstrap FIPS tests */
	fips_init(&fipsctx, discard_initial_data(rng_fd));

	do_loop(rng_fd, random_fd, arguments->random_step,
		arguments->poll_timeout ? : -1.0);

	return 0;
}
