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
 * Copyright (C) 2001 Philipp Rumpf <prumpf@mandrakesoft.com>
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

#ifdef HAVE_CONFIG_H
#  include "rng-tools-config.h"
#endif

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


/*
 * argp stuff
 */


const char *argp_program_version = "rngd " VERSION;
const char *argp_program_bug_address = "Philipp Rumpf <prumpf@mandrakesoft.com>";

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
	rng_name:	"/dev/hwrandom",
	random_name:	"/dev/random",
	poll_timeout:	60,
	random_step:	64,
	daemon:		1,
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


/*
 * FIPS test
 */


/*
 * number of bytes required for a FIPS test.
 * do not alter unless you really, I mean
 * REALLY know what you are doing.
 */
#define FIPS_THRESHOLD 2500

/* These are the startup tests suggested by the FIPS 140-1 spec section
*  4.11.1 (http://csrc.nist.gov/fips/fips1401.htm)
*  The Monobit, Poker, Runs, and Long Runs tests are implemented below.
*  This test is run at periodic intervals to verify
*  data is sufficiently random. If the tests are failed the RNG module
*  will no longer submit data to the entropy pool, but the tests will
*  continue to run at the given interval. If at a later time the RNG
*  passes all tests it will be re-enabled for the next period.
*   The reason for this is that it is not unlikely that at some time
*  during normal operation one of the tests will fail. This does not
*  necessarily mean the RNG is not operating properly, it is just a
*  statistically rare event. In that case we don't want to forever
*  disable the RNG, we will just leave it disabled for the period of
*  time until the tests are rerun and passed.
*
*  For argument sake I tested /dev/urandom with these tests and it
*  took 142,095 tries before I got a failure, and urandom isn't as
*  random as random :)
*/

static int poker[16], runs[12];
static int ones, rlength = -1, current_bit, longrun;

/*
 * rng_fips_test_store - store 8 bits of entropy in FIPS
 * 			 internal test data pool
 */
static void rng_fips_test_store (int rng_data)
{
	int j;
	static int last_bit = 0;

	poker[rng_data >> 4]++;
	poker[rng_data & 15]++;

	/* Note in the loop below rlength is always one less than the actual
	   run length. This makes things easier. */
	for (j = 7; j >= 0; j--) {
		ones += current_bit = (rng_data & 1 << j) >> j;
		if (current_bit != last_bit) {
			/* If runlength is 1-6 count it in correct bucket. 0's go in
			   runs[0-5] 1's go in runs[6-11] hence the 6*current_bit below */
			if (rlength < 5) {
				runs[rlength +
				     (6 * current_bit)]++;
			} else {
				runs[5 + (6 * current_bit)]++;
			}

			/* Check if we just failed longrun test */
			if (rlength >= 33)
				longrun = 1;
			rlength = 0;
			/* flip the current run type */
			last_bit = current_bit;
		} else {
			rlength++;
		}
	}
}

/*
 * now that we have some data, run a FIPS test
 */
static int rng_run_fips_test (unsigned char *buf)
{
	int i, j;
	int rng_test = 0;

	for (i=0; i<FIPS_THRESHOLD; i++) {
		rng_fips_test_store(buf[i]);
	}

	/* add in the last (possibly incomplete) run */
	if (rlength < 5)
		runs[rlength + (6 * current_bit)]++;
	else {
		runs[5 + (6 * current_bit)]++;
		if (rlength >= 33)
			rng_test |= 8;
	}
	
	if (longrun) {
		rng_test |= 8;
		longrun = 0;
	}

	/* Ones test */
	if ((ones >= 10346) || (ones <= 9654))
		rng_test |= 1;
	/* Poker calcs */
	for (i = 0, j = 0; i < 16; i++)
		j += poker[i] * poker[i];
	if ((j >= 1580457) || (j <= 1562821))
		rng_test |= 2;
	if ((runs[0] < 2267) || (runs[0] > 2733) ||
	    (runs[1] < 1079) || (runs[1] > 1421) ||
	    (runs[2] < 502) || (runs[2] > 748) ||
	    (runs[3] < 223) || (runs[3] > 402) ||
	    (runs[4] < 90) || (runs[4] > 223) ||
	    (runs[5] < 90) || (runs[5] > 223) ||
	    (runs[6] < 2267) || (runs[6] > 2733) ||
	    (runs[7] < 1079) || (runs[7] > 1421) ||
	    (runs[8] < 502) || (runs[8] > 748) ||
	    (runs[9] < 223) || (runs[9] > 402) ||
	    (runs[10] < 90) || (runs[10] > 223) ||
	    (runs[11] < 90) || (runs[11] > 223)) {
		rng_test |= 4;
	}
	
	rng_test = !rng_test;

	/* finally, clear out FIPS variables for start of next run */
	memset (poker, 0, sizeof (poker));
	memset (runs, 0, sizeof (runs));
	ones = 0;
	rlength = -1;
	current_bit = 0;

	return rng_test;
}

static void xread(int fd, void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size && (r = read(fd, buf + off, size)) > 0) {
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
	unsigned char buf[FIPS_THRESHOLD];
	unsigned char *p;
	int fips;

	for (;;) {
		xread(rng_fd, buf, sizeof buf);

		fips = rng_run_fips_test(buf);

		if (!fips) {
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

	do_loop(rng_fd, random_fd, arguments->random_step,
		arguments->poll_timeout ? : -1.0);

	return 0;
}
