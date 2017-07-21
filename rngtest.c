/*
 * rngtest.c -- Random Number Generator FIPS 140-1/140-2 tests
 *
 * This program tests the input stream in stdin for randomness,
 * using the tests defined by FIPS 140-1/140-2 2001-10-10.
 *
 * Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <argp.h>
#include <signal.h>

#include "fips.h"
#include "stats.h"
#include "exits.h"

#define PROGNAME "rngtest"
const char* logprefix = PROGNAME ": ";

/*
 * argp stuff
 */

const char *argp_program_version =
	PROGNAME " " VERSION "\n"
	"Copyright (c) 2004 by Henrique de Moraes Holschuh\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

const char *argp_program_bug_address = PACKAGE_BUGREPORT;
error_t argp_err_exit_status = EXIT_USAGE;

static char doc[] =
	"Check the randomness of data using FIPS 140-2 RNG tests.\n"
	"\v"
	"FIPS tests operate on 20000-bit blocks.  Data is read from stdin.  Statistics "
	"and messages are sent to stderr.\n\n"
	"If no errors happen nor any blocks fail the FIPS tests, the program will return "
	"exit status 0.  If any blocks fail the tests, the exit status will be 1.\n";

static struct argp_option options[] = {
	{ "blockcount", 'c', "n", 0,
	  "Exit after processing n blocks (default: 0)" },

	{ "pipe", 'p', 0, 0,
	  "Enable pipe mode: work silently, and echo to stdout all good blocks" },

	{ "timedstats", 't', "n", 0,
	  "Dump statistics every n secods (default: 0)" },

	{ "blockstats", 'b', "n", 0,
	  "Dump statistics every n blocks (default: 0)" },

	{ 0 },
};

struct arguments {
	int blockstats;
	uint64_t timedstats;		/* microseconds */
	int pipemode;
	int blockcount;
};

static struct arguments default_arguments = {
	.blockstats	= 0,
	.timedstats	= 0,
	.pipemode	= 0,
	.blockcount	= 0,
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch(key) {
	case 'c': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0))
			argp_usage(state);
		else
			arguments->blockcount = n;
		break;
	}
	case 'b': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0))
			argp_usage(state);
		else
			arguments->blockstats = n;
		break;
	}
	case 't': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0))
			argp_usage(state);
		else
			arguments->timedstats = 1000000ULL * n;
		break;
	}

	case 'p':
		arguments->pipemode = 1;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/*
 * Globals
 */

/* RNG Buffers */
unsigned char rng_buffer[FIPS_RNG_BUFFER_SIZE];

/* Statistics */
struct {
	/* simple counters */
	uint64_t bad_fips_blocks;	/* Blocks reproved by FIPS 140-2 */
	uint64_t good_fips_blocks;	/* Blocks approved by FIPS 140-2 */
	uint64_t fips_failures[N_FIPS_TESTS]; 	/* Breakdown of block
					   failures per FIPS test */

	uint64_t bytes_received;	/* Bytes read from input */
	uint64_t bytes_sent;		/* Bytes sent to output */

	/* performance timers */
	struct rng_stat source_blockfill;	/* Block-receive time */
	struct rng_stat fips_blockfill;		/* FIPS run time */
	struct rng_stat sink_blockfill;		/* Block-send time */

	struct timeval progstart;	/* Program start time */
} rng_stats;

/* Logic and contexts */
static fips_ctx_t fipsctx;		/* Context for the FIPS tests */
static int exitstatus = EXIT_SUCCESS;	/* Exit status */

/* Command line arguments and processing */
struct arguments *arguments = &default_arguments;
static struct argp argp = { options, parse_opt, NULL, doc };

/* signals */
static volatile int gotsigterm = 0;	/* Received SIGTERM/SIGINT */


/*
 * Signal handling
 */
static void sigterm_handler(int sig)
{
	gotsigterm = sig;
}

static void init_sighandlers(void)
{
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	action.sa_handler = sigterm_handler;

	/* Handle SIGTERM and SIGINT the same way */
	if (sigaction(SIGTERM, &action, NULL) < 0) {
		fprintf(stderr,
			"unable to install signal handler for SIGTERM: %s",
			strerror(errno));
		exit(EXIT_OSERR);
	}
	if (sigaction(SIGINT, &action, NULL) < 0) {
		fprintf(stderr,
			"unable to install signal handler for SIGINT: %s",
			strerror(errno));
	        exit(EXIT_OSERR);
	}
}


static int xread(void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size) {
		r = read(0, buf + off, size);
		if (r < 0) {
			if (gotsigterm) return -1;
			if ((errno == EAGAIN) || (errno == EINTR)) continue;
			break;
		} else if (!r) {
			if (!arguments->pipemode)
				fprintf(stderr,
					"%sentropy source drained\n",
					logprefix);
			return -1;
		}
		off += r;
		size -= r;
		rng_stats.bytes_received += r;
	}

	if (size) {
		fprintf(stderr,
			"%serror reading input: %s\n", logprefix,
			strerror(errno));
		exitstatus = EXIT_IOERR;
		return -1;
	}
	return 0;
}

static int xwrite(void *buf, size_t size)
{
	size_t off = 0;
	ssize_t r;

	while (size) {
		r = write(1, buf + off, size);
		if (r < 0) {
			if (gotsigterm) return -1;
			if ((errno == EAGAIN) || (errno == EINTR)) continue;
			break;
		} else if (!r) {
			fprintf(stderr,
				"%swrite channel stuck\n", logprefix);
			exitstatus = EXIT_IOERR;
			return -1;
		}
		off += r;
		size -= r;
		rng_stats.bytes_sent += r;
	}

	if (size) {
		fprintf(stderr,
			"%serror writing to output: %s\n", logprefix,
			strerror(errno));
		exitstatus = EXIT_IOERR;
		return -1;
	}
	return 0;
}


static void init_rng_stats(void)
{
	memset(&rng_stats, 0, sizeof(rng_stats));
	gettimeofday(&rng_stats.progstart, 0);
	set_stat_prefix(logprefix);
}

static void dump_rng_stats(void)
{
	int j;
	char buf[256];
	struct timeval now;

	fprintf(stderr, "%s\n", dump_stat_counter(buf, sizeof(buf),
			"bits received from input",
			rng_stats.bytes_received * 8));
	if (arguments->pipemode)
		fprintf(stderr, "%s\n", dump_stat_counter(buf, sizeof(buf),
			"bits sent to output",
			rng_stats.bytes_sent * 8));
	fprintf(stderr, "%s\n", dump_stat_counter(buf, sizeof(buf),
			"FIPS 140-2 successes",
			rng_stats.good_fips_blocks));
	fprintf(stderr, "%s\n", dump_stat_counter(buf, sizeof(buf),
			"FIPS 140-2 failures",
			rng_stats.bad_fips_blocks));
	for (j = 0; j < N_FIPS_TESTS; j++)
		fprintf(stderr, "%s\n", dump_stat_counter(buf, sizeof(buf),
					fips_test_names[j],
					rng_stats.fips_failures[j]));
	fprintf(stderr, "%s\n", dump_stat_bw(buf, sizeof(buf),
			"input channel speed", "bits",
			&rng_stats.source_blockfill, FIPS_RNG_BUFFER_SIZE*8));
	fprintf(stderr, "%s\n", dump_stat_bw(buf, sizeof(buf),
			"FIPS tests speed", "bits",
			&rng_stats.fips_blockfill, FIPS_RNG_BUFFER_SIZE*8));
	if (arguments->pipemode)
		fprintf(stderr, "%s\n", dump_stat_bw(buf, sizeof(buf),
			"output channel speed", "bits",
			&rng_stats.sink_blockfill, FIPS_RNG_BUFFER_SIZE*8));

	gettimeofday(&now, 0);
	fprintf(stderr, "%sProgram run time: %llu microseconds\n",
		logprefix,
		(unsigned long long) elapsed_time(&rng_stats.progstart, &now));
}

/* Return 32 bits of bootstrap data */
static int discard_initial_data(void)
{
	unsigned char tempbuf[4];

	/* Do full startup discards when in pipe mode */
	if (arguments->pipemode)
		if (xread(tempbuf, sizeof tempbuf)) exit(EXIT_FAIL);

	/* Bootstrap data for FIPS tests */
	if (xread(tempbuf, sizeof tempbuf)) exit(EXIT_FAIL);

	return tempbuf[0] | (tempbuf[1] << 8) |
		(tempbuf[2] << 16) | (tempbuf[3] << 24);
}

static void do_rng_fips_test_loop( void )
{
	int j;
	int fips_result;
	struct timeval start, stop, statdump, now;
	int statruns, runs;

	runs = statruns = 0;
	gettimeofday(&statdump, 0);
	while (!gotsigterm) {
		gettimeofday(&start, 0);
		if (xread(rng_buffer, sizeof(rng_buffer))) return;
		gettimeofday(&stop, 0);
		update_usectimer_stat(&rng_stats.source_blockfill,
				&start, &stop);

		gettimeofday(&start, 0);
		fips_result = fips_run_rng_test(&fipsctx, &rng_buffer);
		gettimeofday (&stop, 0);
		update_usectimer_stat(&rng_stats.fips_blockfill,
				&start, &stop);

		if (fips_result) {
			rng_stats.bad_fips_blocks++;
			for (j = 0; j < N_FIPS_TESTS; j++)
				if (fips_result & fips_test_mask[j])
					rng_stats.fips_failures[j]++;
		} else {
			rng_stats.good_fips_blocks++;
			if (arguments->pipemode) {
				gettimeofday(&start, 0);
				if (xwrite(rng_buffer, sizeof(rng_buffer)))
					return;
				gettimeofday (&stop, 0);
				update_usectimer_stat(
					&rng_stats.sink_blockfill,
					&start, &stop);
			}
		}

		if (arguments->blockcount &&
		    (++runs >= arguments->blockcount)) break;

		gettimeofday(&now, 0);
		if ((arguments->blockstats &&
		     (++statruns >= arguments->blockstats)) ||
		    (arguments->timedstats &&
		     (elapsed_time(&statdump, &now) > arguments->timedstats))) {
			dump_rng_stats();
			gettimeofday(&statdump, 0);
			statruns = 0;
		}
	}
}

int main(int argc, char **argv)
{
	argp_parse(&argp, argc, argv, 0, 0, arguments);

	if (!arguments->pipemode)
		fprintf(stderr, "%s\n\n",
			argp_program_version);

	init_sighandlers();

	/* Init data structures */
	init_rng_stats();

	if (!arguments->pipemode)
		fprintf(stderr, "%sstarting FIPS tests...\n",
			logprefix);

	/* Bootstrap FIPS tests */
	fips_init(&fipsctx, discard_initial_data());

	do_rng_fips_test_loop();

	dump_rng_stats();

	if ((exitstatus == EXIT_SUCCESS) &&
	    (rng_stats.bad_fips_blocks || !rng_stats.good_fips_blocks)) {
		exitstatus = EXIT_FAIL;
	}

	exit(exitstatus);
}
