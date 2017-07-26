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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <syslog.h>
#include <signal.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"
#include "rngd_linux.h"

/*
 * Globals
 */

/* Background/daemon mode */
bool am_daemon;				/* True if we went daemon */

bool server_running = true;		/* set to false, to stop daemon */

bool ignorefail = false; /* true if we ignore MAX_RNG_FAILURES */

/* Command line arguments and processing */
const char *argp_program_version =
	"rngd " VERSION "\n"
	"Copyright 2001-2004 Jeff Garzik\n"
	"Copyright 2017 Neil Horman\n"
	"Copyright (c) 2001 by Philipp Rumpf\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static char doc[] =
	"Check and feed random data from hardware device to kernel entropy pool.\n";

static struct argp_option options[] = {
	{ "foreground",	'f', 0, 0, "Do not fork and become a daemon" },

	{ "ignorefail", 'i', 0, 0, "Ignore repeated fips failures" },

	{ "background", 'b', 0, 0, "Become a daemon (default)" },

	{ "list", 'l', 0, 0, "List the operational entropy sources on this system and exit" },

	{ "random-device", 'o', "file", 0,
	  "Kernel device used for random number output (default: /dev/random)" },

	{ "rng-device", 'r', "file", 0,
	  "Kernel device used for random number input (default: /dev/hwrng)" },

	{ "pid-file", 'p', "file", 0,
	  "File used for recording daemon PID, and multiple exclusion (default: /var/run/rngd.pid)" },

	{ "random-step", 's', "nnn", 0,
	  "Number of bytes written to random-device at a time (default: 64)" },

	{ "fill-watermark", 'W', "n", 0,
	  "Do not stop feeding entropy to random-device until at least n bits of entropy are available in the pool (default: 2048), 0 <= n <= 4096" },

	{ "quiet", 'q', 0, 0, "Suppress error messages" },

	{ "version" ,'v', 0, 0, "List rngd version" },

	{ "no-drng", 'd', "1|0", 0,
	  "Do not use drng as a source of random number input (default: 0)" },
	
	{ "no-tpm", 'n', "1|0", 0,
	  "Do not use tpm as a source of random number input (default: 0)" },

	{ "entropy-count", 'e', "n", 0, "Number of entropy bits to support (default: 8), 1 <= n <= 8" },

	{ 0 },
};

static struct arguments default_arguments = {
	.random_name	= "/dev/random",
	.pid_file	= "/var/run/rngd.pid",
	.random_step	= 64,
	.daemon		= true,
	.list		= false,
	.ignorefail	= false,
	.quiet		= false,
	.entropy_count	= 8,
};
struct arguments *arguments = &default_arguments;

static enum {
	ENT_HWRNG = 0,
	ENT_TPM = 1,
	ENT_RDRAND,
	ENT_DARN,
	ENT_MAX
} entropy_indexes;

static struct rng entropy_sources[ENT_MAX] = {
	/* Note, the special char dev must be the first entry */
	{
		.rng_name	= "Hardware RNG Device",
		.rng_fname      = "/dev/hwrng",
		.rng_fd         = -1,
		.xread          = xread,
		.init           = init_entropy_source,
	},
	{
		.rng_name	= "TPM RNG Device",
		.rng_fname      = "/dev/tpm0",
		.rng_fd         = -1,
		.xread          = xread_tpm,
		.init           = init_tpm_entropy_source,
	},
	{
		.rng_name       = "Intel RDRAND Instruction RNG",
		.rng_fd         = -1,
#ifdef HAVE_RDRAND
		.xread          = xread_drng,
		.init           = init_drng_entropy_source,
#else
		.init		= NULL,
#endif
	},
	{
		.rng_name       = "Power9 DARN Instruction RNG",
		.rng_fd         = -1,
#ifdef HAVE_DARN
		.xread          = xread_darn,
		.init           = init_darn_entropy_source,
#else
		.init		= NULL,
#endif
	},
};


/*
 * command line processing
 */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'o':
		arguments->random_name = arg;
		break;
	case 'l':
		arguments->list = true;
		break;
	case 'p':
		arguments->pid_file = arg;
		break;
	case 'r':
		entropy_sources[ENT_HWRNG].rng_fname = arg;
		break;
	case 'f':
		arguments->daemon = false;
		break;
	case 'b':
		arguments->daemon = true;
		break;
	case 'i':
		arguments->ignorefail = true;
		break;
	case 's':
		if (sscanf(arg, "%i", &arguments->random_step) == 0)
			argp_usage(state);
		break;
	case 'W': {
		int n;
		if ((sscanf(arg, "%i", &n) == 0) || (n < 0) || (n > 4096))
			argp_usage(state);
		else
			arguments->fill_watermark = n;
		break;
	}
	case 'q':
		arguments->quiet = true;
		break;
	case 'v':
		printf("%s\n", argp_program_version);
		return -EAGAIN;
	case 'd': {
		int n;
		if ((sscanf(arg,"%i", &n) == 0) || ((n | 1)!=1))
			argp_usage(state);
		else
			entropy_sources[ENT_RDRAND].init = NULL;
		break;
	}
	case 'n': {
		int n;
		if ((sscanf(arg,"%i", &n) == 0) || ((n | 1)!=1))
			argp_usage(state);
		else
			entropy_sources[ENT_TPM].init = NULL;
		break;
	}
	case 'e': {
		int e;
		if ((sscanf(arg,"%i", &e) == 0) || (e < 0) || (e > 8))
			argp_usage(state);
		else
			arguments->entropy_count = e;
		break;
	}
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };


static int update_kernel_random(int random_step,
	unsigned char *buf, fips_ctx_t *fipsctx_in)
{
	unsigned char *p;
	int fips;

	fips = fips_run_rng_test(fipsctx_in, buf);
	if (fips)
		return 1;

	for (p = buf; p + random_step <= &buf[FIPS_RNG_BUFFER_SIZE];
		 p += random_step) {
		random_add_entropy(p, random_step);
		random_sleep();
	}
	return 0;
}

static void do_loop(int random_step)
{
	unsigned char buf[FIPS_RNG_BUFFER_SIZE];
	int retval = 0;
	int no_work = 0;
	int i;

	while (no_work < 100) {
		struct rng *iter;
		bool work_done;

		work_done = false;
		for (i=0; i < ENT_MAX; i++)
		{
			int rc;
			iter = &entropy_sources[i];

			if (!server_running)
				return;

			if (!iter->operational)
				continue;

		retry_same:
			if (iter->disabled)
				continue;	/* failed, no work */

			retval = iter->xread(buf, sizeof buf, iter);
			if (retval)
				continue;	/* failed, no work */

			work_done = true;

			rc = update_kernel_random(random_step,
					     buf, iter->fipsctx);
			if (rc == 0) {
				iter->success++;
				if (iter->success >= RNG_OK_CREDIT) {
					if (iter->failures)
						iter->failures--;
					iter->success = 0;
				}
				break;	/* succeeded, work done */
			}

			iter->failures++;
			if (iter->failures <= MAX_RNG_FAILURES/4) {
				/* FIPS tests have false positives */
				goto retry_same;
			} else if (iter->failures >= MAX_RNG_FAILURES && !ignorefail) {
				if (!arguments->quiet)
					message(LOG_DAEMON|LOG_ERR,
					"too many FIPS failures, disabling entropy source\n");
				iter->disabled = true;
			}
		}

		if (!work_done)
			no_work++;
	}

	if (!arguments->quiet)
		message(LOG_DAEMON|LOG_ERR,
		"No entropy sources working, exiting rngd\n");
}

static void term_signal(int signo)
{
	server_running = false;
}

int main(int argc, char **argv)
{
	int i;
	int ent_sources = 0;
	pid_t pid_fd;

	openlog("rngd", 0, LOG_DAEMON);

	/* Get the default watermark level for this platform */
	arguments->fill_watermark = default_watermark();

	/* Parsing of commandline parameters */
	if (argp_parse(&argp, argc, argv, 0, 0, arguments) < 0)
		return 1;

	/* Init entropy sources */
	for (i=0; i < ENT_MAX; i++) {
		entropy_sources[i].operational = 0;
		if ((entropy_sources[i].init) &&
		     !entropy_sources[i].init(&entropy_sources[i])) {
			ent_sources++;
			entropy_sources[i].operational = 1;
		}
	}

	if (!ent_sources) {
		if (!arguments->quiet) {
			message(LOG_DAEMON|LOG_ERR,
				"can't open any entropy source");
			message(LOG_DAEMON|LOG_ERR,
				"Maybe RNG device modules are not loaded\n");
		}
		return 1;
	}

	if (arguments->list) {
		printf("Available entropy sources:\n");
		for (i=0; i < ENT_MAX; i++) 
			if (entropy_sources[i].init && entropy_sources[i].operational)
				printf("%d: %s\n", i, entropy_sources[i].rng_name);
			
		return 1;
	}

	/* Init entropy sink and open random device */
	init_kernel_rng(arguments->random_name);

	if (arguments->daemon) {
		am_daemon = true;

		if (daemon(0, 0) < 0) {
			if(!arguments->quiet)
				fprintf(stderr, "can't daemonize: %s\n",
				strerror(errno));
			return 1;
		}

		/* require valid, locked PID file to proceed */
		pid_fd = write_pid_file(arguments->pid_file);
		if (pid_fd < 0)
			return 1;

		signal(SIGHUP, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		signal(SIGINT, term_signal);
		signal(SIGTERM, term_signal);
	}
	if (arguments->ignorefail)
		ignorefail = true;

	do_loop(arguments->random_step);

	if (pid_fd >= 0)
		unlink(arguments->pid_file);

	return 0;
}
