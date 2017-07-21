/*
 * rngd_linux.c -- Entropy sink for the Linux Kernel (/dev/random)
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/random.h>
#include <string.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_linux.h"

extern struct rng *rng_list;

/* Kernel output device */
static int random_fd;

/*
 * Get the default watermark
 */
int default_watermark(void)
{
	char psbuf[64], *p;
	unsigned long ps;
	FILE *f;
	size_t l;
	unsigned int wm = 2048;	/* Default guess */

	f = fopen("/proc/sys/kernel/random/poolsize", "r");
	if (!f)
		goto err;
	l = fread(psbuf, 1, sizeof psbuf, f);
	if (ferror(f) || !feof(f) || l == 0)
		goto err;
	if (psbuf[l-1] != '\n')
		goto err;
	psbuf[l-1] = '\0';
	ps = strtoul(psbuf, &p, 0);
	if (*p)
		goto err;

	wm = ps*3/4;

err:
	if (f)
		fclose(f);
	return wm;
}

/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 *
 * randomdev is the path to the random device
 */
void init_kernel_rng(const char* randomdev)
{
	FILE *f;
	int err;

	random_fd = open(randomdev, O_RDWR);
	if (random_fd == -1) {
		message(LOG_DAEMON|LOG_ERR, "can't open %s: %s",
			randomdev, strerror(errno));
		exit(EXIT_USAGE);
	}

	f = fopen("/proc/sys/kernel/random/write_wakeup_threshold", "w");
	if (!f) {
		err = 1;
	} else {
		fprintf(f, "%u\n", arguments->fill_watermark);
		/* Note | not || here... we always want to close the file */
		err = ferror(f) | fclose(f);
	}
	if (err) {
		message(LOG_DAEMON|LOG_WARNING,
			"unable to adjust write_wakeup_threshold: %s",
			strerror(errno));
	}
}

void random_add_entropy(void *buf, size_t size)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;

	entropy.ent_count = size * arguments->entropy_count;
	entropy.size = size;
	memcpy(entropy.data, buf, size);

	if (ioctl(random_fd, RNDADDENTROPY, &entropy) != 0) {
		message(LOG_DAEMON|LOG_ERR, "RNDADDENTROPY failed: %s\n",
			strerror(errno));
		exit(1);
	}
}

void random_sleep(void)
{
	struct pollfd pfd = {
		fd:	random_fd,
		events:	POLLOUT,
	};

	poll(&pfd, 1, -1);
}

void src_list_add(struct rng *ent_src)
{
	if (rng_list) {
		struct rng *iter;

		iter = rng_list;
		while (iter->next) {
			iter = iter->next;
		}
		iter->next = ent_src;
	} else {
		rng_list = ent_src;
	}
}
