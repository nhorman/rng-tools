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


/* Kernel output device */
static int random_fd;


/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 *
 * randomdev is the path to the random device
 */
void init_kernel_rng(const char* randomdev)
{
	random_fd = open(randomdev, O_RDWR);
	if (random_fd == -1) {
		message(LOG_DAEMON|LOG_ERR, "can't open %s: %s",
			randomdev, strerror(errno));
		exit(EXIT_USAGE);
	}
}

void random_add_entropy(void *buf, size_t size)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;

	entropy.ent_count = size * 8;
	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(random_fd, RNDADDENTROPY, &entropy) != 0) {
		message(LOG_DAEMON|LOG_ERR, "RNDADDENTROPY failed: %s\n",
			strerror(errno));
		exit(1);
	}
}

void random_sleep(double poll_timeout)
{
	int ent_count;
	struct pollfd pfd = {
		fd:	random_fd,
		events:	POLLOUT,
	};

	if (ioctl(random_fd, RNDGETENTCNT, &ent_count) == 0 &&
	    ent_count < arguments->fill_watermark)
		return;
	
	poll(&pfd, 1, 1000.0 * poll_timeout);
}

