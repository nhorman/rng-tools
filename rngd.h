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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef RNGD__H
#define RNGD__H

#define _GNU_SOURCE

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <syslog.h>

#include "fips.h"

/* Command line arguments and processing */
struct arguments {
	char *random_name;
	char *rng_name;
	
	int random_step;
	int fill_watermark;
	double poll_timeout;

	int daemon;
};
extern struct arguments *arguments;

/* Background/daemon mode */
extern int am_daemon;			/* Nonzero if we went daemon */


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

#endif /* RNGD__H */

