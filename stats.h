/*
 * stats.h -- Statistics helpers
 *
 * Copyright (C) 2004 Henrique M. Holschuh <hmh@debian.org>
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

#ifndef STATS__H
#define STATS__H

#include <unistd.h>
#include <stdint.h>

/* Min-Max stat */
struct rng_stat {
	uint64_t max;			/* Highest value seen */
	uint64_t min;			/* Lowest value seen */
	uint64_t num_samples;		/* Number of samples */
	uint64_t sum;			/* Sum of all samples */
};

/* Sets a prefix for all stat dumps. Maximum length is 19 chars */
extern void set_stat_prefix(const char* prefix);

/* Computes elapsed time in microseconds */
extern uint64_t elapsed_time(struct timeval *start,
                              struct timeval *stop);

/* Updates min-max stat */
extern void update_stat(struct rng_stat *stat, uint64_t value);

/* Updates min-max microseconds timer stat */
#define update_usectimer_stat(STAT, START, STOP) \
	update_stat(STAT, elapsed_time(START, STOP))

/*
 * The following functions format a stat dump on buf, and
 * return a pointer to the start of buf
 */

/* Dump simple counter */
extern char *dump_stat_counter(char *buf, int size,
			      const char *msg, uint64_t value);

/* Dump min-max time stat */
extern char *dump_stat_stat(char *buf, int size,
			   const char *msg, const char *unit,
			   struct rng_stat *stat);

/*
 * Dump min-max speed stat, base time unit is a microsecond
 */
extern char *dump_stat_bw(char *buf, int size,
			 const char *msg, const char *unit,
			 struct rng_stat *stat,
			 uint64_t blocksize);

#endif /* STATS__H */
