/*
 * stats.c -- Statistics helpers
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
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include "fips.h"
#include "stats.h"


static char stat_prefix[20] = "";

void set_stat_prefix(const char* prefix)
{
	stat_prefix[sizeof(stat_prefix)-1] = 0;
	strncpy(stat_prefix, prefix, sizeof(stat_prefix)-1);
}

static void scale_mult_unit(char *unit, int unitsize,
		       const char *baseunit,
		       double *value_min,
		       double *value_avg,
		       double *value_max)
{
	int mult = 0;
	char multchar[] = "KMGTPE";

	while ((*value_min >= 1024.0) && (*value_avg >= 1024.0) &&
	       (*value_max >= 1024.0) && (mult < sizeof(multchar))) {
		mult++;
		*value_min = *value_min / 1024.0;
		*value_max = *value_max / 1024.0;
		*value_avg = *value_avg / 1024.0;
	}
	unit[unitsize-1] = 0;
	if (mult)
		snprintf(unit, unitsize, "%ci%s", multchar[mult-1], baseunit);
	else
		strncpy(unit, baseunit, unitsize);
}

/* Computes elapsed time in microseconds */
uint64_t elapsed_time(struct timeval *start,
		       struct timeval *stop)
{
	uint64_t diff;

	if (stop->tv_sec < start->tv_sec) return 0;

	diff = (stop->tv_sec - start->tv_sec) * 1000000ULL;
	if (stop->tv_usec > start->tv_usec) {
		diff += stop->tv_usec - start->tv_usec;
	} else {
		diff -= start->tv_usec - stop->tv_usec;
	}

	return diff;
}

/* Updates min-max stat */
void update_stat(struct rng_stat *stat, uint64_t value)
{
	uint64_t overflow = stat->num_samples;

	if ((stat->min == 0 ) || (value < stat->min)) stat->min = value;
	if (value > stat->max) stat->max = value;
	if (++stat->num_samples > overflow) {
		stat->sum += value;
	} else {
		stat->sum = value;
		stat->num_samples = 1;
	}
}

char *dump_stat_counter(char *buf, int size,
		       const char *msg, uint64_t value)
{
	buf[size-1] = 0;
	snprintf(buf, size-1, "%s%s: %llu", stat_prefix, msg,
		 (unsigned long long) value);

	return buf;
}

char *dump_stat_stat(char *buf, int size,
		    const char *msg, const char *unit, struct rng_stat *stat)
{
	double avg = 0.0;

	if (stat->num_samples > 0)
		avg = (double)stat->sum / stat->num_samples;

	buf[size-1] = 0;
	snprintf(buf, size-1, "%s%s: (min=%llu; avg=%.3f; max=%llu)%s",
		 stat_prefix, msg, (unsigned long long) stat->min, avg,
		 (unsigned long long) stat->max, unit);

	return buf;
}

char *dump_stat_bw(char *buf, int size,
		  const char *msg, const char *unit,
		  struct rng_stat *stat,
		  uint64_t blocksize)
{
	char unitscaled[20];
	double bw_avg = 0.0, bw_min = 0.0, bw_max = 0.0;

	if (stat->max > 0)
		bw_min = (1000000.0 * blocksize) / stat->max;
	if (stat->min > 0)
		bw_max = (1000000.0 * blocksize) / stat->min;
	if (stat->num_samples > 0)
		bw_avg = (1000000.0 * blocksize * stat->num_samples) / stat->sum;

	scale_mult_unit(unitscaled, sizeof(unitscaled), unit,
			&bw_min, &bw_avg, &bw_max);

	buf[size-1] = 0;
	snprintf(buf, size-1, "%s%s: (min=%.3f; avg=%.3f; max=%.3f)%s/s",
		 stat_prefix, msg, bw_min, bw_avg, bw_max, unitscaled);

	return buf;
}

