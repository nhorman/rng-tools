/*
 * fips.h -- Performs FIPS 140-1/140-2 tests for RNGs
 * $Id: fips.h,v 1.1 2004/04/05 03:14:22 jgarzik Exp $
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

#ifndef FIPS__H
#define FIPS__H

#include <unistd.h>
#include <sys/types.h>

/*  Size of a FIPS test buffer, do not change this */
#define FIPS_THRESHOLD 2500

/*
 *  Runs the FIPS 140-1 4.11.1 and 4.11.2 tests, as updated by
 *  FIPS 140-2 4.9, errata from 2001-10-10 (which set more strict
 *  intervals for the tests to pass), on a buffer of size 
 *  FIPS_RNG_BUFFER_SIZE, using the given context.
 *
 *  FIPS 140-2, errata of 2002-12-03 removed tests for non-deterministic 
 *  RNGs, other than Continuous Run test.
 *  
 *  This funtion returns 0 if all tests passed, or a bitmask
 *  with bits set for every test that failed.
 *
 *  It returns -1 if either fips_ctx or buf is NULL.
 */
extern int fips_run_rng_test(unsigned char *buf);

#endif /* FIPS__H */
