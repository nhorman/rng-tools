/*
 * fips.c -- Performs FIPS 140-1/140-2 RNG tests
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

#include "fips.h"


/*
 * FIPS test
 */

/* These are the startup tests suggested by the FIPS 140-2 spec section
*  4.9 (http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf)
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
static void rng_fips_test_store (unsigned int rng_data)
{
	int j;
	static int last_bit = 0;

	poker[rng_data >> 4]++;
	poker[rng_data & 15]++;

	/* Note in the loop below rlength is always one less than the actual
	   run length. This makes things easier. */
	for (j = 7; j >= 0; j--) {
		ones += current_bit = ((rng_data >> j) & 1);
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
			if (rlength >= 25)
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
int rng_run_fips_test (unsigned char *buf)
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
		if (rlength >= 25)
			rng_test |= 8;
	}
	
	if (longrun) {
		rng_test |= 8;
		longrun = 0;
	}

	/* Ones test */
	if ((ones >= 10275) || (ones <= 9725))
		rng_test |= 1;
	/* Poker calcs */
	for (i = 0, j = 0; i < 16; i++)
		j += poker[i] * poker[i];
	/* 16/5000*1563176-5000 = 2.1632  */
	/* 16/5000*1576928-5000 = 46.1696 */
	if ((j > 1576928) || (j < 1563176))
		rng_test |= 2;
	if ((runs[0] < 2315) || (runs[0] > 2685) ||
	    (runs[1] < 1114) || (runs[1] > 1386) ||
	    (runs[2] < 527) || (runs[2] > 723) ||
	    (runs[3] < 240) || (runs[3] > 384) ||
	    (runs[4] < 103) || (runs[4] > 209) ||
	    (runs[5] < 103) || (runs[5] > 209) ||
	    (runs[6] < 2315) || (runs[6] > 2685) ||
	    (runs[7] < 1114) || (runs[7] > 1386) ||
	    (runs[8] < 527) || (runs[8] > 723) ||
	    (runs[9] < 240) || (runs[9] > 384) ||
	    (runs[10] < 103) || (runs[10] > 209) ||
	    (runs[11] < 103) || (runs[11] > 209)) {
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

