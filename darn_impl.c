/*
 * Copyright (c) 2017, Neil Horman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>

/*
 * Runs PPC64 DARN instruction, returns ULONG_MAX on error.
 *
 * We need this code to be a in separate library to provide
 * special compile options for it.
 */
uint64_t get_darn_impl()
{
	uint64_t darn_val;
	asm volatile("darn %0, 1" : "=r" (darn_val) );
	return darn_val;
}
