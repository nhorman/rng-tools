/*
 * rngd_linux.h -- Entropy sink for the Linux Kernel (/dev/random)
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

#ifndef RNGD_LINUX__H
#define RNGD_LINUX__H

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>

/*
 * Initialize the interface to the Linux Kernel
 * entropy pool (through /dev/random)
 *
 * randomdev is the path to the random device
 */
extern void init_kernel_rng(const char* randomdev);

/* Send entropy to the kernel */
extern void random_add_entropy(void *buf, size_t size);

/* Sleep until the kernel is hungry for entropy */
extern void random_sleep(double poll_timeout);

#endif /* RNGD_LINUX__H */

