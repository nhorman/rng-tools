/*
 * rngd_source.h -- Entropy source and conditioning
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

#ifndef RNGD_ENTSOURCE__H
#define RNGD_ENTSOURCE__H

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>

/* Logic and contexts */
extern fips_ctx_t fipsctx;		/* Context for the FIPS tests */

/*
 * Initialize entropy source and entropy conditioning
 *
 * sourcedev is the path to the entropy source
 */
extern void init_entropy_source(const char* sourcedev);

/* Read data from the entropy source */
void xread(void *buf, size_t size);

#endif /* RNGD_ENTSOURCE__H */
