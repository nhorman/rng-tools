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
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
 */

#ifndef RNGD_ENTSOURCE__H
#define RNGD_ENTSOURCE__H

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>

/* Logic and contexts */
extern fips_ctx_t fipsctx;		/* Context for the FIPS tests */
extern fips_ctx_t tpm_fipsctx;	/* Context for the tpm FIPS tests */

/*
 * Initialize entropy source and entropy conditioning
 *
 * sourcedev is the path to the entropy source
 */
extern int init_entropy_source(struct rng *);
#ifdef HAVE_RDRAND
extern int init_drng_entropy_source(struct rng *);
#endif
#ifdef HAVE_DARN
extern int init_darn_entropy_source(struct rng *);
#endif
#ifdef HAVE_NISTBEACON
extern int init_nist_entropy_source(struct rng *);
#endif
#ifdef HAVE_JITTER
extern int init_jitter_entropy_source(struct rng *);
extern void close_jitter_entropy_source(struct rng *);
extern void cache_jitter_entropy_data(struct rng *);
#endif
#ifdef HAVE_PKCS11
extern int init_pkcs11_entropy_source(struct rng *);
extern void close_pkcs11_entropy_source(struct rng *);
#endif
#ifdef HAVE_RTLSDR
extern int init_rtlsdr_entropy_source(struct rng *);
extern void close_rtlsdr_entropy_source(struct rng *);
#endif

extern int init_tpm_entropy_source(struct rng *);

/* Read data from the entropy source */
extern int xread(void *buf, size_t size, struct rng *ent_src);
#ifdef HAVE_RDRAND
extern int xread_drng(void *buf, size_t size, struct rng *ent_src);
#endif

#ifdef HAVE_DARN
extern int xread_darn(void *buf, size_t size, struct rng *ent_src);
#endif

#ifdef HAVE_JITTER
extern int xread_jitter(void *buf, size_t size, struct rng *ent_src);
#endif

#ifdef HAVE_PKCS11
extern int xread_pkcs11(void *buf, size_t size, struct rng *ent_src);
#endif

#ifdef HAVE_RTLSDR
extern int xread_rtlsdr(void *buf, size_t size, struct rng *ent_src);
#endif

extern int xread_nist(void *buf, size_t size, struct rng *ent_src);

extern int xread_tpm(void *buf, size_t size, struct rng *ent_src);

#endif /* RNGD_ENTSOURCE__H */
