##
## Toplevel Makefile.am for rng-tools
##

SUBDIRS		= contrib

sbin_PROGRAMS	= rngd
bin_PROGRAMS	= rngtest
man_MANS	= rngd.8 rngtest.1

common_sources  = fips.h fips.c
rngd_SOURCES	= $(common_sources) rngd.h rngd.c	\
		  rngd_entsource.h rngd_entsource.c	\
		  rngd_linux.h rngd_linux.c
rngtest_SOURCES	= $(common_sources) exits.h stats.h stats.c rngtest.c


EXTRA_DIST	= autogen.sh

