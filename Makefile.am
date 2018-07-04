##
## Toplevel Makefile.am for rng-tools
##

SUBDIRS		= contrib tests

sbin_PROGRAMS	 = rngd
bin_PROGRAMS	 = rngtest
man_MANS	 = rngd.8 rngtest.1
noinst_LIBRARIES = librngd.a

rngd_SOURCES	= rngd.h rngd.c	rngd_entsource.h rngd_entsource.c	\
		  rngd_linux.h rngd_linux.c util.c
rngd_LDADD	=
rngd_CFLAGS	=

if NISTBEACON
rngd_SOURCES	+= rngd_nistbeacon.c
endif
 
if JENT
rngd_SOURCES	+= rngd_jent.c libjitterentropy.a
rngd_LDADD	+= $(libjitterentropy_prefix)/libjitterentropy.a
endif

if RDRAND
rngd_SOURCES	+= rngd_rdrand.c rdrand_asm.S
endif

if DARN
rngd_SOURCES	+= rngd_darn.c
endif

rngd_LDADD	+= librngd.a -lsysfs ${libcurl_LIBS} ${libxml2_LIBS} ${openssl_LIBS}

rngd_CFLAGS	+= ${libxml2_CFLAGS} ${openssl_CFLAGS}

rngtest_SOURCES	= exits.h stats.h stats.c rngtest.c
rngtest_LDADD	= librngd.a

librngd_a_SOURCES = fips.h fips.c


EXTRA_DIST	= autogen.sh

