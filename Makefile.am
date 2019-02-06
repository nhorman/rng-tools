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

if NISTBEACON
rngd_SOURCES	+= rngd_nistbeacon.c
endif
 
if RDRAND
rngd_SOURCES	+= rngd_rdrand.c rdrand_asm.S
endif

if DARN
rngd_SOURCES	+= rngd_darn.c
endif

if JITTER
rngd_SOURCES	+= rngd_jitter.c
endif

rngd_LDADD	= librngd.a -lsysfs $(LIBS) ${libp11_LIBS} ${libcurl_LIBS} ${libxml2_LIBS} ${openssl_LIBS} $(PTHREAD_LIBS)

if OPENSC 
rngd_SOURCES	+= rngd_opensc.c
endif

rngd_CFLAGS	= ${opensc_CFLAGS} ${libp11_CFLAGS} ${libxml2_CFLAGS} ${openssl_CFLAGS} $(PTHREAD_CFLAGS)
rngd_LDFLAGS	= $(PTHREAD_CFLAGS) 

rngtest_SOURCES	= exits.h stats.h stats.c rngtest.c
rngtest_LDADD	= librngd.a

librngd_a_SOURCES = fips.h fips.c


EXTRA_DIST	= autogen.sh

