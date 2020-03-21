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

if RTLSDR
rngd_SOURCES	+= rngd_rtlsdr.c
endif

rngd_LDADD	= librngd.a -lsysfs $(LIBS) $(librtlsdr_LIBS) ${libp11_LIBS} ${libcrypto_LIBS} ${jansson_LIBS} ${libcurl_LIBS} ${libxml2_LIBS} ${openssl_LIBS} $(PTHREAD_LIBS)

if PKCS11 
rngd_SOURCES	+= rngd_pkcs11.c
pkcs11_ENGINE = -DDEFAULT_PKCS11_ENGINE=\"$(PKCS11_ENGINE)\"
endif

rngd_CFLAGS	= ${pkcs11_CFLAGS} $(librtlsdr_CFLAGS) ${pkcs11_ENGINE} ${libp11_CFLAGS} ${libcrypto_CFLAGS} ${libxml2_CFLAGS} ${openssl_CFLAGS} $(PTHREAD_CFLAGS)
rngd_LDFLAGS	= $(PTHREAD_CFLAGS) 

rngtest_SOURCES	= exits.h stats.h stats.c rngtest.c
rngtest_LDADD	= librngd.a

librngd_a_SOURCES = fips.h fips.c


EXTRA_DIST	= autogen.sh

