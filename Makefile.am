##
## Toplevel Makefile.am for rng-tools
##
SUBDIRS		= contrib tests

sbin_PROGRAMS	 = rngd
bin_PROGRAMS	 = rngtest
man_MANS	 = rngd.8 rngtest.1
noinst_LIBRARIES = librngd.a

rngd_SOURCES	= rngd.h rngd.c	rngd_entsource.h rngd_entsource.c	\
		  rngd_linux.h rngd_linux.c util.c ossl_helpers.c	\
		  rngd_namedpipe.c

if NISTBEACON
rngd_SOURCES	+= rngd_nistbeacon.c
endif

if RDRAND
rngd_SOURCES	+= rngd_rdrand.c rdrand_asm.S
endif

if RNDR
rngd_SOURCES	+= rngd_rndr.c
endif

if JITTER
rngd_SOURCES	+= rngd_jitter.c
endif

if RTLSDR
rngd_SOURCES	+= rngd_rtlsdr.c
endif

if QRYPT
rngd_SOURCES	+= rngd_qrypt.c
endif

rngd_LDADD	= librngd.a $(LIBS) $(librtlsdr_LIBS) ${libp11_LIBS} ${libcrypto_LIBS} ${jansson_LIBS} ${libcurl_LIBS} ${libxml2_LIBS} ${openssl_LIBS} ${libcap_LIBS} $(PTHREAD_LIBS)

if DARN
rngd_SOURCES	+= rngd_darn.c

# Build Power9-only code with Power9
# compile flags in a separate library
rngd_LDADD		+= libdarn_impl.a
noinst_LIBRARIES	+= libdarn_impl.a
libdarn_impl_a_SOURCES	= darn_impl.c
libdarn_impl_a_CFLAGS	= -mcpu=power9 -mtune=power9
endif

if PKCS11
rngd_SOURCES	+= rngd_pkcs11.c
pkcs11_ENGINE = -DDEFAULT_PKCS11_ENGINE=\"$(PKCS11_ENGINE)\"
endif

rngd_CFLAGS	= ${pkcs11_CFLAGS} $(librtlsdr_CFLAGS) ${pkcs11_ENGINE} ${libp11_CFLAGS} ${libcrypto_CFLAGS} ${libxml2_CFLAGS} ${openssl_CFLAGS} ${libcap_CFLAGS} $(PTHREAD_CFLAGS)
rngd_LDFLAGS	= $(PTHREAD_CFLAGS)

rngtest_SOURCES	= exits.h stats.h stats.c rngtest.c
rngtest_LDADD	= librngd.a

librngd_a_SOURCES = fips.h fips.c


EXTRA_DIST	= autogen.sh

