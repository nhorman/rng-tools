dnl Process this file with autoconf 2.52+ to produce a configure script.
dnl
dnl Copyright (C) 2001 Philipp Rumpf
dnl Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA

AC_INIT(rng-tools, 6.11, [Neil Horman <nhorman@tuxdriver.com>])
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([rngd.c])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([rng-tools-config.h])
AC_CONFIG_MACRO_DIRS([m4])

dnl Parse options

AC_ARG_WITH([nistbeacon],
	AS_HELP_STRING([--without-nistbeacon],
		[Disable nistbeacon support. ]),
	[],
	[with_nistbeacon=check]
)

AC_ARG_WITH([pkcs11],
	AS_HELP_STRING([--without-pkcs11],
		[Disable pkcs11 support. ]),
	[],
	[with_pkcs11=check]
)

AC_ARG_WITH([rtlsdr],
	AS_HELP_STRING([--without-rtlsdr],
		[Disable rtlsdr support. ]),
	[],
	[with_rtlsdr=no]
)

AC_ARG_WITH([libargp],
	AS_HELP_STRING([--without-libargp],
		[Disable libargp support. Systems whose libc lacks argp can use libargp instead. (Default: check if libc lacks argp)]),
	[with_libargp=$withval],
	[with_libargp=check]
)

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE
AM_PROG_AS

dnl Checks for programs
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_GCC_TRADITIONAL

AC_CHECK_TOOLS([AR], [ar gar], :)

AX_PTHREAD

AM_CONDITIONAL([RDRAND], [test $target_cpu = x86_64 -o $target_cpu = i686])
AS_IF([test $target_cpu = x86_64 -o $target_cpu = i686], [AC_DEFINE([HAVE_RDRAND],1,[Enable RDRAND])],[])

AM_CONDITIONAL([DARN], [test $target_cpu = powerpc64le])
AS_IF([test $target_cpu = powerpc64le], [AC_DEFINE([HAVE_DARN],1,[Enable DARN])],[])

AM_CONDITIONAL([JITTER], [false])

AC_ARG_ENABLE(jitterentropy,
	AS_HELP_STRING([--disable-jitterentropy | --enable-jitterentropy=<path>],
	[Disable jitterentropy source, or specify its location]),
	[if [ test -d $enable_jitterentropy ]; then
		export LDFLAGS+=-L$enable_jitterentropy;
		export CFLAGS+=" -I$enable_jitterentropy";
	fi],[])

AS_IF(
	[ test "x$enable_jitterentropy" != "xno" ],
	[
		AC_MSG_NOTICE([Searching for jitterentropy library])
		AC_SEARCH_LIBS(jent_version,jitterentropy,
				[AM_CONDITIONAL([JITTER], [true])
				AC_DEFINE([HAVE_JITTER],1,[Enable JITTER])],
				AC_MSG_NOTICE([No Jitterentropy library found]),-lpthread)
	], [AC_MSG_NOTICE([Disabling JITTER entropy source])]
)

AS_IF(
	[ test "x$with_nistbeacon" != "xno"],
	[
		PKG_CHECK_MODULES([libcurl], [libcurl], [], [AC_MSG_ERROR([libcurl is required])])
		PKG_CHECK_MODULES([libxml2], [libxml-2.0], [], [AC_MSG_ERROR([libxml2 is required])])
                PKG_CHECK_MODULES([jansson], [jansson], [], [AC_MSG_ERROR([libjansson is required])])
		AC_DEFINE([HAVE_NISTBEACON],1,[Enable NISTBEACON])
	]
)

AS_IF(
	[ test "x$with_pkcs11" != "xno"],
	[
		PKG_CHECK_MODULES([libp11], [libp11], [], [AC_MSG_ERROR([libp11 is required])])
		PKG_CHECK_MODULES([libcrypto], [libcrypto], [], [AC_MSG_ERROR([libcrypto is required])])
		AC_DEFINE([HAVE_PKCS11],1,[Enable PKCS11])
		AS_CASE([$host_cpu],
			[i?86|armv7hl],
			[
				PKCS11_ENGINE=/usr/lib/opensc-pkcs11.so
			],
			[
				PKCS11_ENGINE=/usr/lib64/opensc-pkcs11.so
			])
		AC_SUBST([PKCS11_ENGINE])
	]
)

AS_IF(
	[ test "x$with_rtlsdr" != "xno"],
	[
		PKG_CHECK_MODULES([librtlsdr], [librtlsdr], [], [AC_MSG_ERROR([librtlsdr is required])])
		AC_DEFINE([HAVE_RTLSDR],1,[Enable RTLSDR])
	]
)

PKG_CHECK_MODULES([openssl], [openssl], [], [AC_MSG_ERROR([openssl is required])])
AM_CONDITIONAL([NISTBEACON], [test "x$with_nistbeacon" != "xno"])
AM_CONDITIONAL([PKCS11], [test "x$with_pkcs11" != "xno"])
AM_CONDITIONAL([RTLSDR], [test "x$with_rtlsdr" != "xno"])

dnl Checks for header files.
dnl AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_SEARCH_LIBS(sysfs_get_mnt_path, sysfs, [], [AC_MSG_ERROR([libsysfs is required])],[])

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------

dnl Determine if we need libargp: either user requested, or libc has no argp
AS_IF(
	[test "x$with_libargp" != "xyes"],
	[
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM(
				[#include <argp.h>],
				[int argc=1; char *argv[]={"test"}; argp_parse(0,argc,argv,0,0,0); return 0;]
				)],
			[need_libargp=no],
			[need_libargp=yes
			 if test "x$with_libargp" = "xno"; then
				AC_MSG_FAILURE([libargp disabled and libc does not have argp])
			 fi]
		)
	],
	[need_libargp=yes],
)

dnl Check for libargp
AS_IF(
	[test "x$need_libargp" = "xyes"],
	[
		AC_CHECK_LIB(
			[argp],
			[argp_parse],
			[LIBS="$LIBS -largp"],
			[AC_MSG_FAILURE([libargp not found])]
		)
	]
)

dnl -----------------
dnl Configure options
dnl -----------------

AM_PROG_AS

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AC_CONFIG_FILES([Makefile contrib/Makefile tests/Makefile rngd.8 rngtest.1])
AC_OUTPUT
