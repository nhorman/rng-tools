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

AC_INIT(rng-tools, 6.5, [Neil Horman <nhorman@tuxdriver.com>])
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([rngd.c])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([rng-tools-config.h])
AC_CONFIG_MACRO_DIRS([m4])

dnl Parse options

AC_ARG_WITH([libgcrypt],
	AS_HELP_STRING([--without-libgcrypt],
		[Disable libgcrypt support. Systems that support RDRAND but not AES-NI will require libgcrypt in order to use RDRAND as an entropy source. (Default: --with-libgcrypt)]),
	[],
	[with_libgcrypt=check]
)
AC_ARG_WITH([nistbeacon],
	AS_HELP_STRING([--without-nistbeacon],
		[Disable nistbeacon support. ]),
	[],
	[with_nistbeacon=check]
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
AM_CONDITIONAL([JITTER_DSO], [false])
AS_IF([test -f jitterentropy-library/Makefile],
		[AM_CONDITIONAL([JITTER], [true])
		 AC_DEFINE([HAVE_JITTER],1,[Enable JITTER])],
		[AC_SEARCH_LIBS(jent_version,jitterentropy,
			[AM_CONDITIONAL([JITTER_DSO], [true])
			 AC_DEFINE([HAVE_JITTER],1,[Enable JITTER])],
			[AC_MSG_NOTICE([Disabling JITTER entropy source])])])

#AM_CONDITIONAL([JITTER], [test -f jitterentropy-library/Makefile])
#AS_IF([test -f jitterentropy-library/Makefile], [AC_DEFINE([HAVE_JITTER],1,[Enable JITTER])],[AC_MSG_NOTICE([Disabling JITTER entropy source])])

AS_IF(
	[ test "x$with_nistbeacon" != "xno"],
	[
		PKG_CHECK_MODULES([libcurl], [libcurl], [], [AC_MSG_ERROR([libcurl is required])])
		PKG_CHECK_MODULES([libxml2], [libxml-2.0], [], [AC_MSG_ERROR([libxml2 is required])])
		PKG_CHECK_MODULES([openssl], [openssl], [], [AC_MSG_ERROR([openssl is required])])
		AC_DEFINE([HAVE_NISTBEACON],1,[Enable NISTBEACON])
	]
)

AM_CONDITIONAL([NISTBEACON], [test "x$with_nistbeacon" != "xno"])

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

dnl -------------------------------------
dnl Check for libgcrypt support
dnl -------------------------------------

AS_IF(
	[test "x$with_libgcrypt" != "xno"],
	[
		AC_CHECK_HEADER([gcrypt.h],
			AC_CHECK_LIB(
				[gcrypt],
				[gcry_check_version], ,
				[
					if test "x$with_libgcrypt" != "xcheck"; then
						AC_MSG_FAILURE([libgcrypt not found]); else
						AC_MSG_NOTICE([libgcrypt support disabled])
					fi
				]
			),
			[if test "x$with_libgcrypt" != "xcheck"; then
				AC_MSG_FAILURE([libgcrypt headers not found]); else
				AC_MSG_NOTICE([libgcrypt support disabled])
			fi]
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
