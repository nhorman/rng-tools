#!/bin/sh

autoheader

automake --gnu --add-missing

aclocal

autoconf

