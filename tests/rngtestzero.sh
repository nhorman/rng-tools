#!/bin/sh

# Test that we catch a repeating zero failure in rngtest
cat /dev/zero | rngtest -c 100 --pipe > /dev/null
if [ $? -eq 0 ]
then
	cat tests/test-suite.log
	exit 1
fi

exit 0

