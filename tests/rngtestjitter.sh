#!/bin/sh

# Test that we catch a repeating zero failure in rngtest
./rngd -f -o /dev/stdout -x hwrng -x rdrand -x tpm -O jitter:use_aes:1 | ../rngtest -c 100 --pipe > /dev/null
if [ $? -eq 0 ]
then
	exit 1
fi

exit 0

