#!/bin/sh

kill_rngd() {
	sleep 5
	echo "killing"
	killall -9 rngd
}

kill_rngd &

../rngd -f -o /dev/stdout -x hwrng -x rdrand -x tpm -O jitter:use_aes:1 | ../rngtest -c 100 --pipe > /dev/null


