#!/bin/sh

kill_rngd() {
	sleep 30
	echo "killing"
	killall -9 rngd
}

kill_rngd &

if [ -n "$RNGD_JITTER_TIMEOUT" ]; then
    TIMEOUT="-O jitter:timeout:$RNGD_JITTER_TIMEOUT"
fi

../rngd -f -o /dev/stdout -x hwrng -x rdrand -x tpm -x namedpipe -O jitter:use_aes:1 $TIMEOUT | ../rngtest -c 100 --pipe > /dev/null
