/*
 * Copyright (c) 2017, Neil Horman 
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "rng-tools-config.h"

#include <jitterentropy.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

static int num_threads = 0;
struct thread_data {
	int core_id;
	int pipe_fd;
	struct rand_data *ec;
	size_t buf_sz;
	int slpmode;
	int active;
	int done;
	struct timespec slptm;
};

static struct thread_data *tdata;
static pthread_t *threads;
int pipefds[2];

unsigned char *aes_buf;

#ifdef HAVE_LIBGCRYPT

#define MIN_GCRYPT_VERSION "1.0.0"

static gcry_cipher_hd_t gcry_cipher_hd;

/* Read data from the drng in chunks of 128 bytes for AES scrambling */
#define AES_BLOCK               16
#define CHUNK_SIZE              (AES_BLOCK*8)   /* 8 parallel streams */
#define RDRAND_ROUNDS           512             /* 512:1 data reduction */

static unsigned char iv_buf[CHUNK_SIZE] __attribute__((aligned(128)));
#endif

static int init_gcrypt(const void *key)
{
#ifdef HAVE_LIBGCRYPT
	gcry_error_t gcry_error;

	if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
		message(LOG_DAEMON|LOG_ERR,
			"libgcrypt version mismatch: have %s, require >= %s\n",
			gcry_check_version(NULL), MIN_GCRYPT_VERSION);
		return 1;
	}

	gcry_error = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
				      GCRY_CIPHER_MODE_CBC, 0);

	if (!gcry_error)
		gcry_error = gcry_cipher_setkey(gcry_cipher_hd, key, AES_BLOCK);

	if (!gcry_error) {
		/*
		 * Only need the first 16 bytes of iv_buf. AES-NI can
		 * encrypt multiple blocks in parallel but we can't.
		 */
		gcry_error = gcry_cipher_setiv(gcry_cipher_hd, iv_buf, AES_BLOCK);
	}

	if (gcry_error) {
		message(LOG_DAEMON|LOG_ERR,
			"could not set key or IV: %s\n",
			gcry_strerror(gcry_error));
		gcry_cipher_close(gcry_cipher_hd);
		return 1;
	}
	return 0;
#else
	(void)key;
	return 1;
#endif
}

static inline int gcrypt_mangle(unsigned char *tmp, size_t size)
{
#ifdef HAVE_LIBGCRYPT
	int i;
	int stride = AES_BLOCK * RDRAND_ROUNDS;
	gcry_error_t gcry_error = 0;

	/* Encrypt tmp in-place. */

	for (i = 0; i < (size - stride) && !gcry_error; i += stride) {
		gcry_error = gcry_cipher_encrypt(gcry_cipher_hd, &tmp[i],
					 AES_BLOCK * RDRAND_ROUNDS,
					 NULL, 0);
	}

	if (gcry_error) {
		message(LOG_DAEMON|LOG_ERR,
			"gcry_cipher_encrypt error: %s\n",
			gcry_strerror(gcry_error));
		return -1;
	}
	return 0;
#else
	(void)tmp;
	return -1;
#endif
}

int xread_jitter(void *buf, size_t size, struct rng *ent_src)
{
	static int data = 0;
	struct thread_data *current = &tdata[data];
	ssize_t request;
	int rc = 1;
	int retry_count = 0;
	ssize_t need=size;
	char *bptr = buf;
	size_t total;
try_again:
	while (need) {
		message(LOG_DAEMON|LOG_DEBUG, "xread_jitter requests %lu bytes from pipe\n", need);
		request = read(pipefds[0], &bptr[size-need], need);
		if ((request < need) && ent_src->rng_options[JITTER_OPT_USE_AES].int_val) {
			message(LOG_DAEMON|LOG_DEBUG, "xread_jitter falls back to AES\n");
			/* empty pipe, use AES */
			total = 0;
			while(need) {
				request = (need >= current->buf_sz) ? current->buf_sz : need;
				memcpy(buf, &aes_buf[total], request);
				gcrypt_mangle(aes_buf, current->buf_sz);
				need -= request;
				total += request;
			}
			rc = 0;
			goto out;
		} else if (request < need) {
			if (request == -1) {
				message(LOG_DAEMON|LOG_DEBUG, "failed read: %s\n", strerror(errno));
				sched_yield();
			} else
				message(LOG_DAEMON|LOG_DEBUG, "request of random data returns %ld less than need %ld\n",
					request, need);
			if (retry_count < ent_src->rng_options[JITTER_OPT_RETRY_COUNT].int_val) {
				retry_count++;
				nanosleep(&current->slptm, NULL);
				goto try_again;
			}
			/* Retry count exceeded, fail */
			rc = 1;
			goto out;
		}

		message(LOG_DAEMON|LOG_DEBUG, "xread_jitter gets %ld bytes\n", request);
		need -= request;
	}

	rc = 0;
out:
	return rc;
}

static inline double elapsed_time(struct timespec *start, struct timespec *end)
{
	double delta;

	delta = (end->tv_sec - start->tv_sec);
	if (start->tv_nsec >= end->tv_nsec)
		delta = (delta * 1.0e9) + (start->tv_nsec - end->tv_nsec);
	else
		delta = ((delta + 1) * 1.0e9) + (end->tv_nsec - start->tv_nsec);	
	delta = delta / 1.0e9; 

	return delta;
}

static inline void update_sleep_time(struct thread_data *me,
				     struct timespec *start,
				     struct timespec *end)
{

	/*
	 * if slpmode is anything other than -1
	 * it will be a positive integer representing
	 * the fixed time to sleep on retry
	 * so if its not negative one, we just stick
	 * with whatever the init routine set up
	 */
	if (me->slpmode != -1)
		return;

	me->slptm.tv_sec = (end->tv_sec - start->tv_sec)/2;
	if (start->tv_nsec >= end->tv_nsec)
		me->slptm.tv_nsec = start->tv_nsec - end->tv_nsec;
	else
		me->slptm.tv_nsec = end->tv_nsec - start->tv_nsec;
	me->slptm.tv_nsec /= 2;
}

static void *thread_entropy_task(void *data)
{
	cpu_set_t cpuset;

	ssize_t ret;
	struct thread_data *me = data;
	char *tmpbuf;
	struct timespec start, end;
	int written;
	int first = 1;
	/* STARTUP */

	me->done = 0;
	/*
	 * Set our timeout value
	 * -1 means adaptive, i.e. sleep for the last 
	 * recorded execution time of a jitter read
	 * otherwise sleep for slpmode seconds
	 */
	if (me->slpmode != -1) {
		me->slptm.tv_sec = me->slpmode;
		me->slptm.tv_nsec = 0;
	}

	/* fill initial entropy */
	CPU_ZERO(&cpuset);
	CPU_SET(me->core_id, &cpuset);
	pthread_setaffinity_np(pthread_self(), CPU_ALLOC_SIZE(me->core_id+1), &cpuset);

	tmpbuf = malloc(me->buf_sz);
	if (!tmpbuf) {
		message(LOG_DAEMON|LOG_DEBUG, "Unable to allocte temp buffer on cpu %d\n", me->core_id);
		goto out;
	}

	/* Now go to sleep until there is more work to do */
	do {
		message(LOG_DAEMON|LOG_DEBUG, "JITTER thread on cpu %d wakes up for refill\n", me->core_id);

		/* We are awake because we need to refil the buffer */
		clock_gettime(CLOCK_REALTIME, &start);
		ret = jent_read_entropy(me->ec, tmpbuf, me->buf_sz);
		clock_gettime(CLOCK_REALTIME, &end);
		message(LOG_DEBUG|LOG_ERR, "jent_read_entropy time on cpu %d is %.12e sec\n",
			me->core_id, elapsed_time(&start, &end));
		if (ret < 0)
			message(LOG_DAEMON|LOG_DEBUG, "JITTER THREAD_FAILS TO GATHER ENTROPY\n");
		/* Need to hold the mutex to update the sleep time */
		update_sleep_time(me, &start, &end);

		/* Write to pipe */
		written = 0;
		while(written != me->buf_sz) {
			message(LOG_DAEMON|LOG_DEBUG, "Writing to pipe\n");
			ret = write(me->pipe_fd, &tmpbuf[written], me->buf_sz - written);
			message(LOG_DAEMON|LOG_DEBUG, "DONE Writing to pipe with return %ld\n", ret);
			if (first)
				me->active = 1;
			if (ret < 0)
				message(LOG_DAEMON|LOG_WARNING, "Error on pipe write: %s\n", strerror(errno));
			if (!first && !me->active)
				break;
			first = 0;
			written += ret;
		}

	} while (me->active);

	free(tmpbuf);
out:
	me->done = 1;
	pthread_exit(NULL);
}

int validate_jitter_options(struct rng *ent_src)
{
	int threads = ent_src->rng_options[JITTER_OPT_THREADS].int_val;
	int buf_sz = ent_src->rng_options[JITTER_OPT_BUF_SZ].int_val;
	int refill = ent_src->rng_options[JITTER_OPT_REFILL].int_val;
	int delay = ent_src->rng_options[JITTER_OPT_RETRY_DELAY].int_val;
	int rcount = ent_src->rng_options[JITTER_OPT_RETRY_COUNT].int_val;

	/* Need at least one thread to do this work */
	if (!threads) {
		message(LOG_DAEMON|LOG_ERR, "JITTER Requires a minimum of 1 thread, setting threads to 1\n");
		ent_src->rng_options[JITTER_OPT_THREADS].int_val = 1;
	}

	/* buf_sz should be the same size or larger than the refill threshold */
	if (buf_sz < refill) {
		message(LOG_DAEMON|LOG_ERR, "JITTER buffer size must be larger than refill threshold\n");
		return 1;
	}

	if (rcount < 0) {
		message(LOG_DAEMON|LOG_ERR, "JITTER retry delay and count must be equal to or greater than 0\n");
		return 1;
	}

	if ((delay < -1) || (delay == 0)) {
		message(LOG_DAEMON|LOG_ERR, "JITTER retry delay must be -1 or larger than 0\n");
		return 1;
	}

	return 0;
}

/*
 * Init JITTER
 */
int init_jitter_entropy_source(struct rng *ent_src)
{
	cpu_set_t *cpus;
	size_t cpusize;
	int i;
	int size;
	int flags;
	int core_id = 0;
#ifdef HAVE_LIBGCRYPT
	char key[AES_BLOCK];
#endif
	int ret = jent_entropy_init();
	if(ret) {
		message(LOG_DAEMON|LOG_WARNING, "JITTER rng fails with code %d\n", ret);
		return 1;
	}

	if (validate_jitter_options(ent_src))
		return 1;

	if (pipe(pipefds)) {
		message(LOG_DAEMON|LOG_WARNING, "JITTER rng can't open pipe: %s\n", strerror(errno));
		return 1;
	}

	/*
 	 * Determine the number of threads we want to run
 	 * 2 threads for two or more cpus
 	 * 4 threads for four or more cpus
 	 */
	i = sysconf(_SC_NPROCESSORS_CONF);
	cpus = CPU_ALLOC(i);
	cpusize = CPU_ALLOC_SIZE(i);
	CPU_ZERO_S(cpusize, cpus);
	if (sched_getaffinity(0, cpusize, cpus) < 0) {
		message(LOG_DAEMON|LOG_DEBUG, "Can not determine affinity of process, defaulting to 1 thread\n");
		CPU_SET(0,cpus);
	}

	num_threads = CPU_COUNT_S(cpusize, cpus);

	if (num_threads >= ent_src->rng_options[JITTER_OPT_THREADS].int_val)
		num_threads = ent_src->rng_options[JITTER_OPT_THREADS].int_val;
	else
		message(LOG_DAEMON|LOG_DEBUG, "Limiting thread count to %d active cpus\n", num_threads);

	size = num_threads * ent_src->rng_options[JITTER_OPT_BUF_SZ].int_val * 1.5;
	if (fcntl(pipefds[1], F_SETPIPE_SZ, size) == -1) {
		message(LOG_DAEMON|LOG_DEBUG, "Failed to set pipe size to %d bytes: %s\n",
			size, strerror(errno));
		close(pipefds[1]);
		close(pipefds[0]);
		CPU_FREE(cpus);
		return 1;
	}
	
	tdata = calloc(num_threads, sizeof(struct thread_data));
	threads = calloc(num_threads, sizeof(pthread_t));

	message(LOG_DAEMON|LOG_DEBUG, "JITTER starts %d threads\n", num_threads);

	/*
 	 * Allocate and init the thread data that we need
 	 */
	for (i=0; i < num_threads; i++) {
		while (!CPU_ISSET_S(core_id, cpusize, cpus))
			core_id++;
		tdata[i].core_id = core_id;
		tdata[i].pipe_fd = pipefds[1];
		tdata[i].active = 0;
		tdata[i].done = 0;
		core_id++;
		tdata[i].buf_sz = ent_src->rng_options[JITTER_OPT_BUF_SZ].int_val;
		tdata[i].ec = jent_entropy_collector_alloc(1, 0);
		tdata[i].slpmode = ent_src->rng_options[JITTER_OPT_RETRY_DELAY].int_val;
		pthread_create(&threads[i], NULL, thread_entropy_task, &tdata[i]);
	}

	CPU_FREE(cpus);
	cpus = NULL;

	/* Make sure all our threads are doing their jobs */
	for (i=0; i < num_threads; i++) {
		while (tdata[i].active == 0)
			sched_yield();
		message(LOG_DAEMON|LOG_DEBUG, "CPU Thread %d is ready\n", i);
	}

	flags = fcntl(pipefds[0], F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(pipefds[0], F_SETFL, &flags);

	if (ent_src->rng_options[JITTER_OPT_USE_AES].int_val) {
#ifdef HAVE_LIBGCRYPT
		/*
		 * Temporarily disable aes so we don't try to use it during init
		 */

		message(LOG_CONS|LOG_INFO, "Initializing AES buffer\n");
		aes_buf = malloc(tdata[0].buf_sz);
		ent_src->rng_options[JITTER_OPT_USE_AES].int_val = 0;
		if (xread_jitter(key, AES_BLOCK, ent_src)) {
			message(LOG_CONS|LOG_INFO, "Unable to obtain AES key, disabling AES in JITTER source\n");
		} else if (xread_jitter(iv_buf, CHUNK_SIZE, ent_src)) {
			message(LOG_CONS|LOG_INFO, "Unable to obtain iv_buffer, disabling AES in JITTER source\n");
		} else if (init_gcrypt(key)) {
			message(LOG_CONS|LOG_INFO, "Unable to inity gcrypt lib, disabling AES in JITTER source\n");
		} else {
			/* re-enable AES */
			ent_src->rng_options[JITTER_OPT_USE_AES].int_val = 1;
		}
		xread_jitter(aes_buf, tdata[0].buf_sz, ent_src);
#else
		message(LOG_CONS|LOG_INFO, "libgcrypt not available. Disabling AES in JITTER source\n");
		ent_src->rng_options[JITTER_OPT_USE_AES].int_val = 0;
#endif
	}
	message(LOG_DAEMON|LOG_INFO, "Enabling JITTER rng support\n");
	return 0;
}

void close_jitter_entropy_source(struct rng *ent_src)
{
	int i;
	char tmpbuf[1024];
	int flags;

	/* Flag all the threads so they exit */
	for (i=0; i < num_threads; i++)
		tdata[i].active = 0;

	close(pipefds[1]);

	/* And wait for completion of each thread */
	for (i=0; i < num_threads; i++) {
		message(LOG_DAEMON|LOG_DEBUG, "Checking on done for thread %d\n", i);
		while (!tdata[i].done)
			pthread_kill(threads[i], SIGINT);
			if(tdata[i].done) {
				message(LOG_DAEMON|LOG_INFO, "Closing thread %d\n", tdata[i].core_id);
				pthread_join(threads[i], NULL);
				jent_entropy_collector_free(tdata[i].ec);
			} else 
				sched_yield();
	}

	close(pipefds[0]);
	free(tdata);
	free(threads);
	return;
}

