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
#include "rng-tools-config.h"

#include <jitterentropy.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

static struct rand_data *ec = NULL;

static int num_threads = 0;
struct thread_data {
	int core_id;
	struct rand_data *ec;
	char *buf_ptr;
	size_t buf_sz;
	size_t avail;
	size_t idx;
	int refill;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
};

static struct thread_data *tdata;
static pthread_t *threads;

/*
 * These must be powers of 2
 */

int xread_jitter(void *buf, size_t size, struct rng *ent_src)
{
	static int data = 0;
	struct thread_data *current = &tdata[data];
	struct thread_data *start = current;
	ssize_t request = size;
	size_t idx = 0;
	size_t need = size;
	char *bptr = buf;
	int rc = 1;
try_again:
	while (need) {
		/* if the current thread is refilling its buffer
 		 * just move on to the next one
 		 */
		pthread_mutex_lock(&current->mtx);

		if (current->refill) {
			message(LOG_DAEMON|LOG_DEBUG, "JITTER skips empty thread on cpu %d\n", current->core_id);
			goto next_unlock;
		}
			
		request = (need > current->avail) ? current->avail : need;
		memcpy(&bptr[idx], &current->buf_ptr[current->idx], request);
		idx += request;
		current->idx += request;
		current->avail -= request;
		need -= request;

		/* Trigger a refill if this thread is low */
		if (current->avail < ent_src->rng_options[JITTER_OPT_REFILL].int_val) {
			current->refill = 1;
			pthread_cond_signal(&current->cond);
		}

next_unlock:
		pthread_mutex_unlock(&current->mtx);
next:
		/* Move to the next thread */
		data = ((data+1) % num_threads);	
		current = &tdata[data];
		if (start == current) {
			if (ent_src->rng_options[JITTER_OPT_RETRY_COUNT].int_val) {
				if (ent_src->rng_options[JITTER_OPT_RETRY_DELAY].int_val)
					sleep(ent_src->rng_options[JITTER_OPT_RETRY_DELAY].int_val);
				goto try_again;
			}
			goto out;
		}
	}
	rc = 0;

	pthread_mutex_unlock(&current->mtx);
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

static void *thread_entropy_task(void *data)
{
	cpu_set_t cpuset;

	ssize_t ret;
	size_t need;
	struct thread_data *me = data;
	char *tmpbuf;
	struct timespec start, end;

	/* STARTUP */
	/* fill initial entropy */
	CPU_ZERO(&cpuset);
	CPU_SET(me->core_id, &cpuset);
	pthread_setaffinity_np(pthread_self(), CPU_ALLOC_SIZE(me->core_id+1), &cpuset);

	tmpbuf = malloc(me->buf_sz);
	if (!tmpbuf) {
		message(LOG_DAEMON|LOG_DEBUG, "Unable to allocte temp buffer on cpu %d\n", me->core_id);
		goto out;
	}

	pthread_mutex_lock(&me->mtx);
	clock_gettime(CLOCK_REALTIME, &start);
	ret = jent_read_entropy(me->ec, tmpbuf, me->buf_sz);
	clock_gettime(CLOCK_REALTIME, &end);
	message(LOG_DEBUG|LOG_ERR, "jent_read_entropy time on cpu %d is %.12e sec\n",
		me->core_id, elapsed_time(&start, &end));

	if (ret < 0)
		message(LOG_DAEMON|LOG_DEBUG, "JITTER THREAD FAILS TO GATHER ENTROPY\n");

	else {
		memcpy(me->buf_ptr, tmpbuf, me->buf_sz);
		me->avail = me->buf_sz;
		me->refill = 0;
	}

	/* Now go to sleep until there is more work to do */
	do {
		pthread_cond_wait(&me->cond, &me->mtx);
		message(LOG_DAEMON|LOG_DEBUG, "JITTER thread on cpu %d wakes up for refill\n", me->core_id);
		/* When we wake up, check to ensure we still have a buffer
 		 * Having a NULL buf_ptr is a signal to exit
 		 */
		if (!me->buf_ptr)
			break;

		/* We are awake because we need to refil the buffer */
		need = me->buf_sz - me->avail;
		pthread_mutex_unlock(&me->mtx);
		clock_gettime(CLOCK_REALTIME, &start);
		ret = jent_read_entropy(me->ec, tmpbuf, need);	
		clock_gettime(CLOCK_REALTIME, &end);
		message(LOG_DEBUG|LOG_ERR, "jent_read_entropy time on cpu %d is %.12e sec\n",
			me->core_id, elapsed_time(&start, &end));
		if (ret == 0)
			message(LOG_DAEMON|LOG_DEBUG, "JITTER THREAD_FAILS TO GATHER ENTROPY\n");
		pthread_mutex_lock(&me->mtx);
		if (!me->buf_ptr) /* buf_ptr may have been removed while gathering entropy */
			break;
		memcpy(me->buf_ptr, tmpbuf, me->buf_sz);
		me->idx = 0;
		me->avail = me->buf_sz;
		me->refill = 0;

	} while (me->buf_ptr);

	free(tmpbuf);
	pthread_mutex_unlock(&me->mtx);
out:
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
		message(LOG_DAEMON|LOG_DEBUG, "JITTER Requires a minimum of 1 thread, setting threads to 1\n");
		ent_src->rng_options[JITTER_OPT_THREADS].int_val = 1;
	}

	/* buf_sz should be the same size or larger than the refill threshold */
	if (buf_sz < refill) {
		message(LOG_DAEMON|LOG_DEBUG, "JITTER buffer size must be larger than refill threshold\n");
		return 1;
	}

	if ((rcount < 0) || (delay < 0)) {
		message(LOG_DAEMON|LOG_DEBUG, "JITTER retry delay and count must be equal to or greater than 0\n");
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
	int core_id = 0;
	int ret = jent_entropy_init();
	if(ret) {
		message(LOG_DAEMON|LOG_WARNING, "JITTER rng fails with code %d\n", ret);
		return 1;
	}

	if (validate_jitter_options(ent_src))
		return 1;

	/*
 	 * Determine the number of threads we want to run
 	 * 2 threads for two or more cpus
 	 * 4 threads for four or more cpus
 	 */
	i = sysconf(_SC_NPROCESSORS_CONF);
	cpus = CPU_ALLOC(i);
	cpusize = CPU_ALLOC_SIZE(i);
	CPU_ZERO_S(cpusize, cpus);
	sched_getaffinity(0, cpusize, cpus);
	num_threads = CPU_COUNT_S(cpusize, cpus);

	if (num_threads >= ent_src->rng_options[JITTER_OPT_THREADS].int_val)
		num_threads = ent_src->rng_options[JITTER_OPT_THREADS].int_val;
	else
		message(LOG_DAEMON|LOG_DEBUG, "Limiting thread count to %d active cpus\n", num_threads);

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
		core_id++;
		tdata[i].buf_sz = ent_src->rng_options[JITTER_OPT_BUF_SZ].int_val;
		tdata[i].buf_ptr = calloc(1, tdata[i].buf_sz);
		tdata[i].ec = jent_entropy_collector_alloc(1, 0);
		tdata[i].refill = 1;
		pthread_mutex_init(&tdata[i].mtx, NULL);
		pthread_cond_init(&tdata[i].cond, NULL);
		pthread_create(&threads[i], NULL, thread_entropy_task, &tdata[i]);
	}

	CPU_FREE(cpus);
	cpus = NULL;

	/* Make sure all our threads are doing their jobs */
	for (i=0; i < num_threads; i++) {
		pthread_mutex_lock(&tdata[i].mtx);
		while (tdata[i].refill) {
			pthread_mutex_unlock(&tdata[i].mtx);
			sched_yield();
			pthread_mutex_lock(&tdata[i].mtx);
		}
		message(LOG_DAEMON|LOG_DEBUG, "CPU Thread %d is ready\n", i);
		pthread_mutex_unlock(&tdata[i].mtx);
	}
		
	message(LOG_DAEMON|LOG_INFO, "Enabling JITTER rng support\n");
	return 0;
}

void close_jitter_entropy_source(struct rng *ent_src)
{
	int i;

	for (i=0; i < num_threads; i++) {
		/* signal closure by setting buf_ptr to null */
		pthread_mutex_lock(&tdata[i].mtx);
		free(tdata[i].buf_ptr);
		tdata[i].buf_ptr = NULL;
		pthread_cond_signal(&tdata[i].cond);
		pthread_mutex_unlock(&tdata[i].mtx);
		pthread_join(threads[i], NULL);
		jent_entropy_collector_free(tdata[i].ec);
	}	

	free(tdata);
	free(threads);
	return;
}

