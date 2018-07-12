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
#include "rng-tools-config.h"

#include <jitterentropy.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

static struct rand_data *ec = NULL;

static int num_threads = 1;
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

#define MAX_THREADS 4 
static struct thread_data tdata[MAX_THREADS];
static pthread_t threads[MAX_THREADS];

/*
 * These must be powers of 2
 */
#define CACHE_REFILL_THRESH 16384 
#define CACHE_SIZE 16384 

int xread_jitter(void *buf, size_t size, struct rng *ent_src)
{
	static int data = 0;
	struct thread_data *current = &tdata[data];
	ssize_t request = size;
	size_t idx = 0;
	size_t need = size;
	char *bptr = buf;

	while (need) {
		/* if the current thread is refilling its buffer
 		 * just move on to the next one
 		 */
		if (pthread_mutex_trylock(&current->mtx)) {
			message(LOG_DAEMON|LOG_DEBUG, "JITTER skips thread on cpu %d\n", current->core_id);
			goto next;
		}
		if (current->refill) {
			message(LOG_DAEMON|LOG_DEBUG, "JITTER skips thread on cpu %d\n", current->core_id);
			goto next_unlock;
		}
			
		request = (need > current->avail) ? current->avail : need;
		memcpy(&bptr[idx], &current->buf_ptr[current->idx], request);
		idx += request;
		current->idx += request;
		current->avail -= request;
		need -= request;

		/* Trigger a refill if this thread is low */
		if (current->avail < CACHE_REFILL_THRESH) {
			current->refill = 1;
			pthread_cond_signal(&current->cond);
		}

next_unlock:
		pthread_mutex_unlock(&current->mtx);
next:
		/* Move to the next thread */
		data = ((data+1) % num_threads);	
		current = &tdata[data];
		pthread_mutex_lock(&current->mtx);
	}

	pthread_mutex_unlock(&current->mtx);
	return 0;

}

static void *thread_entropy_task(void *data)
{
	cpu_set_t cpuset;

	ssize_t ret;
	size_t need;
	struct thread_data *me = data;

	/* STARTUP */
	/* fill initial entropy */
	CPU_ZERO(&cpuset);
	CPU_SET(me->core_id, &cpuset);
	pthread_setaffinity_np(pthread_self(), CPU_ALLOC_SIZE(me->core_id+1), &cpuset);

	pthread_mutex_lock(&me->mtx);
	ret = jent_read_entropy(me->ec, me->buf_ptr, me->buf_sz);
	if (ret < 0)
		message(LOG_DAEMON|LOG_DEBUG, "JITTER THREAD FAILS TO GATHER ENTROPY\n");

	else {
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
		need = CACHE_SIZE - me->avail;
		ret = jent_read_entropy(me->ec, me->buf_ptr, need);	
		if (ret == 0)
			message(LOG_DAEMON|LOG_DEBUG, "JITTER THREAD_FAILS TO GATHER ENTROPY\n");
		me->idx = 0;
		me->avail = CACHE_SIZE;
		me->refill = 0;

	} while (me->buf_ptr);

	pthread_mutex_unlock(&me->mtx);
	pthread_exit(NULL);
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
	for (i=0; (1 << i) <= MAX_THREADS; i++) {
		if (CPU_COUNT_S(cpusize, cpus) >= (1 << i))
			num_threads = (1 << i);
	}

	message(LOG_DAEMON|LOG_DEBUG, "JITTER starts %d threads\n", num_threads);

	/*
 	 * Allocate and init the thread data that we need
 	 */
	for (i=0; i < num_threads; i++) {
		while (!CPU_ISSET_S(core_id, cpusize, cpus))
			core_id++;
		tdata[i].core_id = core_id;
		core_id++;
		tdata[i].buf_ptr = calloc(1, CACHE_SIZE);
		tdata[i].ec = jent_entropy_collector_alloc(1, 0);
		tdata[i].refill = 1;
		/* Divide the buffer into num_threads equal chunks */
		tdata[i].buf_sz = CACHE_SIZE;
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

	return;
}

