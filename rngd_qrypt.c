/*
 * Copyright (c) 2022, Neil Horman
 * Copyright (c) 2022, Qrypt Inc.
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

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/param.h>
#include <syslog.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <time.h>
#include <sys/mman.h>
#include <endian.h>
#include <curl/curl.h>
#include <jansson.h>
#include "rngd.h"
#include "fips.h"
#include "rngd_entsource.h"

#define QRYPT_URL "https://api-eus.qrypt.com/api/v1/quantum-entropy?size=1"
#define ENT_BUF 1024
#define REFILL_THRESH 128
static uint8_t entropy_buffer[ENT_BUF];
static uint32_t ent_idx = 0;
static size_t avail_ent = 0;

static pthread_mutex_t ent_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ent_cond = PTHREAD_COND_INITIALIZER;

static bool refilling = false;
static bool fatal_error = false;

/* Backoff for recoverable errors */
static size_t backoff_iteration, backoff_delay, backoff_max;
static bool   backoff_active;
static struct timespec backoff_started;

static struct rng *my_ent_src;
static char *bearer;

struct body_buffer {
	char *response;
	size_t size;
};

static const char base64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t decodeQuantum(unsigned char *dest, const char *src)
{
	size_t padding = 0;
	const char *s, *p;
	unsigned long i, x = 0;

	for(i = 0, s = src; i < 4; i++, s++) {
		if(*s == '=') {
			x = (x << 6);
			padding++;
		}
		else {
			unsigned long v = 0;
			p = base64;

			while(*p && (*p != *s)) {
				v++;
				p++;
			}

			if(*p == *s)
				x = (x << 6) + v;
			else
				return 0;
		}
	}

	if(padding < 1)
		dest[2] = (unsigned char)(x & 0xFFUL);

	x >>= 8;
	if(padding < 2)
		dest[1] = (unsigned char)(x & 0xFFUL);

	x >>= 8;
	dest[0] = (unsigned char)(x & 0xFFUL);

	return 3 - padding;
}

uint8_t *base64_decode(const char *     data,
		       size_t	   input_length,
		       size_t *	 output_length)
{
	size_t srclen = 0;
	size_t length = 0;
	size_t padding = 0;
	size_t i;
	size_t numQuantums;
	size_t rawlen = 0;
	unsigned char *pos;
	unsigned char *newstr;

	*output_length = 0;
	srclen = input_length;

	/* Check the length of the input string is valid */
	if(!srclen || srclen % 4)
		return NULL;

	/* Find the position of any = padding characters */
	while((data[length] != '=') && data[length])
		length++;

	/* A maximum of two = padding characters is allowed */
	if(data[length] == '=') {
		padding++;
		if(data[length + 1] == '=')
			padding++;
	}

	/* Check the = padding characters weren't part way through the input */
	if(length + padding != srclen)
		return NULL;

	/* Calculate the number of quantums */
	numQuantums = srclen / 4;

	/* Calculate the size of the decoded string */
	rawlen = (numQuantums * 3) - padding;

	/* Allocate our buffer including room for a zero terminator */
	newstr = malloc(rawlen + 1);
	if(!newstr)
		return NULL;

	pos = newstr;

	/* Decode the quantums */
	for(i = 0; i < numQuantums; i++) {
		size_t result = decodeQuantum(pos, data);
		if(!result) {
			free(newstr);

			return NULL;
		}

		pos += result;
		data += 4;
	}

	/* Zero terminate */
	*pos = '\0';

	/* Return the decoded data */
	*output_length = rawlen;

	return newstr;	
}

static void extract_and_refill_entropy(struct body_buffer *buf)
{
	json_t *json;
	json_t *array;
	json_t *bdata;
	uint8_t *decode_data = NULL;
	size_t decode_len = 0;
	json_error_t err;

	json = json_loads(buf->response, buf->size, &err);

	if (!json) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to parse returned json\n");
		fatal_error = true;
		goto out;
	}

	array = json_object_get(json, "random");
	if (!array) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to find random array\n");
		fatal_error = true;
		goto out;
	}

	bdata = json_array_get(array, 0);
	if (!bdata) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to find random array index\n");
		fatal_error = true;
		goto out;
	}

	decode_data = base64_decode(json_string_value(bdata), strlen(json_string_value(bdata)), &decode_len);	
	if (!decode_data) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to decode random data\n");
		fatal_error = true;
		goto out;
	}
	pthread_mutex_lock(&ent_lock);
	decode_len = MIN(decode_len, ENT_BUF);
	memcpy(entropy_buffer, decode_data, decode_len);
	ent_idx = 0;
	avail_ent = decode_len;
	pthread_mutex_unlock(&ent_lock);

	/* We should have valid data now, so reset the backoff counter */
	backoff_iteration = 0;

out:
	if (decode_data)
		free(decode_data);
	if (json)
		json_decref(json);
	return;
}

static size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata)
{
	struct body_buffer *buf = (struct body_buffer *)userdata;
	size_t realsize = size * nmemb;
	char *ptr = realloc(buf->response, buf->size + realsize + 1);

	if (!ptr) {
		return 0;
	}
	buf->response = ptr;
	memcpy(&(buf->response[buf->size]), data, realsize);
	buf->size += realsize;
	buf->response[buf->size] = 0;
	return realsize;
}

/* Qrypt EaaS specific status codes and descriptions (from API docs) */
static const char *get_api_error_for_code(unsigned int response_code)
{
	switch(response_code)
	{
		case 400:
			return "The request was invalid (i.e., malformed or otherwise unacceptable). "
			       "Please verify the format of the URL and the specified parameters.";
		case 401:
			return "The access token is either invalid or has expired.";
		case 403:
			return "The account associated with the specified access token has already "
			       "retrieved the maximum allotment of entropy allowed for the current "
			       "period. Please contact a Qrypt representative to request a change to "
			       "your limit.";
		case 429:
			return "The access token used to pull random has exceeded the maximum number "
			       "of requests (30) allowed for the designated time interval (10 "
			       "seconds). Please wait and try again.";
		case 500:
			return "The Qrypt service has encountered an internal error. Please contact "
			       "Qrypt support for further assistance.";
		case 503:
			return "Qrypt's supply of entropy is temporarily insufficient to fulfill the "
			       "request. Please wait and try the request again.";
	}

	return "unknown error";
}

static void *refill_task(void *data __attribute__((unused)))
{
	CURL *curl;
	struct curl_slist *list = NULL;
	CURLcode res;
	long response_code;
	struct body_buffer response_data;
	bool recoverable_error = false;

	pthread_mutex_lock(&ent_lock);
	refilling = true;
	pthread_cond_signal(&ent_cond);
	pthread_mutex_unlock(&ent_lock);

	response_data.response = NULL;
	response_data.size = 0;
	curl = curl_easy_init();
	if (!curl) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "Unable to init curl\n");
		goto out;
	}

	res = curl_easy_setopt(curl, CURLOPT_URL, QRYPT_URL);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"curl_easy_setopt(URL) failed: %s\n", curl_easy_strerror(res));
		goto out;
	}
	res = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"curl_easy_setopt(HTTP_VER) failed: %s\n", curl_easy_strerror(res));
		goto out;
	}
	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"curl_easy_setopt(WRITEFUNC) failed: %s\n", curl_easy_strerror(res));
		goto out;
	}
	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"curl_easy_setopt(WRITEDATA) failed: %s\n", curl_easy_strerror(res));
		goto out;
	}

	list = curl_slist_append(list, "Accept: application/json");
	list = curl_slist_append(list, bearer);

	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"curl_easy_setopt(HTTPHEADER) failed: %s\n", curl_easy_strerror(res));
		goto out;
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO,
			"Failed to send curl: %s\n", curl_easy_strerror(res));
		recoverable_error = true;
		goto out;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "qrypt server responds not ok: %lu (%s)\n", response_code,
			get_api_error_for_code(response_code));

		/* For any responses which are not going to fix themselves with
		   retries or waiting some time, bail out... */
		if (response_code == 400 || response_code == 401)
			fatal_error = true;
		/* A 403 may be resolved immediately with the user upgrading
		   their account allowances in the background. As such, limit
		   the delay in this case to one minute instead of exponentially
		   backing off... */
		else if (response_code == 403)
		{
			backoff_delay  = 60; /* one minute */
			backoff_active = true;
			clock_gettime(CLOCK_MONOTONIC, &backoff_started);
		} else {
			recoverable_error = true;
		}

		goto out;
	}
	extract_and_refill_entropy(&response_data);
	
out:
	/* Have we picked up a recoverable error? */
	if (recoverable_error) {
		/* These errors cause an increase in the backoff delay */
		size_t backoff_power = backoff_iteration++;

		/* Constrain to integer math to keep things simple */
		backoff_power = MIN(backoff_power, 31);
		backoff_delay = MIN(1 << backoff_power, backoff_max);
		backoff_active = true;
		clock_gettime(CLOCK_MONOTONIC, &backoff_started);
	}

	if (list)
		curl_slist_free_all(list);
	if (curl)
		curl_easy_cleanup(curl);
	if (response_data.response)
		free(response_data.response);
	pthread_mutex_lock(&ent_lock);
	refilling = false;
	pthread_cond_signal(&ent_cond);
	pthread_mutex_unlock(&ent_lock);
	return NULL;
}

static void refill_ent_buffer()
{
	pthread_t tid;
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_lock(&ent_lock);
	if (refilling) {
		pthread_cond_wait(&ent_cond, &ent_lock);
		if (refilling) {
			message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "refilling taking a long time, aborting\n");
		}
		goto out;
	}
	pthread_create(&tid, &tattr, refill_task, NULL);
	pthread_cond_wait(&ent_cond, &ent_lock);
out:
	pthread_mutex_unlock(&ent_lock);
}

int xread_qrypt(void *buf, size_t size, struct rng *ent_src)
{
	size_t new_avail = 0;
	size_t to_copy;
	uint8_t *buf_ptr = buf;
	size_t oldsize = size;

	if (backoff_active)
	{
		/* Has the back-off delay expired? */
		struct timespec tp;
		clock_gettime(CLOCK_MONOTONIC, &tp);

		/* Only care about second-level accuracy here */
		if (difftime(tp.tv_sec, backoff_started.tv_sec) > backoff_delay)
		{
			/* Delay has expired, try again */
			backoff_active = false;
		} else {
			/* Not yet ready... */
			return -1;
		}
	}

	do {
		if (fatal_error) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_ERR, "fatal error encountered, disabling source\n");
			ent_src->disabled = true;
			return -1;
		}
		pthread_mutex_lock(&ent_lock);
		to_copy = (size >= avail_ent) ? avail_ent : size;
		if (to_copy) {
			oldsize = size;
			memcpy(buf_ptr, &entropy_buffer[ent_idx], to_copy);
			buf_ptr += to_copy;
			avail_ent -= to_copy;
			ent_idx += to_copy;
			new_avail = avail_ent;
			size -= to_copy;
		}
		pthread_mutex_unlock(&ent_lock);
		if (new_avail <= REFILL_THRESH) {
			refill_ent_buffer();
		}
	} while(size && (oldsize > size));

	return size ? -1 : 0;
	
}


/*
 * Init QRYPT
 */
int init_qrypt_entropy_source(struct rng *ent_src)
{
	FILE *tokfile;
	char *token, *tokfname = ent_src->rng_options[QRYPT_OPT_TOKEN_FILE].str_val;
	size_t toksize;
	struct stat tokstat;
	size_t header_extra_size = strlen("Authorization: Bearer  ");

	message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Initalizing qrypt beacon\n");
	if (!tokfname) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "No qrypt token file\n");
		return -1;
	}

	if (stat(tokfname, &tokstat) < 0) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Unable to stat qrypt token file\n");
		return -1;
	}

	token = alloca(tokstat.st_size + 1);
	if (!token) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Unable to allocate token data\n");
		return -1;
	}

	bearer = calloc(tokstat.st_size + header_extra_size, 1);
	if (!bearer) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Unable to allocate Bearer space\n");
		return -1;
	}

	tokfile = fopen(tokfname, "r");
	if (!tokfile) {
		free(bearer);
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "cant open token file\n");
		return -1;
	}

	toksize = fread(token, 1, tokstat.st_size, tokfile);
	fclose(tokfile);
	if (!toksize) {
		free(bearer);
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "empty token file\n");
		return -1;
	}
	token[toksize] = '\0';

	snprintf(bearer, tokstat.st_size + header_extra_size, "Authorization: Bearer %s", token);
	bearer = strtok(bearer, "\r\n");

	backoff_max = ent_src->rng_options[QRYPT_OPT_MAX_ERROR_DELAY].int_val;
	my_ent_src = ent_src;

	refill_ent_buffer();
	return 0;
}

void close_qrypt_entropy_source(struct rng *ent_src)
{
	free(bearer);
	bearer = NULL;
	return;
}
