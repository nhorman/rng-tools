/*
 * Copyright (c) 2022, Neil Horman 
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
static struct rng *my_ent_src;
static char bearer[4096];

struct body_buffer {
	char *response;
	size_t size;
};

static int decoding_table[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

uint8_t *base64_decode(const char *     data,
		       size_t	   input_length,
		       size_t *	 output_length)
{
	if (input_length % 4 != 0) {
		return NULL;
	}

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') {
		(*output_length)--;
	}
	if (data[input_length - 2] == '=') {
		(*output_length)--;
	}

	uint8_t *decoded_data = malloc(*output_length);

	if (decoded_data == NULL) {
		return NULL;
	}

	for (int i = 0, j = 0; i < input_length;) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
				  + (sextet_b << 2 * 6)
				  + (sextet_c << 1 * 6)
				  + (sextet_d << 0 * 6);

		if (j < *output_length) {
			decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		}
		if (j < *output_length) {
			decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		}
		if (j < *output_length) {
			decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
		}
	}

	return decoded_data;
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
		goto out;
	}

	array = json_object_get(json, "random");
	if (!array) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to find random array\n");
		goto out;
	}

	bdata = json_array_get(array, 0);
	if (!bdata) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to find random array index\n");
		goto out;
	}

	decode_data = base64_decode(json_string_value(bdata), strlen(json_string_value(bdata)), &decode_len);	
	if (!decode_data) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "failed to decode random data\n");
		goto out;
	}

	pthread_mutex_lock(&ent_lock);
	memcpy(entropy_buffer, decode_data, decode_len);
	ent_idx = 0;
	avail_ent = decode_len;
	pthread_mutex_unlock(&ent_lock);
	
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

static void *refill_task(void *data __attribute__((unused)))
{
	CURL *curl;
	struct curl_slist *list = NULL;
	CURLcode res;
	long response_code;
	struct body_buffer response_data;
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
	curl_easy_setopt(curl, CURLOPT_URL, QRYPT_URL);
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	list = curl_slist_append(list, "Accept: application/json");
	list = curl_slist_append(list, bearer); 

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "Failed to send curl: %d\n", res);
		goto out;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (response_code != 200) {
		message_entsrc(my_ent_src, LOG_DAEMON|LOG_INFO, "qrypt server responds not ok: %lu\n", response_code);
		goto out;
	}
	extract_and_refill_entropy(&response_data);
	
out:
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
	bool satisfied = false;
	pthread_mutex_lock(&ent_lock);
	if (avail_ent >= size) {
		memcpy(buf, &entropy_buffer[ent_idx], size);
		avail_ent -= size;
		ent_idx += size;
		new_avail = avail_ent;
		satisfied = true;
	}
	pthread_mutex_unlock(&ent_lock);
	if (new_avail <= REFILL_THRESH) {
		refill_ent_buffer();
	}
	return satisfied ? 0 : -1;
}


/*
 * Init QRYPT 
 */
int init_qrypt_entropy_source(struct rng *ent_src)
{
	char *tokfile = ent_src->rng_options[QRYPT_OPT_TOKEN_FILE].str_val;
	FILE *tokdata;
	char token[2048];
	size_t toksize;
	message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "Initalizing qrypt beacon\n");
	if (!tokfile) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "No qrypt token file\n");
		return -1;
	}

	tokdata = fopen(tokfile, "r");
	if (!tokdata) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "cant open token file\n");
		return -1;
	}
	toksize = fread(token, 1, 2048, tokdata);
	fclose(tokdata);
	if (!toksize) {
		message_entsrc(ent_src, LOG_DAEMON|LOG_INFO, "empty token file\n");
		return -1;
	}
	memset(bearer, 0, 4096);
	snprintf(bearer,4096, "Authorization: Bearer %s", token);
		
	my_ent_src = ent_src;

	refill_ent_buffer();
	return 0;
}

void close_qrypt_entropy_source(struct rng *ent_src)
{
	return;
}
