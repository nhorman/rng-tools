/*
 * Copyright (c) 2020, Neil Horman
 * Author:  Neil Horman <nhorman@tuxdriver.com>
 *
 * Entropy source to derive random data from atmospheric static obtained by
 * randomly varying the frequency and sample rate of rtl software defined radios
 * through the rtlsdr library.
 *
 * Based in part on the work found at:
 * http://rtl2832-entropyd.sourceforge.net/
 */

#include <stdlib.h>
#include <string.h>
#include <rtl-sdr.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "rngd.h"

#define RAW_BUF_SZ	    4096

#define CHUNK_SIZE	      (AES_BLOCK*8)   /* 8 parallel streams */
#define AES_BLOCK	       16

static rtlsdr_dev_t *radio = NULL;
static char raw_buffera[RAW_BUF_SZ];
static int freq_min;
static int freq_max;
static int sample_min;
static int sample_max;
static int gain = 200;

static int get_random_freq()
{
	int range = freq_max - freq_min;
	long int random_val = random();
	random_val = random_val % range;
	return freq_min + random_val;
}

static int get_random_sample_rate()
{
	int range = sample_min - sample_max;
	long int random_val = random();
	random_val = random_val % range;
	return sample_min + random_val;
}

static int nearest_gain(rtlsdr_dev_t *radio, struct rng *ent_src, int target_gain )
{
	int i, err1, err2, count, close_gain;
	int *gains;
	count = rtlsdr_get_tuner_gains(radio, NULL);
	if (count <= 0)
		return 0;
	gains = malloc(sizeof(int) * count);
	count = rtlsdr_get_tuner_gains(radio, gains);
	close_gain = gains[0];
	message_entsrc(ent_src, LOG_DAEMON, "Capable Gains:\n");
	for (i = 0; i < count; i++) {
		message_entsrc(ent_src, LOG_DAEMON, "%d\n", gains[i]);
		err1 = abs(target_gain - close_gain);
		err2 = abs(target_gain - gains[i]);
		if (err2 < err1)
			close_gain = gains[i];
	}
	free (gains);
	return close_gain;
}


int init_rtlsdr_entropy_source(struct rng *ent_src)
{
	int devcount;
	int i;
        int devid;
	char vendor[256];
	char product[256];
	int rc;
	int sample_rate;
	int freq;

	devcount = rtlsdr_get_device_count();
	if (devcount == 0) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_DEBUG, "No rtlsdr radio devices found\n");
		return 1;
	}
	message_entsrc(ent_src,LOG_DAEMON, "rtlsdr devices found:\n");
	for (i=0; i<devcount; i++) {
		memset(vendor, 0, 256);
		memset(product, 0, 256);
		if (rtlsdr_get_device_usb_strings(i, vendor, product, NULL))
			continue;
		message_entsrc(ent_src, LOG_DAEMON, "%d: %s %s\n", i, vendor, product);
	}

        /*
         * Get our default sample rate and freq settings, as well as the devid
         * to use
         */
        freq_min = ent_src->rng_options[RTLSDR_OPT_FREQ_MIN].int_val;
        freq_max = ent_src->rng_options[RTLSDR_OPT_FREQ_MAX].int_val;
        sample_min = ent_src->rng_options[RTLSDR_OPT_SRATE_MIN].int_val;
        sample_max = ent_src->rng_options[RTLSDR_OPT_SRATE_MAX].int_val;
        devid = ent_src->rng_options[RTLSDR_OPT_DEVID].int_val;

	message_entsrc(ent_src, LOG_DAEMON, "Using device %d\n", devid);
	rc = rtlsdr_open(&radio, devid);
	if (rc) {
		message_entsrc(ent_src, LOG_DAEMON, "Failed to open radio at index %d: %d\n", i, rc);
		return 1;
	}
	if (rtlsdr_set_tuner_gain_mode(radio, 1)) {
		message_entsrc(ent_src, LOG_DAEMON, "Failed to set manual gain mode\n");
		return 1;
	}

	gain = nearest_gain(radio, ent_src, gain); 
	message_entsrc(ent_src, LOG_DAEMON, "Setting gain to %d\n", gain);
	if (rtlsdr_set_tuner_gain(radio, gain)) {
		message_entsrc(ent_src, LOG_DAEMON, "Failed to set gain\n");
		return 1;
	}
	sample_rate = get_random_sample_rate();
	message_entsrc(ent_src, LOG_DAEMON, "Setting sample rate to %d\n", sample_rate);
	if (rtlsdr_set_sample_rate(radio, sample_rate)) {
		message_entsrc(ent_src, LOG_DAEMON, "Failed to set sample rate\n");
		return 1;
	}
	freq = get_random_freq();
	message_entsrc(ent_src, LOG_DAEMON, "Setting frequency to %d\n", freq);
	if (rtlsdr_set_center_freq(radio, freq)) {
		message_entsrc(ent_src, LOG_DAEMON, "Failed to set frequency\n");
		return 1;
	}
	rtlsdr_reset_buffer(radio);
	return 0;
}

void close_rtlsdr_entropy_source(struct rng *ent_src)
{
	if (radio)
		rtlsdr_close(radio);
	return;
}

static size_t condition_buffer(unsigned char *in, unsigned char *out, size_t insize, size_t outsize)
{
	EVP_CIPHER_CTX *ctx;
	static unsigned char key[AES_BLOCK];
	unsigned char iv[CHUNK_SIZE] __attribute__((aligned(128)));
	int len;
	size_t ciphertext_len = 0;

	/*
	 * Setup our key and iv
	 */
	memcpy(key, in, AES_BLOCK);
	memcpy(iv, &in[AES_BLOCK], CHUNK_SIZE);

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		return 0;

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		goto out;
	/*
	* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, out, &len, in, insize))
		goto out;

	ciphertext_len = len;

	/*
	* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, out, &len))
		return 0;
	ciphertext_len += len;

out:
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int xread_rtlsdr(void *buf, size_t size, struct rng *ent_src)
{
	int rc;
	int read_len;
	size_t gen_len;
	char *buf_ptr = buf;
	unsigned char outbuf[RAW_BUF_SZ + EVP_MAX_BLOCK_LENGTH];
	size_t copy_size;
	size_t total_size = 0;
	while (total_size < size) {
		if (rtlsdr_set_center_freq(radio, get_random_freq())) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Failed to adjust frequency\n");
			return 1;
		}
		if (rtlsdr_set_sample_rate(radio, get_random_sample_rate())) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Failed to adjust sample rate\n");
			return 1;
		}
		rtlsdr_reset_buffer(radio);
		rc = rtlsdr_read_sync(radio, raw_buffera, RAW_BUF_SZ, &read_len);
		if (rc) {
			message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Radio read failed (buffer b): %d\n", rc);
			return 1;
		}
		gen_len = condition_buffer(raw_buffera, outbuf, RAW_BUF_SZ, RAW_BUF_SZ);
		copy_size = (size - total_size) < gen_len ? (size - total_size) : gen_len;
		memcpy(buf_ptr, outbuf, copy_size);
		buf_ptr += copy_size;
		total_size += copy_size;
	}
	return 0;
}

