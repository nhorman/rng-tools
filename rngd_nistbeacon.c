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

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
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
#include <sysfs/libsysfs.h>
#include <curl/curl.h>
#include <libxml/xmlreader.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

#define min(x,y) ({ \
	typeof(x) _x = (x);     \
	typeof(y) _y = (y);     \
	(void) (&_x == &_y);    \
	_x < _y ? _x : _y; })

#define NIST_RECORD_URL "https://beacon.nist.gov/rest/record/last"
#define NIST_BUF_SIZE 512
#define NIST_CERT "/home/nhorman/Downloads/beacon.cer"

static char nist_pubkey[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryY9m2YHOui12tk93ntM\n"
"ZAL2uvlXr7jTaxx5WJ1PM6SJllJ3IopuwUQGLxUEDNinFWE2xlF5sayoR+CRZGDG\n"
"6Hjtw2fBRcsQKiIpaws6CdusRaRMM7Wjajm3vk96gD7Mwcqo+uxuq9186UeNPLeA\n"
"xMmFlcQcSD4pJgKrZKgHtOk0/t2kz9cgJ343aN0LuV7w91LvfXwdeCtcHM4nyt3g\n"
"V+UyxAe6wPoOSsM6Px/YLHWqAqXMfSgEQrd920LyNb+VgNcPyqhLySDyfcUNtr1B\n"
"S09nTcw1CaE6sTmtSNLiJCuWzhlzsjcFh5uMoElAaFzN1ilWCRk/02/B/SWYPGxW\n"
"IQIDAQAB\n"
"-----END PUBLIC KEY-----";

static int get_nist_record();

int read_nist_pubkey();
void cleanup_nist_pubkey();

int read_nist_certificate();
void cleanup_nist_work();

static size_t nist_buf_avail = 0;
static size_t nist_buf_ptr = 0;
static char nist_rand_buf[NIST_BUF_SIZE];
static EVP_PKEY *pkey;
static char errbuf[120];
int cfp;
BIO *bfp;

struct nist_data_block {
	char *version;
	uint32_t frequency;
	uint64_t timestamp;
	unsigned char *seedvalue;
	size_t seedvaluelen;
	unsigned char *previoushash;
	size_t previoushashlen;
	unsigned int errorcode;
	size_t errorcodelen;
	unsigned char *sigvalue;
	size_t sigvaluelen;
	unsigned char *sighash;
	size_t sighashlen;
};

static struct nist_data_block block;

static int refill_rand()
{

	if (nist_buf_avail > 0)
		return 0;

	if (get_nist_record())
		return 1;

	memcpy(nist_rand_buf, block.seedvalue, block.seedvaluelen);
	nist_buf_avail = block.seedvaluelen;
	nist_buf_ptr = 0;

	return 0;
}

static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied)
{
	size_t left_to_copy = size - copied;
	size_t to_copy = min(left_to_copy, nist_buf_avail);

	memcpy(&buf[copied], &nist_rand_buf[nist_buf_ptr], to_copy);

	nist_buf_avail -= to_copy;
	nist_buf_ptr += to_copy;
	return to_copy;
}


int xread_nist(void *buf, size_t size, struct rng *ent_src)
{
	size_t copied = 0;

	while (copied < size) {
		if (refill_rand()) {
			return 1;
		}
		copied += copy_avail_rand_to_buf(buf, size, copied);
	}
	return 0;
}

static void dup_val(unsigned char **v, size_t *len, xmlTextReaderPtr reader)
{
	int i;
	char tmp;
	char *val = (char *)xmlTextReaderReadInnerXml(reader);

	if (val && strlen(val) >= 1) {
		*len = strlen(val);
		*(char **)v = strdup(val);
		for (i=0; i < *len; i++) {
			tmp = (*v)[i+1];
			(*v)[i+1] = '\0';
			((char *)(*v))[i] = strtol(&((((char *)*v))[i]), NULL, 16);
			(*v)[i+1] = tmp;
		}
	}
}

/*
 * The seed, previous and current hash values are ascii representations
 * of large ( > 8 byte) values.  Because of that, each byte in the ascii
 * representation only represent 4 bits of the actual value.  So to really work
 * with it we have to drop the most significant 4 bits of each byte, and
 * compress adjacent half words to form a proper real byte of the value.  Note
 * length of the value is the length of the string, not the real hash
 */
static void dup_val_compress(unsigned char **v, size_t *len, xmlTextReaderPtr reader)
{
	int i,j;

	dup_val(v, len, reader);

        if (*len > 1) {
		/* for each byte in value ... */
		for(i=0;i<*len;i++){
			/*
			 * the output index is half the input index,
			 * with trucation intended
			 */
			j=i/2;
			/* odd bytes in input represent the upper 4 bits 
			 * of the output bytes */
			if (!(i & 0x1)) {
				/*
				 * odd bytes in input represent the upper
				 * 4 bits of the output word
				 */
				(*v)[j] = (*v)[i] << 4;
			} else {
				/* 
				 * even bytes are the lower 4 bits
				 */
				(*v)[j] |= (*v)[i];
			}
		}

		/*
		 * the output len is half the input len
		 */
		*len /= 2;
	}

}

/*
 * Because Microsoft forgot to make the output
 * signature arrive in network byte order, some values
 * always have to be byte reversed so openssl can digest 
 * them
 */
unsigned char *reverse(unsigned char **srcp, size_t len)
{
	int i,j;
	unsigned char *src = *srcp;
	unsigned char *result = malloc(len);

	if (!result)
		return NULL;

	for (i=0, j=len - 1; i <= j; ++i, --j) {
	    result[i] = src[j];
	    result[j] = src[i];
	}

	free(*srcp);
	*srcp = result;
	return result;
}

/*
 * Note, I'm making the assumption that the entire xml block gets returned 
 * in a single call here, which I should fix
 */
static size_t parse_nist_xml_block(char *ptr, size_t size, size_t nemb, void *userdata)
{
	xmlTextReaderPtr reader;
	int ret = 1;
	const char *name;
	size_t realsize = size * nemb;
	char *xml = (char *)ptr;

#define FREE_VAL(b) do {if (b) free(b); (b) = NULL;} while(0)

	block.errorcode = block.timestamp = block.frequency = 0;
	FREE_VAL(block.version);
	FREE_VAL(block.seedvalue);
	FREE_VAL(block.previoushash);
	FREE_VAL(block.sigvalue);
	FREE_VAL(block.sighash);


	reader = xmlReaderForMemory(xml, realsize, NIST_RECORD_URL, NULL, 0);
	if (!reader) {
		message(LOG_DAEMON|LOG_ERR, "Unparseable XML\n");
		return 0;
	}

	while (ret == 1) {
		name = (const char *)xmlTextReaderConstName(reader);
		if (name) {
			if (!strcmp(name, "version")) {
				unsigned char *val = xmlTextReaderReadInnerXml(reader);
				if (val && strlen((char *)val)) {
					block.version = malloc(strlen((char *)val) + 1);
					memset(block.version, 0, strlen((char *)val) + 1);
					strcpy(block.version, (char *)val);
				}
			} else if (!strcmp(name, "frequency")) {
				int freq;
				if (!block.frequency) {
					unsigned char *val = xmlTextReaderReadInnerXml(reader);
					if (val && strlen((char *)val)) {
						sscanf((char *)val, "%d", &freq);
						block.frequency = be32toh(freq);
					}
				}
			} else if (!strcmp(name, "timeStamp")) {
				long stamp;
				if (!block.timestamp) {
					unsigned char *val = xmlTextReaderReadInnerXml(reader);
					if (val && strlen((char *)val)) {
						sscanf((char *)val, "%lu", &stamp);
						block.timestamp = be64toh(stamp);
					}
				}
			} else if (!strcmp(name, "seedValue")) {
				if (!block.seedvalue)
					dup_val_compress(&block.seedvalue, &block.seedvaluelen, reader);
			} else if (!strcmp(name, "previousOutputValue")) {
				if (!block.previoushash)
					dup_val_compress(&block.previoushash, &block.previoushashlen, reader);
			} else if (!strcmp(name, "signatureValue")) {
				if (!block.sigvalue) {
					dup_val_compress(&block.sigvalue, &block.sigvaluelen, reader);
				}
			} else if (!strcmp(name, "statusCode")) {
				if (!block.errorcode) {
					unsigned char *val = xmlTextReaderReadInnerXml(reader);
					sscanf((char *)val, "%u", &block.errorcode);
					block.errorcodelen = 4;
				}
			} else if (!strcmp(name, "outputValue")) {
				if (!block.sighash)
					dup_val_compress(&block.sighash, &block.sighashlen, reader);
			}
		}
		ret = xmlTextReaderRead(reader);
	}


	xmlTextReaderClose(reader);
	return realsize;
}

static int validate_nist_block()
{
	SHA512_CTX sha_ctx = { 0 };
	unsigned char digest[SHA512_DIGEST_LENGTH];
	EVP_MD_CTX *mdctx;
	const EVP_MD* md = EVP_get_digestbyname("RSA-SHA512");
	int ret = 1;

	if (read_nist_pubkey())
		goto out;
	
	mdctx = EVP_MD_CTX_create();

	memset(digest, 0, SHA512_DIGEST_LENGTH);

	EVP_MD_CTX_init(mdctx);

	if (!EVP_VerifyInit_ex(mdctx, md, NULL)) {
		message(LOG_DAEMON|LOG_ERR, "Unable to Init Verifyer");
		goto out;
	}

	if (SHA512_Init(&sha_ctx) != 1) {
		message(LOG_DAEMON|LOG_ERR, "Unable to init SHA512\n");
		goto out;
	}

	if (SHA512_Update(&sha_ctx, block.sigvalue, block.sigvaluelen) != 1) {
		message(LOG_DAEMON|LOG_ERR, "Unable to update sha512\n");
		goto out;
	}

	if (SHA512_Final(digest, &sha_ctx) != 1) {
		message(LOG_DAEMON|LOG_ERR, "Unable to finalize sha512\n");
		goto out;
	}

	if (memcmp(digest, block.sighash, SHA512_DIGEST_LENGTH)) {
		message(LOG_DAEMON|LOG_ERR, "Digest mismatch in nist block validation\n");
		goto out;
	}


	EVP_VerifyUpdate(mdctx, block.version, strlen(block.version));
	EVP_VerifyUpdate(mdctx, &block.frequency, sizeof(uint32_t));
	EVP_VerifyUpdate(mdctx, &block.timestamp, sizeof(uint64_t));
	EVP_VerifyUpdate(mdctx, block.seedvalue, block.seedvaluelen);
	EVP_VerifyUpdate(mdctx, block.previoushash, block.previoushashlen);
	EVP_VerifyUpdate(mdctx, &block.errorcode, block.errorcodelen);

	if (!reverse(&block.sigvalue, block.sigvaluelen)) {
		message(LOG_DAEMON|LOG_ERR, "Unable to allocate memory for sig reversal\n");
		goto out;
	}

	if (EVP_VerifyFinal(mdctx, block.sigvalue, block.sigvaluelen, pkey) != 1) {
		unsigned long err;
		message(LOG_DAEMON| LOG_ERR, "Unable to validate signature on message\n");
		while( (err = ERR_get_error()) != 0 ) {
			ERR_error_string(err, errbuf);
			puts (errbuf);
		}

		goto out;
	}

	ret = 0;
	EVP_MD_CTX_destroy(mdctx);
out:
	cleanup_nist_pubkey();
	return ret;

}

static int get_nist_record()
{
	CURL *curl;
	CURLcode res;
	int rc = 1;
	struct timeval ct;

	if (block.frequency != 0) {
		if (gettimeofday(&ct, NULL)) {
			message(LOG_DAEMON|LOG_ERR, "Gettimeofday failed\n");
			goto out;
		}

		message(LOG_DAEMON|LOG_DEBUG, "NIST: timestamp is %d, frequency is %d, tv_sec is %d\n",
			block.timestamp, block.frequency, ct.tv_sec);
		if (block.timestamp + block.frequency >= ct.tv_sec) {
			message(LOG_DAEMON|LOG_ERR, "Multiple nist reads in same frequency period of %d sec\n",
				block.frequency);
			goto out;
		}
	}

	curl = curl_easy_init();

	if (!curl)
		goto out;

	curl_easy_setopt(curl, CURLOPT_URL, NIST_RECORD_URL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, nist_rand_buf);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, parse_nist_xml_block);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", 
			curl_easy_strerror(res));
		goto out;
	}

	curl_easy_cleanup(curl);

	if (validate_nist_block()) {
		message(LOG_DAEMON|LOG_ERR, "Recieved block failed validation\n");
		goto out;
	}

	rc = 0;

out:
	return rc;
	
}

int read_nist_pubkey()
{
	RSA *rsa = RSA_new();

	pkey = EVP_PKEY_new();
	bfp = BIO_new_mem_buf(nist_pubkey, -1);


	rsa = PEM_read_bio_RSA_PUBKEY(bfp, &rsa, NULL,  NULL);

	EVP_PKEY_assign_RSA(pkey, rsa);

	return 0;
}

void cleanup_nist_pubkey()
{
	EVP_PKEY_free(pkey);
	pkey = NULL;
	BIO_free(bfp);
	bfp = NULL;
}

/*
 * Confirm DARN capabilities for drng entropy source
 */
int init_nist_entropy_source(struct rng *ent_src)
{
	int rc;
	memset(&block, 0, sizeof (struct nist_data_block));

	rc = refill_rand();
	if (!rc) {
		message(LOG_DAEMON|LOG_WARNING, "WARNING: NIST Randomness beacon "
						"is sent in clear text over the internet.  "
						"Do not use this source in any entropy pool "
						"which generates cryptographic objects!\n");
	}
	return rc;
}
