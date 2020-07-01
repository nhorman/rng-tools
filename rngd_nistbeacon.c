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
#include <jansson.h>
#include <ctype.h>
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

#define NIST_RECORD_URL "https://beacon.nist.gov/beacon/2.0/pulse/last"
#define NIST_CERT_BASE_URL "https://beacon.nist.gov/beacon/2.0/certificate/"
#define NIST_BUF_SIZE 64 
#define NIST_CERT "/home/nhorman/Downloads/beacon.cer"

#ifdef CLOCK_MONOTONIC_COARSE
#define NIST_CLOCK_SOURCE CLOCK_MONOTONIC_COARSE
#else
#define NIST_CLOCK_SOURCE CLOCK_MONOTONIC
#endif

static int get_nist_record(struct rng *ent_src);


static size_t nist_buf_avail = 0;
static size_t nist_buf_ptr = 0;
static char nist_rand_buf[NIST_BUF_SIZE];
static char errbuf[120];
int cfp;

/*
 * Built from https://beacon.nist.gov/ns/beacon/pulse/2.0/beacon-2.0.xsd
 * Note all values are big endian and must remain so for the purposes 
 * of hashing, but must be converted to local endianess for the purpose of 
 * copying to the hash library
 */
struct nist_data_block {
        uint32_t urilen; /* strlen(uri) */
        char *uri; /* UTF-8 seq of chars */
        uint32_t verlen; /* strlen(version) */
	char *version; /* UTF-8 seq of chars */
        uint32_t cipherSuite; /* Big endian 32 bit value */
        uint32_t period; /* Big endian 32 bit value */
        uint32_t certificateIdLen; /* length of certificateid array */
        char *certificateId; /* hex decoded seq of bytes */
        uint32_t certificateIdStringLen; /* len of cert id string */
        char *certificateIdString; /* certificate id string */
        uint64_t chainIndex; /* 64 bit big endian integer value */
        uint64_t pulseIndex; /* 64 bit big endian integer value */
        uint32_t timeStampLen; /* strlen(timestamp) */
        char *timeStamp; /* UTF-8 seq of chars */
        uint32_t localRandomLen; /* length of localRandomValueArray */
        char *localRandomValue; /* hex decoded seq of bytes */
        uint32_t exSourceIdLen; /* length of external/SourceId array */
        char *exSourceId; /* hex decoded seq of bytes */
        uint32_t exStatusCode; /* 32 bit big endian value */
        uint32_t exValueLen; /* length of exValue Array */
        char *exValue; /* hex decoded seq of bytes */
        uint32_t prevValueLen; /* Length of previous value arrah */
        char *prevValue; /* hex decoded seq of bytes for prev value */
        uint32_t hourValueLen; /* Length of previous value arrah */
        char *hourValue; /* hex decoded seq of bytes for prev value */
        uint32_t dayValueLen; /* Length of previous value arrah */
        char *dayValue; /* hex decoded seq of bytes for prev value */
        uint32_t monthValueLen; /* Length of previous value arrah */
        char *monthValue; /* hex decoded seq of bytes for prev value */
        uint32_t yearValueLen; /* Length of previous value arrah */
        char *yearValue; /* hex decoded seq of bytes for prev value */
        uint32_t preCommitValueLen; /* length of precommit value array */
        char *preCommitValue; /* hex decoded array of bytes */
        uint32_t statusCode; /* 32 bit big endian integer */
        char *signatureValue; /* hex encoded byte array */
        uint32_t signatureValueLen; /* length of signatureValue */ 
        char *outputValue; /* expected sha 512 hex buffer */
        uint32_t outputValueLen; /* Len of sha512 hex string */
};

static struct nist_data_block block;

char *activeCertId = NULL;
char *activeCert = NULL;
BIO *bfp = NULL;
X509 *cert = NULL;
EVP_PKEY *pubkey;
uint64_t lastpulse = 0;

#define AES_BLOCK               16
#define CHUNK_SIZE              (AES_BLOCK*8)   /* 8 parallel streams */
#define RDRAND_ROUNDS           512             /* 512:1 data reduction */
static unsigned char key[AES_BLOCK] = {0,};

static int osslencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
        EVP_CIPHER_CTX *ctx;

        int len;

        int ciphertext_len;

        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
                return 0;

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
                return 0;
        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                return 0;

        ciphertext_len = len;

        /*
        * Finalise the encryption. Further ciphertext bytes may be written at
        * this stage.
        */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
                return 0;
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
}

static inline int openssl_mangle(unsigned char *tmp, size_t size, struct rng *ent_src)
{
        unsigned char xkey[AES_BLOCK];  /* Material to XOR into the key */
        unsigned char iv_buf[CHUNK_SIZE];
        int i;        
        int ciphertext_len;

        /*
        * Buffer for ciphertext. Ensure the buffer is long enough for the
        * ciphertext which may be longer than the plaintext, depending on the
        * algorithm and mode.
        */
        unsigned char ciphertext[CHUNK_SIZE * RDRAND_ROUNDS];

        for(i=0; i < AES_BLOCK; i++) 
                key[i] = key[i] ^ xkey[i];

        /* Encrypt the plaintext */
        ciphertext_len = osslencrypt (tmp, size, key, iv_buf,
                              ciphertext);
        if (!ciphertext_len)
                return -1;

        memcpy(tmp, ciphertext, size);
        return 0;
}

static int refill_rand(struct rng *ent_src)
{
	static struct timespec last = {0, 0};
	struct timespec now;

	if (nist_buf_avail > 0)
		return 0;

	clock_gettime(NIST_CLOCK_SOURCE, &now);
	if (last.tv_sec == 0 || (now.tv_sec-last.tv_sec > 60)) {
		last.tv_sec = now.tv_sec;
		message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Getting new record\n");
                if (get_nist_record(ent_src))
                        return 1;
        }
        if (block.pulseIndex == lastpulse) {
                if (ent_src->rng_options[NIST_OPT_USE_AES].int_val) {
                        if (openssl_mangle(nist_rand_buf, NIST_BUF_SIZE, ent_src) != 0) {
                                message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Failed mangle\n");
                                return 1;
                        }
                        goto fresh_buffer;
                } else
                        return 0;
        }

	memcpy(nist_rand_buf, block.outputValue, be32toh(block.outputValueLen));
fresh_buffer:
	nist_buf_avail = NIST_BUF_SIZE;
	nist_buf_ptr = 0;

	return 0;
}

static size_t copy_avail_rand_to_buf(unsigned char *buf, size_t size, size_t copied)
{
	size_t left_to_copy = size - copied;
	size_t to_copy = left_to_copy < nist_buf_avail ? left_to_copy : nist_buf_avail;

	memcpy(&buf[copied], &nist_rand_buf[nist_buf_ptr], to_copy);

	nist_buf_avail -= to_copy;
	nist_buf_ptr += to_copy;
	return to_copy;
}


int xread_nist(void *buf, size_t size, struct rng *ent_src)
{
	size_t copied = 0;

	while (copied < size) {
                /*
                 * Bail out if the daemon is shutting down
                 */
                if (server_running == false)
                        return 1;
		if ((nist_buf_avail == 0) && refill_rand(ent_src))
			return 1;
                if (nist_buf_avail == 0)
                        return 1;
		copied += copy_avail_rand_to_buf(buf, size, copied);
                message_entsrc(ent_src, LOG_DAEMON|LOG_DEBUG, "Got %zu/%zu bytes data\n", copied, size);
	}
	return 0;
}


static void get_json_string_and_len(json_t *parent, char *key, char **val, uint32_t *len)
{
        const char *tmpval;
        uint32_t slen;
        json_t *obj = json_object_get(parent, key);
        tmpval = json_string_value(obj);
        slen = strlen(tmpval);
        *val = strdup(tmpval);
        if (len != NULL)
                *len = htobe32(slen);
        return;
}

static void get_json_u32_value(json_t *parent, char *key, uint32_t *val)
{
        json_t *obj = json_object_get(parent, key);
        *val = htobe32((uint32_t)(json_integer_value(obj)));
        return;
}

static void get_json_u64_value(json_t *parent, char *key, uint64_t *val)
{
        json_t *obj = json_object_get(parent, key);
        *val = htobe64((uint64_t)(json_integer_value(obj)));
        return;
}

static void get_json_byte_array(json_t *parent, char *key, char **val, uint32_t *len)
{
        bool unibble;
        int i,j;
        json_t *obj = json_object_get(parent, key);
        uint32_t rawlen;
        const char *rawstring = json_string_value(obj);
        char *newval;
        char tmpval;

        rawlen = strlen(rawstring);
        if (rawlen%2)
                message(LOG_DAEMON|LOG_ERR, "Byte array isn't of even length!\n");
 
        newval = malloc(rawlen/2);
        unibble = true;
 
        for(i=j=0;i<rawlen;i++) {
                char nibble = rawstring[i];
                if (isalpha(nibble)) {
                        nibble = toupper(nibble);
                        nibble = nibble - 0x37; /*convert to hex val*/
                } else
                        nibble = nibble - 0x30; /* convert to hex val*/                        
                if (unibble) {
                        tmpval = nibble << 4;
                        unibble = false;
                } else {
                        tmpval = tmpval | nibble;
                        newval[j] = tmpval;
                        unibble = true;
                        j++;
                }
        } 
        *len = htobe32(rawlen/2); 
        *val = newval;
        return; 
}

/*
 * Note, I'm making the assumption that the entire xml block gets returned 
 * in a single call here, which I should fix
 */
static size_t parse_nist_json_block(char *ptr, size_t size, size_t nemb, void *userdata)
{
        size_t idx;
        json_t *jidx;
	xmlTextReaderPtr reader;
	int ret = 1;
	const char *name;
	size_t realsize = size * nemb;
	char *xml = (char *)ptr;
        json_t *json, *pulse, *values, *obj;
        json_error_t jsonerror;
        struct rng *ent_src = userdata;


        json = json_loads(ptr, size, &jsonerror);
        if (!json) {
                message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unparseable JSON\n");
                return 0;
        }
        pulse = json_object_get(json, "pulse");

        get_json_string_and_len(pulse, "uri", &block.uri, &block.urilen);

        get_json_string_and_len(pulse, "version", &block.version, &block.verlen);

        get_json_u32_value(pulse, "cipherSuite", &block.cipherSuite);

        get_json_u32_value(pulse, "period", &block.period);
        get_json_byte_array(pulse, "certificateId", &block.certificateId, &block.certificateIdLen);

        get_json_string_and_len(pulse, "certificateId", &block.certificateIdString, &block.certificateIdStringLen);

        get_json_u64_value(pulse, "chainIndex", &block.chainIndex);

        get_json_u64_value(pulse, "pulseIndex", &block.pulseIndex);

        get_json_string_and_len(pulse, "timeStamp", &block.timeStamp, &block.timeStampLen);
        get_json_byte_array(pulse, "localRandomValue", &block.localRandomValue, &block.localRandomLen);
        obj = json_object_get(pulse, "external");
        get_json_byte_array(obj, "sourceId", &block.exSourceId, &block.exSourceIdLen);
        get_json_u32_value(obj, "statusCode", &block.exStatusCode);
        get_json_byte_array(obj, "value", &block.exValue, &block.exValueLen);
        obj = json_object_get(pulse, "listValues");
        json_array_foreach(obj, idx, jidx) {
                json_t *tobj = json_object_get(jidx, "type");
                const char *type = json_string_value(tobj);

                if (!strncmp("previous", type, strlen("previous"))) {
                        get_json_byte_array(jidx, "value", &block.prevValue, &block.prevValueLen); 
                } else if (!strncmp("hour", type, strlen("hour"))) {
                        get_json_byte_array(jidx, "value", &block.hourValue, &block.hourValueLen);
                } else if (!strncmp("day", type, strlen("day"))) {
                        get_json_byte_array(jidx, "value", &block.dayValue, &block.dayValueLen);
                } else if (!strncmp("month", type, strlen("month"))) {
                        get_json_byte_array(jidx, "value", &block.monthValue, &block.monthValueLen);
                } else if (!strncmp("year", type, strlen("yar"))) {
                        get_json_byte_array(jidx, "value", &block.yearValue, &block.yearValueLen);
                }

        }

        get_json_byte_array(pulse, "precommitmentValue", &block.preCommitValue, &block.preCommitValueLen);
        get_json_u32_value(pulse, "statusCode", &block.statusCode);

        get_json_byte_array(pulse, "signatureValue", &block.signatureValue, &block.signatureValueLen);
        get_json_byte_array(pulse, "outputValue", &block.outputValue, &block.outputValueLen);
        json_decref(json);

        return realsize;
}

static int validate_nist_block(struct rng *ent_src)
{
	unsigned char digest[SHA512_DIGEST_LENGTH];
	EVP_MD_CTX *mdctx;
	const EVP_MD* md = EVP_get_digestbyname("RSA-SHA512");
	int ret = 1;
        uint32_t flen;
	mdctx = EVP_MD_CTX_create();

	memset(digest, 0, SHA512_DIGEST_LENGTH);

	EVP_MD_CTX_init(mdctx);

	if (!EVP_VerifyInit_ex(mdctx, md, NULL)) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to Init Verifier");
		goto out;
	}

        /*
         * Validate the signature
         */
        flen = block.urilen;
	if (EVP_VerifyUpdate(mdctx, &flen, sizeof(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.uri, be32toh(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

        flen = block.verlen;
	if (EVP_VerifyUpdate(mdctx, &flen, sizeof(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}
	if (EVP_VerifyUpdate(mdctx, block.version, be32toh(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.cipherSuite, sizeof(block.cipherSuite)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.period, sizeof(block.period)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.certificateIdLen, sizeof(block.certificateIdLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.certificateId, be32toh(block.certificateIdLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.chainIndex, sizeof(block.chainIndex)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.pulseIndex, sizeof(block.pulseIndex)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

        flen = block.timeStampLen;
	if (EVP_VerifyUpdate(mdctx, &flen, sizeof(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.timeStamp, be32toh(flen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.localRandomLen, sizeof(block.localRandomLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.localRandomValue, be32toh(block.localRandomLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.exSourceIdLen, sizeof(block.exSourceIdLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.exSourceId, be32toh(block.exSourceIdLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.exStatusCode, sizeof(block.exStatusCode)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.exValueLen, sizeof(block.exValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.exValue, be32toh(block.exValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.prevValueLen, sizeof(block.prevValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.prevValue, be32toh(block.prevValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.hourValueLen, sizeof(block.hourValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.hourValue, be32toh(block.hourValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.dayValueLen, sizeof(block.dayValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.dayValue, be32toh(block.dayValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.monthValueLen, sizeof(block.monthValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.monthValue, be32toh(block.monthValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.yearValueLen, sizeof(block.yearValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.yearValue, be32toh(block.yearValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.preCommitValueLen, sizeof(block.preCommitValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, block.preCommitValue, be32toh(block.preCommitValueLen)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyUpdate(mdctx, &block.statusCode, sizeof(block.statusCode)) != 1) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Unable to update verifier\n");
		goto out;
	}

	if (EVP_VerifyFinal(mdctx, block.signatureValue, be32toh(block.signatureValueLen), pubkey) < 1) {
		unsigned long err;
		message_entsrc(ent_src,LOG_DAEMON| LOG_ERR, "Unable to validate signature on message\n");
		while( (err = ERR_get_error()) != 0 ) {
			ERR_error_string(err, errbuf);
			puts (errbuf);
		}

		goto out;
	}

	ret = 0;
	EVP_MD_CTX_destroy(mdctx);
out:
	return ret;

}

static size_t copy_nist_certificate(char *ptr, size_t size, size_t nemb, void *userdata)
{
        activeCert = strdup(ptr);

        if (cert) {
                X509_free(cert);
                cert = NULL;
        }
        bfp = BIO_new_mem_buf(activeCert, -1);
        cert = PEM_read_bio_X509(bfp, NULL, NULL,  NULL);
        pubkey = X509_get_pubkey(cert); 
        BIO_free(bfp);
        bfp = NULL;
        return size * nemb;
}

static void update_active_cert() {
        CURL *curl;
        CURLcode res;
        char *certurl;
        size_t urlsize = strlen(NIST_CERT_BASE_URL) + be32toh(block.certificateIdStringLen) + 1;

        free(activeCert);
        activeCert = NULL;
                
        curl = curl_easy_init();
        if (!curl)
                return;

        certurl = alloca(urlsize);
        if (!certurl)
                return;
        strcpy(certurl, NIST_CERT_BASE_URL);
        certurl = strcat(certurl, block.certificateIdString);
        curl_easy_setopt(curl, CURLOPT_URL, certurl);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, copy_nist_certificate);

        res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed in cert update: %s\n", 
			curl_easy_strerror(res));
	}
        curl_easy_cleanup(curl);
        return;
}

static int get_nist_record(struct rng *ent_src)
{
	CURL *curl;
	CURLcode res;
	int rc = 1;

	curl = curl_easy_init();

	if (!curl)
		goto out;

	curl_easy_setopt(curl, CURLOPT_URL, NIST_RECORD_URL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, parse_nist_json_block);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, ent_src);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", 
			curl_easy_strerror(res));
		goto out;
	}

	curl_easy_cleanup(curl);

        lastpulse = block.pulseIndex;

        if (!activeCertId || memcmp(activeCertId, block.certificateId, be32toh(block.certificateIdLen))) {
                free(activeCertId);
                activeCertId = strndup(block.certificateId, be32toh(block.certificateIdLen));
                update_active_cert();
        }

	if (validate_nist_block(ent_src)) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_ERR, "Received block failed validation\n");
		goto out;
	}

        
	rc = 0;

out:
	return rc;
	
}

/*
 * Confirm DARN capabilities for drng entropy source
 */
int init_nist_entropy_source(struct rng *ent_src)
{
	int rc;
	memset(&block, 0, sizeof (struct nist_data_block));

	rc = refill_rand(ent_src);
	if (!rc) {
		message_entsrc(ent_src,LOG_DAEMON|LOG_WARNING, "WARNING: NIST Randomness beacon "
						"is sent in clear text over the internet.  "
						"Do not use this source in any entropy pool "
						"which generates cryptographic objects!\n");
	}

	return rc;
}
