/*
 * ossl_helpers.c -- Helper wrappers around openssl functions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ossl_helpers.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

struct ossl_aes_ctx
{
	EVP_CIPHER_CTX *c;
	const unsigned char *key;
	const unsigned char *iv;
};

void ossl_aes_random_key(unsigned char *key, const unsigned char *pepper)
{
	static unsigned char default_key[AES_BLOCK] = {
		0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
		0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0
	}; /* AES data reduction key */
	volatile unsigned char stack_junk[AES_BLOCK];
	int fd, i;

	/* Try getting some randomness from the kernel */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		int r __attribute__((unused));
		r = read(fd, key, AES_BLOCK);
		close(fd);
	}

	/* Mix in our default key */
	for (i = 0; i < AES_BLOCK; i++)
		key[i] ^= default_key[i];

	/* Mix in stack junk */
	for (i = 0; i < AES_BLOCK; i++)
		key[i] ^= stack_junk[i];

	/* Spice it up if we can */
	for (i = 0; i < AES_BLOCK && pepper; i++)
		key[i] ^= pepper[i];
}


struct ossl_aes_ctx *ossl_aes_init(const unsigned char *key,
				   const unsigned char *iv)
{
	struct ossl_aes_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;
	
	ctx->c = EVP_CIPHER_CTX_new();
	if (!ctx->c) {
		free(ctx);
		return NULL;
	}
	ctx->key = key;
	ctx->iv = iv;
	return ctx;
}

void ossl_aes_exit(struct ossl_aes_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->c);
	free(ctx);
}

int ossl_aes_encrypt(struct ossl_aes_ctx *ctx,
		     unsigned char *plaintext, int plaintext_len,
		     unsigned char *ciphertext)
{
        int len, ciphertext_len;

 	if(1 != EVP_EncryptInit_ex(ctx->c, EVP_aes_128_cbc(), NULL, ctx->key, ctx->iv))
		return 0;

	/*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx->c, ciphertext, &len, plaintext, plaintext_len))
                return 0;

        ciphertext_len = len;

        /*
        * Finalise the encryption. Further ciphertext bytes may be written at
        * this stage.
        */
        if(1 != EVP_EncryptFinal_ex(ctx->c, ciphertext + len, &len))
                return 0;
        ciphertext_len += len;

	return ciphertext_len;
}

