/*
 * ossl_helpers.h -- Helper wrappers around openssl functions
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

#ifndef OSSL_HELPERS__H
#define OSSL_HELPERS__H

#define AES_BLOCK		16

struct ossl_aes_ctx;

extern int ossl_aes_encrypt(struct ossl_aes_ctx *ctx,
			    unsigned char *plaintext, int plaintext_len,
			    unsigned char *ciphertext);

extern struct ossl_aes_ctx *ossl_aes_init(const unsigned char *key,
					  const unsigned char *iv);
extern void ossl_aes_exit(struct ossl_aes_ctx *ctx);
extern void ossl_aes_random_key(unsigned char *key, const unsigned char *pepper);

static inline int ossl_aes_mangle(struct ossl_aes_ctx *ctx, unsigned char *data,
				  size_t size)
{
        int ciphertext_len;

        /*
        * Buffer for ciphertext. Ensure the buffer is long enough for the
        * ciphertext which may be longer than the plaintext, depending on the
        * algorithm and mode.
	*
	* For AES, one extra AES block should be sufficient.
        */
        unsigned char ciphertext[size + AES_BLOCK];

        /* Encrypt the plaintext */
	ciphertext_len = ossl_aes_encrypt(ctx, data, size, ciphertext);
        if (!ciphertext_len)
                return -1;

        memcpy(data, ciphertext, size);
        return ciphertext_len;
}

#endif /* OSSL_HELPERS__H */
