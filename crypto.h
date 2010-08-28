#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/blowfish.h>
#include <string.h>

/**
 * This module provides an interface to OpenSSL library.
 *
 * We are going to use Blowfish cipher.
 */

#define CIPHER_BLOCK_SIZE BF_BLOCK /*That's the size of block in bytes, our cipher uses*/

#define ENCRYPT 2
#define DECRYPT 4



/**
 * Interface to openssl cipher.
 * @param data - data to operate at, answer is pushed back to buffer
 * @param len - data length: N*CIPHER_BLOCK_SIZE, if len is not a
 * multiple of CIPHER_BLOCK_SIZE, the bytes, that don't fit, are left
 * unchanged
 * @param password - secret string
 * @param direction - ENCRYPT or DECRYPT
 */
void cipher(unsigned char * data, size_t len, const char * password, int direction);

#endif
