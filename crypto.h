/**	
 * Copyright 2010 Ivan Zelinskiy
 * 
 * This file is part of C-jpeg-steganography.
 *
 * C-jpeg-steganography is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * C-jpeg-steganography is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with C-jpeg-steganography.  If not, see <http://www.gnu.org/licenses/>.
 */

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
