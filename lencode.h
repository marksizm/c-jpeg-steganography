/**	
 * Copyright 2011 Ivan Zelinskiy
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

#ifndef LENCODE_H
#define LENCODE_H
#include <stdint.h>
#include <stdlib.h>
/**
 * The module provides functions to read variable-length size records.
 * Such a record is a sequence of bytes: zero or more bytes with upper
 * bit set 0 and last byte with this bit set to 1.
 *
 * Such a record denotes an unsigned integer. Seven significant bits,
 * starting from lower, of each byte sequentally correspond to the big
 * integer bits, starting from the lower bit.
 *
 * E.g. 3 byte record:
 *
 *            byte 0           byte 1            byte 2
 *        lsb               lsb               lsb
 *        1 1 1 1 1 1 1 0   1 1 1 1 1 1 1 0   1 1 1 1 1 1 1 1
 *                      ^                 ^                 ^
 *            control : |-----------------|-----------------|
 *        ^ ^ ^ ^ ^ ^ ^     ^ ^ ^ ^ ^ ^ ^     ^ ^ ^ ^ ^ ^ ^
 *        | | | | | | |     | | | | | | |     | | | | | | |
 *        |-|-|-|-|-|-|-----|-|-|-|-|-|-|-----|-|-|-|-|-|-| : 21 bit integer
 *        Big int lsb                           Big int msb
 *
 *  And the number is 2^21 - 1 = 2097151.
 *
 */

/**
 * Looks for code in `buf` - `bufsize` bytes long buffer.
 * @param buf - buffer to search code in
 * @param bufsize - buffer size
 * @param num - place to put answer to, set @ return = 0
 * @param record length - variable to report detected record length to,
 * in bytes, set @ return = 1,0
 * @return 	0 - code detected, result put into `num`
 * 			1 - code detected, result too big
 * 			2 - code wrong
 */
char lencode_yield(const unsigned char * buf, size_t bufsize,
		size_t * num, size_t * record_length);


/**
 * Encodes given number into a sequence of bytes.
 * @param num - number to encode
 * @param buf - place to put answer to, no more than lencode_estimate()
 * bytes will be produced.
 * @return number of bytes produced
 */
unsigned int lencode_produce(size_t num, unsigned char * buf);

/**
 * Estimates maximal number of bytes, lencode_produce can occupy
 * @return number of bytes to allocate output buffer of such size for
 * outputting code to.
 */
unsigned int lencode_estimate();
#endif
