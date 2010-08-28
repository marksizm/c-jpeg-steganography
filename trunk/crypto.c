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

 * You should have received a copy of the GNU General Public License
 * along with C-jpeg-steganography.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

void cipher(unsigned char * data, size_t len, const char * password, int direction){
	int enc;
	assert(direction == ENCRYPT || direction == DECRYPT);
	if (direction == ENCRYPT){
		enc = BF_ENCRYPT;
	}else{
		enc = BF_DECRYPT;
	}
	unsigned char ivec[8];
	ivec[0] = 0xe7;
	ivec[1] = 0xd9;
	ivec[2] = 0x5c;
	ivec[3] = 0x3a;
	ivec[4] = 0x52;
	ivec[5] = 0x2b;
	ivec[6] = 0x8a;
	ivec[7] = 0x63;/* taken by fair use of /dev/random */
	BF_KEY key;
	BF_set_key(&key, strlen(password), password);
	size_t nblocks = len / CIPHER_BLOCK_SIZE;	
	long cipher_batch =  16*1024*CIPHER_BLOCK_SIZE; /* 128 Kb of data to cipher at one time */
	unsigned char buf[cipher_batch];
	size_t unciphered, last_pack;
	for( unciphered = 0; unciphered < nblocks * CIPHER_BLOCK_SIZE; unciphered += last_pack ){
		size_t left_to_cipher = nblocks * CIPHER_BLOCK_SIZE - unciphered;
		size_t tocipher;
		if(left_to_cipher / cipher_batch){
			tocipher = cipher_batch;
		}else{
			tocipher = left_to_cipher;
		}
		BF_cbc_encrypt(data + unciphered, buf, tocipher, & key, ivec, enc);
		last_pack = tocipher;
		/*copying*/
		memcpy(data + unciphered, buf, tocipher);
	}
	/* Clean-up */
	memset(ivec, 0, BF_BLOCK);
	memset(&key, 0, sizeof(BF_KEY));
}
