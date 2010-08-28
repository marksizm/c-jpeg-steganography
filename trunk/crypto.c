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
	fprintf(stderr, "FIXME! change cipher batch in crypto.c\n");
	long cipher_batch =  16*CIPHER_BLOCK_SIZE; /* 131072 */
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
