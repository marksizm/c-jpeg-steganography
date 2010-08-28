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

#include "lencode.h"


unsigned int lencode_estimate(){
	unsigned int b = sizeof(size_t);
	unsigned int bits_max = b*8;
	unsigned int bytes = bits_max / 7;
	if ( bits_max % 7 ){
		bytes += 1;
	}
	return bytes;
}

unsigned int lencode_produce(size_t num, unsigned char * buf){
	int ksi;
	for(ksi=0;;ksi+=1){
		buf[ksi] = (num >> (ksi * 7)) & 0b01111111;
		if(
			(num >> (ksi * 7)) & (~(size_t)0b01111111)
		){
			/* OMG still bits above this pack! */
		}else{
			/* No more bytes will be needed!
			 * setting stop */
			buf[ksi] |=  0b10000000;
			return ksi + 1;
		}
	}
}

/**
 * Finds the upper non-zero bit except the last (N 8) and returns it's id.
 * Bytes are numbered starting from 1.
 * 0 at return means that all data bits (NN 1 - 7) are equal to zero.
 * @param byte - byte to study
 * @return 	1 - 7 - number of most significant non-zero data bit,
 *  		0 - all data bits are zero.
 */
static unsigned char bit_detect(unsigned char byte){
	unsigned char bit;
	for(bit = 7; bit > 0; bit -= 1){
		if ( byte & ( 1 << (bit-1) ) ){
			break;
		}
	}
	return bit;
}



char lencode_yield(const unsigned char * buf, size_t bufsize,
		size_t * num, size_t * record_length){
	size_t stop, ksi;
	char stop_found = 0;
	for(ksi = 0; ksi < bufsize; ksi+=1){
		if ( buf[ksi] & 0b10000000 ){
			stop = ksi;
			stop_found = 1;
			break;
		}
	}
	if ( ! stop_found ){
		return 2;
	}
	* record_length = stop + 1;/* Pushing detected record length */
	/* Let's find how many bits with significant data we have */
	size_t lbyte; /* Byte, carrying last significant bit */
	unsigned char lbit; /* this bit offset, over this bit all are zero */
	char empty; /* set to true if there are no active bits at all */
	{
		size_t mu = stop + 1;
		unsigned char bit, found = 0;
		do{
			mu -= 1;
			bit = bit_detect(buf[mu]);
			if( bit ) {
				found = 1;
				break;
			}
		}while(mu != 0);
		/* output */
		if(found){
			lbyte = mu;
			lbit = bit - 1;
			empty = 0;
		}else{
			empty = 1;
		}
	}
	/* So we know the bits configuration */
	if(empty){
		* num = 0;
		return 0; /* OK */
	}
	/* We have (lbyte + 1)*7 - (6 - lbit) bits of big integer.
	 * After simplifying: lbyte*7 + 1 + lbit.
	 * Do we have space in size_t for that? */
	unsigned int wehavebits = sizeof(size_t)*8;
	if ( lbyte > wehavebits ){
		/* Than lbyte * 7 + 1 + lbit will be even more, we don't have place for that */
		return 1;
	}
	/* but wehavebits is very small, many times smaller (log2) than max size_t:
	 * now we calculate the expression without a fear of overflow */
	size_t weneedbits = lbyte * 7 + 1 + lbit;
	if (weneedbits > wehavebits){
		/* fail, number too big :) */
		return 1;
	}
	/* Copying what we have, we have enough space to do that */
	* num = 0;
	size_t copybyte;
	for ( copybyte = 0; copybyte < lbyte; copybyte += 1 ){
		* num |= (size_t)(buf[copybyte] & 0b01111111) << 7*copybyte;
	}
	/* Now, the last byte */
	* num |= (size_t)(buf[lbyte] & ( 0b11111111 >> (7-lbit) )) << 7*lbyte;
	/* num ready! */
	return 0;
}
