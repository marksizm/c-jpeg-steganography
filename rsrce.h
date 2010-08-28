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

#ifndef RSRCE_H
#define RSRCE_H
#include <stdio.h>
/**
 * This module provides a random source, based on /dev/urandom
 * UNIX standart generator.
 */
#define RANDOM_SOURCE "/dev/urandom"
struct rsrce {
	FILE * r;
	unsigned char buf;/* one-byte buffer */
	char next_bit; /* next unused random bit in buffer, bit = 8 -> we need to take a new byte */
};

/**
 * Constructor
 * @return 0 if OK, other if impossible to acquire radnom file
 * (no need to free not created object)
 */
char rsrce_init(struct rsrce * self);

/**
 * Destructor
 */
void rsrce_free(struct rsrce * self);

/**
 * Yields a random bit : 0 or 1
 * @return random 0,1 or -1 if getting data from random source fails
 */
char rsrce_produce(struct rsrce * self);




#endif
