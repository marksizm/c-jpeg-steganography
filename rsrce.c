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

#include <assert.h>
#include "rsrce.h"

char rsrce_init(struct rsrce * self){
	self -> r = fopen(RANDOM_SOURCE, "r");
	if(NULL == self -> r){
		return 1;
	}
	self -> next_bit = 8; /* buffer dirty, needs genning a new random byte */
	return 0;
}


void rsrce_free(struct rsrce * self){
	fclose(self -> r);
}

char rsrce_produce(struct rsrce * self){
	if(self -> next_bit == 8){/* We assume to have 8 bits in byte */
		int R = fgetc(self -> r);
		if (R == EOF){
			return -1;
		}
		self -> buf = (unsigned char)R;
		self -> next_bit = 0;
	}
	/*So we have some fresh radnom bits*/
	char out = self -> buf & ( 1 << self -> next_bit );
	self -> next_bit += 1;/* moving up */
	if(out){
		return 1;
	}else{
		return 0;
	}
}


