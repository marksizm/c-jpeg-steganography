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


