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

#include "steganolab.h"
#include <stdio.h>
#include <malloc.h>
#include <stdint.h>
#include <limits.h>
#include <setjmp.h>
#include <assert.h>
#include <jpeglib.h>
#include <openssl/sha.h>

#include "lencode.h" /* length mark generator and reader */
#include "rsrce.h" /* /dev/urandom as source of random bits */
#include "rgen.h" /* PRNG based on BLOWFISH */
#include "crypto.h" /* Interface to OpenSSL Blowfish cipher */

#include <string.h> /* debug */

/**
 * Number of usable DCT coefficients
 * @param R - radius, i^2+j^2 <= R^2
 * @return number of coefficients, satisfying the spicified condition
 */
static uint8_t usable_DCT(uint8_t R){
	uint8_t i,j,N = 0;
	for( i = 0; i < DCTSIZE; i += 1 ){
		for( j = 0; j < DCTSIZE; j += 1 ){
			if (i*i + j*j <= R*R){
				N += 1;
			}
		}
	}
	return N;
}

/**
 * Gets i and j by given index and limiting radius, thus enumerating
 * elements of dct block.
 * @param id - element id
 * @param DCT_radius - limiting radius
 * @return 0 if element found, 1 not
 * */
static char getij(uint8_t id, uint8_t DCT_radius, uint8_t * I, uint8_t * J){
	uint8_t i,j;
	uint8_t curid = 0, found = 0;
	for(i=0; i<DCTSIZE; i+=1){
		for(j=0; j<DCTSIZE; j+=1){
			if (i*i + j*j <= (DCT_radius * DCT_radius)){
				if( id == curid ){
					found = 1;
					break;
				}
				curid += 1;
			}else{
				break;
			}
		}
		if(found) break;
	}

	if(found){
		*I = i;
		*J = j;
		return 0;
	}else{
		return 1;
	}
}



struct enumerator_card {
	unsigned int width;
	unsigned int height;/* both in DCT blocks */
	unsigned int Nblocks;
};
/**
 * The object is a mean of giving unique numbers to all available
 * DCT coefficients in an abstract way.
 */
struct enumerator {
		uint8_t cards_in;
		uint8_t places_reserved;
		struct enumerator_card * cards;
		uint8_t DCT_radius; /* Only use coefficients that have i^2 + j ^ 2 <= R^2 */
};

/**
 * Constructor
 * @param DCT_radius - DCT coefficient usage limit: i^2 + j^2 <= R^2, i,j start from zero.
 */
static void enumerator_init(struct enumerator * self, int8_t DCT_radius) {
	self -> cards_in = 0;
	self -> places_reserved = 0;
	self -> cards = NULL;
	self -> DCT_radius = DCT_radius;
}

/**
 * Appends DCT array of given size to enumerator collection.
 * Arrays with zero dimensions are OK, despite empty
 * @param width, heigth - new array dimensions in DCT blocks
 * @return	0: OK
 * 			1: full
 * 			2: dimensions too big (so that w*h overflows it's type)
 */
static char enumerator_add(struct enumerator * self, unsigned int width,
		unsigned int height){
	if (self -> places_reserved == self -> cards_in ){
		if ( self -> places_reserved == 0xff ){
			return 1;/* Full! */
		}
		uint16_t newnum = (uint16_t)self -> places_reserved*2 + 3;
		if(newnum > 0xff){
			newnum = 0xff;
		}
		self -> cards = realloc( self -> cards, sizeof(struct enumerator_card) * newnum );
		assert(self -> cards != NULL);
		self -> places_reserved = (uint8_t)newnum;
	}
	/* Now we have at least one free position */
	/* Adding a card */
	struct enumerator_card * newcard = self -> cards + self -> cards_in;

	newcard -> width = width;
	newcard -> height = height;
	newcard -> Nblocks = width * height;
	if (  newcard -> Nblocks / width != height ){
		/* overflow */
		return 2;
	}
	self -> cards_in += 1;
	return 0;
}

static void enumerator_free(struct enumerator * obj){
	free(obj -> cards);
}

struct position {
	uint8_t array_id;
	unsigned int m,n; /* DCT block position */
	uint8_t i,j; /* Coefficient position inside DCT block */
};

/**
 * By given element ID retrieves data to locate in in arrays
 * @param idx - element index
 * @param pos - answer structure to fill
 * @return	0: OK
 * 			1: Element not found
 */
static char enumerator_get_position_by_index(struct enumerator * self,
		unsigned int idx, struct position * pos){
	uint8_t inblock = usable_DCT( self -> DCT_radius );
	unsigned long long lastarr=0; /* Summ of DCT @ previous arrays */
	char found = 0;
	uint8_t ksi;
	for ( ksi = 0; ksi < self -> cards_in; ksi += 1 ){
		unsigned int nb = self -> cards[ksi] . Nblocks;
		unsigned long long nk = nb * inblock;
		if ( lastarr + nk > idx ) {
			/* The index is here */
			found = 1;
			break;
		}else{
			lastarr += nk;
		}
	}
	if ( ! found ){
		return 1;
	}
	/* So we know that the element is in array ksi */
	uint8_t array_id = ksi;
	pos -> array_id = array_id;
	unsigned int array_offset = idx - lastarr;/* index relative to array of DCT blocks */
	/* For a single array all is of fixed size */
	unsigned int block_id = array_offset / inblock;
	unsigned int block_offset = array_offset % inblock;
	/* block position ? */
	pos -> m = block_id / self -> cards[array_id] . width;
	pos -> n = block_id % self -> cards[array_id] . width;
	/* DCT coefficient address in block */
	uint8_t i,j;
	getij(block_offset, self -> DCT_radius, &i, &j);
	pos -> i = i;
	pos -> j = j;
	return 0;
}


/**
 * Calculates how many usable DCT coefficients enumerator knows about
 *
 * @param N - number of available DCT coefficients
 * @return 0 if OK, 1 if data type is not enough to represent the number
 */
static char enumerator_get_number_of_positions(struct enumerator * self,
		unsigned int * N){
	uint8_t card;
	uint8_t perblock = usable_DCT(self -> DCT_radius);
	unsigned int all = 0;
	for(card = 0; card < self -> cards_in; card += 1){
		struct enumerator_card * c = &self -> cards[card];
		unsigned int nblocks = c->Nblocks;
		unsigned int nelements = nblocks * perblock;
		if(nelements / perblock != nblocks){
			return 1;/* Too big! */
		}
		unsigned int newall = all + nelements;
		if(newall < all){
			return 1;
		}
		all = newall;
	}
	* N = all;
	return 0;
}

/**
 * Alters DCT coefficient so that it holds requested bit.
 * This is a modified LSB, plain LSB is not secure.
 *
 * The algorythm is:
 * If LSB is OK -> Do nothing
 * 			 NOT OK -> get random bit and either
 * 				shift up ( +1 ), or down ( -1 ).
 * As a result, steganographic shift and initial DCT value become
 * statistically independant values (here I don't prove it, it's evident).
 *
 * This is not so for simple LSB coding: a value with LSB = 1 will never shift up,
 * a value with LSB = 0 will never shift down, this can be used for steganodetection.
 *
 * This method has many other vulnerabilities, of couse. One idea is
 * that it's addition modifies natural noisy distribution of DCT coefficients,
 * that can be detected.
 * @param dctc - DCT coefficient to alter
 * @param bit - data bit to embed (0 means zero bit, any other means one bit)
 * @param random_source - object to take random data from, if needed
 */
static void embed_bit ( JCOEF * dctc, unsigned char bit, struct rsrce * random_source ){
	/* According to jmorecfg, dctc holds 16 bit signed integer.
	 * By altering the coefficient we shall not overflow the value accidentally. */
	JCOEF lsb = * dctc & 1;
	if( bit && lsb || ! bit && ! lsb ){
		/* OK */
		return;
	}
	/* Need to change */
	char rbit = rsrce_produce(random_source);
	assert(rbit != -1);/* OS radnom source fail */
	char direction = rbit;/* C false - down, C true - up */
	/* Ensuring that won't overflow we */
	if( direction && * dctc == 32767 || ! direction && ! (* dctc == -32768) ){
		direction = ! direction; /* dont'go there, go in the opposite direction * */
	}

	/* Applying shift */
	if( direction ){
		* dctc += 1;
	}else{
		* dctc -= 1;
	}
}


/**
 * Reads LSB from specified integer
 * @param dctc - integer to read bit from
 * @return 0 for 'zero' bit, 1 for 'one' bit
 */
static unsigned char read_bit ( const JCOEF * dctc ){
	return (unsigned char)( * dctc & 1 );
}


/**
 * Here are many pieces of copypaste, that came from jpeglib62 example
 */
struct my_error_mgr {
	struct jpeg_error_mgr pub;
	jmp_buf setjmp_buffer;
};

typedef struct my_error_mgr * my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */
static void
my_error_exit (j_common_ptr cinfo){
	/* cinfo->err really points to a my_error_mgr struct, so coerce pointer */
	my_error_ptr myerr = (my_error_ptr) cinfo->err;

   (*cinfo->err->output_message) (cinfo);

	/* Return control to the setjmp point */
	longjmp(myerr->setjmp_buffer, 1);
}


/**
 * This structure holds pointers to objects, that need freeing.
 * There is a function that cals the needed freers, called
 * encode_cleanup_func, that calls proper functions.
 */
struct cleanup {
	/* These must be set to real objects before freeing */
	struct jpeg_decompress_struct * cinfo;
	FILE * infile;
	struct enumerator * enu;
	struct rgen * rge;
	/* These may be set to NULL before setting pointing to real objects */
	struct rsrce * rsrc;
	unsigned char * message;
	unsigned int * shuffle;
	struct color_channel_info * cci;
};

static void cleanup_func(struct cleanup * o){
	jpeg_destroy_decompress(o -> cinfo);
	fclose(o -> infile);
	enumerator_free(o -> enu);
	/* Objects that can be NULL */
	if ( o -> rge != NULL ){
		rgen_free(o -> rge);
	}
	if( NULL != o -> rsrc ){
		rsrce_free(o -> rsrc);
	}
	free(o -> message);
	free(o -> shuffle);
	free(o -> cci);
}






/**
 * Writes a jpeg from specified context of other jpeg as it appears when
 * obtaining DCT coefficients and modifying them.
 * @param filename - to write new jpeg to
 * @param cinfo_in - decompression context pointer
 * @param bvarr - DCT data array to write
 * @return 0 if OK, other values for errors
 */
static int write_jpeg_by_other(const char * filename, j_decompress_ptr cinfo_in, jvirt_barray_ptr * bvarr){
	struct jpeg_compress_struct cinfo;/*compressor states*/
	struct my_error_mgr jerr; /*error-handling structure*/
	FILE *outfile;

	outfile=fopen(filename, "w");
	if(NULL==outfile){
		return 2;/*Can't open file for writing*/
	}

	cinfo.err = jpeg_std_error(&jerr.pub);/*initialising default error handler
											at jerr.pub*/
	jerr.pub.error_exit = my_error_exit;/*Changing error action to defined here*/


	/* Longjump section. If an error occurs, all functional stack above here is forgotten,
	 * and function continues execution from here with non-zero return code from setjmp
	 */
	if (setjmp(jerr.setjmp_buffer)) {
		/* If we get here, the JPEG code has signaled an error.
		 * We need to clean up the JPEG object, close the input file, and return.
		 */
		jpeg_destroy_compress(&cinfo);
		fclose(outfile);
		return 10;
	}

	/*Initialising compression structure (cinfo.err given above)*/
	jpeg_create_compress(&cinfo);
	jpeg_stdio_dest(&cinfo, outfile);/*telling, where to put jpeg data*/

	/* Applying parameters from source jpeg */
	jpeg_copy_critical_parameters(cinfo_in, &cinfo);

	/* copying DCT */
	jpeg_write_coefficients(&cinfo, bvarr);

	/*clean-up*/
	jpeg_finish_compress(&cinfo);
	fclose(outfile);
	jpeg_destroy_compress(&cinfo);
	/*Done!*/
	return 0;
}



/**
 * Reads message of specified length from DCT array.
 * The routine is a programming convinience, with it there is just less
 * code to write.
 * @param msg - buffer to put message to. Must have space to put n
 * cipher blocks.
 * @param n - message length to read in CIPHER_BLOCK_SIZE
 * Checks agains reading more bits than enumeratro can offer, are included.
 * @param color_component_block_arrays - pointer to place, from where
 * jpeglib DCT coefficients can be extracted
 * @param cinfo - jpeg decompress info object
 * @param password - secret to decrypt message
 * @param enu - enumerator object with all data loaded in
 * @param bits_in_enu - positions, available in enumerator: we can
 * retrieve this number of bits from the image
 * @param shuffle - shuffle table to link between bit id's and
 * enumerator id's: shuffle(bitid) = enumid
 * @return	0: OK
 * 			1: Requested message too big
 */
static int read_steganographic_message_from_DCT_buffer(unsigned char * msg,
		unsigned int n, jvirt_barray_ptr * color_component_block_arrays,
		struct jpeg_decompress_struct * cinfo,
		const char * password, struct enumerator * enu,
		unsigned int bits_in_enu,
		const unsigned int * shuffle){
	unsigned int need_bits = n * CIPHER_BLOCK_SIZE * 8;
	if ( need_bits / (CIPHER_BLOCK_SIZE * 8) != n ){
		/* Overflow */
		return 1;
	}
	if ( bits_in_enu < need_bits ){
		/* Can't get so much */
		return 1;
	}
	unsigned int need_bytes = need_bits / 8;
	/* Cleaning the buffer */
	memset( msg, 0, need_bytes );
	/* copying raw data */
	unsigned int bit;
	for(bit = 0; bit < need_bits; bit += 1){
		struct position pos;
		char fail = enumerator_get_position_by_index(enu, shuffle[bit]-1, &pos);
		assert(!fail);
		JBLOCKARRAY B = (cinfo -> mem -> access_virt_barray)((j_common_ptr) cinfo,
						color_component_block_arrays[pos.array_id],
						pos.m, 1/*1 row, not more */, FALSE /* We are NOT writing to the buffer */);
		JCOEFPTR dctblck = B[0][pos.n];

		unsigned char bitval = read_bit( & dctblck[pos.i * DCTSIZE + pos.j] ); /* 0 or 1 */
		if(bitval){
			msg [bit / 8] |= 1 << bit % 8;
		}else{
			/* Zero allready there */
		}
	}
	/* unciphering message */
	cipher(msg, need_bytes, password, DECRYPT);
	/* ready! */
	return 0;
}




#define DECODE		0
#define ENCODE		1
#define ESTIMATE	2
/**
 * Worker function, that does embeding and reading upon request.
 * This function is convinient, because writer and reader share much of
 * similar code.
 * @param file - file name to work with
 * @param data_in - message to embed if encoder
 * @param len_in - message length if encoder
 * @param data_out - pointer to pointer to push malloced buffer with
 *  message to if decoder (to be freed by caller)
 * @param len_out - message length if decoder
 * @param action - what to do, DECODE|ENCODE|ESTIMATE.
 * @param password - secret key
 * @param DCT_radius - Constant, limiting DCT block coefficients
 *  use: i^2 + j^2 <= R^2
 * @param stats - statistics object to fill with data if not NULL
 * The object don't need to be freed if the function fails.
 * @return 0 if OK, various error statuses on error, the statuses can be
 * decoded to human-readable from with the function providden
 */
static int steganolab_worker(const char * file, const char * data_in,
		unsigned int len_in, char ** data_out, unsigned int * len_out,
		uint8_t action, const char * password, uint8_t DCT_radius,
		struct steganolab_statistics * stats){
	struct jpeg_decompress_struct cinfo;
	struct my_error_mgr jerr;

	FILE * infile;

	if ((infile = fopen(file, "r")) == NULL) {
		return 1;
	}

	struct enumerator enu;/* Thing, able to explain where DCT coefficient is by it's id */
	enumerator_init(&enu, DCT_radius);

	/* We set up the normal JPEG error routines, then override error_exit. */
	cinfo.err = jpeg_std_error(&jerr.pub);
	jerr.pub.error_exit = my_error_exit;

	struct cleanup clu;
	clu . cinfo = & cinfo;
	clu . infile = infile;
	clu . enu = & enu;
	clu . rge = NULL;
	clu . message = NULL;/* This will be set after, until this free(NULL) would work OK */
	clu . shuffle = NULL;
	clu . rsrc = NULL;
	clu . cci = NULL;

	/* Establish the setjmp return context for my_error_exit to use. */
	if (setjmp(jerr.setjmp_buffer)) {
		/* If we get here, the JPEG code has signaled an error.
		* We need to clean up the JPEG object, close the input file, and return.
		*/
		cleanup_func(& clu);
		return 2;
	}
	jpeg_create_decompress(&cinfo);
	jpeg_stdio_src(&cinfo, infile);
	(void) jpeg_read_header(&cinfo, TRUE);
	/* We can ignore the return value from jpeg_read_header since
	*   (a) suspension is not possible with the stdio data source, and
	*   (b) we passed TRUE to reject a tables-only JPEG file as an error.
	* See libjpeg.doc for more info.
	*/
	/* Studying image */
	int color_channels = cinfo.num_components;
	/* How many blocks will we have? */
	/* Looking at component properties */
	struct color_channel_info * cci = malloc(sizeof(struct color_channel_info) * color_channels);
	if(NULL == cci){
		cleanup_func(& clu);
		return 20;/* Out of memory */
	}
	{/* Studying image */
		int ksi;
		for(ksi=0; ksi<color_channels; ksi+=1){
			assert(cinfo.comp_info[ksi].DCT_scaled_size == DCTSIZE);/* We didn't requsted it to be different, so it mustn't be different */
			int w = cinfo.comp_info[ksi].downsampled_width;
			int h = cinfo.comp_info[ksi].downsampled_height;
			char afraid_of_w = 0, afraid_of_h = 0;
			/* Don't use blocks next to border picture don't fit in blocks precisely */
			if ( w % DCTSIZE ){
				afraid_of_w = 1;
			}
			if ( h % DCTSIZE ){
				afraid_of_h = 1;
			}
			unsigned int Wbl,Hbl;
			Wbl = (unsigned int)cinfo.comp_info[ksi].width_in_blocks;/* It's safe because jpeg images can only be 64kx64k (see jmorecfg of jpeglib62)*/
			Hbl = (unsigned int)cinfo.comp_info[ksi].height_in_blocks;
			if(afraid_of_w){
				assert(Wbl);
				Wbl -= 1;
			}
			if(afraid_of_h){
				assert(Hbl);
				Hbl -= 1;
			}/* Exclude border blocks */
			char fail_adding_block_record_to_enumerator = enumerator_add(&enu, Wbl, Hbl);
			assert(!fail_adding_block_record_to_enumerator);

			/* Saving array for statistics */
			cci [ksi] . afraid = (afraid_of_w) | (afraid_of_h << 1);
			cci [ksi] . usable_DCT_blocks = Wbl * Hbl; /* If this overflows, we would fail in enumerator_add */
			cci [ksi] . h_samp_factor = cinfo.comp_info[ksi].h_samp_factor;
			cci [ksi] . v_samp_factor = cinfo.comp_info[ksi].v_samp_factor;
			cci [ksi] . Wbl = Wbl;
			cci [ksi] . Hbl = Hbl;
			cci [ksi] . h = h;
			cci [ksi] . w = w;
		}
	}/* studying image */
	unsigned int all_available;
	{
		char fail = enumerator_get_number_of_positions(&enu, &all_available);
		assert(!fail);
	}

	/* Now the shuffle is a map from data bit id to enumerator id,
	 * it's very random and seeded by the password */

	unsigned int bits_used = 0;/* For statistics, this is set to number
	of bits, used for steganography, in both decoder and encoder */
	/* Requesting to read DCT coefficients and return an array of DCT
	 * block 2D arrays.
	 */
	jvirt_barray_ptr * color_component_block_arrays = jpeg_read_coefficients( &cinfo );
	if( DECODE == action || ENCODE == action ){
		/* Things, needed by encoder/decoder, but not needed for estimation
		set here */

		struct rgen rge;
		rgen_init(& rge, password);/* Pseurandom generator, based on BLOWFISH,
		is created in this line and seeded by password */
		clu . rge = & rge;/* Setting for clean-up */

		/* generating a random shuffle to know which bit is in which position */
		unsigned int shuffle_length = all_available;
		unsigned int * shuffle = rgen_shuffle(&rge, shuffle_length);
		if( NULL == shuffle ){
			cleanup_func(& clu);
			return 20;/* Out of memory */
		}
		clu . shuffle = shuffle; /* Setting for clean-up */

		if ( DECODE == action ){
			unsigned int max_len_rec = lencode_estimate();
			/* Reading max_len_rec bytes from file */
			/* How many cipher blocks will we need to get the length record? */
			unsigned int len_rec_blocks = max_len_rec / CIPHER_BLOCK_SIZE;
			if(max_len_rec % CIPHER_BLOCK_SIZE){
				len_rec_blocks += 1;
			}
			unsigned char msg[len_rec_blocks*CIPHER_BLOCK_SIZE];
			int readstate = read_steganographic_message_from_DCT_buffer(msg,
				len_rec_blocks,color_component_block_arrays, &cinfo, password,
				&enu, all_available, shuffle);

			if(readstate){
				cleanup_func( &clu );
				return 40;
			}

			size_t data_length_big = 0, record_length_big = 0; /* message + SHA1 */

			char data_length_decoding_result = lencode_yield (msg, max_len_rec,
				&data_length_big, &record_length_big);

			if(data_length_decoding_result ||
				data_length_big + record_length_big > UINT_MAX
				/* At least on x86_64 that seriously makes sence */){
				/* Failed to read length code */
				cleanup_func( &clu );
				return 40; /* Garbage */
			}

			/* This is a length of message together with length record in
			 * the beginning */
			unsigned int full_message_length = data_length_big + record_length_big;
			unsigned int full_message_blocks = full_message_length / CIPHER_BLOCK_SIZE;
			if( full_message_length % CIPHER_BLOCK_SIZE ){
				full_message_blocks += 1;
			}
			unsigned int full_message_length_after_fitting_to_blocks = full_message_blocks * CIPHER_BLOCK_SIZE;
			if(full_message_length_after_fitting_to_blocks / CIPHER_BLOCK_SIZE != full_message_blocks ){
				cleanup_func( & clu );
				return 40;/* garbage */
			}
			/* Do we have so much bits in image ?*/
			unsigned int full_message_bits_after_fitting_to_blocks =
				full_message_length_after_fitting_to_blocks * 8;
			if(full_message_bits_after_fitting_to_blocks / 8 != full_message_length_after_fitting_to_blocks){
				cleanup_func( & clu );
				return 40; /* garbage */
			}
			/* For statistics */
			bits_used = full_message_bits_after_fitting_to_blocks;
			/* Generally speaking, the following check is done in read_steganographic_message_from_DCT_buffer */
			/* However, let's do it before allocating possibly tons of memory in case of garbage input */
			if ( full_message_bits_after_fitting_to_blocks > all_available ){
				cleanup_func( & clu );
				return 40;
			}
			/* So we have needed number of bits in image */
			/* How will parts of data be located ? */
			unsigned int data_offset = record_length_big;
			unsigned int sha1_offset = full_message_length - SHA_DIGEST_LENGTH;
			if(sha1_offset <= data_offset ){
				/* No data can fit here! :P */
				cleanup_func( & clu );
				return 40;
			}
			/* Allocating space for message */
			unsigned char * message = malloc(full_message_length_after_fitting_to_blocks);
			if(NULL == message){
				cleanup_func( & clu );
				return 20;/* out of memory */
			}
			clu . message = message;/* Remembering for clean-up */

			readstate = read_steganographic_message_from_DCT_buffer(message,
				full_message_blocks, color_component_block_arrays, &cinfo,
				password, &enu, all_available, shuffle);
			if(readstate){
				cleanup_func( & clu );
				return 40;
			}
			/* We have decrypted message! Does the SHA1 checksum match? */
			unsigned char sha1[SHA_DIGEST_LENGTH];
			SHA1(message + data_offset, sha1_offset - data_offset, sha1);/* We have the whole in memory, so it's easy to calculate sha1 */
			/* Comparing sha1 sums by byte */
			uint8_t shabyte, differ = 0;
			for(shabyte = 0; shabyte < SHA_DIGEST_LENGTH; shabyte += 1){
				if( message[sha1_offset + shabyte] != sha1[shabyte] ){
					differ = 1;
					break;
				}
			}
			if (differ){
				cleanup_func( & clu );
				return 40;/* Garbage! */
			}
			/* Woops! A real message. */
			* len_out = sha1_offset - data_offset;
			*data_out = malloc( * len_out );
			if( *data_out == NULL ){
				/* How sad, we were close to reporting the message */
				cleanup_func( & clu );
				return 20;/* Out of memory */
			}
			/* memory allocated ! */
			memcpy( * data_out, message + data_offset, * len_out );
			/* Now the malloced patch is under responsibility of the caller, we don't care about it */
			/* Done decoding! */
		}else{/* :: ENCODE This is encoder !*/
			/* We need rsrce to take random data from OS */
			struct rsrce rsrc;
			if(rsrce_init(& rsrc )){
				cleanup_func(& clu);
				return 3; /* error opening random source */
			}
			clu . rsrc = & rsrc;/* Remembering for clean-up */

			/* preparing length record */
			if(len_in + SHA_DIGEST_LENGTH < len_in ){
				cleanup_func(& clu);
				return 10;
			}
			unsigned int data_and_sha1_length = len_in + SHA_DIGEST_LENGTH;

			unsigned char len_rec[lencode_estimate()];
			unsigned int len_rec_len = lencode_produce(data_and_sha1_length, len_rec);
			/* calculating message digest */
			unsigned char sha1[SHA_DIGEST_LENGTH];
			SHA1(data_in,len_in,sha1);/* We have the whole in memory, so it's easy to calculate sha1 */
			/* packing the whole message in buffer for ciphering */
			unsigned int message_len = data_and_sha1_length + len_rec_len;
			if ( message_len < data_and_sha1_length ){
				/* overflow */
				cleanup_func(& clu);
				return 10;
			}
			unsigned int message_len_in_blocks = message_len / CIPHER_BLOCK_SIZE;
			if(message_len % CIPHER_BLOCK_SIZE) message_len_in_blocks += 1;
			if ( message_len_in_blocks * CIPHER_BLOCK_SIZE / CIPHER_BLOCK_SIZE != message_len_in_blocks){
				/* overflow */
				cleanup_func(& clu);
				return 10;
			}
			unsigned char * message = malloc(message_len_in_blocks * CIPHER_BLOCK_SIZE);
			if( NULL == message ){
				cleanup_func(& clu);
				return 20;/* Out of memory */
			}
			clu . message = message;/* remembering for clean-up */
			if (message_len % CIPHER_BLOCK_SIZE )memset(message +
				message_len_in_blocks * CIPHER_BLOCK_SIZE - CIPHER_BLOCK_SIZE,
				0, CIPHER_BLOCK_SIZE);/* memsetting the last block so that some
				data don't escape from us in case trere is padding */

			size_t mpos = 0; /* To hold next free byte in message */
			memcpy(message + mpos, len_rec, len_rec_len);
			mpos += len_rec_len;
			memcpy(message + mpos, data_in, len_in);
			mpos += len_in;
			memcpy(message + mpos, sha1, SHA_DIGEST_LENGTH);/* OK copying */
			/* ciphering the message */
			cipher(message, message_len_in_blocks*CIPHER_BLOCK_SIZE, password, ENCRYPT);
			/* embeding the message according to shuffle table */

			/* Now we can check if we have enough space */
			if ( message_len_in_blocks * CIPHER_BLOCK_SIZE * 8 / 8 != message_len_in_blocks * CIPHER_BLOCK_SIZE ){
				/* overflow */
				cleanup_func(& clu);
				return 10;
			}

			if(all_available < message_len_in_blocks * CIPHER_BLOCK_SIZE * 8){
				cleanup_func( & clu );
				return 10;
			}
			unsigned int bits_out = message_len_in_blocks * CIPHER_BLOCK_SIZE * 8; /* Due to previous check, here we'll not get an owerflow */

			/* For statistics */
			bits_used = bits_out;

			/* we have enough space, because there is a check above */
			unsigned int bit_idx;
			for ( bit_idx = 0; bit_idx < bits_out; bit_idx += 1 ){
				struct position p;
				char get_pos_fail = enumerator_get_position_by_index(& enu, shuffle[bit_idx] - 1, & p);
				assert(!get_pos_fail);

				JBLOCKARRAY B = (cinfo.mem -> access_virt_barray)((j_common_ptr) &cinfo,
							color_component_block_arrays[p.array_id],
							p.m, 1/*1 row, not more */, TRUE /* We are writing to the buffer */);
				JCOEFPTR dctblck = B[0][p.n];
				embed_bit( & dctblck[p.i * DCTSIZE + p.j],
					message[bit_idx/8] & 1 << bit_idx % 8,
					&rsrc );
			}/* Done embeding */
			int write_status = write_jpeg_by_other("out.jpeg", &cinfo, color_component_block_arrays);
			if(write_status){
				cleanup_func( & clu );
				return 30;
			}
			/* OK! */
		}
	}else{/* This must be estimator: ESTIMATE */
		bits_used = 0;/* We didn't use any bytes while estimating, did we? :) */
	}

	/* It's time to report statistics */
	if(NULL != stats){
		/* Outputting statistics */
		stats -> bits_available = all_available;
		stats -> color_channels = color_channels;
		stats -> bits_in_block = usable_DCT(DCT_radius);
		const char * cs;
		const char * undef = "Unknown colorspace";
		switch(cinfo.jpeg_color_space){
			case JCS_RGB:
				cs = "RGB";
			break;
			case JCS_GRAYSCALE:
				cs = "Grayscale";
			break;
			case JCS_YCbCr:
				cs = "YCbCr";
			break;
			case JCS_UNKNOWN:
				cs = undef;
			break;
			default:
				cs = undef;
		}
		stats -> colorspace = cs;
		stats -> bits_used = bits_used;
		/* Now component info: we have cci array allready allocated and filled
		 * with proper data. This array is, however, remembered in clu
		 * structure: it's going to be freed. Let's take it out of there
		 * and give to caller */
		clu . cci = NULL;/* Disabling free */
		stats -> info = cci;/* Giving link to caller */
	}

	cleanup_func( & clu ); /* Overall clean-up */
	return 0;
}


const char * steganolab_describe(int code){
	switch(code){
		case 0:
			return "OK";
		case 1:
			return "Failed to open file";
		case 2:
			return "Jpeglib fail";
		case 3:
			return "Can't read data from RANDOM_SOURCE";
		case 10:
			return "Data too long";
		case 20:
			return "Out of memory";
		case 30:
			return "Error writing file copy";
		case 40:
			return "Only garbage found";
	}
	return "Unknown error";
}



int steganolab_encode(const char * file, const char * data,
		unsigned int len, const char * password, uint8_t DCT_radius,
		struct steganolab_statistics * stats){
	return steganolab_worker(file, data, (unsigned int)len, NULL, NULL, ENCODE, password, DCT_radius, stats);
}

int steganolab_decode(const char * file, char ** data,
		unsigned int * len, const char * password, uint8_t DCT_radius,
		struct steganolab_statistics * stats){
	return steganolab_worker(file, NULL, 0, data, len, DECODE, password, DCT_radius, stats);
}

int steganolab_estimate(const char * file, uint8_t DCT_radius, struct
		steganolab_statistics * stats){
	return steganolab_worker(file, NULL, 0, NULL, NULL, ESTIMATE, NULL, DCT_radius, stats);
}

/**
 * Return yes or no string depending on C boolean value of input
 * parameter.
 * @param b - boolean value to trabslate
 * @return yes or no strings depending on input value
 */
static const char * yesno(int b){
	if(b){
		return "yes";
	}else{
		return "no";
	}
}


void steganolab_print_statistics(struct steganolab_statistics * stats, FILE * dest){
	fprintf(dest, "Statistics:\n");
	unsigned int bits = stats -> bits_available;
	fprintf(dest, "\tAll bits available: %u\n", bits);
	fprintf(dest, "\tBytes available: ");
	{/* Printing human-readable storage size */
		unsigned int bytes = bits / 8;
		if(bytes < 1024 * 2){
			fprintf(dest, "%u B", bytes);
		}else{
			float kbytes = bytes / 1024.0;
			if( kbytes < 1024.0 * 2 ){
				fprintf(dest, "%.1f Kib", kbytes);
			}else{
				float mbytes = kbytes / 1024.0;
				fprintf(dest, "%.1f Mib", mbytes);
			}
		}
	}
	fprintf(dest, "\n");
	fprintf(dest, "\tBits in DCT block: %i\n", stats -> bits_in_block);
	fprintf(dest, "\tColorspace: %s, %i channels\n", stats -> colorspace, stats -> color_channels);
	fprintf(dest, "Color components:\n");
	uint8_t o;
	for(o = 0; o < stats -> color_channels; o += 1){
		fprintf(dest, "Component %i:\n", o);
		struct color_channel_info * cci = stats -> info + o;
		fprintf(dest, "\tSampling (width x height): %i x %i\n", cci -> h_samp_factor, cci -> v_samp_factor);
		fprintf(dest, "\tWidth and height in pixels after sampling: %i, %i\n", cci -> w, cci -> h);
		fprintf(dest, "\tSkip border blocks (width, height): %s, %s\n", yesno(cci -> afraid & 1), yesno(cci -> afraid & 2));
		fprintf(dest, "\tUsable DCT blocks: %i\n", cci -> usable_DCT_blocks);
		fprintf(dest, "\tWidth and height in blocks after skipping border blocks: %u, %u\n", cci -> Wbl, cci -> Hbl);
	}
	if ( stats -> bits_used ){ /* There can't be 0, because there is at
		least SHA1 sum. If we see 0, there has been an estimation run */
		fprintf(dest, "Used %u of %u available bits, usage: ", stats -> bits_used, stats -> bits_available);
		float usage = stats -> bits_used / (float) stats -> bits_available * 100.0;
		if(usage > 0.005){
			fprintf(dest, "%.2f%%\n", usage);
		}else{
			fprintf(dest, "%e%%\n", usage);
		}
	}else{
		fprintf(dest, "Statistics produced by estimation\n");
	}
	fprintf(dest, "End of statistics.\n");
}



void steganolab_free_statistics(struct steganolab_statistics * stats){
	free(stats -> info);
}
