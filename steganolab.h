/**	
 * Copyright 2012 Ivan Zelinskiy
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

#ifndef STEGANOLAB_H
#define STEGANOLAB_H
#include <stddef.h>/* for size_t */
#include <stdio.h>
#include <stdint.h>
/**
 * This module contains end-user steganographic functions
 */
/* JPEG library is designed so that it's possible to redefine stdio 
 * functions. Steganolab functions pass stream objects directly to 
 * the underlying calls. If you hack jpeg library to use your custom 
 * IO objects, define SLFILE type accordingly. */
typedef FILE SLFILE;

/**
 * This structure describes properties of jpeg color channel.
 * It is used to report channels info in the folowing structure.
 */
struct color_channel_info {
	uint8_t afraid;					/* bit 0 - afraid of width, bit 1 - afraid of height */
									/* Afraid mean skip one DCT block next to border */
	unsigned int usable_DCT_blocks;	/* Number of DCT blocks, the color channel offers */
	int h_samp_factor;
	int v_samp_factor;				/* Both copied from jpeg_component_info, sampling factors */
	int w,h;						/* Width and height after sampling */
	unsigned int Wbl, Hbl;			/* Available blocks after taking afraids in consideration */
};

/**
 * This structure is used to report processing information to library
 * user. A pointer to this structure may be passed to library decoder/
 * encoder to retrieve the information.
 *
 * The structure with data in may hold not-NULL pointers to malloced
 * memory patches. Because of that, library user must call
 * steganolab_statistics_free before forgetting about the structure.
 */
struct steganolab_statistics {
	unsigned int bits_available;		/* Overall bits, image the image offers for store */
	uint8_t color_channels;				/* Color channels in image */
	struct color_channel_info * info;	/* Array with info about every channel */
	uint8_t bits_in_block;				/* Quite static, function of DCT_radius */
	const char * colorspace;			/* Colorspace string (not for free-ing)*/
	unsigned int bits_used;				/* Bits, used by the message */
};


/**
 * By given jpeg file writes another, that contains the hidden message.
 * @param infile - input stream
 * @param outfile - output stream
 * @param data - message to embed
 * @param len - message length
 * @param password - key string to cipher data and set up PRNG
 * @param DCT_radius - which DCT coefficients shall be used to carry
 * 	information, i^2+j^2 <= R^2
 * @param stats - pointer to structure to put statistics to. The caller
 * must take care about freeing the structure properly. NULL pass
 * disables statistics output.  The object doesn't need to be freed if the
 * function fails, and it contains no message.
 * @return 0: All OK
 * not 0: Failed
 **/
int steganolab_encode(SLFILE * infile, SLFILE * outfile, 
	const char * data, unsigned int len, const char * password,
	uint8_t DCT_radius, struct steganolab_statistics * stats);

/**
 * Reads steganographic message from stream
 * @param file - jpeg stream
 * @param data - pointer to pointer to buffer to put data to, needs to be free-d
 * @param len - pointer to push obtained buffer length to
 * @param password - secred string for cipher and PRNG
 * @param DCT_radius - which DCT coefficients shall be used to carry
 * 	information, i^2+j^2 <= R^2
 * @param stats - statistics object. Free is up to the caller.
 * NULL disables the feature.  The object don't need to be freed if the
 * function fails, and it contains no message.
 * @return 0: All OK
 * not 0: fail (no resources need to be freed in this case)
 */
int steganolab_decode(SLFILE * file, char ** data,
	unsigned int * len, const char * password, uint8_t DCT_radius,
	struct steganolab_statistics * stats);



/**
 * Outputs jpeg file statistics.
 * @param file - jpeg file stream to study
 * @param DCT_radius - DCT coefficient limitation
 * @param stats - statistics object to populate with data. NULL passed
 * to this parameter makes the whole function quite useless.
 * @return 0 : OK
 * not 0 : an error occured, statistics object don't need to be
 * freed.
 */
int steganolab_estimate(SLFILE * file, uint8_t DCT_radius, struct
	steganolab_statistics * stats);



/**
 * Describes meaning of steganolab functions return value
 * @param code - return code
 * @return pointer to description string (static, no need to free)
 */
const char * steganolab_describe(int code);



/**
 * Describes statistics by printing it to specified destination
 * with the help of fprintf(dest, ...)
 * @param stats - statistics object
 * @param dest - stdio descriptor
 */
void steganolab_print_statistics(struct steganolab_statistics * stats, FILE * dest);


/**
 * Frees statistics object internal resources
 * @param stats - statistics object to free
 */
void steganolab_free_statistics(struct steganolab_statistics * stats);

#endif
