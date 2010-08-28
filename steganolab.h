#ifndef STEGANOLAB_H
#define STEGANOLAB_H
#include <malloc.h>/* for size_t */
#include <stdio.h>
#include <stdint.h>
/**
 * This module contains end-user steganographic functions
 */

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
 * Modifies specified jpeg file so that it contains given message.
 * @param file - jpeg file name
 * @param data - message to embed
 * @param len - message length
 * @param password - key string to cipher data and set up PRNG
 * @param DCT_radius - which DCT coefficients shall be used to carry
 * 	information, i^2+j^2 <= R^2
 * @param stats - pointer to structure to put statistics to. The caller
 * must take care about freeing the structure properly. NULL pass
 * disables statistics output.  The object don't need to be freed if the
 * function fails, and it contains no message.
 * @return		0: All OK
 * 				not 0: Failed
 **/
int steganolab_encode(const char * file, const char * data,
	unsigned int len, const char * password, uint8_t DCT_radius,
	struct steganolab_statistics * stats);

/**
 * Reads steganographic message from specified file
 * @param file - jpeg file name
 * @param data - pointer to pointer to string to put data to
 * @param len - pointer to push obtained buffer length to
 * @param password - secred string for cipher and PRNG
 * @param DCT_radius - which DCT coefficients shall be used to carry
 * 	information, i^2+j^2 <= R^2
 * @param stats - statistics object. Free is up to the caller.
 * NULL disables the feature.  The object don't need to be freed if the
 * function fails, and it contains no message.
 * @return	0: All OK
 * 			not 0: fail (no buffers need freeing in this case)
 */
int steganolab_decode(const char * file, char ** data,
	unsigned int * len, const char * password, uint8_t DCT_radius,
	struct steganolab_statistics * stats);



/**
 * Outputs jpeg file statistics.
 * @param file - jpeg file to study
 * @param DCT_radius - DCT coefficient limitation
 * @param stats - statistics object to populate with data. NULL passed
 * to this parameter makes the whole function quite useless.
 * @return	0		: OK
 * 			not 0	: an error occured, statistics object don't need to be
 * 			freed.
 */
int steganolab_estimate(const char * file, uint8_t DCT_radius, struct
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
