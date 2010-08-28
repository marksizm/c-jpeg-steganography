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
