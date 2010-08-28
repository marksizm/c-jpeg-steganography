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

#include <stdio.h>
#include <sys/types.h>
#include "steganolab.h"
#include <limits.h>
#include <string.h>
#include <malloc.h>

/**
 * This is the main c file of steganolab project. It compiles to a
 * utility program for embeding and decrypting messages to/from jpeg
 * files.
 */



/**
 * Reads from stdin until there is no more data.
 * Pushes back a pointer to malloced patch of memory with length of
 * useful data in the buffer. The buffer dealocation is up to the user.
 *
 * On errors return NULL, nothing needs to be freed.
 *
 * @param buf pointer to set pointing to data
 * @param len - resulting buffer length
 * @param fd - file descriptor to read from
 */
static void read_from_fd(char ** buf_out, size_t * buflen_out, int fd){
	char * buf=malloc(100);
	size_t len=100;/* malloced patch size */
	size_t used=0;/* bytes used for data */
	if( NULL == buf ){
		*buf_out = NULL;
		*buflen_out = 0;
		return;
	}
	/* At every step we have values set properly and some free space in buffer */
	char smth_went_wrong=0;
	for(;;){
		ssize_t nread = read(fd, buf+used, len-used);
		if(-1 == nread){
			/*IO ERROR*/
			smth_went_wrong = 1;
			break;
		}
		if(0 == nread){
			break; /* OK, EOF */
		}
		/* have some data */
		used += nread;
		/* Enlarging if necessary */
		if(used == len){
			size_t newlen=len*3/2;
			char * newbuf = realloc(buf, newlen);
			if(newbuf == NULL){ /* Out of memory */
				smth_went_wrong = 1;
				break;
			}
			buf=newbuf;
			len=newlen;
		}
	}

	if(smth_went_wrong){
		/* Clean-up, suitable for both cases */
		free(buf);
		 * buf_out = NULL;
		 * buflen_out = 0;
	}else{
		/* OK */
		* buf_out = buf;
		* buflen_out = used;
	}
}

/**
 * Scans buffer, cutting out zero bytes
 * @param data - buffer to remove zeros from
 * @param len - buffer length
 * @return squeesed buffer length
 */
static size_t eat_zeros(char * data, size_t len){
	size_t copied, place_to_put_copy_to = 0;
	/*@ each iteration: copied - byte studied, place... - next free place */
	/* Initially they are equal, no need to copy. After that, if we find zero,
	 * we will copy back */
	for(copied = 0; copied < len; copied += 1){
		if ( data[copied] ){
			/* We need to copy this */
			if( copied != place_to_put_copy_to ){
				data[place_to_put_copy_to] = data[copied];
			}else{
				/* They don't differ, no need to copy */
			}
			place_to_put_copy_to += 1;
		}else{
			/* We shall skip this */
			/* place... lags one more byte */
		}
	}
	return place_to_put_copy_to;
}

/**
 * Reads password as C string from specified FD
 * @param fd - file descriptor to read password from
 * @param password - pointer to pointer to take password from
 * @return 0 if OK, not 0 if error, nothing need to be freed in case of
 * an error
 */
int read_password_from_fd(int fd, char ** password){
	size_t len;
	read_from_fd(password, & len, fd);
	if ( len == 0 ){
		return 1;
	}
	size_t new_len = eat_zeros( *password, len );
	char * newp = realloc( *password, new_len + 1 );
	if (newp == NULL){
		free(*password);
		fprintf(stderr, "Can't beleive it! Can't add 1 byte by realloc :D\n");
		return 2;
	}
	* password = newp;
	(* password)[new_len] = 0; /* Setting C stop */

	/* Let's search for trailing \n, \t, ' ' and remove it */
	size_t o = new_len + 1;
	do{
		o -= 1;
		char c = (* password)[o];
		if ( c == ' ' || c == '\n' || c == '\t' || c == 0){
			(* password)[o] = 0;
		}else{
			break;
		}
	}while ( o );

	return 0;
}


#define DCT_RADIUS	2
#define SECRET_FD	4

int main(int argc, char ** argv){
	if ( !(argc == 3 || argc == 4) ){
		fprintf(stderr, "Usage:\t... [--write,--read] filename [secret]\n");
		fprintf(stderr, "\t... --estimate filename\n");
		fprintf(stderr, "Where: secret - key string\n");
		fprintf(stderr, "       filename - name of jpeg file\n");
		fprintf(stderr, "If secret is undefined, secret string is read from file descriptor %i\n", SECRET_FD);
		fprintf(stderr, "Any 0 bytes in secret string are skipped for correct C string representation.\n");
		fprintf(stderr, "Also, trailing newline, tab and space symbols are removed.\n");
		return 1;
	}

	int toreturn = 0;

	const char * cmd = argv[1];

	if( ! strcmp(cmd, "--write") ){
		/*############################################################*/
		if(! (argc == 4 || argc == 3) ){
			return 100;
		}
		const char * filename = argv[2];
		char * password;
		char need_free_password;
		if (argc == 4){
			password = argv[3];
			need_free_password = 0;
		}else{/* We need to read password from FD */
			int rv = read_password_from_fd(SECRET_FD, &password);
			if(rv){
				fprintf(stderr, "Failed to read password from FD %i\n", SECRET_FD);
				return 101;
			}
			need_free_password = 1;
		}
		/* Reading data from stdin */
		char * buf;
		size_t len;
		struct steganolab_statistics stats;

		read_from_fd(&buf, &len, 0);
		if(buf == NULL||len > UINT_MAX){
			fprintf(stderr, "Can't read data from stdin\n");
			if(need_free_password) free(password);
			return 3;
		}

		int rv = steganolab_encode(filename, buf, (unsigned int)len, password, DCT_RADIUS, & stats);
		free(buf);

		if(rv){
			fprintf(stderr, "Emeder failed with message: %s\n", steganolab_describe(rv));
			toreturn = 10;
		}else{
			fprintf(stderr, "Embeding OK\n");
			steganolab_print_statistics( & stats, stderr );
			steganolab_free_statistics( & stats );
		}
		if(need_free_password) free(password);
	}else if( ! strcmp(cmd, "--read")){
		/*############################################################*/
		if( !(argc == 4||argc == 3) ){
			return 200;
		}
		const char * filename = argv[2];
		char * password;
		char need_free_password;
		if (argc == 4){
			password = argv[3];
			need_free_password = 0;
		}else{/* We need to read password from FD */
			int rv = read_password_from_fd(SECRET_FD, &password);
			if(rv){
				fprintf(stderr, "Failed to read password from FD %i\n", SECRET_FD);
				return 201;
			}
			need_free_password = 1;
		}
		char * buf;
		unsigned int len;
		struct steganolab_statistics stats;

		int rv = steganolab_decode(filename, &buf, &len, password, DCT_RADIUS, & stats);
		if(rv){
			fprintf(stderr, "Decoder failed with message: %s\n", steganolab_describe(rv));
			toreturn = 20;
		}else{
			size_t id;
			for( id = 0; id < len; id+=1 ){
				fputc(buf[id], stdout);
			}
			steganolab_print_statistics( & stats, stderr );
			steganolab_free_statistics( & stats );
			fprintf(stderr, "Decoding OK, your message on stdout\n");
			free(buf);
		}
		if(need_free_password) free(password);
	}else if (! strcmp(cmd, "--estimate")){
		if(argc != 3){
			return 302;
		}
		const char * file = argv[2];
		struct steganolab_statistics stats;
		int rv = steganolab_estimate(file, DCT_RADIUS, & stats);
		if(rv){
			fprintf(stderr, "Estimator failed with message: %s\n", steganolab_describe(rv));
			toreturn = 30;
		}else{
			fprintf(stderr, "Estimating OK\n");
			steganolab_print_statistics( & stats, stderr );
			steganolab_free_statistics( & stats );
		}
	}else{
		/*############################################################*/
		fprintf(stderr, "Wrong arguments\n");
		return 2;
	}
	return toreturn;
}

