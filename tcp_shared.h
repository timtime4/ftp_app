// Mitch Patin (mpatin)
// Tim Pusateri (tpusater)
// Jon Richelsen (jrichels)
// CSE30264
// Programming Assignment 3: TCP
// Shared Functions
// Due 2015-10-15

#ifndef TCP_SHARED_H
#define TCP_SHARED_H

#include <inttypes.h>

extern int DEBUG; // flag for whether to print debug statements

void analyze_argc( int argc, int argc_expected, void (* print_usage_ptr)() );
int cmp_MD5_hash( unsigned char MD5_hash1[16], unsigned char MD5_hash2[16] );
void debugprintf( const char * const format, ... );
void MD5_hash_of_byte_array( unsigned char * byteArray, size_t len, unsigned char * MD5_hash[16] );
long int open_filename_to_byte_array( char * filename, unsigned char * * byteArray );
void print_MD5_hash( unsigned char * MD5_hash[16] );
void recv_bytes( int socket_fd, void * buf, size_t len, const char * const desc );
void send_bytes( int socket_fd, void * buf, size_t len, const char * const desc );

#endif //TCP_SHARED_H
