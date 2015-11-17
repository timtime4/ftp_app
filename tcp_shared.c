// Mitch Patin (mpatin)
// Tim Pusateri (tpusater)
// Jon Richelsen (jrichels)
// CSE30264
// Programming Assignment 3: TCP
// Shared Functions
// Due 2015-10-15

#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <mhash.h>
#include <inttypes.h>
#include <errno.h>

#include "tcp_shared.h"

void analyze_argc( int argc, int argc_expected, void (* print_usage_ptr)() )
{
    if (argc == 1) {
        fprintf(stderr, "no command line arguments specified, exiting now.\n");
        print_usage_ptr();
        exit(EXIT_FAILURE);
    } else if (argc != argc_expected) {
        fprintf(stderr, "incorrect number of command line arguments, exiting now.\n");
        print_usage_ptr();
        exit(EXIT_FAILURE);
    }
}

int cmp_MD5_hash( unsigned char MD5_hash1[16], unsigned char MD5_hash2[16] )
{
    return memcmp(MD5_hash1, MD5_hash2, 16);
}

void debugprintf( const char * const format, ... )
{
    if (!DEBUG) {
        return;
    }

    va_list args;
    va_start(args, format);
    printf("DEBUG: ");
    vprintf (format, args);
    printf("\n");
}

void MD5_hash_of_byte_array( unsigned char * byteArray, size_t len, unsigned char * MD5_hash[16] )
{
    MHASH MD5_hash_context = mhash_init(MHASH_MD5);
    mhash(MD5_hash_context, byteArray, len);
    *MD5_hash = mhash_end(MD5_hash_context);
}

long int open_filename_to_byte_array( char * filename, unsigned char * * byteArray )
{
    FILE * file = fopen(filename, "rb");
    if (file == NULL) {
        return -1;
    }
    fseek(file, 0, SEEK_END);
    size_t len = ftell(file);
    fseek(file, 0, SEEK_SET);
    *byteArray = NULL;
    *byteArray = malloc(len + 1);
    if (*byteArray == NULL) {
        fprintf(stderr, "error allocating memory for file, exiting now\n");
        exit(EXIT_FAILURE);
    }
    fread(*byteArray, len, 1, file);
    fclose(file);
    (*byteArray)[len] = 0;
    return len;
}

void print_MD5_hash( unsigned char * MD5_hash[16] )
{
    int i_MD5_hash;
    for (i_MD5_hash = 0; i_MD5_hash < 16; i_MD5_hash++) {
        printf("%.2x", (*MD5_hash)[i_MD5_hash]);
    }
}

void recv_bytes( int socket_fd, void * buf, size_t len, const char * const desc )
{
    ssize_t bytes_recvd = recv(socket_fd, buf, len, 0);
    if (bytes_recvd == -1) {
        fprintf(stderr, "error receiving %s\n", desc);
        perror("exiting now");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    if (bytes_recvd != len) {
        fprintf(stderr, "error receiving %s:\n", desc);
        fprintf(stderr, "    incorrect number of bytes received, expecting %zu, received %zd\n", len, bytes_recvd);
        fprintf(stderr, "    exiting now\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void send_bytes( int socket_fd, void * buf, size_t len, const char * const desc )
{
    ssize_t bytes_sent = send(socket_fd, buf, len, 0);
    if (bytes_sent == -1) {
    fprintf(stderr, "error sending %s\n", desc);
        perror("exiting now");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    if (bytes_sent != len) {
        fprintf(stderr, "error sending %s:\n", desc);
        fprintf(stderr, "    incorrect number of bytes sent, expecting %zu, sent %zd\n", len, bytes_sent);
        fprintf(stderr, "    exiting now\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void recv_string( int socket_fd, char * buf, size_t len, const char * const desc ) {
  ssize_t bytes_recvd = recv(socket_fd, buf, len, 0);
  if (bytes_recvd == -1) {
    fprintf(stderr, "error receiving %s\n", desc);
    perror("exiting now");
    close(socket_fd);
    exit(EXIT_FAILURE);
  }
  if (bytes_recvd == 0) {
    fprintf(stderr, "error receiving %s:\n", desc);
    fprintf(stderr, "    no bytes received\n");
    fprintf(stderr, "    exiting now\n");
    close(socket_fd);
    exit(EXIT_FAILURE);
  }
  buf[len-1] = '\0';
}

void send_string( int socket_fd, char * string, const char * const desc ) {
    ssize_t bytes_sent = send(socket_fd, string, (strlen(string) + sizeof(char)), 0);
    if (bytes_sent == -1) {
      fprintf(stderr, "error sending %s\n", desc);
      perror("exiting now");
      close(socket_fd);
      exit(EXIT_FAILURE);
    }

    if (bytes_sent != (strlen(string) + sizeof(char))) {
        fprintf(stderr, "error sending %s:\n", desc);
        fprintf(stderr, "    incorrect number of bytes sent, expecting %zu, sent %zd\n", (strlen(string) + sizeof(char)), bytes_sent);
        fprintf(stderr, "    exiting now\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
}

void receive_file_info ( int client_socket_fd, char * filename_buf){
  // receive filename length from client
  unsigned long int filename_len; // length of filename sent from client
  uint32_t filename_len_net;
  recv_bytes(client_socket_fd, &filename_len_net, sizeof(filename_len_net), "filename length");
  filename_len = ntohl(filename_len_net);
  debugprintf("filename length received from client: %lu", filename_len);

  // receive filename from client TODO: FIX LATER
  ssize_t bytes_recvd_filename = recv(client_socket_fd, filename_buf, (filename_len + sizeof(char)), 0);
  if (bytes_recvd_filename == -1) {
      perror("error receiving filename from client, exiting now");
      close(client_socket_fd);
      exit(EXIT_FAILURE);
  }
  if (bytes_recvd_filename != ((filename_len + 1) * sizeof(char))) {
      fprintf(stderr, "error receiving filename from client:\n");
      fprintf(stderr, "\tincorrect number of bytes received, expecting %zu, received %zd\n", ((filename_len + 1) * sizeof(char)), bytes_recvd_filename);
      fprintf(stderr, "\texiting now\n");
      close(client_socket_fd);
      exit(EXIT_FAILURE);
  }
  filename_buf[FILENAME_BUF_LEN] = '\0';
  debugprintf("filename received from client: %s", filename_buf);

  // ensure that filename length and length of actual filename match
  if (filename_len != strlen(filename_buf)) {
      fprintf(stderr, "filename length and filename from client do not match, exiting now\n");
      exit(EXIT_FAILURE);
  }
  debugprintf("filename length and filename match");
}

void send_file_info( int socket_fd, char * filename) {
  // send filename length to server
  unsigned long int filename_len = strlen(filename);
  uint32_t filename_len_net = htonl(filename_len);
  send_bytes(socket_fd, &filename_len_net, sizeof(filename_len_net), "filename length");
  debugprintf("filename length sent to server: %d", filename_len);

  send_string( socket_fd, filename, "filename" );
}
