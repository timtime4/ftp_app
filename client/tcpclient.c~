// Mitch Patin (mpatin)
// Tim Pusateri (tpusater)
// Jon Richelsen (jrichels)
// CSE30264
// Programming Assignment 3: TCP
// TCP Client
// Due 2015-10-15

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "tcp_shared.h" // utility functions

int DEBUG = 0; // flag for whether to print debug statements
#define FILE_PCKT_LEN 512

int connect_to_server( const char * server_hostname, const char * port_str );
void print_usage( ); // print correct command usage (arguments, etc.)

int main( int argc, char * argv[] )
{
    // variables and data structures
    const char * server_hostname; // (from command line)
    const char * port_str; // (from command line)
    const char * filename; // (from command line)
    unsigned long int filename_len; // length of filename string
    int socket_fd; // socket for communicating with server
    long int file_len; // length of file sent by server
    unsigned char MD5_hash_server[16]; // array (NOT STRING) holding hex values for MD5 hash from server
    unsigned char * file_buf = NULL;
    unsigned char * MD5_hash_client[16]; // POINTER to array (NOT STRING) holding hex values for MD5 hash from client (self)
    FILE * file = NULL;
    struct timeval time_start;
    struct timeval time_end;
    struct timeval time_elapsed;

    // get information from command line
    analyze_argc(argc, 4, &print_usage);
    server_hostname = argv[1];
    debugprintf("server hostnamename argument: %s", server_hostname);
    port_str = argv[2];
    debugprintf("port argument: %s", port_str);
    filename = argv[3];
    debugprintf("filename argument: %s", filename);
    filename_len = strlen(filename);
    debugprintf("filename length: %hu", filename_len);

    // capture start time
    if (gettimeofday(&time_start, NULL) == -1) {
        perror("error getting start time");
        exit(EXIT_FAILURE);
    }
    debugprintf("start time recorded");

    // connect to server
    socket_fd = connect_to_server(server_hostname, port_str);
    if (socket_fd == -1) {
        fprintf(stderr, "failed to connect to server, exiting now\n");
        exit(EXIT_FAILURE);
    }

    // send filename length to server
    uint32_t filename_len_net = htonl(filename_len);
    send_bytes(socket_fd, &filename_len_net, sizeof(filename_len_net), "filename length");
    debugprintf("filename length sent to server: %d", filename_len);

    // send filename to server TODO: FIX LATER
    ssize_t bytes_sent_filename = send(socket_fd, filename, (filename_len + sizeof(char)), 0);
    if (bytes_sent_filename == -1) {
        perror("error sending filename to server");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    if (bytes_sent_filename != (filename_len + sizeof(char))) {
        fprintf(stderr, "error sending filename to server:\n");
        fprintf(stderr, "    incorrect number of bytes sent, expecting %zu, sent %zd\n", (filename_len + sizeof(char)), bytes_sent_filename);
        fprintf(stderr, "    exiting now\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    debugprintf("filename sent to server: %s", filename);

    // receive file length from server
    long int file_len_net;
    recv_bytes(socket_fd, &file_len_net, sizeof(file_len_net), "file length");
    file_len = file_len_net;
    debugprintf("file length received from server: %ld", file_len);

    // quit if file does not exist on server
    if (file_len == -1) {
        fprintf(stderr, "File does not exists\n");
        close(socket_fd);
        exit(EXIT_SUCCESS);
    }

    // receive MD5 hash from server
    recv_bytes(socket_fd, MD5_hash_server, 16, "MD5 hash");
    debugprintf("MD5 hash received from server");

    // prepare to receive file byte array (packet by packet) from server
    file_buf = (unsigned char *)malloc(file_len * sizeof(unsigned char));
    int i_full_pckt;
    int n_full_pckts = file_len / FILE_PCKT_LEN;
    size_t last_pckt_len = file_len % FILE_PCKT_LEN;
    debugprintf("expecting %d full packets from server (%zu bytes)", n_full_pckts, FILE_PCKT_LEN);
    if (last_pckt_len != 0) {
        debugprintf("last packet will be %zu bytes", last_pckt_len);
    } else {
        debugprintf("no last packet will be received");
    }

    // recieve full packets from server
    for (i_full_pckt = 0; i_full_pckt < n_full_pckts; i_full_pckt++) {
        recv_bytes(socket_fd, &file_buf[i_full_pckt * FILE_PCKT_LEN], FILE_PCKT_LEN, "file packet");
        debugprintf("full packet %d of %d received from server", (i_full_pckt + 1), n_full_pckts);
    }

    // receive last packet from server (if necessary)
    if (last_pckt_len != 0) {
        recv_bytes(socket_fd, &file_buf[n_full_pckts * FILE_PCKT_LEN], last_pckt_len, "last file packet");
        debugprintf("last packet received from server");
    }
    debugprintf("file received from server");

    // create MD5 hash of file
    MD5_hash_of_byte_array(file_buf, file_len, MD5_hash_client);
    debugprintf("MD5 hash created");

    // compare MD5 hashes
    if (cmp_MD5_hash(*MD5_hash_client, MD5_hash_server) != 0) {
        fprintf(stderr, "File hashes do not match – bad transfer\n");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    debugprintf("MD5 hashes match"); //TODO: MAKE FAIL!

    // write byte array to file
    file = fopen(filename, "wb");
    fwrite(file_buf, 1, file_len, file); //return value!
    debugprintf("file created, DONE");

    // capture end time
    if (gettimeofday(&time_end, NULL) == -1) {
        perror("error getting end time");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }
    debugprintf("end time recorded");

    // calculate and print time difference and throughput
    timersub(&time_end, &time_start, &time_elapsed);
    double seconds_elapsed = time_elapsed.tv_sec + (time_elapsed.tv_usec / 1000000.0);
    double throughput = ((double)file_len / 1048576) / seconds_elapsed;
    printf("%ld bytes transferred in %f sec. Throughput: %f Megabytes/sec. File MD5sum: ", file_len, seconds_elapsed, throughput);
    print_MD5_hash(MD5_hash_client);
    printf("\n");
    close(socket_fd);
    exit(EXIT_SUCCESS);
}

int connect_to_server( const char * server_hostname, const char * port_str )
{
    struct addrinfo hints; // hints for getaddrinfo()
    struct addrinfo * server_info_ll = NULL; // linked list returned by getaddrinfo()
    struct addrinfo * this_addr_ptr = NULL; // pointer to current item on server_info_ll linked list
    int socket_fd;

    // set hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // return both IPv4 and IPv6 addresses
    hints.ai_socktype = SOCK_STREAM; // specify TCP

    // get address info of server
    int gai_rv;
    if ((gai_rv = getaddrinfo(server_hostname, port_str, &hints, &server_info_ll)) != 0) {
        fprintf(stderr, "error getting address information for server: %s\n", gai_strerror(gai_rv));
        fprintf(stderr, "quitting now\n");
        freeaddrinfo(server_info_ll);
        exit(EXIT_FAILURE);
    }

    // connect to first server address possible
    for (this_addr_ptr = server_info_ll; this_addr_ptr != NULL; this_addr_ptr = this_addr_ptr->ai_next) {
        // create server socket
        socket_fd = socket(this_addr_ptr->ai_family, this_addr_ptr->ai_socktype, this_addr_ptr->ai_protocol);
        if (socket_fd == -1) {
            debugprintf("could not create server socket: %s", strerror(errno));
            continue;
        } else {
            debugprintf("server socket created");
        }

        // connect server socket to server
        if (connect(socket_fd, this_addr_ptr->ai_addr, this_addr_ptr->ai_addrlen) == -1) {
            debugprintf("could not connect server socket to server: %s", strerror(errno));
            continue;
        } else {
            debugprintf("server socket connected");
        }

        freeaddrinfo(server_info_ll);
        return socket_fd;
    }

    freeaddrinfo(server_info_ll);
    return -1;
}

void print_usage( )
{
    printf("tcpclient is to be used in the following manner: \"tcpclient <HOSTNAME OR IP ADDRESS> <PORT> <FILENAME>\"\n");
}
