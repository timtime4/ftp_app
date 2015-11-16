// Mitch Patin (mpatin)
// Tim Pusateri (tpusater)
// Jon Richelsen (jrichels)
// CSE30264
// Programming Assignment 3: TCP
// TCP Server
// Due 2015-10-15

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
// CONST POINTERS?

#include "tcp_shared.h" // utility functions

int DEBUG = 0; // flag for whether to print debug statements
#define MAX_PENDING 5
#define FILENAME_BUF_LEN 1000
#define FILE_PCKT_LEN 512

int accept_client_connection( int control_socket_fd, struct sockaddr * client_addr, socklen_t * addr_len );
int create_control_socket_and_listen( );
void print_usage( ); // print correct command usage (arguments, etc.)

int main( int argc, char * argv[] )
{
    // variables and data structures
    const char * port_str; // (from command line)
    int control_socket_fd; // socket accepting connections
    int client_socket_fd; // socket for communicating with client
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    unsigned long int filename_len; // length of filename sent from client
    char filename_buf[FILENAME_BUF_LEN];
    const size_t filename_buf_len = sizeof(filename_buf);
    unsigned char * byteArray = NULL; // byte array holding file to send to client
    long int file_len; // length of file to send to client
    unsigned char * MD5_hash[16]; // POINTER to array (NOT STRING) holding hex values for MD5 hash

    // get information from command line
    analyze_argc(argc, 2, &print_usage);
    port_str = argv[1];
    debugprintf("port argument: %s", port_str);

    // create control socket
    control_socket_fd = create_control_socket_and_listen(port_str, MAX_PENDING);
    if (control_socket_fd == -1) {
        fprintf(stderr, "failed to create control socket, exiting now\n");
        exit(EXIT_FAILURE);
    }
    debugprintf("control socket created and listening");

    while (1) {
        debugprintf("awaiting connection...");

        // accept client connection
        client_socket_fd = accept_client_connection(control_socket_fd, (struct sockaddr *)&client_addr, &addr_len);
        debugprintf("accepted client connection");

        // receive filename length from client
        uint32_t filename_len_net;
        recv_bytes(client_socket_fd, &filename_len_net, sizeof(filename_len_net), "filename length");
        filename_len = ntohl(filename_len_net);
        debugprintf("filename length received from client: %lu", filename_len);

        // receive filename from client TODO: FIX LATER
        ssize_t bytes_recvd_filename = recv(client_socket_fd, filename_buf, (filename_buf_len - sizeof(char)), 0);
        if (bytes_recvd_filename == -1) {
            perror("error receiving filename from client, exiting now");
            close(client_socket_fd);
            exit(EXIT_FAILURE);
        }
        if (bytes_recvd_filename != ((filename_len + 1) * sizeof(char))) {
            fprintf(stderr, "error receiving filename from client:\n");
            fprintf(stderr, "    incorrect number of bytes received, expecting %zu, received %zd\n", ((filename_len + 1) * sizeof(char)), bytes_recvd_filename);
            fprintf(stderr, "    exiting now\n");
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

        // attempt to open file on local filesystem
        file_len = open_filename_to_byte_array(filename_buf, &byteArray);
        if (file_len == -1) {
            debugprintf("file does not exist, size set to %ld bytes", file_len);
        } else {
            debugprintf("file opened to byte array, %ld bytes", file_len);
        }

        // send file length to client
        long int file_len_net = file_len;
        send_bytes(client_socket_fd, &file_len_net, sizeof(file_len_net), "size of file");
        debugprintf("file length sent to client");

        // quit if file does not exist
        if (file_len == -1) {
            debugprintf("file does not exist");
            close(client_socket_fd);
            continue;
        }
    
        // create MD5 hash of file
        MD5_hash_of_byte_array(byteArray, file_len, MD5_hash);
        debugprintf("MD5 hash created");

        // send MD5 hash to client
        send_bytes(client_socket_fd, *MD5_hash, 16, "MD5 hash");
        debugprintf("MD5 hash sent to server");

        // prepare to send file byte array (packet by packet) to client
        int i_full_pckt;
        int n_full_pckts = file_len / FILE_PCKT_LEN;
        size_t last_pckt_len = file_len % FILE_PCKT_LEN;
        debugprintf("expecting to send %d full packets to client (%zu bytes)", n_full_pckts, FILE_PCKT_LEN);
        if (last_pckt_len != 0) {
            debugprintf("last packet will be %zu bytes", last_pckt_len);
        } else {
            debugprintf("no last packet will be sent");
        }

        // send full packets to client
        for (i_full_pckt = 0; i_full_pckt < n_full_pckts; i_full_pckt++) {
            send_bytes(client_socket_fd, &byteArray[i_full_pckt * FILE_PCKT_LEN], FILE_PCKT_LEN, "file packet");
            debugprintf("full packet %d of %d sent to client", (i_full_pckt + 1), n_full_pckts);
            usleep(1000);
        }

        // send last packet to client (if necessary)
        if (last_pckt_len != 0) {
            send_bytes(client_socket_fd, &byteArray[n_full_pckts * FILE_PCKT_LEN], last_pckt_len, "last file packet");
            debugprintf("last packet sent to client");
        }
        debugprintf("file sent to client, DONE");

        close(client_socket_fd);
    }

    exit(EXIT_SUCCESS);
}

int accept_client_connection( int control_socket_fd, struct sockaddr * client_addr, socklen_t * addr_len )
{
    int client_socket_fd = accept(control_socket_fd, client_addr, addr_len);
    if (client_socket_fd == -1) {
        perror("failed to accept client connection, exiting now");
        exit(EXIT_FAILURE);
    }

    return client_socket_fd;
}

int create_control_socket_and_listen( const char * port_str, int max_pending )
{
    struct addrinfo hints; // hints for getaddrinfo()
    struct addrinfo * server_info_ll = NULL; // linked list returned by getaddrinfo()
    struct addrinfo * this_addr_ptr = NULL; // pointer to current item on server_info_ll linked list
    const int YES = 1; // used for setsockopt()
    int control_socket_fd;

    // set hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE; // autofill IP address
    hints.ai_family = AF_UNSPEC; // return both IPv4 and IPv6 addresses
    hints.ai_socktype = SOCK_STREAM; // specify TCP

    // get address info of server (self)
    int gai_rv;
    if ((gai_rv = getaddrinfo(NULL, port_str, &hints, &server_info_ll)) != 0) {
        fprintf(stderr, "error getting address information for server (self): %s\n", gai_strerror(gai_rv));
        fprintf(stderr, "quitting now\n");
        freeaddrinfo(server_info_ll);
        exit(EXIT_FAILURE);
    }

    // bind to first address where binding is possible
    for (this_addr_ptr = server_info_ll; this_addr_ptr != NULL; this_addr_ptr = this_addr_ptr->ai_next) {
        // create control socket
        control_socket_fd = socket(this_addr_ptr->ai_family, this_addr_ptr->ai_socktype, this_addr_ptr->ai_protocol);
        if (control_socket_fd == -1) {
            debugprintf("could not create control socket: %s", strerror(errno));
            continue;
        } else {
            debugprintf("control socket created");
        }

        // make control socket reusable
        if (setsockopt(control_socket_fd, SOL_SOCKET, SO_REUSEADDR, &YES, sizeof(YES)) == -1) {
            debugprintf("could not make control socket reusable: %s", strerror(errno));
            continue;
        } else {
            debugprintf("control socket set to reusable");
        }

        // bind control socket
        if (bind(control_socket_fd, this_addr_ptr->ai_addr, this_addr_ptr->ai_addrlen) == -1) {
            debugprintf("could not bind control socket: %s", strerror(errno));
            continue;
        } else {
            debugprintf("control socket bound");
        }

        freeaddrinfo(server_info_ll);

        if (listen(control_socket_fd, max_pending) == -1) {
        perror("failed to listen to socket, exiting now");
        close(control_socket_fd);
        exit(EXIT_FAILURE);
        }
        debugprintf("listening");

        return control_socket_fd;
    }

    freeaddrinfo(server_info_ll);
    return -1;
}

void print_usage( )
{
    printf("tcpserver is to be used in the following manner: \"tcpserver <PORT>\"\n");
}
