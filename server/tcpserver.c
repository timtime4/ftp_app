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
#include <dirent.h>
// CONST POINTERS?

#include "tcp_shared.h" // utility functions

int DEBUG = 1; // flag for whether to print debug statements
#define MAX_PENDING 5
#define FILENAME_BUF_LEN 1000
#define FILE_PCKT_LEN 1024

int accept_client_connection( int control_socket_fd, struct sockaddr * client_addr, socklen_t * addr_len );
int create_control_socket_and_listen( );
void print_usage( ); // print correct command usage (arguments, etc.)
void receive_file_info ( int client_socket_fd, char * filename_buf);

int main( int argc, char * argv[] )
{
    // variables and data structures
    const char * port_str; // (from command line)
    int control_socket_fd; // socket accepting connections
    int client_socket_fd; // socket for communicating with client
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char filename_buf[FILENAME_BUF_LEN];
    unsigned char * byteArray = NULL; // byte array holding file to send to client
    long int file_len; // length of file to send to client
    unsigned char * MD5_hash[16]; // POINTER to array (NOT STRING) holding hex values for MD5 hash
    enum OPERATION op;

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

        // Enter loop to determine operation from client
        op = REQ; 
        while(op != XIT){

          // receive operation from client
          uint32_t op_net;
          recv_bytes(client_socket_fd, &op_net, sizeof(op_net), "operation");
          op = ntohl(op_net);
          debugprintf("operation received from client: %lu", op);

          // Operation control
          if(op == REQ){
              debugprintf("operation = REQ");
              receive_file_info(client_socket_fd, filename_buf);

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
          } else if(op == UPL){
            debugprintf("operation = UPL");
          } else if ( op == DEL ) {
            debugprintf("operation = DEL");
            receive_file_info(client_socket_fd, filename_buf);
            
            // check if file exists
            short int file_exists = 0;
            if( access( filename_buf, F_OK ) != -1 ) file_exists = 1;

            uint32_t file_exists_net;
            file_exists_net = htons(file_exists);
            send_bytes(client_socket_fd, &file_exists_net, sizeof(file_exists_net), "file exists");
            debugprintf("file exists status sent to client");

            if( file_exists ) {
              // Listen for delete confirmation
              uint32_t confirm_net;
              recv_bytes(client_socket_fd, &confirm_net, sizeof(confirm_net), "confirm delete from client");
              short int confirm = ntohs(confirm_net);
              if( confirm ){
                debugprintf("Delete the file");
                confirm = unlink(filename_buf);   // reuse confirm for successful delete flag
                confirm_net = htons(confirm);
                send_bytes(client_socket_fd, &confirm_net, sizeof(confirm_net), "confirm delete by server");
                  
              } else {
                debugprintf("Don't delete the file");
              }
            }
            
          } else if ( op == LIS ) {
            debugprintf("operation = LIS");
            DIR *dp;
            struct dirent *ep;  
        
            // send over number of files in dir   
            dp = opendir ("./");
            short int num_files = 0;
            if (dp != NULL) {
              while (ep = readdir (dp)) num_files++;
              uint32_t num_files_net;
              num_files_net = htons(num_files);
              send_bytes(client_socket_fd, &num_files_net, sizeof(num_files_net), "Server sending number of files");
              
              (void) closedir (dp);
            }
            else perror ("Couldn't open the directory");

            // send over directory listing
            dp = opendir ("./");
            if (dp != NULL) {
              while (ep = readdir (dp)){
                strcpy(filename_buf, ep->d_name);
                send_file_info(client_socket_fd, filename_buf);
              }
              
              (void) closedir (dp);
            }
            else perror ("Couldn't open the directory");
            
          } else if ( op == XIT ) {
            debugprintf("operation = XIT");
          }

          
        }

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
    printf("ftpserver is to be used in the following manner: \"myftpd <PORT>\"\n");
}


