#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "helper.h"

#define DEFAULT_DEST_IP "127.0.0.1"
#define PACKET_SIZE 1024
#define DEFAULT_SPECFILE_DIR "../specfiles"
#define MAX_SPECFILE_PATH_LEN 1024

char* get_arg_val(char* key, char**arg_list, int len)
{

    char *val = NULL;
    for (int i=1; i<len; i++) {
        if (strcmp(arg_list[i], key) == 0) {
            if (i+1 < len) {
                val = arg_list[i+1];
            }
            break;
        }
    }
    return val;

}

int main(int argc, char**argv) 
{
    char* packet_type = NULL;

    char *specfile_dir = NULL;
    char specfile_path[MAX_SPECFILE_PATH_LEN];
    char *specfile_content;

    //char ip_packet[PACKET_SIZE];
    //int len_ip_packet;

    //int sockfd;
    //struct sockaddr_in dest_addr;

    struct packet_attr *packet_attrs = NULL;
    int num_attrs = 0;
    int max_header_size = 0;
    struct packet_attr *pseudo_header_packet_attrs = NULL;
    int pseudo_header_num_attrs = 0;
    int max_pseudo_header_size = 0;

    char *packet_payload = NULL;
    int packet_payload_size = 0;

    unsigned char *serial_header = NULL;
    int serial_header_size = 0;
    unsigned char *serial_pseudo_header = NULL;
    int serial_pseudo_size = 0;
    unsigned char *serial_packet_data = NULL;

    printf("Starting packet transmitter\n");
    printf("argc: %d\n", argc);

    for (int i=1; i<argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }

    /* Get all the required arguments */
    packet_type = get_arg_val("--packet-type", argv, argc);
    
    if (packet_type == NULL) {
        printf("Error: Packet type not specified\n");
        return -1;
    }

    /* Construct specfile path for given packet type */
    specfile_dir = get_arg_val("--spec-dir", argv, argc);
    if (specfile_dir == NULL) {
        specfile_dir = DEFAULT_SPECFILE_DIR;
    }

    /* TODO: use snprintf */
    sprintf(specfile_path, "%s/%s", specfile_dir, packet_type);
    printf("specfile_path: %s\n", specfile_path);





    printf("packet-type: %s\n", packet_type);

    /* handle packet creation based on spec */
    
    if (read_file_contents(specfile_path, &specfile_content) < 0) {
        printf("Error: failed to read file content for %s\n", specfile_path);
        return -1;
    }
    printf("SPC: %s\n", specfile_content);

    
    num_attrs = load_packet(specfile_content, &packet_attrs, &max_header_size);
    if (num_attrs < 0) {
        printf("Error: failed to load packet spec for file %s\n", "../specfiles/tcp");
        return -1;
    }
    printf("DONE LOADING PACKET\n");
    
    /*PSEUDO HEADER */
    pseudo_header_num_attrs = load_packet_pseudo_header(specfile_content, &pseudo_header_packet_attrs, &max_pseudo_header_size);
    if (pseudo_header_num_attrs < 0) {
        printf("Error: failed to load pseudo header spec for file %s\n", "../specfiles/tcp");
        return -1;
    }

    /* Get payload */
    serial_header = (unsigned char *)calloc(sizeof(unsigned char), max_header_size);
    serial_header_size = serialize_packet_header(packet_attrs, num_attrs, serial_header, max_header_size);
    printf("written_bytes: %d\n", serial_header_size);
    print_binary(serial_header, serial_header_size);

    /* Serialize pseudo header */
    serial_pseudo_header = (unsigned char *)calloc(sizeof(unsigned char), max_header_size);
    serial_pseudo_size = serialize_packet_pseudo_header(pseudo_header_packet_attrs, pseudo_header_num_attrs, serial_pseudo_header, max_pseudo_header_size, serial_header_size);
    printf("written_bytes PS: %d\n", serial_pseudo_size);
    print_binary(serial_pseudo_header, serial_pseudo_size);



    /* Print all */
    print_all_packet_attrs(packet_attrs, num_attrs);     
    print_all_packet_attrs(pseudo_header_packet_attrs, pseudo_header_num_attrs);     
   
    packet_payload_size = load_packet_data(specfile_content, &packet_payload);
    serial_packet_data = (unsigned char *)calloc(sizeof(unsigned char), packet_payload_size);
    serialize_packet_data(packet_payload, serial_packet_data, packet_payload_size);
    print_binary(serial_packet_data, packet_payload_size);

    /* Compute and set the checksum */
    compute_and_set_checksum(packet_attrs, num_attrs, serial_header, serial_header_size, serial_pseudo_header, serial_pseudo_size, serial_packet_data, packet_payload_size);

    send_ip_packet(serial_header, serial_header_size, serial_packet_data, packet_payload_size);

    return 0;
}
