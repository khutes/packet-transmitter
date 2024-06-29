#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "helper.h"

#define DEFAULT_NETWORK_LAYER 3
#define MIN_NETWORK_LAYER 1
#define MAX_NETWORK_LAYER 3


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
    char* network_layer_str = NULL;
    int network_layer = DEFAULT_NETWORK_LAYER;

    char *specfile_dir = NULL;
    char specfile_path[MAX_SPECFILE_PATH_LEN];

    char ip_packet[PACKET_SIZE];
    int len_ip_packet;

    int sockfd;
    struct sockaddr_in dest_addr;

    struct packet_attr *packet_attrs = NULL;
    int num_attrs = 0;


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





    /*Get optional non packet attribute arguments */
    network_layer_str = get_arg_val("--network-layer", argv, argc);
    if (network_layer_str != NULL) {
        network_layer = atoi(network_layer_str);
        if (network_layer < MIN_NETWORK_LAYER || network_layer > MAX_NETWORK_LAYER) {
            printf("Error: %s is not a valid network layer\n", network_layer_str);
            return -1;
        }
    }
    printf("network_layer: %d\n", network_layer);



    printf("packet-type: %s\n", packet_type);

    /* handle packet creation based on spec */

    num_attrs = load_packet(specfile_path, &packet_attrs);
    if (num_attrs < 0) {
        printf("Error: failed to load packet spec for file %s\n", "../specfiles/tcp");
        return -1;
    }
    print_all_packet_attrs(packet_attrs, num_attrs);     
    

    
    /* Socket setup */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        printf("Error opening socket\n");
        return -1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;
    dest_addr.sin_addr.s_addr = inet_addr(DEFAULT_DEST_IP);

    len_ip_packet = ip_encapsulate(ip_packet, "HELLO", strlen("HELLO"), "127.0.0.1", "127.0.0.1");
    if (len_ip_packet < 0) {
        printf("Error encapsulating ip packet\n");
        return -1;
    }

    if (sendto(sockfd, ip_packet, len_ip_packet, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        printf("Error: send failed\n");
    }

    close(sockfd);

    return 0;
}
