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

    char *num_packets_str;
    int num_packets = 0;

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

    num_packets_str = get_arg_val("--num-packets", argv, argc);
    if (num_packets_str == NULL) {
        num_packets = 0;
    } else {
        if (strcmp(num_packets_str, "0") == 0) {
            num_packets = 0;
        } else {
            num_packets = atoi(num_packets_str);
            if (num_packets == 0) {
                printf("Error: %s is invalid value for --num-packets\n", num_packets_str);
                return -1;
            }
        }
    }

    /* Construct specfile path for given packet type */
    specfile_dir = get_arg_val("--spec-dir", argv, argc);
    if (specfile_dir == NULL) {
        specfile_dir = DEFAULT_SPECFILE_DIR;
    }

    /* TODO: use snprintf */
    sprintf(specfile_path, "%s/%s", specfile_dir, packet_type);
    printf("specfile_path: %s\n", specfile_path);
    /* handle packet creation based on spec */

    if (num_packets == 0) {
        while (true) {
            send_packet(specfile_path);
        }
    } else {
        for (int i=0; i<num_packets; i++) {
            send_packet(specfile_path);
        }
    }
    return 0;
}
