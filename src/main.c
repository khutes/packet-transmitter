#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "helper.h"

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

void print_help_string(void)
{
    char *help_string = " Packet Transmitter options\n"
        "--packet-type:         (required) The name of the spec file which will be chosen in the set specfile directory\n"
        "--spec-dir:            The directory which contains the specfile. Default value is [../specfiles]\n"
        "--num-packets:         Number of packets which will be sent. Default value of 0 results in packets being sent forever\n"
        "--interval:            Milliseconds between packet sends. Default value of 0 results in no wait between packet sends\n"
        "--dest-ip:             (required) Destination IP to send the packets to. IPv4 only\n"
        "--src-ip:              (required) Source IP to send packets from. IPv4 only\n"
        "--help:                See this help string\n";

    printf("%s\n", help_string);
}

int main(int argc, char**argv) 
{
    char* packet_type = NULL;

    char *specfile_dir = NULL;
    char specfile_path[MAX_SPECFILE_PATH_LEN];

    char *num_packets_str = NULL;
    int num_packets = 0;

    char *interval_str = NULL;
    int interval;

    char *dest_ip_str = NULL;
    in_addr_t dest_ip = INADDR_NONE;
    char *src_ip_str = NULL;
    in_addr_t src_ip = INADDR_NONE;


    if (get_arg_val("--help", argv, argc) != NULL) {
        print_help_string();
        return 0;
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

    interval_str = get_arg_val("--interval", argv, argc);
    if (interval_str == NULL) {
        interval = 0;
    } else {
        if (strcmp(interval_str, "0") == 0) {
            interval = 0;
        } else {
            interval = atoi(interval_str);
            if (interval <= 0) {
                printf("Error: Invalid value %s for --interval. Must be integer > 0\n", interval_str);
                return -1;
            }
        }
    }
    interval *= 1000; /*Convert input milliseconds to microseconds */

    /* Get destination IP */
    dest_ip_str = get_arg_val("--dest-ip", argv, argc);
    if (dest_ip_str == NULL) {
        printf("Error: Destination IP address not set\n");
        return -1;
    }
    if ((dest_ip = inet_addr(dest_ip_str)) == INADDR_NONE) {
        printf("Error: invalid destination IP address %s\n", dest_ip_str);
        return -1;
    }

    /* Get src IP */
    src_ip_str = get_arg_val("--src-ip", argv, argc);
    if (src_ip_str == NULL) {
        printf("Error: Source IP address not set\n");
        return -1;
    }
    if ((src_ip = inet_addr(src_ip_str)) == INADDR_NONE) {
        printf("Error: Invalid Source IP address %s\n", src_ip_str);
        return -1;
    }

    /* Construct specfile path for given packet type */
    specfile_dir = get_arg_val("--spec-dir", argv, argc);
    if (specfile_dir == NULL) {
        specfile_dir = DEFAULT_SPECFILE_DIR;
    }

    /* TODO: use snprintf */
    printf("Starting packet transmitter\n");
    sprintf(specfile_path, "%s/%s", specfile_dir, packet_type);
    if (num_packets == 0) {
        while (true) {
            send_packet(specfile_path, dest_ip, src_ip);
            usleep((useconds_t)interval);
        }
    } else {
        for (int i=0; i<num_packets; i++) {
            send_packet(specfile_path, dest_ip, src_ip);
            usleep((useconds_t)interval);
        }
    }
    return 0;
}
