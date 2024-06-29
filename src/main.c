#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define DEFAULT_NETWORK_LAYER 3
#define MIN_NETWORK_LAYER 1
#define MAX_NETWORK_LAYER 3


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

    



    return 0;
}
