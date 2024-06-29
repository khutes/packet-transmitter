#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>

#include "helper.h"

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

/* Returns len of ip packet */
int ip_encapsulate(char* buffer, char* payload, int len_payload, char *src_addr, char* dest_addr) {   
    
    struct ip *ip_header = (struct ip*) buffer;

    /* Set all header values */
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + len_payload + 1;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_sum = 0;
    ip_header->ip_p = IPPROTO_RAW;
    ip_header->ip_src.s_addr = inet_addr(src_addr);
    ip_header->ip_dst.s_addr = inet_addr(dest_addr);

    ip_header->ip_sum = checksum((unsigned short *) buffer, ip_header->ip_len);

    /* Add payload */
    memcpy(buffer + sizeof(struct ip), payload, len_payload);

    return ip_header->ip_len;

}
