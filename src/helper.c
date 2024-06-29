
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

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

void remove_newline(char *str)
{
    int len = strlen(str);

    for (int i=0; i<len; i++) {
        if (str[i] == '\n' || str[i] == '\r') {
            str[i] = '\0';
            return;
        }
    }
}

void print_packet_attr(struct packet_attr attr)
{
    char *format_str = "%s(%d): %s\n";
    char print_str[MAX_ATTRIBUTE_LINE_LEN];
    sprintf(print_str, format_str, attr.name, attr.len, attr.value);
    printf("%s", print_str);

    if (attr.child_attrs != NULL) {

        for (int i=0; i<attr.num_children; i++) {
            printf("printsize: %d\n", attr.child_attrs[i].len*2);
            printf("\t(%d): %.*s\n", attr.child_attrs[i].len, attr.child_attrs[i].len*2, attr.child_attrs[i].value);
        }
    }
}

void print_all_packet_attrs(struct packet_attr *attr_array, int num_attrs)
{
    printf("==============================\n");
    for (int i=0; i<num_attrs; i++) {
        print_packet_attr(attr_array[i]);
    }
    printf("==============================\n");
}

int load_packet(char *packet_file_path, struct packet_attr **input_attr_array)
{
    FILE *fp;
    char line[MAX_ATTRIBUTE_LINE_LEN];
    int max_packet_size;
    int line_count = 0;
    int attr_count = 0;
    int i = 0;
    int fp_save = 0;
    int value_copy_size = 0;
    char *copy_pointer = NULL;
    struct packet_attr* attr_array = NULL;

    char *attr_format_str = "%s %d"; /* Used to get name and length */

    fp = fopen(packet_file_path, "r");
    if (fp == NULL) {
        printf("Error: Unable to open %s\n", packet_file_path);
        return -1;
    }

    /* Get the number of attributes */
    while (fgets(line, sizeof(line), fp)) {
            printf("%s", line);
            remove_newline(line);
            if (line_count == 0) {
                max_packet_size = atoi(line);
                if (max_packet_size == 0) {
                    printf("Error: invalid packet size %s", line);
                    return -1;
                }
            } else if (strcmp("DATA", line) == 0) { 
                break;
            } else if (strcmp("PSEUDOHEADER", line) == 0) {
                break;
            } else if (strcmp("END", line) == 0) {
                break;
            } else if (isblank(line[0])) {     /* Don't count child attributes in main attribute count */
                    continue;
            } else {
                /* We got an attribute */
                attr_count++;
            }
            line_count++;
    }

    /* Allocate attribute array */
    attr_array = (struct packet_attr*)calloc(sizeof(struct packet_attr), attr_count);
    if (attr_array == NULL) {
        printf("Error: Unable to allocate attribute array\n");
        return -1;
    }
    
    fseek(fp, 0, SEEK_SET);
    line_count = 0;
    
    /* Get values for each attribute */
    while (fgets(line, sizeof(line), fp)) {
            remove_newline(line);
            if (line_count == 0) {
                line_count++;
                continue;
            } else if (strcmp("DATA", line) == 0) { 
                break;
            } else if (strcmp("PSEUDOHEADER", line) == 0) {
                break;
            } else if (strcmp("END", line) == 0) {
                break;
            } else if (isblank(line[0])) {     /* Don't count child attributes in main attribute count */
                    continue;
            } else {
                /* We got an attribute */
                sscanf(line, attr_format_str, attr_array[i].name, &(attr_array[i].len));
                printf("name: %s, len %d\n", attr_array[i].name, attr_array[i].len); 

                if (attr_array[i].name[0] == '$') {
                    attr_array[i].is_checksum = true;
                }

                /* alloc value of attribute based on the read in length */
                if (attr_array[i].len == -1) {
                    printf("Variable length attr\n");

                    /* Count number of child attributes */
                    attr_array[i].num_children = 0;
                    fp_save = ftell(fp);
                    while (fgets(line, sizeof(line), fp)) {

                        remove_newline(line);
                        if (!isblank(line[0])) {
                            break;
                        }
                        attr_array[i].num_children++;

                    }
                    
                    attr_array[i].child_attrs = (struct packet_attr *)calloc(
                        sizeof(struct packet_attr), attr_array[i].num_children);
                    if (attr_array[i].child_attrs == NULL) {
                        printf("Error: Unable to allocate child attributes\n");
                        return -1;
                    }

                    fseek(fp, fp_save, SEEK_SET);
                    /* Get child attribute values */
                    for (int child_idx=0; child_idx<attr_array[i].num_children; child_idx++) {
                        if (!fgets(line, sizeof(line), fp)) {
                            printf("Read Error: Error reading child attributes\n");
                            return -1;
                        }
                        remove_newline(line);
                        if (!isblank(line[0])) {
                            fseek(fp, fp_save, SEEK_SET);
                            break;
                        }
                        fp_save = ftell(fp);
                        
                        sscanf(line, "%d", &(attr_array[i].child_attrs[child_idx].len));
                        attr_array[i].child_attrs[child_idx].value = (char *)calloc(sizeof(char), 
                                attr_array[i].child_attrs[child_idx].len*2);

                        /* copy len*2 bytes of memory from current fp - len*2 
                         * multiply by 2 since len represents number of octets and each octect is represented by 2 chars
                         */
                        value_copy_size = attr_array[i].child_attrs[child_idx].len * 2;
                        copy_pointer = line + (strlen(line) - value_copy_size);
                        if (!memcpy(attr_array[i].child_attrs[child_idx].value, copy_pointer, value_copy_size)) {
                            printf("Error: Memory copy of child attribute value failed\n");
                        }
                    }


                } else {
                    attr_array[i].value = (char *)calloc(sizeof(char), attr_array[i].len);
                    if (attr_array[i].value == NULL) {
                        printf("Error: Unable to alloc value for attribute\n");
                        return -1;
                    }

                    value_copy_size = attr_array[i].len * 2;
                    copy_pointer = line + (strlen(line) - value_copy_size);
                    if (!memcpy(attr_array[i].value, copy_pointer, value_copy_size)) {
                        printf("Error: Memory copy of attribute value failed\n");
                    }

                }
                i++;
            }
            line_count++;
    }

    *input_attr_array = attr_array;
    fclose(fp);

    return attr_count;

}




