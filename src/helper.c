
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <stdint.h>

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

uint16_t packet_checksum(unsigned char *buffer, int num_bytes)
{
    uint32_t sum = 0;

    while (num_bytes > 1) {
        sum += ((uint16_t)(*buffer << 8) | *(buffer + 1));
        buffer += 2;
        num_bytes -= 2;
    }

    /* Add final byte */
    if (num_bytes > 0) {
        sum += (uint16_t)(*buffer << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

int transmit_packet(unsigned char* packet, int packet_size, char* dest_addr_str)
{

    int sockfd;
    struct sockaddr_in dest_addr;

    /* Socket setup */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        printf("Error: failed to open socket\n");
        return -1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;
    dest_addr.sin_addr.s_addr = inet_addr(dest_addr_str);

    if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        printf("Error: failed to send packet\n");
        return -1;
        close(sockfd);
    }

    close(sockfd);

    return 0;
}

/* Returns len of ip packet */
int ip_encapsulate(unsigned char* buffer, unsigned char* payload, int len_payload, char *src_addr, char* dest_addr) {   
    
    struct ip *ip_header = (struct ip*) buffer;

    /* Set all header values */
    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = (sizeof (struct ip)) >> 2;
    ip_header->ip_tos = 0;
    ip_header->ip_len = sizeof(struct ip) + len_payload + 1;
    ip_header->ip_id = htons(54321);
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

int create_ip_packet_payload(
        unsigned char *ip_payload_buffer,
        unsigned char *serial_header, 
        int serial_header_size, 
        unsigned char *serial_data,
        int serial_data_size)
{
    /* Write all buffers into payload */
    int written_bytes = 0;
    if (serial_header != NULL) {
        memcpy(ip_payload_buffer, serial_header, serial_header_size);
        written_bytes += serial_header_size;
    }
    if (serial_data != NULL) {
        memcpy(ip_payload_buffer + written_bytes, serial_data, serial_data_size);
        written_bytes += serial_data_size;
    }

    return written_bytes;
}

int send_ip_packet(unsigned char *serial_header, int serial_header_size, unsigned char *serial_data, int serial_data_size)
{
    
    unsigned char* payload = NULL;
    int payload_size = 0;
    unsigned char *ip_buffer = NULL;
    int ip_buffer_size = 0;
    int ip_packet_size = 0;


    payload = (unsigned char *)calloc(sizeof(unsigned char), serial_header_size + serial_data_size);
    if (payload == NULL) {
        printf("Error: failed to allocate ip payload\n");
        return -1;
    }
    payload_size = create_ip_packet_payload(payload, serial_header, serial_header_size, serial_data, serial_data_size);

    ip_buffer_size = sizeof(struct ip) + payload_size;
    ip_buffer = (unsigned char *)calloc(sizeof(unsigned char), ip_buffer_size);
    if (ip_buffer == NULL) {
        printf("Error: failed to allocate ip buffer\n");
        return -1;
    }
    
    ip_packet_size = ip_encapsulate(ip_buffer, payload, payload_size, "127.0.0.1", "127.0.0.1");
    transmit_packet(ip_buffer, ip_packet_size, "127.0.0.1");

    printf("FINAL\n");
    print_binary(ip_buffer, ip_packet_size);
    printf("\n");
    print_hex(ip_buffer, ip_packet_size);

    return 0;
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

int read_file_contents(char *filepath, char **output_buffer)
{

    FILE *fp;
    char *buffer = NULL;
    int file_size;
    int bytes_read;
    int fd;

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("Error: Unable to open file %s\n", filepath);
        return -1;
    }

    fd = fileno(fp);

    if(flock(fd, LOCK_SH) == -1) {
        printf("Error: Unable to lock file %s\n", filepath);
        fclose(fp);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buffer = (char *)calloc(sizeof(char), file_size + 1);
    if (buffer == NULL) {
        printf("Error: error allocating buffer for file read\n");
        fclose(fp);
        return -1;
    }

    bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != file_size) {
        printf("Error: failed to read file %s\n", filepath);
        fclose(fp);
        free(buffer);
        return -1;
    }

    buffer[file_size] = '\0';
    flock(fd, LOCK_UN);
    fclose(fp);
    *output_buffer = buffer;

    return 0;

}

void print_binary(unsigned char *buffer, int len)
{
    unsigned char c;
    printf(" ");
    for (int i = 0; i < len; ++i) {
        c = buffer[i];
        for (int j = 7; j >= 0; --j) {
            printf("%d", (c >> j) & 1);
        }
        if ((i + 1)%4 == 0) {
            printf("\n");
        }
        printf(" ");
    }
    printf("\n");
}

void print_hex(unsigned char *buffer, int len)
{
    for (int i = 0; i < len; ++i) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
}

int convert_hex_to_bytes(char *hex_buffer, unsigned char *byte_array, int byte_array_len) {
    for (int i=0; i<byte_array_len; i++) {
        sscanf(hex_buffer + (2 * i), "%2hhx", &byte_array[i]);
    }
    return 0;
}

int get_checksum_offset(struct packet_attr *packet_attrs, int num_attrs)
{

    int offset = 0;
    struct packet_attr curr_attr;
    bool checksum_found = false;
    for (int i=0; i<num_attrs; i++) {

        curr_attr = packet_attrs[i];
        if (curr_attr.is_checksum) {
            if (curr_attr.len != 2) {
                printf("Error: invalid checksum length of %d, auto compute of checksum is only supported for checksums of len 2\n", curr_attr.len);
                return -1;
            }
            checksum_found = true;
            break;
        }

        if (curr_attr.len == -1) {
            for (int child_idx=0; child_idx<curr_attr.num_children; child_idx++) {
                offset += curr_attr.child_attrs[child_idx].len;
            }    
        } else {
            offset += curr_attr.len;
        }
    }
    if (!checksum_found) {
        printf("Warning: checksum not found, continuing with default value\n");
        return -1;
    }
    return offset;
}

/* Computes the checksum for the header and sets it
 * Requires that the checksum have a length of 2
 */
int compute_and_set_checksum(
        struct packet_attr *packet_attrs, 
        int num_attrs, 
        unsigned char* serial_header, 
        int serial_header_size, 
        unsigned char* serial_pseudo, 
        int serial_pseudo_size, 
        unsigned char* serial_data, 
        int serial_data_size)
{

    uint32_t checksum = 0;
    uint16_t sum16 = 0;
    int offset = 0;
    
    if (serial_pseudo != NULL) {
        checksum += packet_checksum(serial_pseudo, serial_pseudo_size);
    }
    if (serial_header != NULL) {
        checksum += packet_checksum(serial_header, serial_header_size);
    }
    if (serial_data != NULL) {
        checksum += packet_checksum(serial_data, serial_data_size);
    }

    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    sum16 = (uint16_t)~checksum;

    offset = get_checksum_offset(packet_attrs, num_attrs);
    if (offset == -1) {
        printf("Error: Unable to auto compute checksum\n");
        return -1;
    }
    serial_header[offset] = (uint8_t)(sum16 >> 8);
    serial_header[offset + 1] = (uint8_t)(sum16);

    return 0;

}

void serialize_packet_data(char *buffer, unsigned char*serial_buffer, int len_serial_buffer)
{
    for (int i=0; i<len_serial_buffer; i++) {
        serial_buffer[i] = (unsigned char)buffer[i];
    }
}

int serialize_packet_pseudo_header(struct packet_attr *packet_attrs, int num_attrs, unsigned char *serialized_header, int max_header_size, int len_overwrite) {
    struct packet_attr curr_attr;
    /* Need to check if value of any attrs need to be overwritten before serializing */
    for (int i=0; i<num_attrs; i++) {
        curr_attr = packet_attrs[i];
        if (curr_attr.overwrite_value) {
            /*Convert len_overwrite to hex padded with 0s to keep len of the attribute the same */
            sprintf(curr_attr.value, "%0*X", curr_attr.len * 2, len_overwrite);
        }
    }
    return serialize_packet_header(packet_attrs, num_attrs, serialized_header, max_header_size);
}

int serialize_packet_header(struct packet_attr *packet_attrs, int num_attrs, unsigned char *serialized_header, int max_header_size) {

    unsigned char *bytes = NULL;
    unsigned char *full_packet = NULL;
    int written_bytes = 0;
    struct packet_attr curr_attr;
    struct packet_attr curr_child;
    printf("NUM ATTRS: %d\n", num_attrs);

    for (int i=0; i< num_attrs; i++) {

        curr_attr = packet_attrs[i];
    
        /* Is variable length, iterate through children */
        if (curr_attr.len == -1) {
            for (int j=0; j<curr_attr.num_children; j++) {
                curr_child = curr_attr.child_attrs[j];
                bytes = (unsigned char *)calloc(sizeof(unsigned char), curr_child.len);
                convert_hex_to_bytes(curr_child.value, bytes, curr_child.len);
                printf("(%d): %s -> ", curr_child.len, curr_child.value);
                print_binary(bytes, curr_child.len);
                memcpy(serialized_header + written_bytes, bytes, curr_child.len);
                written_bytes +=  curr_child.len;
            }
        } else {
            bytes = (unsigned char *)calloc(sizeof(unsigned char), curr_attr.len);
            convert_hex_to_bytes(curr_attr.value, bytes, curr_attr.len);
            printf("%s (%d): %s -> ", curr_attr.name, curr_attr.len, curr_attr.value);
            print_binary(bytes, curr_attr.len);
            memcpy(serialized_header + written_bytes, bytes, curr_attr.len);
            written_bytes +=  curr_attr.len;
            free(bytes);
        }
    }
    return written_bytes;
}



int load_packet_data(char *spec_content, char** input_buffer) {


    char line[MAX_ATTRIBUTE_LINE_LEN];
    int line_len;
    
    char *start;
    char *end;
    char *buffer;
    bool data_found = false;
    start = spec_content;
    /* Move forward until at "DATA" */
    while ((end = strchr(start, '\n')) != NULL) {

        line_len = end - start;
        strncpy(line, start, line_len);
        line[line_len] = '\0';

        if (strcmp(line, "DATA") == 0) {
            start = end + 1;
            data_found = true;
            break;
        }

        start = end + 1;
    }

    if (!data_found) {
        return 0;
    }
    
    buffer = (char *)calloc(sizeof(char), strlen(start) - 1);
    memcpy(buffer, start, strlen(start) - 1);
    *input_buffer = buffer;

   return strlen(start) - 1;
}

int load_packet_pseudo_header(char *spec_content, struct packet_attr **input_attr_array, int* header_size)
{       
    char line[MAX_ATTRIBUTE_LINE_LEN];
    int line_len;
    
    char *start;
    char *end;
    start = spec_content;
    bool ps_header_found = false;
    while ((end = strchr(start, '\n')) != NULL) {

        line_len = end - start;
        strncpy(line, start, line_len);
        line[line_len] = '\0';

        if (strcmp(line, "PSEUDOHEADER") == 0) {
            start = end + 1;
            ps_header_found = true;
            break;
        }

        start = end + 1;
    }

    if (!ps_header_found) {
        return 0;
    }

    return load_packet(start, input_attr_array, header_size);
}

int load_packet(char *spec_content, struct packet_attr **input_attr_array, int *header_size)
{
    char line[MAX_ATTRIBUTE_LINE_LEN];
    int line_len;
    int max_packet_size;
    int line_count = 0;
    int attr_count = 0;
    int i = 0;
    char *save_ptr;
    int value_copy_size = 0;
    char *copy_pointer = NULL;
    struct packet_attr* attr_array = NULL;
    char *start;
    char *end;
    char *attr_format_str = "%s %d"; /* Used to get name and length */

    /* Get the number of attributes */
    start = spec_content;
    while ((end = strchr(start, '\n')) != NULL) {
            
            line_len = end - start;
            strncpy(line, start, line_len);
            line[line_len] = '\0';
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
            } else if (!isblank(line[0])) {     /* Don't count child attributes in main attribute count */
                attr_count++;
            }
            line_count++;
            start = end + 1;
    }

    /* Allocate attribute array */
    attr_array = (struct packet_attr*)calloc(sizeof(struct packet_attr), attr_count);
    if (attr_array == NULL) {
        printf("Error: Unable to allocate attribute array\n");
        return -1;
    }
    
    start = spec_content;
    line_count = 0;
    /* Get values for each attribute */
    while ((end = strchr(start, '\n')) != NULL) {

            line_len = end - start;
            strncpy(line, start, line_len);
            line[line_len] = '\0';

            if (line_count == 0) {
                line_count++;
                start = end + 1;
                continue;
            } else if (strcmp("DATA", line) == 0) { 
                break;
            } else if (strcmp("PSEUDOHEADER", line) == 0) {
                break;
            } else if (strcmp("END", line) == 0) {
                break;
            } else if (isblank(line[0])) { 
                    continue;
            } else {
                /* We got an attribute */
                sscanf(line, attr_format_str, attr_array[i].name, &(attr_array[i].len));
                //printf("name: %s\n", attr_array[i].name);

                if (attr_array[i].name[0] == '$') {
                    attr_array[i].is_checksum = true;
                } 
                if (attr_array[i].name[0] == '^') {
                    attr_array[i].overwrite_value = true;
                } else {
                    attr_array[i].overwrite_value = false;
                }

                /* alloc value of attribute based on the read in length */
                if (attr_array[i].len == -1) {
                    /* Count number of child attributes */
                    attr_array[i].num_children = 0;
                    start = end + 1;
                    save_ptr = start;
                    while ((end = strchr(start, '\n')) != NULL) {
                        line_len = end - start;
                        strncpy(line, start, line_len);
                        line[line_len] = '\0';

                        if (!isblank(line[0])) {
                            break;
                        }
                        attr_array[i].num_children++;
                        start = end + 1;

                    }
                    if (attr_array[i].num_children == 0) {
                       continue;
                    } 
                    attr_array[i].child_attrs = (struct packet_attr *)calloc(
                        sizeof(struct packet_attr), attr_array[i].num_children);
                    if (attr_array[i].child_attrs == NULL) {
                        printf("Error: Unable to allocate child attributes\n");
                        return -1;
                    }

                    start = save_ptr;
                    /* Get child attribute values */
                    for (int child_idx=0; child_idx<attr_array[i].num_children; child_idx++) {
                        if ((end = strchr(start, '\n')) == NULL) {
                            printf("Read Error: Error reading child attributes\n");
                            return -1;
                        }

                        line_len = end - start;
                        strncpy(line, start, line_len);
                        line[line_len] = '\0';

                        if (!isblank(line[0])) {
                            break;
                        }
                        save_ptr = start;
                        
                        sscanf(line, "%d", &(attr_array[i].child_attrs[child_idx].len));
                        attr_array[i].child_attrs[child_idx].value = (char *)calloc(sizeof(char), 
                                attr_array[i].child_attrs[child_idx].len*2);

                        value_copy_size = attr_array[i].child_attrs[child_idx].len * 2;
                        copy_pointer = line + (strlen(line) - value_copy_size);
                        if (!memcpy(attr_array[i].child_attrs[child_idx].value, copy_pointer, value_copy_size)) {
                            printf("Error: Memory copy of child attribute value failed\n");
                            return -1;
                        }
                        if (attr_array[i].child_attrs[child_idx].value[0] == 'x') {
                            printf("Error: actual length of value for (%s) child number %d does not match specified length of (%d)\n", attr_array[i].name, child_idx, attr_array[i].child_attrs[child_idx].len);
                            return -1;
                        }
                        start = end + 1;
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
                        return -1;
                    }

                    if (attr_array[i].value[0] == 'x') {
                        printf("Error: actual length of value for (%s) does not match specified length of (%d)\n", attr_array[i].name, attr_array[i].len);
                        return -1;
                    }

                }
                i++;
            }
            line_count++;
            start = end + 1;
    }

    *input_attr_array = attr_array;
    *header_size = max_packet_size;

    return attr_count;

}




