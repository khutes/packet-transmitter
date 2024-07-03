#include <stdbool.h>


#define MAX_ATTRIBUTE_LINE_LEN 1024
#define MAX_ATTRIBUTE_NAME_LEN 128

struct packet_attr 
{
    char name[MAX_ATTRIBUTE_NAME_LEN];
    int len;
    char *value;
    bool is_checksum;
    bool overwrite_value;   /* true if value should be overwritten with length of real header */
    struct packet_attr *child_attrs;
    int num_children;
};

//int ip_encapsulate (char *buffer, char* payload, int len_payload, char* src_addr, char* dest_addr);
int load_packet (char *spec_content, struct packet_attr **input_attr_array, int *header_size);
int load_packet_pseudo_header (char *spec_content, struct packet_attr **input_attr_array, int *header_size);
int load_packet_data(char *spec_content, char **input_buffer);
void print_all_packet_attrs(struct packet_attr *attr_array, int num_attrs);
int read_file_contents(char *filepath, char **output_buffer);
int serialize_packet_header(struct packet_attr *packet_attrs, int num_attrs, unsigned char *serialized_header, int max_header_size);
int serialize_packet_pseudo_header(struct packet_attr *packet_attrs, int num_attrs, unsigned char *serialized_header, int max_header_size, int len_overwrite);
void serialize_packet_data(char *buffer, unsigned char*serial_buffer, int len_serial_buffer);
int compute_and_set_checksum(
        struct packet_attr *packet_attrs,
        int num_attrs,
        unsigned char *serial_header,
        int serial_header_size,
        unsigned char* serial_pseudo,
        int serial_pseudo_size,
        unsigned char* serial_data,
        int serial_data_size
);
int send_ip_packet(unsigned char *serial_header, int serial_header_size, unsigned char *serial_data, int serial_data_size, in_addr_t dest_ip, in_addr_t src_ip);
int send_packet(char *specfile_path, in_addr_t dest_ip, in_addr_t src_ip);

/* Debug functions */
void print_binary(unsigned char *buffer, int len);
void print_hex(unsigned char *buffer, int len);
