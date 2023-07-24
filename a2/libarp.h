#include "rp.h"

int init_raw_socket(char *device);
void print_ether_header(struct ether_header *eh, FILE *fp);
void print_ip_header(struct iphdr * ip_hdr, FILE *fp);
void print_tcp_header(struct tcphdr *tcp, FILE *fp);
void print_http_data(u_char* data, int size);
bool analyze_packet(u_char *data, int size);
