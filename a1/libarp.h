#include "rp.h"

int init_raw_socket(char *device);
bool send_arp_request(int soc, in_addr_t target_ip, u_char target_mac[6], in_addr_t source_ip, u_char source_mac[6]);
char** analyze_arp(u_char *data, int size, char** rt);
bool check_reply(u_char *data, int size, char* ip);
bool get_ip_address(char* addr, in_addr_t* res);
bool get_device_ip_address(int soc, char* device, in_addr_t* res);
bool get_device_mac_address(int soc, char* device, u_char res[6]);
typedef struct
{
    int soc;
    in_addr_t ip; 
}pth_arg;
