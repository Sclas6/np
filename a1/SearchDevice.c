#include "rp.h"
#include "libarp.h"

void* threadRecv(void* arg){
	pth_arg *this_arg;
	this_arg = arg;
	int soc = this_arg->soc;
	int size = -1;
	struct in_addr tmp;
	tmp.s_addr = this_arg->ip;
	u_char buf[65535];
	while(true){
		if ((size = read(soc, buf, sizeof(buf))) > 0){
			if(check_reply(buf, size, inet_ntoa(tmp)) == 1){
				char** test = (char**)malloc(sizeof(char*) * 512);
				test[0] = (char*)malloc(sizeof(char)*32);
				test[1] = (char*)malloc(sizeof(char)*32);
				test = analyze_arp(buf, size, test);
				fprintf(stderr, "IP: %s, MAC: %s\n", test[1], test[0]);
				free(test);
			}
		}
	}
	pthread_exit(NULL);
}

int main(int argc, char *argv[]){
	char* device = argv[1];
	int soc = -1;

	if ((soc = init_raw_socket(device)) == -1){
			fprintf(stderr, "ERROR: cannot initialize device: %s\n", device);
			return (-1);
		}

	if (argc <= 1){
		fprintf(stderr, "Usage: SearchDevice device_name\n");
		return (1);
	}

	in_addr_t this_ip;
	get_device_ip_address(soc, device, &this_ip);
	pth_arg pth;
	pth.soc = soc;
	pth.ip = this_ip;
	pthread_t th;
	pthread_create(&th, NULL, threadRecv, (void *)&pth);

    struct ifaddrs *ifap, *ifa;
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next){
        if (ifa->ifa_addr->sa_family==AF_INET && strcmp(ifa->ifa_name,device)==0){
            uint32_t addr_search = ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr & ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            uint32_t addr_broadcast = ~((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr | ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            for(int i = ntohl(addr_search) + 1; i < ntohl(addr_broadcast); i++){
                struct in_addr tmp;
                tmp.s_addr = htonl(i);
				char* addr = inet_ntoa(tmp);
				in_addr_t source_ip;
				get_device_ip_address(soc, device, &source_ip);
				in_addr_t target_ip;
				get_ip_address(addr, &target_ip);
				u_char source_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
				get_device_mac_address(soc, device, source_mac);
				u_char target_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
				send_arp_request(soc, target_ip, target_mac, source_ip, source_mac);
            }
        }
    }
	
    freeifaddrs(ifap);
	sleep(10);
	close(soc);
	return (0);
}


