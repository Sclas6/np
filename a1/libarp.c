#include "libarp.h"

int init_raw_socket(char *device){
	struct ifreq ifreq;
	int soc = -1;

	if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("socket");
		return (-1);
	}

	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
	if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0){
		perror("ioctl");
		close(soc);
		return (-1);
	}

	struct packet_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_ifindex = ifreq.ifr_ifindex;
	if ((setsockopt(soc, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) < 0){
		perror("setsockopt");
		return (-1);
	}

	struct sockaddr_ll sa;
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0){
		perror("bind");
		close(soc);
		return (-1);
	}
	return (soc);
}

bool send_arp_request(int soc, in_addr_t target_ip, u_char target_mac[6], in_addr_t source_ip, u_char source_mac[6]){
	struct ether_header eh;
	struct ether_arp arp;
	union {
		unsigned long l;
		u_char c[4];
	} ip_conv;

	for (int i = 0; i < 6; i++){
		eh.ether_dhost[i] = target_mac[i];
		eh.ether_shost[i] = source_mac[i];
	}
	eh.ether_type = htons(ETHERTYPE_ARP);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = 6;
	arp.arp_pln = 4;
	arp.arp_op = htons(ARPOP_REQUEST);

	for (int i = 0; i < 6; i++){
		arp.arp_sha[i] = source_mac[i];
		arp.arp_tha[i] = 0;
	}

	ip_conv.l = source_ip;
	for (int i = 0; i < 4; i++){
		arp.arp_spa[i] = ip_conv.c[i];
	}
	ip_conv.l = target_ip;
	for (int i = 0; i < 4; i++){
		arp.arp_tpa[i] = ip_conv.c[i];
	}

	u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	memset(buf, 0, sizeof(buf));
	u_char *p = buf;
	memcpy(p, &eh, sizeof(struct ether_header));
	p = p + sizeof(struct ether_header);
	memcpy(p, &arp, sizeof(struct ether_arp));
	p = p + sizeof(struct ether_arp);
	int size = p - buf;
	write(soc, buf, size);
	return true;
}

char *ether2str(u_char *hwaddr, char *buf, int size){
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return (buf);
}

char *ip2str(u_int8_t *ip, char *buf, int size){	
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	return (buf);
}

bool check_reply(u_char *data, int size, char* ip){
	if (size < sizeof(struct ether_header)) return false;
	struct ether_arp *arp = (struct ether_arp *)(data + sizeof(struct ether_header));
	char buf[80];
	if(ntohs(arp->arp_op) == 2 && strcmp(ip, ip2str(arp->arp_tpa, buf, sizeof(buf))) == 0) return true;
	return false;
}

char** analyze_arp(u_char *data, int size, char** rt){
	char buf[80];
	struct ether_header *eh = (struct ether_header *)data;
	u_char *body = data + sizeof(struct ether_header);
	struct ether_arp *arp = (struct ether_arp *)body;
	strcpy(rt[0], ether2str(eh->ether_shost, buf, sizeof(buf)));
	strcpy(rt[1], ip2str(arp->arp_spa, buf, sizeof(buf)));
	return rt;
}

bool get_ip_address(char* addr, in_addr_t* res){
	if (inet_pton(PF_INET, addr, res) != 1)	{
		perror("inet_pton");
		return false;
	}
	return true;
}

bool get_device_ip_address(int soc, char* device, in_addr_t* res){
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = PF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);

	if ( ioctl(soc, SIOCGIFADDR, &ifr) == -1 ){
		perror("ioctl: SIOCGIFADDR");
		return false;
	}
	*res = ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr;
	return true;
}

bool get_device_mac_address(int soc, char* device, u_char res[6]){
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = PF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	if ( ioctl(soc, SIOCGIFHWADDR, &ifr) == -1 ){
		perror("ioctl: SIOCGIFHWADDR");
		return false;
	}
	for (int i = 0; i < 6; i++){
		res[i] = ifr.ifr_hwaddr.sa_data[i];
	}
	return true;
}


