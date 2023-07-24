#include "libarp.h"

#define PORT_HTTP 80

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

char *ether2str(u_char *hwaddr, char *buf, int size){
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return (buf);
}

char *ip2str(u_int8_t *ip, char *buf, int size){
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	return (buf);
}

void print_ether_header(struct ether_header *eh, FILE *fp){
	char buf[80];
	fprintf(fp, "\n\t### ETHER_HEADER ###\n");
	fprintf(fp, "ether_dhost=%s\n", ether2str(eh->ether_dhost, buf, sizeof(buf)));
	fprintf(fp, "ether_shost=%s\n", ether2str(eh->ether_shost, buf, sizeof(buf)));
	fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
	switch (ntohs(eh->ether_type)){
	case ETH_P_IP:
		fprintf(fp, "(IP)\n");
		break;
	case ETH_P_IPV6:
		fprintf(fp, "(IPv6)\n");
		break;
	case ETH_P_ARP:
		fprintf(fp, "(ARP)\n");
		break;
	default:
		fprintf(fp, "(unknown)\n");
		break;
	}
}

void print_ip_header(struct iphdr * ip_hdr, FILE *fp){
	static char *ver[] = {
		"pre-v4",
		"undefine",
		"undefine",
		"undefine",
		"IPv4",
		"Internet Stream Protocol or ST",
		"IPv6",
		"IPv7",
		"P Internet Protocol",
		"TCP and UDP over Bigger Addresses",
		"IPv9",
		"Chinese IPv9"
	};
	fprintf(fp, "\n\t### IP_HEADER ###\n");
	fprintf(fp, "Version: %s\n", ver[ip_hdr->version]);
	fprintf(fp, "Length: %ubyte\n" , ip_hdr->ihl*4 );
	struct in_addr saddr;
	struct in_addr daddr;
	saddr.s_addr = ip_hdr->saddr;
	daddr.s_addr = ip_hdr->daddr;
	fprintf(fp, "Source IP: %s\n", inet_ntoa(saddr));
	fprintf(fp, "Destination IP: %s\n", inet_ntoa(daddr));
  	if( 0 == (ip_hdr->tos & (0xFF & ~IPTOS_CLASS_MASK))){
		fprintf(fp, "Precedence: " );
    	switch( IPTOS_PREC( ip_hdr->tos ) ){
		case IPTOS_PREC_ROUTINE:
			fprintf(fp, "Best Effort\n");
			break;
		case IPTOS_PREC_PRIORITY:
			fprintf(fp, "Priority\n");
			break;
		case IPTOS_PREC_IMMEDIATE:
			fprintf(fp, "Immediate\n");
			break;
		case IPTOS_PREC_FLASH:
			fprintf(fp, "Flash - mainly used for voice signaling\n");
			break;
		case IPTOS_PREC_FLASHOVERRIDE:
			fprintf(fp, "Flash Override\n");
			break;
		case IPTOS_PREC_CRITIC_ECP:
			fprintf(fp, "Critical - mainly used for voice RTP\n");
			break;
		case IPTOS_PREC_INTERNETCONTROL:
			fprintf(fp, "Internetwork Control\n");
			break;
		case IPTOS_PREC_NETCONTROL:
			fprintf(fp, "Network Control\n");
			break;
		default:
			fprintf(fp, "(unknown)\n");
			break;
		}
	}
	fprintf(fp, "Total Length=%d\n", ip_hdr->tot_len);
	fprintf(fp, "id=%d ", ip_hdr->id);
	fprintf(fp, "frag_off=%d ", ip_hdr->frag_off);
	fprintf(fp, "ttl=%d ", ip_hdr->ttl);
	fprintf(fp, "check=%d\n", ip_hdr->check);
}

void print_tcp_header(struct tcphdr *tcp, FILE *fp){
	fprintf(fp, "\n\t### TCP_HEADER ###\n");
	fprintf(fp, "Source Port: %d  ", ntohs(tcp->source));
	fprintf(fp, "Destination Port: %d\n", ntohs(tcp->dest));
	fprintf(fp, "Sequence: %d\n", ntohs(tcp->seq));
	fprintf(fp, "ACK Sequence: %d\n", ntohs(tcp->ack_seq));
	fprintf(fp, "Data Offset: %d\n", tcp->doff);
	fprintf(fp, " U  A  P  R  S  F\n");
	fprintf(fp, " R  C  S  S  Y  I\n");
	fprintf(fp, " G  K  H  K  T  N\n");
	fprintf(fp, " %d  %d  %d  %d  %d  %d\n", tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
	fprintf(fp, "Check Sum: %d  ", ntohs(tcp->check));
	fprintf(fp, "Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));
}

bool analyze_packet(u_char *data, int size){
	struct ether_header *eh = (struct ether_header *)data;
	u_char *body = data + sizeof(struct ether_header);
	int body_size = size - sizeof(struct ether_header);
	if(ntohs(eh->ether_type)==ETHERTYPE_IP){
		struct iphdr *ip = (struct iphdr *)body;
		if(ip->protocol == 0x06){
			struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
			if(htons(tcp->source) == PORT_HTTP){
				int tcp_header_size = tcp->doff * 4;
				int ip_header_size = ip->ihl * 4;
				int payload_offset = tcp_header_size + ip_header_size;
				print_ether_header(eh, stderr);
				print_ip_header(ip, stderr);
				print_tcp_header(tcp, stderr);
				print_http_data(body + payload_offset, body_size - payload_offset);
				return true;
			}
		}
	}
	return false;
}

void print_http_data(u_char *data, int size){
	char buf[16];
	for (int i = 0; i <= size; i++){
		buf[i%16] = data[i];
		if ( i % 16 == 15 || i == size - 1 ) {
			for ( int j=0; j<16; j++ ) {
				char ch = buf[j] & 0xFF;
				if (32 <= ch && ch < 127) {
					printf("%c", ch);
				}else if(ch == 10){
					printf("\n");
				}
			}
		}
	}
}

