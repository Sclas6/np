#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <stdlib.h>
#include <arpa/inet.h>