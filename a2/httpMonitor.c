#include "libarp.h"
#include "rp.h"

int main(int argc, char *argv[]){
	int soc = -1;
	int size = 0;
	u_char buf[65535];

	if (argc <= 1){
		fprintf(stderr, "Usage: httpMonitor device_name\n");
		return (1);
	}

	if ((soc = init_raw_socket(argv[1])) == -1){
		fprintf(stderr, "ERROR: cannot initialize device: %s\n", argv[1]);
		return (-1);
	}

	while (true){
		if ((size = read(soc, buf, sizeof(buf))) <= 0){
			perror("read buf");
		}
		else{
			analyze_packet(buf, size);
		}
	}
	close(soc);
	return (0);
}