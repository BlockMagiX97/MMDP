#include "mmdp.h"
#include <stdio.h>
#include <stdlib.h>
/* perror and errno */
#include <errno.h>
/* networking */
#include <sys/socket.h>
#include <netinet/in.h>

/* testlogin */
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

int main(void) {


	struct mmdp_clientside_config c_config;

	struct sockaddr_in address;
	int server_fd;
	char buffer[256];
	struct msg_struct msg;
	
	init_mmdp_lib(0, NULL, 1);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(8081);

	if (connect(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (init_connection_config_client(server_fd, &c_config, NULL, NULL) != 0) {
		printf("Unable to init connection\n");
		return 0;
	}

	
	
	printf("send: ");
	fflush(stdout);
	fgets(buffer, 256, stdin);
	msg.msg = buffer;
	msg.msg_len = strlen(msg.msg);

	if (send_struct_client(&c_config, MMDP_msg_struct, server_fd, &msg, NULL) != 0) {
		printf("What is love\n");
		return 0;
	}
	if (recv_struct_client(&c_config, MMDP_msg_struct, server_fd, &msg, NULL) != 0) {
		printf("Baby don't hurt me, don't hurt me, no more\n");
		return 0;
	}

	msg.msg[msg.msg_len-1] = 0;
	printf("recieved: %s\n", msg.msg);
	free(msg.msg);
	free_client_config(&c_config);
	return 0;
}
