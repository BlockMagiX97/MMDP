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
	struct mmdp_serverside_config s_config;

	struct sockaddr_in address;
	int server_fd, new_socket;
	int opt;
	socklen_t addrlen = sizeof(address);
	struct msg_struct msg;
	char buffer[256];
	
	init_mmdp_lib(0, NULL, 1);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	opt=1;
	if (setsockopt(server_fd, SOL_SOCKET,
		SO_REUSEADDR, &opt,
		sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(8081);

	if (bind(server_fd, (struct sockaddr*)&address,
	  sizeof(address))
		< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	/* server */
	if (init_connection_config_server(new_socket, &s_config, NULL, NULL) != 0) {
		printf("Unable to init connection\n");
		return 0;
	}

	

	printf("send: ");
	fflush(stdout);

	fgets(buffer, 256, stdin);
	msg.msg = buffer; 
	msg.msg_len = strlen(msg.msg);
	if (send_struct_server(&s_config, MMDP_msg_struct, new_socket, &msg, NULL) != 0) {
		printf("Never gonna give you up\n");
		return 0;
	}

	if (recv_struct_server(&s_config, MMDP_msg_struct, new_socket, &msg, NULL) != 0) {
		printf("Never gonna let you down\n");
		return 0;
	}

	printf("recieved: %s\n", msg.msg);
	free(msg.msg);
	free_server_config(&s_config);
	return 0;
}
