#include <common/mmdp.h>
#include <server/mmdp-server.h>
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

/* time */
#include <time.h>

uint32_t ser_sizeof_time(const void *_) {
	printf("here0\n");
	return sizeof(time_t); }
void *ser_time(void *dst, const void *struc) {
	printf("here1\n");
	return ((uint8_t *)(memcpy(dst, struc, sizeof(time_t))) + sizeof(time_t));
}
const void *deser_time(void *dst, const void *src, uint32_t max) {
	printf("here2\n");
	if (max < sizeof(time_t)) {
		return NULL;
	}
	return ((uint8_t *)(memcpy(dst, src, sizeof(time_t))) + sizeof(time_t));
}
void free_time(void *struc) {
	printf("here3\n");
	return;
}


int main(void) {
	struct mmdp_server_config s_config;

	struct sockaddr_in address;
	int server_fd, new_socket;
	int opt;
	socklen_t addrlen = sizeof(address);
	struct struct_a a;
	struct struct_b b;
	time_t time_send;
	
	init_mmdp_lib();

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
	address.sin_port = htons(4444);

	if (bind(server_fd, (struct sockaddr*)&address,
	  sizeof(address))
		< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0) {
		perror("listen"); exit(EXIT_FAILURE); }
	if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	/* server */
	if (init_connection_config_server(&s_config, &new_socket, &new_socket) != 0) {
		printf("Unable to init connection\n");
		return 0;
	}
	printf("%d\n", MMDP_time_t);
	
	b.c =0xdeadbeef;
	a.msg = "Hello from server using MMDP\n";
	a.msg_len = strlen(a.msg);
	a.b = &b;
	a.time = &time_send;
	time_send = time(NULL);
	printf("time: %lx\n", time_send);
	send_struct_server(&s_config, MMDP_time_t, &time_send, &new_socket);
	printf("time: %lx\n", time_send);
	send_struct_server(&s_config, MMDP_struct_a, &a, &new_socket);
	

	printf("SUCCESS\n");
	free_server_config(&s_config);
	return 0;
}
