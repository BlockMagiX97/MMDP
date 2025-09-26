#include "mmdp-client.h"
#include "mmdp.h"
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

uint32_t ser_sizeof_time(const void *_) { return sizeof(time_t); }
void *ser_time(void *dst, const void *struc) {
	memcpy(dst, struc, sizeof(time_t));
	return (uint8_t *)struc + sizeof(time_t);
}
const void *deser_time(void *dst, const void *src, uint32_t max) {
	if (max < sizeof(time_t)) {
		return NULL;
	}
	memcpy(dst, src, sizeof(time_t));
	return (uint8_t *)src + sizeof(time_t);
}
void free_time(void *struc) { return; }
void print_struct_a(const struct struct_a *a) {
	if (a == NULL) {
		printf("struct_a is NULL\n");
		return;
	}

	printf("Message Length: %u\n", a->msg_len);
	printf("Message: %s\n", a->msg);

	if (a->b != NULL) {
		printf("struct_b.c: %x\n", a->b->c);
	} else {
		printf("struct_b is NULL\n");
	}

	if (a->time != NULL) {
		printf("Time: %lx\n", (long)(*a->time));
	} else {
		printf("Time is NULL\n");
	}
}
int main() {
	int sock;
	struct sockaddr_in server_addr;
	struct mmdp_client_config config;
	time_t time_recv;
	struct struct_a a;

	init_mmdp_lib();

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Socket creation failed");
		return 1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(4444);
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Connection failed");
		close(sock);
		return 1;
	}
	if (init_connection_config_client(sock, &config, NULL, NULL) != 0) {
		printf("Unable to init connection\n");
		return 0;
	}
	recv_struct_client(&config, MMDP_time_t, sock, &time_recv, NULL);
	printf("time: %lx\n", time_recv);
	recv_struct_client(&config, MMDP_struct_a, sock, &a, NULL);
	print_struct_a(&a);

	return 0;
}
