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


struct cstruct1 {
	uint16_t x;
	uint16_t y;
};

uint32_t cstruct1_sizeof(const void* struc) {
	return 4;
}

void* cstruct1_ser(void* dst, const void* in) {
	const struct cstruct1* struc;
	uint16_t *out;
	out = dst;
	struc = in;
	out[0] = struc->x;
	out[1] = struc->y;
	return ((uint8_t*)dst)+4;
}

const void* cstruct1_deser(void* dst, const void* src, uint32_t max_size) {
	struct cstruct1* dsts;
	const uint16_t* srcs;
	printf("I was called\n");
	if (max_size < 4) {
		return NULL;
	}
	srcs = src;
	dsts = dst;
	dsts->x = srcs[0];
	dsts->y = srcs[1];
	return ((uint8_t*)src)+4;
}



int main(void) {

	struct mmdp_custom_struct c_structs[1];

	struct mmdp_serverside_config s_config;

	struct struct1 s1;
	struct struct1 s1_2;
	struct struct2 s2;
	struct struct2 arr_s2[2];
	struct cstruct1 arr_cs1[2];
	struct cstruct1 cs1;

	int i;
	

	struct sockaddr_in address;
	int server_fd, new_socket;
	int opt;
	socklen_t addrlen = sizeof(address);
	
	c_structs[0]._real_name = "cstruct1";
	c_structs[0]._size = sizeof(struct cstruct1);
	c_structs[0].net_name = "cstruct1";
	c_structs[0].flags = MMDP_IS_ESSENTIAL;
	c_structs[0].ser_func = &cstruct1_ser;
	c_structs[0].deser_func = &cstruct1_deser;
	c_structs[0].sizeof_func = &cstruct1_sizeof;
	
	init_mmdp_lib(1, c_structs, 1);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	opt=1;
	if (setsockopt(server_fd, SOL_SOCKET,
		SO_REUSEADDR | SO_REUSEPORT, &opt,
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
		printf("FUCK ME SIDEWAYS PLS\n");
		return 0;
	}
	s1.norm = 2;

	s2.norm = 5;
	s1.structure = &s2;

	cs1.x = 0xabcd;
	cs1.y = 0xefab;
	s1.structure2 = &cs1;

	s1.arr = malloc(sizeof(int32_t)*2);
	s1.arr[0] = 8;
	s1.arr[1] = 0xDEADF00D;

	arr_s2[0].norm = 1;
	arr_s2[1].norm = 2;
	s1.struct_arr = arr_s2;

	arr_cs1[0].x = 3;
	arr_cs1[0].y = 4;
	arr_cs1[1].x = 0xfffe;
	arr_cs1[1].y = 0xf00d;
	s1.struct_arr2 = arr_cs1;

	if (send_struct_server(&s_config, MMDP_struct1, new_socket, &s1, NULL) != 0) {
		printf("PLS DONT LEAVE MEEEEEEEE\n");
		return 0;
	}
	if (recv_struct_server(&s_config, MMDP_struct1, new_socket, &s1_2, NULL) != 0) {
		printf("PLS DONT LEAVE MEEEEEEEE 2\n");
		return 0;
	}
	printf("s1_2.norm: %u\n", s1_2.norm);
	printf("s1_2.structure->norm: %u\n", s1_2.structure->norm);
	printf("s1_2.structure2->x: %x\n", s1_2.structure2->x);
	printf("s1_2.structure2->y: %x\n", s1_2.structure2->y);
	for (i=0;i<s1_2.norm;i++) {
		printf("s1_2.arr[%d]: %x\n",i,s1_2.arr[i]);
	}
	for (i=0;i<s1_2.norm;i++) {
		printf("s1_2.s1_2.struct_arr[%d].norm: %x\n",i,s1_2.struct_arr[i].norm);
	}
	for (i=0;i<s1_2.norm;i++) {
		printf("s1_2.s1_2.struct_arr2[%d].x: %x\n",i,s1_2.struct_arr2[i].x);
		printf("s1_2.s1_2.struct_arr2[%d].y: %x\n",i,s1_2.struct_arr2[i].y);
	}
	
	
	
	
	printf("here4\n");

	return 0;
}
