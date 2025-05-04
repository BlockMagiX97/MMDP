#include "mmdp.h"
#include <stdio.h>
#include <stdlib.h>
/* perror and errno */
#include <errno.h>
/* networking */
#include <sys/socket.h>
#include <netinet/in.h>


void* cstruct1_ser(void* in, uint32_t* size_out) {
	struct cstruct1* struc;
	uint16_t *out;
	struc = in;
	out = malloc(sizeof(uint16_t)*2);
	*size_out = sizeof(uint16_t)*2;
	out[0] = struc->x;
	out[1] = struc->y;
	return out;
}

void* cstruct1_deser(void* in, uint32_t max_size) {
	struct cstruct1* struc;
	uint16_t *in16;
	in16 = in;
	struc = malloc(sizeof(struct cstruct1));
	struc->x = in16[0];
	struc->y = in16[1];
	return struc;
}



int main(void) {

	struct mmdp_custom_struct c_structs[1];

	const void* ser_capability;
	void* ser_ssconfig;
	uint32_t sizeof_ser_capability;
	uint32_t sizeof_ser_serverside;
	struct mmdp_capability deser_capability;
	struct mmdp_clientside_config c_config;
	struct mmdp_serverside_config s_config;

	c_structs[0]._real_name = "cstruct1";
	c_structs[0].net_name = "cstruct1";
	c_structs[0].flags = MMDP_IS_ESSENTIAL;
	c_structs[0].ser_func = &cstruct1_ser;
	c_structs[0].deser_func = &cstruct1_deser;

	/* server */
	generate_capability(1, c_structs);
	ser_capability= serialize_capability(&sizeof_ser_capability);
	/* client */
	deserialize_capability(ser_capability, sizeof_ser_capability, &deser_capability);
	create_clientside_config(&deser_capability, &c_config);

	printf("here1\n");
	ser_ssconfig = convert_clientside_to_serealized_serverside(&c_config, &sizeof_ser_serverside);
	printf("here2\n");
	serverside_from_ser(&s_config, ser_ssconfig, sizeof_ser_serverside);
	printf("here3\n");
	
	

	return 0;
}
