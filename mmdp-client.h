#ifndef MMDP_CLIENT_H
#define MMDP_CLIENT_H
#include "mmdp.h"

struct mmdp_client_config {
	uint32_t *c_to_s_struct_remap;
	uint32_t **field_order;

	uint32_t s_mmdp_struct_num;
	uint32_t s_custom_struct_num;

	uint32_t *s_to_c_struct_remap;
};


int deserialize_capability(const void *buf, uint32_t size, struct mmdp_capability *out);
int create_clientside_config(const struct mmdp_capability *srv_cap, struct mmdp_client_config *out);
void *convert_clientside_to_serealized_serverside(const struct mmdp_client_config *cconfig, uint32_t *out_size);


uint32_t sizeof_ser_struct_client(struct mmdp_client_config *config, uint32_t id, const void *src);
void *ser_struct_client(struct mmdp_client_config *config, uint32_t id, void *dest, const void *src);
const void *deser_struct_client(struct mmdp_client_config *config, uint32_t id, void *dest, const void *src,
				uint32_t max_size);
void free_struct_client(struct mmdp_client_config *config, uint32_t id, void *struc);


int send_struct_client(struct mmdp_client_config *config, uint32_t id, uint32_t fd, const void *src,
		       void *write_context);
int recv_struct_client(struct mmdp_client_config *config, uint32_t id, uint32_t fd, void *dest, void *read_context);
void *recv_struct_client_any(struct mmdp_client_config *config, uint32_t *out_id, uint32_t fd, void *read_context);

int init_connection_config_client(int fd, struct mmdp_client_config *conf_dest, void *write_context,
				  void *read_context);

void free_client_config(struct mmdp_client_config *config);
#endif
