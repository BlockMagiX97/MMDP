#ifndef MMDP_SERVER_H
#define MMDP_SERVER_H
#include "mmdp.h"
struct mmdp_server_config {
	uint8_t *struct_mask;
	uint8_t **field_mask;
};
void *serialize_capability(uint32_t *size_out, struct mmdp_capability *cap);
int serverside_from_ser(struct mmdp_server_config *sconfig, void *serialized_sconfig, uint32_t max_size);

uint32_t sizeof_ser_struct_server(struct mmdp_server_config *config, uint32_t id, const void *src);
void *ser_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, const void *src);
const void *deser_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, const void *src,
				uint32_t max_size);
void free_struct_server(struct mmdp_server_config *config, uint32_t id, void *struc);

int send_struct_server(struct mmdp_server_config *config, uint32_t id, uint32_t fd, const void *src,
		       void *write_context);
int recv_struct_server(struct mmdp_server_config *config, uint32_t id, uint32_t fd, void *dest, void *read_context);
void *recv_struct_server_any(struct mmdp_server_config *config, uint32_t *out_id, uint32_t fd, void *read_context);

int init_connection_config_server(int fd, struct mmdp_server_config *conf_dest, void *write_context,
				  void *read_context);
void free_server_config(struct mmdp_server_config *config);
#endif
