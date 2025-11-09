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

int send_struct_server(struct mmdp_server_config *config, uint32_t id, const void *src,
		       void *write_context);
int recv_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, void *read_context);
void *recv_struct_server_any(struct mmdp_server_config *config, uint32_t *out_id, void *read_context);

int init_connection_config_server(struct mmdp_server_config *conf_dest, void *write_context,
				  void *read_context);
void free_server_config(struct mmdp_server_config *config);
int is_struct_active_server(const struct mmdp_server_config *config, enum mmdp_structs id);
int is_field_active_server(const struct mmdp_server_config *config, enum mmdp_structs id, uint32_t field_id);

/* is a compile time check if that struct has that field */
#define IS_FIELD_ACTIVE_SERVER(config, struc, field) \
	(is_field_active_server((config), MMDP_##struc, MMDPFIELD_##struc##_##field))
#define IS_STRUCT_ACTIVE_SERVER(config, struc) \
	(is_struct_active_server((config), MMDP_##struc))
#endif
