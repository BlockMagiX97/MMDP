#ifndef MMDP_SERIALIZE_H
#define MMDP_SERIALIZE_H
#include <stdint.h>
#include "mmdp.h"

int send_struct_server(struct mmdp_serverside_config* config, int fd, uint32_t id, void* src);
void* recv_strcut_server_any(struct mmdp_serverside_config* config, int fd, void* src, uint32_t);

int send_struct_client(struct mmdp_clientside_config* config, int fd, uint32_t id, void* src);
int recv_struct_client(struct mmdp_clientside_config* config, int fd, uint32_t id, void* dst);

#endif
