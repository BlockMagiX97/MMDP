#ifndef MMDP_H
#define MMDP_H

#define DEBUG

#include <stdint.h>
#include <stddef.h>
#include "mmdp_macro_utils.h"

#include "mmdp_config.h"
#include "mmdp_struct_decl.h"






typedef uint8_t mmdp_struct_flags;
enum _mmdp_struct_flags {
	MMDP_IS_ESSENTIAL=1
};

typedef uint8_t mmdp_field_flags;
enum _mmdp_field_flags {
	MMDP_FIELD_IS_ESSENTIAL=1
};
/* don't change for backward compatibility */
typedef uint8_t mmdp_field_type;
enum _mmdp_field_type {
	MMDP_NORMAL=0,
	MMDP_STRUCT=1,
	MMDP_ARRAY=2,
	MMDP_STRUCT_ARRAY=3
};

struct mmdp_field {
	const char* net_name;
	mmdp_field_type type;
	mmdp_field_flags flags;
	size_t offset;
	union {
		struct {
			uint32_t size;
			const char* _name;
		} normal;
		struct {
			uint32_t id;
			const char* _name;
		} struc;
		struct {
			uint32_t size;
			uint32_t depends_id;
			const char* _depends_name;
		} array;
		struct {
			/* sizeof the struct */
			uint32_t id;
			const char* _name;
			uint32_t depends_id;
			const char* _depends_name;
		} struct_array;
	} body;
};

struct mmdp_struct {
	const char* _real_name;
	/* sizeof this struct */
	uint32_t _size;

	const char* net_name;
	mmdp_struct_flags flags;

	uint32_t fields_num;
	struct mmdp_field* fields;
};

struct mmdp_custom_struct {
	/* real name (struct ${_real_name}). it is used so that library defined structs can interact with it. is NOT sent over the network */
	const char* _real_name;
	/* sizeof this struct */
	uint32_t _size;

	const char* net_name;
	mmdp_struct_flags flags;

	/* this function returns serialized size */
	uint32_t (*sizeof_func)(const void*);
	/* this function must ptr pointing to byte AFTER last byte */
	/* parameter1 is pointer to dst*/
	/* parameter2 is pointer to struct */
	void* (*ser_func)(void*, const void*);
	/* returns pointer to byte AFTER last byte of serialized struct */
	/* parameter1 is destination */
	/* parameter2 is pointer to serealized struct by ser_func */
	/* paramater3 is a maximum size that deser_func can read */
	const void* (*deser_func)(void*, const void*, uint32_t);
};

struct mmdp_capability{
	uint32_t mmdp_struct_num;
	struct mmdp_struct* mmdp_structs;

	uint32_t custom_struct_num;
	struct mmdp_custom_struct* custom_structs;
};

struct mmdp_serverside_config {
	uint8_t* struct_mask;
	uint8_t** field_mask;
};
struct mmdp_clientside_config {
	uint32_t* c_to_s_struct_remap;
	uint32_t** field_order;

	uint32_t s_mmdp_struct_num;
	uint32_t s_custom_struct_num;
	/* has size of max_s_struct_id * 4 */
	uint32_t* s_to_c_struct_remap;
};


extern struct mmdp_capability mmdp_capability;
extern uint32_t hard_limit_pre_conn;
extern uint32_t hard_limit_post_conn;


int generate_capability(uint32_t c_struct_num, struct mmdp_custom_struct* c_structs);
void* serialize_capability(uint32_t* size_out);
int deserialize_capability(const void* buf, uint32_t size, struct mmdp_capability* out);
int create_clientside_config(const struct mmdp_capability* srv_cap, struct mmdp_clientside_config* out);
void* convert_clientside_to_serealized_serverside(const struct mmdp_clientside_config *cconfig, uint32_t* out_size);
int serverside_from_ser(struct mmdp_serverside_config* sconfig, void* serialized_sconfig, uint32_t max_size);

void print_capability(struct mmdp_capability* mmdp_capability);

uint32_t sizeof_ser_struct_server(struct mmdp_serverside_config* config, uint32_t id, const void* src);
void* ser_struct_server(struct mmdp_serverside_config* config, uint32_t id, void* dest, const void* src);
const void* deser_struct_server(struct mmdp_serverside_config* config, uint32_t id, void* dest, const void* src, uint32_t max_size);

uint32_t sizeof_ser_struct_client(struct mmdp_clientside_config* config, uint32_t id, const void* src);
void* ser_struct_client(struct mmdp_clientside_config* config, uint32_t id, void* dest, const void* src);
const void* deser_struct_client(struct mmdp_clientside_config* config, uint32_t id, void* dest, const void* src, uint32_t max_size);


int send_struct_server(struct mmdp_serverside_config* config, uint32_t id, uint32_t fd, const void* src, void* write_context);
int recv_struct_server(struct mmdp_serverside_config* config, uint32_t id, uint32_t fd, void* dest, void* read_context);
void* recv_struct_server_any(struct mmdp_serverside_config* config, uint32_t* out_id, uint32_t fd, void* read_context);

int send_struct_client(struct mmdp_clientside_config* config, uint32_t id, uint32_t fd, const void* src, void* write_context);
int recv_struct_client(struct mmdp_clientside_config* config, uint32_t id, uint32_t fd, void* dest, void* read_context);
void* recv_struct_client_any(struct mmdp_clientside_config* config, uint32_t* out_id, uint32_t fd, void* read_context);



int init_connection_config_server(int fd, struct mmdp_serverside_config* conf_dest, void* write_context, void* read_context);
int init_connection_config_client(int fd, struct mmdp_clientside_config* conf_dest, void* write_context, void* read_context);

/* is NOT thread-safe */
int init_mmdp_lib(uint32_t c_struct_num, struct mmdp_custom_struct* c_structs, int is_server);

void free_server_config(struct mmdp_serverside_config* config);
void free_client_config(struct mmdp_clientside_config* config);
#endif
