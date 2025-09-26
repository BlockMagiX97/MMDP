#ifndef MMDP_H
#define MMDP_H

#define DEBUG

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "mmdp_macro_utils.h"

#include "mmdp_config.h"
#include "mmdp_struct_decl.h"

#define MMDP_CUSTOM_FUNC_DECL(_, __, ___, ____, sizeof_func, ser_func, deser_func, free_func) \
	uint32_t sizeof_func(const void *); \
	void *ser_func(void *, const void *); \
	const void *deser_func(void *, const void *, uint32_t); \
	void free_func(void *);
MMDP_CUSTOM_STRUCTS(MMDP_CUSTOM_FUNC_DECL)

typedef uint8_t mmdp_struct_flags;
enum _mmdp_struct_flags {
	MMDP_IS_ESSENTIAL=1
};

typedef uint8_t mmdp_field_flags;
enum _mmdp_field_flags {
	MMDP_FIELD_IS_ESSENTIAL=1
};

/* don't reorder */
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
		} normal;
		struct {
			uint32_t id;
		} struc;
		struct {
			uint32_t size;
			uint32_t depends_id;
		} array;
		struct {
			/* sizeof the struct */
			uint32_t id;
			uint32_t depends_id;
		} struct_array;
	} body;
};

struct mmdp_struct {
	/* sizeof this struct */
	uint32_t _size;

	const char* net_name;
	mmdp_struct_flags flags;

	uint32_t fields_num;
	struct mmdp_field* fields;
};

struct mmdp_custom_struct {
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
	/* should free buffers allocated inside structure */
	/* if no frees are necessary set to NULL */
	void (*free_func)(void*);
};

struct mmdp_capability{
	uint32_t mmdp_struct_num;
	struct mmdp_struct* mmdp_structs;

	uint32_t custom_struct_num;
	struct mmdp_custom_struct* custom_structs;
};

extern struct mmdp_capability mmdp_capability;
extern uint32_t hard_limit_pre_conn;
extern uint32_t hard_limit_post_conn;

void swap_bytes_little(void *pv, size_t n);
ssize_t mmdp_read(int fd, void *buf, size_t count, void *read_context);
ssize_t mmdp_write(int fd, void *buf, size_t count, void *write_context);
	
/* free the capability received over the network */
void free_capability_heap(struct mmdp_capability *cap);
void print_capability(struct mmdp_capability* mmdp_capability);
/* is NOT thread-safe */
int init_mmdp_lib();

#endif
