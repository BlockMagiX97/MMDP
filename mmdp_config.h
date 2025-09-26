#ifndef MMDP_CONFIG_H
#define MMDP_CONFIG_H


#include <stdint.h>
#include <stddef.h>
#include "mmdp_macro_utils.h"
	/* struct_name, is_essential, net_id */
#define MMDP_STRUCTS(_F) \
	_F(struct_a, 1           , "struct_a") \
	_F(struct_b, 1           , "struct_b")
	
	/* type, is_essential, keyword, var_type, var_name, net_id, depends_on, "_parent_struct" */
	/* the last argument is to have a way to pass arguments to offsetof */

#define MMDP_FIELDS_struct_a(_F, _parent_struct) \
	_F(MMDP_NORMAL, 1, MMDP_EMPTY, uint32_t, msg_len, "msg_len", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_ARRAY, 1, MMDP_EMPTY, char, msg, "msg", msg_len, _parent_struct) \
	_F(MMDP_STRUCT, 1, struct, struct_b, b, "b", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_STRUCT, 1, MMDP_EMPTY, time_t, time, "time", MMDP_EMPTY, _parent_struct)

#define MMDP_FIELDS_struct_b(_F, _parent_struct) \
	_F(MMDP_NORMAL, 1, MMDP_EMPTY, uint32_t, c, "c", MMDP_EMPTY, _parent_struct)

	/* keyword, type_name, is_essential, net_id, ser_sizeof_func, ser_func, deser_func, free_func */
#define MMDP_CUSTOM_STRUCTS(_F) \
	_F(MMDP_EMPTY, time_t, 1, "time_t_cust", ser_sizeof_time, ser_time, deser_time, free_time) \

#endif
