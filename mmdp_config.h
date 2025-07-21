#ifndef MMDP_CONFIG_H
#define MMDP_CONFIG_H


#include <stdint.h>
#include <stddef.h>
#include "mmdp_macro_utils.h"
	/* struct_name, is_essential, net_id */
#define MMDP_STRUCTS(_F) \
	_F(msg_struct, 1           , "msg_str")
	
	/* type, is_essential, var_type, var_name, net_id, depends_on, "_parent_struct" */
	/* the last argument is to have a way to pass arguments to offsetof */
	/* in case of MMDP_STRUCT omit the "struct" keyword */

#define MMDP_FIELDS_msg_struct(_F, _parent_struct) \
	_F(MMDP_NORMAL, 1, uint32_t, msg_len, "msg_len", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_ARRAY, 1, char, msg, "msg", msg_len, _parent_struct)


#endif
