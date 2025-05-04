#ifndef MMDP_CONFIG_H
#define MMDP_CONFIG_H


#include <stdint.h>
#include <stddef.h>
#include "mmdp_macro_utils.h"

struct cstruct1 {
	uint16_t x;
	uint16_t y;
};

	/* struct_name, is_essential, net_id */
#define MMDP_STRUCTS(_F) \
	_F(struct1    , 1           , "struct1") \
	_F(struct2    , 0           , "struct2")

	
	/* type, is_essential, var_type, var_name, net_id, depends_on, "_parent_struct" */
	/* the last argument is to have a way to pass arguments to offsetof */
	/* in case of MMDP_STRUCT omit the "struct" keyword */
#define MMDP_FIELDS_struct1(_F, _parent_struct) \
	_F(MMDP_NORMAL, 1, uint32_t, norm, "normal", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_STRUCT, 1, struct2, structure, "structure", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_STRUCT, 1, cstruct1, structure2, "structure2", MMDP_EMPTY, _parent_struct) \
	_F(MMDP_ARRAY, 1, int32_t, arr, "arr", norm, _parent_struct) \
	_F(MMDP_STRUCT_ARRAY, 1, struct2, struct_arr, "struct_arr", norm, _parent_struct) \
	_F(MMDP_STRUCT_ARRAY, 1, cstruct1, struct_arr2, "struct_arr2", norm, _parent_struct)

#define MMDP_FIELDS_struct2(_F, _parent_struct) \
	_F(MMDP_NORMAL, 1, uint32_t, norm, "norm", MMDP_EMPTY, _parent_struct)
	


#endif
