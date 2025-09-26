#ifndef MMDP_STRUCT_DECL_H
#define MMDP_STRUCT_DECL_H

/* auto struct declaration */
#define MMDP_MAKE_STRUCT_DECL(name, is_essential, net_id) \
	struct name;

/* auto struct definition */
#define MMDP_MAKE_STRUCT_DEF(name, is_essential, net_id) \
	struct name { \
		MMDP_FIELDS_##name(MMDP_MAKE_FIELD_DEF, name) \
	};

#define MMDP_MAKE_FIELD_DEF(type, is_essential, keyword, var_type, var_name, net_id, depends_on, _parent_struct) \
	MMDP_MAKE_FIELD_DEF_##type(var_type, keyword, var_name)

#define MMDP_MAKE_FIELD_DEF_MMDP_NORMAL(var_type, keyword, var_name) \
	var_type var_name;
	
#define MMDP_MAKE_FIELD_DEF_MMDP_STRUCT(var_type, keyword, var_name) \
	keyword var_type * var_name;

#define MMDP_MAKE_FIELD_DEF_MMDP_ARRAY(var_type, keyword, var_name) \
	var_type * var_name;

#define MMDP_MAKE_FIELD_DEF_MMDP_STRUCT_ARRAY(var_type, keyword, var_name) \
	keyword var_type * var_name;

#define MMDP_MAKE_ENUM_DEF(name, is_essential, net_id) \
	MMDP_##name ,

#define MMDP_CUSTOM_MAKE_ENUM_DEF(keyword, name, _, __, ___, ____, _____, ______) \
	MMDP_##name ,


MMDP_STRUCTS(MMDP_MAKE_STRUCT_DECL)
MMDP_STRUCTS(MMDP_MAKE_STRUCT_DEF)

enum mmdp_structs {
	MMDP_STRUCTS(MMDP_MAKE_ENUM_DEF)
	MMDP_CUSTOM_STRUCTS(MMDP_CUSTOM_MAKE_ENUM_DEF)
	MMDP_ANY=-1
};



#endif
