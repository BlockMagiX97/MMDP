#include <stddef.h>
#include <assert.h>
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || \
    defined(__THUMBEB__) || \
    defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
// It's a big-endian target architecture
void swap_bytes_little(void *pv, size_t n) {
	/* already big-endian do nothing */
	return;
}
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
// It's a little-endian target architecture
void swap_bytes_little(void *pv, size_t n) {
    assert(n > 0);

    char *p = pv;
    size_t lo, hi;
    for(lo=0, hi=n-1; hi>lo; lo++, hi--)
    {
        char tmp=p[lo];
        p[lo] = p[hi];
        p[hi] = tmp;
    }
}
#else
#error "FATAL: Unable to get endianness of a machine"
#endif


uint32_t sizeof_ser_struct_server(struct mmdp_serverside_config* config, uint32_t id, void* src) {
	uint32_t size;
	uint32_t i, j;
	struct mmdp_struct* curr_struct;
	struct mmdp_field* curr_field;
	uint32_t struct_size;
	uint32_t offset;
	size=0;
	if (id < mmdp_capability.mmdp_struct_num) {
		curr_struct = mmdp_capability.mmdp_structs+id;
		for (i=0;i<curr_struct->fields_num;i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			curr_field = curr_struct->fields+i;
			switch (curr_field->type) {
				case MMDP_NORMAL:
					size += curr_field->body.normal.size;
					break;
				case MMDP_STRUCT:
					size += sizeof_ser_struct_server(config, curr_field->body.struc.id, *((void**)(((uint8_t*)src)+curr_field->offset)));
					break;
				case MMDP_ARRAY:
					size += curr_field->body.array.size * (*((uint32_t*)(((uint8_t*)src)+curr_struct->fields[curr_field->body.array.depends_id].offset)));
					break;
				case MMDP_STRUCT_ARRAY:
					offset = 0;
					if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
						struct_size = mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
					} else if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num+mmdp_capability.custom_struct_num) {
						struct_size = mmdp_capability.custom_structs[curr_field->body.struct_array.id-mmdp_capability.custom_struct_num]._size;
					} else {
						#ifdef DEBUG
							printf("SOMETHINGS WRONG, I CAN FEEL IT\n");
						#endif
						return 0;
					}
					for (j=0;j<*((uint32_t*)(((uint8_t*)src)+(curr_struct->fields[curr_field->body.struct_array.depends_id].offset)));j++) {
						size += sizeof_ser_struct_server(config, curr_field->body.struct_array.id, (*((uint8_t**)(((uint8_t*)src)+curr_field->offset)))+offset);
						offset += struct_size;
					}
					break;
			}
		}
	} else if (id < mmdp_capability.mmdp_struct_num+mmdp_capability.custom_struct_num){
		size = mmdp_capability.custom_structs[id-mmdp_capability.mmdp_struct_num].sizeof_func(src);
	}
	
	return size;
}
void* ser_struct_server(struct mmdp_serverside_config* config, uint32_t id, void* src, uint32_t* ser_size) {
	void* ser_struct;
	uint8_t* ptr;
	uint32_t i, j;
	struct mmdp_struct* curr_struct;
	struct mmdp_field* curr_field;
	uint32_t struct_size;
	uint32_t offset;

	void* tmp_ser_struct;
	uint32_t size;


	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		/* 4 bytes for id */
		*ser_size = 4+sizeof_ser_struct_server(config, id, src);
		ser_struct = malloc(*ser_size);
		if (ser_struct == NULL) {
			perror("malloc");
			return NULL;
		}
		memset(ser_struct, 0, *ser_size);
		ptr = ser_struct;
		*((uint32_t*)ptr) = htonl(id);
		ptr+=4;
		curr_struct = mmdp_capability.mmdp_structs+id;
		for (i=0;i<curr_struct->fields_num;i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			curr_field = curr_struct->fields+i;
			switch (curr_field->type) {
				case MMDP_NORMAL:
					memcpy(ptr, ((uint8_t*)src)+curr_field->offset, curr_field->body.normal.size);
					ptr += curr_field->body.normal.size;
					break;
				case MMDP_STRUCT:
					tmp_ser_struct = ser_struct_server(config, curr_field->body.struc.id, *((void**)(((uint8_t*)src)+curr_field->offset)), &size);
					if (tmp_ser_struct == NULL) {
						#ifdef DEBUG
							printf("unable to serialize struct\n");
						#endif
						return NULL;
					}
					memcpy(ptr, tmp_ser_struct, size);
					ptr += size;
					break;
				case MMDP_ARRAY:
					size += curr_field->body.array.size * (*((uint32_t*)(((uint8_t*)src)+curr_struct->fields[curr_field->body.array.depends_id].offset)));
					break;
				case MMDP_STRUCT_ARRAY:
					offset = 0;
					if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
						struct_size = mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
					} else if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num+mmdp_capability.custom_struct_num) {
						struct_size = mmdp_capability.custom_structs[curr_field->body.struct_array.id-mmdp_capability.custom_struct_num]._size;
					} else {
						#ifdef DEBUG
							printf("SOMETHINGS WRONG, I CAN FEEL IT\n");
						#endif
						return 0;
					}
					for (j=0;j<*((uint32_t*)(((uint8_t*)src)+(curr_struct->fields[curr_field->body.struct_array.depends_id].offset)));j++) {
						size += sizeof_ser_struct_server(config, curr_field->body.struct_array.id, (*((uint8_t**)(((uint8_t*)src)+curr_field->offset)))+offset);
						offset += struct_size;
					}
					break;
			}
		}
		

	} else if (id < mmdp_capability.mmdp_struct_num+mmdp_capability.custom_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		*ser_size = 4+mmdp_capability.custom_structs[id-mmdp_capability.mmdp_struct_num].sizeof_func(src);
		ser_struct = malloc(*ser_size);
		if (ser_struct == NULL) {
			perror("malloc");
			return NULL;
		}
		memset(ser_struct, 0, *ser_size);
		ptr = ser_struct;

		*((uint32_t*)ptr) = htonl(id);
		ptr+=4;
		

	}
	return NULL;
}
void* deser_strcut_server_any(struct mmdp_serverside_config* config, int fd, void* src, uint32_t);

int ser_struct_client(struct mmdp_clientside_config* config, int fd, uint32_t id, void* src);
int deser_struct_client(struct mmdp_clientside_config* config, int fd, uint32_t id, void* dst);
