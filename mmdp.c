#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mmdp.h"
#include "string_helper.h"

#include <assert.h>
#include <stddef.h>

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || defined(__BIG_ENDIAN__) || defined(__ARMEB__) ||          \
    defined(__THUMBEB__) || defined(__AARCH64EB__) || defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
/* It's a big-endian target architecture */
void swap_bytes_little(void *pv, size_t n) {
	/* already big-endian do nothing */
	return;
}
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) ||  \
    defined(__THUMBEL__) || defined(__AARCH64EL__) || defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
/* It's a little-endian target architecture */
void swap_bytes_little(void *pv, size_t n) {
	char tmp, *p;
	size_t lo, hi;

	assert(n > 0);
	p = pv;
	for (lo = 0, hi = n - 1; hi > lo; lo++, hi--) {
		tmp = p[lo];
		p[lo] = p[hi];
		p[hi] = tmp;
	}
}
#else
#error "FATAL: Unable to get endianness of a machine"
#endif

struct mmdp_capability mmdp_capability;
/* limits for packet size before and after establishing connection */
uint32_t hard_limit_pre_conn = 1024;	     /* 1kB */
uint32_t hard_limit_post_conn = 1024 * 1024; /* 1MB */
/* used by server connection init */
void *_mmdp_chache_ser_server_cap = NULL;
uint32_t _mmdp_chache_ser_server_cap_size = 0;

/* wrappers so we can implement TLS */
ssize_t mmdp_read(int fd, void *buf, size_t count, void *read_context) {
	size_t log;
	if ((log = read(fd, buf, count)) == count) {
		printf("mmdp_read count: %lu\n", log);
		printf("mmdp_read supposed: %lu\n", count);
		return 0;
	}

	printf("mmdp_read count: %lu\n", log);
	printf("mmdp_read supposed: %lu\n", count);
	return -1;
}
ssize_t mmdp_write(int fd, void *buf, size_t count, void *write_context) {
	size_t log;
	if ((log = write(fd, buf, count)) == count) {
		printf("mmdp_write count: %lu\n", log);
		printf("mmdp_write supposed: %lu\n", count);
		return 0;
	}
	printf("mmdp_write count: %lu\n", log);
	printf("mmdp_write supposed: %lu\n", count);
	return -1;
}
#define MMDP_FILOUT_CAP_FIELD(_type, _flags, var_type, var_name, net_id, depends_on, parent_struct) \
	mmdp_capability.mmdp_structs[i].fields[j].net_name = net_id ; \
	mmdp_capability.mmdp_structs[i].fields[j].type = _type ; \
	mmdp_capability.mmdp_structs[i].fields[j].flags = _flags ; \
	mmdp_capability.mmdp_structs[i].fields[j].offset = offsetof(struct parent_struct, var_name ); \
	MMDP_FILOUT_CAP_FIELD_##_type(var_type, var_name, depends_on) \
	j++;

#define MMDP_FILOUT_CAP_FIELD_MMDP_NORMAL(var_type, var_name, depends_on) \
	mmdp_capability.mmdp_structs[i].fields[j].body.normal.size = sizeof( var_type ); \
	mmdp_capability.mmdp_structs[i].fields[j].body.normal._name = #var_name ;

#define MMDP_FILOUT_CAP_FIELD_MMDP_STRUCT(var_type, var_name, depends_on) \
	mmdp_capability.mmdp_structs[i].fields[j].body.struc._name = #var_type ;

#define MMDP_FILOUT_CAP_FIELD_MMDP_ARRAY(var_type, var_name, depends_on) \
	mmdp_capability.mmdp_structs[i].fields[j].body.array._depends_name = #depends_on ; \
	mmdp_capability.mmdp_structs[i].fields[j].body.array.size = sizeof( var_type ) ;

#define MMDP_FILOUT_CAP_FIELD_MMDP_STRUCT_ARRAY(var_type, var_name, depends_on) \
	mmdp_capability.mmdp_structs[i].fields[j].body.struct_array._name = #var_type ; \
	mmdp_capability.mmdp_structs[i].fields[j].body.struct_array._depends_name = #depends_on ;

#define MMDP_FILOUT_CAP_STRUCT(struct_name, is_essential, net_id) \
	mmdp_capability.mmdp_structs[i]._real_name = #struct_name ; \
	mmdp_capability.mmdp_structs[i]._size = sizeof( struct struct_name ); \
	mmdp_capability.mmdp_structs[i].net_name = net_id ; \
	mmdp_capability.mmdp_structs[i].flags = is_essential ; \
	COUNT_2(MMDP_FIELDS_##struct_name, 7, struct_name) ; \
	mmdp_capability.mmdp_structs[i].fields_num = macro_count; \
	mmdp_capability.mmdp_structs[i].fields = malloc(macro_count*sizeof(struct mmdp_field)); \
	if (mmdp_capability.mmdp_structs[i].fields == NULL) { \
		perror("malloc"); \
		while (i>0) { \
			i--; \
			free(mmdp_capability.mmdp_structs[i].fields); \
			mmdp_capability.mmdp_structs[i].fields = NULL; \
		} \
		return -1; \
	} \
	j=0; \
	MMDP_FIELDS_##struct_name(MMDP_FILOUT_CAP_FIELD , struct_name) \
	i++;

int mmdp_field_type_qsort_compar(const void *x, const void *y) {
	/* we use this so we dont have to waste another 16 bytes*/
	return ((struct mmdp_field *)x)->type - ((struct mmdp_field *)y)->type;
}

void print_b8(uint8_t num) {
	int i;
	for (i = sizeof(uint8_t) * 8 - 1; i >= 0; i--) {
		printf("%d", (num >> i) & 1);
		if (i % 4 == 0)
			printf(" "); /* Group by 4 bits for readability */
	}
	printf("\n");
}
void print_b32(uint32_t num) {
	int i;
	for (i = sizeof(uint32_t) * 8 - 1; i >= 0; i--) {
		printf("%d", (num >> i) & 1);
		if (i % 4 == 0)
			printf(" "); /* Group by 4 bits for readability */
	}
	printf("\n");
}
void print_capability(struct mmdp_capability *cap) {
	struct mmdp_struct *c_struct;
	struct mmdp_field *c_field;
	uint32_t i;
	for (c_struct = cap->mmdp_structs; c_struct < (cap->mmdp_structs + cap->mmdp_struct_num); c_struct++) {
		printf("%s (ess: %hx):\n", c_struct->net_name, c_struct->flags);
		for (c_field = c_struct->fields; c_field < c_struct->fields + c_struct->fields_num; c_field++) {

			printf("\t%s (type: %hx, off: %lu) flags: ", c_field->net_name, c_field->type, c_field->offset);
			print_b8(c_field->flags);
			switch (c_field->type) {
			case MMDP_NORMAL:
				printf("\t\tsize: %u\n", c_field->body.normal.size);
				break;
			case MMDP_STRUCT:
				printf("\t\tname: %s, id: %d\n", c_field->body.struc._name, c_field->body.struc.id);
				break;
			case MMDP_ARRAY:
				printf("\t\tdep: %s, dep_id: %d, size: %u\n", c_field->body.array._depends_name,
				       c_field->body.array.depends_id, c_field->body.array.size);
				break;
			case MMDP_STRUCT_ARRAY:
				printf("\t\tname: %s, id: %d, dep: %s, dep_id: "
				       "%d\n",
				       c_field->body.struct_array._name, c_field->body.struct_array.id,
				       c_field->body.struct_array._depends_name, c_field->body.struct_array.depends_id);
				break;
			}
		}
	}
	for (i = 0; i < cap->custom_struct_num; i++) {
		printf("custom: %s\n", cap->custom_structs->net_name);
	}
}

/* free the capability generated by generate_capability */
void free_capability(struct mmdp_capability *cap) {
	uint32_t i;
	for (i = 0; i < cap->mmdp_struct_num; i++) {
		free(cap->mmdp_structs[i].fields);
		cap->mmdp_structs[i].fields = NULL;
	}
	free(cap->mmdp_structs);
	cap->mmdp_structs = NULL;
	/* we cannot free custom_structs since the user provided them to us and
	 * we dont know if it is heap allocated or not*/
	return;
}

/* free the capability received over the network */
void free_capability_heap(struct mmdp_capability *cap) {
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	for (curr_struct = cap->mmdp_structs; curr_struct < cap->mmdp_structs + cap->mmdp_struct_num; curr_struct++) {
		for (curr_field = curr_struct->fields; curr_field < curr_struct->fields + curr_struct->fields_num;
		     curr_field++) {
			free((void *)curr_field->net_name);
			curr_field->net_name = NULL;
		}
		free((void *)curr_struct->net_name);
		curr_struct->net_name = NULL;
		free(curr_struct->fields);
		curr_struct->fields = NULL;
	}
	free(cap->mmdp_structs);
	cap->mmdp_structs = NULL;
	free(cap->custom_structs);
	cap->custom_structs = NULL;
	return;
}
int generate_capability(uint32_t c_struct_num, struct mmdp_custom_struct *c_structs) {
	uint32_t macro_count;
	uint32_t i, j, k;
	struct mmdp_struct *curr_mstruct;
	struct mmdp_field *curr_mfield;
	mmdp_capability.custom_struct_num = c_struct_num;
	mmdp_capability.custom_structs = c_structs;

	COUNT_1(MMDP_STRUCTS, 3);
	mmdp_capability.mmdp_struct_num = macro_count;

	mmdp_capability.mmdp_structs = malloc(mmdp_capability.mmdp_struct_num * sizeof(struct mmdp_struct));
	if (mmdp_capability.mmdp_structs == NULL) {
		perror("malloc");
		return -1;
	}
	i = 0;
	MMDP_STRUCTS(MMDP_FILOUT_CAP_STRUCT);

	/* sort it so that normal fields always go first */
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		qsort(mmdp_capability.mmdp_structs[i].fields, mmdp_capability.mmdp_structs[i].fields_num,
		      sizeof(struct mmdp_field), &mmdp_field_type_qsort_compar);
	}
#ifdef DEBUG
	print_capability(&mmdp_capability);
#endif

	/* fillout depends_id and struct_id (it is impossible to do at compile
	 * time)*/
	for (curr_mstruct = mmdp_capability.mmdp_structs;
	     curr_mstruct < mmdp_capability.mmdp_structs + mmdp_capability.mmdp_struct_num; curr_mstruct++) {
		for (curr_mfield = curr_mstruct->fields; curr_mfield < curr_mstruct->fields + curr_mstruct->fields_num;
		     curr_mfield++) {
			switch (curr_mfield->type) {
			case MMDP_NORMAL:
				/* continue on next iter. we dont need to do
				 * anything*/
				break;
			case MMDP_STRUCT:
				for (k = 0; k < mmdp_capability.mmdp_struct_num; k++) {
					if (strcmp(mmdp_capability.mmdp_structs[k]._real_name,
						   curr_mfield->body.struc._name) == 0) {
						curr_mfield->body.struc.id = k;
						goto mmdp_struct_success;
					}
				}
				for (k = 0; k < mmdp_capability.custom_struct_num; k++) {
					if (strcmp(mmdp_capability.custom_structs[k]._real_name,
						   curr_mfield->body.struc._name) == 0) {
						curr_mfield->body.struc.id = mmdp_capability.mmdp_struct_num + k;
						goto mmdp_struct_success;
					}
				}

				printf("MMDP: Didnt find matching struct\n");
				free_capability(&mmdp_capability);
				return -1;
			mmdp_struct_success:
				break;

			case MMDP_ARRAY:
				curr_mfield->body.array.depends_id = UINT32_MAX;
				for (k = 0; k < curr_mstruct->fields_num; k++) {
					if (curr_mstruct->fields[k].type != MMDP_NORMAL) {
						break; /* no need to continue
							  searching since list
							  is sorted */
					}
					if (strcmp(curr_mstruct->fields[k].body.normal._name,
						   curr_mfield->body.array._depends_name) == 0) {
						curr_mfield->body.array.depends_id = k;
						break;
					}
				}
				if (curr_mfield->body.array.depends_id == UINT32_MAX) {
					printf("MMDP: Didnt find matching "
					       "depends\n");
					free_capability(&mmdp_capability);
					return -1;
				}
				break;
			case MMDP_STRUCT_ARRAY:
				for (k = 0; k < mmdp_capability.mmdp_struct_num; k++) {
					if (strcmp(mmdp_capability.mmdp_structs[k]._real_name,
						   curr_mfield->body.struct_array._name) == 0) {
						curr_mfield->body.struct_array.id = k;
						goto mmdp_struct_array_struct_success;
					}
				}
				for (k = 0; k < mmdp_capability.custom_struct_num; k++) {
					if (strcmp(mmdp_capability.custom_structs[k]._real_name,
						   curr_mfield->body.struct_array._name) == 0) {
						curr_mfield->body.struct_array.id = mmdp_capability.mmdp_struct_num + k;
						goto mmdp_struct_array_struct_success;
					}
				}

				printf("MMDP: Didnt find matching struct\n");
				free_capability(&mmdp_capability);
				return -1;
			mmdp_struct_array_struct_success:
				curr_mfield->body.array.depends_id = UINT32_MAX;
				for (k = 0; k < curr_mstruct->fields_num; k++) {
					if (curr_mstruct->fields[k].type != MMDP_NORMAL) {
						break; /* no need to continue
							  searching since list
							  is sorted */
					}
					if (strcmp(curr_mstruct->fields[k].body.normal._name,
						   curr_mfield->body.array._depends_name) == 0) {
						curr_mfield->body.array.depends_id = k;
						break;
					}
				}
				if (curr_mfield->body.array.depends_id == UINT32_MAX) {
					printf("MMDP: Didnt find matching "
					       "depends\n");
					free_capability(&mmdp_capability);
					return -1;
				}
				break;
			}
		}
	}
#ifdef DEBUG
	print_capability(&mmdp_capability);
#endif
	return 0;
}

uint32_t sizeof_ser_capability(struct mmdp_capability *cap) {
	uint32_t i, j;
	uint32_t size;

	size = 0;
	size += 4; /* num_mmdp */
	size += 4; /* num_custom */

	for (i = 0; i < cap->mmdp_struct_num; i++) {
		size += strlen(cap->mmdp_structs[i].net_name);
		size += 1; /* null terminator */
		size += 4; /* num of fields and flags */
		for (j = 0; j < cap->mmdp_structs[i].fields_num; j++) {
			size += strlen(cap->mmdp_structs[i].fields[j].net_name);
			size += 1; /* null terminator */
			size += 1; /* flags */
			switch (cap->mmdp_structs[i].fields[j].type) {
			case MMDP_NORMAL:
				size += 4; /* size */
				break;
			case MMDP_STRUCT:
				size += 4; /* struct_id */
				break;
			case MMDP_ARRAY:
				size += 4; /* size */
				size += 4; /* depends_id */
				break;
			case MMDP_STRUCT_ARRAY:
				size += 4; /* struct_id */
				size += 4; /* depends_id */
				break;
			}
		}
	}
	for (i = 0; i < cap->custom_struct_num; i++) {
		size += strlen(cap->custom_structs[i].net_name);
		size += 1; /* null terminator */
		size += 1; /* flags */
	}
	return size;
}

/* TODO: fix so no ub when accessing unaligned memory */
/* returns a heap allocated pointer. up to the user to free it */
void *serialize_capability(uint32_t *size_out, struct mmdp_capability *cap) {
	uint8_t *ser_buf;
	uint8_t *ptr;
	uint32_t i, j;
	uint32_t total_size;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
#ifdef DEBUG
	int fd;
#endif

	total_size = 4 + sizeof_ser_capability(cap);
	ser_buf = malloc(total_size);
	if (ser_buf == NULL) {
		perror("malloc");
		return NULL;
	}
	memset(ser_buf, 0, total_size);
	ptr = ser_buf;

	*((uint32_t *)ptr) = htonl(total_size - 4);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(cap->mmdp_struct_num);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(cap->custom_struct_num);
	ptr += 4;

	for (i = 0; i < cap->mmdp_struct_num; i++) {
		/* we trust the user of this function since it is programmer */
		curr_struct = cap->mmdp_structs + i;
		/* include null terminator */
		memcpy(ptr, curr_struct->net_name, strlen(curr_struct->net_name) + 1);
		ptr += strlen(curr_struct->net_name) + 1;

#ifdef DEBUG
		printf("struct_flags: ");
		print_b32((curr_struct->fields_num & (~(UINT32_MAX << 31))) |
			  (IS_FLAG_ACTIVE(curr_struct->flags, MMDP_IS_ESSENTIAL) << 31));
#endif
		*((uint32_t *)ptr) = htonl(
		    /* zero out first 2 bits */ /* add is_essential flag */
		    (curr_struct->fields_num & (~(UINT32_MAX << 31))) |
		    (IS_FLAG_ACTIVE(curr_struct->flags, MMDP_IS_ESSENTIAL) << 31));
		ptr += 4;
		for (j = 0; j < curr_struct->fields_num; j++) {
			curr_field = curr_struct->fields + j;

			memcpy(ptr, curr_field->net_name, strlen(curr_field->net_name) + 1);
			ptr += strlen(curr_field->net_name) + 1;

#ifdef DEBUG
			printf("field_flags: ");
			print_b8(((IS_FLAG_ACTIVE(curr_field->flags, MMDP_FIELD_IS_ESSENTIAL) << 7) |
				  (curr_field->type << 5)));
#endif
			/* flags have format: | is_essential on most sig, type
			 * on 2 - 3 most sig | */
			*ptr = (uint8_t)((IS_FLAG_ACTIVE(curr_field->flags, MMDP_FIELD_IS_ESSENTIAL) << 7) |
					 (curr_field->type << 5));
			ptr += 1;
			switch (curr_field->type) {
			case MMDP_NORMAL:
				*((uint32_t *)ptr) = htonl(curr_field->body.normal.size);
				ptr += 4;
				break;
			case MMDP_STRUCT:
				*((uint32_t *)ptr) = htonl(curr_field->body.struc.id);
				ptr += 4;
				break;
			case MMDP_ARRAY:
				*((uint32_t *)ptr) = htonl(curr_field->body.array.size);
				ptr += 4;
				*((uint32_t *)ptr) = htonl(curr_field->body.array.depends_id);
				ptr += 4;
				break;
			case MMDP_STRUCT_ARRAY:
				*((uint32_t *)ptr) = htonl(curr_field->body.struct_array.id);
				ptr += 4;
				*((uint32_t *)ptr) = htonl(curr_field->body.struct_array.depends_id);
				ptr += 4;
				break;
			}
		}
	}
	for (i = 0; i < cap->custom_struct_num; i++) {
		memcpy(ptr, cap->custom_structs[i].net_name, strlen(cap->custom_structs[i].net_name) + 1);
		ptr += strlen(cap->custom_structs[i].net_name) + 1;
		*ptr = cap->custom_structs[i].flags;
		ptr += 1;
	}
#ifdef DEBUG
	fd = open("./log/ser_cap", O_CREAT | O_WRONLY, 0666);
	if (fd < 0) {
		perror("open ./log/ser_cap");
	} else {
		write(fd, ser_buf, total_size);
	}
#endif
	*size_out = total_size;
	return ser_buf;
}
/* TODO: fix so no ub when accessing unaligned memory */
/* returns negative number on fail */
int deserialize_capability(const void *buf, uint32_t size, struct mmdp_capability *out) {
	uint32_t i, j;
	size_t len;
	const uint8_t *ptr;

	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	struct mmdp_custom_struct *curr_custom_struct;

	struct mmdp_struct *struct_ptr;
	struct mmdp_field *field_ptr;
	struct mmdp_custom_struct *custom_struct_ptr;

	uint32_t net_num_fields;
	uint8_t net_field_flags;

	int ret;

	ptr = buf;
	if (size < 8) {
#ifdef DEBUG
		printf("size is too small while recving "
		       "mmdp_struct_num+custom_struct_num\n");
#endif
		/* we must have at least 2 uint32_t numbers */
		ret = -1;
		goto return_func;
	}
	out->mmdp_struct_num = ntohl(*((uint32_t *)ptr));
	if (out->mmdp_struct_num > hard_limit_pre_conn / sizeof(struct mmdp_struct)) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");
		ret = -1;
		goto return_func;
	}
	ptr += 4;
	out->mmdp_structs = malloc(sizeof(struct mmdp_struct) * out->mmdp_struct_num);
	if (out->mmdp_structs == NULL) {
		perror("malloc");
		ret = -1;
		goto return_func;
	}
	out->custom_struct_num = ntohl(*((uint32_t *)ptr));
	if (out->custom_struct_num > hard_limit_pre_conn / sizeof(struct mmdp_custom_struct)) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");
		ret = -1;
		goto fail_mmdp_structs;
	}
	ptr += 4;
	out->custom_structs = malloc(sizeof(struct mmdp_custom_struct) * out->custom_struct_num);
	if (out->custom_structs == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_mmdp_structs;
	}
	size -= 8;
	for (curr_struct = out->mmdp_structs; curr_struct < out->mmdp_structs + out->mmdp_struct_num; curr_struct++) {
		len = strnlen((char *)ptr, size);
		/* if they equal than string was not null terminated */
		if (len >= size) {
#ifdef DEBUG
			printf("size is too small while recving "
			       "struct.net_name\n");
#endif
			ret = -1;
			goto fail_structs_fillout;
		}
		/* checked size beforehand */
		curr_struct->net_name = strndup((char *)ptr, len);
		if (curr_struct->net_name == NULL) {
			perror("strndup\n");
			ret = -1;
			goto fail_structs_fillout;
		}
		/* include null terminator */
		ptr += len + 1;
		size -= len + 1;
#ifdef DEBUG
		printf("net: %s\n", curr_struct->net_name);
#endif
		if (size < 4) {
#ifdef DEBUG
			printf("size is too small while recving "
			       "struct.num_fields\n");
#endif
			ret = -1;
			goto fail_structs_fillout_name;
		}
		net_num_fields = ntohl(*((uint32_t *)ptr));
		ptr += 4;
		size -= 4;
		curr_struct->flags = 0;
		if (IS_FLAG_ACTIVE(net_num_fields, 1 << 31) == 1) {
			curr_struct->flags |= MMDP_IS_ESSENTIAL;
		}
		/* zero out the flags (only MSB for now) to get num_of_fields */
		curr_struct->fields_num = net_num_fields & (~(1 << 31));
#ifdef DEBUG
		printf("net_num_fields: ");
		print_b32(net_num_fields);
		printf("struct_flags: ");
		print_b8(curr_struct->flags);
		printf("num_fields: %d\n", curr_struct->fields_num);
#endif
		if (curr_struct->fields_num > hard_limit_pre_conn / sizeof(struct mmdp_field)) {
			printf("MMDP: rejecting connection since we would "
			       "allocate more than hardlimit\n");
			ret = -1;
			goto fail_structs_fillout_name;
		}
		curr_struct->fields = malloc(sizeof(struct mmdp_field) * curr_struct->fields_num);
		if (curr_struct->fields == NULL) {
			perror("malloc");
			ret = -1;
			goto fail_structs_fillout_name;
		}
		for (curr_field = curr_struct->fields; curr_field < curr_struct->fields + curr_struct->fields_num;
		     curr_field++) {
			len = strnlen((char *)ptr, size);
			/* if they equal than string was not null terminated */
			if (len >= size) {
#ifdef DEBUG
				printf("size is too small while recving "
				       "field.net_name\n");
#endif
				ret = -1;
				goto fail_fields_fillout;
			}
			/* checked size beforehand */
			curr_field->net_name = strndup((char *)ptr, len);
			ptr += len + 1;
			size -= len + 1;
			if (curr_field->net_name == NULL) {
				perror("strndup");
				ret = -1;
				goto fail_fields_fillout;
			}
#ifdef DEBUG
			printf("\tnet_field: %s\n", curr_field->net_name);
#endif
			if (size < 1) {
#ifdef DEBUG
				printf("size is too small while recving "
				       "field.flags\n");
#endif
				ret = -1;
				goto fail_fields_fillout_name;
			}
			net_field_flags = *ptr;
			ptr += 1;
			size -= 1;
			curr_field->flags = 0;
			if (IS_FLAG_ACTIVE(net_field_flags, 1 << 7) == 1) {
				curr_field->flags |= MMDP_FIELD_IS_ESSENTIAL;
			}
			curr_field->type = (net_field_flags & (~(1 << 7))) >> 5;
#ifdef DEBUG
			printf("\tnet_flags: ");
			print_b8(net_field_flags);
			printf("\tfield_flags: ");
			print_b8(curr_field->flags);
			printf("\tfield_type: %d\n", curr_field->type);
#endif
			switch (curr_field->type) {
			case MMDP_NORMAL:
				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while recving "
					       "field.body.normal.size\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.normal.size = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;
				break;
			case MMDP_STRUCT:
				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while "
					       "recving field.body.struc.id\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.struc.id = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;
				break;
			case MMDP_ARRAY:
				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while recving "
					       "field.body.array.size\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.array.size = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;

				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while recving "
					       "field.body.array.depends_id\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.array.depends_id = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;

				break;
			case MMDP_STRUCT_ARRAY:
				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while recving "
					       "field.body.struct_array.id\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.struct_array.id = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;

				if (size < 4) {
#ifdef DEBUG
					printf("size is too small while recving "
					       "field.body.struct_array.depends_"
					       "id\n");
#endif
					ret = -1;
					goto fail_fields_fillout_name;
				}
				curr_field->body.struct_array.depends_id = ntohl(*((uint32_t *)ptr));
				ptr += 4;
				size -= 4;
				break;
			default:
#ifdef DEBUG
				printf("INVALID TYPE FAILED\n");
#endif
				ret = -1;
				goto fail_fields_fillout_name;
			}
		}
	}
	for (i = 0; i < out->custom_struct_num; i++) {
		len = strnlen((char *)ptr, size);
		curr_custom_struct = out->custom_structs + i;
		/* if they equal than string was not null terminated */
		if (len >= size) {
#ifdef DEBUG
			printf("size is too small while recving "
			       "struct.net_name\n");
#endif
			ret = -1;
			goto fail_custom_fillout;
		}
		/* checked size beforehand */
		curr_custom_struct->net_name = strndup((char *)ptr, len);
		ptr += len + 1;
		size -= len + 1;
		if (curr_custom_struct->net_name == NULL) {
			perror("strndup");

			ret = -1;
			goto fail_custom_fillout;
		}
#ifdef DEBUG
		printf("custom_net: %s\n", out->custom_structs[i].net_name);
#endif
		if (size < 1) {
#ifdef DEBUG
			printf("size is too small while recving "
			       "custom_struct.flags\n");
#endif

			ret = -1;
			goto fail_custom_fillout_name;
		}
		curr_custom_struct->flags = *ptr;
		ptr += 1;
		size -= 1;
	}

	ret = 0;
	goto return_func;
fail_custom_fillout_name:
	free((void *)out->custom_structs[i].net_name);
fail_custom_fillout:
	for (custom_struct_ptr = out->custom_structs; custom_struct_ptr < curr_custom_struct; custom_struct_ptr++) {
		free((void *)out->custom_structs[i].net_name);
	}
	if (out->mmdp_struct_num < 1) 
		goto fail_custom_structs;
fail_fields_fillout_name:
	free((void *)curr_field->net_name);
fail_fields_fillout:
	for (field_ptr = curr_struct->fields; field_ptr < curr_field; field_ptr++) {
		free((void *)field_ptr->net_name);
	}
	free(curr_struct->fields);
fail_structs_fillout_name:
	free((void *)curr_struct->net_name);
fail_structs_fillout:
	for (struct_ptr = out->mmdp_structs; struct_ptr < curr_struct; struct_ptr++) {
		free((void *)struct_ptr->net_name);
		for (j = 0; j < struct_ptr->fields_num; j++) {
			curr_field = struct_ptr->fields + j;
			free((void *)curr_field->net_name);
		}
		free(struct_ptr->fields);
	}
fail_custom_structs:
	free(out->custom_structs);
fail_mmdp_structs:
	free(out->mmdp_structs);
return_func:
	return ret;
}
/* creates clientside config according to its own requirements (doesn't account
 * for server requirements for now (will change whe adding not preffered flag))
 */
int create_clientside_config(const struct mmdp_capability *srv_cap, struct mmdp_clientside_config *out) {
	uint32_t i, j, k, order;
	size_t size;
	void **free_ptr;

	struct mmdp_struct *curr_struct;
	struct mmdp_struct *srv_struct;
	struct mmdp_field *curr_field;
	struct mmdp_field *srv_field;

	int ret;

	size = sizeof(uint32_t) * (mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num);
	out->c_to_s_struct_remap = malloc(size);
	if (out->c_to_s_struct_remap == NULL) {
		perror("malloc");
		ret = -1;
		goto return_func;
	}
	/* set all to max */
	memset(out->c_to_s_struct_remap, 0xff, size);

	out->s_mmdp_struct_num = srv_cap->mmdp_struct_num;
	out->s_custom_struct_num = srv_cap->custom_struct_num;

	size = sizeof(uint32_t) * (out->s_mmdp_struct_num + out->s_custom_struct_num);
	out->s_to_c_struct_remap = malloc(size);
	if (out->s_to_c_struct_remap == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_c_to_s;
	}
	memset(out->s_to_c_struct_remap, 0xff, size);

	size = sizeof(uint32_t *) * mmdp_capability.mmdp_struct_num;
	out->field_order = malloc(size);
	if (out->field_order == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_s_to_c;
	}
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		out->field_order[i] = NULL;
	}

	/* fillout mmdp remaps */
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		curr_struct = mmdp_capability.mmdp_structs + i;
		srv_struct = NULL;
		for (j = 0; j < srv_cap->mmdp_struct_num; j++) {
			if (strcmp(curr_struct->net_name, srv_cap->mmdp_structs[j].net_name) != 0) {
				continue;
			}
			srv_struct = srv_cap->mmdp_structs + j;
			out->c_to_s_struct_remap[i] = j;
			out->s_to_c_struct_remap[j] = i;
			break;
		}
		if (srv_struct == NULL) {
			if (IS_FLAG_ACTIVE(curr_struct->flags, MMDP_IS_ESSENTIAL)) {
#ifdef DEBUG
				printf("essential struct (%s) not supported by "
				       "server\n",
				       curr_struct->_real_name);
#endif
				ret = -1;
				goto fail_remap_mmdp;
			}
			continue;
		}

		size = sizeof(uint32_t) * curr_struct->fields_num;
		out->field_order[i] = malloc(size);
		if (out->field_order[i] == NULL) {
			perror("malloc");
			ret = -1;
			goto fail_remap_mmdp;
		}
		memset(out->field_order[i], 0xff, size);
		order = 0;
		for (j = 0; j < srv_struct->fields_num; j++) {
			srv_field = srv_struct->fields + j;
			assert(curr_struct->fields_num > 0);
			for (k = 0; k < curr_struct->fields_num; k++) {
				curr_field = curr_struct->fields + k;
				if (strcmp(curr_field->net_name, srv_field->net_name) != 0) {
					continue;
				}
				out->field_order[i][order] = k;
				order++;
				goto skip_essential;
			}
			if (IS_FLAG_ACTIVE(curr_field->flags, MMDP_FIELD_IS_ESSENTIAL)) {
				if (out->field_order[i][order] == UINT32_MAX) {
#ifdef DEBUG
					printf("essential struct (%s) not "
					       "supported by server\n",
					       curr_struct->_real_name);
#endif
					ret = -1;
					goto fail_remap_mmdp_field_order;
				}
			}
		skip_essential:
			continue;
		}
		/* now we could possibly save some memory by shrinking the
		 * field_order[i] to the required size. TODO: implement this */
	}
	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		for (j = 0; j < srv_cap->custom_struct_num; j++) {
			/* skip if net_names dont match */
			if (strcmp(mmdp_capability.custom_structs[i].net_name, srv_cap->custom_structs[j].net_name) !=
			    0) {
				continue;
			}
			out->c_to_s_struct_remap[mmdp_capability.mmdp_struct_num + i] = j;
			out->s_to_c_struct_remap[out->s_mmdp_struct_num + j] = i;
			printf("i: %u, j: %u\n", i, j);
			break;
		}
		if (out->c_to_s_struct_remap[mmdp_capability.mmdp_struct_num + i] == UINT32_MAX) {
			if (IS_FLAG_ACTIVE(mmdp_capability.custom_structs[i].flags, MMDP_IS_ESSENTIAL)) {
#ifdef DEBUG
				printf("essential custom struct (%s) not "
				       "supported by server\n",
				       mmdp_capability.custom_structs[i]._real_name);
#endif
				ret = -1;
				goto fail_remap_custom;
			}
		}
	}

#ifdef DEBUG
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		printf("%s: %u\n", mmdp_capability.mmdp_structs[i]._real_name, out->c_to_s_struct_remap[i]);
		for (j = 0; j < mmdp_capability.mmdp_structs[i].fields_num; j++) {
			printf("\t%s: %u\n", mmdp_capability.mmdp_structs[i].fields[j].net_name,
			       out->field_order[i][j]);
		}
	}

	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		printf("custom %s: %u\n", mmdp_capability.custom_structs[i]._real_name,
		       out->c_to_s_struct_remap[mmdp_capability.mmdp_struct_num + i]);
	}
	printf("s_to_c:\n");
	for (i = 0; i < out->s_mmdp_struct_num + out->s_custom_struct_num; i++) {
		printf("\t %u: %u\n", i, out->s_to_c_struct_remap[i]);
	}
#endif

	/* we dont need to validate server requirements since it will do it
	 * itself */
	ret = 0;
	goto return_func;

fail_remap_custom:
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		free(out->field_order[i]);
		out->field_order[i] = NULL;
	}
	/* here we have to skip fail_remap_mmdp because we repurpose i */
	goto fail_field_order;

fail_remap_mmdp_field_order:
	free(*(out->field_order + i));
	*(out->field_order + i) = NULL;
fail_remap_mmdp:
	for (free_ptr = (void **)(out->field_order); free_ptr < (void **)(out->field_order + i); free_ptr++) {
		free(*free_ptr);
		*free_ptr = NULL;
	}
fail_field_order:
	free(out->field_order);
	out->field_order = NULL;
fail_s_to_c:
	free(out->s_to_c_struct_remap);
	out->s_to_c_struct_remap = NULL;
fail_c_to_s:
	free(out->c_to_s_struct_remap);
	out->c_to_s_struct_remap = NULL;
return_func:
	return ret;
}
void *convert_clientside_to_serealized_serverside(const struct mmdp_clientside_config *cconfig, uint32_t *out_size) {
	uint32_t i, j;
	uint32_t client_id;
	uint32_t size;

	uint32_t mmdp_struct_num, custom_struct_num;
	uint32_t *fields_num;

	void *ser_ss_config;
	uint8_t *ptr;
#ifdef DEBUG
	int fd;
#endif

	fields_num = malloc(sizeof(uint32_t) * mmdp_capability.mmdp_struct_num);
	if (fields_num == NULL) {
		perror("malloc");
		return NULL;
	}
	memset(fields_num, 0, sizeof(uint32_t) * mmdp_capability.mmdp_struct_num);

	mmdp_struct_num = 0;
	custom_struct_num = 0;
	/* compute size */
	size = 0;
	size += 4; /* size */
	size += 4; /* num_mmdp_structs */
	size += 4; /* num_custom_structs */

	/* after this boundary there are custom structs */
	for (i = 0; i < cconfig->s_mmdp_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[i];
		printf("client_id=%d\n", client_id);
		if (client_id == UINT32_MAX) {
			continue;
		}
		size += strlen(mmdp_capability.mmdp_structs[client_id].net_name);
		size += 1; /* null terminator */
		size += 4; /* num_fields */
		mmdp_struct_num++;
		for (j = 0; j < mmdp_capability.mmdp_structs[client_id].fields_num; j++) {
			printf("field: %d\n", cconfig->field_order[client_id][j]);
		}

		for (j = 0; j < mmdp_capability.mmdp_structs[client_id].fields_num; j++) {
			if (cconfig->field_order[client_id][j] == UINT32_MAX) {
				break;
			}
			size += strlen(mmdp_capability.mmdp_structs[client_id]
					   .fields[cconfig->field_order[client_id][j]]
					   .net_name);
			size += 1; /* null terminator */
			fields_num[client_id]++;
		}
	}
	for (i = 0; i < cconfig->s_custom_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[cconfig->s_mmdp_struct_num + i];
		if (client_id == UINT32_MAX) {
			continue;
		}

		custom_struct_num++;
		size += strlen(mmdp_capability.custom_structs[client_id].net_name);
		size += 1; /* null terminator */
	}
#ifdef DEBUG
	printf("Serealized_serverside size: %u\n", size);
#endif

	ser_ss_config = malloc(size);
	if (ser_ss_config == NULL) {
		perror("malloc");
		free(fields_num);
		return NULL;
	}
	memset(ser_ss_config, 0, size);
	ptr = ser_ss_config;

	*((uint32_t *)ptr) = htonl(size - 4);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(mmdp_struct_num);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(custom_struct_num);
	ptr += 4;
	for (i = 0; i < cconfig->s_mmdp_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[i];
		if (client_id == UINT32_MAX) {
			continue;
		}
		ptr = (uint8_t *)stpcpy((char *)ptr, mmdp_capability.mmdp_structs[client_id].net_name);
		ptr++;
		*((uint32_t *)ptr) = htonl(fields_num[client_id]);
		ptr += 4;
		for (j = 0; j < mmdp_capability.mmdp_structs[client_id].fields_num; j++) {
			if (cconfig->field_order[client_id][j] == UINT32_MAX) {
				break;
			}
			ptr =
			    (uint8_t *)stpcpy((char *)ptr, mmdp_capability.mmdp_structs[client_id].fields[j].net_name);
			ptr++;
		}
	}
	for (i = 0; i < cconfig->s_custom_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[cconfig->s_mmdp_struct_num + i];
		if (client_id == UINT32_MAX) {
			continue;
		}
		ptr = (uint8_t *)stpcpy((char *)ptr, mmdp_capability.custom_structs[client_id].net_name);
		ptr++;
	}
#ifdef DEBUG
	fd = open("./log/ser_ssconf", O_TRUNC | O_CREAT | O_WRONLY, 0666);
	if (fd < 0) {
		perror("open ./log/ser_ssconf");
	} else {
		write(fd, ser_ss_config, size);
		close(fd);
	}
#endif
	free(fields_num);
	fields_num = NULL;
	*out_size = size;

	return ser_ss_config;
}
int serverside_from_ser(struct mmdp_serverside_config *sconfig, void *serialized_sconfig, uint32_t max_size) {
	uint32_t i, j, k, l;
	uint32_t num_mmdp_ser, num_custom_ser;
	uint8_t *ptr;
	uint32_t len;
	void **free_ptr;

	char **struct_net_names;
	char **custom_struct_net_names;
	char ***field_net_names;
	char ***ptr_field_net_names;
	uint32_t *num_fields;
	int ret;
#ifdef DEBUG
	int fd;
#endif

	ptr = serialized_sconfig;
#ifdef DEBUG
	fd = open("./log/ser_ssconf2", O_CREAT | O_WRONLY, 0666);
	if (fd < 0) {
		perror("open ./log/ser_ssconf2");
	} else {
		write(fd, serialized_sconfig, max_size);
	}
	close(fd);
#endif

	memset(sconfig, 0, sizeof(struct mmdp_serverside_config));

	sconfig->struct_mask = malloc(mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num);
	if (sconfig->struct_mask == NULL) {
		perror("malloc");
		ret = -1;
		goto return_func;
	}
	memset(sconfig->struct_mask, 0, mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num);

	sconfig->field_mask = malloc(sizeof(uint32_t *) * mmdp_capability.mmdp_struct_num);
	if (sconfig->field_mask == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_struct_mask;
	}
	memset(sconfig->field_mask, 0, sizeof(uint32_t *) * mmdp_capability.mmdp_struct_num);

	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		sconfig->field_mask[i] = malloc(mmdp_capability.mmdp_structs[i].fields_num);
		if (sconfig->field_mask[i] == NULL) {
			perror("malloc");
			ret = -1;
			goto fail_field_mask_alloc_loop;
		}
		memset(sconfig->field_mask[i], 0, mmdp_capability.mmdp_structs[i].fields_num);
	}

	if (max_size < 4) {
#ifdef DEBUG
		printf("size too small unable to get num_mmdp_ser\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	max_size -= 4;
	num_mmdp_ser = ntohl(*((uint32_t *)ptr));
	ptr += 4;
	if (num_mmdp_ser > hard_limit_pre_conn / sizeof(char **)) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");

		ret = -1;
		goto fail_field_mask_complete;
	}

	if (max_size < 4) {
#ifdef DEBUG
		printf("size too small unable to get num_custom_ser\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	max_size -= 4;
	num_custom_ser = ntohl(*((uint32_t *)ptr));
	ptr += 4;
	if (num_custom_ser > hard_limit_pre_conn / sizeof(char **)) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");
		ret = -1;
		goto fail_field_mask_complete;
	}
	struct_net_names = malloc(sizeof(char *) * num_mmdp_ser);
	if (struct_net_names == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_field_mask_complete;
	}

	custom_struct_net_names = malloc(sizeof(char *) * num_custom_ser);
	if (custom_struct_net_names == NULL) {
		perror("malloc");
		ret = -1;
		goto free_struct_net_names;
	}

	field_net_names = malloc(sizeof(char **) * num_mmdp_ser);
	if (field_net_names == NULL) {
		perror("malloc");
		ret = -1;
		goto free_custom_struct_net_names;
	}
	memset(field_net_names, 0, sizeof(char **) * num_mmdp_ser);

	num_fields = malloc(sizeof(uint32_t) * num_mmdp_ser);
	if (struct_net_names == NULL) {
		perror("malloc");
		ret = -1;
		goto free_field_net_names;
	}
	memset(num_fields, 0, sizeof(uint32_t) * num_mmdp_ser);

	/* get the pointers to struct and field net_names */
	for (i = 0; i < num_mmdp_ser; i++) {
		len = strnlen((char *)ptr, max_size);
		if (len >= max_size) {
#ifdef DEBUG
			printf("structname not properly null terminated\n");
#endif
			ret = -1;
			goto free_field_net_names_loop;
		}
		struct_net_names[i] = (char *)ptr;
		printf("ptr: %x, ptr+1: %x", *ptr, *ptr + 1);
		max_size -= len + 1; /* the netname and the null terminator */
		ptr += len + 1;

		if (max_size < 4) {
#ifdef DEBUG
			printf("size is too small unable to get num_of_fields\n");
#endif
			ret = -1;
			goto free_field_net_names_loop;
		}
		max_size -= 4; /* num_fields */
		num_fields[i] = ntohl(*((uint32_t *)ptr));
		ptr += 4;
		if (num_fields[i] > hard_limit_pre_conn / sizeof(char *)) {
			printf("MMDP: rejecting connection since we would "
			       "allocate more than hardlimit\n");
			ret = -1;
			goto free_field_net_names_loop;
		}

		field_net_names[i] = malloc(sizeof(char *) * num_fields[i]);
		if (field_net_names[i] == NULL) {
			perror("malloc");
			ret = -1;
			goto free_field_net_names_loop;
		}

		printf("num_field: %d\n", num_fields[i]);
		for (j = 0; j < num_fields[i]; j++) {
			len = strnlen((char *)ptr, max_size);
			if (len >= max_size) {
#ifdef DEBUG
				printf("fieldname not properly null terminated\n");
#endif
				ret = -1;
				goto free_field_net_names_loop_inclusive;
			}
			field_net_names[i][j] = (char *)ptr;
			max_size -= len + 1;
			ptr += len + 1;
		}
	}

	for (i = 0; i < num_custom_ser; i++) {
		len = strnlen((char *)ptr, max_size);
		if (len >= max_size) {
#ifdef DEBUG
			printf("custom_struct_name not properly null "
			       "terminated\n");
#endif
			ret = -1;
			goto free_field_net_names_complete;
		}
		custom_struct_net_names[i] = (char *)ptr;
		max_size -= len + 1; /* the netname and the null terminator */
		ptr += len + 1;
	}

	/* increment until you find the match or you reach the limit*/
	j = 0;
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		if (j >= num_mmdp_ser) {

			break;
		}
		printf("mmdp_net_name: %s\n", mmdp_capability.mmdp_structs[i].net_name);
		printf("struct_net_name: %s\n", struct_net_names[j]);
		if (strcmp(mmdp_capability.mmdp_structs[i].net_name, struct_net_names[j]) == 0) {
			sconfig->struct_mask[i] = 0xff;
			l = 0;
			for (k = 0; k < mmdp_capability.mmdp_structs[i].fields_num; k++) {
				if (l >= num_fields[j]) {
					break;
				}
				if (strcmp(mmdp_capability.mmdp_structs[i].fields[k].net_name, field_net_names[j][l]) ==
				    0) {
					sconfig->field_mask[i][k] = 0xff;
					l++;
				}
			}
			j++;
		}
	}

	j = 0;
	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		if (j >= num_custom_ser) {

			break;
		}
		if (strcmp(mmdp_capability.custom_structs[i].net_name, custom_struct_net_names[j]) == 0) {
			sconfig->struct_mask[mmdp_capability.mmdp_struct_num + i] = 0xff;
			j++;
		}
	}
#ifdef DEBUG
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		printf("%s : %d\n", mmdp_capability.mmdp_structs[i]._real_name, sconfig->struct_mask[i]);
		for (j = 0; j < mmdp_capability.mmdp_structs[i].fields_num; j++) {
			printf("\t%s : %d\n", mmdp_capability.mmdp_structs[i].fields[j].net_name,
			       sconfig->field_mask[i][j]);
		}
	}
	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		printf("custom: %s : %s\n", mmdp_capability.custom_structs[i]._real_name,
		       sconfig->struct_mask[mmdp_capability.mmdp_struct_num + i] == 0xff ? "active" : "inactive");
	}
#endif

	ret = 0;
free_field_net_names_complete:
	for (i = 0; i < num_mmdp_ser; i++) {
		free(field_net_names[i]);
		field_net_names[i] = NULL;
	}
	goto free_num_fields;
free_field_net_names_loop_inclusive:
	free(*field_net_names);
	*field_net_names = NULL;
free_field_net_names_loop:
	for (ptr_field_net_names = field_net_names; ptr_field_net_names < field_net_names + i; ptr_field_net_names++) {
		free(*ptr_field_net_names);
		*ptr_field_net_names = NULL;
	}
free_num_fields:
	free(num_fields);
	num_fields = NULL;
free_field_net_names:
	free(field_net_names);
	field_net_names = NULL;
free_custom_struct_net_names:
	free(custom_struct_net_names);
	custom_struct_net_names = NULL;
free_struct_net_names:
	free(struct_net_names);
	struct_net_names = NULL;
	if (ret == 0) {
		goto return_func;
	}
fail_field_mask_complete:
	/* loop over all structs and free the fields */
	i = mmdp_capability.mmdp_struct_num;
fail_field_mask_alloc_loop:
	for (free_ptr = (void **)(sconfig->field_mask); free_ptr < (void **)(sconfig->field_mask + i); free_ptr++) {
		free(*free_ptr);
		*free_ptr = NULL;
	}
	free(sconfig->field_mask);
	sconfig->field_mask = NULL;
fail_struct_mask:
	free(sconfig->struct_mask);
	sconfig->struct_mask = NULL;
return_func:
	return ret;
}

uint32_t sizeof_ser_struct_server(struct mmdp_serverside_config *config, uint32_t id, const void *src) {
	uint32_t size;
	uint32_t i, j;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t struct_size;
	size = 0;
	if (id < mmdp_capability.mmdp_struct_num) {
		curr_struct = mmdp_capability.mmdp_structs + id;
		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			curr_field = curr_struct->fields + i;
			switch (curr_field->type) {
			case MMDP_NORMAL:
				size += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				size += sizeof_ser_struct_server(config, curr_field->body.struc.id,
								 *((void **)(((uint8_t *)src) + curr_field->offset)));
				break;
			case MMDP_ARRAY:
				size +=
				    curr_field->body.array.size *
				    (*((uint32_t *)(((uint8_t *)src) +
						    curr_struct->fields[curr_field->body.array.depends_id].offset)));
				break;
			case MMDP_STRUCT_ARRAY:
				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					return 0;
				}
				for (j = 0;
				     j < *((uint32_t *)(((uint8_t *)src) +
							(curr_struct->fields[curr_field->body.struct_array.depends_id]
							     .offset)));
				     j++) {
					size += sizeof_ser_struct_server(
					    config, curr_field->body.struct_array.id,
					    (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) + j * struct_size);
				}
				break;
			}
		}
	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		size = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].sizeof_func(src);
	}

	return size;
}
/* returns NULL on fail */
/* on success this fuction will fillout sizeof_ser_struct_server(config, id,
 * src) bytes and return pointer pointing to byte after the serialized struct*/
/* on fail dest will be left in corrupted state */
void *ser_struct_server(struct mmdp_serverside_config *config, uint32_t id, void *dest, const void *src) {
	uint8_t *ptr;
	uint32_t i, j;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t struct_size;

	ptr = NULL;
	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		ptr = dest;
		curr_struct = mmdp_capability.mmdp_structs + id;
		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			curr_field = curr_struct->fields + i;
			switch (curr_field->type) {
			case MMDP_NORMAL:
				memcpy(ptr, ((uint8_t *)src) + curr_field->offset, curr_field->body.normal.size);
				swap_bytes_little(ptr, curr_field->body.normal.size);
				ptr += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				if (*((void **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type MMDP_STRUCT "
					       "must not be NULL\n");
					return NULL;
				}
				ptr = ser_struct_server(config, curr_field->body.struc.id, ptr,
							*((void **)(((uint8_t *)src) + curr_field->offset)));
				if (ptr == NULL) {
#ifdef DEBUG
					printf("unable to serialize struct\n");
#endif
					return NULL;
				}
				break;
			case MMDP_ARRAY:
				if (*((uint32_t *)(((uint8_t *)src) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset)) ==
				    0) {
					break;
				}
				if (*((uint8_t **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type MMDP_ARRAY "
					       "is NULL, but DEPENDS_ON is not "
					       "zero\n");
					return NULL;
				}
				for (j = 0;
				     j <
				     (*((uint32_t *)(((uint8_t *)src) +
						     curr_struct->fields[curr_field->body.array.depends_id].offset)));
				     j++) {
					memcpy(ptr,
					       (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) +
						   j * curr_field->body.array.size,
					       curr_field->body.array.size);
					swap_bytes_little(ptr, curr_field->body.array.size);
					ptr += curr_field->body.array.size;
				}
				break;
			case MMDP_STRUCT_ARRAY:

				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					return NULL;
				}
				if (*((uint32_t *)(((uint8_t *)src) +
						   (curr_struct->fields[curr_field->body.struct_array.depends_id]
							.offset))) == 0) {
					break;
				}
				if (*((uint8_t **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type "
					       "MMDP_STRUCT_ARRAY is NULL, but "
					       "DEPENDS_ON is not zero\n");
					return NULL;
				}
				for (j = 0;
				     j < *((uint32_t *)(((uint8_t *)src) +
							(curr_struct->fields[curr_field->body.struct_array.depends_id]
							     .offset)));
				     j++) {

					ptr = ser_struct_server(
					    config, curr_field->body.struct_array.id, ptr,
					    (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) + j * struct_size);
					if (ptr == NULL) {
#ifdef DEBUG
						printf("unable to serialize "
						       "struct\n");
#endif
						return NULL;
					}
				}
				break;
			}
		}

	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		ptr = dest;
		ptr = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].ser_func(ptr, src);
	}
	return ptr;
}

/* TODO: fix memory leak in fail_mmdp_clean since structs can have its ovn allocations made */
/* returns pointer to byte AFTER last byte of serialized struct */
const void *deser_struct_server(struct mmdp_serverside_config *config, uint32_t id, void *dest, const void *src,
				uint32_t max_size) {
	const uint8_t *ptr;
	uint32_t i, j, k;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t nmemb_array;
	uint8_t *array;
	uint8_t *struc;
	uint32_t struct_size;
	const uint8_t *saved_ptr;

	ptr = NULL;
	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		ptr = src;
		curr_struct = mmdp_capability.mmdp_structs + id;

		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			curr_field = curr_struct->fields + i;
			/* since we sorted mmdp_capability the normal will be
			 * first */
			printf("type: %d (arr=%d)\n", curr_field->type, MMDP_ARRAY);
			switch (curr_field->type) {
			case MMDP_NORMAL:
				if (max_size < curr_field->body.normal.size) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				memcpy(((uint8_t *)dest) + curr_field->offset, ptr, curr_field->body.normal.size);
				swap_bytes_little(((uint8_t *)dest) + curr_field->offset, curr_field->body.normal.size);
				max_size -= curr_field->body.normal.size;
				ptr += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				if (curr_field->body.struc.id < mmdp_capability.mmdp_struct_num) {
					struct_size = mmdp_capability.mmdp_structs[curr_field->body.struc.id]._size;
				} else if (curr_field->body.struc.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struc.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					goto mmdp_fail_clean;
				}
				struc = malloc(struct_size);
				if (struc == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}
				saved_ptr = ptr;
				ptr = deser_struct_server(config, curr_field->body.struc.id, struc, ptr, max_size);
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = struc;
				if (ptr == NULL) {
					free(struc);
					*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				max_size -= ptr - saved_ptr;
				break;
			case MMDP_ARRAY:
				nmemb_array =
				    *((uint32_t *)(((uint8_t *)dest) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset));
				if (nmemb_array == 0) {
					*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
					break;
				}
				if (max_size < nmemb_array * curr_field->body.array.size) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				max_size -= nmemb_array * curr_field->body.array.size;

				array = malloc(nmemb_array * curr_field->body.array.size);
				if (array == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = array;
				printf("array: %p\n", array);
				for (j = 0; j < nmemb_array; j++) {
					memcpy(array + j * curr_field->body.array.size, ptr,
					       curr_field->body.array.size);
					swap_bytes_little(array + j * curr_field->body.array.size,
							  curr_field->body.array.size);
					ptr += curr_field->body.array.size;
				}
				break;
			case MMDP_STRUCT_ARRAY:
				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					goto mmdp_fail_clean;
				}
				nmemb_array = *(
				    (uint32_t *)(((uint8_t *)dest) +
						 curr_struct->fields[curr_field->body.struct_array.depends_id].offset));
				if (nmemb_array == 0) {
					*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
					break;
				}
				array = malloc(nmemb_array * struct_size);
				if (array == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = array;

				for (j = 0; j < nmemb_array; j++) {
					saved_ptr = ptr;
					ptr = deser_struct_server(config, curr_field->body.struct_array.id,
								  array + j * struct_size, ptr, max_size);
					if (ptr == NULL) {
						for (k = 0; k < j; k++) {
							free_struct_server(config, curr_field->body.struct_array.id,
									   array + j * struct_size);
						}
						free(array);
						*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
#ifdef DEBUG
						printf("unable to deserialize "
						       "struct\n");

#endif
						goto mmdp_fail_clean;
					}
					max_size -= ptr - saved_ptr;
				}
				break;
			}
		}

	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			return NULL;
		}
		printf("max_size: %u\n", max_size);
		ptr = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].deser_func(dest, src,
												      max_size);
		if (ptr == NULL) {
			printf("unble to deserialize custom struct %s\n",
			       mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].net_name);
			return NULL;
		}
		return ptr;
	}
	return ptr;
mmdp_fail_clean:
	for (j = 0; j < i; j++) {
		curr_field = curr_struct->fields + j;
		if (config->field_mask[id][j] != 0xff) {
			continue;
		}
		switch (curr_field->type) {
		case MMDP_STRUCT:
			free_struct_server(config, curr_field->body.struc.id,
					   *((void **)(((uint8_t *)dest) + curr_field->offset)));
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		case MMDP_ARRAY:
			nmemb_array = *((uint32_t *)(((uint8_t *)dest) +
						     curr_struct->fields[curr_field->body.array.depends_id].offset));
			if (nmemb_array == 0) {
				break;
			}
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		case MMDP_STRUCT_ARRAY:
			if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
				struct_size = mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
			} else if (curr_field->body.struct_array.id <
				   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
				struct_size = mmdp_capability
						  .custom_structs[curr_field->body.struct_array.id -
								  mmdp_capability.mmdp_struct_num]
						  ._size;
			} else {
#ifdef DEBUG
				printf("THIS IS UNREACHABLE\n");
#endif
				return NULL;
			}
			nmemb_array =
			    *((uint32_t *)(((uint8_t *)dest) +
					   curr_struct->fields[curr_field->body.struct_array.depends_id].offset));
			if (nmemb_array == 0) {
				break;
			}
			for (k = 0; k < nmemb_array; k++) {
				free_struct_server(config, curr_field->body.struct_array.id,
						   *((uint8_t **)(((uint8_t *)dest) + curr_field->offset)) +
						       k * struct_size);
			}
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		default:
			break;
		}
	}
	return NULL;
}
void free_struct_server(struct mmdp_serverside_config *config, uint32_t id, void *struc) {
	const struct mmdp_struct *curr_struct;
	const struct mmdp_field *curr_field;
	uint32_t nmemb_array;
	uint32_t i, j;
	uint32_t struct_size;
	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			printf("MMDP: Attempted to free masked struct\n");
			return;
		}
		curr_struct = mmdp_capability.mmdp_structs + id;
		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			switch (curr_field->type) {
			case MMDP_STRUCT:
				free_struct_server(config, curr_field->body.struc.id,
						   *((void **)(((uint8_t *)struc) + curr_field->offset)));
				free(*((void **)(((uint8_t *)struc) + curr_field->offset)));
				*((void **)(((uint8_t *)struc) + curr_field->offset)) = NULL;
			case MMDP_ARRAY:
				nmemb_array =
				    *((uint32_t *)(((uint8_t *)struc) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset));
				if (nmemb_array == 0) {
					break;
				}
				free(*((void **)(((uint8_t *)struc) + curr_field->offset)));
				*((void **)(((uint8_t *)struc) + curr_field->offset)) = NULL;
				break;
			case MMDP_STRUCT_ARRAY:
				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("THIS IS UNREACHABLE\n");
#endif
					return;
				}
				nmemb_array =
				    *((uint32_t *)(((uint8_t *)struc) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset));
				if (nmemb_array == 0) {
					break;
				}
				for (j = 0; j < nmemb_array; j++) {
					free_struct_server(config, curr_field->body.struct_array.id,
							   *((uint8_t **)(((uint8_t *)struc) + curr_field->offset)) +
							       j * struct_size);
				}
				free(*((void **)(((uint8_t *)struc) + curr_field->offset)));
				*((void **)(((uint8_t *)struc) + curr_field->offset)) = NULL;
				break;
			}
		}
	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		if (config->struct_mask[id] != 0xff) {
			printf("MMDP: Attempted to free masked struct\n");
			return;
		}
		mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].free_func(struc);
	}
}

uint32_t sizeof_ser_struct_client(struct mmdp_clientside_config *config, uint32_t id, const void *src) {
	uint32_t size;
	uint32_t i, j;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t struct_size;
	size = 0;
	if (id < mmdp_capability.mmdp_struct_num) {
		curr_struct = mmdp_capability.mmdp_structs + id;
		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_order[id][i] == UINT32_MAX) {
				break;
			}
			curr_field = curr_struct->fields + config->field_order[id][i];
			switch (curr_field->type) {
			case MMDP_NORMAL:
				size += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				size += sizeof_ser_struct_client(config, curr_field->body.struc.id,
								 *((void **)(((uint8_t *)src) + curr_field->offset)));
				break;
			case MMDP_ARRAY:
				size +=
				    curr_field->body.array.size *
				    (*((uint32_t *)(((uint8_t *)src) +
						    curr_struct->fields[curr_field->body.array.depends_id].offset)));
				break;
			case MMDP_STRUCT_ARRAY:
				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					return 0;
				}
				for (j = 0;
				     j < *((uint32_t *)(((uint8_t *)src) +
							(curr_struct->fields[curr_field->body.struct_array.depends_id]
							     .offset)));
				     j++) {
					size += sizeof_ser_struct_client(
					    config, curr_field->body.struct_array.id,
					    (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) + j * struct_size);
				}
				break;
			}
		}
	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		size = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].sizeof_func(src);
	}

	return size;
}
/* returns NULL on fail */
/* on success this fuction will fillout sizeof_ser_struct_server(config, id,
 * src) bytes and return pointer pointing to byte after the serialized struct*/
/* on fail dest will be left in corrupted state */
void *ser_struct_client(struct mmdp_clientside_config *config, uint32_t id, void *dest, const void *src) {
	uint8_t *ptr;
	uint32_t i, j;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t struct_size;

	ptr = NULL;
	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
			return NULL;
		}
		ptr = dest;
		curr_struct = mmdp_capability.mmdp_structs + id;
		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_order[id][i] == UINT32_MAX) {
				break;
			}
			curr_field = curr_struct->fields + config->field_order[id][i];
			switch (curr_field->type) {
			case MMDP_NORMAL:
				memcpy(ptr, ((uint8_t *)src) + curr_field->offset, curr_field->body.normal.size);
				swap_bytes_little(ptr, curr_field->body.normal.size);
				ptr += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				if (*((void **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type MMDP_STRUCT "
					       "must not be NULL\n");
					return NULL;
				}
				ptr = ser_struct_client(config, curr_field->body.struc.id, ptr,
							*((void **)(((uint8_t *)src) + curr_field->offset)));
				if (ptr == NULL) {
#ifdef DEBUG
					printf("unable to serialize struct\n");
#endif
					return NULL;
				}
				break;
			case MMDP_ARRAY:
				if (*((uint32_t *)(((uint8_t *)src) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset)) ==
				    0) {
					break;
				}
				if (*((uint8_t **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type MMDP_ARRAY "
					       "is NULL, but DEPENDS_ON is not "
					       "zero\n");
					return NULL;
				}
				for (j = 0;
				     j <
				     (*((uint32_t *)(((uint8_t *)src) +
						     curr_struct->fields[curr_field->body.array.depends_id].offset)));
				     j++) {
					memcpy(ptr,
					       (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) +
						   j * curr_field->body.array.size,
					       curr_field->body.array.size);
					swap_bytes_little(ptr, curr_field->body.array.size);
					ptr += curr_field->body.array.size;
				}
				break;
			case MMDP_STRUCT_ARRAY:

				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					return NULL;
				}
				if (*((uint32_t *)(((uint8_t *)src) +
						   (curr_struct->fields[curr_field->body.struct_array.depends_id]
							.offset))) == 0) {
					break;
				}
				if (*((uint8_t **)(((uint8_t *)src) + curr_field->offset)) == NULL) {
					printf("MMDP: field of type "
					       "MMDP_STRUCT_ARRAY is NULL, but "
					       "DEPENDS_ON is not zero\n");
					return NULL;
				}
				for (j = 0;
				     j < *((uint32_t *)(((uint8_t *)src) +
							(curr_struct->fields[curr_field->body.struct_array.depends_id]
							     .offset)));
				     j++) {
					ptr = ser_struct_client(
					    config, curr_field->body.struct_array.id, ptr,
					    (*((uint8_t **)(((uint8_t *)src) + curr_field->offset))) + j * struct_size);
					if (ptr == NULL) {
#ifdef DEBUG
						printf("unable to serialize "
						       "struct\n");
#endif
						return NULL;
					}
				}
				break;
			}
		}

	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
			return NULL;
		}
		ptr = dest;
		ptr = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].ser_func(ptr, src);
		return ptr;
	}
	return ptr;
}
/* TODO: fix memory leak in fail_mmdp_clean since structs can have its ovn allocations made */
/* returns pointer to byte AFTER last byte of serialized struct */
const void *deser_struct_client(struct mmdp_clientside_config *config, uint32_t id, void *dest, const void *src,
				uint32_t max_size) {
	const uint8_t *ptr;
	uint32_t i, j;
	struct mmdp_struct *curr_struct;
	struct mmdp_field *curr_field;
	uint32_t nmemb_array;
	uint8_t *array;
	uint8_t *struc;
	uint32_t struct_size;
	const uint8_t *saved_ptr;

	ptr = NULL;
	if (id < mmdp_capability.mmdp_struct_num) {
		if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
			return NULL;
		}
		ptr = src;
		curr_struct = mmdp_capability.mmdp_structs + id;

		for (i = 0; i < curr_struct->fields_num; i++) {
			if (config->field_order[id][i] == UINT32_MAX) {
				break;
			}
			curr_field = curr_struct->fields + config->field_order[id][i];
			/* since we sorted mmdp_capability the normal will be
			 * first */
			printf("type: %d (arr=%d)\n", curr_field->type, MMDP_ARRAY);
			switch (curr_field->type) {
			case MMDP_NORMAL:
				if (max_size < curr_field->body.normal.size) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				memcpy(((uint8_t *)dest) + curr_field->offset, ptr, curr_field->body.normal.size);
				swap_bytes_little(((uint8_t *)dest) + curr_field->offset, curr_field->body.normal.size);
				max_size -= curr_field->body.normal.size;
				ptr += curr_field->body.normal.size;
				break;
			case MMDP_STRUCT:
				if (curr_field->body.struc.id < mmdp_capability.mmdp_struct_num) {
					struct_size = mmdp_capability.mmdp_structs[curr_field->body.struc.id]._size;
				} else if (curr_field->body.struc.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struc.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					goto mmdp_fail_clean;
				}
				struc = malloc(struct_size);
				if (struc == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}

				saved_ptr = ptr;
				ptr = deser_struct_client(config, curr_field->body.struc.id, struc, ptr, max_size);
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = struc;
				if (ptr == NULL) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				max_size -= ptr - saved_ptr;
				break;
			case MMDP_ARRAY:
				nmemb_array =
				    *((uint32_t *)(((uint8_t *)dest) +
						   curr_struct->fields[curr_field->body.array.depends_id].offset));
				if (nmemb_array == 0) {
					*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
					break;
				}
				if (max_size < nmemb_array * curr_field->body.array.size) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				if (max_size < nmemb_array * curr_field->body.array.size) {
#ifdef DEBUG
					printf("max_size too small while "
					       "deserializing %s\n",
					       curr_field->net_name);
#endif
					goto mmdp_fail_clean;
				}
				max_size -= nmemb_array * curr_field->body.array.size;

				array = malloc(nmemb_array * curr_field->body.array.size);
				if (array == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = array;
				printf("array: %p\n", array);
				for (j = 0; j < nmemb_array; j++) {
					memcpy(array + j * curr_field->body.array.size, ptr,
					       curr_field->body.array.size);
					swap_bytes_little(array + j * curr_field->body.array.size,
							  curr_field->body.array.size);
					ptr += curr_field->body.array.size;
				}
				break;
			case MMDP_STRUCT_ARRAY:
				if (curr_field->body.struct_array.id < mmdp_capability.mmdp_struct_num) {
					struct_size =
					    mmdp_capability.mmdp_structs[curr_field->body.struct_array.id]._size;
				} else if (curr_field->body.struct_array.id <
					   mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
					struct_size = mmdp_capability
							  .custom_structs[curr_field->body.struct_array.id -
									  mmdp_capability.mmdp_struct_num]
							  ._size;
				} else {
#ifdef DEBUG
					printf("SOMETHINGS WRONG, I CAN FEEL "
					       "IT\n");
#endif
					goto mmdp_fail_clean;
				}
				nmemb_array = *(
				    (uint32_t *)(((uint8_t *)dest) +
						 curr_struct->fields[curr_field->body.struct_array.depends_id].offset));
				if (nmemb_array == 0) {
					*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
					break;
				}
				array = malloc(nmemb_array * struct_size);
				if (array == NULL) {
					perror("malloc");
					goto mmdp_fail_clean;
				}
				*((void **)(((uint8_t *)dest) + curr_field->offset)) = array;

				for (j = 0; j < nmemb_array; j++) {
					saved_ptr = ptr;
					ptr = deser_struct_client(config, curr_field->body.struct_array.id,
								  array + j * struct_size, ptr, max_size);
					if (ptr == NULL) {
#ifdef DEBUG
						printf("unable to deserialize "
						       "struct\n");
#endif
						goto mmdp_fail_clean;
					}
					max_size -= ptr - saved_ptr;
				}
				break;
			}
		}

	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
			return NULL;
		}
		ptr = src;
		printf("max_size: %u\n", max_size);
		ptr = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].deser_func(dest, ptr,
												      max_size);
		if (ptr == NULL) {
			printf("unble to deserialize custom struct %s\n",
			       mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].net_name);
			return NULL;
		}
		/* here we dont need to decrement max_size since we will quit
		 * anyways */
		return ptr;
	}
	return ptr;
mmdp_fail_clean:
	for (; i > 0; i--) {
		curr_field = curr_struct->fields + i;
		switch (curr_field->type) {
		case MMDP_STRUCT:
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		case MMDP_ARRAY:
			nmemb_array = *((uint32_t *)(((uint8_t *)dest) +
						     curr_struct->fields[curr_field->body.array.depends_id].offset));
			if (nmemb_array == 0) {
				break;
			}
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		case MMDP_STRUCT_ARRAY:
			nmemb_array =
			    *((uint32_t *)(((uint8_t *)dest) +
					   curr_struct->fields[curr_field->body.struct_array.depends_id].offset));
			if (nmemb_array == 0) {
				break;
			}
			free(*((void **)(((uint8_t *)dest) + curr_field->offset)));
			*((void **)(((uint8_t *)dest) + curr_field->offset)) = NULL;
			break;
		default:
			break;
		}
	}
	return NULL;
}
int send_struct_server(struct mmdp_serverside_config *config, uint32_t id, uint32_t fd, const void *src,
		       void *write_context) {
	uint32_t size;
	void *packet;
	uint8_t *ptr;
	if (config->struct_mask[id] != 0xff) {
#ifdef DEBUG
		printf("Attempted to send masked struct\n");
#endif
		return -1;
	}
	size = 8 + sizeof_ser_struct_server(config, id, src);
	packet = malloc(size);
	if (packet == NULL) {
		perror("malloc");
		return -1;
	}
	memset(packet, 0, size);
	ptr = packet;
	*((uint32_t *)ptr) = htonl(id);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(size - 8);
	ptr += 4;
	if (ser_struct_server(config, id, ptr, src) == NULL) {
#ifdef DEBUG
		printf("Unable to serialize struct\n");
#endif
		free(packet);
		return -1;
	}
	if (mmdp_write(fd, packet, size, write_context) != 0) {
		free(packet);
		return -1;
	}
	free(packet);
	packet = NULL;
	return 0;
}
/* even on fail (when id is invalid) it reads at least 8 bytes from fd */
int recv_struct_server(struct mmdp_serverside_config *config, uint32_t id, uint32_t fd, void *dest,
		       void *read_context) {
	uint8_t data[8];
	uint32_t packet_id;
	uint32_t size;
	void *ser_struct_buffer;
	if (config->struct_mask[id] != 0xff) {
#ifdef DEBUG
		printf("Attempted to recv masked struct\n");
#endif
		return -1;
	}
	if (mmdp_read(fd, data, 8, read_context) != 0) {
		perror("mmdp_read failed");
		return -1;
	}
	packet_id = ntohl(*((uint32_t *)data));
	size = ntohl(*((uint32_t *)(data + 4)));
	if (packet_id != id) {
#ifdef DEBUG
		printf("packet_id and id dont match\n");
#endif
		return -1;
	}
	if (size > hard_limit_post_conn) {
		printf("MMDP: not able to recv struct since it is too big\n");
		return -1;
	}

	ser_struct_buffer = malloc(size);
	if (ser_struct_buffer == NULL) {
		perror("malloc");
		return -1;
	}
	if (mmdp_read(fd, ser_struct_buffer, size, read_context) != 0) {
		perror("mmdp_read failed");
		free(ser_struct_buffer);
		return -1;
	}
	if (deser_struct_server(config, id, dest, ser_struct_buffer, size) == NULL) {
#ifdef DEBUG
		printf("unable to deser struct\n");
#endif
		free(ser_struct_buffer);
		return -1;
	}
	free(ser_struct_buffer);
	ser_struct_buffer = NULL;
	return 0;
}
void *recv_struct_server_any(struct mmdp_serverside_config *config, uint32_t *out_id, uint32_t fd, void *read_context) {
	uint8_t data[8];
	uint32_t id;
	uint32_t size;
	void *ser_struct_buffer;
	void *struct_out;
	uint32_t struct_size;
	if (mmdp_read(fd, data, 8, read_context) != 0) {
		perror("mmdp_read failed");
		return NULL;
	}
	id = ntohl(*((uint32_t *)data));
	size = ntohl(*((uint32_t *)(data + 4)));

	/* check if id is in bounds and also fillout struct_size */
	if (id < mmdp_capability.mmdp_struct_num) {
		struct_size = mmdp_capability.mmdp_structs[id]._size;
	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		struct_size = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num]._size;
	} else {
#ifdef DEBUG
		printf("ID not supported\n");
#endif
		return NULL;
	}
	if (config->struct_mask[id] != 0xff) {
#ifdef DEBUG
		printf("Client sent masked struct\n");
#endif
		return NULL;
	}
	if (size > hard_limit_post_conn) {
		printf("MMDP: not able to recv struct since it is too big\n");
		return NULL;
	}
	ser_struct_buffer = malloc(size);
	if (ser_struct_buffer == NULL) {
		perror("malloc");
		return NULL;
	}
	if (mmdp_read(fd, ser_struct_buffer, size, read_context) != 0) {
		perror("mmdp_read failed");
		free(ser_struct_buffer);
		return NULL;
	}
	struct_out = malloc(struct_size);
	if (struct_out == NULL) {
		perror("malloc");
		free(ser_struct_buffer);
		return NULL;
	}
	memset(struct_out, 0, struct_size);
	if (deser_struct_server(config, id, struct_out, ser_struct_buffer, size) == NULL) {
#ifdef DEBUG
		printf("unable to deser struct\n");
#endif
		free(ser_struct_buffer);
		free(struct_out);
		return NULL;
	}
	free(ser_struct_buffer);
	ser_struct_buffer = NULL;
	*out_id = id;
	return struct_out;
}
int send_struct_client(struct mmdp_clientside_config *config, uint32_t id, uint32_t fd, const void *src,
		       void *write_context) {
	uint32_t size;
	void *packet;
	uint8_t *ptr;
	if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
#ifdef DEBUG
		printf("Attempted to send masked struct\n");
#endif
		return -1;
	}
	size = 8 + sizeof_ser_struct_client(config, id, src);
	packet = malloc(size);
	if (packet == NULL) {
		perror("malloc");
		return -1;
	}
	memset(packet, 0, size);
	ptr = packet;
	*((uint32_t *)ptr) = htonl(config->c_to_s_struct_remap[id]);
	ptr += 4;
	*((uint32_t *)ptr) = htonl(size - 8);
	ptr += 4;
	if (ser_struct_client(config, id, ptr, src) == NULL) {
#ifdef DEBUG
		printf("Unable to serialize struct\n");
#endif
		free(packet);
		return -1;
	}
	if (mmdp_write(fd, packet, size, write_context) != 0) {
		free(packet);
		return -1;
	}
	free(packet);
	packet = NULL;
	return 0;
}
/* when -1 is returned (when id is invalid) it reads at least 8 bytes from fd */
/* when -2 is returned no bytes are read from fd */
/* when -3 is returned it read undefined bytes (is recommened to restart
 * communication) */
int recv_struct_client(struct mmdp_clientside_config *config, uint32_t id, uint32_t fd, void *dest,
		       void *read_context) {
	uint8_t data[8];
	uint32_t packet_id;
	uint32_t size;
	void *ser_struct_buffer;

	if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
#ifdef DEBUG
		printf("Attempted to recv masked struct\n");
#endif
		return -2;
	}
	if (mmdp_read(fd, data, 8, read_context) != 0) {
		perror("mmdp_read failed");
		return -3;
	}
	packet_id = ntohl(*((uint32_t *)data));
	size = ntohl(*((uint32_t *)(data + 4)));

	if (packet_id >= config->s_mmdp_struct_num + config->s_custom_struct_num) {
#ifdef DEBUG
		printf("packet_id is too big\n");
#endif
		return -1;
	}

	packet_id = config->s_to_c_struct_remap[packet_id];
	if (packet_id != id) {
#ifdef DEBUG
		printf("packet_id and id dont match\n");
#endif
		return -1;
	}

	if (size > hard_limit_post_conn) {
		printf("MMDP: not able to recv struct since it is too big\n");
		return -1;
	}
	ser_struct_buffer = malloc(size);
	if (ser_struct_buffer == NULL) {
		perror("malloc");
		return -1;
	}
	if (mmdp_read(fd, ser_struct_buffer, size, read_context) != 0) {
		perror("mmdp_read failed");
		free(ser_struct_buffer);
		return -3;
	}
	if (deser_struct_client(config, id, dest, ser_struct_buffer, size) == NULL) {
#ifdef DEBUG
		printf("unable to deser struct\n");
#endif
		free(ser_struct_buffer);
		return -1;
	}
	free(ser_struct_buffer);
	ser_struct_buffer = NULL;
	return 0;
}
void *recv_struct_client_any(struct mmdp_clientside_config *config, uint32_t *out_id, uint32_t fd, void *read_context) {
	uint8_t data[8];
	uint32_t id;
	uint32_t size;
	void *ser_struct_buffer;
	void *struct_out;
	uint32_t struct_size;
	if (mmdp_read(fd, data, 8, read_context) != 0) {
		perror("mmdp_read failed");
		return NULL;
	}
	id = htonl(*((uint32_t *)data));
	size = htonl(*((uint32_t *)(data + 4)));

	/* check if id is in bounds and also fillout struct_size */
	if (id < mmdp_capability.mmdp_struct_num) {
		struct_size = mmdp_capability.mmdp_structs[id]._size;
	} else if (id < mmdp_capability.mmdp_struct_num + mmdp_capability.custom_struct_num) {
		struct_size = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num]._size;
	} else {
#ifdef DEBUG
		printf("ID not supported\n");
#endif
		return NULL;
	}
	if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
#ifdef DEBUG
		printf("Client sent masked struct\n");
#endif
		return NULL;
	}
	if (size > hard_limit_post_conn) {
		printf("MMDP: not able to recv struct since it is too big\n");
		return NULL;
	}
	ser_struct_buffer = malloc(size);
	if (ser_struct_buffer == NULL) {
		perror("malloc");
		return NULL;
	}
	if (mmdp_read(fd, ser_struct_buffer, size, read_context) != 0) {
		perror("mmdp_read failed");
		free(ser_struct_buffer);
		return NULL;
	}
	struct_out = malloc(struct_size);
	if (struct_out == NULL) {
		perror("malloc");
		free(ser_struct_buffer);
		return NULL;
	}
	memset(struct_out, 0, struct_size);
	if (deser_struct_client(config, id, struct_out, ser_struct_buffer, size) == NULL) {
#ifdef DEBUG
		printf("unable to deser struct\n");
#endif
		free(ser_struct_buffer);
		free(struct_out);
		return NULL;
	}
	free(ser_struct_buffer);
	ser_struct_buffer = NULL;
	*out_id = id;
	return struct_out;
}
/* is NOT thread-safe */
int init_mmdp_lib(uint32_t c_struct_num, struct mmdp_custom_struct *c_structs, int is_server) {
	if (generate_capability(c_struct_num, c_structs) != 0) {
		printf("MMDP: Unable to generate format\n");
		return -1;
	}
	if (is_server == 0) {
		/* it is a client */
		return 0;
	}
	/* it is a server */
	_mmdp_chache_ser_server_cap = serialize_capability(&_mmdp_chache_ser_server_cap_size, &mmdp_capability);
	if (_mmdp_chache_ser_server_cap == NULL) {
		printf("MMDP: Unable to serialize capability\n");
		return -1;
	}

	return 0;
}
int init_connection_config_server(int fd, struct mmdp_serverside_config *conf_dest, void *write_context,
				  void *read_context) {
	uint32_t size;
	void *ser_serverconfig;
	if (mmdp_write(fd, _mmdp_chache_ser_server_cap, _mmdp_chache_ser_server_cap_size, write_context) != 0) {
		printf("MMDP: Unable to write serialized capability\n");
		return -1;
	}
	if (mmdp_read(fd, &size, 4, read_context) != 0) {
		printf("MMDP: Unable to read serialized serverconfig size\n");
		return -1;
	}
	size = ntohl(size);
	if (size > hard_limit_pre_conn) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");
		return -1;
	}
	ser_serverconfig = malloc(size);
	if (ser_serverconfig == NULL) {
		perror("malloc");
		return -1;
	}
	memset(ser_serverconfig, 0, size);
	if (mmdp_read(fd, ser_serverconfig, size, read_context) != 0) {
		printf("MMDP: Unable to read serialized serverconfig\n");
		free(ser_serverconfig);
		return -1;
	}

	if (serverside_from_ser(conf_dest, ser_serverconfig, size) != 0) {
		printf("MMDP: Unable to deserialize serialized serverconfig\n");
		free(ser_serverconfig);
		return -1;
	}
	free(ser_serverconfig);
	return 0;
}
/* TODO: fix leaks here */
int init_connection_config_client(int fd, struct mmdp_clientside_config *conf_dest, void *write_context,
				  void *read_context) {
	uint32_t size;
	void *ser_cap_s;
	struct mmdp_capability server_cap;
	uint32_t size_ser_ss_config;
	void *ser_ss_config;

	if (mmdp_read(fd, &size, 4, read_context) != 0) {
		printf("MMDP: Unable to read serialized capability size\n");
		return -1;
	}
	size = ntohl(size);
	if (size > hard_limit_pre_conn) {
		printf("MMDP: rejecting connection since we would allocate "
		       "more than hardlimit\n");
		return -1;
	}
	ser_cap_s = malloc(size);
	if (ser_cap_s == NULL) {
		perror("malloc");
		return -1;
	}
	if (mmdp_read(fd, ser_cap_s, size, read_context) != 0) {
		printf("MMDP: Unable to read serialized capability\n");
		free(ser_cap_s);
		return -1;
	}
	if (deserialize_capability(ser_cap_s, size, &server_cap) != 0) {
		printf("MMDP: Unable to deserialize capability\n");
		free(ser_cap_s);
		return -1;
	}
	if (create_clientside_config(&server_cap, conf_dest) != 0) {
		printf("MMDP: Unable to create config\n");
		free(ser_cap_s);
		return -1;
	}
	free_capability_heap(&server_cap);
	ser_ss_config = convert_clientside_to_serealized_serverside(conf_dest, &size_ser_ss_config);
	if (ser_ss_config == NULL) {
		printf("MMDP: Unable to serialize config\n");
		free(ser_cap_s);
		return -1;
	}
	if (mmdp_write(fd, ser_ss_config, size_ser_ss_config, write_context) != 0) {
		printf("MMDP: Unable to send serialized config\n");
		free(ser_cap_s);
		free(ser_ss_config);
		return -1;
	}
	free(ser_ss_config);
	free(ser_cap_s);
	return 0;
}
void free_server_config(struct mmdp_serverside_config *config) {
	uint32_t i;
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		free(config->field_mask[i]);
		config->field_mask[i] = NULL;
	}
	free(config->field_mask);
	config->field_mask = NULL;
	free(config->struct_mask);
	config->struct_mask = NULL;
}

void free_client_config(struct mmdp_clientside_config *config) {
	uint32_t i;
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		free(config->field_order[i]);
		config->field_order[i] = NULL;
	}
	free(config->field_order);
	config->field_order = NULL;
	free(config->c_to_s_struct_remap);
	config->c_to_s_struct_remap = NULL;
	free(config->s_to_c_struct_remap);
	config->s_to_c_struct_remap = NULL;
}
