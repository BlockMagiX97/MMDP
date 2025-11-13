#include <arpa/inet.h> /* ntoh*,hton* */
#include <errno.h>     /* perror */
#include <fcntl.h>     /* open */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* write */

#include <common/string_helper.h>
#include <common/log-helpers.h>
#include <common/mmdp.h>
#include <server/mmdp-server.h>

void *_mmdp_chache_ser_server_cap;
uint32_t _mmdp_chache_ser_server_cap_size;

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

int serverside_from_ser(struct mmdp_server_config *sconfig, void *serialized_sconfig, uint32_t max_size) {
	uint32_t i, j;
	uint32_t num_mmdp_ser, num_custom_ser, field_num;
	uint32_t id, field_id;
	uint8_t *ptr;
	void **free_ptr;
	int ret;
#ifdef DEBUG
	int fd;

	fd = open("./log/ser_ssconf2", O_CREAT | O_WRONLY, 0666);
	if (fd < 0) {
		perror("open ./log/ser_ssconf2");
	} else {
		write(fd, serialized_sconfig, max_size);
	}
	close(fd);
#endif

	memset(sconfig, 0, sizeof(struct mmdp_server_config));

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

	ptr = serialized_sconfig;
	if (max_size < 4) {
#ifdef DEBUG
		printf("MMDP: max_size is too small while deserializing num_mmdp_ser\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	num_mmdp_ser = ntohl(*((uint32_t *)ptr));
	if (num_mmdp_ser > mmdp_capability.mmdp_struct_num) {
#ifdef DEBUG
		printf("MMDP: deserializing more structs than possible\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	max_size -= 4;
	ptr += 4;
	if (max_size < 4) {
#ifdef DEBUG
		printf("MMDP: max_size is too small while deserializing num_custom_ser\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	num_custom_ser = ntohl(*((uint32_t *)ptr));
	if (num_custom_ser > mmdp_capability.custom_struct_num) {
#ifdef DEBUG
		printf("MMDP: deserializing more structs than possible\n");
#endif
		ret = -1;
		goto fail_field_mask_complete;
	}
	max_size -= 4;
	ptr += 4;
	for (i = 0; i < num_custom_ser; i++) {
		if (max_size < 4) {
#ifdef DEBUG
			printf("MMDP: max_size is too small while deserializing custom_id\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		id = ntohl(*((uint32_t *)ptr));
		max_size -= 4;
		ptr += 4;
		if (id >= mmdp_capability.custom_struct_num) {
#ifdef DEBUG
			printf("MMDP: custom_id is too large\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		if (sconfig->struct_mask[mmdp_capability.mmdp_struct_num + id] == 0xff) {
#ifdef DEBUG
			printf("MMDP: custom_id was sent twice\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		sconfig->struct_mask[mmdp_capability.mmdp_struct_num + id] = 0xff;
	}
	for (i = 0; i < num_mmdp_ser; i++) {
		if (max_size < 4) {
#ifdef DEBUG
			printf("MMDP: max_size is too small while deserializing mmdp_id\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		id = ntohl(*((uint32_t *)ptr));
		max_size -= 4;
		ptr += 4;
		if (id >= mmdp_capability.mmdp_struct_num) {
#ifdef DEBUG
			printf("MMDP: mmdp_id is too large\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		if (sconfig->struct_mask[id] == 0xff) {
#ifdef DEBUG
			printf("MMDP: mmdp_id was sent twice\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		sconfig->struct_mask[id] = 0xff;

		if (max_size < 4) {
#ifdef DEBUG
			printf("MMDP: max_size is too small while deserializing field_num\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		field_num = ntohl(*((uint32_t *)ptr));
		max_size -= 4;
		ptr += 4;
		if (field_num > mmdp_capability.mmdp_structs[id].fields_num) {
#ifdef DEBUG
			printf("MMDP: field_num is too large\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		/* there must be at least one field inside every struct */
		if (field_num < 1) {
#ifdef DEBUG
			printf("MMDP: field_num is too small\n");
#endif
			ret = -1;
			goto fail_field_mask_complete;
		}
		for (j = 0; j < field_num; j++) {
			if (max_size < 4) {
#ifdef DEBUG
				printf("MMDP: max_size is too small while deserializing field_id\n");
#endif
				ret = -1;
				goto fail_field_mask_complete;
			}
			field_id = ntohl(*((uint32_t *)ptr));
			max_size -= 4;
			ptr += 4;
			if (field_id >= mmdp_capability.mmdp_structs[id].fields_num) {
#ifdef DEBUG
				printf("MMDP: field_id is too large\n");
#endif
				ret = -1;
				goto fail_field_mask_complete;
			}
			if (sconfig->field_mask[id][field_id] == 0xff) {
#ifdef DEBUG
				printf("MMDP: field_id was sent twice\n");
#endif
				ret = -1;
				goto fail_field_mask_complete;
			}
			sconfig->field_mask[id][field_id] = 0xff;
		}
	}
	/* check for essentiality */
	/* invalid:	if any essential field is inactive inside active struct
	 * 		if any essential struct is inactive */
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		if (sconfig->struct_mask[i] == 0xff) {
			for (j = 0; j < mmdp_capability.mmdp_structs[i].fields_num; j++) {
				if (IS_FLAG_ACTIVE(mmdp_capability.mmdp_structs[i].fields[j].flags,
						   MMDP_FIELD_IS_ESSENTIAL) &&
				    sconfig->field_mask[i][j] == 0) {
#ifdef DEBUG
					printf("MMDP: field essentiality failed\n");
#endif
					ret = -1;
					goto fail_field_mask_complete;
				}
			}
		} else {
			if (IS_FLAG_ACTIVE(mmdp_capability.mmdp_structs[i].flags, MMDP_IS_ESSENTIAL)) {
#ifdef DEBUG
				printf("MMDP: struct essentiality failed\n");
#endif
				ret = -1;
				goto fail_field_mask_complete;
			}
		}
	}
	ret = 0;
	goto return_func;

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

uint32_t sizeof_ser_struct_server(struct mmdp_server_config *config, uint32_t id, const void *src) {
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
void *ser_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, const void *src) {
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
const void *deser_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, const void *src,
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
void free_struct_server(struct mmdp_server_config *config, uint32_t id, void *struc) {
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
			curr_field = curr_struct->fields + i;
			if (config->field_mask[id][i] != 0xff) {
				continue;
			}
			switch (curr_field->type) {
			case MMDP_STRUCT:
				free_struct_server(config, curr_field->body.struc.id,
						   *((void **)(((uint8_t *)struc) + curr_field->offset)));
				free(*((void **)(((uint8_t *)struc) + curr_field->offset)));
				*((void **)(((uint8_t *)struc) + curr_field->offset)) = NULL;
				break;
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
int send_struct_server(struct mmdp_server_config *config, uint32_t id, const void *src,
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
	if (mmdp_write(packet, size, write_context) != 0) {
		free(packet);
		return -1;
	}
	free(packet);
	packet = NULL;
	return 0;
}
/* even on fail (when id is invalid) it reads at least 8 bytes from fd */
int recv_struct_server(struct mmdp_server_config *config, uint32_t id, void *dest, void *read_context) {
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
	if (mmdp_read(data, 8, read_context) != 0) {
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
	if (mmdp_read(ser_struct_buffer, size, read_context) != 0) {
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
void *recv_struct_server_any(struct mmdp_server_config *config, uint32_t *out_id, void *read_context) {
	uint8_t data[8];
	uint32_t id;
	uint32_t size;
	void *ser_struct_buffer;
	void *struct_out;
	uint32_t struct_size;
	if (mmdp_read(data, 8, read_context) != 0) {
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
	if (mmdp_read(ser_struct_buffer, size, read_context) != 0) {
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
int init_connection_config_server(struct mmdp_server_config *conf_dest, void *write_context,
				  void *read_context) {
	uint32_t size;
	void *ser_serverconfig;
	if (_mmdp_chache_ser_server_cap == NULL) {
		_mmdp_chache_ser_server_cap = serialize_capability(&_mmdp_chache_ser_server_cap_size, &mmdp_capability);
	}
	if (mmdp_write(_mmdp_chache_ser_server_cap, _mmdp_chache_ser_server_cap_size, write_context) != 0) {
		printf("MMDP: Unable to write serialized capability\n");
		return -1;
	}
	if (mmdp_read(&size, 4, read_context) != 0) {
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
	if (mmdp_read(ser_serverconfig, size, read_context) != 0) {
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
void free_server_config(struct mmdp_server_config *config) {
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
int is_struct_active_server(const struct mmdp_server_config *config, enum mmdp_structs id) {
	return config->struct_mask[id] != 0;
}
int is_field_active_server(const struct mmdp_server_config *config, enum mmdp_structs id, uint32_t field_id) {
	if (config->struct_mask[id] != 0) {
		return config->field_mask[id][field_id] != 0;
	}
	return 0;
}
