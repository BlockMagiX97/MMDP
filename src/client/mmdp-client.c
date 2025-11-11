#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/log-helpers.h"
#include "mmdp-client.h"
#include "common/mmdp.h"
#include "common/string_helper.h"

#include <assert.h>
#include <stddef.h>

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
	goto fail_structs_fillout;

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
	/*fail_custom_structs: */
	free(out->custom_structs);
fail_mmdp_structs:
	free(out->mmdp_structs);
return_func:
	return ret;
}
/* creates clientside config according to its own requirements (doesn't account
 * for server requirements for now (will change whe adding not preffered flag))
 */
int create_clientside_config(const struct mmdp_capability *srv_cap, struct mmdp_client_config *out) {
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

	size = sizeof(uint8_t *) * mmdp_capability.mmdp_struct_num;
	out->field_mask = malloc(size);
	if (out->field_mask == NULL) {
		perror("malloc");
		ret = -1;
		goto fail_field_mask;
	}
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		size = sizeof(uint8_t) * mmdp_capability.mmdp_structs[i].fields_num;
		out->field_mask[i] = malloc(size);
		if (out->field_mask[i] == NULL) {
			perror("malloc");
			ret = -1;
			goto fail_field_mask_loop;
		}
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
				       curr_struct->net_name);
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
			if (curr_struct->fields_num <= 0) {
				printf("MMDP_FATAL: %s has no fields\n", curr_struct->net_name);
				ret = -1;
				goto fail_remap_mmdp_field_order;
			}
			for (k = 0; k < curr_struct->fields_num; k++) {
				curr_field = curr_struct->fields + k;
				if (strcmp(curr_field->net_name, srv_field->net_name) != 0) {
					continue;
				}
				out->field_order[i][order] = k;
				out->field_mask[i][k] = 0xff;
				order++;
				break;
			}
		}
		/* now we could possibly save some memory by shrinking the
		 * field_order[i] to the required size. TODO: implement this */
		for (j = 0; j < curr_struct->fields_num; j++) {
			curr_field = curr_struct->fields + j;
			if (IS_FLAG_ACTIVE(curr_field->flags, MMDP_FIELD_IS_ESSENTIAL)) {
				for (k = 0; k < curr_struct->fields_num; k++) {
					if (out->field_order[i][k] == j) {
						goto essential_success;
					} else if (out->field_order[i][k] == UINT32_MAX) {
						break;
					}
				}
				printf("MMDP: essential field (%s) not "
				       "supported by server\n",
				       curr_field->net_name);
				ret = -1;
				goto fail_remap_mmdp_field_order;
			essential_success:
				continue;
			}
		}
	}
	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		for (j = 0; j < srv_cap->custom_struct_num; j++) {
			/* skip if net_names dont match */
			if (strcmp(mmdp_capability.custom_structs[i].net_name, srv_cap->custom_structs[j].net_name) !=
			    0) {
				continue;
			}
			out->c_to_s_struct_remap[mmdp_capability.mmdp_struct_num + i] = out->s_mmdp_struct_num + j;
			out->s_to_c_struct_remap[out->s_mmdp_struct_num + j] = mmdp_capability.mmdp_struct_num + i;
			printf("i: %u, j: %u\n", i, j);
			break;
		}
		if (out->c_to_s_struct_remap[mmdp_capability.mmdp_struct_num + i] == UINT32_MAX) {
			if (IS_FLAG_ACTIVE(mmdp_capability.custom_structs[i].flags, MMDP_IS_ESSENTIAL)) {
#ifdef DEBUG
				printf("essential custom struct (%s) not "
				       "supported by server\n",
				       mmdp_capability.custom_structs[i].net_name);
#endif
				ret = -1;
				goto fail_remap_custom;
			}
		}
	}

#ifdef DEBUG
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		printf("%s: %u\n", mmdp_capability.mmdp_structs[i].net_name, out->c_to_s_struct_remap[i]);
		for (j = 0; j < mmdp_capability.mmdp_structs[i].fields_num; j++) {
			printf("\t%s: %u\n", mmdp_capability.mmdp_structs[i].fields[j].net_name,
			       out->field_order[i][j]);
		}
	}

	for (i = 0; i < mmdp_capability.custom_struct_num; i++) {
		printf("custom %s: %u\n", mmdp_capability.custom_structs[i].net_name,
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
fail_field_mask_complete:
	i = mmdp_capability.mmdp_struct_num;
fail_field_mask_loop:
	for (free_ptr = (void **)(out->field_mask); free_ptr < (void **)(out->field_mask + i); free_ptr++) {
		free(*free_ptr);
		*free_ptr = NULL;
	}
fail_field_mask:
	free(out->field_mask);
	out->field_mask = NULL;
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
void *convert_clientside_to_serealized_serverside(const struct mmdp_client_config *cconfig, uint32_t *out_size) {
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

	for (i = 0; i < cconfig->s_custom_struct_num; i++) {
		if (cconfig->s_to_c_struct_remap[cconfig->s_mmdp_struct_num + i] == UINT32_MAX)
			continue;
		size += 4;
		custom_struct_num++;
	}
	for (i = 0; i < cconfig->s_mmdp_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[i];
		if (client_id == UINT32_MAX)
			continue;
		size += 4;
		size += 4;
		mmdp_struct_num++;
		for (j = 0; j < mmdp_capability.mmdp_structs[client_id].fields_num; j++) {
			if (cconfig->field_order[client_id][j] == UINT32_MAX) {
				break;
			}
			size += 4;
			fields_num[client_id]++;
		}
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
	for (i = 0; i < cconfig->s_custom_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[cconfig->s_mmdp_struct_num + i];
		if (client_id == UINT32_MAX) {
			continue;
		}
		*((uint32_t *)ptr) = htonl(i);
		ptr += 4;
	}
	for (i = 0; i < cconfig->s_mmdp_struct_num; i++) {
		client_id = cconfig->s_to_c_struct_remap[i];
		if (client_id == UINT32_MAX) {
			continue;
		}
		*((uint32_t *)ptr) = htonl(i);
		ptr += 4;
		*((uint32_t *)ptr) = htonl(fields_num[client_id]);
		ptr += 4;
		for (j = 0; j < mmdp_capability.mmdp_structs[client_id].fields_num; j++) {
			if (cconfig->field_order[client_id][j] == UINT32_MAX) {
				break;
			}
			*((uint32_t *)ptr) = htonl(j);
			ptr += 4;
		}
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

uint32_t sizeof_ser_struct_client(struct mmdp_client_config *config, uint32_t id, const void *src) {
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
void *ser_struct_client(struct mmdp_client_config *config, uint32_t id, void *dest, const void *src) {
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
const void *deser_struct_client(struct mmdp_client_config *config, uint32_t id, void *dest, const void *src,
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
			printf("ptr: %p\n", ptr);
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
					printf("%c\n", *ptr);
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
		printf("ptr: %p\n", ptr);
		ptr = mmdp_capability.custom_structs[id - mmdp_capability.mmdp_struct_num].deser_func(dest, ptr,
												      max_size);
		printf("ptr2: %p\n", ptr);
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

int send_struct_client(struct mmdp_client_config *config, uint32_t id, const void *src,
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
	if (mmdp_write(packet, size, write_context) != 0) {
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
int recv_struct_client(struct mmdp_client_config *config, uint32_t id, void *dest, void *read_context) {
	uint8_t data[8];
	uint32_t packet_id;
	uint32_t size;
	void *ser_struct_buffer;
#ifdef DEBUG
	int debugfd;
#endif

	if (config->c_to_s_struct_remap[id] == UINT32_MAX) {
#ifdef DEBUG
		printf("Attempted to recv masked struct\n");
#endif
		return -2;
	}
	if (mmdp_read(data, 8, read_context) != 0) {
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
	printf("packet_id = %u\n", packet_id);
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
	if (mmdp_read(ser_struct_buffer, size, read_context) != 0) {
		perror("mmdp_read failed");
		free(ser_struct_buffer);
		return -3;
	}
#ifdef DEBUG
	debugfd = open("./log/deser_struct1", O_TRUNC | O_CREAT | O_WRONLY, 0666);
	if (debugfd < 0) {
		perror("open ./log/deser_struct1");
	} else {
		write(debugfd, ser_struct_buffer, size);
		close(debugfd);
	}
#endif
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
void *recv_struct_client_any(struct mmdp_client_config *config, uint32_t *out_id, void *read_context) {
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
/* TODO: fix leaks here */
int init_connection_config_client(struct mmdp_client_config *conf_dest, void *write_context,
				  void *read_context) {
	uint32_t size;
	void *ser_cap_s;
	struct mmdp_capability server_cap;
	uint32_t size_ser_ss_config;
	void *ser_ss_config;

	if (mmdp_read(&size, 4, read_context) != 0) {
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
	if (mmdp_read(ser_cap_s, size, read_context) != 0) {
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
	if (mmdp_write(ser_ss_config, size_ser_ss_config, write_context) != 0) {
		printf("MMDP: Unable to send serialized config\n");
		free(ser_cap_s);
		free(ser_ss_config);
		return -1;
	}
	free(ser_ss_config);
	free(ser_cap_s);
	return 0;
}
void free_client_config(struct mmdp_client_config *config) {
	uint32_t i;
	for (i = 0; i < mmdp_capability.mmdp_struct_num; i++) {
		free(config->field_order[i]);
		config->field_order[i] = NULL;
	}
	free(config->field_mask);
	config->field_mask = NULL;
	free(config->field_order);
	config->field_order = NULL;
	free(config->c_to_s_struct_remap);
	config->c_to_s_struct_remap = NULL;
	free(config->s_to_c_struct_remap);
	config->s_to_c_struct_remap = NULL;
}
int is_struct_active_client(const struct mmdp_client_config *config, enum mmdp_structs id) {
	return config->c_to_s_struct_remap[id] != UINT32_MAX;
}
int is_field_active_client(const struct mmdp_client_config *config, enum mmdp_structs id, uint32_t field_id) {
	if (is_struct_active_client(config, id)) {
		return config->field_mask[id][field_id] == 0xff;
	}
	return 0;
}
