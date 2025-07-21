#include <stddef.h>
#include <stdlib.h>
/* memcpy */
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "string_helper.h"

/* memcpy with malloc */
void* memdup(const void* src, size_t size) {
	void* out = malloc(size);
	if (out == NULL) {
		return NULL;
	}
	memcpy(out, src, size);
	return out;
}
size_t strnlen(const char *str, size_t size) {
	size_t i=0;
	while (i < size) {
		if (str[i] == '\0') {
			break;
		}
		i++;
	}
	return i;
}
char* strndup(const char *src, size_t size) {
	char* out;
	size_t len = strnlen(src, size);
	out = (char*) malloc(len+1);
	if (out == NULL) {
		return NULL;
	}
	memcpy(out, src, len);
	out[len] = '\0';
	return out;
}
void *mempcpy(void* dest, const void* src, size_t n) {
	return ((uint8_t*)memcpy(dest,src,n))+n;
}
char* stpcpy(char* dst, const char* src) {
	char  *p;

	p = mempcpy(dst, src, strlen(src));
	*p = '\0';

	return p;
}
