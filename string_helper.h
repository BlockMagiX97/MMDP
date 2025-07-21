#include <stddef.h>
#include <stdint.h>
/* memcpy with malloc */
void *memdup(const void* src, size_t size);
size_t strnlen(const char *str, size_t size);
char* strndup(const char *src, size_t size);
void *mempcpy(void* dest, const void* src, size_t n);
char* stpcpy(char* dst, const char* src);
