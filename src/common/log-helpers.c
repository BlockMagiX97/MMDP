#include <stdint.h>
#include <stdio.h>
#include <common/log-helpers.h>

void print_b8(uint8_t num) {
	int i;
	for (i = sizeof(uint8_t) * 8 - 1; i >= 0; i--) {
		printf("%d", (num >> i) & 1);
		if (i % 4 == 0)
			printf(" ");
	}
	printf("\n");
}
void print_b32(uint32_t num) {
	int i;
	for (i = sizeof(uint32_t) * 8 - 1; i >= 0; i--) {
		printf("%d", (num >> i) & 1);
		if (i % 8 == 0)
			printf(" ");
	}
	printf("\n");
}
