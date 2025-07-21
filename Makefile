BUILD_DIR = ./build
CC = gcc
CFLAGS = -O0 --std=c89 -pedantic -r -Wall -Werror -g
LDFLAGS = 

all: $(BUILD_DIR)/server $(BUILD_DIR)/client

mmdp.h: mmdp_config.h mmdp_macro_utils.h mmdp_struct_decl.h
mmdp.c: mmdp.h string_helper.h
server.c: mmdp.h string_helper.h

$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/server: $(BUILD_DIR)/string_helper.o $(BUILD_DIR)/server.o $(BUILD_DIR)/mmdp.o
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/client: $(BUILD_DIR)/string_helper.o $(BUILD_DIR)/client.o $(BUILD_DIR)/mmdp.o
	$(CC) $(LDFLAGS) $^ -o $@

.PHONY: all clean

