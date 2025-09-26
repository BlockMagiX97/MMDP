BUILD_DIR = ./build
CC = gcc
#CFLAGS = -Ofast --std=c89 -pedantic -r -g -fsanitize=undefined -fanalyzer -Wall -Werror -Wno-unused-result
#LDFLAGS = -fsanitize=undefined -fanalyzer
CFLAGS = -Ofast --std=c89 -pedantic -r -g
LDFLAGS = 
all: $(BUILD_DIR)/server $(BUILD_DIR)/client

mmdp.h: mmdp_config.h mmdp_macro_utils.h mmdp_struct_decl.h
mmdp.c: mmdp.h string_helper.h
server.c: mmdp.h mmdp-server.h string_helper.h
client.c: mmdp.h mmdp-client.h string_helper.h

$(BUILD_DIR)/%.o: %.c %.h Makefile
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/server: $(BUILD_DIR)/string_helper.o $(BUILD_DIR)/server.o $(BUILD_DIR)/mmdp.o $(BUILD_DIR)/mmdp-server.o $(BUILD_DIR)/log-helpers.o
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/client: $(BUILD_DIR)/string_helper.o $(BUILD_DIR)/client.o $(BUILD_DIR)/mmdp.o $(BUILD_DIR)/mmdp-client.o $(BUILD_DIR)/log-helpers.o
	$(CC) $(LDFLAGS) $^ -o $@

.PHONY: all clean

