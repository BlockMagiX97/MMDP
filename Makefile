BUILD_DIR := build
CC := gcc
CFLAGS := -Ofast
LDFLAGS :=
.PHONY: all clean server client

# top level
all: server client
server: $(BUILD_DIR)/server
client: $(BUILD_DIR)/client
clean:
	rm build/*

# dependencies for library header files here
mmdp_struct_decl.h: mmdp_macro_utils.h
mmdp.h: mmdp_config.h mmdp_macro_utils.h mmdp_struct_decl.h
mmdp-server.h: mmdp.h
mmdp-client.h: mmdp.h

# dependencies for library source files here
log-helpers.c: log-helpers.h
string_helper.c: string_helper.h
mmdp-client.c: mmdp-client.h log-helpers.h mmdp.h string_helper.h
mmdp-server.c: mmdp-server.h log-helpers.h mmdp.h string_helper.h
mmdp.c: mmdp.h string_helper.h log-helpers.h

# dependencies for example user apps
client.c: mmdp.h mmdp-client.h
server.c: mmdp.h mmdp-server.h

# build the object files
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# create example executables
$(BUILD_DIR)/client: $(BUILD_DIR)/client.o $(BUILD_DIR)/mmdp.o $(BUILD_DIR)/mmdp-client.o $(BUILD_DIR)/log-helpers.o $(BUILD_DIR)/string_helper.o
	$(CC) $(LDFLAGS) -o $@ $^ 
$(BUILD_DIR)/server: $(BUILD_DIR)/server.o $(BUILD_DIR)/mmdp.o $(BUILD_DIR)/mmdp-server.o $(BUILD_DIR)/log-helpers.o $(BUILD_DIR)/string_helper.o
	$(CC) $(LDFLAGS) -o $@ $^ 

