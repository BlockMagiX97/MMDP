INCLUDE_PATH = include
# Compiler and flags
CC = gcc
CFLAGS_COMMON = --std=c89 -Wall -Wextra -Wformat -Wformat=2 -Wconversion -Wimplicit-fallthrough -Werror=format-security -I include
CFLAGS = $(CFLAGS_COMMON) -s -Ofast -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstrict-flex-arrays=3 -fstack-clash-protection -fstack-protector-strong -Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,--no-copy-dt-needed-entries -fPIE -pie -fcf-protection=full -fstack-protector -fstack-protector-all -fstack-protector-strong
CFLAGS_DEBUG = $(CFLAGS_COMMON) -ggdb
DEBUG_ASANITIZE = $(CFLAGS_DEBUG) -fsanitize=address -fno-omit-frame-pointer

SRC_PATH := src
SRC_PATH_CLIENT := $(SRC_PATH)/client
SRC_PATH_SERVER := $(SRC_PATH)/server
SRC_PATH_COMMON := $(SRC_PATH)/common
OBJ_PATH := build/obj
OBJ_PATH_CLIENT := $(OBJ_PATH)/client
OBJ_PATH_SERVER := $(OBJ_PATH)/server
OBJ_PATH_COMMON := $(OBJ_PATH)/common
BIN_PATH := build/bin
SERVER_BIN_NAME := server
CLIENT_BIN_NAME := client
DEPENDS_PATH := build/depends
DEPENDS_PATH_CLIENT := $(DEPENDS_PATH)/client
DEPENDS_PATH_SERVER := $(DEPENDS_PATH)/server
DEPENDS_PATH_COMMON := $(DEPENDS_PATH)/common


SRC_FILES_CLIENT := $(shell find $(SRC_PATH_CLIENT) -name '*.c')
OBJ_FILES_CLIENT := $(patsubst $(SRC_PATH_CLIENT)/%.c,$(OBJ_PATH_CLIENT)/%.o,$(SRC_FILES_CLIENT))

SRC_FILES_SERVER := $(shell find $(SRC_PATH_SERVER) -name '*.c')
OBJ_FILES_SERVER := $(patsubst $(SRC_PATH_SERVER)/%.c,$(OBJ_PATH_SERVER)/%.o,$(SRC_FILES_SERVER))

SRC_FILES_COMMON := $(shell find $(SRC_PATH_COMMON) -name '*.c')
OBJ_FILES_COMMON := $(patsubst $(SRC_PATH_COMMON)/%.c,$(OBJ_PATH_COMMON)/%.o,$(SRC_FILES_COMMON))

all: make-build-dir $(BIN_PATH)/$(CLIENT_BIN_NAME) $(BIN_PATH)/$(SERVER_BIN_NAME) 


debug: CFLAGS = $(CFLAGS_DEBUG)
debug: make-build-dir $(BIN_PATH)/$(CLIENT_BIN_NAME) $(BIN_PATH)/$(SERVER_BIN_NAME)

asan: CFLAGS = $(DEBUG_ASANITIZE)
asan: make-build-dir $(BIN_PATH)/$(CLIENT_BIN_NAME) $(BIN_PATH)/$(SERVER_BIN_NAME)


make-build-dir:
	mkdir -p $(OBJ_PATH_CLIENT) $(OBJ_PATH_SERVER) $(OBJ_PATH_COMMON) $(BIN_PATH) $(DEPENDS_PATH_CLIENT) $(DEPENDS_PATH_SERVER) $(DEPENDS_PATH_COMMON)

$(DEPENDS_PATH_CLIENT)/%.d: $(SRC_PATH_CLIENT)/%.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(DEPENDS_PATH_SERVER)/%.d: $(SRC_PATH_SERVER)/%.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(DEPENDS_PATH_COMMON)/%.d: $(SRC_PATH_COMMON)/%.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


$(BIN_PATH)/$(CLIENT_BIN_NAME): $(OBJ_FILES_CLIENT) $(OBJ_FILES_COMMON)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN_PATH)/$(SERVER_BIN_NAME): $(OBJ_FILES_SERVER) $(OBJ_FILES_COMMON)
	$(CC) $(CFLAGS) $^ -o $@


$(OBJ_PATH_CLIENT)/%.o: $(SRC_PATH_CLIENT)/%.c
	$(CC) $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) -c $< -o $@

$(OBJ_PATH_SERVER)/%.o: $(SRC_PATH_SERVER)/%.c
	$(CC) $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) -c $< -o $@

$(OBJ_PATH_COMMON)/%.o: $(SRC_PATH_COMMON)/%.c
	$(CC) $(CFLAGS) -I $(patsubst $(SRC_PATH)/%,$(INCLUDE_PATH)/%,$(dir $<)) -c $< -o $@

install:
	@install -vpm 755 -o root -g root $(BIN_PATH)/$(CLIENT_BIN_NAME) /usr/bin/

clean:
	rm -fr build

.PHONY: all clean install debug asan

include $(patsubst $(SRC_PATH)/%.c,$(DEPENDS_PATH)/%.d,$(shell find $(SRC_PATH) -name *.c))
