CC = clang
OBJCOPY = objcopy

COMMON_CFLAGS = -O0 -ggdb -Wall -Werror -Wextra -Iinclude/ -I/mingw64/include/ \
								-Wno-ignored-attributes -DNO_TRACE_VERBOSE -Wno-unused-function \
								-Wno-unused-parameter -DSTRICT -DNO_TRACE

CFG_DEFS := $(foreach cfg,$(filter CFG_%,$(.VARIABLES)),-D$(cfg))
LDLIBPATH := /mingw64/lib
LDFLAGS = -lcapstone -largp

CFLAGS ?= $(COMMON_CFLAGS) $(CFG_DEFS)

OBJ = $(SOURCES:src/%.c=build/%.o)
SOURCES = $(wildcard src/*.c) $(wildcard src/pe/*.c) $(wildcard src/cfg/*.c) \
					$(wildcard src/cfg/arch/*.c) $(wildcard src/cfg/insns/*.c)

TARGET = ucfg

all: build/$(TARGET)

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -L$(LDLIBPATH) $(LDFLAGS)

-include $(OBJ:.o=.d)