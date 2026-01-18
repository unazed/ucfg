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
SOURCES = $(wildcard src/*.c) $(wildcard src/pe/*.c)

ANALYZE_CFLAGS = --analyze -Xanalyzer -analyzer-output=html
ANALYZE_OUT = analyze-reports

all: build/test

.PHONY: analyze
analyze: $(SOURCES)
	@mkdir -p analyze-reports
	@for f in $(SOURCES); do \
		echo "Analyzing $$f"; \
		$(CC) $(CFLAGS) --analyze -Xanalyzer -analyzer-output=html \
			-Xanalyzer -output-dir=analyze-reports $$f >/dev/null || exit $$?; \
	done

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/test: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -L$(LDLIBPATH) $(LDFLAGS)

-include $(OBJ:.o=.d)