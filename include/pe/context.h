#pragma once

#include <stdio.h>

#include "generic.h"
#include "pe/format.h"
#include "sys/cdefs.h"

#define PE_CONTEXT_LOAD_IMPORT_DIRECTORY (1ull << 0)
#define PE_CONTEXT_LOAD_EXPORT_DIRECTORY (1ull << 1)

typedef struct _pe_context* pe_context_t;

void pe_context$free (pe_context_t pe_context);

__attribute__ (( malloc(pe_context$free, 1)))
pe_context_t pe_context$from_file (FILE* file, uint8_t flags);

