#pragma once

#include <stdio.h>

#include "generic.h"
#include "pe/format.h"
#include "sys/cdefs.h"

typedef struct _pe_context* pe_context_t;

void pe_context$free (pe_context_t pe_context);

__attribute__(( malloc(pe_context$free, 1) ))
pe_context_t pe_context$alloc (void);

__attribute__ (( malloc(pe_context$free, 1)))
pe_context_t pe_context$alloc_from_file (FILE* file);