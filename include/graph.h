#pragma once

#include "generic.h"
#include "array.h"

typedef struct _graph *graph_t;

void graph$free (graph_t);

__attribute__ (( malloc(graph$free, 1) ))
graph_t graph$new (void);