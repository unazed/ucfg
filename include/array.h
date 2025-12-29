#pragma once

#include "generic.h"

typedef struct _array *array_t;

#define $array_for_each(tag, array, ty, varname) \
  for ( \
    struct { size_t i; ty* varname; } tag = { .i = 0, .varname = NULL}; \
    ({ \
      auto _array = (array); \
      auto cond = tag.i < array$length (_array); \
      if (cond) \
        tag.varname = (ty *)array$at (_array, tag.i); \
      cond; \
    }); \
    ++tag.i) 

void array$free (array_t);

__attribute__ (( malloc(array$free, 1) ))
array_t array$new (size_t membsize);

void** array$append (array_t, void* ptrmemb);
void** array$insert (array_t, size_t idx, void* ptrmemb);
void array$remove (array_t, size_t idx);
void** array$at (array_t, size_t idx);
void array$pop (array_t, void* into, size_t idx);
size_t array$length (array_t);