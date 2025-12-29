#pragma once

#include "generic.h"

typedef struct _array *array_t;

struct array_allocopts
{ 
  /* size (in members) by which to grow when capacity is met.
   * cannot be zero, unless the array is a tuple
   */
  size_t alloc_nmemb_increment;

  /* determine minimum/maximum capacity constraints.
   * if `min_nmemb` == `max_nmemb`, then both alloc/trim options are ignored
   * and the array is considered a fixed-size tuple
   */
  size_t min_nmemb, max_nmemb;
  
  /* how many members must be empty before the array is trimmed.
   * can be zero, but the array will never be trimmed
   */
  size_t trim_nmemb_threshold;
};

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
void array$allocopts (array_t, struct array_allocopts opts);
