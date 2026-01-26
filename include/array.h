#pragma once

#include <string.h>

#include "generic.h"

typedef struct _array *array_t;

typedef typeof (memcpy)* array_memcpy_fn_t;
typedef typeof (memmove)* array_memmove_fn_t;
typedef typeof (free)* array_free_fn_t;

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

  /* user-defined copy/free hooks if array objects need to be copied
   * differently, e.g., to preserve dynamic members, or to simplify finalisation
   *  of dynamic members
   */
  array_memcpy_fn_t hook_memcpy;
  array_memmove_fn_t hook_memmove;
  array_free_fn_t hook_free;
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

void array$_default_free_hook (void*);
void array$free (array_t);

__attribute__ (( malloc(array$free, 1) ))
array_t array$new (size_t membsize);
__attribute__ (( malloc(array$free, 1) ))
array_t array$from_existing (void* ptr, size_t n, size_t membsize);

void* array$append (array_t, void* ptrmemb);
void* array$append_rval (array_t, uintmax_t memb);
void* array$insert (array_t, size_t idx, void* ptrmemb);
void array$remove (array_t, size_t idx);
void array$remove_rval (array_t, uintmax_t memb);
void array$remove_lval (array_t array, void* memb);
void array$pop (array_t, void* into, size_t idx);
void array$concat (array_t, array_t other);
void* array$at (array_t, size_t idx);

size_t array$length (array_t);
size_t array$capacity (array_t);

ssize_t array$find (array_t, void* ptrmemb);
ssize_t array$find_rval (array_t, uintmax_t memb);

bool array$contains (array_t, void* ptrmemb);
bool array$contains_rval (array_t array, uintmax_t memb);
bool array$is_empty (array_t);

void array$set_copy_hooks (
  array_t, array_memcpy_fn_t hook_memcpy, array_memmove_fn_t hook_memmove);
void array$set_free_hook (array_t, array_free_fn_t hook_free);
void array$allocopts (array_t, struct array_allocopts opts);
