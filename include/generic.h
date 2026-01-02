#pragma once

#include <stdbool.h>

#include "trace.h"

#define $ptrsize(ty) (sizeof (*(ty)(0)))
#define $offset_between(ty, memb1, memb2) \
  offsetof (ty, memb2) - offsetof (ty, memb1)
#define $read_type(into, file) \
  read_sized (&(into), sizeof (into), file)

#define $max(a, b) \
  ({ \
    auto _a = (a); \
    auto _b = (b); \
    _a > _b ? _a : _b; \
  })
#define $min(a, b) \
  ({ \
    auto _a = (a); \
    auto _b = (b); \
    _a < _b ? _a : _b; \
  })
#define $round_up_to(mult, n) \
  ({ \
    auto _mult = (mult); \
    auto _n = (n); \
    (_n + _mult - 1) & ~(_mult - 1); \
  })

#ifdef STRICT
# define $strict_assert(cond, msg) \
  ({ \
    if (!(cond)) \
      $abort ("strict assertion failed: " msg " (" #cond ")"); \
  })
#else
# define $strict_assert(cond, msg) ({ })
#endif

#define __builtin_unimplemented() $abort ("unimplemented")
#define auto __auto_type

int read_sized (void* into, size_t size, FILE* file);
int read_asciz (char* into, ssize_t max_length, FILE* file);