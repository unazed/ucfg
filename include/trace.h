#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "generic.h"

#define _$fmt_trace(prefix, fmt) \
  "<" prefix "> " __FILE__ ":%d, %s(): " fmt "\n", __LINE__, __func__
#define _$printf_trace(prefix, fmt, ...) \
  printf (_$fmt_trace (prefix, fmt),##__VA_ARGS__)

#define $trace(...) _$printf_trace ("std",##__VA_ARGS__)
#define $abort(fmt, ...) \
  { \
    fprintf (stderr, _$fmt_trace ("abort", fmt),##__VA_ARGS__); \
    exit (EXIT_FAILURE); \
  }

#define $trace_alloc(...)   ({})
#define $trace_debug(...)   ({})
#define $trace_verbose(...) ({})
/* NB: just using `{}` causes an error if left dangling in a condition with a
 *     suffixed semicolon, like `if (x) $trace_alloc(...) else [...]
 */

#ifndef NO_TRACE
# ifndef NO_TRACE_ALLOC
#   undef $trace_alloc
#   define $trace_alloc(...) _$printf_trace ("alloc",##__VA_ARGS__)
# endif
# ifndef NO_TRACE_DEBUG
#   undef $trace_debug
#   define $trace_debug(...) _$printf_trace ("debug",##__VA_ARGS__)
# endif
# ifndef NO_TRACE_VERBOSE
#   undef $trace_verbose
#   define $trace_verbose(...) _$printf_trace ("verbose",##__VA_ARGS__)
# endif
#endif

#define $chk_calloc(size, nmemb) \
  ({ \
    auto _size = (size); \
    auto _nmemb = (nmemb); \
    void* ptr = calloc (_size, _nmemb); \
    if (ptr == NULL) \
      $abort ( \
        "calloc: failed to allocate %zu bytes", \
        (size_t)_size * (size_t)_nmemb); \
    $trace_alloc ( \
      "calloc: allocated %zu bytes (" #size ")", \
      (size_t)_size * (size_t)_nmemb); \
    ptr; \
  })
#define $chk_free(ptr) \
  ({ \
    auto _ptr = (ptr); \
    $trace_alloc ("freeing data: %p (" #ptr ")", _ptr); \
    free (_ptr); \
  })
#define $chk_reallocarray(ptr, size, nmemb) \
  ({ \
    auto _ptr = (ptr); \
    auto _size = (size); \
    auto _nmemb = (nmemb); \
    void* new = reallocarray (_ptr, _size, _nmemb); \
    if (new == NULL) \
      $abort ( \
        "realloc: failed to reallocate to %zu bytes (" #ptr ")", \
        (size_t)_size * (size_t)_nmemb); \
    new; \
  })
#define $chk_realloc(ptr, size) $chk_reallocarray (ptr, size, 1)
