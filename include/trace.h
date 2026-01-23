#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "generic.h"

#define $fmt_ansi_white_ul(string) "\e[4;37m" string "\e[0m"
#define $fmt_ansi_red(string) "\e[0;31m" string "\e[0m"
#define $fmt_ansi_red_ul(string) "\e[4;31m" string "\e[0m"
#define $fmt_ansi_green(string) "\e[0;32m" string "\e[0m"
#define $fmt_ansi_blue(string) "\e[0;34m" string "\e[0m"

#define _$fmt_trace(prefix, fmt) \
  "<" prefix "> " __FILE__ ":%d, %s(): " fmt "\n", __LINE__, __func__
#define _$fmt_trace_ul(prefix, fmt) \
  _$fmt_trace(prefix, $fmt_ansi_white_ul (fmt))
#define _$printf_trace(prefix, fmt, ...) \
  printf (_$fmt_trace (prefix, fmt),##__VA_ARGS__)
#define _$printf_trace_ul(prefix, fmt, ...) \
  printf (_$fmt_trace_ul (prefix, fmt),##__VA_ARGS__)

#define $trace(...) _$printf_trace ($fmt_ansi_blue ("std"),##__VA_ARGS__)
#define $trace_err(...) \
  _$printf_trace_ul ($fmt_ansi_red ("error"),##__VA_ARGS__)
#define $abort(fmt, ...) \
  { \
    fprintf ( \
      stderr, _$fmt_trace_ul ($fmt_ansi_red_ul ("abort"), fmt),##__VA_ARGS__); \
    exit (EXIT_FAILURE); \
  }
#define $abort_dbg(fmt, ...) \
  { \
    fprintf ( \
      stderr, _$fmt_trace_ul ($fmt_ansi_red_ul ("abort"), fmt),##__VA_ARGS__); \
    __asm__ ("int3"); \
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
#define $chk_allocb(size) $chk_calloc (sizeof (uint8_t), (size))
#define $chk_allocty(ty) ((ty)$chk_calloc (1, $ptrsize (ty)))
#define $chk_free(ptr) \
  ({ \
    auto _ptr = (ptr); \
    if (_ptr != NULL) \
    { \
      $trace_alloc ("freeing data: %p (" #ptr ")", _ptr); \
      free (_ptr); \
    } \
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
    $trace_alloc ( \
      "realloc: reallocated buffer to %zu bytes (" #ptr ")", \
      (size_t)_size * (size_t)_nmemb); \
    new; \
  })
#define $chk_realloc(ptr, size) $chk_reallocarray (ptr, size, 1)
