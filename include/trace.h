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

#define $trace_alloc(...)   {}
#define $trace_debug(...)   {}
#define $trace_verbose(...) {}

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