#include <stdbool.h>
#include <string.h>

#include "array.h"
#include "trace.h"

#define MEMBER_ALIGNMENT      (8ull)
#define INITIAL_BYTE_CAPACITY (64ull)

static const struct array_allocopts g_default_allocopts = {
  .alloc_nmemb_increment  = 4,
  .trim_nmemb_threshold   = 8,
  .min_nmemb              = 0,
  .max_nmemb              = 0,
  .hook_memcpy            = memcpy,
  .hook_memmove           = memmove,
  .hook_free              = NULL
};

struct _array
{
  uint8_t* raw;
  size_t capacity;
  size_t nmemb;
  size_t membsize, membsize_unaligned;
  struct array_allocopts allocopts;
};

static bool
is_tuple (array_t array)
{
  auto opts = array->allocopts;
  return opts.min_nmemb && (opts.min_nmemb == opts.max_nmemb);
}

static size_t
get_free_capacity (array_t array)
{
  return array->capacity - array->nmemb * array->membsize;
}

static bool
has_space_for_new (array_t array)
{
  return get_free_capacity (array) >= array->membsize;
}

static void*
get_array_at_unchecked (array_t array, size_t idx)
{
  return &array->raw[array->membsize * idx];
}

static void*
get_array_head (array_t array)
{
  if (!array->capacity)
  {
    $trace_debug ("tried to get head of empty array");
    return NULL;
  }
  return get_array_at_unchecked (array, array->nmemb);
}

static void*
maybe_extend_array (array_t array)
{
  auto allocopts = array->allocopts;
  if (!has_space_for_new (array))
  {
    if (array->allocopts.max_nmemb
        && (array->nmemb == array->allocopts.max_nmemb))
      $abort ("tried to insert data into fixed-size array");
    if (is_tuple (array))
      $abort ("tried to insert data into full tuple");
    size_t new_capacity;
    if (allocopts.max_nmemb)
      new_capacity = array->membsize * $min (
        array->nmemb + allocopts.alloc_nmemb_increment,
        allocopts.max_nmemb);
    else
      new_capacity
        = array->membsize * (array->nmemb + allocopts.alloc_nmemb_increment);
    $trace_debug (
      "extending array capacity from %zu bytes to %zu",
      array->capacity, new_capacity);
    array->capacity = new_capacity;
    array->raw = $chk_realloc (array->raw, array->capacity);
  }
  return get_array_head (array);
}

static void
maybe_downsize_array (array_t array)
{
  auto allocopts = array->allocopts;
  if (!allocopts.trim_nmemb_threshold || is_tuple (array))
    return;
  auto free_nmemb = get_free_capacity (array) / array->membsize;
  size_t nmemb_threshold = allocopts.trim_nmemb_threshold;
  if (free_nmemb >= nmemb_threshold)
  {
    auto new_capacity = array->capacity - nmemb_threshold * array->membsize;
    $trace_debug (
      "downsizing array from %zu bytes to %zu",
      array->capacity, new_capacity);
    array->raw = $chk_realloc (array->raw, new_capacity);
    array->capacity = new_capacity;
  }
}

static void
check_index_bounds (array_t array, size_t idx)
{
  if (idx >= array->nmemb)
  {
    $trace_debug (
      "array has %zu members, %zu (%zu raw) bytes per member, "
      "%zu byte capacity (array at %p, buffer at %p)",
      array->nmemb, array->membsize, array->membsize_unaligned,
      array->capacity, array, array->raw);
    $abort ("tried to access out of bounds array index %zu", idx);
  }
}

array_t
array$new (size_t membsize)
{
  auto array = $chk_allocty (array_t);
  $trace_debug (
    "creating new array with member size: %zu byte(s) (@%p)",
    membsize, array);
  array->allocopts = g_default_allocopts;
  array->membsize = $round_up_to (MEMBER_ALIGNMENT, membsize);
  array->membsize_unaligned = membsize;
  array->capacity = $max (array->membsize, INITIAL_BYTE_CAPACITY);
  array->raw = $chk_allocb (array->capacity);
  return array;
}

array_t
array$from_existing (void* ptr, size_t n, size_t membsize)
{
  auto array = array$new (membsize);
  uint8_t* as_char = ptr;
  for (size_t i = 0; i < n; ++i)
    array$append (array, &as_char[membsize * i]);
  return array;
}

void
array$_default_free_hook (void* ptr)
{
  array_t array = ptr;
  if (array != NULL)
    $chk_free (array->raw);
  $chk_free (array);
}

void
array$free (array_t array)
{
  $trace_debug ("freeing array");
  if (array->allocopts.hook_free != NULL)
    array->allocopts.hook_free (array);
  array$_default_free_hook (array);
}

void*
array$append (array_t array, void* ptrmemb)
{
  $trace_debug ("appending member to array: %p", array);
  auto newmemb = array->allocopts.hook_memcpy (
    maybe_extend_array (array), ptrmemb, array->membsize_unaligned);
  array->nmemb++;
  return newmemb;
}

/* NB: `*_rval` functions won't work on little endian systems, need to create a 
 *     tmp buffer and invert the byteorder
 */

void*
array$append_rval (array_t array, uintmax_t memb)
{
  $strict_assert (
    array->membsize_unaligned <= sizeof (memb),
    "Member size too large to fit in rvalue");
  return array$append (array, &memb);
}

void*
array$insert (array_t array, size_t idx, void* ptrmemb)
{
  if (idx == array->nmemb)
    return array$append (array, ptrmemb);
  check_index_bounds (array, idx);
  maybe_extend_array (array);
  $trace_debug ("inserting new member at index %zu: %p", idx, ptrmemb);
  auto newmemb = get_array_at_unchecked (array, idx);
  array->allocopts.hook_memmove (
    get_array_at_unchecked (array, idx + 1),
    newmemb,
    array->membsize * (array->nmemb - idx));
  array->allocopts.hook_memcpy (newmemb, ptrmemb, array->membsize_unaligned);
  array->nmemb++;
  return newmemb;
}

void
array$remove (array_t array, size_t idx)
{
  check_index_bounds (array, idx);
  if (idx == array->nmemb - 1)
  {
    /* don't leak anything at the tail */
    memset (get_array_at_unchecked (array, idx), 0, array->membsize);
    goto ret;
  }
  array->allocopts.hook_memmove (
    get_array_at_unchecked(array, idx),
    get_array_at_unchecked(array, idx + 1),
    array->membsize * (array->nmemb - idx + 1));
ret:
  array->nmemb--;
  maybe_downsize_array (array);
}

void
array$remove_rval (array_t array, uintmax_t memb)
{
  auto idx = array$find_rval (array, memb);
  if (idx == -1)
    $abort ("tried to remove member which does not exist");
  return array$remove (array, idx);
}

void
array$remove_lval (array_t array, void* memb)
{
  auto idx = array$find (array, memb);
  if (idx == -1)
    $abort ("tried to remove member which does not exist");
  return array$remove (array, idx);
}

ssize_t
array$find (array_t array, void* ptrmemb)
{
  $array_for_each ($, array, void*, memb)
  {
    if (!memcmp ($.memb, ptrmemb, array->membsize_unaligned))
      return $.i;
  }
  return -1;
}

ssize_t
array$find_rval (array_t array, uintmax_t memb)
{
  $strict_assert (
    array->membsize_unaligned <= sizeof (memb),
    "Member size too large to fit in rvalue");
  return array$find (array, &memb);
}

void*
array$at (array_t array, size_t idx)
{
  check_index_bounds (array, idx);
  return get_array_at_unchecked (array, idx);
}

void
array$pop (array_t array, void* into, size_t idx)
{
  check_index_bounds (array, idx);
  auto memb = get_array_at_unchecked (array, idx);
  array->allocopts.hook_memcpy (into, memb, array->membsize_unaligned);
  array$remove (array, idx);
}

void
array$concat (array_t array, array_t other)
{
  $strict_assert (
    array->membsize_unaligned == other->membsize_unaligned,
    "Cannot concatenate size-incompatible arrays");
  $array_for_each ($, other, void*, memb)
  {
    array$append (array, $.memb);
  }
}

bool
array$contains_rval (array_t array, uintmax_t memb)
{
  $strict_assert (
    array->membsize_unaligned <= sizeof (memb),
    "Member size too large to fit in rvalue");
  return array$contains (array, &memb);
}

bool
array$contains (array_t array, void* ptrmemb)
{
  return array$find (array, ptrmemb) != -1;
}

size_t
array$length (array_t array)
{
  return array->nmemb;
}

size_t
array$capacity (array_t array)
{
  return array->capacity / array->membsize;
}

bool
array$is_empty (array_t array)
{
  return !array$length (array);
}

void
array$allocopts (array_t array, struct array_allocopts opts)
{
  if (opts.max_nmemb && (opts.min_nmemb > opts.max_nmemb))
    $abort ("min. allocated members must be equal to or less than maximum");
  array->allocopts.min_nmemb = opts.min_nmemb;
  if (array->nmemb > opts.max_nmemb)
    $abort ("array size exceeds configured maximum");
  array->allocopts.max_nmemb = opts.max_nmemb;
  if ((opts.min_nmemb != opts.max_nmemb) && !opts.alloc_nmemb_increment)
    $abort ("reallocation increment must be positive");
  if (opts.max_nmemb && (opts.trim_nmemb_threshold > opts.max_nmemb))
    $abort ("trim threshold is too large within the capacity constraints");
  array->allocopts.alloc_nmemb_increment = opts.alloc_nmemb_increment;
  $trace_debug (
    "configuring allocation options for array (%p): "
    "min./max. memb=%zu/%zu, alloc. increment=%zu, trim threshold=%zu",
    array, opts.min_nmemb, opts.max_nmemb, opts.alloc_nmemb_increment,
    opts.trim_nmemb_threshold);
  auto min_capacity = opts.min_nmemb * array->membsize;
  array->nmemb = opts.min_nmemb;
  if (array->capacity < min_capacity)
  {
    $trace_debug (
      "growing array (%p) to meet min. capacity constraint "
      "(from %zu to %zu bytes)",
      array, array->capacity, min_capacity);
    array->raw = $chk_realloc (array->raw, min_capacity);
    array->capacity = min_capacity;
  }
}

void
array$set_copy_hooks (
  array_t array, array_memcpy_fn_t hook_memcpy, array_memmove_fn_t hook_memmove)
{
  if (hook_memcpy != NULL)
  {
    $trace_debug ("setting custom array `memcpy` hook: %p", hook_memcpy);
    array->allocopts.hook_memcpy = hook_memcpy;
  }
  else
    array->allocopts.hook_memcpy = memcpy;

  if (hook_memmove != NULL)
  {
    $trace_debug ("setting custom array `memmove` hook: %p", hook_memmove);
    array->allocopts.hook_memmove = hook_memmove;
  }
  else
    array->allocopts.hook_memmove = memmove;
}

void
array$set_free_hook (array_t array, array_free_fn_t hook_free)
{
  $trace_debug ("setting custom array `free` hook: %p", hook_free);
  array->allocopts.hook_free = hook_free;
}