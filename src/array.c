#include <stdbool.h>
#include <string.h>

#include "array.h"
#include "trace.h"

#define MEMBER_ALIGNMENT      (8)
#define INITIAL_BYTE_CAPACITY (256)

static const struct array_allocopts g_default_allocopts = {
  .alloc_nmemb_increment  = 4,
  .trim_nmemb_threshold   = 8,
  .min_nmemb              = 0,
  .max_nmemb              = 0
};

struct _array
{
  uint8_t* raw;
  size_t capacity;
  size_t nmemb;
  size_t membsize, membsize_unaligned;
  struct array_allocopts allocopts;
};

static size_t
round_up_to (size_t mult, size_t n)
{
  return (n + mult - 1) & ~(mult - 1);
}

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
  array_t array = $chk_allocty (array_t);
  $trace_debug (
    "creating new array with member size: %zu byte(s) (@%p)",
    membsize, array);
  array->allocopts = g_default_allocopts;
  array->capacity = INITIAL_BYTE_CAPACITY;
  array->raw = $chk_allocb (array->capacity);
  array->membsize = round_up_to (MEMBER_ALIGNMENT, membsize);
  array->membsize_unaligned = membsize;
  return array;
}

void
array$free (array_t array)
{
  $trace_debug ("freeing array");
  $chk_free (array->raw);
  $chk_free (array);
}

void**
array$append (array_t array, void* ptrmemb)
{
  $trace_debug ("appending member to array: %p", array);
  auto newmemb = memcpy (
    maybe_extend_array (array), ptrmemb, array->membsize_unaligned);
  array->nmemb++;
  return newmemb;
}

void**
array$insert (array_t array, size_t idx, void* ptrmemb)
{
  if (idx == array->nmemb)
    return array$append (array, ptrmemb);
  check_index_bounds (array, idx);
  maybe_extend_array (array);
  $trace_debug ("inserting new member at index %zu: %p", idx, ptrmemb);
  auto newmemb = get_array_at_unchecked (array, idx);
  memmove (
    get_array_at_unchecked (array, idx + 1),
    newmemb,
    array->membsize * (array->nmemb - idx + 1));
  memcpy (newmemb, ptrmemb, array->membsize_unaligned);
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
  memmove (
    get_array_at_unchecked(array, idx),
    get_array_at_unchecked(array, idx + 1),
    array->membsize * (array->nmemb - idx + 1));
ret:
  array->nmemb--;
  maybe_downsize_array (array);
}

void**
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
  memcpy (into, memb, array->membsize_unaligned);
  array$remove (array, idx);
}

size_t
array$length (array_t array)
{
  return array->nmemb;
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
    "min_nmemb=%zu, max_nmemb=%zu, alloc. increment=%zu, trim threshold=%zu",
    array, opts.min_nmemb, opts.max_nmemb, opts.alloc_nmemb_increment,
    opts.trim_nmemb_threshold);
  auto min_capacity = opts.min_nmemb * array->membsize;
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