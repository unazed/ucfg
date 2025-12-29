#include <string.h>

#include "array.h"
#include "trace.h"

#define MEMBER_ALIGNMENT      (8)
#define INITIAL_BYTE_CAPACITY (1024)
_Static_assert (
  INITIAL_BYTE_CAPACITY > 0, "Initial array allocation size must be positive");
#define ALLOC_NMEMB_INCREMENT (4)
_Static_assert (
  ALLOC_NMEMB_INCREMENT > 0, "Array reallocation increment must be positive");

struct _array
{
  uint8_t* raw;
  size_t capacity;
  size_t nmemb, membsize, membsize_unaligned;
};

static size_t
round_up_to (size_t mult, size_t n)
{
  return (n + mult - 1) & ~(mult - 1);
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
  if (!has_space_for_new (array))
  {
    auto new_capacity = ALLOC_NMEMB_INCREMENT * array->membsize;
    $trace_debug (
      "extending array capacity from %zu bytes to %zu",
      array->capacity, array->capacity + new_capacity);
    array->capacity += new_capacity;
    array->raw = $chk_realloc (array->raw, array->capacity);
  }
  return get_array_head (array);
}

static void
maybe_downsize_array (array_t array)
{
  auto free_nmemb = get_free_capacity (array) / array->membsize;
  size_t nmemb_threshold = 2 * ALLOC_NMEMB_INCREMENT;
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
  $trace_debug ("appending member to array: %p", ptrmemb);
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