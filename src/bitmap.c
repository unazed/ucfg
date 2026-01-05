#include "bitmap.h"
#include "generic.h"

#define $bits_up_to(bit) ((2u << (bit)) - 1)
#define $bits_from(bit) (~((1u << (bit)) - 1))
#define $bits_range(start, end) ($bits_up_to (end) & $bits_from (start))

struct _bitmap
{
  uint8_t* array;
  size_t size;
};

struct bitmap_index
{
  size_t idx;
  size_t offset;
};

bitmap_t
bitmap$new (size_t range)
{
  auto bitmap = $chk_allocty (bitmap_t);
  bitmap->array = $chk_calloc (
    sizeof (*bitmap->array), $round_up_to (8, range) / 8);
  bitmap->size = range;
  $trace_debug ("allocated bitmap with range %zu", range);
  return bitmap;
}

static struct bitmap_index
get_bitmap_index (bitmap_t bitmap, size_t idx)
{
  return (struct bitmap_index){
    .idx = idx / (8 * sizeof (*bitmap->array)),
    .offset = idx % (8 * sizeof (*bitmap->array))
  };
}

void
bitmap$free (bitmap_t bitmap)
{
  $trace_debug ("freeing bitmap at %p", bitmap);
  $chk_free (bitmap->array);
  $chk_free (bitmap);
}

void
bitmap$set (bitmap_t bitmap, size_t idx)
{
  $trace_debug ("trying to set bitmap index %zu (bitmap size %zu)", idx, bitmap->size);
  $strict_assert (idx < bitmap->size, "Bitmap index out of bounds");
  auto index = get_bitmap_index (bitmap, idx);
  bitmap->array[index.idx] |= 1u << index.offset;
}

void
bitmap$set_range (bitmap_t bitmap, size_t start, size_t end)
{
  $strict_assert (
    start < end && end <= bitmap->size,
    "Invalid or out of bounds bitmap indices");
  $trace_debug ("setting bit-range from %zu to %zu exclusive", start, end);
  auto start_index = get_bitmap_index (bitmap, start);
  auto end_index = get_bitmap_index (bitmap, end - 1);

  if (start_index.idx == end_index.idx)
  {
    bitmap->array[start_index.idx] 
      |= $bits_range (start_index.offset, end_index.offset);
    return;
  }

  bitmap->array[start_index.idx] |= $bits_from (start_index.offset);
  for (size_t i = start_index.idx + 1; i < end_index.idx; ++i)
    bitmap->array[i] = (typeof (*bitmap->array))(-1);
  bitmap->array[end_index.idx] |= $bits_up_to (end_index.offset);
}

bool
bitmap$test (bitmap_t bitmap, size_t idx)
{
  $strict_assert (idx < bitmap->size, "Bitmap index out of bounds");
  auto index = get_bitmap_index (bitmap, idx);
  return bitmap->array[index.idx] & (1u << index.offset);
}

bool
bitmap$test_any_in_range (bitmap_t bitmap, size_t start, size_t end)
{
  $strict_assert (
    start < end && end <= bitmap->size,
    "Invalid or out of bounds bitmap indices");
  auto start_index = get_bitmap_index (bitmap, start);
  auto end_index = get_bitmap_index (bitmap, end - 1);

  /* single-member case, e.g. `uint8_t` range [2, 6) */
  if (start_index.idx == end_index.idx)
    return bitmap->array[start_index.idx]
      & $bits_range (start_index.offset, end_index.offset);

  /* partial first index */
  if (bitmap->array[start_index.idx] & $bits_from (start_index.offset))
    return true;
  
  /* middle indices (if any) */
  for (size_t i = start_index.idx + 1; i < end_index.idx; ++i)
    if (bitmap->array[i])
      return true;
  
  /* final index */
  return bitmap->array[end_index.idx] & $bits_up_to (end_index.offset);
}

bool
bitmap$test_all_in_range (bitmap_t bitmap, size_t start, size_t end)
{
  $strict_assert (
    start < end && end <= bitmap->size,
    "Invalid or out of bounds bitmap indices");
  auto start_index = get_bitmap_index (bitmap, start);
  auto end_index = get_bitmap_index (bitmap, end - 1);

  if (start_index.idx == end_index.idx)
  {
    auto mask = $bits_range (start_index.offset, end_index.offset);
    return (bitmap->array[start_index.idx] & mask) == mask;
  }

  auto start_mask = $bits_from (start_index.offset);
  if ((bitmap->array[start_index.idx] & start_mask) != start_mask)
    return false;
  
  for (size_t i = start_index.idx + 1; i < end_index.idx; ++i)
    if (bitmap->array[i] != (typeof (*bitmap->array))(-1))
      return false;
  
  auto end_mask = $bits_up_to (end_index.offset);
  return (bitmap->array[end_index.idx] & end_mask) == end_mask;
}

size_t
bitmap$get_size (bitmap_t bitmap)
{
  return bitmap->size;
}