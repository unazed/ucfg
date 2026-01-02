#include <assert.h>
#include <string.h>

#include "map.h"
#include "array.h"

#define NR_INITIAL_BUCKETS    (16)
_Static_assert (
  !(NR_INITIAL_BUCKETS & (NR_INITIAL_BUCKETS - 1)),
  "Bucket count should be a power of 2");
#define FNV1A64_PRIME         (1099511628211ull)
#define FNV1A64_OFFSET_BASIS  (14695981039346656037ull)

#define $map_for_each_bucket(tag, map, name) \
  $array_for_each (tag, (map)->buckets, struct map_bucket, name)
#define $bucket_for_each_entry(tag, bucket, name) \
  $array_for_each (tag, (bucket)->entries, struct map_bucket_entry, name)

struct map_bucket_entry
{
  hashnum_t hashnum;
  void* value;
};

struct map_bucket
{
  array_t /* struct map_bucket_entry */ entries; 
};

struct _map
{
  array_t /* struct map_bucket */ buckets;
};

hashnum_t
compute_fnv1a64_hash (void* data, size_t length)
{
  if (length % 8)
    $abort ("cannot compute FNV-1a hash of data with length indivisible by 8");
  uint64_t* as_octet = data;
  hashnum_t hash = FNV1A64_OFFSET_BASIS;
  for (size_t i = 0; i < length / 8; ++i)
    hash = (hash ^ as_octet[i]) * FNV1A64_PRIME;
  return hash;
}

hashnum_t
map$compute_hash_sized (void* buff, size_t size)
{
  $strict_assert ((buff != NULL) || !size, "Invalid parameters");
  if (!(size % 8))
    return compute_fnv1a64_hash (buff, size);
  /* is there a better way to do this? */
  auto rounded_size = $round_up_to (8, size);
  auto copy_buffer = $chk_allocb (rounded_size);
  memcpy (copy_buffer, buff, size);
  auto hash = compute_fnv1a64_hash (copy_buffer, rounded_size);
  $chk_free (copy_buffer);
  return hash;
}

hashnum_t
map$compute_hash (uint64_t octet)
{
  return compute_fnv1a64_hash (&octet, sizeof (octet));
}

size_t
get_bucket_count (map_t map)
{
  auto map_length = array$length (map->buckets);
  $strict_assert (
    !(map_length & (map_length - 1)),
    "Hashmap bucket count must be a power of two");
  return map_length;
}

struct map_bucket*
get_bucket_for_key (map_t map, hashnum_t key)
{
  return (struct map_bucket *)array$at (
    map->buckets, key & (get_bucket_count (map) - 1));
}

map_t
map$new (void)
{
  map_t map = $chk_allocty (map_t);
  map->buckets = array$new (sizeof (struct map_bucket));
  array$allocopts (map->buckets, (struct array_allocopts){
    .min_nmemb = NR_INITIAL_BUCKETS,
    .alloc_nmemb_increment = 1,
  });
  $map_for_each_bucket ($, map, bucket)
  {
    $.bucket->entries = array$new (sizeof (struct map_bucket_entry));
    array$allocopts ($.bucket->entries, (struct array_allocopts){
      .alloc_nmemb_increment = 1,
      .trim_nmemb_threshold = 1
    });
  }
  return map;
}

void
map$free (map_t map)
{
  $map_for_each_bucket ($, map, bucket)
  {
    array$free ($.bucket->entries);
  }
  array$free (map->buckets);
  $chk_free (map);
}

void
map$set (map_t map, hashnum_t key, void* value)
{
  auto bucket = get_bucket_for_key (map, key);
  $strict_assert (bucket.entries != NULL, "Bucket entries array is NULL");
  struct map_bucket_entry entry = { .hashnum = key, .value = value };
  if (array$length (bucket->entries))  /* maybe collision? */
  {
    $bucket_for_each_entry ($, bucket, entry)
    {
      if ($.entry->hashnum == key)
      {
        $trace_debug ("updating map entry for key: %zu", key);
        $.entry->value = value;
        return;
      }
    }
    $trace_debug ("creating map entry for key: %zu (with collision)", key);
  }
  else
    $trace_debug ("creating map entry for key: %zu", key);
  $trace_verbose (
    "map entry for value %p, in bucket %zu",
    value, key & (get_bucket_count (map) - 1));
  array$append (bucket->entries, &entry);
}

void*
map$get (map_t map, hashnum_t key)
{
 auto bucket = get_bucket_for_key (map, key);
 $bucket_for_each_entry ($, bucket, entry)
 {
  if ($.entry->hashnum == key)
    return $.entry->value;
 }
 return NULL;
}

void
map$remove (map_t map, hashnum_t key)
{
  auto bucket = get_bucket_for_key (map, key);
  if (array$is_empty (bucket->entries))
    goto not_found;
  $bucket_for_each_entry ($, bucket, entry)
  {
    if ($.entry->hashnum == key)
    {
      array$remove (bucket->entries, $.i);
      $trace_debug ("removed key from map: %zu", key);
      return;
    }
  }

not_found:
  $trace_debug ("tried to remove key that doesn't exist: %zu", key);
}

bool
map$contains (map_t map, hashnum_t key)
{
  return map$get (map, key) != NULL;
}

bool
map$is_empty (map_t map)
{
  $map_for_each_bucket ($, map, bucket)
  {
    if (!array$is_empty ($.bucket->entries))
      return false;
  }
  return true;
}