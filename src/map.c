#include "map.h"
#include "array.h"

#define NR_INITIAL_BUCKETS  (16)

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

map_t
map$new (void)
{
  map_t map = $chk_allocty (map_t);
  map->buckets = array$new (sizeof (struct map_bucket));
  array$allocopts (map->buckets, (struct array_allocopts){
    .min_nmemb = NR_INITIAL_BUCKETS,
    .alloc_nmemb_increment = 1,
  });
  return map;
}

void
map$free (map_t map)
{
  (void)map;
}

void
map$set (map_t map, hashnum_t key, void* value)
{
  (void)map; (void)key; (void)value;
}

void*
map$get (map_t map, hashnum_t key)
{
 (void)map; (void)key;
 return NULL;
}

void
map$remove (map_t map, hashnum_t key)
{
  (void)map; (void)key;
}

bool
map$contains (map_t map, hashnum_t key)
{
  (void)map; (void)key;
  return false;
}

bool
map$is_empty (map_t map)
{
  (void)map;
  return false;
}