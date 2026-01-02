#pragma once

#include "generic.h"

typedef struct _map *map_t;

typedef uint64_t hashnum_t;
typedef bool (*iter_foreach_t)(void*, hashnum_t, void*);

void map$free (map_t);

__attribute__ (( malloc(map$free, 1) ))
map_t map$new (void);

void map$set (map_t, hashnum_t key, void* value);
void* map$get (map_t, hashnum_t key);
void map$remove (map_t, hashnum_t key);
bool map$contains (map_t, hashnum_t key);
bool map$is_empty (map_t);
hashnum_t map$compute_hash_sized (void* buff, size_t size);
hashnum_t map$compute_hash (uint64_t octet);
void map$for_each_pair (map_t, iter_foreach_t callback, void* data);