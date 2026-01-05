#pragma once

#include "generic.h"

typedef struct _bitmap *bitmap_t;

void bitmap$free (bitmap_t);

__attribute__ (( malloc(bitmap$free, 1) ))
bitmap_t bitmap$new (size_t range);
void bitmap$set (bitmap_t, size_t idx);
void bitmap$set_range (bitmap_t, size_t start, size_t end);
bool bitmap$test (bitmap_t, size_t idx);
bool bitmap$test_any_in_range (bitmap_t, size_t start, size_t end);
bool bitmap$test_all_in_range (bitmap_t, size_t start, size_t end);
size_t bitmap$get_size (bitmap_t bitmap);