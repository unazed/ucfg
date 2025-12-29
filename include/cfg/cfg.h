#pragma once

#include "generic.h"
#include "array.h"

typedef struct cfg_basic_block
{
  uint64_t address;
  uint8_t* raw_data;
  size_t raw_data_length;
  array_t terminals;
} *cfg_basic_block_t;

typedef struct
{
  cfg_basic_block_t blk_entry;
} *cfg_t;