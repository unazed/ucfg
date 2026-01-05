#pragma once

#include "generic.h"
#include "graph.h"

typedef struct _cfg *cfg_t;

void cfg$free (cfg_t);

__attribute__ (( malloc(cfg$free, 1) ))
cfg_t cfg$new (uint64_t image_base, size_t executable_size);

vertex_tag_t cfg$add_function_block (cfg_t, uint64_t address);
vertex_tag_t cfg$add_function_block_succ (
  cfg_t cfg, vertex_tag_t fn_tag, uint64_t address);
vertex_tag_t cfg$add_basic_block (cfg_t, vertex_tag_t fn_tag, uint64_t address);
vertex_tag_t cfg$add_basic_block_succ (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address);
void cfg$set_basic_block_end (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address);
bool cfg$is_address_overlapping (cfg_t, uint64_t address);