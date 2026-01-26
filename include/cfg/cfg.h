#pragma once

#include "generic.h"
#include "graph.h"

typedef struct _cfg *cfg_t;

void cfg$free (cfg_t);

__attribute__ (( malloc(cfg$free, 1) ))
cfg_t cfg$new (uint64_t image_base, size_t executable_size);

vertex_tag_t cfg$add_function_block (cfg_t, uint64_t address);
vertex_tag_t cfg$add_function_block_succ (
  cfg_t, vertex_tag_t fn_tag, uint64_t address);
vertex_tag_t cfg$add_basic_block (cfg_t, vertex_tag_t fn_tag, uint64_t address);
vertex_tag_t cfg$add_basic_block_succ (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address);

vertex_tag_t cfg$get_entry_block (cfg_t, vertex_tag_t fn_tag);
vertex_tag_t cfg$get_basic_block (cfg_t, vertex_tag_t fn_tag, uint64_t address);
uint64_t cfg$get_basic_block_rva (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag);
uint64_t cfg$get_basic_block_size (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag);

vertex_tag_t cfg$split_basic_block (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address);
void cfg$connect_basic_blocks (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t a, vertex_tag_t b);

void cfg$set_basic_block_end (
  cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address);
void cfg$set_function_block_sp_offset (
  cfg_t, vertex_tag_t fn_tag, uint64_t offset);

bool cfg$is_address_visited (cfg_t, uint64_t address);

__attribute__(( malloc(array$free, 1) ))
array_t cfg$get_preds (cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag);
array_t cfg$get_succs (cfg_t, vertex_tag_t fn_tag, vertex_tag_t basic_tag);

uint8_t* cfg$new_stack_frame (cfg_t, vertex_tag_t fn_tag);
void cfg$free_stack_frame (cfg_t, vertex_tag_t fn_tag);