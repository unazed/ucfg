#include "cfg.h"
#include "graph.h"
#include "bitmap.h"

struct _cfg_basic_block
{
  uint64_t rva;
  uint64_t size;
};

struct _cfg_function_block
{
  vertex_tag_t entry_block;
  graph_t basic_blocks;
};

struct _cfg
{
  graph_t functions;
  bitmap_t address_bitmap;
  uint64_t image_base;
};

struct _cfg_function_block*
get_fn_metadata (cfg_t cfg, vertex_tag_t fn_block_tag)
{
  return graph$metadata (cfg->functions, fn_block_tag);
}

struct _cfg_basic_block*
get_basic_metadata (
  cfg_t cfg, vertex_tag_t fn_block_tag, vertex_tag_t basic_block_tag)
{
  auto fn_meta = get_fn_metadata (cfg, fn_block_tag);
  return graph$metadata (fn_meta->basic_blocks, basic_block_tag);
}

cfg_t
cfg$new (uint64_t image_base, uint64_t executable_size)
{
  auto cfg = $chk_allocty (cfg_t);
  cfg->functions = graph$new ();
  cfg->address_bitmap = bitmap$new (executable_size);
  cfg->image_base = image_base;
  return cfg;
}

void
cfg$free (cfg_t cfg)
{
  $chk_free (cfg);
}

vertex_tag_t
cfg$add_function_block (cfg_t cfg, uint64_t address)
{
  $strict_assert (address != 0, "Function address should be non-zero");
  auto metadata = $chk_allocty (struct _cfg_function_block*);
  metadata->basic_blocks = graph$new ();
  auto tag = graph$add_tagged (cfg->functions, address, metadata);
  return tag;
}

vertex_tag_t
cfg$add_function_block_succ (cfg_t cfg, vertex_tag_t fn_tag, uint64_t address)
{
  $strict_assert (address != 0, "Function address should be non-zero");
  auto metadata = $chk_allocty (struct _cfg_function_block*);
  metadata->basic_blocks = graph$new ();
  auto new_tag = graph$add_tagged (cfg->functions, address, metadata);
  digraph$connect (cfg->functions, fn_tag, new_tag);
  return new_tag;
}

vertex_tag_t
cfg$add_basic_block (cfg_t cfg, vertex_tag_t fn_tag, uint64_t address)
{
  $strict_assert (address != 0, "Basic block address should be non-zero");
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  auto basic_meta = $chk_allocty (struct _cfg_basic_block *);
  basic_meta->rva = address; 
  auto tag = graph$add_tagged (fn_meta->basic_blocks, address, basic_meta);
  return tag;
}

vertex_tag_t
cfg$add_basic_block_succ (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address)
{
  $strict_assert (address != 0, "Basic block address should be non-zero");
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  auto basic_meta = $chk_allocty (struct _cfg_basic_block *);
  basic_meta->rva = address; 
  auto new_tag = graph$add_tagged (fn_meta->basic_blocks, address, basic_meta);
  digraph$connect (fn_meta->basic_blocks, basic_tag, new_tag);
  return new_tag;
}

void
cfg$set_basic_block_end (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address)
{
  auto basic_meta = get_basic_metadata (
    cfg, fn_tag, basic_tag);
  basic_meta->size = address - basic_meta->rva;
}

bool
cfg$is_address_overlapping (cfg_t cfg, uint64_t address)
{
  return false;
}