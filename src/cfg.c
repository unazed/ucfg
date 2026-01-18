#include "cfg.h"
#include "graph.h"
#include "bitmap.h"
#include "array.h"
#include <stdint.h>

struct _cfg_basic_block
{
  uint64_t rva;
  uint64_t size;
  bool is_fallthrough;
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

static struct _cfg_function_block*
get_fn_metadata (cfg_t cfg, vertex_tag_t fn_tag)
{
  return graph$metadata (cfg->functions, fn_tag);
}

static struct _cfg_basic_block*
get_basic_metadata (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag)
{
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  return graph$metadata (fn_meta->basic_blocks, basic_tag);
}

static bool
is_address_in_block_range (struct _cfg_basic_block* meta, uint64_t address)
{
  return meta->rva <= address && (address < (meta->rva + meta->size));
}

static uint64_t
get_block_end (cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag)
{
  auto meta = get_basic_metadata (cfg, fn_tag, basic_tag);
  return meta->rva + meta->size;
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
  bitmap$set (cfg->address_bitmap, address);
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
  bitmap$set (cfg->address_bitmap, address);
  return new_tag;
}

void
cfg$set_basic_block_end (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag, uint64_t address)
{
  auto basic_meta = get_basic_metadata (
    cfg, fn_tag, basic_tag);
  basic_meta->size = address - basic_meta->rva;
  bitmap$set_range (cfg->address_bitmap, basic_meta->rva, address);
}

struct iter_get_basic_block_param
{
  uint64_t out_tag;
  uint64_t comp;
};

static bool
iter_get_basic_block (vertex_tag_t basic_tag, void* metadata, void* param)
{
  struct iter_get_basic_block_param* iter_param = param;
  struct _cfg_basic_block* basic_meta = metadata;
  if (is_address_in_block_range (basic_meta, iter_param->comp))
  {
    iter_param->out_tag = basic_tag;
    return false;
  }
  return true;
}

vertex_tag_t
cfg$get_basic_block (cfg_t cfg, vertex_tag_t fn_tag, uint64_t address)
{
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  struct iter_get_basic_block_param param = { .comp = address };
  if (!graph$for_each_vertex (
      fn_meta->basic_blocks, iter_get_basic_block, &param))
  {
    $trace_debug ("failed to find basic block by address %" PRIx64, address);
    return 0;
  }
  return param.out_tag;
}

uint64_t
cfg$get_basic_block_rva (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag)
{
  auto meta = get_basic_metadata (cfg, fn_tag, basic_tag);
  return meta->rva;
}

uint64_t
cfg$get_basic_block_size (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t basic_tag)
{
  auto meta = get_basic_metadata (cfg, fn_tag, basic_tag);
  return meta->size;
}

vertex_tag_t
cfg$split_basic_block (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t old_tag, uint64_t address)
{
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  auto old_meta = get_basic_metadata (cfg, fn_tag, old_tag);

  $strict_assert (
    is_address_in_block_range (old_meta, address),
    "Address not in scope of specified basic block");
  /* no need to split at beginning */
  if (old_meta->rva == address)
    return old_tag;

  old_meta->is_fallthrough = true;
  auto new_block = cfg$add_basic_block_succ (cfg, fn_tag, old_tag, address);
  cfg$set_basic_block_end (
    cfg, fn_tag, new_block, old_meta->rva + old_meta->size);
  old_meta->size = address - old_meta->rva;

  $array_for_each (
    $, digraph$get_egress (fn_meta->basic_blocks, old_tag),
    vertex_tag_t, vertex)
  {
    digraph$disconnect (fn_meta->basic_blocks, old_tag, *$.vertex);
    digraph$connect (fn_meta->basic_blocks, new_block, *$.vertex);
  }

  return new_block;
}

void
cfg$connect_basic_blocks (
  cfg_t cfg, vertex_tag_t fn_tag, vertex_tag_t a, vertex_tag_t b)
{
  auto fn_meta = get_fn_metadata (cfg, fn_tag);
  digraph$connect (fn_meta->basic_blocks, a, b);
}

bool
cfg$is_address_visited (cfg_t cfg, uint64_t address)
{
  return bitmap$test (cfg->address_bitmap, address);
}