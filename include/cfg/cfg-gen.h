#pragma once

#include <capstone/capstone.h>

#include "pe/context.h"
#include "cfg/cfg.h"

typedef struct _cfg_gen_ctx *cfg_gen_ctx_t;

void cfg_gen$free_context (cfg_gen_ctx_t);

__attribute__(( malloc(cfg_gen$free_context, 1) ))
cfg_gen_ctx_t cfg_gen$new_context (
  pe_context_t pe_context, cfg_t cfg, csh handle);

bool cfg_gen$recurse_function_block (
  cfg_gen_ctx_t ctx, vertex_tag_t fn_pred, uint64_t block_address);
bool cfg_gen$recurse_branch_insns (
  cfg_gen_ctx_t ctx, cs_insn* branch_insn, vertex_tag_t pred);