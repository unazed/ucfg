#pragma once

#include <capstone/capstone.h>

#include "generic.h"

/* nasty work :u */
#define $get_regloc_chk(sim_ctx, reg, regloc, regmask) \
  uint64_t regmask; \
  auto regloc = (sim_ctx)->fn.get_reg ((sim_ctx)->state, &regmask, (reg)); \
  if ((regloc) == NULL) \
  { \
    $trace_err ("indeterminate register (%" PRIu16 ")", (reg)); \
    return false; \
  }

/* fwd. decl */
typedef struct _cfg_sim_ctx *cfg_sim_ctx_t;

bool sim_dispatch$binop_reg_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_reg_imm (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_reg_mem (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$binop_mem_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_mem_imm (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$unop_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$unop_mem (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$nullop (cfg_sim_ctx_t, cs_insn* insn);