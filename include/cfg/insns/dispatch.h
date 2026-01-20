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

/* flag setting helpers */
bool
sim_dispatch$update_flags__arith (
  cfg_sim_ctx_t, enum x86_reg reg, uint64_t op_1, uint64_t op_2,
  bool is_sub);
bool sim_dispatch$update_flags__rot (
  cfg_sim_ctx_t, uint64_t shift, uint64_t val, uint8_t reg_width);
bool sim_dispatch$update_flags__logic (cfg_sim_ctx_t, enum x86_reg reg);
bool sim_dispatch$update_flags__shift (
  cfg_sim_ctx_t, enum x86_reg reg, uint64_t shift_count, uint64_t last_bit_out,
  bool is_left);
bool sim_dispatch$update_flags__inc_dec (
  cfg_sim_ctx_t, enum x86_reg reg, uint64_t old_val, bool is_dec);

/* instruction dispatch handlers */
bool sim_dispatch$binop_reg_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_reg_imm (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_reg_mem (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$binop_mem_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$binop_mem_imm (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$unop_reg (cfg_sim_ctx_t, cs_insn* insn);
bool sim_dispatch$unop_mem (cfg_sim_ctx_t, cs_insn* insn);

bool sim_dispatch$nullop (cfg_sim_ctx_t, cs_insn* insn);