#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"

static bool
lea_reg_mem (
  cfg_sim_ctx_t sim_ctx, uint16_t dst_reg, uint16_t base_reg,
  uint16_t index_reg, int scale, int64_t disp)
{
  uint64_t sib = disp;

  if (base_reg != X86_REG_INVALID)
  {
    $get_regloc_chk(sim_ctx, base_reg, base_regloc, base_mask);
    sib += *base_regloc & base_mask;
  }

  if (index_reg != X86_REG_INVALID)
  {
    $get_regloc_chk(sim_ctx, index_reg, index_regloc, index_mask);
    sib += (*index_regloc * scale) & index_mask;
  }
  
  sim_ctx->fn.set_reg (sim_ctx->state, dst_reg, sib);

  return true;
}

bool
sim_dispatch$binop_reg_mem (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  auto operands = insn->detail->x86.operands;
  auto mem = operands[1].mem;

  switch (insn->id)
  {
#define $binop_case(ins, fn) \
  case ins: \
    return fn ( \
      sim_ctx, operands[0].reg, mem.base, mem.index, mem.scale, mem.disp);

    $binop_case (X86_INS_LEA, lea_reg_mem);

    default:
      $trace_err ("unhandled reg/mem. instruction (%s)", insn->mnemonic);
      return false;
  }
}