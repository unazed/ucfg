#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"

static bool
push_reg (cfg_sim_ctx_t sim_ctx, uint16_t src_reg)
{
  $get_regloc_chk (sim_ctx, src_reg, regloc, regmask); (void)regmask;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx, src_reg);
  sim_ctx->fn.push_stack (sim_ctx->state, regloc, reg_width);
  return true;
}

static bool
pop_reg (cfg_sim_ctx_t sim_ctx, uint16_t dst_reg)
{
  $get_regloc_chk (sim_ctx, dst_reg, regloc, regmask); (void)regmask;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx, dst_reg);
  sim_ctx->fn.pop_stack (sim_ctx->state, regloc, reg_width);
  return true;
}

bool
sim_dispatch$unop_reg (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  auto reg = insn->detail->x86.operands[0].reg;

  switch (insn->id)
  {
#define $unop_case(insn, fn) \
  case insn: return fn (sim_ctx, reg);

    $unop_case (X86_INS_PUSH, push_reg);
    $unop_case (X86_INS_POP, pop_reg);

    default:
      $trace_err ("unhandled reg instruction (%s)", insn->mnemonic);
      return false;
  }
}