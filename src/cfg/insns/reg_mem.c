#include "capstone/x86.h"
#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"

static bool
lea_reg_mem (cfg_sim_ctx_t sim_ctx, uint16_t dst_reg, struct x86_op_mem* mem)
{
  uint64_t sib;
  if (!sim_dispatch$resolve_memop (sim_ctx, mem, &sib))
    return false;
  sim_ctx->fn.set_reg (sim_ctx->state, dst_reg, sib);
  return true;
}

static bool
mov_reg_mem (cfg_sim_ctx_t sim_ctx, uint16_t dst_reg, struct x86_op_mem* mem)
{
  uint64_t sib;
  if (!sim_dispatch$resolve_memop (sim_ctx, mem, &sib))
    return false;
  sim_ctx->fn.set_reg (sim_ctx->state, dst_reg, *(uint64_t *)sib);
  return true;
}

bool
sim_dispatch$binop_reg_mem (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  auto operands = insn->detail->x86.operands;

  switch (insn->id)
  {
#define $binop_case(insn, fn) \
  case insn: \
    return fn (sim_ctx, operands[0].reg, &operands[1].mem);

    $binop_case (X86_INS_LEA, lea_reg_mem);
    $binop_case (X86_INS_MOV, mov_reg_mem);

    default:
      $trace_err ("unhandled reg/mem. instruction (%s)", insn->mnemonic);
      return false;
  }
}