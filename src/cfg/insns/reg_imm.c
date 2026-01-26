#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"
#include "intrin.h"

static bool
mov_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  sim_ctx->fn.set_reg (sim_ctx->state, reg, imm);
  return true;
}

static bool
movabs_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  sim_ctx->fn.set_reg (sim_ctx->state, reg, imm);
  return true;
}

static bool
add_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);
  auto op_1 = *regloc & regmask;
  auto op_2 = imm & regmask;
  auto result = (op_1 + op_2) & regmask;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg);
  
  sim_ctx->fn.set_reg (sim_ctx->state, reg, result);
  sim_dispatch$update_flags__arith (
    sim_ctx, reg_width, result, op_1, op_2, false);
  return true;
}

static bool
rol_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg);
  uint64_t shifted = __rolg (*regloc & regmask, imm, reg_width);
  sim_ctx->fn.set_reg (sim_ctx->state, reg, shifted);
  sim_dispatch$update_flags__rot (sim_ctx, imm, shifted, reg_width);
  return true;
}

static bool
ror_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg);
  uint64_t shifted = __rorg (*regloc & regmask, imm, reg_width);
  sim_ctx->fn.set_reg (sim_ctx->state, reg, shifted);
  sim_dispatch$update_flags__rot (sim_ctx, imm, shifted, reg_width);
  return true;
}

static bool
cmp_reg_imm (cfg_sim_ctx_t sim_ctx, uint16_t reg, uint64_t imm)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);
  auto op_1 = *regloc & regmask;
  auto result = op_1 - imm;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg);
  
  sim_dispatch$update_flags__arith (
    sim_ctx, reg_width, result, op_1, imm, true);
  return true;
}

bool
sim_dispatch$binop_reg_imm (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  auto operands = insn->detail->x86.operands;

  switch (insn->id)
  {
#define $binop_case(ins, fn) \
  case ins: return fn (sim_ctx, operands[0].reg, operands[1].imm);

    $binop_case (X86_INS_MOV, mov_reg_imm);
    $binop_case (X86_INS_MOVABS, movabs_reg_imm);
    $binop_case (X86_INS_ADD, add_reg_imm);
    $binop_case (X86_INS_ROL, rol_reg_imm);
    $binop_case (X86_INS_ROR, ror_reg_imm);
    $binop_case (X86_INS_CMP, cmp_reg_imm);
    
    default:
      $trace_err ("unhandled reg/imm. instruction (%s)", insn->mnemonic);
      return false;
  }
}