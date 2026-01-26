#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"
#include "intrin.h"

static bool
mov_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_dst, uint16_t reg_src)
{
  $get_regloc_chk(sim_ctx, reg_src, src_loc, src_mask);
  sim_ctx->fn.set_reg (sim_ctx->state, reg_dst, *src_loc & src_mask);
  return true;
}

static bool
movsxd_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_dst, uint16_t reg_src)
{
  $get_regloc_chk(sim_ctx, reg_src, src_loc, src_mask);
  uint64_t sx_val = (int64_t)((int32_t)(*src_loc & src_mask));
  sim_ctx->fn.set_reg (sim_ctx->state, reg_dst, sx_val);
  return true;
}

static bool
add_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_a, uint16_t reg_b)
{
  $get_regloc_chk(sim_ctx, reg_a, loc_a, mask_a);
  $get_regloc_chk(sim_ctx, reg_b, loc_b, mask_b);
  auto op_1 = *loc_a & mask_a;
  auto op_2 = *loc_b & mask_b;
  auto result = (op_1 + op_2) & mask_a;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg_a);
  
  sim_ctx->fn.set_reg (sim_ctx->state, reg_a, result);
  sim_dispatch$update_flags__arith (
    sim_ctx, reg_width, result, op_1, op_2, false);
  return true;
}

static bool
rol_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_dst, uint16_t reg_src)
{
  $get_regloc_chk(sim_ctx, reg_dst, dst_loc, dst_mask);
  $get_regloc_chk(sim_ctx, reg_src, src_loc, src_mask);

  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg_dst);
  auto shift_val = *src_loc & src_mask;
  auto val = *dst_loc & dst_mask;

  sim_ctx->fn.set_reg (
    sim_ctx->state, reg_dst, __rolg (val, shift_val, reg_width));
  sim_dispatch$update_flags__rot (sim_ctx, shift_val, val, reg_width);

  return true;
}

static bool
ror_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_dst, uint16_t reg_src)
{
  $get_regloc_chk(sim_ctx, reg_dst, dst_loc, dst_mask);
  $get_regloc_chk(sim_ctx, reg_src, src_loc, src_mask);

  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg_dst);
  auto shift_val = *src_loc & src_mask;
  auto val = *dst_loc & dst_mask;

  sim_ctx->fn.set_reg (
    sim_ctx->state, reg_dst, __rorg (val, shift_val, reg_width));
  sim_dispatch$update_flags__rot (sim_ctx, shift_val, val, reg_width);

  return true;
}

static bool
cmp_reg_reg (cfg_sim_ctx_t sim_ctx, uint16_t reg_a, uint16_t reg_b)
{
  $get_regloc_chk(sim_ctx, reg_a, loc_a, mask_a);
  $get_regloc_chk(sim_ctx, reg_b, loc_b, mask_b);

  auto op_1 = *loc_a & mask_a;
  auto op_2 = *loc_b & mask_b;
  $trace ("comparing %" PRIx64 " to %" PRIx64, op_1, op_2);
  auto result = op_1 - op_2;
  auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx->state, reg_a);
  
  sim_dispatch$update_flags__arith (
    sim_ctx, reg_width, result, op_1, op_2, true);
  return true;
}

bool
sim_dispatch$binop_reg_reg (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  auto operands = insn->detail->x86.operands;

  switch (insn->id)
  {
#define $binop_case(ins, fn) \
  case ins: return fn (sim_ctx, operands[0].reg, operands[1].reg);

    $binop_case (X86_INS_MOV, mov_reg_reg);
    $binop_case (X86_INS_MOVSXD, movsxd_reg_reg);
    $binop_case (X86_INS_ADD, add_reg_reg);
    $binop_case (X86_INS_ROL, rol_reg_reg);
    $binop_case (X86_INS_ROR, ror_reg_reg);
    $binop_case (X86_INS_CMP, cmp_reg_reg);

    default:
      $trace_err ("unhandled reg/reg. instruction (%s)", insn->mnemonic);
      return false;
  }
}