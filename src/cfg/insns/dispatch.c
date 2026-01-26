#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"
#include "platform.h"

#define $set_flag(sim_ctx, flag, val) \
  ({ \
    auto _sim_ctx = (sim_ctx); \
    _sim_ctx->fn.set_flag (_sim_ctx->state, (flag), !!(val)); \
  })

bool
sim_dispatch$resolve_memop (
  cfg_sim_ctx_t sim_ctx, struct x86_op_mem* mem, uint64_t* out_sib)
{
  uint64_t sib = mem->disp;

  if (mem->base != X86_REG_INVALID)
  {
    $get_regloc_chk(sim_ctx, mem->base, base_regloc, base_mask);
    sib += *base_regloc & base_mask;
  }

  if (mem->index != X86_REG_INVALID)
  {
    $get_regloc_chk(sim_ctx, mem->index, index_regloc, index_mask);
    sib += (*index_regloc * mem->scale) & index_mask;
  }

  if (mem->segment == X86_REG_GS)
  {
    auto gs = platform_readgs ();
    $trace ("resolved gs segment to %p", gs);
    sib += (uintptr_t)gs;
  }

  *out_sib = sib;
  return true;
}

bool
sim_dispatch$update_flags__arith (
  cfg_sim_ctx_t sim_ctx, uint8_t reg_width, uint64_t result, uint64_t op_1,
  uint64_t op_2, bool is_sub)
{
  auto regmask = (reg_width == 64) ? ~0ull : ((1ull << reg_width) - 1);
  auto val = result & regmask;
  auto msb_mask = 1ull << (reg_width - 1);
  
  $set_flag(sim_ctx, EFLAGS_ZF, !val);
  $set_flag(sim_ctx, EFLAGS_SF, val & msb_mask);
  $set_flag(sim_ctx, EFLAGS_PF, !(__builtin_popcountg (val & 0xff) & 1));
  
  if (is_sub)
    $set_flag(sim_ctx, EFLAGS_CF, op_1 < op_2);
  else
    $set_flag(sim_ctx, EFLAGS_CF, val < op_1);
  
  auto sgn_op_1 = op_1 & msb_mask;
  auto sgn_op_2 = op_2 & msb_mask;
  auto res_sign = val & msb_mask;
  
  if (is_sub)
    $set_flag(
      sim_ctx, EFLAGS_OF, (sgn_op_1 != sgn_op_2) && (sgn_op_1 != res_sign));
  else
    $set_flag(
      sim_ctx, EFLAGS_OF, (sgn_op_1 == sgn_op_2) && (sgn_op_1 != res_sign));
  
  auto af = ((op_1 ^ op_2 ^ val) >> 4) & 1;
  $set_flag(sim_ctx, EFLAGS_AF, af);
  
  return true;
}

bool
sim_dispatch$update_flags__logic (cfg_sim_ctx_t sim_ctx, enum x86_reg reg)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);

  auto val = *regloc & regmask;
  auto msb_pos = sim_ctx->fn.get_reg_width (sim_ctx->state, reg) - 1;
  
  $set_flag(sim_ctx, EFLAGS_ZF, !val);
  $set_flag(sim_ctx, EFLAGS_SF, val & (1ull << msb_pos));
  $set_flag(sim_ctx, EFLAGS_PF, !(__builtin_popcountg (val & 0xff) & 1));
  $set_flag(sim_ctx, EFLAGS_CF, 0);
  $set_flag(sim_ctx, EFLAGS_OF, 0);
  
  return true;
}

bool
sim_dispatch$update_flags__rot (
  cfg_sim_ctx_t sim_ctx, uint64_t shift, uint64_t val, uint8_t reg_width)
{
  $set_flag(sim_ctx, EFLAGS_CF, val & 1);
  if (shift == 1)
    $set_flag (sim_ctx, EFLAGS_OF, ((val >> (reg_width - 1)) & 1) ^ (val & 1));
  return true;
}

bool
sim_dispatch$update_flags__shift (
  cfg_sim_ctx_t sim_ctx, enum x86_reg reg, uint64_t shift_count,
  uint64_t last_bit_out, bool is_left)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);

  auto val = *regloc & regmask;
  auto msb_pos = sim_ctx->fn.get_reg_width (sim_ctx->state, reg) - 1;
  
  $set_flag(sim_ctx, EFLAGS_ZF, !val);
  $set_flag(sim_ctx, EFLAGS_SF, val & (1ull << msb_pos));
  $set_flag(sim_ctx, EFLAGS_PF, !(__builtin_popcountg (val & 0xff) & 1));
  $set_flag(sim_ctx, EFLAGS_CF, last_bit_out);
  
  if (shift_count == 1)
  {
    if (is_left)
      $set_flag(sim_ctx, EFLAGS_OF, last_bit_out ^ ((val >> msb_pos) & 1));
    else
      $set_flag(sim_ctx, EFLAGS_OF, last_bit_out);
  }
  
  return true;
}

bool
sim_dispatch$update_flags__inc_dec (
  cfg_sim_ctx_t sim_ctx, enum x86_reg reg, uint64_t old_val, bool is_dec)
{
  $get_regloc_chk(sim_ctx, reg, regloc, regmask);

  auto val = *regloc & regmask;
  auto msb_mask = 1ull << (sim_ctx->fn.get_reg_width (sim_ctx->state, reg) - 1);
  
  $set_flag(sim_ctx, EFLAGS_ZF, !val);
  $set_flag(sim_ctx, EFLAGS_SF, val & msb_mask);
  $set_flag(sim_ctx, EFLAGS_PF, !(__builtin_popcountg (val & 0xff) & 1));
  
  if (is_dec)
    $set_flag(sim_ctx, EFLAGS_OF, old_val == msb_mask);
  else
    $set_flag(sim_ctx, EFLAGS_OF, old_val == (msb_mask - 1));
  
  $set_flag(sim_ctx, EFLAGS_AF, ((old_val ^ val) >> 4) & 1);
  
  return true;
}