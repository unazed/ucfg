#include <x86intrin.h>

#include "capstone/x86.h"
#include "cfg/cfg.h"
#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"
#include "cfg/arch/x86.h"

static void
init_state_fnptrs (cfg_sim_ctx_t sim_ctx, cs_arch arch)
{
  switch (arch)
  {
    case CS_ARCH_X86:
      sim_ctx->fn = (struct cfg_sim_ctx_fnptrs){
        .new_state = cfg_sim$x86$new_state,
        .free_state = cfg_sim$x86$free_state,
        .reset = cfg_sim$x86$reset,
        .get_reg = cfg_sim$x86$get_reg,
        .get_reg_indet = cfg_sim$x86$get_reg_indet,
        .get_reg_width = cfg_sim$x86$get_reg_width,
        .get_reg_name = cfg_sim$x86$get_reg_name,
        .get_flags = cfg_sim$x86$get_flags,
        .get_stack_frame = cfg_sim$x86$get_stack_frame,
        .push_stack = cfg_sim$x86$push_stack,
        .pop_stack = cfg_sim$x86$pop_stack,
        .set_reg = cfg_sim$x86$set_reg,
        .set_pc = cfg_sim$x86$set_pc,
        .set_flag = cfg_sim$x86$set_flag,
      };
      sim_ctx->state = sim_ctx->fn.new_state ();
      break;
    default:
      $abort ("unsupported simulation architecture (%d)", arch);
  }
}

cfg_sim_ctx_t
cfg_sim$new_context (cfg_t cfg, cs_arch arch)
{
  auto sim_ctx = $chk_allocty (cfg_sim_ctx_t);
  sim_ctx->cfg = cfg;
  init_state_fnptrs (sim_ctx, arch);
  return sim_ctx;
}

void
cfg_sim$free (cfg_sim_ctx_t sim_ctx)
{
  sim_ctx->fn.free_state (sim_ctx->state);
  $chk_free (sim_ctx);
}

bool
cfg_sim$simulate_insns (
  cfg_sim_ctx_t sim_ctx, vertex_tag_t fn_tag, array_t insns)
{
  sim_ctx->fn.reset (sim_ctx->state);
  auto stack_frame = cfg$new_stack_frame (sim_ctx->cfg, fn_tag);
  sim_ctx->fn.set_reg (sim_ctx->state, X86_REG_RBP, (uintptr_t)stack_frame);
  sim_ctx->fn.set_reg (sim_ctx->state, X86_REG_RSP, (uintptr_t)stack_frame);
  sim_ctx->fn_tag = fn_tag;
  $array_for_each($, insns, struct cs_insn, insn)
  {
    if ($.insn->id == X86_INS_INVALID)
      $abort ("tried to simulate invalid instruction");
    
    $trace_debug (
      "(trace: %" PRIx64 ") %s %s",
      $.insn->address, $.insn->mnemonic, $.insn->op_str);

    sim_ctx->fn.set_pc (sim_ctx->state, $.insn->address + $.insn->size);

    auto op_1 = &$.insn->detail->x86.operands[0];
    auto op_2 = &$.insn->detail->x86.operands[1];
    switch ($.insn->detail->x86.op_count)
    {
#define $ret_if_false(expr) \
  { \
    if (!(expr)) \
    { \
      $trace_debug ("dispatch failed: " #expr); \
      return false; \
    } \
    break; \
  }

      case 0:
        $ret_if_false(sim_dispatch$nullop (sim_ctx, $.insn));

      case 1:
        if (op_1->type == X86_OP_REG)
          $ret_if_false(sim_dispatch$unop_reg (sim_ctx, $.insn));
        if (op_1->type == X86_OP_MEM)
          $ret_if_false(sim_dispatch$unop_mem (sim_ctx, $.insn));
        $abort ("unhandled unop insn. operand type");
        break;

      case 2:
        if ((op_1->type == X86_OP_REG) && (op_2->type == X86_OP_REG))
          $ret_if_false(sim_dispatch$binop_reg_reg (sim_ctx, $.insn));
        if ((op_1->type == X86_OP_REG) && (op_2->type == X86_OP_IMM))
          $ret_if_false(sim_dispatch$binop_reg_imm (sim_ctx, $.insn));
        if ((op_1->type == X86_OP_REG) && (op_2->type == X86_OP_MEM))
          $ret_if_false(sim_dispatch$binop_reg_mem (sim_ctx, $.insn));
        if ((op_1->type == X86_OP_MEM) && (op_2->type == X86_OP_REG))
          $ret_if_false(sim_dispatch$binop_mem_reg (sim_ctx, $.insn));
        if ((op_1->type == X86_OP_MEM) && (op_2->type == X86_OP_IMM))
          $ret_if_false(sim_dispatch$binop_mem_imm (sim_ctx, $.insn));
        $abort ("unhandled binop insn. operand types");

      default:
        $abort (
          "unhandled insn. %s has %" PRIu8 " operands",
          $.insn->mnemonic, $.insn->detail->x86.op_count);
#undef $ret_if_false
    }
  }
  return true;
}