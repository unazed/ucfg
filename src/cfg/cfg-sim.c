#include <x86intrin.h>

#include "cfg/cfg-sim.h"
#include "capstone/x86.h"
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
        .set_reg = cfg_sim$x86$set_reg,
        .get_reg_width = cfg_sim$x86$get_reg_width
      };
      sim_ctx->state = sim_ctx->fn.new_state ();
      break;
    default:
      $abort ("unsupported simulation architecture (%d)", arch);
  }
}

cfg_sim_ctx_t
cfg_sim$new_context (cs_arch arch)
{
  auto sim_ctx = $chk_allocty (cfg_sim_ctx_t);
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
cfg_sim$simulate_insns (cfg_sim_ctx_t sim_ctx, array_t insns)
{
  $array_for_each($, insns, struct cs_insn, insn)
  {
    sim_ctx->fn.set_reg (sim_ctx, X86_REG_RIP, $.insn->address + $.insn->size);
    $trace ("(trace) %s %s", $.insn->mnemonic, $.insn->op_str);
    auto operands = $.insn->detail->x86.operands;
    switch ($.insn->id)
    {
      case X86_INS_MOV:
      {
        if (operands[1].type == X86_OP_IMM)
          sim_ctx->fn.set_reg (sim_ctx, operands[0].reg, operands[1].imm);
        else if (operands[1].type == X86_OP_REG)
        {
          uint64_t src_mask;
          auto reg_src = sim_ctx->fn.get_reg (
            sim_ctx, &src_mask, operands[1].reg);
          if (reg_src == NULL)
          {
            $trace ("indeterminate mov source register");
            return false;
          }
          sim_ctx->fn.set_reg (sim_ctx, operands[0].reg, *reg_src & src_mask);
        }
        else
        {
          $trace ("unsupported mov operand type");
          return false;
        }
        break;
      }
      case X86_INS_ADD:
      {
        uint64_t dst_mask;
        auto reg_dst = sim_ctx->fn.get_reg (
          sim_ctx, &dst_mask, operands[0].reg);
        if (reg_dst == NULL)
        {
          $trace ("indeterminate add destination register");
          return false;
        }
        if (operands[1].type == X86_OP_IMM)
        {
          sim_ctx->fn.set_reg (
            sim_ctx, operands[0].reg, (*reg_dst & dst_mask) + operands[1].imm);
        }
        else if (operands[1].type == X86_OP_REG)
        {
          uint64_t src_mask;
          auto reg_src = sim_ctx->fn.get_reg (
            sim_ctx, &src_mask, operands[1].reg);
          if (reg_src == NULL)
          {
            $trace ("indeterminate add source register");
            return false;
          }
          sim_ctx->fn.set_reg (
            sim_ctx, operands[0].reg,
            (*reg_dst & dst_mask) + (*reg_src & src_mask));
        }
        else
        {
          $trace ("unsupported add operand type");
          return false;
        }
        break;
      }
      case X86_INS_ROL:
      {
        if (operands[1].type == X86_OP_IMM)
        {
          uint64_t mask;
          auto reg = sim_ctx->fn.get_reg (sim_ctx, &mask, operands[0].reg);
          if (reg == NULL)
          {
            $trace ("tried to access indeterminate register");
            return false;
          }
          auto reg_width = sim_ctx->fn.get_reg_width (sim_ctx, operands[0].reg);
          uint64_t val;
          switch (reg_width)
          {
            case 8:
              val = __rolb (*reg & mask, operands[1].imm);
              break;
            case 16:
              val = __rolw (*reg & mask, operands[1].imm);
              break;
            case 32:
              val = __rold (*reg & mask, operands[1].imm);
              break;
            case 64:
              val = __rolq (*reg & mask, operands[1].imm);
              break;
            default:
              __builtin_unreachable ();
          }
          sim_ctx->fn.set_reg (sim_ctx, operands[0].reg, val);
          break;
        }
      }
      case X86_INS_LEA:
      {
        auto sib = operands[1].mem;
        uint64_t val = sib.disp;

        if (sib.base != X86_REG_INVALID)
        {
          uint64_t mask_base;
          auto reg_base = sim_ctx->fn.get_reg (sim_ctx, &mask_base, sib.base);
          if (reg_base == NULL)
          {
            $trace ("indeterminate SIB base register");
            return false;
          }
          val += *reg_base & mask_base;
        }

        if (sib.index != X86_REG_INVALID)
        {
          uint64_t mask_index;
          auto reg_index = sim_ctx->fn.get_reg (
            sim_ctx, &mask_index, sib.index);
          if (reg_index == NULL)
          {
            $trace ("indeterminate SIB index register");
            return false;
          }
          val += (*reg_index & mask_index) * sib.scale;
        }
        sim_ctx->fn.set_reg (sim_ctx, operands[0].reg, val);
        break;
      }
      case X86_INS_MOVSXD:
      {
        auto src = operands[1];
        uint64_t src_val;
        
        if (src.type == X86_OP_REG)
        {
          uint64_t mask_src;
          auto reg_src = sim_ctx->fn.get_reg (sim_ctx, &mask_src, src.reg);
          if (reg_src == NULL)
          {
            $trace ("indeterminate source register");
            return false;
          }
          src_val = *reg_src & mask_src;
        }
        else
        {
          $trace ("invalid source operand type for MOVSXD");
          return false;
        }
        
        int32_t signed_val = (int32_t)(src_val & REGMASK_DWORD);
        uint64_t extended_val = (uint64_t)(int64_t)signed_val;
        
        sim_ctx->fn.set_reg (sim_ctx, operands[0].reg, extended_val);
        break;
      }

      default:
        $abort ("unimplemented instruction: %s", $.insn->mnemonic);
    }
  }
  return true;
}