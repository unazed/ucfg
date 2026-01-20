#include <capstone/capstone.h>

#include <string.h>

#include "cfg/cfg-gen.h"
#include "capstone/x86.h"
#include "cfg/cfg-sim.h"
#include "cfg/cfg.h"
#include "generic.h"
#include "graph.h"

struct _cfg_gen_ctx
{
  pe_context_t pe;
  cfg_sim_ctx_t sim;
  cfg_t cfg;
  csh handle;
  vertex_tag_t fn_tag;
};

static cs_insn*
read_insns_at (cfg_gen_ctx_t ctx, size_t* insn_count, uint64_t address)
{
  uint8_t* page = pe$read_page_at (ctx->pe, address);
  cs_insn* insns;
  *insn_count = cs_disasm (
    ctx->handle, page, pe$get_pagesize (ctx->pe), address, 0, &insns);
  $chk_free (page);
  return insns;
}

static inline bool
is_load_insn (cs_insn* insn)
{
  /* TODO: SIMD has more complex load instructions */
  return !strncmp (insn->mnemonic, "mov", 3) || (insn->id == X86_INS_LEA);
}

static cs_insn*
read_insns_at_block (cfg_gen_ctx_t ctx, size_t* insn_count, vertex_tag_t tag)
{
  auto block_size = cfg$get_basic_block_size (ctx->cfg, ctx->fn_tag, tag);
  auto block_rva = cfg$get_basic_block_rva (ctx->cfg, ctx->fn_tag, tag);
  auto insn_raw = pe$read_sized (ctx->pe, block_size, block_size);
  cs_insn* insns;
  *insn_count = cs_disasm (
    ctx->handle, insn_raw, block_size, block_rva, 0, &insns);
  $chk_free (insn_raw);
  return insns;
}

static cs_insn*
read_insns_at_block_before (
  cfg_gen_ctx_t ctx, size_t* insn_count, vertex_tag_t tag, uint64_t address)
{
  auto block_rva = cfg$get_basic_block_rva (ctx->cfg, ctx->fn_tag, tag);
  $strict_assert (
    (block_rva <= address)
    && (address < block_rva
        + cfg$get_basic_block_size (ctx->cfg, ctx->fn_tag, tag)),
    "Address specified not in bounds of block given");
  auto block_size = address - block_rva;
  auto insn_raw = pe$read_sized (ctx->pe, block_rva, block_size);
  cs_insn* insns;
  *insn_count = cs_disasm (
    ctx->handle, insn_raw, block_size, block_rva, 0, &insns);
  $chk_free (insn_raw);
  return insns;
}

static uint64_t
get_insn_flags (cs_insn* insn)
{
  /* rarely do instructions both check and set flags, so this should be
   * sufficent to understand what an instruction is doing, in context,
   * by combining both Capstone test/set flags.
   */
#define $test_set(flag) \
  if (branch_flags & (X86_EFLAGS_TEST_##flag)) ret |= EFLAGS_##flag; \
  if (branch_flags & (X86_EFLAGS_SET_##flag)) ret |= EFLAGS_##flag; \
  if (branch_flags & (X86_EFLAGS_MODIFY_##flag)) ret |= EFLAGS_##flag;

  auto branch_flags = insn->detail->x86.eflags;
  uint64_t ret = 0;

  $test_set(OF);
  $test_set(SF);
  $test_set(ZF);
  $test_set(PF);
  $test_set(CF);
  $test_set(DF);
  $test_set(AF);
  $test_set(IF);

  if (branch_flags & (X86_EFLAGS_TEST_TF))
    ret |= EFLAGS_TF;

  return ret;
#undef $test_set
}

static array_t /* struct cs_insn */
trace_reg_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t block_tag, cs_insn* dep_insn,
  cs_insn** out_insns, size_t* out_insn_count)
{
  size_t insn_count;
  auto insns = read_insns_at_block_before (
    ctx, &insn_count, block_tag, dep_insn->address);

  auto dep_regs = array$new (sizeof (enum x86_reg));
  auto df_insns = array$new (sizeof (struct cs_insn));
  array$append_rval (dep_regs, dep_insn->detail->x86.operands[0].reg);

  for (ssize_t i = insn_count - 1; i >= 0; --i)
  {
    auto insn = &insns[i];
    auto operands = insn->detail->x86.operands;
    auto op_count = insn->detail->x86.op_count;
    if (!op_count
        || (operands[0].type != X86_OP_REG)
        || !array$contains_rval (dep_regs, operands[0].reg))
      continue;
    if (is_load_insn (insn))
    {
      $trace_debug (
        "no longer tracking register: %s",
        cs_reg_name (ctx->handle, operands[0].reg));
      array$remove_rval (dep_regs, operands[0].reg);
    }
    if ((op_count >= 2) && (operands[1].type == X86_OP_REG))
    {
      $trace_debug (
        "tracking register: %s", cs_reg_name (ctx->handle, operands[1].reg));
      array$append_rval (dep_regs, operands[1].reg);
    }
    $trace ("\t%s %s", insn->mnemonic, insn->op_str);
    array$insert (df_insns, 0, insn);
  }

  if (!array$is_empty (dep_regs))
  {
    $trace_debug ("still tracking %zu registers", array$length (dep_regs));
    array$free (df_insns);
    return NULL;
  }
  else
    $trace_debug ("fully resolved register dataflow");

  *out_insns = insns;
  *out_insn_count = insn_count;

  array$free (dep_regs);
  return df_insns;
}

static array_t /* struct cs_insn */
trace_flag_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t block_tag, cs_insn* branch_insn,
  uint64_t* mod_flags, cs_insn** out_insns, size_t* out_insn_count)
{
  size_t insn_count;
  auto insns = read_insns_at_block_before (
    ctx, &insn_count, block_tag, branch_insn->address);
  auto branch_flags = get_insn_flags (branch_insn);
  *mod_flags = branch_flags;

  cs_insn* cmp_insn = NULL;
  for (ssize_t i = insn_count - 1; i >= 0; --i)
  {
    auto insn = &insns[i];
    auto insn_flags = get_insn_flags (insn);

    $trace_debug (
      "%s %s (flags: %" PRIx64 ", real: %" PRIx64 ")",
      insn->mnemonic, insn->op_str, insn_flags, insn->detail->x86.eflags);

    if ((insn_flags & branch_flags) == branch_flags)
    {
      $trace (
        "found insn. matching flag criteria: %s %s",
        insn->mnemonic, insn->op_str);
      cmp_insn = insn;
      break;
    }
  }

  if (cmp_insn == NULL)
  {
    $trace (
      "couldn't find insn. matching flag criteria for %s",
      branch_insn->mnemonic);
    cs_free (insns, insn_count);
    return NULL;
  }

  auto df_insns = trace_reg_dataflow (
    ctx, block_tag, cmp_insn, out_insns, out_insn_count);
  cs_free (insns, insn_count);
  return df_insns;
}

static cs_insn*
find_next_branch (cfg_gen_ctx_t ctx, cs_insn** ptrinsns, size_t insn_count)
{
  auto insns = *ptrinsns;
  for (size_t j = 0; j < 3; ++j)
  {
    uint64_t last_address;
    for (size_t i = 0; i < insn_count; ++i)
    {
      auto insn = &insns[i];
      $trace (
        "%" PRIx64 ": %s\t%s", insn->address, insn->mnemonic, insn->op_str);
      if (cs_insn_group (ctx->handle, insn, X86_GRP_JUMP)
          || cs_insn_group (ctx->handle, insn, X86_GRP_CALL)
          || cs_insn_group (ctx->handle, insn, X86_GRP_RET))
        return insn;
      last_address = insn->address;
    }
    cs_free (insns, insn_count);
    insns = read_insns_at (ctx, &insn_count, last_address);
    *ptrinsns = insns;
  }
  $abort (
    "failed to find branch in several pages, maybe we are disassembling "
    "non-executable data?");
}

static bool
dispatch_jump_imm (
  cfg_gen_ctx_t ctx, cs_insn* branch_insn, vertex_tag_t pred)
{
  int64_t jmp_targets[2] = {
    branch_insn->detail->x86.operands[0].imm,  /* true branch */
    0  /* fallthrough, false branch */
  };

  if (branch_insn->id != X86_INS_JMP)
  { /* is conditional jump? if so, check if reducible */
    size_t insn_count;
    uint64_t mod_eflags;
    cs_insn* insns;
    auto df_flags = trace_flag_dataflow (
      ctx, pred, branch_insn, &mod_eflags, &insns, &insn_count);

    jmp_targets[1] = branch_insn->address + branch_insn->size;
    if (df_flags == NULL)
    {
      $trace ("branch is indeterminate, continuing...");
      goto failed_df;
    }

    $trace ("found %zu flag dataflow instructions", array$length (df_flags));

    $trace ("1st insn: %s", ((struct cs_insn*)array$at (df_flags, 0))->mnemonic);

    if (cfg_sim$simulate_insns (ctx->sim, df_flags))
    {
      auto sim_eflags = ctx->sim->fn.get_flags (ctx->sim->state);
      if ((sim_eflags & mod_eflags) != mod_eflags)
      {  /* branch is never taken */
        $trace (
          "opaque predicate resolved, branch to %" PRIx64 " never taken",
          jmp_targets[0]);
        jmp_targets[0] = jmp_targets[1];
      }
      else
        $trace (
          "opaque predicate resolved, branch to %" PRIx64 " always taken",
          jmp_targets[0]);
      jmp_targets[1] = 0;
    }
    cs_free (insns, insn_count);
    array$free (df_flags);
  }

failed_df:
  for (size_t i = 0; i < sizeof (jmp_targets) / sizeof (*jmp_targets); ++i)
  {
    auto jmp_target = jmp_targets[i];
    if (i && !jmp_target)
      break;

    $trace (
      "%" PRIx64 ": JUMP (%s) -> %" PRIx64,
      branch_insn->address, branch_insn->mnemonic, jmp_target);

    if (cfg$is_address_visited (ctx->cfg, jmp_target))
    { /* is back-reference to earlier block? */
      auto visited_block = cfg$get_basic_block (
        ctx->cfg, ctx->fn_tag, jmp_target);
      auto jmp_block = cfg$split_basic_block (
        ctx->cfg, ctx->fn_tag, visited_block, jmp_target);
      cfg$connect_basic_blocks (ctx->cfg, ctx->fn_tag, pred, jmp_block);
      continue;
    }

    size_t insn_count;
    auto insns = read_insns_at (ctx, &insn_count, jmp_target);
    auto next_branch = find_next_branch (ctx, &insns, insn_count);

    auto new_tag = cfg$add_basic_block_succ (
      ctx->cfg, ctx->fn_tag, pred, jmp_target);
    cfg$set_basic_block_end (
      ctx->cfg, ctx->fn_tag, new_tag, next_branch->address + next_branch->size);

    if (!cfg_gen$recurse_branch_insns (ctx, next_branch, new_tag))
      return false;
    cs_free (insns, insn_count);
  }
  return true;
}

bool
cfg_gen$recurse_branch_insns (
  cfg_gen_ctx_t ctx, cs_insn* branch_insn, vertex_tag_t pred)
{
  auto operands = branch_insn->detail->x86.operands;
  if (cs_insn_group (ctx->handle, branch_insn, X86_GRP_JUMP))
  {
    switch (operands[0].type)
    {
      case X86_OP_IMM:
        return dispatch_jump_imm (ctx, branch_insn, pred); 
      case X86_OP_REG:
      case X86_OP_MEM:
      case X86_OP_INVALID:
        $abort ("unimplemented jump type");
        break;
    }
  }
  else if (cs_insn_group (ctx->handle, branch_insn, X86_GRP_CALL))
  {
    switch (operands[0].type)
    {
      case X86_OP_IMM:
        return cfg_gen$recurse_function_block (
          ctx, ctx->fn_tag, operands[0].imm);

      case X86_OP_MEM:
      {
        auto operand = branch_insn->detail->x86.operands[0];
        if (operand.mem.base != X86_REG_RIP)
          $abort ("unimplemented call to %s", branch_insn->op_str);
        auto iat_addr
          = branch_insn->address + branch_insn->size + operand.mem.disp;
        $trace ("jump to IAT entry at %" PRIx64, iat_addr);
        /* TODO: validate `iat_addr` actually in IAT bounds */
        return false;
      }

      case X86_OP_REG:
      {
        /* N.B.: superset of `df_insns` since `trace_insn_dataflow` (probably)
         *       can't `cs_free` them after copying them into an array, since
         *       the `cs_insn[n].details->x86` member is dynamic, and we only
         *       do a shallow copy for `df_insns`
         */
        cs_insn* insns;
        size_t insn_count;
        auto df_insns = trace_reg_dataflow (
          ctx, pred, branch_insn, &insns, &insn_count);
        if (df_insns == NULL)
        {
          $trace ("failed to simulate dataflow, possibly indeterminate");
          return false;
        }

        $trace (
          "found %zu register dataflow instructions", array$length (df_insns));

        auto success = cfg_sim$simulate_insns (ctx->sim, df_insns);
        cs_free (insns, insn_count);
        array$free (df_insns);

        if (!success)
        {
          $trace ("failed to simulate dataflow, possibly indeterminate");
          return false;
        }

        uint64_t reg_mask;
        auto reg_val = ctx->sim->fn.get_reg (
          ctx->sim->state, &reg_mask, operands[0].reg);
        $trace (
          "simulated %s value: %" PRIx64,
          branch_insn->op_str, *reg_val & reg_mask);

        return cfg_gen$recurse_function_block (
          ctx, ctx->fn_tag, *reg_val & reg_mask);
      }

      case X86_OP_INVALID:
        $abort ("invalid call operand type");
        break;
    }
  }
  else if (cs_insn_group (ctx->handle, branch_insn, X86_GRP_RET))
  {
    $abort ("unimplemented ret insn.");
  }
  __builtin_unreachable ();
}

bool
cfg_gen$recurse_function_block (
  cfg_gen_ctx_t ctx, vertex_tag_t fn_pred, uint64_t block_address)
{
  if (cfg$is_address_visited (ctx->cfg, block_address))
    return true;
  vertex_tag_t fn_tag;
  if (fn_pred)
    fn_tag = cfg$add_function_block_succ (ctx->cfg, fn_pred, block_address);
  else
    fn_tag = cfg$add_function_block (ctx->cfg, block_address);
  ctx->fn_tag = fn_tag;
  auto entry_tag = cfg$add_basic_block (ctx->cfg, fn_tag, block_address);

  size_t insn_count;
  cs_insn *insns = read_insns_at (ctx, &insn_count, block_address);
  cs_insn *branch_insn = find_next_branch (ctx, &insns, insn_count);
  cfg$set_basic_block_end (
    ctx->cfg, fn_tag, entry_tag,
    branch_insn->address + branch_insn->size);
  auto success = cfg_gen$recurse_branch_insns (ctx, branch_insn, entry_tag);
  cs_free (insns, insn_count);
  return success;
}

void
cfg_gen$free_context (cfg_gen_ctx_t ctx)
{
  cfg_sim$free (ctx->sim);
  $chk_free (ctx);
}

cfg_gen_ctx_t
cfg_gen$new_context (pe_context_t pe_context, cfg_t cfg, csh handle)
{
  auto ctx = $chk_allocty (cfg_gen_ctx_t);
  ctx->pe = pe_context;
  ctx->cfg = cfg;
  ctx->handle = handle;
  ctx->sim = cfg_sim$new_context (CS_ARCH_X86);
  return ctx;
}