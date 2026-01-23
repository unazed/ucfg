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
read_insns_at_block (
  cfg_gen_ctx_t ctx, size_t* insn_count, vertex_tag_t basic_tag)
{
  auto block_size = cfg$get_basic_block_size (
    ctx->cfg, ctx->fn_tag, basic_tag);
  auto block_rva = cfg$get_basic_block_rva (
    ctx->cfg, ctx->fn_tag, basic_tag);
  auto insn_raw = pe$read_sized (ctx->pe, block_rva, block_size);
  if (insn_raw == NULL)
  {
    $trace (
      "failed to read block at %" PRIx64 " (%" PRIu64 " bytes)",
      block_rva, block_size);
    return NULL;
  }
  cs_insn* insns;
  *insn_count = cs_disasm (
    ctx->handle, insn_raw, block_size, block_rva, 0, &insns);
  $chk_free (insn_raw);
  return insns;
}

static cs_insn*
read_insns_at_block_before (
  cfg_gen_ctx_t ctx, size_t* insn_count, vertex_tag_t basic_tag, uint64_t address)
{
  auto block_rva = cfg$get_basic_block_rva (ctx->cfg, ctx->fn_tag, basic_tag);
  $strict_assert (
    (block_rva <= address)
    && (address < block_rva
        + cfg$get_basic_block_size (ctx->cfg, ctx->fn_tag, basic_tag)),
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

static inline bool
is_equal_ops (struct cs_x86_op* dst_loc, struct cs_x86_op* src_loc)
{
  if (dst_loc->type != src_loc->type)
    return false;

  switch (dst_loc->type)
  {
    case X86_OP_MEM:
      return !memcmp (
        &dst_loc->mem, &src_loc->mem, sizeof (struct x86_op_mem));
    case X86_OP_REG:
      return dst_loc->reg == src_loc->reg;
    default:
      __builtin_unimplemented ();
  }
}

static void /* struct cs_insn */
trace_reg_block_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t basic_tag, cs_insn* insns,
  size_t insn_count_or_depth, array_t df_insns, array_t tracked_regs,
  array_t tracked_mem, array_t visited_blocks)
{
  size_t insn_count = insn_count_or_depth;
  size_t depth = 0;

  if (array$contains_rval (visited_blocks, basic_tag))
  {
    $trace ("ALREADY VISITED BLOCK: %" PRIx64, basic_tag);
    return;
  }
  array$append_rval (visited_blocks, basic_tag);

  if (insns == NULL)
  {
    if (insn_count_or_depth > MAX_DF_BLOCK_DEPTH)
    {
      $trace_err ("exceeded maximum dataflow analysis depth");
      return;
    }
    depth = insn_count_or_depth;
    insns = read_insns_at_block (ctx, &insn_count, basic_tag);
  }

  $trace ("-> AT BLOCK (%zu insns): %" PRIx64, insn_count, basic_tag);
  for (ssize_t i = insn_count - 1; i >= 0; --i)
  {
    auto insn = &insns[i];

    uint8_t regs_write_count, regs_read_count;
    cs_regs regs_write, regs_read;
    if (cs_regs_access (
        ctx->handle, insn, regs_read, &regs_read_count, regs_write,
        &regs_write_count) != CS_ERR_OK)
    {
      $trace_err ("cs_regs_access failed");
      continue;
    }

    for (size_t i_wreg = 0; i_wreg < regs_write_count; ++i_wreg)
    {
      auto wreg = regs_write[i_wreg];
      if (!array$contains_rval (tracked_regs, wreg))
        continue;
      $trace_debug (
        "no longer tracking register: %s", cs_reg_name (ctx->handle, wreg));
      array$remove_rval (tracked_regs, wreg);
      for (size_t i_rreg = 0; i_rreg < regs_read_count; ++i_rreg)
      {
        auto rreg = regs_read[i_rreg];
        $trace_debug ("tracking register: %s", cs_reg_name (ctx->handle, rreg));
        array$append_rval (tracked_regs, rreg);
      }
      array$insert (df_insns, 0, insn);
      $trace ("\t%s %s", insn->mnemonic, insn->op_str);
    }
  }
  cs_free (insns, insn_count);

  if (!array$is_empty (tracked_regs))
  {
    auto preds = cfg$get_preds (ctx->cfg, ctx->fn_tag, basic_tag);
    if (array$is_empty (preds))
      $trace ("NO PREDECESSOR BLOCKS...");
    $array_for_each ($, preds, vertex_tag_t, pred)
    {
      trace_reg_block_dataflow (
        ctx, *$.pred, NULL, depth + 1, df_insns, tracked_regs, tracked_mem,
        visited_blocks);
    }
    array$free (preds);
  }
}

static void
df_insn_free (void* ptr)
{
  array_t array = ptr;
  $array_for_each ($, array, struct cs_insn, insn)
  {
    $chk_free ($.insn->detail);
  }
}

static void*
cs_insn_memmove (
  void* dst, const void* src, size_t n)
{
  const cs_insn* src_insn = src;
  auto src_detail = src_insn->detail;
  cs_insn* dst_insn = memmove (dst, src_insn, n);
  if (src_detail != NULL)
  {
    dst_insn->detail = $chk_allocty (struct cs_detail*);
    memmove (dst_insn->detail, src_detail, sizeof (struct cs_detail));
  }
  return dst_insn;
}

static void*
cs_insn_memcpy (
  void* restrict dst, const void* restrict src, size_t n)
{
  const cs_insn* src_insn = src; 
  cs_insn* dst_insn = memcpy (dst, src_insn, n);
  if (src_insn->detail != NULL)
  {
    dst_insn->detail = $chk_allocty (struct cs_detail*);
    memcpy (dst_insn->detail, src_insn->detail, sizeof (struct cs_detail));
  }
  return dst_insn;
}

static array_t /* struct cs_insn (copy) */
trace_reg_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t basic_tag, enum x86_reg dep_reg,
  uint64_t address)
{
  size_t insn_count;
  auto insns = read_insns_at_block_before (
    ctx, &insn_count, basic_tag, address);
  auto df_insns = array$new (sizeof (struct cs_insn));
  array$set_copy_hooks (df_insns, cs_insn_memcpy, cs_insn_memmove);
  array$set_free_hook (df_insns, df_insn_free);

  /* store ptrs to operands so we can use `array`'s `*_rval` functions */
  array_t tracked_regs = array$new (sizeof (enum x86_reg)),
          tracked_mem = array$new (sizeof (struct x86_op_mem*));
  array$append_rval (tracked_regs, dep_reg);

  array_t visited_blocks = array$new (sizeof (vertex_tag_t));
  $trace ("BEGIN TRACING (%s)", cs_reg_name (ctx->handle, dep_reg));
  trace_reg_block_dataflow (
    ctx, basic_tag, insns, insn_count, df_insns, tracked_regs, tracked_mem,
    visited_blocks);
  $trace ("FINISH TRACE.");

  array$free (visited_blocks);
  array$free (tracked_regs);
  array$free (tracked_mem);
  return df_insns;
}

static array_t /* struct cs_insn */
trace_flag_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t block_tag, cs_insn* branch_insn,
  uint64_t* mod_flags)
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

  auto cmp_reg = cmp_insn->detail->x86.operands[0].reg;
  auto cmp_insn_addr = cmp_insn->address;
  cs_free (insns, insn_count);

  return trace_reg_dataflow (ctx, block_tag, cmp_reg, cmp_insn_addr);
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
determine_sp_offset (cfg_gen_ctx_t ctx, uint64_t* sp_offset)
{
  size_t insn_count;
  auto entry_insns = read_insns_at_block(
    ctx, &insn_count, cfg$get_entry_block (ctx->cfg, ctx->fn_tag));

  for (size_t i = 0; i < insn_count; ++i)
  {
    auto insn = &entry_insns[i];
    auto operands = insn->detail->x86.operands;
    if ((insn->id != X86_INS_SUB) || (operands[0].type != X86_OP_REG))
      continue;
    switch (operands[0].reg)
    {
      case X86_REG_SP:
      case X86_REG_ESP:
      case X86_REG_RSP:
        break;
      default:
        continue;
    }

    switch (operands[1].type)
    {
      case X86_OP_IMM:
        *sp_offset = operands[1].imm;
        $trace ("determined sp-offset for function: -%" PRIx64, *sp_offset);
        return true;
      default:
        $trace_err ("indeterminate sp-offset for function block");
        return false;
    }
  }

  return false;
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
    uint64_t mod_eflags;
    auto df_flags = trace_flag_dataflow (ctx, pred, branch_insn, &mod_eflags);

    jmp_targets[1] = branch_insn->address + branch_insn->size;
    if ((df_flags == NULL) || array$is_empty (df_flags))
    {
      $trace ("branch is indeterminate, continuing...");
      if (df_flags != NULL)
        array$free (df_flags);
      goto failed_df;
    }
    $trace ("found %zu flag dataflow instructions", array$length (df_flags));

    if (cfg_sim$simulate_insns (ctx->sim, ctx->fn_tag, df_flags))
    {
      auto sim_eflags = ctx->sim->fn.get_flags (ctx->sim->state);
      $trace ("sim_eflags %" PRIx64 ", expected: %" PRIx64, sim_eflags, mod_eflags);
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
        auto df_insns = trace_reg_dataflow (
          ctx, pred, branch_insn->detail->x86.operands[0].reg,
          branch_insn->address);
        if (df_insns == NULL)
        {
          $trace ("failed to simulate dataflow, possibly indeterminate");
          return false;
        }

        $trace (
          "found %zu register dataflow instructions", array$length (df_insns));

        auto success = cfg_sim$simulate_insns (ctx->sim, ctx->fn_tag, df_insns);
        array$free (df_insns);

        if (!success || array$is_empty (df_insns))
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
  auto entry_tag = cfg$add_basic_block (ctx->cfg, ctx->fn_tag, block_address);

  size_t insn_count;
  cs_insn *insns = read_insns_at (ctx, &insn_count, block_address);
  cs_insn *branch_insn = find_next_branch (ctx, &insns, insn_count);
  cfg$set_basic_block_end (
    ctx->cfg, fn_tag, entry_tag,
    branch_insn->address + branch_insn->size);
  $trace (
    "new function block (size %" PRIu64" bytes): %" PRIx64,
    cfg$get_basic_block_size (ctx->cfg, ctx->fn_tag, entry_tag), ctx->fn_tag);

  uint64_t sp_offset;
  if (!determine_sp_offset (ctx, &sp_offset))
    $trace_err ("couldn't find function block sp-offset");
  else
    cfg$set_function_block_sp_offset (ctx->cfg, fn_tag, sp_offset);

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