#include <capstone/capstone.h>

#include <string.h>

#include "cfg-gen.h"
#include "cfg.h"
#include "graph.h"

struct _cfg_gen_ctx
{
  pe_context_t pe;
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
  int64_t jmp_targets[2] = { branch_insn->detail->x86.operands[0].imm, 0 };
  if (branch_insn->id != X86_INS_JMP)  /* is conditional jump? */
    jmp_targets[1] = branch_insn->address + branch_insn->size;
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

static bool
trace_insn_dataflow (
  cfg_gen_ctx_t ctx, vertex_tag_t block_tag, cs_insn* dep_insn)
{
  /* 1. grab instructions from current block
   * 2. iterate them in reverse order from before `insn`
   * 3. search for `mov/lea` on `dep_reg`
   * 4. if found, exit
   * 5. 
   */
  size_t insn_count;
  auto insns = read_insns_at_block_before (
    ctx, &insn_count, block_tag, dep_insn->address);
  auto dep_regs = array$new (sizeof (enum x86_reg));
  array$append_rval (dep_regs, dep_insn->detail->x86.operands[0].reg);
  
  for (ssize_t i = insn_count - 1; i >= 0; --i)
  {
    auto insn = insns[i];
    auto operands = insn.detail->x86.operands;
    auto op_count = insn.detail->x86.op_count;
    if (!op_count
        || (operands[0].type != X86_OP_REG)
        || !array$contains_rval (dep_regs, operands[0].reg))
      continue;
    if (is_load_insn (&insn))
    {
      $trace ("no longer tracking register: %s", cs_reg_name (ctx->handle, operands[0].reg));
      array$remove_rval (dep_regs, operands[0].reg);
    }
    if ((op_count >= 2) && (operands[1].type == X86_OP_REG))
    {
      $trace ("tracking register: %s", cs_reg_name (ctx->handle, operands[1].reg));
      array$append_rval (dep_regs, operands[1].reg);
    }
    $trace ("TRACE: %s %s", insn.mnemonic, insn.op_str);
  }
  if (!array$is_empty (dep_regs))
    $trace ("still tracking %zu registers", array$length (dep_regs));
  else
    $trace ("fully resolved dataflow");
  return true;
}

bool
cfg_gen$recurse_branch_insns (
  cfg_gen_ctx_t ctx, cs_insn* branch_insn, vertex_tag_t pred)
{
  if (cs_insn_group (ctx->handle, branch_insn, X86_GRP_JUMP))
  {
    switch (branch_insn->detail->x86.operands[0].type)
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
    switch (branch_insn->detail->x86.operands[0].type)
    {
      case X86_OP_IMM:
      {
        auto call_target = branch_insn->detail->x86.operands[0].imm;
        return cfg_gen$recurse_function_block (ctx, ctx->fn_tag, call_target);
      }
      case X86_OP_MEM:
      {
        auto operand = branch_insn->detail->x86.operands[0];
        if (operand.mem.base != X86_REG_RIP)
          $abort ("unimplemented call to %s", branch_insn->op_str);
        auto iat_addr
          = branch_insn->address + branch_insn->size + operand.mem.disp;
        $trace ("jump to IAT entry at %" PRIx64, iat_addr);
        return false;
      }
      case X86_OP_REG:
      {
        auto dataflow = trace_insn_dataflow (ctx, pred, branch_insn);
        (void)dataflow;
        $abort ("unimplemented call to register: %s", branch_insn->op_str);
        break;
      }
      case X86_OP_INVALID:
        $abort ("unimplemented call type");
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
  $chk_free (ctx);
}

cfg_gen_ctx_t
cfg_gen$new_context (pe_context_t pe_context, cfg_t cfg, csh handle)
{
  auto ctx = $chk_allocty (cfg_gen_ctx_t);
  ctx->pe = pe_context;
  ctx->cfg = cfg;
  ctx->handle = handle;
  return ctx;
}