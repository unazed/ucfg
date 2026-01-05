#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "capstone/x86.h"
#include "pe/context.h"
#include "pe/format.h"
#include "trace.h"
#include "cfg.h"

static bool
recurse_branch_insns (
  pe_context_t pe_context, cfg_t cfg, csh handle, cs_insn* branch_insn,
  vertex_tag_t fn_tag, vertex_tag_t pred);
static bool
recurse_function_block (
  pe_context_t pe_context, cfg_t cfg, vertex_tag_t fn_pred, csh handle,
  uint64_t block_address);

size_t
read_page_at (pe_context_t pe_context, uint64_t address, uint8_t** dest)
{
  *dest = pe$read_page_at (pe_context, address);
  return pe$get_pagesize (pe_context);
}

cs_insn*
read_insns_at (
  pe_context_t pe_context, csh handle, size_t *insn_count, uint64_t address)
{
  uint8_t* page;
  auto block_size = read_page_at (pe_context, address, &page);
  cs_insn* insns;
  *insn_count = cs_disasm (
    handle, page, block_size, address, 0, &insns);
  $chk_free (page);
  return insns;
}

cs_insn*
find_next_branch (
  pe_context_t pe_context, csh handle, cs_insn** ptrinsns, size_t insn_count)
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
      if (cs_insn_group (handle, insn, X86_GRP_JUMP)
          || cs_insn_group (handle, insn, X86_GRP_CALL)
          || cs_insn_group (handle, insn, X86_GRP_RET))
        return insn;
      last_address = insn->address;
    }
    cs_free (insns, insn_count);
    insns = read_insns_at (pe_context, handle, &insn_count, last_address);
    *ptrinsns = insns;
  }
  $abort (
    "failed to find branch in several pages, maybe we are disassembling "
    "non-executable data?");
}

static bool
dispatch_jump_imm (
  pe_context_t pe_context, cfg_t cfg, csh handle, cs_insn* branch_insn,
  vertex_tag_t fn_tag, vertex_tag_t pred)
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

    size_t insn_count;
    auto insns = read_insns_at (pe_context, handle, &insn_count, jmp_target);
    auto next_branch = find_next_branch (
      pe_context, handle, &insns, insn_count);

    auto new_tag = cfg$add_basic_block_succ (cfg, fn_tag, pred, jmp_target);
    cfg$set_basic_block_end (
      cfg, fn_tag, new_tag, next_branch->address + next_branch->size);

    if (!recurse_branch_insns (
        pe_context, cfg, handle, next_branch, fn_tag, new_tag))
      return false;
    cs_free (insns, insn_count);
  }
  return true;
}

static bool
recurse_branch_insns (
  pe_context_t pe_context, cfg_t cfg, csh handle, cs_insn* branch_insn,
  vertex_tag_t fn_tag, vertex_tag_t pred)
{
  if (cs_insn_group (handle, branch_insn, X86_GRP_JUMP))
  {
    switch (branch_insn->detail->x86.operands[0].type)
    {
      case X86_OP_IMM:
        return dispatch_jump_imm (
          pe_context, cfg, handle, branch_insn, fn_tag, pred); 
      case X86_OP_REG:
      case X86_OP_MEM:
      case X86_OP_INVALID:
        $abort ("unimplemented jump type");
        break;
    }
  }
  else if (cs_insn_group (handle, branch_insn, X86_GRP_CALL))
  {
    switch (branch_insn->detail->x86.operands[0].type)
    {
      case X86_OP_IMM:
      {
        auto call_target = branch_insn->detail->x86.operands[0].imm;
        return recurse_function_block (
          pe_context, cfg, fn_tag, handle, call_target);
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
      case X86_OP_INVALID:
        $abort ("unimplemented call type");
        break;
    }
  }
  else if (cs_insn_group (handle, branch_insn, X86_GRP_RET))
  {
    $abort ("unimplemented ret insn.");
  }
  __builtin_unreachable ();
}

static bool
recurse_function_block (
  pe_context_t pe_context, cfg_t cfg, vertex_tag_t fn_pred, csh handle,
  uint64_t block_address)
{
  vertex_tag_t fn_tag;
  if (fn_pred)
    fn_tag = cfg$add_function_block_succ (cfg, fn_pred, block_address);
  else
    fn_tag = cfg$add_function_block (cfg, block_address);
  auto entry_tag = cfg$add_basic_block (cfg, fn_tag, block_address);

  size_t insn_count;
  cs_insn *insns = read_insns_at (
    pe_context, handle, &insn_count, block_address);
  cs_insn *branch_insn = find_next_branch (
    pe_context, handle, &insns, insn_count);
  cfg$set_basic_block_end (
    cfg, fn_tag, entry_tag,
    branch_insn->address + branch_insn->size);
  auto success = recurse_branch_insns (
    pe_context, cfg, handle, branch_insn, fn_tag, entry_tag);
  cs_free (insns, insn_count);
  return success;
}

array_t /* struct image_section_header */
find_executable_sections (pe_context_t pe_context)
{
  array_t ex_sections = array$new (sizeof (struct image_section_header));
  $array_for_each (
    $, pe_context->section_headers, struct image_section_header, section)
  {
    if ($.section->characteristics & IMAGE_SCN_MEM_EXECUTE)
      array$append (ex_sections, $.section);
  }
  return ex_sections;
}

int
main (int argc, const char* argv[])
{
  if (argc < 2)
    $abort ("usage: %s <path-to-image>", argv[0]);

  auto file = fopen (argv[1], "rb");
  if (file == NULL)
    $abort ("failed to open path: %s", argv[1]);
  $trace_debug ("file opened: %s", argv[1]);

  auto pe_context = pe$from_file (
    file, PE_CONTEXT_LOAD_IMPORT_DIRECTORY | PE_CONTEXT_LOAD_EXPORT_DIRECTORY
      | PE_CONTEXT_LOAD_TLS_DIRECTORY);
  if (pe_context == NULL)
    $abort ("failed to create PE context from file");

  auto ex_sections = find_executable_sections (pe_context);
  if (array$is_empty (ex_sections))
    $abort ("failed to find any executable sections");
  if (array$length (ex_sections) > 1)
    $trace ("note: application has more than one executable section");

  if (array$is_empty (pe_context->tls.callbacks))
    $abort ("no valid application entrypoint");
  auto entry_point = pe$va_to_rva (
    pe_context, *(uint64_t *)array$at (pe_context->tls.callbacks, 0));

  csh handle;
  if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    $abort ("failed to initialize Capstone");
  cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);

  auto ex_section = (struct image_section_header *)array$at (ex_sections, 0);
  auto cfg = cfg$new (
    pe$get_image_base (pe_context), ex_section->size_of_raw_data);
  array$free (ex_sections);
  if (!recurse_function_block (pe_context, cfg, 0, handle, entry_point))
    $abort ("failed to generate basic blocks");

  cfg$free (cfg);
  pe$free (pe_context);
  cs_close (&handle);
  fclose (file);

  return EXIT_SUCCESS;
}