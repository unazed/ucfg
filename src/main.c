#include <capstone/capstone.h>
#include <stdlib.h>
#include <stdio.h>

#include "capstone/x86.h"
#include "pe/context.h"
#include "trace.h"

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

  if (!array$length (pe_context->tls.callbacks))
    $abort ("no TLS callbacks to start from");
  auto tls_rva = pe$va_to_rva (
    pe_context, *(uint64_t *)array$at (pe_context->tls.callbacks, 0));
  auto entry_tls = pe$read_page_at (pe_context, tls_rva);
  if (entry_tls == NULL)
    $abort ("failed to read memory page for TLS callback");

  csh handle;
	cs_insn *insns;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		$abort ("failed to initialize Capstone");
  cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	size_t insn_count = cs_disasm (
    handle, entry_tls, pe$get_pagesize (pe_context), 0, 0, &insns);
  if (!insn_count)
    $abort ("failed to disassemble TLS callback");

  for (size_t i_insn = 0; i_insn < insn_count; i_insn++)
  {
    auto insn = &insns[i_insn];
    for (size_t i_group = 0; i_group < insn->detail->groups_count; ++i_group)
    {
      auto group = insn->detail->groups[i_group];
      uint64_t insn_va = insn->address + tls_rva;
      if (group == X86_GRP_JUMP)
      {
        if (insn->detail->x86.op_count > 0 && 
            insn->detail->x86.operands[0].type == X86_OP_IMM)
        {
          int64_t imm = insn->detail->x86.operands[0].imm;
          int64_t va_imm = pe$rva_to_va (pe_context, imm + tls_rva);
          printf("0x%"PRIx64":\t%s\t\t0x%"PRIx64"\n",
            insn_va, insn->mnemonic, va_imm);
        }
        else
        {
          printf ("0x%"PRIx64":\t%s\t\t%s\n",
            insn_va, insn->mnemonic, insn->op_str);
        }
      }
    }
  }

  cs_free (insns, insn_count);
	cs_close (&handle);
  free (entry_tls);

  pe$free (pe_context);
  fclose (file);
  return EXIT_SUCCESS;
}