#include <capstone/capstone.h>
#include <stdlib.h>
#include <stdio.h>

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

  if (!pe_context->tls.ncallbacks)
    $abort ("no TLS callbacks to start from");
  auto entry_tls = pe$read_page_at (
    pe_context, pe$va_to_rva (pe_context, pe_context->tls.callbacks[0]));
  if (entry_tls == NULL)
    $abort ("failed to read memory page for TLS callback");

  csh handle;
	cs_insn *insn;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		$abort ("failed to initialize Capstone");
	size_t insn_count = cs_disasm (
    handle, entry_tls, pe$get_pagesize (pe_context), 0x1000, 0, &insn);
  if (!insn_count)
    $abort ("failed to disassemble TLS callback");
  
  for (size_t j = 0; j < insn_count; j++)
  {
    printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
        insn[j].op_str);
  }

  cs_free (insn, insn_count);
	cs_close (&handle);
  free (entry_tls);

  pe$free (pe_context);
  fclose (file);
  return EXIT_SUCCESS;
}