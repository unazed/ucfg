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

  auto pe_context = pe_context$from_file (
    file, PE_CONTEXT_LOAD_IMPORT_DIRECTORY | PE_CONTEXT_LOAD_EXPORT_DIRECTORY
      | PE_CONTEXT_LOAD_TLS_DIRECTORY);

  pe_context$free (pe_context);
  fclose (file);
  return EXIT_SUCCESS;
}