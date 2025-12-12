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

  auto pe_context = pe_context$alloc_from_file (file);

  pe_context$free (pe_context);
  fclose (file);
  return EXIT_SUCCESS;
}