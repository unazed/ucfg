#include <stdio.h>

#include "trace.h"

int
read_sized (void* into, size_t size, FILE* file)
{
  auto nread = fread (into, size, 1, file);
  if (nread)
    $trace_verbose ("read %" PRIu64 " bytes", size);
  else
    $trace_debug ("failed to read %" PRIu64 " bytes", size);
  return nread;
}

int
read_asciz (char* into, ssize_t max_length, FILE* file)
{
  int c, nread;
  for (nread = 0; nread < max_length; ++nread)
  {
    if ((c = fgetc (file)) == EOF)
    {
      $trace_debug ("failed to read string from file");
      return 0;
    }
    into[nread] = c;
    if (!c)
      break;
  }
  return nread;
}