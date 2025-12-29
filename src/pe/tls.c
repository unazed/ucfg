#include "pe/context.h"

bool
pe$read_tls_directory (pe_context_t pe_context, uint32_t offset)
{
  auto file = pe_context->stream;
  auto tls = &pe_context->tls;

  pe_context->tls.callbacks = array$new (sizeof (uint64_t));

  fseek (file, offset, SEEK_SET);
  if (!pe$read_maxint (&tls->descriptor.raw_data_start, pe_context)
      || !pe$read_maxint (&tls->descriptor.raw_data_end, pe_context)
      || !pe$read_maxint (&tls->descriptor.index_address, pe_context)
      || !pe$read_maxint (&tls->descriptor.callback_address, pe_context)
      || !$read_type (tls->descriptor.size_of_zero_fill, file)
      || !$read_type (tls->descriptor.characteristics, file))
  {
    $trace_debug ("failed to read TLS descriptor from file");
    return false;
  }
  auto callback_offset = pe$find_fileoffs_by_rva (
    pe_context, NULL, pe$va_to_rva (
      pe_context, tls->descriptor.callback_address));
  if (!callback_offset)
  {
    $trace_debug ("failed to find TLS callback address table offset");
    return false;
  }

  fseek (file, callback_offset, SEEK_SET);
  for (;;)
  {
    uint64_t callback_address;
    if (!$read_type (callback_address, file))
    {
      $trace_debug ("failed to read TLS callback address");
      goto fail;
    }
    if (!callback_address)
      break;
    $trace_debug ("found TLS callback: %" PRIx64, callback_address);
    array$append (tls->callbacks, &callback_address);
  }
  return true;

fail:
  array$free (tls->callbacks);
  tls->callbacks = NULL;
  return false;
}