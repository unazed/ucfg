#include "pe/context.h"

bool
pe$read_export_descriptors (pe_context_t pe_context, uint32_t offset)
{
  auto file = pe_context->stream;
  fseek (file, offset, SEEK_SET);
  auto exports = &pe_context->exports;
  if (!$read_type (exports->descriptor, file))
  {
    $trace_debug ("failed to read export directory from file");
    return false;
  }
  exports->nfuncs = exports->descriptor.number_of_functions;
  exports->array = $chk_calloc (sizeof (*exports->array), exports->nfuncs);
  auto offs_eat = pe$find_fileoffs_by_rva (
    pe_context, NULL, exports->descriptor.address_of_functions);
  auto offs_names = pe$find_fileoffs_by_rva (
    pe_context, NULL, exports->descriptor.address_of_names);
  auto offs_ordinals = pe$find_fileoffs_by_rva (
    pe_context, NULL, exports->descriptor.address_of_name_ordinals);
  if (!offs_eat || !offs_names || !offs_ordinals)
  {
    $trace_debug ("failed to find export address table RVAs");
    goto fail;
  }
  for (size_t i = 0; i < exports->descriptor.number_of_functions; ++i)
  {
    auto entry = &exports->array[i];
    fseek (
      file, offs_eat + i * sizeof (struct image_export_table_entry), SEEK_SET);
    if (!$read_type (entry->rva, file))
    {
      $trace_debug ("failed to read export table entry from file");
      goto fail;
    }
    entry->ordinal = i;
    
    /* find the export name pointer, if it exists */
    for (size_t j = 0; j < exports->descriptor.number_of_names; ++j)
    {
      fseek (file, offs_ordinals + i * sizeof (uint16_t), SEEK_SET);
      uint16_t ordinal;
      if (!$read_type (ordinal, file))
      {
        $trace_debug ("failed to read export table ordinal");
        goto fail;
      }
      if (ordinal != i)
        continue;
      fseek (file, offs_names + j * sizeof (uint32_t), SEEK_SET);
      uint32_t rva_name;
      if (!$read_type (rva_name, file))
      {
        $trace_debug ("failed to read export table entry name pointer");
        goto fail;
      }
      auto offs_name = pe$find_fileoffs_by_rva (pe_context, NULL, rva_name);
      if (!offs_name)
      {
        $trace_debug ("failed to find export table entry name");
        goto fail;
      }
      entry->func_name = $chk_calloc (sizeof (char), MAX_FUNCNAME_LENGTH);
      fseek (file, offs_name, SEEK_SET);
      auto nread = read_asciz (
        entry->func_name, MAX_FUNCNAME_LENGTH, file);
      if (!nread)
      {
        $trace_debug ("failed to read export function name");
        $chk_free (entry->func_name);
        goto fail;
      }
      entry->func_name = $chk_reallocarray (
        entry->func_name, sizeof (char), nread);
      $trace_debug (
        "read exported function (+%" PRIx32 ")#%" PRIu16 ": %s",
        entry->rva.address, entry->ordinal, entry->func_name);
    }
    if (entry->func_name == NULL)
      $trace_debug (
        "read exported function (+%" PRIx32 ")#%" PRIu16 ": (no-name)",
        entry->rva.address, entry->ordinal);
  }
  return true;

fail:
  $chk_free (exports->array);
  exports->array = NULL;
  exports->nfuncs = 0;
  return false;
}