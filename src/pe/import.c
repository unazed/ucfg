#include <string.h>

#include "array.h"
#include "pe/context.h"
#include "platform.h"

static bool
resolve_imports (
  pe_context_t pe_context, struct import_entry* ientry)
{
  auto file = pe_context->stream;
  ientry->functions = array$new (sizeof (struct import_func_entry));
  auto module = platform_load_library (ientry->module_name);
  if (module == NULL)
  {
    $trace_debug ("failed to load module: %s", ientry->module_name);
    return false;
  }
  ientry->module_base = module;
  auto ilt_offset = pe$find_fileoffs_by_rva (
    pe_context, NULL, ientry->descriptor.original_first_thunk);
  if (!ilt_offset)
  {
    $trace_debug (
      "failed to find ILT offset for module: %s", ientry->module_name);
    return false;
  }

  auto ilt_increment = pe$get_image_maxsize (pe_context);
  for (size_t i = 0;; ++i)
  {
    fseek (file, ilt_offset + i * ilt_increment, SEEK_SET);
    struct import_func_entry fentry = { 0 };

    uint64_t ilt_entry;
    auto nread = pe$read_maxint (&ilt_entry, pe_context); 
    if (!nread)
    {
      $trace_debug (
        "failed to read ILT entry for module: '%s'", ientry->module_name);
      return false;
    }
    if (!ilt_entry)
      break;
    if (ilt_entry & (1ull << (8 * ilt_increment - 1)))
    {
      /* TODO: import by ordinal */
      $trace_debug (
        "reading ordinal: %s#%" PRIx16,
        ientry->module_name, (uint16_t)ilt_entry);
      __builtin_unimplemented ();
    }
    else
    {
      auto hint_offset = pe$find_fileoffs_by_rva(
        pe_context, NULL, ilt_entry & 0x7fffffff);
      if (!hint_offset)
      {
        $trace_debug ("failed to find hint/name offset for ILT");
        continue;
      }
      struct image_import_by_name hint_name;
      fseek (file, hint_offset, SEEK_SET);
      if (!$read_type (hint_name, file))
      {
        $trace_debug ("failed to read hint/name offset for ILT");
        continue;
      }
      char* func_name = $chk_calloc (sizeof (char), MAX_FUNCNAME_LENGTH);
      auto nread = read_asciz (func_name, MAX_FUNCNAME_LENGTH, file);
      if (!nread)
      {
        $trace_debug ("failed to read function name from hint/name");
        $chk_free (func_name);
        continue;
      }
      func_name = $chk_realloc (func_name, nread + 1);
      $trace_debug (
        "importing (%s): %s#%" PRIx16,
        ientry->module_name, func_name, hint_name.hint);
      auto func_address = platform_get_procedure (module, func_name);
      if (func_address == NULL)
      {
        $trace_debug (
          "failed to get function (%s): %s", ientry->module_name, func_name);
        continue;
      }
      fentry.name = func_name;
      fentry.address = func_address;
      $trace_debug (
        "found function: %s (rva. %" PRIx64 ")",
        fentry.name, ientry->iat_rva + pe$get_ptrsize (pe_context) * i);
      array$append (ientry->functions, &fentry);
    }
    continue;
  }
  return true;
}

bool
pe$read_import_descriptors (pe_context_t pe_context, uint32_t offset)
{
  auto file = pe_context->stream;
  pe_context->imports = array$new (sizeof (struct import_entry));
  for (size_t i = 0;; ++i)
  {
    fseek (
      file, offset + i * sizeof (struct image_import_descriptor), SEEK_SET);
    struct import_entry ientry = { 0 };
    if (!$read_type (ientry.descriptor, file))
    {
      $trace_debug ("failed to read import descriptor");
      goto fail;
    }
    if (!ientry.descriptor.characteristics)
      break; /* sentinel descriptor */
    auto name_offset = pe$find_fileoffs_by_rva (
      pe_context, NULL, ientry.descriptor.name);
    if (!name_offset)
    {
      $trace_debug ("failed to find IDT name");
      continue; 
    }
    ientry.module_name = $chk_calloc (sizeof (char), MAX_PATH);
    fseek (file, name_offset, SEEK_SET);
    auto nread = read_asciz (ientry.module_name, MAX_PATH, file);
    if (!nread)
    {
      $trace_debug ("failed to read IDT name");
      goto entry_fail;
    }
    ientry.module_name = $chk_realloc (ientry.module_name, nread);
    ientry.iat_rva = ientry.descriptor.first_thunk;
    if (!resolve_imports (pe_context, &ientry))
    {
      $trace_debug (
        "failed to resolve imports for module: %s", ientry.module_name);
      goto fail;
    }
    array$append (pe_context->imports, &ientry);
    continue;

entry_fail:
    $chk_free (ientry.module_base);
  }
  return true;

fail:
  array$free (pe_context->imports);
  return false;
}