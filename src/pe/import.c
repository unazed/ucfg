#include <string.h>

#include "pe/context.h"
#include "platform.h"

static bool
resolve_imports (
  pe_context_t pe_context, struct _import_entry* ientry)
{
  auto file = pe_context->stream;
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
    ientry->funcs = $chk_reallocarray (
      ientry->funcs, sizeof (struct _import_func_entry), ++ientry->nfuncs);
    auto fentry = &ientry->funcs[ientry->nfuncs - 1];
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
        goto invalid_entry;
      }
      struct image_import_by_name hint_name;
      fseek (file, hint_offset, SEEK_SET);
      if (!$read_type (hint_name, file))
      {
        $trace_debug ("failed to read hint/name offset for ILT");
        goto invalid_entry;
      }
      char* func_name = $chk_calloc (sizeof (char), MAX_FUNCNAME_LENGTH);
      auto nread = read_asciz (func_name, MAX_FUNCNAME_LENGTH, file);
      if (!nread)
      {
        $trace_debug ("failed to read function name from hint/name");
        $chk_free (func_name);
        goto invalid_entry;
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
        goto invalid_entry;
      }
      fentry->name = func_name;
      fentry->address = func_address;
      $trace_debug (
        "found function (%s@%p): %s@%p",
        ientry->module_name, module, fentry->name, func_address);
    }
    continue;

invalid_entry:
    ientry->funcs = $chk_reallocarray (
      ientry->funcs, sizeof (struct _import_func_entry), --ientry->nfuncs);
  }
  return true;
}

bool
pe$read_import_descriptors (pe_context_t pe_context, uint32_t offset)
{
  auto file = pe_context->stream;
  for (size_t i = 0;; ++i)
  {
    fseek (
      file, offset + i * sizeof (struct image_import_descriptor), SEEK_SET);
    pe_context->imports.array = $chk_reallocarray (
        pe_context->imports.array, sizeof (struct _import_entry),
        ++pe_context->imports.size);
    auto ientry = &pe_context->imports.array[pe_context->imports.size - 1];
    /* NB: `reallocarray` doesn't zero memory like `calloc` :( */
    memset (ientry, 0, sizeof (*ientry));
    if (!$read_type (ientry->descriptor, file))
    {
      $trace_debug ("failed to read import descriptor");
      return false;
    }
    if (!ientry->descriptor.characteristics)
    {  /* sentinel descriptor */
      if (pe_context->imports.size)
        pe_context->imports.array = $chk_reallocarray (
          pe_context->imports.array, sizeof (struct _import_entry),
          --pe_context->imports.size);
      break;
    }
    auto name_offset = pe$find_fileoffs_by_rva (
      pe_context, NULL, ientry->descriptor.name);
    if (!name_offset)
    {
      $trace_debug ("failed to find IDT name");
      continue; 
    }
    ientry->module_name = $chk_calloc (sizeof (char), MAX_PATH);
    fseek (file, name_offset, SEEK_SET);
    auto nread = read_asciz (ientry->module_name, MAX_PATH, file);
    if (!nread)
    {
      $trace_debug ("failed to read IDT name");
      $chk_free (ientry->module_name);
      continue;
    }
    ientry->module_name = $chk_realloc (ientry->module_name, nread);
    if (!resolve_imports (pe_context, ientry))
    {
      $trace_debug (
        "failed to resolve imports for module: %s", ientry->module_name);
      $chk_free (ientry->module_name);
      pe_context->imports.array = $chk_reallocarray (
        pe_context->imports.array, sizeof (struct _import_entry),
        --pe_context->imports.size);
      continue;
    }
  }
  return true;
}