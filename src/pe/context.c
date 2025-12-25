#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pe/context.h"
#include "pe/format.h"
#include "generic.h"
#include "stdio.h"
#include "trace.h"
#include "platform.h"

#define $try_read_sized(into, size, file) \
  ({ \
    auto nread = fread ((into), (size), 1, (file)); \
    if (nread) \
      $trace_verbose ("read " #size " (%" PRIu64 ") bytes", size); \
    nread; \
  })
#define $try_read_type(into, file) \
  $try_read_sized (&(into), sizeof (into), file)
#define $try_read_asciz(into, max_length, file) \
  ({ \
    int c, nread; \
    for (nread = 0; nread < (max_length) - 1; ++nread) \
    { \
      if ((c = fgetc (file)) == EOF) \
      { \
        nread = 0; \
        break; \
      } \
      into[nread] = c; \
      if (!c) \
        break; \
    } \
    nread; \
  })

#define $offset_between_opthdr(memb1, memb2) \
  $offset_between (struct image_optional_header, memb1, memb2)

struct _pe_context
{
  struct image_dos_header dos_header;
  struct image_nt_headers nt_header;
  struct
  {
    struct image_section_header* array;
    size_t size;
  } section_headers;
  struct
  {
    struct image_export_directory descriptor;
    struct _export_func_entry
    {
      char* func_name;
      uint16_t ordinal;  /* unbiased */
      struct image_export_table_entry rva;
    } *array;
    size_t nfuncs;
  } exports;
  struct
  {
    struct _import_entry
    {
      struct image_import_descriptor descriptor;
      char* module_name;
      void* module_base;
      struct _import_func_entry
      {
        char* name;
        void* address;
      } *funcs;
      size_t nfuncs;
    } *array;
    size_t size;
  } imports;
};

static bool
is_image_x64 (pe_context_t pe_context)
{
  return (
    pe_context->nt_header.optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
  );
}

static bool
validate_dos_header (pe_context_t pe_context)
{
  auto dos_header = pe_context->dos_header;
  if (dos_header.e_magic != 0x5a4d)
  {
    $trace_debug (
      "invalid file DOS header magic number, got: %" PRIu16,
      dos_header.e_magic);
    return false;
  }
  $trace_debug ("file DOS header is VALID");
  return true;
}

static bool
validate_nt_headers (pe_context_t pe_context)
{
  auto nt_header = pe_context->nt_header;
  if (nt_header.signature != IMAGE_NT_PE_SIGNATURE)
  {
    $trace_debug (
      "invalid NT header signature, got: %" PRIx32 ", expected: %" PRIx32,
      nt_header.signature, IMAGE_NT_PE_SIGNATURE);
    return false;
  }
  
  auto optional_header = nt_header.optional_header;
  switch (optional_header.magic)
  {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      $trace_debug (
        "file identified as 32-bit, image base: 0x%" PRIx32,
        optional_header.bases._32.image_base);
      break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      $trace_debug (
        "file identified as 64-bit, image base: 0x%" PRIx64,
        optional_header.bases._64.image_base);
      break;
    default:
      $trace_debug (
        "invalid optional header magic number: %" PRIx16,
        optional_header.magic);
      return false;
  }
  $trace_debug ("file NT headers are VALID");
  return true;
}

static struct image_section_header*
find_section_by_rva (pe_context_t pe_context, uint64_t rva)
{
  auto nr_sections = pe_context->section_headers.size;
  auto section_headers = pe_context->section_headers.array;
  for (size_t i = 0; i < nr_sections; ++i)
  {
    auto section = &section_headers[i];
    if ((section->virtual_address <= rva)
        && (rva < section->virtual_address + section->misc.virtual_size))
      return section;
  }
  return NULL;
}

static uint64_t
find_fileoffs_by_rva (
  pe_context_t pe_context, struct image_section_header** out, uint64_t rva)
{
  auto section = find_section_by_rva (pe_context, rva);
  if (section == NULL)
    return 0;
  if (out != NULL)
    *out = section;
  return section->pointer_to_raw_data + (rva - section->virtual_address);
}

static uint64_t
find_directory_fileoffs (pe_context_t pe_context, uint8_t index)
{
  auto data_dir = pe_context->nt_header.optional_header.data_directory;
  auto entry = data_dir[index];
  struct image_section_header* section;
  auto file_offset = find_fileoffs_by_rva (
      pe_context, &section, entry.virtual_address);
  if (!file_offset)
  {
    $trace_debug (
      "invalid entry descriptor RVA: %" PRIx32,
      entry.virtual_address);
    return 0;
  }
  $trace_debug (
    "found directory (%" PRIu8 ") table in: %.8s (file+%" PRIx64 ")",
    index, section->name, file_offset);
  return file_offset;
}

static bool
resolve_imports (
  pe_context_t pe_context, FILE* file, struct _import_entry* ientry)
{
  $trace_alloc ("loading library handle: %s", ientry->module_name);
  auto module = platform_load_library (ientry->module_name);
  if (module == NULL)
  {
    $trace_debug ("failed to load module: %s", ientry->module_name);
    return false;
  }
  ientry->module_base = module;
  auto ilt_offset = find_fileoffs_by_rva (
    pe_context, NULL, ientry->descriptor.original_first_thunk);
  if (!ilt_offset)
  {
    $trace_debug (
      "failed to find ILT offset for module: %s", ientry->module_name);
    return false;
  }

  uint64_t size, rshift, msb_mask;
  if (is_image_x64 (pe_context))
  {
    size = sizeof (uint64_t);
    rshift = 0;
    msb_mask = 1ull << 63;
  }
  else
  {
    size = sizeof (uint32_t);
    rshift = 32;
    msb_mask = 1ull << 31;
  }

  for (size_t i = 0;; ++i)
  {
    fseek (file, ilt_offset + i * size, SEEK_SET);
    uint64_t ilt_entry = 0;
    if (!$try_read_sized (&ilt_entry, size, file))
    {
      $trace_debug (
        "failed to read ILT entry for module: '%s'", ientry->module_name);
      return false;
    }
    if (!ilt_entry)
      break;
    ilt_entry >>= rshift;
    $trace_alloc (
      "(re-)allocating function entry table for %zu entries",
      ientry->nfuncs + 1);
    auto funcs = reallocarray (
      ientry->funcs, sizeof (struct _import_func_entry), ++ientry->nfuncs);
    if (funcs == NULL)
      $abort ("failed to allocate import function array");
    ientry->funcs = funcs;
    auto fentry = &ientry->funcs[ientry->nfuncs - 1];
    if (ilt_entry & msb_mask)
    {
      /* TODO: import by ordinal */
      $trace_debug (
        "reading ordinal: %s#%" PRIx16,
        ientry->module_name, (uint16_t)ilt_entry);
      __builtin_unimplemented ();
    }
    else
    {
      auto hint_offset = find_fileoffs_by_rva(
        pe_context, NULL, ilt_entry & 0x7fffffff);
      if (!hint_offset)
      {
        $trace_debug ("failed to find hint/name offset for ILT");
        goto invalid_entry;
      }
      struct image_import_by_name hint_name;
      fseek (file, hint_offset, SEEK_SET);
      if (!$try_read_type (hint_name, file))
      {
        $trace_debug ("failed to read hint/name offset for ILT");
        goto invalid_entry;
      }
      $trace_alloc (
        "allocating buffer for function name (%d bytes)", MAX_FUNCNAME_LENGTH);
      char* func_name = calloc (sizeof (char), MAX_FUNCNAME_LENGTH);
      if (func_name == NULL)
        $abort ("failed to allocate function name buffer");
      auto nread = $try_read_asciz (func_name, MAX_FUNCNAME_LENGTH, file);
      if (!nread)
      {
        $trace_debug ("failed to read function name from hint/name");
        free (func_name);
        goto invalid_entry;
      }
      $trace_alloc (
        "downsizing buffer for function name to %d bytes", nread + 1);
      void* resized = realloc (func_name, nread + 1);
      if (resized == NULL)
        $abort ("failed to resize function name");
      func_name = resized;
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
    $trace_alloc (
      "downsizing function entry table to %zu entries", ientry->nfuncs - 1);
    funcs = reallocarray (
      ientry->funcs, sizeof (struct _import_func_entry), --ientry->nfuncs);
    if (funcs == NULL)
      $abort ("failed to reallocate import function array");
    ientry->funcs = funcs;
  }
  return true;
}

static bool
read_export_descriptors (pe_context_t pe_context, FILE* file, uint32_t offset)
{
  fseek (file, offset, SEEK_SET);
  auto exports = &pe_context->exports;
  if (!$try_read_type (exports->descriptor, file))
  {
    $trace_debug ("failed to read export directory from file");
    return false;
  }
  $trace_alloc (
    "allocating export table for %" PRIu32 " entries",
    exports->descriptor.number_of_functions);
  exports->nfuncs = exports->descriptor.number_of_functions;
  exports->array = calloc (sizeof (*exports->array), exports->nfuncs);
  if (exports->array == NULL)
    $abort ("failed to allocate exports array");
  auto offs_eat = find_fileoffs_by_rva (
    pe_context, NULL, exports->descriptor.address_of_functions);
  auto offs_names = find_fileoffs_by_rva (
    pe_context, NULL, exports->descriptor.address_of_names);
  auto offs_ordinals = find_fileoffs_by_rva (
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
    if (!$try_read_type (entry->rva, file))
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
      if (!$try_read_type (ordinal, file))
      {
        $trace_debug ("failed to read export table ordinal");
        goto fail;
      }
      if (ordinal != i)
        continue;
      fseek (file, offs_names + j * sizeof (uint32_t), SEEK_SET);
      uint32_t rva_name;
      if (!$try_read_type (rva_name, file))
      {
        $trace_debug ("failed to read export table entry name pointer");
        goto fail;
      }
      auto offs_name = find_fileoffs_by_rva (pe_context, NULL, rva_name);
      if (!offs_name)
      {
        $trace_debug ("failed to find export table entry name");
        goto fail;
      }
      $trace_alloc (
        "allocating %d bytes for export function name", MAX_FUNCNAME_LENGTH);
      entry->func_name = calloc (sizeof (char), MAX_FUNCNAME_LENGTH);
      if (entry->func_name == NULL)
        $abort ("failed to allocate export function name");
      fseek (file, offs_name, SEEK_SET);
      auto nread = $try_read_asciz (
        entry->func_name, MAX_FUNCNAME_LENGTH, file);
      if (!nread)
      {
        $trace_debug ("failed to read export function name");
        free (entry->func_name);
        goto fail;
      }
      $trace_alloc ("downsizing export function name to %d bytes", nread);
      auto resized = reallocarray (entry->func_name, sizeof (char), nread);
      if (resized == NULL)
        $abort ("failed to reallocate export function name");
      entry->func_name = resized;
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
  free (exports->array);
  return false;
}

static bool
read_import_descriptors (pe_context_t pe_context, FILE* file, uint32_t offset)
{
  for (size_t i = 0;; ++i)
  {
    fseek (
      file, offset + i * sizeof (struct image_import_descriptor), SEEK_SET);
    $trace_alloc (
      "(re-)allocating import array for %zu entries",
      pe_context->imports.size + 1);
    struct _import_entry* entries = reallocarray (
        pe_context->imports.array, sizeof (struct _import_entry),
        ++pe_context->imports.size);
    if (entries == NULL)
      $abort ("failed to reallocate IDT entries tables");
    pe_context->imports.array = entries;
    auto ientry = &entries[pe_context->imports.size - 1];
    /* NB: `reallocarray` doesn't zero memory like `calloc` :( */
    memset (ientry, 0, sizeof (*ientry));
    if (!$try_read_type (ientry->descriptor, file))
    {
      $trace_debug ("failed to read import descriptor");
      return false;
    }
    if (!ientry->descriptor.characteristics)
    {  /* sentinel descriptor */
      if (pe_context->imports.size)
      {
        $trace_alloc (
          "downsizing import array to %zu entries",
          pe_context->imports.size - 1);
        void* resized = reallocarray (
          pe_context->imports.array, sizeof (struct _import_entry),
          --pe_context->imports.size);
        if (resized == NULL)
          $abort ("failed to resize import array");
        pe_context->imports.array = resized;
      }
      break;
    }
    auto name_offset = find_fileoffs_by_rva (
      pe_context, NULL, ientry->descriptor.name);
    if (!name_offset)
    {
      $trace_debug ("failed to find IDT name");
      continue; 
    }
    $trace_alloc ("allocating module name (%d bytes)", MAX_PATH);
    ientry->module_name = calloc (sizeof (char), MAX_PATH);
    if (ientry->module_name == NULL)
      $abort ("failed to allocate IDT module name");
    fseek (file, name_offset, SEEK_SET);
    auto nread = $try_read_asciz (ientry->module_name, MAX_PATH, file);
    if (!nread)
    {
      $trace_debug ("failed to read IDT name");
      free (ientry->module_name);
      continue;
    }
    $trace_alloc ("downsizing module name to %d bytes", nread);
    void* resized = realloc (ientry->module_name, nread);
    if (resized == NULL)
      $abort ("failed to resize module name");
    ientry->module_name = resized;
    pe_context->imports.array = entries;
    if (!resolve_imports (pe_context, file, ientry))
    {
      $trace_debug (
        "failed to resolve imports for module: %s", ientry->module_name);
      $trace_alloc (
        "downsizing import array to %zu entries, and freeing module name",
        pe_context->imports.size - 1);
      free (ientry->module_name);
      resized = reallocarray (
        pe_context->imports.array, sizeof (struct _import_entry),
        --pe_context->imports.size);
      if (resized == NULL)
        $abort ("failed to resize import table");
      pe_context->imports.array = resized;
      continue;
    }
  }
  return true;
}

static pe_context_t
pe_context$alloc (void)
{
  auto pe_context = calloc (1, $ptrsize (pe_context_t));
  if (pe_context == NULL)
    $abort ("failed to allocate context");
  $trace_alloc (
    "allocated PE context: %p, size: %" PRIu64 " bytes", pe_context,
    $ptrsize (pe_context_t));
  return pe_context;
}

pe_context_t
pe_context$from_file (FILE* file, uint8_t flags)
{
  $trace_debug ("allocating PE context from file");
  auto pe_context = pe_context$alloc ();
  
  if (!$try_read_type (pe_context->dos_header, file))
    goto read_fail;
  if (!validate_dos_header (pe_context))
  {
    $trace_debug ("invalid file DOS header");
    goto fail;
  }

  fseek (file, pe_context->dos_header.e_lfanew, SEEK_SET);

  if (!$try_read_type (pe_context->nt_header.signature, file))
    goto read_fail;
  if (!$try_read_type (pe_context->nt_header.file_header, file))
    goto read_fail;

  /* splicing together the optional header, since there are variations
   * between the 32- and 64-bit versions
   */
  auto optional_header = &pe_context->nt_header.optional_header;
  if (!$try_read_sized (
      optional_header, $offset_between_opthdr (
        _$start, size_of_stack_reserve), file))
    goto read_fail;

  switch (optional_header->magic)
  {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      if (!$try_read_type (optional_header->size_of_stack_reserve.lo, file)
          || !$try_read_type (optional_header->size_of_stack_commit.lo, file)
          || !$try_read_type (optional_header->size_of_heap_reserve.lo, file)
          || !$try_read_type (optional_header->size_of_heap_commit.lo, file))
        goto read_fail;
      break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      if (!$try_read_type (optional_header->size_of_stack_reserve.u64, file)
          || !$try_read_type (optional_header->size_of_stack_commit.u64, file)
          || !$try_read_type (optional_header->size_of_heap_reserve.u64, file)
          || !$try_read_type (optional_header->size_of_heap_commit.u64, file))
        goto read_fail;
      break;
    default:
      $trace_debug (
        "invalid optional header magic number: %" PRIx16,
        optional_header->magic);
      goto fail;
  }

  if (!$try_read_sized (
      &optional_header->loader_flags, $offset_between_opthdr (
        loader_flags, _$end), file))
    goto read_fail;

  if (!validate_nt_headers (pe_context))
  {
    $trace_debug ("failed to validate NT headers");
    goto fail;
  }

  auto nr_sections = pe_context->nt_header.file_header.number_of_sections;
  auto array_size = nr_sections * sizeof (struct image_section_header);
  $trace_alloc (
    "allocating %" PRIu16 " PE section headers (%zu bytes)",
    nr_sections, array_size);
  auto section_headers = pe_context->section_headers.array
    = calloc (array_size, 1);
  if (section_headers == NULL)
    $abort ("failed to allocate PE section headers");
  pe_context->section_headers.size = nr_sections;

  if (!$try_read_sized (section_headers, array_size, file))
    goto read_fail;

  for (size_t i = 0; i < nr_sections; ++i)
  {
    auto section = section_headers[i];
    $trace_debug (
      "section '%.8s' at file offset %" PRIx32 " (virt. %" PRIx32 "), size %"
      PRIu32 " bytes (virt. %" PRIu32 " bytes)",
      section.name, section.pointer_to_raw_data, section.virtual_address,
      section.size_of_raw_data, section.misc.virtual_size);
  }

  if (flags & PE_CONTEXT_LOAD_IMPORT_DIRECTORY)
  {
    auto import_offset
      = find_directory_fileoffs (pe_context, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_offset)
    {
      $trace_debug ("failed to find import directory file offset");
      goto fail;
    }
    if (!read_import_descriptors (pe_context, file, import_offset))
      goto fail;
  }
  if (flags & PE_CONTEXT_LOAD_EXPORT_DIRECTORY)
  {
    auto export_offset
      = find_directory_fileoffs (pe_context, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_offset)
    {
      $trace_debug ("failed to find export directory file offset");
      goto fail;
    }
    if (!read_export_descriptors (pe_context, file, export_offset))
      goto fail;
  }

  return pe_context;

read_fail:
  $trace_debug ("failed to read bytes from file");
fail:
  pe_context$free (pe_context);
  return NULL;
}

void
pe_context$free (pe_context_t pe_context)
{
  $trace_alloc ("freeing export entries");
  for (size_t i = 0; i < pe_context->exports.nfuncs; ++i)
  {
    auto entry = pe_context->exports.array[i];
    $trace_alloc (
      "\tfreeing export: +%" PRIx32 "#%" PRIu16 " (%s)",
      entry.rva.address, entry.ordinal, entry.func_name);
    free (entry.func_name);
  }
  free (pe_context->exports.array);
  $trace_alloc ("freeing import entries");
  for (size_t i = 0; i < pe_context->imports.size; ++i)
  {
    auto ientry = pe_context->imports.array[i];
    $trace_alloc (
      "freeing function entry table for module: %s", ientry.module_name);
    for (size_t j = 0; j < ientry.nfuncs; ++j)
    {
      auto func = ientry.funcs[j];
      $trace_alloc ("\tfreeing function name: %s", func.name);
      free (func.name);
    }
    platform_free_library (ientry.module_base);
    free (ientry.funcs);
    free (ientry.module_name);
  }
  free (pe_context->imports.array);
  $trace_alloc ("freeing section headers");
  free (pe_context->section_headers.array);
  $trace_alloc ("freeing PE context");
  free (pe_context);
}