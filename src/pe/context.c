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

#define $read_type(into, file) \
  read_sized (&(into), sizeof (into), file)
#define $offset_between_opthdr(memb1, memb2) \
  $offset_between (struct image_optional_header, memb1, memb2)

struct _pe_context
{
  FILE* stream;
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
  struct
  {
    struct image_tls_table descriptor;
    uint64_t* callbacks;
    size_t ncallbacks;
  } tls;
};

static bool
is_image_x64 (pe_context_t pe_context)
{
  return (
    pe_context->nt_header.optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
  );
}

static uint8_t
get_image_maxsize (pe_context_t pe_context)
{
  return is_image_x64 (pe_context)? sizeof (uint64_t): sizeof (uint32_t);
}

static uint64_t
get_image_base (pe_context_t pe_context)
{
  if (is_image_x64 (pe_context))
    return pe_context->nt_header.optional_header.bases._64.image_base;
  return pe_context->nt_header.optional_header.bases._32.image_base;
}

static uint64_t
rva_to_va (pe_context_t pe_context, uint64_t address)
{
  return address + get_image_base (pe_context);
}

static uint64_t
va_to_rva (pe_context_t pe_context, uint64_t address)
{
  return address - get_image_base (pe_context);
}

static int
read_sized (void* into, size_t size, FILE* file)
{
  auto nread = fread (into, size, 1, file);
  if (nread)
    $trace_verbose ("read %" PRIu64 " bytes", size);
  else
    $trace_debug ("failed to read %" PRIu64 " bytes", size);
  return nread;
}

static int
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

static int
read_maxint (uint64_t* into, pe_context_t pe_context)
{
  if (is_image_x64 (pe_context))
  {
    uint64_t n;
    auto nread = $read_type (n, pe_context->stream);
    if (nread)
      *into = n;
    else
      $trace_debug ("failed to read 64-bit integer from file");
    return nread;
  }
  auto nread = $read_type (into, pe_context->stream);
  if (!nread)
    $trace_debug ("failed to read 32-bit integer from file");
  return nread;
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
  auto ilt_offset = find_fileoffs_by_rva (
    pe_context, NULL, ientry->descriptor.original_first_thunk);
  if (!ilt_offset)
  {
    $trace_debug (
      "failed to find ILT offset for module: %s", ientry->module_name);
    return false;
  }

  auto ilt_increment = get_image_maxsize (pe_context);
  for (size_t i = 0;; ++i)
  {
    fseek (file, ilt_offset + i * ilt_increment, SEEK_SET);
    uint64_t ilt_entry;
    auto nread = read_maxint (&ilt_entry, pe_context); 
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
      auto hint_offset = find_fileoffs_by_rva(
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

static bool
read_export_descriptors (pe_context_t pe_context, uint32_t offset)
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
      auto offs_name = find_fileoffs_by_rva (pe_context, NULL, rva_name);
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
  return false;
}

static bool
read_tls_directory (pe_context_t pe_context, uint32_t offset)
{
  auto file = pe_context->stream;
  auto tls = &pe_context->tls;
  fseek (file, offset, SEEK_SET);
  if (!read_maxint (&tls->descriptor.raw_data_start, pe_context)
      || !read_maxint (&tls->descriptor.raw_data_end, pe_context)
      || !read_maxint (&tls->descriptor.index_address, pe_context)
      || !read_maxint (&tls->descriptor.callback_address, pe_context)
      || !$read_type (tls->descriptor.size_of_zero_fill, file)
      || !$read_type (tls->descriptor.characteristics, file))
  {
    $trace_debug ("failed to read TLS descriptor from file");
    return false;
  }
  auto callback_offset = find_fileoffs_by_rva (
    pe_context, NULL, va_to_rva (pe_context, tls->descriptor.callback_address));
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
    tls->callbacks = $chk_reallocarray (
      tls->callbacks, sizeof (uint64_t), ++tls->ncallbacks);
  }
  return true;

fail:
  $chk_free (tls->callbacks);
  tls->callbacks = NULL;
  tls->ncallbacks = 0;
  return false;
}

static bool
read_import_descriptors (pe_context_t pe_context, uint32_t offset)
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
    auto name_offset = find_fileoffs_by_rva (
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

static pe_context_t
pe_context$alloc (void)
{
  return $chk_calloc ($ptrsize (pe_context_t), 1);
}

pe_context_t
pe_context$from_file (FILE* file, uint8_t flags)
{
  $trace_debug ("allocating PE context from file");
  auto pe_context = pe_context$alloc ();
  pe_context->stream = file;
  
  if (!$read_type (pe_context->dos_header, file))
    goto fail;
  if (!validate_dos_header (pe_context))
  {
    $trace_debug ("invalid file DOS header");
    goto fail;
  }

  fseek (file, pe_context->dos_header.e_lfanew, SEEK_SET);

  if (!$read_type (pe_context->nt_header.signature, file))
    goto fail;
  if (!$read_type (pe_context->nt_header.file_header, file))
    goto fail;

  /* splicing together the optional header, since there are variations
   * between the 32- and 64-bit versions
   */
  auto optional_header = &pe_context->nt_header.optional_header;
  if (!read_sized (
      optional_header, $offset_between_opthdr (
        _$start, size_of_stack_reserve), file))
    goto fail;

  switch (optional_header->magic)
  {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      break;
    default:
      $trace_debug (
        "invalid optional header magic number: %" PRIx16,
        optional_header->magic);
      goto fail;
  }
  if (!read_maxint (&optional_header->size_of_stack_reserve, pe_context)
      || !read_maxint (&optional_header->size_of_stack_commit, pe_context)
      || !read_maxint (&optional_header->size_of_heap_reserve, pe_context)
      || !read_maxint (&optional_header->size_of_heap_commit, pe_context))
    goto fail;

  if (!read_sized (
      &optional_header->loader_flags, $offset_between_opthdr (
        loader_flags, _$end), file))
    goto fail;

  if (!validate_nt_headers (pe_context))
  {
    $trace_debug ("failed to validate NT headers");
    goto fail;
  }

  auto nr_sections = pe_context->nt_header.file_header.number_of_sections;
  auto array_size = nr_sections * sizeof (struct image_section_header);
  auto section_headers = pe_context->section_headers.array
    = $chk_calloc (array_size, 1);
  pe_context->section_headers.size = nr_sections;

  if (!read_sized (section_headers, array_size, file))
    goto fail;

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
    auto import_offset = find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_offset)
    {
      $trace_debug ("failed to find import directory file offset");
      goto fail;
    }
    if (!read_import_descriptors (pe_context, import_offset))
      goto fail;
  }

  if (flags & PE_CONTEXT_LOAD_EXPORT_DIRECTORY)
  {
    auto export_offset = find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_offset)
    {
      $trace_debug ("failed to find export directory file offset");
      goto fail;
    }
    if (!read_export_descriptors (pe_context, export_offset))
      goto fail;
  }

  if (flags & PE_CONTEXT_LOAD_TLS_DIRECTORY)
  {
    auto tls_offset = find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls_offset)
    {
      $trace_debug ("failed to find TLS directory file offset");
      goto fail;
    }
    if (!read_tls_directory (pe_context, tls_offset))
      goto fail;
  }

  return pe_context;

fail:
  pe_context$free (pe_context);
  return NULL;
}

void
pe_context$free (pe_context_t pe_context)
{
  $trace_debug ("freeing PE context");
  $chk_free (pe_context->tls.callbacks);
  for (size_t i = 0; i < pe_context->exports.nfuncs; ++i)
  {
    auto entry = pe_context->exports.array[i];
    $chk_free (entry.func_name);
  }
  $chk_free (pe_context->exports.array);
  for (size_t i = 0; i < pe_context->imports.size; ++i)
  {
    auto ientry = pe_context->imports.array[i];
    for (size_t j = 0; j < ientry.nfuncs; ++j)
    {
      auto func = ientry.funcs[j];
      $chk_free (func.name);
    }
    platform_free_library (ientry.module_base);
    $chk_free (ientry.funcs);
    $chk_free (ientry.module_name);
  }
  $chk_free (pe_context->imports.array);
  $chk_free (pe_context->section_headers.array);
  $chk_free (pe_context);
}