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

#define $offset_between_opthdr(memb1, memb2) \
  $offset_between (struct image_optional_header, memb1, memb2)

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

static pe_context_t
pe$alloc (void)
{
  return $chk_calloc ($ptrsize (pe_context_t), 1);
}

pe_context_t
pe$from_file (FILE* file, uint8_t flags)
{
  $trace_debug ("allocating PE context from file");
  auto pe_context = pe$alloc ();
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
  if (!pe$read_maxint (&optional_header->size_of_stack_reserve, pe_context)
      || !pe$read_maxint (&optional_header->size_of_stack_commit, pe_context)
      || !pe$read_maxint (&optional_header->size_of_heap_reserve, pe_context)
      || !pe$read_maxint (&optional_header->size_of_heap_commit, pe_context))
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
    auto section = section_headers[i]; (void)section;
    $trace_debug (
      "section '%.8s' at file offset %" PRIx32 " (virt. %" PRIx32 "), size %"
      PRIu32 " bytes (virt. %" PRIu32 " bytes)",
      section.name, section.pointer_to_raw_data, section.virtual_address,
      section.size_of_raw_data, section.misc.virtual_size);
  }

  if (flags & PE_CONTEXT_LOAD_IMPORT_DIRECTORY)
  {
    auto import_offset = pe$find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_offset)
    {
      $trace_debug ("failed to find import directory file offset");
      goto fail;
    }
    if (!pe$read_import_descriptors (pe_context, import_offset))
      goto fail;
  }

  if (flags & PE_CONTEXT_LOAD_EXPORT_DIRECTORY)
  {
    auto export_offset = pe$find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_offset)
    {
      $trace_debug ("failed to find export directory file offset");
      goto fail;
    }
    if (!pe$read_export_descriptors (pe_context, export_offset))
      goto fail;
  }

  if (flags & PE_CONTEXT_LOAD_TLS_DIRECTORY)
  {
    auto tls_offset = pe$find_directory_fileoffs (
      pe_context, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls_offset)
    {
      $trace_debug ("failed to find TLS directory file offset");
      goto fail;
    }
    if (!pe$read_tls_directory (pe_context, tls_offset))
      goto fail;
  }

  return pe_context;

fail:
  pe$free (pe_context);
  return NULL;
}

void
pe$free (pe_context_t pe_context)
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