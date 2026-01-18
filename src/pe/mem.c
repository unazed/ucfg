#include "generic.h"
#include "pe/context.h"
#include <stddef.h>
#include <stdint.h>

bool
pe$is_image_x64 (pe_context_t pe_context)
{
  return (
    pe_context->nt_header.optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
  );
}

uint8_t
pe$get_image_maxsize (pe_context_t pe_context)
{
  return pe$is_image_x64 (pe_context)? sizeof (uint64_t): sizeof (uint32_t);
}

uint64_t
pe$get_image_base (pe_context_t pe_context)
{
  if (pe$is_image_x64 (pe_context))
    return pe_context->nt_header.optional_header.bases._64.image_base;
  return pe_context->nt_header.optional_header.bases._32.image_base;
}

uint64_t
pe$rva_to_va (pe_context_t pe_context, uint64_t address)
{
  return address + pe$get_image_base (pe_context);
}

uint64_t
pe$va_to_rva (pe_context_t pe_context, uint64_t address)
{
  return address - pe$get_image_base (pe_context);
}

int
pe$read_maxint (uint64_t* into, pe_context_t pe_context)
{
  if (pe$is_image_x64 (pe_context))
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

struct image_section_header*
pe$find_section_by_rva (pe_context_t pe_context, uint64_t rva)
{
  $array_for_each (
    $, pe_context->section_headers, struct image_section_header, section)
  {
    if (($.section->virtual_address <= rva)
        && (rva < $.section->virtual_address + $.section->misc.virtual_size))
      return $.section;
  }
  return NULL;
}

uint64_t
pe$find_fileoffs_by_rva (
  pe_context_t pe_context, struct image_section_header** out, uint64_t rva)
{
  auto section = pe$find_section_by_rva (pe_context, rva);
  if (section == NULL)
    return 0;
  if (out != NULL)
    *out = section;
  return section->pointer_to_raw_data + (rva - section->virtual_address);
}

uint64_t
pe$find_directory_fileoffs (pe_context_t pe_context, uint8_t index)
{
  auto data_dir = pe_context->nt_header.optional_header.data_directory;
  auto entry = data_dir[index];
  struct image_section_header* section;
  auto file_offset = pe$find_fileoffs_by_rva (
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

uint32_t
pe$get_pagesize (pe_context_t pe_context)
{
  return pe_context->nt_header.optional_header.section_alignment;
}

size_t
pe$get_ptrsize (pe_context_t pe_context)
{
  return pe$is_image_x64 (pe_context)? sizeof (uint64_t): sizeof (uint32_t);
}

uint8_t*
pe$read_sized (pe_context_t pe_context, uint64_t rva, uint64_t size)
{
  auto file = pe_context->stream;
  auto offset = pe$find_fileoffs_by_rva (pe_context, NULL, rva);
  if (!offset)
  {
    $trace_debug ("failed to find file offset for RVA: %" PRIx64, rva);
    return NULL;
  }
  fseek (file, offset, SEEK_SET);
  auto page_alloc = $chk_calloc (sizeof (char), size);
  if (!read_sized (page_alloc, size, file))
  {
    $trace_debug ("failed to read %" PRIu64 " bytes from file", size);
    $chk_free (page_alloc);
    return NULL;
  }
  return page_alloc;
}

uint8_t*
pe$read_page_at (pe_context_t pe_context, uint64_t rva)
{
  return pe$read_sized (pe_context, rva, pe$get_pagesize (pe_context));
}