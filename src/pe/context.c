#include <stdbool.h>
#include <stdlib.h>

#include "pe/context.h"
#include "generic.h"
#include "pe/format.h"
#include "stdio.h"
#include "trace.h"

#define $try_read_sized(into, size, file) \
  ({ \
    auto nread = fread (into, (size), 1, (file)); \
    if (nread) \
      $trace_verbose ("reading " #size " (%" PRIu64 ") bytes", size); \
    nread; \
  })
#define $try_read_type(into, file) \
  $try_read_sized (&(into), sizeof (into), file)

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
};

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
      $trace_debug ("file identified as 32-bit");
      break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      $trace_debug ("file identified as 64-bit");
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

pe_context_t
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
pe_context$alloc_from_file (FILE* file)
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
    $trace_verbose (
      "section #%zu: %.8s at RVA: %" PRIx32 ", size: %" PRIx32,
      i, section.name, section.virtual_address, section.misc.virtual_size);
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
  $trace_alloc ("freeing PE context: %p", pe_context);
  free (pe_context);
}