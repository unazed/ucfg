#include <stdbool.h>
#include <stdlib.h>

#include "pe/context.h"
#include "generic.h"
#include "pe/format.h"
#include "stdio.h"
#include "trace.h"

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
    for (nread = 0; nread < (max_length); ++nread) \
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
    if (into[nread]) \
      nread = 0; \
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
    struct image_export_directory* table;
  } exports;
  struct
  {
    struct
    {
      struct image_import_descriptor* array;
      char** names;
      size_t size;
    } desc;
  } imports;
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

static bool
read_import_descriptors (pe_context_t pe_context, FILE* file, uint32_t offset)
{
  fseek (file, offset, SEEK_SET);
  
  /* if we're parsing strictly, then we believe the size given by the
   * directory entry, otherwise we search until there's a null descriptor
   * to mark the end of the table
   */
  auto desc_size = sizeof (struct image_import_descriptor);
#ifdef PE_STRICT
  auto optional_header = pe_context->nt_header.optional_header;
  auto entry = optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  pe_context->imports.size = entry.size / desc_size - 1;
  pe_context->imports.descriptors
    = calloc (desc_size, pe_context->imports.size);
  if (pe_context->imports.descriptors == NULL)
    $abort ("failed to allocate import descriptor table");
  if (!$try_read_sized (
      pe_context->imports.descriptors, desc_size * pe_context->imports.size,
      file))
  {
    $trace_debug ("failed to read import descriptor table");
    free (pe_context->imports.descriptors);
    pe_context->imports.descriptors = NULL;
    return false;
  }
#else
  struct image_import_descriptor desc;
  while (true)
  {
    if (!$try_read_type (desc, file))
    {
      $trace_debug ("failed to read import descriptor");
      return false;
    }
    if (!desc.characteristics)
      break;  /* sentinel value */
  }
  pe_context->imports.desc.size = (ftell (file) - offset) / desc_size - 1;
  pe_context->imports.desc.array
    = calloc (desc_size, pe_context->imports.desc.size);
  if (pe_context->imports.desc.array == NULL)
    $abort ("failed to allocate import descriptor table");
  fseek (file, offset, SEEK_SET);
  if (!$try_read_sized (
      pe_context->imports.desc.array, desc_size * pe_context->imports.desc.size,
      file))
  {
    $trace_debug ("failed to read import descriptor table");
    free (pe_context->imports.desc.array);
    pe_context->imports.desc.array = NULL;
    return false;
  }
#endif
  $trace_debug ("read %zu import descriptors", pe_context->imports.desc.size);
  pe_context->imports.desc.names
    = calloc (sizeof (char*), pe_context->imports.desc.size);
  if (pe_context->imports.desc.names == NULL)
    $abort ("failed to allocate import descriptor name table");
  for (size_t i = 0; i < pe_context->imports.desc.size; ++i)
  {
    auto import = pe_context->imports.desc.array[i];
    char* import_name = calloc (sizeof (char), MAX_PATH);
    if (import_name == NULL)
      $abort ("failed to allocate import descriptor name");
    struct image_section_header* section;
    auto file_offset = find_fileoffs_by_rva (pe_context, &section, import.name);
    if (!file_offset)
    {
      $trace_debug ("failed to find section containing import name");
      free (import_name);
      continue;
    }
    fseek (file, file_offset, SEEK_SET);
    auto name_length = $try_read_asciz (import_name, MAX_PATH, file);
    if (!name_length)
    {
      $trace_debug ("failed to read import descriptor name");
      free (import_name);
      continue;
    }
    $trace_debug (
      "found import descriptor \"%s\" in: '%.8s' (file+%" PRIx64 ")",
      import_name, section->name, file_offset);
    import_name = reallocarray (import_name, sizeof (char), name_length + 1);
    if (import_name == NULL)
      $abort ("failed to reallocate import descriptor name");
    pe_context->imports.desc.names[i] = import_name;
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

  auto data_dir = optional_header->data_directory;
  if (flags & PE_CONTEXT_LOAD_IMPORT_DIRECTORY)
  {
    auto import_entry = data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    struct image_section_header* section;
    auto file_offset
      = find_fileoffs_by_rva (
        pe_context, &section, import_entry.virtual_address);
    if (!file_offset)
    {
      $trace_debug (
        "invalid import descriptor RVA: %" PRIx32,
        import_entry.virtual_address);
      goto fail;
    }
    $trace_debug (
      "found import descriptor table in: %.8s (file+%" PRIx64 ")",
      section->name, file_offset);
    fseek (file, file_offset, SEEK_SET);
    if (!read_import_descriptors (pe_context, file, file_offset))
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
  $trace_alloc ("freeing PE context: %p", pe_context);
  free (pe_context->section_headers.array);
  auto import_descs = pe_context->imports.desc;
  if (import_descs.array != NULL)
  {
    for (size_t i = 0; i < import_descs.size; ++i)
      free (import_descs.names[i]);
    free (import_descs.array);
  }
  free (pe_context);
}