#pragma once

#include <stdio.h>

#include "generic.h"
#include "pe/format.h"
#include "sys/cdefs.h"

#define PE_CONTEXT_LOAD_IMPORT_DIRECTORY (1ull << 0)
#define PE_CONTEXT_LOAD_EXPORT_DIRECTORY (1ull << 1)
#define PE_CONTEXT_LOAD_TLS_DIRECTORY    (1ull << 2)

typedef struct
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
} *pe_context_t;

void pe$free (pe_context_t pe_context);
__attribute__ (( malloc(pe$free, 1)))
pe_context_t pe$from_file (FILE* file, uint8_t flags);

bool pe$read_import_descriptors (pe_context_t pe_context, uint32_t offset);
bool pe$read_export_descriptors (pe_context_t pe_context, uint32_t offset);
bool pe$read_tls_directory (pe_context_t pe_context, uint32_t offset);
uint64_t pe$find_fileoffs_by_rva (
  pe_context_t pe_context, struct image_section_header** out, uint64_t rva);
bool pe$is_image_x64 (pe_context_t pe_context);
uint8_t pe$get_image_maxsize (pe_context_t pe_context);
uint64_t pe$get_image_base (pe_context_t pe_context);
uint64_t pe$rva_to_va (pe_context_t pe_context, uint64_t address);
uint64_t pe$va_to_rva (pe_context_t pe_context, uint64_t address);
int pe$read_maxint (uint64_t* into, pe_context_t pe_context);
uint64_t pe$find_directory_fileoffs (pe_context_t pe_context, uint8_t index);
uint32_t pe$get_pagesize (pe_context_t pe_context);
__attribute__ (( malloc(free, 1) ))
uint8_t* pe$read_page_at (pe_context_t pe_context, uint64_t rva);