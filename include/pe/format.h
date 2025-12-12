#pragma once

#include <stdint.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES (16)

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b)
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC (0x20b)
#define IMAGE_NT_PE_SIGNATURE         (0x4550)

#define IMAGE_DIRECTORY_ENTRY_EXPORT         (0)
#define IMAGE_DIRECTORY_ENTRY_IMPORT         (1)
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       (2)
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      (3)
#define IMAGE_DIRECTORY_ENTRY_SECURITY       (4)
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      (5)
#define IMAGE_DIRECTORY_ENTRY_DEBUG          (6)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   (7)
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      (8)
#define IMAGE_DIRECTORY_ENTRY_TLS            (9)
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    (10)
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   (11)
#define IMAGE_DIRECTORY_ENTRY_IAT            (12)
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   (13)
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (14)

#pragma pack(push, 1)

struct image_dos_header
{
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
};

struct image_file_header
{
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_headers;
  uint16_t characteristics;
};

struct image_data_directory
{
  uint32_t virtual_address;
  uint32_t size;
};

struct image_optional_header
{
  uint8_t _$start[0];
  uint16_t magic;
  uint8_t major_linker_version;
  uint8_t minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entry_point;
  union
  {
    struct
    {
      uint32_t base_of_code;
      uint64_t image_base;
    } _64;
    struct
    {
      uint32_t base_of_code;
      uint32_t base_of_data;
      uint32_t image_base;
    } _32;
  } bases;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t check_sum;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  union
  {
    uint64_t u64;
    struct
    {
      uint32_t hi;
      uint32_t lo;
    };
  } size_of_stack_reserve;
  union
  {
    uint64_t u64;
    struct
    {
      uint32_t hi;
      uint32_t lo;
    };
  } size_of_stack_commit;
  union
  {
    uint64_t u64;
    struct
    {
      uint32_t hi;
      uint32_t lo;
    };
  } size_of_heap_reserve;
  union
  {
    uint64_t u64;
    struct
    {
      uint32_t hi;
      uint32_t lo;
    };
  } size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;
  struct image_data_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
  uint8_t _$end[0];
};

struct image_nt_headers
{
  uint32_t signature;
  struct image_file_header file_header;
  struct image_optional_header optional_header;
};

struct image_section_header
{
  uint8_t name[8];
  union
  {
    uint32_t physical_address;
    uint32_t virtual_size;
  } misc;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_linenumbers;
  uint16_t number_of_relocations;
  uint16_t number_of_linenumbers;
  uint32_t characteristics;
};

#pragma pack(pop)