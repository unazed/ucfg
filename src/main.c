#include <capstone/capstone.h>
#include <argp.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "pe/context.h"
#include "pe/format.h"
#include "cfg/cfg-gen.h"
#include "cfg/cfg.h"
#include "trace.h"

static char doc[] = "Control-flow graph generation for x86";
static char args_doc[] = "FILE";

static struct argp_option options[] = {
  { "file", 'c', "FILE", 0, "Path to PE image", 0 },
  { "entry", 'e', "ADDR", 0, "Entry point of PE image", 0 },
  { 0 }
};

struct arguments
{
  uint64_t entry_point;
  char* file_path;
};

static error_t
parse_opt (int key, char* arg, struct argp_state* state)
{
  struct arguments *args = state->input;
  switch (key)
  {
    case 'e':
      args->entry_point = strtoull (arg, NULL, 0);
      break;
    case 'c':
      args->file_path = arg;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num > 0)
        argp_usage (state);
      args->file_path = arg;
      break;
    case ARGP_KEY_END:
      if (!state->arg_num)
        argp_usage (state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int
main (int argc, char** argv)
{
  struct arguments args;
  args.entry_point = 0;
  argp_parse (&argp, argc, argv, 0, 0, &args);

  auto file = fopen (args.file_path, "rb");
  if (file == NULL)
    $abort ("failed to open path: %s", argv[1]);
  $trace_debug ("file opened: %s", argv[1]);

  auto pe_context = pe$from_file (
    file, PE_CONTEXT_LOAD_IMPORT_DIRECTORY | PE_CONTEXT_LOAD_EXPORT_DIRECTORY
      | PE_CONTEXT_LOAD_TLS_DIRECTORY);
  if (pe_context == NULL)
    $abort ("failed to create PE context from file");

  if (!args.entry_point)
    args.entry_point
      = pe_context->nt_header.optional_header.address_of_entry_point;

  auto entry_section = pe$find_section_by_rva (pe_context, args.entry_point);
  if (entry_section == NULL)
    $abort ("failed to find section containing entry-point")
  if (!(entry_section->characteristics & IMAGE_SCN_MEM_EXECUTE))
    $abort ("section containing entry-point is non-executable");
  $trace ("configured analysis entry-point: +0x%" PRIx64, args.entry_point);

  auto cfg = cfg$new (
    pe$get_image_base (pe_context), entry_section->size_of_raw_data);

  csh handle;
  if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    $abort ("failed to initialize Capstone");
  cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);

  auto cfg_gen_ctx = cfg_gen$new_context (pe_context, cfg, handle);

  if (!cfg_gen$recurse_function_block (cfg_gen_ctx, 0, args.entry_point))
    $abort ("failed to generate basic blocks");

  cfg_gen$free_context (cfg_gen_ctx);
  cfg$free (cfg);
  pe$free (pe_context);
  cs_close (&handle);
  fclose (file);

  return EXIT_SUCCESS;
}