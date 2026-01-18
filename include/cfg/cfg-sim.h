#pragma once

#include <capstone/capstone.h>

#include "cfg/cfg.h"
#include "array.h"

typedef struct _cfg_sim_ctx *cfg_sim_ctx_t;

void cfg_sim$free (cfg_sim_ctx_t);

__attribute__ (( malloc (cfg_sim$free, 1) ))
cfg_sim_ctx_t cfg_sim$new_context (cs_arch arch);

bool cfg_sim$simulate_insns (cfg_sim_ctx_t, array_t /* struct cs_insn */ insns);
