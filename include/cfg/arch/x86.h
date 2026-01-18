#pragma once

#include <stdint.h>

#include "generic.h"

#define CFG_SIM_X86_NREGS (16)

struct cfg_sim_state_x86
{
  uint64_t gpregs[CFG_SIM_X86_NREGS];
  uint64_t bitmap_gpregs : CFG_SIM_X86_NREGS;
  uint64_t flags;
};

void cfg_sim$x86$free_state (void* state);

__attribute__ (( malloc(cfg_sim$x86$free_state, 1) ))
void* cfg_sim$x86$new_state (void);

void cfg_sim$x86$reset (void* state);
uint64_t* cfg_sim$x86$get_reg (void* state, uint16_t reg);
void cfg_sim$x86$set_reg (void* state, uint16_t reg, uint64_t val);