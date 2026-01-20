#pragma once

#include <stdint.h>

#include "generic.h"

#define CFG_SIM_X86_NREGS (17)

#define REGMASK_LOWB  (0x00ff)
#define REGMASK_HIGHB (0xff00)
#define REGMASK_WORD  (0xffff)
#define REGMASK_DWORD (0xffffffff)
#define REGMASK_QWORD (0xffffffffffffffff)

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
uint64_t* cfg_sim$x86$get_reg (void* state, uint64_t* mask, uint16_t reg);
uint64_t* cfg_sim$x86$get_reg_indet (void* state, uint64_t* mask, uint16_t reg);
uint64_t cfg_sim$x86$get_flags (void* state);
void cfg_sim$x86$set_reg (void* state, uint16_t reg, uint64_t val);
void cfg_sim$x86$set_pc (void* state, uint64_t val);
void cfg_sim$x86$set_flag (void* state, uint64_t mask, bool val);
uint8_t cfg_sim$x86$get_reg_width (void* state, uint16_t reg);