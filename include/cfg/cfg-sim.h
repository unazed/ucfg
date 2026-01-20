#pragma once

#include <capstone/capstone.h>

#include "cfg/cfg.h"
#include "array.h"

struct cfg_sim_ctx_fnptrs
{
  void* (*new_state)(void);
  void (*free_state)(void* state);
  void (*reset)(void* state);

  /* get_reg: returns a pointer to the register location, otherwise NULL
   *          if the value is yet indeterminate given the initial context
   */
  uint64_t* (*get_reg)(void* state, uint64_t* mask, uint16_t reg);

  /* get_reg_indet: return pointer to the register location, only NULL if
   *                the register ID is invalid
   */
  uint64_t* (*get_reg_indet)(void* state, uint64_t* mask, uint16_t reg);
  void (*set_reg)(void* state, uint16_t reg, uint64_t val);
  void (*set_pc)(void* state, uint64_t val);
  uint8_t (*get_reg_width)(void* state, uint16_t reg);
};

struct _cfg_sim_ctx
{
  array_t /* struct cs_insn */ insns;
  void* state;
  struct cfg_sim_ctx_fnptrs fn;
};

typedef struct _cfg_sim_ctx *cfg_sim_ctx_t;

void cfg_sim$free (cfg_sim_ctx_t);

__attribute__ (( malloc (cfg_sim$free, 1) ))
cfg_sim_ctx_t cfg_sim$new_context (cs_arch arch);

bool cfg_sim$simulate_insns (cfg_sim_ctx_t, array_t /* struct cs_insn */ insns);
