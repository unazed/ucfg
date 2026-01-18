#include "cfg/cfg-sim.h"
#include "cfg/arch/x86.h"
#include "generic.h"

struct cfg_sim_ctx_fnptrs
{
  void* (*new_state)(void);
  void (*free_state)(void* state);
  void (*reset)(void* state);

  /* get_reg: returns a pointer to the register location, otherwise NULL
   *          if the value is yet indeterminate given the initial context
   */
  uint64_t* (*get_reg)(void* state, uint16_t reg);
  void (*set_reg)(void* state, uint16_t reg, uint64_t val);
};

struct _cfg_sim_ctx
{
  array_t /* struct cs_insn */ insns;
  void* state;
  struct cfg_sim_ctx_fnptrs fn;
};

static void
init_state_fnptrs (cfg_sim_ctx_t sim_ctx, cs_arch arch)
{
  switch (arch)
  {
    case CS_ARCH_X86:
      sim_ctx->fn = (struct cfg_sim_ctx_fnptrs){
        .new_state = cfg_sim$x86$new_state,
        .free_state = cfg_sim$x86$free_state,
        .reset = cfg_sim$x86$reset,
        .get_reg = cfg_sim$x86$get_reg,
        .set_reg = cfg_sim$x86$set_reg
      };
      sim_ctx->state = sim_ctx->fn.new_state ();
      break;
    default:
      $abort ("unsupported simulation architecture (%d)", arch);
  }
}

cfg_sim_ctx_t
cfg_sim$new_context (cs_arch arch)
{
  auto sim_ctx = $chk_allocty (cfg_sim_ctx_t);
  init_state_fnptrs (sim_ctx, arch);
  return sim_ctx;
}

void
cfg_sim$free (cfg_sim_ctx_t sim_ctx)
{
  sim_ctx->fn.free_state (sim_ctx->state);
  $chk_free (sim_ctx);
}

bool
cfg_sim$simulate_insns (cfg_sim_ctx_t sim_ctx, array_t insns)
{
  __builtin_unimplemented ();
}