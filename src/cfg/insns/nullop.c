#include "cfg/insns/dispatch.h"
#include "cfg/cfg-sim.h"

bool
sim_dispatch$nullop (cfg_sim_ctx_t sim_ctx, cs_insn* insn)
{
  return true;
}