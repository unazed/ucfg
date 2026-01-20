#include <capstone/capstone.h>
#include <string.h>

#include "cfg/arch/x86.h"
#include "capstone/x86.h"

#define REG_RAX (0)
#define REG_RBX (1)
#define REG_RCX (2)
#define REG_RDX (3)
#define REG_RSI (4)
#define REG_RDI (5)
#define REG_RBP (6)
#define REG_RSP (7)
#define REG_R8  (8)
#define REG_R9  (9)
#define REG_R10 (10)
#define REG_R11 (11)
#define REG_R12 (12)
#define REG_R13 (13)
#define REG_R14 (14)
#define REG_R15 (15)
#define REG_RIP (16)

static uint64_t*
get_regloc_mask (
  struct cfg_sim_state_x86* state, enum x86_reg reg, uint64_t* mask)
{
#define $case_regloc_mask(_case, _mask, idx) \
  case _case: *mask = (_mask); return &state->gpregs[idx];
  
  switch (reg)
  {
    $case_regloc_mask(X86_REG_AL, REGMASK_LOWB, REG_RAX);
    $case_regloc_mask(X86_REG_AH, REGMASK_HIGHB, REG_RAX);
    $case_regloc_mask(X86_REG_AX, REGMASK_WORD, REG_RAX);
    $case_regloc_mask(X86_REG_EAX, REGMASK_DWORD, REG_RAX);
    $case_regloc_mask(X86_REG_RAX, REGMASK_QWORD, REG_RAX);
    
    $case_regloc_mask(X86_REG_BL, REGMASK_LOWB, REG_RBX);
    $case_regloc_mask(X86_REG_BH, REGMASK_HIGHB, REG_RBX);
    $case_regloc_mask(X86_REG_BX, REGMASK_WORD, REG_RBX);
    $case_regloc_mask(X86_REG_EBX, REGMASK_DWORD, REG_RBX);
    $case_regloc_mask(X86_REG_RBX, REGMASK_QWORD, REG_RBX);

    $case_regloc_mask(X86_REG_CL, REGMASK_LOWB, REG_RCX);
    $case_regloc_mask(X86_REG_CH, REGMASK_HIGHB, REG_RCX);
    $case_regloc_mask(X86_REG_CX, REGMASK_WORD, REG_RCX);
    $case_regloc_mask(X86_REG_ECX, REGMASK_DWORD, REG_RCX);
    $case_regloc_mask(X86_REG_RCX, REGMASK_QWORD, REG_RCX);

    $case_regloc_mask(X86_REG_DL, REGMASK_LOWB, REG_RDX);
    $case_regloc_mask(X86_REG_DH, REGMASK_HIGHB, REG_RDX);
    $case_regloc_mask(X86_REG_DX, REGMASK_WORD, REG_RDX);
    $case_regloc_mask(X86_REG_EDX, REGMASK_DWORD, REG_RDX);
    $case_regloc_mask(X86_REG_RDX, REGMASK_QWORD, REG_RDX);

    $case_regloc_mask(X86_REG_SIL, REGMASK_LOWB, REG_RSI);
    $case_regloc_mask(X86_REG_SI, REGMASK_WORD, REG_RSI);
    $case_regloc_mask(X86_REG_ESI, REGMASK_DWORD, REG_RSI);
    $case_regloc_mask(X86_REG_RSI, REGMASK_QWORD, REG_RSI);

    $case_regloc_mask(X86_REG_DIL, REGMASK_LOWB, REG_RDI);
    $case_regloc_mask(X86_REG_DI, REGMASK_WORD, REG_RDI);
    $case_regloc_mask(X86_REG_EDI, REGMASK_DWORD, REG_RDI);
    $case_regloc_mask(X86_REG_RDI, REGMASK_QWORD, REG_RDI);

    $case_regloc_mask(X86_REG_BPL, REGMASK_LOWB, REG_RBP);
    $case_regloc_mask(X86_REG_BP, REGMASK_WORD, REG_RBP);
    $case_regloc_mask(X86_REG_EBP, REGMASK_DWORD, REG_RBP);
    $case_regloc_mask(X86_REG_RBP, REGMASK_QWORD, REG_RBP);

    $case_regloc_mask(X86_REG_SPL, REGMASK_LOWB, REG_RSP);
    $case_regloc_mask(X86_REG_SP, REGMASK_WORD, REG_RSP);
    $case_regloc_mask(X86_REG_ESP, REGMASK_DWORD, REG_RSP);
    $case_regloc_mask(X86_REG_RSP, REGMASK_QWORD, REG_RSP);

    $case_regloc_mask(X86_REG_R8B, REGMASK_LOWB, REG_R8);
    $case_regloc_mask(X86_REG_R8W, REGMASK_WORD, REG_R8);
    $case_regloc_mask(X86_REG_R8D, REGMASK_DWORD, REG_R8);
    $case_regloc_mask(X86_REG_R8, REGMASK_QWORD, REG_R8);

    $case_regloc_mask(X86_REG_R9B, REGMASK_LOWB, REG_R9);
    $case_regloc_mask(X86_REG_R9W, REGMASK_WORD, REG_R9);
    $case_regloc_mask(X86_REG_R9D, REGMASK_DWORD, REG_R9);
    $case_regloc_mask(X86_REG_R9, REGMASK_QWORD, REG_R9);

    $case_regloc_mask(X86_REG_R10B, REGMASK_LOWB, REG_R10);
    $case_regloc_mask(X86_REG_R10W, REGMASK_WORD, REG_R10);
    $case_regloc_mask(X86_REG_R10D, REGMASK_DWORD, REG_R10);
    $case_regloc_mask(X86_REG_R10, REGMASK_QWORD, REG_R10);

    $case_regloc_mask(X86_REG_R11B, REGMASK_LOWB, REG_R11);
    $case_regloc_mask(X86_REG_R11W, REGMASK_WORD, REG_R11);
    $case_regloc_mask(X86_REG_R11D, REGMASK_DWORD, REG_R11);
    $case_regloc_mask(X86_REG_R11, REGMASK_QWORD, REG_R11);

    $case_regloc_mask(X86_REG_R12B, REGMASK_LOWB, REG_R12);
    $case_regloc_mask(X86_REG_R12W, REGMASK_WORD, REG_R12);
    $case_regloc_mask(X86_REG_R12D, REGMASK_DWORD, REG_R12);
    $case_regloc_mask(X86_REG_R12, REGMASK_QWORD, REG_R12);

    $case_regloc_mask(X86_REG_R13B, REGMASK_LOWB, REG_R13);
    $case_regloc_mask(X86_REG_R13W, REGMASK_WORD, REG_R13);
    $case_regloc_mask(X86_REG_R13D, REGMASK_DWORD, REG_R13);
    $case_regloc_mask(X86_REG_R13, REGMASK_QWORD, REG_R13);

    $case_regloc_mask(X86_REG_R14B, REGMASK_LOWB, REG_R14);
    $case_regloc_mask(X86_REG_R14W, REGMASK_WORD, REG_R14);
    $case_regloc_mask(X86_REG_R14D, REGMASK_DWORD, REG_R14);
    $case_regloc_mask(X86_REG_R14, REGMASK_QWORD, REG_R14);

    $case_regloc_mask(X86_REG_R15B, REGMASK_LOWB, REG_R15);
    $case_regloc_mask(X86_REG_R15W, REGMASK_WORD, REG_R15);
    $case_regloc_mask(X86_REG_R15D, REGMASK_DWORD, REG_R15);
    $case_regloc_mask(X86_REG_R15, REGMASK_QWORD, REG_R15);

    $case_regloc_mask(X86_REG_IP, REGMASK_WORD, REG_RIP);
    $case_regloc_mask(X86_REG_EIP, REGMASK_DWORD, REG_RIP);
    $case_regloc_mask(X86_REG_RIP, REGMASK_QWORD, REG_RIP);

    case X86_REG_INVALID:
      /* this might be valid in some cases? */
      $abort ("tried to get location of invalid register");

    default:
      $abort ("unrecognised x86 register: %d", reg);
#undef $case_regloc_mask
  }
}

static inline bool
is_dirty_bit_set (struct cfg_sim_state_x86* state, uint64_t* regloc)
{
  $strict_assert (
    (state->gpregs <= regloc)
      && (regloc < (state->gpregs + $arraysize (state->gpregs))),
    "Invalid register location");
  return state->bitmap_gpregs & (1ull << (regloc - state->gpregs));
}

static inline void
set_dirty_bit (struct cfg_sim_state_x86* state, uint64_t* regloc)
{
  $strict_assert (
    (state->gpregs <= regloc)
      && (regloc < (state->gpregs + $arraysize (state->gpregs))),
    "Invalid register location");
  state->bitmap_gpregs |= 1ull << (regloc - state->gpregs);
}

void*
cfg_sim$x86$new_state (void)
{
  return $chk_allocty (struct cfg_sim_state_x86 *);
}

void
cfg_sim$x86$free_state (void* _state)
{
  $chk_free (_state);
}

void
cfg_sim$x86$reset (void* _state)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  memset (state->gpregs, 0, sizeof (state->gpregs));
  state->bitmap_gpregs = state->flags = 0;
}

uint64_t*
cfg_sim$x86$get_reg_indet (void* _state, uint64_t* mask, uint16_t _reg)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  auto reg = (enum x86_reg)_reg;
  return get_regloc_mask (state, reg, mask);
}

uint64_t*
cfg_sim$x86$get_reg (void* _state, uint64_t* mask, uint16_t _reg)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  auto regloc = cfg_sim$x86$get_reg_indet (_state, mask, _reg);

  if (!is_dirty_bit_set (state, regloc))
    return NULL;

  return regloc;
}

void
cfg_sim$x86$set_reg (void* _state, uint16_t _reg, uint64_t val)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  auto reg = (enum x86_reg)_reg;

  uint64_t mask;
  uint64_t* regloc = get_regloc_mask (state, reg, &mask);
  
  /* NB: writing to 32-bit registers clears the upper 32 bits of the 64-bit
   *     variant
   */
  if (mask == REGMASK_DWORD)
    *regloc = val & REGMASK_DWORD;
  else
    *regloc = (*regloc & ~mask) | (val & mask);

  set_dirty_bit (state, regloc);
}

void
cfg_sim$x86$set_pc (void* _state, uint64_t val)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  cfg_sim$x86$set_reg (state, X86_REG_RIP, val);
}

uint8_t
cfg_sim$x86$get_reg_width (void* _state, uint16_t _reg)
{
  auto state = (struct cfg_sim_state_x86 *)_state;
  auto reg = (enum x86_reg)_reg;

  uint64_t mask;
  (void)get_regloc_mask (state, reg, &mask);

  return __builtin_popcountg (mask);
}