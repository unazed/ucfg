#include <x86intrin.h>

#include "intrin.h"

uint64_t
__rolg (uint64_t val, uint64_t shift, uint8_t width)
{
  $strict_assert (
    !(width & (width - 1)) && (8 <= width) && (width <= 64),
    "Bit width must be a power of two between 8 and 64");
  switch (width)
  {
    case 8:   return __rolb (val, shift);
    case 16:  return __rolw (val, shift);
    case 32:  return __rold (val, shift);
    case 64:  return __rolq (val, shift);
    default: __builtin_unreachable ();
  }
}

uint64_t
__rorg (uint64_t val, uint64_t shift, uint8_t width)
{
  $strict_assert (
    !(width & (width - 1)) && (8 <= width) && (width <= 64),
    "Bit width must be a power of two between 8 and 64");
  switch (width)
  {
    case 8:   return __rorb (val, shift);
    case 16:  return __rorw (val, shift);
    case 32:  return __rord (val, shift);
    case 64:  return __rorq (val, shift);
    default: __builtin_unreachable ();
  }
}