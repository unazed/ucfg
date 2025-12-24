#pragma once

#include <stdbool.h>
#include "trace.h"

#define $ptrsize(ty) (sizeof (*(ty)(0)))
#define $offset_between(ty, memb1, memb2) \
  offsetof (ty, memb2) - offsetof (ty, memb1)

#define __builtin_unimplemented() $abort ("unimplemented")
#define auto __auto_type
