#pragma once

#include "generic.h"

#define stack$push_ty(stack, dest) \
  ({ \
    auto _dest = (dest); \
    stack$push ((stack), (_dest), sizeof (_des)); \
  })
#define stack$push_ptr(stack, dest) \
  ({ \
    auto _dest = (dest); \
    stack$push ((stack), (_dest), $ptrsize(_dest)); \
  })
#define stack$pop_ty(stack, dest) \
  ({ \
    auto _dest = (dest); \
    stack$pop ((stack), (_dest), sizeof (_des)); \
  })
#define stack$pop_ptr(stack, dest) \
  ({ \
    auto _dest = (dest); \
    stack$pop ((stack), (_dest), $ptrsize(_dest)); \
  })

typedef struct _stack *stack_t;

void stack$free (stack_t);

__attribute__(( malloc(stack$free, 1) ))
stack_t stack$new (void);

void stack$push (stack_t, void* memb, size_t membsize);
void stack$pop (stack_t, void* dest, size_t membsize);