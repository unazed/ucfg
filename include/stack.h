#pragma once

#include "generic.h"

typedef struct _stack *stack_t;

void stack$free (stack_t);

__attribute__(( malloc(stack$free, 1) ))
stack_t stack$new (void);

void stack$push (stack_t, void* memb, size_t membsize);
void stack$pop (stack_t, void* dest, size_t membsize);
uint8_t* stack$reserve (stack_t, size_t size);
void stack$unreserve (stack_t, size_t size);