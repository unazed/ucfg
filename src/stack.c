#include <string.h>

#include "stack.h"

#define INITIAL_STACK_SIZE    (1024)
#define ALLOC_STACK_INCREMENT (512)

struct _stack
{
  /* top still grows upwards, otherwise reallocation is inefficient */
  uint8_t *base, *top;
  size_t nmemb, capacity;
  struct
  {
    size_t alloc_increment;
  } opts;
};

void
stack$free (stack_t stack)
{

}

stack_t
stack$new (void)
{
  auto stack = $chk_allocty (stack_t);
  stack->capacity = INITIAL_STACK_SIZE;
  $trace_debug (
    "allocated stack with initial capacity %zu bytes", stack->capacity);
  stack->opts.alloc_increment = ALLOC_STACK_INCREMENT;
  stack->top = stack->base = $chk_allocb (stack->capacity);
  return stack;
}

static inline size_t
get_stack_size (stack_t stack)
{
  return stack->top - stack->base;
}

static inline size_t
get_uncommitted_size (stack_t stack)
{
  return stack->capacity - get_stack_size (stack);
}

static void
maybe_extend_stack (stack_t stack, size_t new_membsize)
{
  auto capacity = stack->capacity;
  if (get_stack_size (stack) + new_membsize <= capacity)
    return;
  auto new_capacity = capacity + $round_up_to (
    stack->opts.alloc_increment,
    $max (new_membsize, stack->opts.alloc_increment));
  stack->base = $chk_realloc (stack->base, new_capacity);
  stack->capacity = new_capacity;
  $trace_debug ("upsized stack from %zu bytes to %zu", capacity, new_capacity);
}

static void
maybe_downsize_stack (stack_t stack)
{
  size_t reserved_size = get_uncommitted_size (stack),
         stack_size = get_stack_size (stack);
  /* 4+512 byte membs in 1024 capacity stack, pop, then 1024 - 4 > 512 inc
   * so, round 4 up to next increment to 512
   * if only 511+2, pop 1, 512 >= 512, 
   */ 
  if (reserved_size <= stack->opts.alloc_increment)
    return;
  
  auto new_capacity = $round_up_to (stack->opts.alloc_increment, stack_size);
  stack->base = $chk_realloc (stack->base, new_capacity);
  $trace_debug (
    "downsized stack from %zu bytes to %zu", stack->capacity, new_capacity);
  stack->capacity = new_capacity;
}

void
stack$push (stack_t stack, void* memb, size_t membsize)
{
  maybe_extend_stack (stack, membsize);
  /* no need to use `memmove`, since if `memb` aliases
   * [stack->top, stack->top + membsize] we're already in trouble
   */
  memcpy (stack->top, memb, membsize);
  $trace_debug ("pushed stack member (size %zu bytes)", membsize);
  stack->top += membsize;
  stack->nmemb++;
}

void
stack$pop (stack_t stack, void* dest, size_t membsize)
{
  $strict_assert (stack->nmemb > 0, "Tried to pop from empty stack");
  $strict_assert (
    (membsize <= stack->capacity) && (membsize <= get_stack_size (stack)),
    "Tried to pop more bytes than allocated from stack");
  stack->top -= membsize;
  memcpy (dest, stack->top, membsize);
  $trace_debug ("popped stack member (size %zu bytes)", membsize);
  stack->nmemb--;
}