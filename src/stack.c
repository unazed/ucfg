#include <string.h>

#include "stack.h"

#define INITIAL_STACK_SIZE    (1024)
#define ALLOC_STACK_INCREMENT (512)

struct _stack
{
  uint8_t *base, *top;
  size_t nmemb, capacity;
  size_t last_commit_size;
  struct
  {
    size_t alloc_increment;
  } opts;
};

void
stack$free (stack_t stack)
{
  $chk_free (stack->base);
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
  if (reserved_size <= stack->opts.alloc_increment)
    return;
  
  auto new_capacity = $round_up_to (stack->opts.alloc_increment, stack_size);
  stack->base = $chk_realloc (stack->base, new_capacity);
  $trace_debug (
    "downsized stack from %zu bytes to %zu", stack->capacity, new_capacity);
  stack->capacity = new_capacity;
}

static void
validate_stack_removal (stack_t stack, size_t size)
{
  if (stack->last_commit_size && (size != stack->last_commit_size))
    $abort (
      "last stack commit was %zu bytes, trying to decommit %zu",
      stack->last_commit_size, size);
  $strict_assert (stack->nmemb > 0, "Tried to decommit from an empty stack");
  $strict_assert (
    (size <= stack->capacity) && (size <= get_stack_size (stack)),
    "Tried to decommit more bytes than allocated from the stack");
  if (stack->nmemb == 1)
    $strict_assert (
      size == get_stack_size (stack),
      "Decommitting from stack would leave dangling data");
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
  stack->last_commit_size = membsize;
  stack->nmemb++;
}

void
stack$pop (stack_t stack, void* dest, size_t membsize)
{
  validate_stack_removal (stack, membsize);
  stack->top -= membsize;
  memcpy (dest, stack->top, membsize);
  $trace_debug ("popped stack member (size %zu bytes)", membsize);
  stack->last_commit_size = 0;
  stack->nmemb--;
  maybe_downsize_stack (stack);
}

uint8_t*
stack$reserve (stack_t stack, size_t size)
{
  maybe_extend_stack (stack, size);
  stack->top += size;
  stack->last_commit_size = size;
  stack->nmemb++;
  return stack->top;
}

void
stack$unreserve (stack_t stack, size_t size)
{
  validate_stack_removal (stack, size);
  stack->top -= size;
  stack->last_commit_size = 0;
  stack->nmemb--;
}