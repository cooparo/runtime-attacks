#ifndef SHADOW_STACK_H
#define SHADOW_STACK_H

#include <stddef.h>
#include <stdint.h>

#define SHADOW_STACK_MAX 1024

void   shadow_stack_init(void);
int    shadow_stack_push(uint64_t addr);
int    shadow_stack_pop(uint64_t *out);
size_t shadow_stack_depth(void);

#endif
