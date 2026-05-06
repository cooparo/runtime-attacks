#include "shadow_stack.h"
#include <stdio.h>

static uint64_t stack[SHADOW_STACK_MAX];
static size_t   top;

void shadow_stack_init(void) {
    top = 0;
}

int shadow_stack_push(uint64_t addr) {
    if (top >= SHADOW_STACK_MAX) {
        fprintf(stderr, "[shadow_stack] overflow at depth %zu\n", top);
        return -1;
    }
    stack[top++] = addr;
    return 0;
}

int shadow_stack_pop(uint64_t *out) {
    if (top == 0) return -1;
    *out = stack[--top];
    return 0;
}

size_t shadow_stack_depth(void) {
    return top;
}
