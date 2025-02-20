#include "../../extern/AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"
#include "imgread.h"

#include <stdio.h>
#include <string.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x) - guest_base)

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })


void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base,
    uint8_t *input_buf, uint32_t input_buf_len) {

    // In this example the register RDI is pointing to the memory location
    // of the target buffer, and the length of the input is in RSI.
    // This can be seen with a debugger, e.g. gdb (and "disass main")
    printf("Placing input into 0x%lx\n", regs->rdi);
    memcpy( g2h(regs->rdi), input_buf, min(input_buf_len, sizeof(struct Image)) );
}

#undef g2h
#undef h2g

int afl_persistent_hook_init(void) {
    // 1 for shared memory input (faster), 0 for normal input (you have to use
    // read(), input_buf will be NULL)
    return 1;
}