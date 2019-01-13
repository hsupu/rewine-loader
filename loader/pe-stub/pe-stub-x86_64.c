#if defined(__x86_64__)

#include "pe-stub-internal.h"

#include "pshpack1.h"
struct _stub {
    BYTE movq_rdi[2];      /* movq $dll,%rdi */
    const char *dll;
    BYTE movq_rsi[2];      /* movq $name,%rsi */
    const char *name;
    BYTE movq_rsp_rdx[4];  /* movq (%rsp),%rdx */
    BYTE movq_rax[2];      /* movq $entry, %rax */
    const void* entry;
    BYTE jmpq_rax[2];      /* jmp %rax */
};
#include "poppack.h"

void * __create_stub_asm(PVOID entrypoint, PCSTR dll, PCSTR name) {
    struct _stub *stub = MALLOC(struct _stub, 1);
    stub->movq_rdi[0]     = 0x48;
    stub->movq_rdi[1]     = 0xbf;
    stub->dll             = dll;
    stub->movq_rsi[0]     = 0x48;
    stub->movq_rsi[1]     = 0xbe;
    stub->name            = name;
    stub->movq_rsp_rdx[0] = 0x48;
    stub->movq_rsp_rdx[1] = 0x8b;
    stub->movq_rsp_rdx[2] = 0x14;
    stub->movq_rsp_rdx[3] = 0x24;
    stub->movq_rax[0]     = 0x48;
    stub->movq_rax[1]     = 0xb8;
    stub->entry           = entrypoint;
    stub->jmpq_rax[0]     = 0xff;
    stub->jmpq_rax[1]     = 0xe0;
    return stub;
}

#endif /* __x86_64__ */
