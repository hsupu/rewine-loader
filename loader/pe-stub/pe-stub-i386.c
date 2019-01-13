#if defined(__i386__)

#include "pe-stub-internal.h"

#include "pshpack1.h"
struct _stub {
    BYTE        pushl1;     /* pushl $name */
    const char *name;
    BYTE        pushl2;     /* pushl $dll */
    const char *dll;
    BYTE        call;       /* call entrypoint */
    DWORD       entry;
};
#include "poppack.h"

void * __create_stub_asm(PVOID entrypoint, PCSTR dll, PCSTR name) {
    struct _stub *stub = MALLOC(struct _stub, 1);
    stub->pushl1    = 0x68;
    stub->name      = name;
    stub->pushl2    = 0x68;
    stub->dll       = dll;
    stub->call      = 0xe8;
    stub->entry     = (BYTE *)entrypoint - (BYTE *)(&stub->entry + 1);
    return stub;
}

#endif /* __i386__ */
