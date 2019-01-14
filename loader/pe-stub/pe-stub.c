#include <stdio.h>

#include "pe-stub.h"
#include "pe-stub-internal.h"

static void stub_entry_point(PCSTR dll, PCSTR name, PVOID retaddr) {
    fprintf(stderr, "stub: %s %s\n", dll, name);
}

PVOID stub(image_info_t *dll, WORD ordinal, PCSTR name) {
    PCSTR dllname = (dll->export_name) ? dll->export_name->str : "";
    PSTR idname = MALLOC(CHAR, 256);
    if (ordinal) {
        sprintf(idname, "#%d", ordinal);
    } else {
        sprintf(idname, "%s", name);
    }
    PVOID addr = __create_stub_asm(stub_entry_point, dllname, idname);
    if (!dll->stubs) {
        dll->stubs = ll_new();
    }
    struct stub_malloc *m = MALLOC(struct stub_malloc, 1);
    m->func = addr;
    m->name = idname;
    ll_push(dll->stubs, m);
    return addr;
}
