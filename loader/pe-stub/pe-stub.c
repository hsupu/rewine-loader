#include <stdio.h>

#include "pe-stub.h"
#include "pe-stub-internal.h"

static void stub_entry_point(PCSTR dll, PCSTR name, PVOID retaddr) {
    fprintf(stderr, "stub: %s %s\n", dll, name);
}

PVOID stub(image_info_t *dll, WORD ordinal, PCSTR name) {
    PCSTR dllname = (dll->exportname) ? dll->exportname->str : "";
    PSTR idname = MALLOC(CHAR, 256);
    if (ordinal) {
        sprintf(idname, "#%d", ordinal);
    } else {
        sprintf(idname, "%s", name);
    }
    return __create_stub_asm(stub_entry_point, dllname, idname);
}
