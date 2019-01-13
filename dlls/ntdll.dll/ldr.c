#include <stdio.h>

#include "winapi/ldr.h"


static WORD LOWORD(DWORD l) {
    return l & 0xFFFF;
}

static WORD HIWORD(DWORD l) {
    return (l >> 16) & 0xFFFF;
}

PIMAGE_BASE_RELOCATION WINAPI LdrProcessRelocationBlock(PVOID page, UINT count, USHORT *rel, INT_PTR delta) {
    INT_PTR hiword = HIWORD(delta);
    INT_PTR loword = LOWORD(delta);
    while (count--) {
        USHORT offset = *rel & 0xfff;
        PVOID addr = page + offset;
        int type = *rel >> 12;
        switch(type) {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(PWORD)addr += hiword;
            break;
        case IMAGE_REL_BASED_LOW:
            *(PWORD)addr += loword;
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(PINT)addr += delta;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(PLONGLONG)addr += delta;
            break;
        default:
            fprintf(stderr, "FIXME: unsupported fixup type: %x\n", type);
            return NULL;
        }
        rel++;
    }
    return (PIMAGE_BASE_RELOCATION)rel;  /* return address of next block */
}
