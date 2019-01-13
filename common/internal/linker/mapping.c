#include "internal/linker/mapping.h"

void rewine_mmap_rewind(mmap_info_t *mi) {
    mi->pos = 0;
    mi->carry = 0;
}

void *rewine_mmap_current(mmap_info_t *mi) {
    return mi->addr + mi->pos;
}

void *rewine_mmap_jump(mmap_info_t *mi, size_t pos, size_t carry) {
    if (pos + carry >= mi->size) return 0;
    mi->pos = pos;
    mi->carry = carry;
    return rewine_mmap_current(mi);
}

void *rewine_mmap_next(mmap_info_t *mi, size_t carry) {
    return rewine_mmap_jump(mi, mi->pos + mi->carry, carry);
}
