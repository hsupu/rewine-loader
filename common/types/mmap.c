#include "misc/mem.h"
#include "types/mmap.h"

mmap_info_t * rewine_mmap_new(size_t offset, size_t size, void *address) {
    mmap_info_t *mi = MALLOC_S(mmap_info_t, 1);
    if (!mi) return NULL;
    mi->offset = offset;
    mi->size = size;
    mi->address = address;
    return mi;
}

void rewine_mmap_free(mmap_info_t *mi) {
    if (mi->address && mi->address != (void *)-1) {
        munmap(mi->address);
        mi->address = NULL;
    }
    free(mi);
}

void rewine_mmap_rewind(mmap_info_t *mi) {
    mi->pos = 0;
    mi->carry = 0;
}

void *rewine_mmap_current(mmap_info_t *mi) {
    return mi->address + mi->pos;
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
