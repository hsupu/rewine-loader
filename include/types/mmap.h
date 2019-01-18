#pragma once

#include <stddef.h>

typedef struct _mmap_info {
    void *  address;
    size_t  size;
    size_t  offset;
    size_t  pos;
    size_t  carry;
} mmap_info_t;

mmap_info_t * rewine_mmap_new(size_t offset, size_t size, void *address);
void rewine_mmap_free(mmap_info_t *mi);

void rewine_mmap_rewind(mmap_info_t *mi);
void * rewine_mmap_current(mmap_info_t *mi);
void * rewine_mmap_jump(mmap_info_t *mi, size_t pos, size_t carry);
void * rewine_mmap_next(mmap_info_t *mi, size_t carry);
