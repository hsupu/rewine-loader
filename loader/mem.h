#pragma once

#include "types/mmap.h"
#include "wintypes/hint.h"
#include "wintypes/pe.h"

extern long page_size;
extern unsigned long page_mask;

int mmap_pe_file(int fd, OUT mmap_info_t **out_mi);
int mmap_zero(PVOID fixed_base, size_t size, OUT mmap_info_t **out_mi);

int set_mmap_protect(PIMAGE_SECTION_HEADER section, mmap_info_t *section_map);

DWORD align_to(UINT_PTR addr, DWORD size, DWORD mask);
DWORD align_to_page(UINT_PTR addr, DWORD size);
DWORD align_to_sector(UINT_PTR addr, DWORD size);
