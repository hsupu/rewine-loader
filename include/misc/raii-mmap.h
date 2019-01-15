#pragma once
#include "misc/raii.h"

#include "internal/linker/mapping.h"

void __cleanup_mmap_info(mmap_info_t *info);
#define RAII_MMAP RAII(__cleanup_mmap_info)
