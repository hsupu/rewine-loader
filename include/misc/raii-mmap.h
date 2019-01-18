#pragma once

#include "misc/raii.h"
#include "types/mmap.h"

void __cleanup_mmap_info(mmap_info_t *info);
#define RAII_MMAP RAII(__cleanup_mmap_info)
