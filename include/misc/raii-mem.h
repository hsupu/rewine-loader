#pragma once
#include "misc/raii.h"

void __cleanup_mem(void **p);
#define RAII_MEM(__cleanup_mem)
