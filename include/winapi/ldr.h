#pragma once

#include "wintypes/hint.h"
#include "wintypes/primitive.h"
#include "wintypes/pe.h"

PIMAGE_BASE_RELOCATION WINAPI LdrProcessRelocationBlock(PVOID page, UINT count, USHORT *rel, INT_PTR delta);
