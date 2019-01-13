#pragma once

#include "misc/mem.h"
#include "wintypes/hint.h"
#include "wintypes/primitive.h"
#include "wintypes/string.h"

void * __create_stub_asm(PVOID entrypoint, PCSTR dll, PCSTR name);
