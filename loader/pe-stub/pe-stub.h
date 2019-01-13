#pragma once

#include "internal/linker/pe.h"
#include "wintypes/hint.h"
#include "wintypes/primitive.h"
#include "wintypes/string.h"

struct stub_malloc {
    PVOID   func;
    PSTR    name;
};

PVOID stub(image_info_t *info, WORD ordinal, PCSTR name);
