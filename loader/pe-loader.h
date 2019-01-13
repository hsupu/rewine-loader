#pragma once

#include "internal/linker/pe.h"
#include "wintypes/string.h"
#include "wintypes/function.h"


HMODULE rewine_LoadLibrary(PCSTR filename);
FARPROC rewine_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName);
FARPROC rewine_GetProcAddressByOrdinal(HMODULE hModule, WORD wOrdinal);
