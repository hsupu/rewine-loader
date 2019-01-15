#pragma once

#include "internal/linker/pe.h"
#include "wintypes/string.h"
#include "wintypes/function.h"


HMODULE rewine_LoadLibrary(PCSTR filename);
FARPROC rewine_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName);
FARPROC rewine_GetProcAddressByOrdinal(HMODULE hModule, WORD wOrdinal);

size_t rewine_GetExports(HMODULE hModule, OUT image_export_symbol_t **out_export_tbl);
size_t rewine_GetImports(HMODULE hModule, OUT image_import_dll_t **out_import_tbl);
