#pragma once

#include <wchar.h>

size_t mbs2wcs(const char *cstr, wchar_t **pwstr);
size_t wcs2mbs(const wchar_t * wstr, char **pcstr);

wchar_t * wcsndup(const wchar_t * string, size_t maxlen);