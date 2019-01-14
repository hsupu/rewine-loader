#include <string.h>

#include "types/wstr.h"

#include "misc/mem.h"


size_t mbs2wcs(const char *cstr, wchar_t **pwstr) {
    size_t clen = strlen(cstr);
    wchar_t *wstr = MALLOC(wchar_t, clen);
    return mbstowcs(wstr, cstr, clen);
}

size_t wcs2mbs(const wchar_t * wstr, char **pcstr) {
    size_t wlen = wcslen(wstr);
    char *cstr = MALLOC(char, wlen * 4);
    return wcstombs(cstr, wstr, wlen);
}

wchar_t * wcsndup(const wchar_t * string, size_t maxlen) {
    size_t n = wcsnlen(string, maxlen) + 1;
    wchar_t * r = malloc(n * sizeof(wchar_t));
    return r == NULL ? NULL : wmemcpy(r, string, n);
}
