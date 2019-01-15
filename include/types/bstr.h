#pragma once

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct bstr {
    size_t len;
    const char *str;
} bstr_t, BSTR, *PBSTR;

typedef struct bwstr {
    size_t len;
    const wchar_t *str;
} bwstr_t, BWSTR, *PBWSTR;

typedef const BSTR      *PCBSTR;
typedef const BWSTR     *PCBWSTR;

bstr_t * cstr2bstr(const char *cstr);
const char * bstr2cstr(bstr_t *bstr);

bstr_t * bstrdup(const bstr_t *bstr);
int bstrcmp(const bstr_t *a, const bstr_t *b);

bwstr_t * wstr2bstr(const wchar_t *wstr);
const wchar_t * bstr2wstr(bwstr_t *bstr);
