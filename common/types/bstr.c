#include "types/bstr.h"

// mbs

bstr_t * cstr2bstr(const char *cstr) {
    bstr_t *bstr = (bstr_t *)malloc(sizeof(bstr_t));
    bstr->len = strlen(cstr);
    bstr->str = cstr;
    return bstr;
}

const char * bstr2cstr(bstr_t *bstr) {
    const char *cstr = bstr->str;
    free(bstr);
    return cstr;
}

bstr_t * bstrdup(const bstr_t *bstr) {
    return cstr2bstr(strdup(bstr->str));
}

int bstrcmp(const bstr_t *a, const bstr_t *b) {
    if (!a || !b) return -1;
    return strcmp(a->str, b->str);
}

// wcs

bwstr_t * wstr2bstr(const wchar_t *wstr) {
    bwstr_t *bstr = (bwstr_t *)malloc(sizeof(bwstr_t));
    bstr->len = wcslen(wstr);
    bstr->str = wstr;
    return bstr;
}

const wchar_t * bstr2wstr(bwstr_t *bstr) {
    const wchar_t *wstr = bstr->str;
    free(bstr);
    return wstr;
}
