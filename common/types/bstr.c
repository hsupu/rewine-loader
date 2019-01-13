#include "types/bstr.h"

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
