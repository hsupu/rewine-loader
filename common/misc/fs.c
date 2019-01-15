#include "misc/fs.h"

#include <string.h>

#include "types/wstr.h"


PCSTR get_dirname(PCSTR fullname) {
    PCSTR p = strrchr(fullname, '/');
    return strndup(fullname, p - fullname);
}

PCWSTR get_dirname_w(PCWSTR fullname) {
    PCWSTR p = wcsrchr(fullname, '/');
    return wcsndup(fullname, p - fullname);
}

PCSTR get_basename(PCSTR fullname) {
    PCSTR p = strrchr(fullname, '/');
    return strdup((p) ? p + 1 : fullname);
}

PCWSTR get_basename_w(PCWSTR fullname) {
    PCWSTR p = wcsrchr(fullname, L'/');
    return wcsdup((p) ? p + 1 : fullname);
}
