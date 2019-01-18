#include <string.h>

#include "misc/fs.h"
#include "types/wstr.h"

PCSTR copy_dirname(PCSTR fullname) {
    PCSTR p = strrchr(fullname, '/');
    return strndup(fullname, p - fullname);
}

PCWSTR copy_dirname_w(PCWSTR fullname) {
    PCWSTR p = wcsrchr(fullname, '/');
    return wcsndup(fullname, p - fullname);
}

PCSTR copy_basename(PCSTR fullname) {
    PCSTR p = strrchr(fullname, '/');
    return strdup((p) ? p + 1 : fullname);
}

PCWSTR copy_basename_w(PCWSTR fullname) {
    PCWSTR p = wcsrchr(fullname, L'/');
    return wcsdup((p) ? p + 1 : fullname);
}
