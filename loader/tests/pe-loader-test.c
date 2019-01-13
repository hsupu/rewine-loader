#include <stdio.h>
#include <unistd.h>

#include "misc/fs.h"

#include "../pe-loader.h"

int main(int argc, const char *argv[]) {
    PCSTR dirname = get_dirname(argv[1]);
    PCSTR basename = get_basename(argv[1]);
    fprintf(stdout, "%s / %s\n", dirname, basename);

    chdir(dirname);
    setvbuf(stdout, NULL, _IONBF, 0);

    HMODULE hDll = rewine_LoadLibrary(basename);
    if (hDll == (HMODULE)-1) {
        fprintf(stderr, "ERR: LoadLibrary\n");
        return 1;
    }
    fprintf(stdout, "INFO: LoadLibrary() %p\n", hDll);

    int (*lstrlenA)(LPCSTR lpString);
    lstrlenA = rewine_GetProcAddressByName(hDll, "lstrlenA");
    fprintf(stdout, "lstrlenA=%p\n", lstrlenA);
    int ret = lstrlenA("Hello World.");
    fprintf(stdout, "ret=%d\n", ret);

    return 0;
}
