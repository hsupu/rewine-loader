#include <stdio.h>
#include <unistd.h>

#include "misc/fs.h"

#include "../pe-loader.h"

typedef int (WINAPI *PFMyAdd)(int, int);

typedef int (WINAPI *PFstrlen)(const char *);

int main(int argc, const char *argv[]) {
    PCSTR fullname = "/mnt/hgfs/shared/kernel32.dll";

    PCSTR dirname = get_dirname(fullname);
    PCSTR basename = get_basename(fullname);
    fprintf(stdout, "%s/ %s\n", dirname, basename);

    chdir(dirname);
    setvbuf(stdout, NULL, _IONBF, 0);

    HMODULE hDll = rewine_LoadLibrary(basename);
    if (hDll == (HMODULE)-1) {
        fprintf(stderr, "ERR: LoadLibrary\n");
        return 1;
    }
    fprintf(stdout, "INFO: LoadLibrary() %p\n", hDll);

    PFstrlen pf = (PFstrlen)rewine_GetProcAddressByName(hDll, "lstrlenA");
    fprintf(stdout, "pf=%p\n", pf);
    int ret = pf("HelloWorld");
    fprintf(stdout, "ret=%d\n", ret);

    return 0;
}
