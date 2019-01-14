#include <stdio.h>
#include <unistd.h>

#include "misc/fs.h"

#include "../pe-loader.h"

typedef int (WINAPI *PFMyAdd)(int, int);

int main(int argc, const char *argv[]) {
    PCSTR fullname = "/mnt/hgfs/shared/HelloDll.dll";

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

    PFMyAdd pf = (PFMyAdd)rewine_GetProcAddressByName(hDll, "myadd");
    fprintf(stdout, "pf=%p\n", pf);
    int ret = pf(1, 2);
    fprintf(stdout, "ret=%d\n", ret);

    return 0;
}
