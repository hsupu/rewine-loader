#include <dlfcn.h>

void *rewine_dlopen(const char *filename, int flags) {
    return dlopen(filename, flags);
}

int rewine_dlclose(void *handle) {
    return dlclose(handle);
}

char *rewine_dlerror(void){
    return dlerror();
}

int rewine_dlinfo(void *handle, int request, void *info) {
    return dlinfo(handle, request, info);
}

void *rewine_dlsym(void *handle, const char *symbol) {
    return dlsym(handle, symbol);
}
