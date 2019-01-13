#pragma once

void *rewine_dlopen(const char *filename, int flags);
int rewine_dlclose(void *handle);
char *rewine_dlerror(void);
int rewine_dlinfo(void *handle, int request, void *info);
void *rewine_dlsym(void *handle, const char *symbol);
