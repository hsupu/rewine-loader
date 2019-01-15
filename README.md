# rewine loader

The native win32 DLL can be loaded and the routine inside the DLL can be called on Linux application, but you should build every infrastructure to make the DLL work.

For example, we can use the `lstrlenA()` in `kernel32.dll`, because it depends on no DLL else.

```c
#include "rewine-loader.c"
#include "wintypes/hint.h"      // for WINAPI
#include "wintypes/handle.h"    // for HMODULE
#include "wintypes/string.h"    // for LPCSTR

typedef int (WINAPI *PFstrlen)(LPCSTR);

int lstrlenA(LPCSTR lpString) {
    HMODULE hDll = rewine_LoadLibrary("/path/to/kernel32.dll");
    PFstrlen pf = (PFstrlen)rewine_GetProcAddressByName(hDll, "lstrlenA");
    return pf(lpString);
}
```

Luckily, we do make a step further, you can modify the export symbol of imported DLL or modify the import symbol of DLL to make DLL happy. This will help if you want to build a more lightweight infrastructure to porting DLLs to Linux platform.

```c
//TODO
```
