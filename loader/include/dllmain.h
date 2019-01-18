#pragma once

#include "wintypes/hint.h"
#include "wintypes/primitive.h"
#include "wintypes/handle.h"

/**
 * DLL_PROCESS_ATTACH : Be called when the DLL is been loaded.
 * DLL_PROCESS_DETACH : Be called when the DLL is being unloaded (including at the time the process is terminating).
 * DLL_THREAD_ATTACH  : Be called when a new thread is been created after the DLL is attached.
 * DLL_THREAD_DETACH  : Be called when a thread is exiting.
 *  
 * If fdwReason is DLL_PROCESS_ATTACH, lpvReserved is NULL for dynamic loads and non-NULL for static loads.
 * If fdwReason is DLL_PROCESS_DETACH, lpvReserved is NULL if FreeLibrary has been called or the DLL load failed and non-NULL if the process is terminating.
 * 
 * If DllMain(DLL_PROCESS_ATTACH) returns FALSE, it means LoadLibrary failed, then DllMain(DLL_PROCESS_DETACH) should be called immediately and the DLL will be unloaded.
 * The return value is ignored with any other situation.
 */
BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
);

#define DLL_PROCESS_ATTACH   1    
#define DLL_THREAD_ATTACH    2    
#define DLL_THREAD_DETACH    3    
#define DLL_PROCESS_DETACH   0    
