#pragma once

#include "wintypes/hint.h"

#ifndef _MANAGED

#ifndef _MAC

#ifdef _WIN64
typedef INT_PTR (FAR WINAPI *FARPROC)();
typedef INT_PTR (NEAR WINAPI *NEARPROC)();
typedef INT_PTR (WINAPI *PROC)();
#else /* _WIN64 */
typedef int (FAR WINAPI *FARPROC)();
typedef int (NEAR WINAPI *NEARPROC)();
typedef int (WINAPI *PROC)();
#endif /* _WIN64 */

#else /* _MAC */
typedef int (CALLBACK *FARPROC)();
typedef int (CALLBACK *NEARPROC)();
typedef int (CALLBACK *PROC)();
#endif /* _MAC */

#else /* _MANAGED */
typedef INT_PTR (WINAPI *FARPROC)(void);
typedef INT_PTR (WINAPI *NEARPROC)(void);
typedef INT_PTR (WINAPI *PROC)(void);
#endif /* _MANAGED */
