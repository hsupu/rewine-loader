#pragma once

#include <stdint.h>

// part

typedef void            VOID,       *PVOID,     *LPVOID;
typedef const void      CVOID,      *PCVOID,    *LPCVOID;

typedef int8_t          INT8,       *PINT8;
typedef int16_t         INT16,      *PINT16;
typedef int32_t         INT32,      *PINT32;
typedef int32_t         INT64,      *PINT64;

typedef uint8_t         UINT8,      *PUINT8;
typedef uint16_t        UINT16,     *PUINT16;
typedef uint32_t        UINT32,     *PUINT32;
typedef uint32_t        UINT64,     *PUINT64;

typedef int8_t          CHAR,       *PCHAR,     *LPCHAR;
typedef uint8_t         UCHAR,      *PUCHAR,    *LPUCHAR;

typedef int16_t         SHORT,      *PSHORT,    *LPSHORT;
typedef uint16_t        USHORT,     *PUSHORT,   *LPUSHORT;

typedef int32_t         INT,        *PINT,      *LPINT;
typedef uint32_t        UINT,       *PUINT,     *LPUINT;

typedef int32_t         LONG,       *PLONG,     *LPLONG;
typedef uint32_t        ULONG,      *PULONG,    *LPULONG;

typedef int8_t          BYTE,       *PBYTE,     *LPBYTE;
typedef uint16_t        WORD,       *PWORD,     *LPWORD;
typedef int32_t         DWORD,      *PDWORD,    *LPDOWRD;

typedef float           FLOAT,      *PFLOAT,    *LPFLOAT;
typedef double          DOUBLE,     *PDOUBLE,   *LPDOUBLE;

// part

typedef BYTE            BOOLEAN,    *PBOOLEAN;  
typedef BOOLEAN         BOOL,       *PBOOL,    *LPBOOL;

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE  1

// part

typedef intptr_t        INT_PTR,    *PINT_PTR;
typedef intptr_t        LONG_PTR,   *PLONG_PTR;
typedef uintptr_t       UINT_PTR,   *PUINT_PTR;
typedef uintptr_t       ULONG_PTR,  *PULONG_PTR;

// unofficial solution
typedef uint64_t        PVOID64;

// part

#if !defined(__int64)
typedef int64_t         __int64;
#endif

// part

#if !defined(_ULONGLONG_)
#define _ULONGLONG_

typedef int64_t         LONGLONG,   *PLONGLONG;
typedef uint64_t        ULONGLONG,  *PULONGLONG;

#define MAXLONGLONG (0x7fffffffffffffff)

#endif

// part

#if !defined(_FLOAT128_)
#define _FLOAT128_

#if defined(_M_IA64) && !defined(MIDL_PASS)
__declspec(align(16))
#endif
typedef struct _FLOAT128 {
    int64_t LowPart;
    int64_t HighPart;
} FLOAT128, *PFLOAT128;

#endif

// part

typedef void *HANDLE;
typedef HANDLE *PHANDLE, *LPHANDLE;

#ifdef STRICT
// this is just a type check machanism
#define DECLARE_HANDLE(a) typedef struct a##__ { int unused; } *a
#else /* STRICT */
#define DECLARE_HANDLE(a) typedef HANDLE a
#endif /* STRICT */

typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;

// part

// from minwindef.h

typedef UINT_PTR            WPARAM;
typedef LONG_PTR            LPARAM;
typedef LONG_PTR            LRESULT;
