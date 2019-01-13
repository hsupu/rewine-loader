#pragma once

#include <wchar.h>

#include "wintypes/hint.h"
#include "wintypes/primitive.h"

//
// UNICODE (Wide Character) types
//

#ifndef _MAC
typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
#else
// some Macintosh compilers don't define wchar_t in a convenient location, or define it as a char
typedef unsigned short WCHAR;    // wc,   16-bit UNICODE character
#endif

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

typedef _Null_terminated_ WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef _Null_terminated_ PWSTR *PZPWSTR;
typedef _Null_terminated_ CONST PWSTR *PCZPWSTR;
typedef _Null_terminated_ WCHAR UNALIGNED *LPUWSTR, *PUWSTR;
typedef _Null_terminated_ CONST WCHAR *LPCWSTR, *PCWSTR;
typedef _Null_terminated_ PCWSTR *PZPCWSTR;
typedef _Null_terminated_ CONST PCWSTR *PCZPCWSTR;
typedef _Null_terminated_ CONST WCHAR UNALIGNED *LPCUWSTR, *PCUWSTR;

typedef _NullNull_terminated_ WCHAR *PZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR *PCZZWSTR;
typedef _NullNull_terminated_ WCHAR UNALIGNED *PUZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR UNALIGNED *PCUZZWSTR;

typedef  WCHAR *PNZWCH;
typedef  CONST WCHAR *PCNZWCH;
typedef  WCHAR UNALIGNED *PUNZWCH;
typedef  CONST WCHAR UNALIGNED *PCUNZWCH;

#if _WIN32_WINNT >= 0x0600 || (defined(__cplusplus) && defined(WINDOWS_ENABLE_CPLUSPLUS))

typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;
typedef CONST WCHAR UNALIGNED *LPCUWCHAR, *PCUWCHAR;

//
//  UCS (Universal Character Set) types
//

typedef unsigned long UCSCHAR;

//
//  Even pre-Unicode agreement, UCS values are always in the
//  range U+00000000 to U+7FFFFFFF, so we'll pick an obvious
//  value.

#define UCSCHAR_INVALID_CHARACTER (0xffffffff)

#define MIN_UCSCHAR (0)

//
//  We'll assume here that the ISO-10646 / Unicode agreement
//  not to assign code points after U+0010FFFF holds so that
//  we do not have to have separate "UCSCHAR" and "UNICODECHAR"
//  types.
//

#define MAX_UCSCHAR (0x0010FFFF)

typedef UCSCHAR *PUCSCHAR;
typedef const UCSCHAR *PCUCSCHAR;

typedef UCSCHAR *PUCSSTR;
typedef UCSCHAR UNALIGNED *PUUCSSTR;

typedef const UCSCHAR *PCUCSSTR;
typedef const UCSCHAR UNALIGNED *PCUUCSSTR;

typedef UCSCHAR UNALIGNED *PUUCSCHAR;
typedef const UCSCHAR UNALIGNED *PCUUCSCHAR;

#endif // _WIN32_WINNT >= 0x0600


//
// ANSI (Multi-byte Character) types
//
typedef CHAR *PCHAR, *LPCH, *PCH;
typedef CONST CHAR *LPCCH, *PCCH;

typedef _Null_terminated_ CHAR *NPSTR, *LPSTR, *PSTR;
typedef _Null_terminated_ PSTR *PZPSTR;
typedef _Null_terminated_ CONST PSTR *PCZPSTR;
typedef _Null_terminated_ CONST CHAR *LPCSTR, *PCSTR;
typedef _Null_terminated_ PCSTR *PZPCSTR;
typedef _Null_terminated_ CONST PCSTR *PCZPCSTR;

typedef _NullNull_terminated_ CHAR *PZZSTR;
typedef _NullNull_terminated_ CONST CHAR *PCZZSTR;

typedef  CHAR *PNZCH;
typedef  CONST CHAR *PCNZCH;

//
// Neutral ANSI/UNICODE types and macros
//
#ifdef  UNICODE                     // r_winnt

#ifndef _TCHAR_DEFINED
typedef WCHAR TCHAR, *PTCHAR;
typedef WCHAR TBYTE , *PTBYTE ;
#define _TCHAR_DEFINED
#endif /* !_TCHAR_DEFINED */

typedef LPWCH LPTCH, PTCH;
typedef LPCWCH LPCTCH, PCTCH;
typedef LPWSTR PTSTR, LPTSTR;
typedef LPCWSTR PCTSTR, LPCTSTR;
typedef LPUWSTR PUTSTR, LPUTSTR;
typedef LPCUWSTR PCUTSTR, LPCUTSTR;
typedef LPWSTR LP;
typedef PZZWSTR PZZTSTR;
typedef PCZZWSTR PCZZTSTR;
typedef PUZZWSTR PUZZTSTR;
typedef PCUZZWSTR PCUZZTSTR;
typedef PZPWSTR PZPTSTR;
typedef PNZWCH PNZTCH;
typedef PCNZWCH PCNZTCH;
typedef PUNZWCH PUNZTCH;
typedef PCUNZWCH PCUNZTCH;
#define __TEXT(quote) L##quote      // r_winnt

#else   /* UNICODE */               // r_winnt

#ifndef _TCHAR_DEFINED
typedef char TCHAR, *PTCHAR;
typedef unsigned char TBYTE , *PTBYTE ;
#define _TCHAR_DEFINED
#endif /* !_TCHAR_DEFINED */

typedef LPCH LPTCH, PTCH;
typedef LPCCH LPCTCH, PCTCH;
typedef LPSTR PTSTR, LPTSTR, PUTSTR, LPUTSTR;
typedef LPCSTR PCTSTR, LPCTSTR, PCUTSTR, LPCUTSTR;
typedef PZZSTR PZZTSTR, PUZZTSTR;
typedef PCZZSTR PCZZTSTR, PCUZZTSTR;
typedef PZPSTR PZPTSTR;
typedef PNZCH PNZTCH, PUNZTCH;
typedef PCNZCH PCNZTCH, PCUNZTCH;
#define __TEXT(quote) quote         // r_winnt

#endif /* UNICODE */                // r_winnt
