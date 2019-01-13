#pragma once

// call convenience (copied from crtdefs.h)

#ifndef __stdcall
# ifdef __i386__
#  ifdef __GNUC__
#   if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || defined(__APPLE__)
#    define __stdcall __attribute__((__stdcall__)) __attribute__((__force_align_arg_pointer__))
#   else
#    define __stdcall __attribute__((__stdcall__))
#   endif
#  elif defined(_MSC_VER)
    /* __stdcall already exists */
#  else
#   error __stdcall should be defined manually
#  endif
# elif defined(__x86_64__) && defined (__GNUC__)
#  if (__GNUC__ > 5) || ((__GNUC__ == 5) && (__GNUC_MINOR__ >= 3))
#   define __stdcall __attribute__((ms_abi)) __attribute__((__force_align_arg_pointer__))
#  else
#   define __stdcall __attribute__((ms_abi))
#  endif
# elif defined(__arm__) && defined (__GNUC__) && !defined(__SOFTFP__)
#   define __stdcall __attribute__((pcs("aapcs-vfp")))
# elif defined(__aarch64__) && defined (__GNUC__)
#  define __stdcall __attribute__((ms_abi))
# else
#  define __stdcall
# endif
#endif /* __stdcall */

#ifndef __cdecl
# if defined(__i386__) && defined(__GNUC__)
#   if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || defined(__APPLE__)
#   define __cdecl __attribute__((__cdecl__)) __attribute__((__force_align_arg_pointer__))
#  else
#   define __cdecl __attribute__((__cdecl__))
#  endif
# elif defined(__x86_64__) && defined (__GNUC__)
#  if (__GNUC__ > 5) || ((__GNUC__ == 5) && (__GNUC_MINOR__ >= 3))
#   define __cdecl __attribute__((ms_abi)) __attribute__((__force_align_arg_pointer__))
#  else
#   define __cdecl __attribute__((ms_abi))
#  endif
# elif defined(__arm__) && defined (__GNUC__) && !defined(__SOFTFP__)
#   define __cdecl __attribute__((pcs("aapcs-vfp")))
# elif defined(__aarch64__) && defined (__GNUC__)
#  define __cdecl __attribute__((ms_abi))
# elif !defined(_MSC_VER)
#  define __cdecl
# endif
#endif /* __cdecl */


#define _CDECL      __cdecl
#define CDECL       _CDECL

#define WINAPI      __stdcall

#define APIENTRY    WINAPI
#define APIPRIVATE  WINAPI
#define CALLBACK    WINAPI
#define NTAPI       WINAPI
#define PASCAL      WINAPI
#define IMAGEAPI    WINAPI

// param modifier

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

// data type modifier

#define CONST const

#define _Null_terminated_
#define _NullNull_terminated_

#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
#define ALIGNMENT_MACHINE
#else
#undef ALIGNMENT_MACHINE
#endif

#if defined(ALIGNMENT_MACHINE)
#define UNALIGNED __unaligned
#if defined(_WIN64)
#define UNALIGNED64 __unaligned
#else
#define UNALIGNED64
#endif
#else
#define UNALIGNED
#define UNALIGNED64
#endif

#define NEAR
#define FAR

// dummy union/struct

//
// For compilers that don't support nameless unions/structs
//
#ifndef DUMMYUNIONNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define DUMMYUNIONNAME   u
#define DUMMYUNIONNAME2  u2
#define DUMMYUNIONNAME3  u3
#define DUMMYUNIONNAME4  u4
#define DUMMYUNIONNAME5  u5
#define DUMMYUNIONNAME6  u6
#define DUMMYUNIONNAME7  u7
#define DUMMYUNIONNAME8  u8
#define DUMMYUNIONNAME9  u9
#else
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
#define DUMMYUNIONNAME3
#define DUMMYUNIONNAME4
#define DUMMYUNIONNAME5
#define DUMMYUNIONNAME6
#define DUMMYUNIONNAME7
#define DUMMYUNIONNAME8
#define DUMMYUNIONNAME9
#endif
#endif // DUMMYUNIONNAME

#ifndef DUMMYSTRUCTNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define DUMMYSTRUCTNAME  s
#define DUMMYSTRUCTNAME2 s2
#define DUMMYSTRUCTNAME3 s3
#define DUMMYSTRUCTNAME4 s4
#define DUMMYSTRUCTNAME5 s5
#define DUMMYSTRUCTNAME6 s6
#else
#define DUMMYSTRUCTNAME
#define DUMMYSTRUCTNAME2
#define DUMMYSTRUCTNAME3
#define DUMMYSTRUCTNAME4
#define DUMMYSTRUCTNAME5
#define DUMMYSTRUCTNAME6
#endif
#endif // DUMMYSTRUCTNAME
