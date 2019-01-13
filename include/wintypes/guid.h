#pragma once

typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[ 8 ];
} GUID;

#ifndef _GUIDDEF_H_
#define _GUIDDEF_H_

#ifndef __LPGUID_DEFINED__
#define __LPGUID_DEFINED__
typedef GUID *LPGUID;
#endif

#ifndef __LPCGUID_DEFINED__
#define __LPCGUID_DEFINED__
typedef const GUID *LPCGUID;
#endif

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef GUID IID;
typedef IID *LPIID;
#define IID_NULL            GUID_NULL
#define IsEqualIID(riid1, riid2) IsEqualGUID(riid1, riid2)
typedef GUID CLSID;
typedef CLSID *LPCLSID;
#define CLSID_NULL          GUID_NULL
#define IsEqualCLSID(rclsid1, rclsid2) IsEqualGUID(rclsid1, rclsid2)
typedef GUID FMTID;
typedef FMTID *LPFMTID;
#define FMTID_NULL          GUID_NULL
#define IsEqualFMTID(rfmtid1, rfmtid2) IsEqualGUID(rfmtid1, rfmtid2)

#ifdef __midl_proxy
#define __MIDL_CONST
#else
#define __MIDL_CONST const
#endif

#ifndef _REFGUID_DEFINED
#define _REFGUID_DEFINED
#ifdef __cplusplus
#define REFGUID const GUID &
#else
#define REFGUID const GUID * __MIDL_CONST
#endif
#endif

#ifndef _REFIID_DEFINED
#define _REFIID_DEFINED
#ifdef __cplusplus
#define REFIID const IID &
#else
#define REFIID const IID * __MIDL_CONST
#endif
#endif

#ifndef _REFCLSID_DEFINED
#define _REFCLSID_DEFINED
#ifdef __cplusplus
#define REFCLSID const IID &
#else
#define REFCLSID const IID * __MIDL_CONST
#endif
#endif

#ifndef _REFFMTID_DEFINED
#define _REFFMTID_DEFINED
#ifdef __cplusplus
#define REFFMTID const IID &
#else
#define REFFMTID const IID * __MIDL_CONST
#endif
#endif

#endif // !__IID_DEFINED__

#if !defined (__midl)
#if !defined (_SYS_GUID_OPERATORS_)
#define _SYS_GUID_OPERATORS_
#include <string.h>

// Faster (but makes code fatter) inline version...use sparingly
#ifdef __cplusplus
__inline int InlineIsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
   return (
      ((unsigned long *) &rguid1)[0] == ((unsigned long *) &rguid2)[0] &&
      ((unsigned long *) &rguid1)[1] == ((unsigned long *) &rguid2)[1] &&
      ((unsigned long *) &rguid1)[2] == ((unsigned long *) &rguid2)[2] &&
      ((unsigned long *) &rguid1)[3] == ((unsigned long *) &rguid2)[3]);
}

__inline int IsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
    return !memcmp(&rguid1, &rguid2, sizeof(GUID));
}

#else   // ! __cplusplus

#define InlineIsEqualGUID(rguid1, rguid2)  \
        (((unsigned long *) rguid1)[0] == ((unsigned long *) rguid2)[0] &&   \
        ((unsigned long *) rguid1)[1] == ((unsigned long *) rguid2)[1] &&    \
        ((unsigned long *) rguid1)[2] == ((unsigned long *) rguid2)[2] &&    \
        ((unsigned long *) rguid1)[3] == ((unsigned long *) rguid2)[3])

#define IsEqualGUID(rguid1, rguid2) (!memcmp(rguid1, rguid2, sizeof(GUID)))

#endif  // __cplusplus

#ifdef __INLINE_ISEQUAL_GUID
#undef IsEqualGUID
#define IsEqualGUID(rguid1, rguid2) InlineIsEqualGUID(rguid1, rguid2)
#endif

// Same type, different name

#define IsEqualIID(riid1, riid2) IsEqualGUID(riid1, riid2)
#define IsEqualCLSID(rclsid1, rclsid2) IsEqualGUID(rclsid1, rclsid2)


#if !defined _SYS_GUID_OPERATOR_EQ_ && !defined _NO_SYS_GUID_OPERATOR_EQ_
#define _SYS_GUID_OPERATOR_EQ_
// A couple of C++ helpers

#ifdef __cplusplus
__inline bool operator==(REFGUID guidOne, REFGUID guidOther)
{
    return !!IsEqualGUID(guidOne,guidOther);
}

__inline bool operator!=(REFGUID guidOne, REFGUID guidOther)
{
    return !(guidOne == guidOther);
}
#endif
#endif  // _SYS_GUID_OPERATOR_EQ_
#endif  // _SYS_GUID_OPERATORS_
#endif  // __midl
#endif  // _GUIDDEF_H_
