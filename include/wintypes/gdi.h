#pragma once

#include "wintypes/hint.h"
#include "wintypes/primitive.h"

typedef struct tagRECT
{
    LONG    left;
    LONG    top;
    LONG    right;
    LONG    bottom;
} RECT, *PRECT, NEAR *NPRECT, FAR *LPRECT;

typedef const RECT FAR* LPCRECT;

typedef struct _RECTL       /* rcl */
{
    LONG    left;
    LONG    top;
    LONG    right;
    LONG    bottom;
} RECTL, *PRECTL, *LPRECTL;

typedef const RECTL FAR* LPCRECTL;

typedef struct tagPOINT
{
    LONG  x;
    LONG  y;
} POINT, *PPOINT, NEAR *NPPOINT, FAR *LPPOINT;

typedef struct _POINTL      /* ptl  */
{
    LONG  x;
    LONG  y;
} POINTL, *PPOINTL;

typedef struct tagSIZE
{
    LONG        cx;
    LONG        cy;
} SIZE, *PSIZE, *LPSIZE;

typedef SIZE               SIZEL;
typedef SIZE               *PSIZEL, *LPSIZEL;

typedef struct tagPOINTS
{
#ifndef _MAC
    SHORT   x;
    SHORT   y;
#else
    SHORT   y;
    SHORT   x;
#endif
} POINTS, *PPOINTS, *LPPOINTS;

/* mode selections for the device mode function */
#define DM_UPDATE           1
#define DM_COPY             2
#define DM_PROMPT           4
#define DM_MODIFY           8

#define DM_IN_BUFFER        DM_MODIFY
#define DM_IN_PROMPT        DM_PROMPT
#define DM_OUT_BUFFER       DM_COPY
#define DM_OUT_DEFAULT      DM_UPDATE

/* device capabilities indices */
#define DC_FIELDS           1
#define DC_PAPERS           2
#define DC_PAPERSIZE        3
#define DC_MINEXTENT        4
#define DC_MAXEXTENT        5
#define DC_BINS             6
#define DC_DUPLEX           7
#define DC_SIZE             8
#define DC_EXTRA            9
#define DC_VERSION          10
#define DC_DRIVER           11
#define DC_BINNAMES         12
#define DC_ENUMRESOLUTIONS  13
#define DC_FILEDEPENDENCIES 14
#define DC_TRUETYPE         15
#define DC_PAPERNAMES       16
#define DC_ORIENTATION      17
#define DC_COPIES           18
