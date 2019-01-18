#pragma once

#include "types/bstr.h"
#include "types/linkedlist.h"
#include "types/mmap.h"
#include "wintypes/handle.h"
#include "wintypes/pe.h"

typedef enum _machine_type {
    MACHINE_I386, MACHINE_AMD64
} machine_type_t;

typedef enum _cpu_bits {
    CPU_BITS_32, CPU_BITS_64
} cpu_bits_t;

typedef enum _image_export_type {
    IMAGE_EXPORT_EXPORT,
    IMAGE_EXPORT_FORWARDER,
} image_export_type_t;

typedef struct _image_export_symbol_entry {
    DWORD                   ordinal;
    LPCSTR                  name;
    image_export_type_t     type;
    PVOID                   address;
    PVOID                   original;           // NULL means unmodified
} image_export_symbol_t;

typedef struct _image_import_symbol_entry {
    WORD                    ordinal;            // 0 means import by name
    PIMAGE_IMPORT_BY_NAME   name;
    PIMAGE_THUNK_DATA       iat_entry;
    PVOID                   stub;
    PVOID                   original;           // NULL means unmodified
} image_import_symbol_t;

typedef struct _image_import_dll_entry {
    struct _image_info     *image;
    size_t                  nb_symbol;
    image_import_symbol_t  *symbol_tbl;
} image_import_dll_t;

typedef struct _image_info {

    // mmap info

    BOOL                    is_fixed_base;
    PVOID                   image_base;
    size_t                  image_size;
    size_t                  headers_size;

    bstr_t                 *filename;
    mmap_info_t            *filemap;
    mmap_info_t            *map;

    size_t                  nb_section;
    mmap_info_t            *section_map_tbl;

    // freq-used vars

    PIMAGE_NT_HEADERS       nt;

    machine_type_t          machine;
    cpu_bits_t              bits;
    BOOL                    is_exe;
    BOOL                    is_dll;
    BOOL                    is_flatmap;

    // exports

    bstr_t                 *exportname;
    DWORD                   export_ordinal_base;
    size_t                  nb_export;
    image_export_symbol_t  *export_tbl;

    ll_t                   *referers; // ll<image_import_dll_t>

    // imports

    size_t                  nb_import;
    image_import_dll_t     *import_tbl;

} image_info_t;

#define IMAGE_FILE_FLAGS_ALREADY_RELOCATED          0x01

#define IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP            0x01

extern 