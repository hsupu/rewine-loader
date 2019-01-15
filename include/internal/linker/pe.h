#pragma once

#include "internal/types/primitive.h"
#include "types/bstr.h"
#include "types/linkedlist.h"
#include "wintypes/pe.h"
#include "wintypes/handle.h"

#include "mapping.h"

// PE Format : https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format

// typedef struct _IMAGE_NT_HEADERS_PORTABLE {
//     DWORD Signature;
//     IMAGE_FILE_HEADER FileHeader;
//     union {
//         IMAGE_OPTIONAL_HEADER32 hdr32;
//         IMAGE_OPTIONAL_HEADER64 hdr64;
//     } OptionalHeader;
// } image_nt_headers_t;

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
    PVOID                   original;   // NULL means unmodified
} image_export_symbol_t;

typedef struct _image_import_symbol_entry {
    WORD                    ordinal;    // 0 means import by name
    PIMAGE_IMPORT_BY_NAME   name;
    PIMAGE_THUNK_DATA       iat_entry;
    PVOID                   stub;
    PVOID                   original;   // NULL means unmodified
} image_import_symbol_t;

typedef struct _image_import_dll_entry {
    struct _image_info      *image;
    size_t                  nb_symbol;
    image_import_symbol_t   *symbol_tbl;
} image_import_dll_t;

typedef struct _image_info {

    // info unchanged from file

    ULONGLONG               image_base;
    size_t                  image_size;
    size_t                  headers_size;

    DWORD                   entrypoint; // RVA
    USHORT                  file_charact;
    USHORT                  dll_charact;
    WORD                    subsystem;

    DWORD                   exp_ordinal_base;

    // info derived from file

    BOOLEAN                 is_flatmap;
    bstr_t                  *filename;
    machine_type_t          machine;
    cpu_bits_t              bits;
    UINT                    file_flags;

    bstr_t                  *exportname;
    size_t                  nb_export;
    image_export_symbol_t   *export_tbl;

    size_t                  nb_import;
    image_import_dll_t      *import_tbl;
    
    // mmap (and relative)

    mmap_info_t             *filemap;
    mmap_info_t             *map;

    PIMAGE_NT_HEADERS       nt;

    IMAGE_DATA_DIRECTORY    *data_dir_tbl;
    IMAGE_COR20_HEADER      *cor20;

    size_t                  nb_section;
    mmap_info_t             *sec_mmap_tbl;

    // in memory

    UINT                    map_flags;

} image_info_t;

#define IMAGE_FILE_FLAGS_ALREADY_RELOCATED          0x01

#define IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP            0x01
