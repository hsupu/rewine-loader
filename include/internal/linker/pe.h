#pragma once

#include "internal/types/primitive.h"
#include "types/bstr.h"
#include "types/linkedlist.h"
#include "wintypes/pe.h"
#include "wintypes/handle.h"

#include "mapping.h"

// PE Format : https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format

typedef struct _IMAGE_NT_HEADERS_PORTABLE {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 hdr32;
        IMAGE_OPTIONAL_HEADER64 hdr64;
    } OptionalHeader;
} image_nt_headers_t;

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

typedef struct _image_export_entry {
    DWORD                   ordinal;
    LPCSTR                  name;
    image_export_type_t     type;
    PVOID                   addr;
} image_export_t;

typedef struct _image_info {

    // info unchanged from file

    ULONGLONG               image_base;
    size_t                  image_size;
    size_t                  headers_size;

    DWORD                   entrypoint; // offset of file_base
    USHORT                  file_charact;
    USHORT                  dll_charact;
    WORD                    subsystem;

    // info derived from file

    BOOLEAN                 is_flatmap;
    bstr_t                  *filename;
    machine_type_t          machine;
    cpu_bits_t              bits;
    UINT                    file_flags;

    bstr_t                  *export_name;
    size_t                  nb_export;
    DWORD                   exp_ordinal_base;
    image_export_t          *exp_tbl;

    size_t                  dep_count;
    struct _image_info      **deps;
    
    // mmap (and relative)

    mmap_info_t             *filemap;
    mmap_info_t             *map;

    image_nt_headers_t      *nt;

    IMAGE_DATA_DIRECTORY    *data_dir_tbl;
    IMAGE_COR20_HEADER      *cor20;

    size_t                  nb_section;
    mmap_info_t             *sec_mmap_tbl;

    // in memory

    UINT                    map_flags;

    ll_t                    *stubs;

} image_info_t;

#define IMAGE_FILE_FLAGS_ALREADY_RELOCATED          0x01

#define IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP            0x01
