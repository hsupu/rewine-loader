#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <sys/stat.h>

#include "misc/fs.h"
#include "misc/mem.h"
#include "misc/raii-fd.h"
#include "misc/raii-mem.h"
#include "types/bstr.h"
#include "types/linkedlist.h"
#include "types/pe-image.h"
#include "winapi/ldr.h"
#include "winapi/rtl.h"
#include "wintypes/fnptr.h"
#include "wintypes/handle.h"
#include "wintypes/ntstatus.h"

#include "pe-stub/pe-stub.h"
#include "loaded-image.h"
#include "mem.h"
#include "pe-loader.h"

static int load_dll_c(PCSTR filename, OUT image_info_t **out_image);

/**
 * get relative virtual address
 */
static PVOID rva2va(image_info_t *image, LONG_PTR offset) {
    if (offset >= image->map->size) {
        fprintf(stderr, "ERR: rva2va: out of range: offset=%#zx size=%#zx\n", offset, image->map->size);
        return NULL;
    }
    return image->map->address + offset;
}

static NTSTATUS get_nt_from_mmap(mmap_info_t *mi, OUT PIMAGE_NT_HEADERS *out_nt) {
    rewine_mmap_rewind(mi);

    IMAGE_DOS_HEADER *dos;
    dos = (IMAGE_DOS_HEADER *)rewine_mmap_next(mi, sizeof(*dos));
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_NOT_MZ;

    PIMAGE_NT_HEADERS nt;
    nt = (PIMAGE_NT_HEADERS)rewine_mmap_jump(mi, dos->e_lfanew, sizeof(nt->Signature));
    if (!nt) return STATUS_INVALID_IMAGE_FORMAT;
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        IMAGE_OS2_HEADER *os2 = (IMAGE_OS2_HEADER *)nt;
        if (os2->ne_magic != IMAGE_OS2_SIGNATURE) return STATUS_INVALID_IMAGE_PROTECT;
        if (os2->ne_exetyp == 2) return STATUS_INVALID_IMAGE_WIN_16;
        if (os2->ne_exetyp == 5) return STATUS_INVALID_IMAGE_PROTECT;
        return STATUS_INVALID_IMAGE_NE_FORMAT;
    }
    *out_nt = nt;

    return STATUS_SUCCESS;
}

static int remmap_image_headers(image_info_t *image) {
    int ret;
    NTSTATUS status;

    ret = mmap_zero((image->is_fixed_base) ? image->image_base : NULL, image->image_size, &image->map);
    if (ret) {
        fprintf(stderr, "ERR: mmap /dev/zero failed: %d\n", ret);
        return 1;
    }
    image->map->pos = image->filemap->pos;
    image->map->carry = image->filemap->carry;
    memcpy(image->map->address, image->filemap->address, image->headers_size);
    
    status = get_nt_from_mmap(image->map, &image->nt);
    if (status) {
        fprintf(stderr, "ERR: remmap but headers is broken: status=%#xu\n", status);
        return 2;
    }
    return 0;
}

static int verify_image_checksum(image_info_t *image) {
    //TODO
    return 0;
}

static NTSTATUS load_image(image_info_t *image) {
    int ret;
    NTSTATUS status;

    mmap_info_t *fmi = image->filemap;

    PIMAGE_NT_HEADERS nt;
    status = get_nt_from_mmap(fmi, &nt);
    if (status) return status;

    if (!rewine_mmap_next(fmi, sizeof(nt->FileHeader))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    switch (nt->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
        image->machine = MACHINE_I386;
        image->bits = CPU_BITS_32;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        image->machine = MACHINE_AMD64;
        image->bits = CPU_BITS_64;
        break;
    default:
        return STATUS_INVALID_IMAGE_FORMAT;
    }

#if defined(_WIN64)
    if (image->bits != CPU_BITS_64) return STATUS_INVALID_IMAGE_WIN_32;
#else
    if (image->bits != CPU_BITS_32) return STATUS_INVALID_IMAGE_WIN_64;
#endif

    DWORD file_charact = nt->FileHeader.Characteristics;

    image->is_exe = (file_charact & IMAGE_FILE_EXECUTABLE_IMAGE); 
    image->is_dll = (file_charact & IMAGE_FILE_DLL);

    if (!nt->FileHeader.SizeOfOptionalHeader || !rewine_mmap_next(fmi, nt->FileHeader.SizeOfOptionalHeader)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_OPTIONAL_HEADER opthdr = &(nt->OptionalHeader);
    image->is_fixed_base    = opthdr->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    image->image_base       = (PVOID)opthdr->ImageBase;
    image->image_size       = align_to_page(0, opthdr->SizeOfImage);
    image->headers_size     = opthdr->SizeOfHeaders;
    image->is_flatmap       = (opthdr->SectionAlignment & page_mask) ? TRUE : FALSE;

    if (image->is_flatmap && (opthdr->FileAlignment != opthdr->SectionAlignment)) return STATUS_INVALID_FILE_FOR_SECTION;
    if (opthdr->Win32VersionValue) return STATUS_INVALID_IMAGE_FORMAT;
    if (opthdr->LoaderFlags) return STATUS_INVALID_IMAGE_FORMAT;
    
    if (verify_image_checksum(image)) return STATUS_INVALID_IMAGE_FORMAT;

    // remmap image headers after image base/size is set
    // we can use rva2va() after this
    ret = remmap_image_headers(image);
    if (ret) return STATUS_NO_MEMORY;

    nt = image->nt;
 
    // clr contains continuous sections from clr->VirtualAddress
    //TODO: load_clr()

    size_t nb_section = image->nb_section = nt->FileHeader.NumberOfSections;
    if (!rewine_mmap_next(image->map, sizeof(IMAGE_SECTION_HEADER) * nb_section)) {
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)rewine_mmap_current(image->map);
    if (image->is_flatmap) {
        // non page-aligned binary (native subsystem binary) just mmap the whole file
        for (int i = 0; i < nb_section; i++, section++) {
            // check if sections are loaded to the right offset
            if (section->VirtualAddress != section->PointerToRawData)
                fprintf(stderr, "ERR: load_dll: non page-aligned binary are loaded with an incorrect offset (section %d).\n", i + 1);
        }
        memcpy(
            image->map->address + nt->OptionalHeader.SizeOfHeaders,
            image->filemap->address + nt->OptionalHeader.SizeOfHeaders,
            nt->OptionalHeader.SizeOfImage - nt->OptionalHeader.SizeOfHeaders
        );
    } else {
        image->section_map_tbl = MALLOC_S(mmap_info_t, nb_section);
        mmap_info_t *section_map = image->section_map_tbl;

        for (int i = 0; i < nb_section; i++, section++, section_map++) {
            section_map->offset = section->PointerToRawData;
            section_map->address = rva2va(image, section->VirtualAddress);
            section_map->size = align_to_page(0, section->Misc.VirtualSize);

            DWORD section_charact = section->Characteristics;
            size_t copy_size = min(section->SizeOfRawData, section_map->size);
            if (copy_size) {
                BOOL allow = TRUE;
                if (section_charact & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                    allow = FALSE;
                    fprintf(stderr, "ERR: load_dll: attempt to copy uninitialized data (section %d).\n", i + 1);
                }
                if (!(section_charact & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_CODE))) {
                    allow = FALSE;
                    fprintf(stderr, "ERR: load_dll: attempt to copy unknown characteristics data (section %d).\n", i + 1);
                }
                if (allow) memcpy(section_map->address, fmi->address + section->PointerToRawData, copy_size);
            }

            set_mmap_protect(section, section_map);
        }
    }

    return STATUS_SUCCESS;
}

static int relocate(image_info_t *image) {

    if (image->is_flatmap) {
        // cannot relocate on non page-aligned binary
        fprintf(stdout, "cannot relocate on non page-aligned binary\n");
        return 0;
    }

    if (!(image->nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        fprintf(stdout, "relocate DLL only\n");
        return 0;
    }

    if (!(image->nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
        fprintf(stderr, "ERR: relocate: fixed image base\n");
        return 1;
    }

    if (image->nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        fprintf(stderr, "ERR: relocate: relocation info is stripped\n");
        return 2;
    }

    ULONG size;
    PIMAGE_BASE_RELOCATION reld = RtlImageDirectoryEntryToData(image->map->address, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size);
    if (!reld) return 0;

    INT_PTR delta = (LONG_PTR)(image->map->address - image->image_base);

    size_t used = 0;
    while (used < size) {
        used += reld->SizeOfBlock;
        // reld is followed by some Type/Offset field entries
        UINT nb_block = (reld->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        // returned address of the next reld
        reld = LdrProcessRelocationBlock(rva2va(image, reld->VirtualAddress), nb_block, (PWORD)(reld + 1), delta);
        if (!reld) return 3;
    }

    return 0;
}

static int load_exports(image_info_t *image) {
    ULONG size;
    PIMAGE_EXPORT_DIRECTORY expd = RtlImageDirectoryEntryToData(image->map->address, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (!expd) return 0;

    image->exportname = cstr2bstr(rva2va(image, expd->Name));

    size_t nb_export;
    nb_export = image->nb_export = expd->NumberOfFunctions;

    DWORD ordinal_base = image->export_ordinal_base = expd->Base;

    PDWORD fn_tbl = rva2va(image, expd->AddressOfFunctions);
    PDWORD name_tbl = rva2va(image, expd->AddressOfNames);
    PWORD ordinal_tbl = rva2va(image, expd->AddressOfNameOrdinals);

    image_export_symbol_t *export;
    export = image->export_tbl = MALLOC_S(image_export_symbol_t, nb_export);
    for (int i = 0; i < nb_export; i++, export++) {
        export->ordinal = ordinal_base + i;
        export->address = rva2va(image, fn_tbl[i]);

        if ((export->address >= (PVOID)expd) && (export->address < ((PVOID)expd) + size)) {
            // addr is point to a null-term ASCII string in .edata section
            export->type = IMAGE_EXPORT_FORWARDER;
        } else {
            // addr is point to the exported symbol
            export->type = IMAGE_EXPORT_EXPORT;
        }
    }

    for (int i = 0; i < expd->NumberOfNames; i++) {
        PCSTR name = rva2va(image, name_tbl[i]);
        WORD index = ordinal_tbl[i]; // not absolute ordinal
        image->export_tbl[index].name = name;
    }

    return 0;
}

static PVOID get_forwarded_export(image_info_t *image, PCSTR label);

/**
 * unchecked
 */
static PVOID get_export(image_info_t *image, image_export_symbol_t *export) {
    if (export->type == IMAGE_EXPORT_EXPORT) {
        return export->address;
    } else {
        return get_forwarded_export(image, export->address);
    }
}

static PVOID get_export_by_ordinal(image_info_t *image, WORD ordinal) {
    if (!image || !image->nb_export) return NULL;
    int index = ordinal - image->exp_ordinal_base;
    image_export_symbol_t *export = image->export_tbl + index;
    return get_export(image, export);
}

/**
 * TODO: try export_symbol_name_tbl[hint] first (if hint in [0, nb_export_symbol_name_tbl)), then bsearch(name)
 */
static PVOID get_export_by_name(image_info_t *image, WORD hint, PCSTR name) {
    if (!image || !image->nb_export) return NULL;
    image_export_symbol_t *export = image->export_tbl;
    for (int i = 0; i < image->nb_export; i++, export++) {
        if (!export || !export->name) continue;
        if (strcmp(export->name, name) == 0) {
            return get_export(image, export);
        }
    }
    return NULL;
}

static image_import_dll_t * find_import_dll_by_exportname(image_info_t *image, PBSTR exportname) {
    image_import_dll_t *dll = image->import_tbl;
    for (int i = 0; i < image->nb_import; i++, dll++) {
        if (!dll->image || !dll->image->exportname) continue;
        if (bstrcmp(dll->image->exportname, exportname) == 0) {
            return dll;
        }
    }
    return NULL;
}

static PVOID get_forwarded_export(image_info_t *image, PCSTR label) {
    PCSTR split = strrchr(label, '.');
    if (!split) {
        fprintf(stderr, "ERR: unresolveable forward export: %s\n", label);
        return NULL;
    }

    PSTR dllname = strndup(label, (split - label));
    RAII_MEM PBSTR bname = cstr2bstr(dllname);
    image_import_dll_t *dll = find_import_dll_by_exportname(image, bname);
    free(bname);
    free(dllname);
    if (!dll) {
        fprintf(stderr, "ERR: imported dll not found (maybe delayload ?): %s\n", label);
        return NULL;
    }
    if (split[1] == '#') {
        return get_export_by_ordinal(dll->image, (WORD)atoi(split + 2));
    } else {
        return get_export_by_name(dll->image, -1, split + 1);
    }
}

static int bind_import(image_info_t *image, PIMAGE_IMPORT_DESCRIPTOR impd, image_import_dll_t *dll) {
    PIMAGE_THUNK_DATA ilt = rva2va(image, impd->u.OriginalFirstThunk); // readonly
    PIMAGE_THUNK_DATA iat = rva2va(image, impd->FirstThunk); // rw

    size_t nb_symbol = 0;
    PIMAGE_THUNK_DATA ilt0 = ilt;
    while (ilt0->u1.Ordinal) {
        nb_symbol++;
        ilt0++;
    }
    dll->nb_symbol = nb_symbol;
    dll->symbol_tbl = MALLOC_S(image_import_symbol_t, nb_symbol);

    image_info_t *dll_image = dll->image;
    image_import_symbol_t *symbol = dll->symbol_tbl;
    for (int i = 0; i < nb_symbol; i++, ilt++, iat++, symbol++) {
        PVOID va;
        if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) {
            WORD ordinal = symbol->ordinal = IMAGE_ORDINAL(ilt->u1.Ordinal);
            va = get_export_by_ordinal(dll_image, ordinal);
        } else {
            PIMAGE_IMPORT_BY_NAME name = symbol->name = rva2va(image, ilt->u1.AddressOfData);
            va = get_export_by_name(dll_image, name->Hint, name->Name);
        }
        if (!va) {
            va = stub(dll_image, symbol->ordinal, (symbol->name) ? symbol->name->Name : NULL);
            symbol->stub = va;
        }
        iat->u1.Function = (ULONGLONG)va;
        symbol->iat_entry = iat;
    }
    
    return 0;
}

static int fixup_imports(image_info_t *image) {
    int ret;

    if (image->map_flags & IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP) return 0;
    image->map_flags ^= IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP;

    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR impd_tbl = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    if (!impd_tbl) return 0;

    size_t nb_import = 0;
    PIMAGE_IMPORT_DESCRIPTOR impd = impd_tbl;
    while (impd->u.Characteristics) {
        nb_import++;
        impd++;
    }
    image->nb_import = nb_import;
    if (!nb_import) return 0;

    image->import_tbl = MALLOC_S(image_import_dll_t, nb_import);

    image_import_dll_t *dll = image->import_tbl;
    impd = impd_tbl;
    for (int i = 0; i < nb_import; i++, dll++, impd++) {
        PSTR name = rva2va(image, impd->Name);
        size_t name_len = strlen(name);

        while (name_len && name[name_len-1] == ' ') name_len--; // remove trailing spaces
        if (name_len) {
            PSTR stripped_name = strndup(name, name_len);
            ret = load_dll_c(stripped_name, &(dll->image));
            free(stripped_name);
            if (ret) {
                fprintf(stderr, "ERR: fixup_imports load_dll(%s) return %d\n", name, ret);
            }
        }
        ret = bind_import(image, impd, dll);
        if (ret) {
            fprintf(stderr, "ERR: fixup_imports import_dll(%s) return %d\n", (dll->image) ? dll->image->filename->str : NULL, ret);
        }
    }

    return 0;
}

static int fixup_delayload_import(image_info_t *image) {
    int ret;

    ULONG size;
    PIMAGE_DELAYLOAD_DESCRIPTOR impd_tbl = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &size);
    if (!impd_tbl) return 0;

    return 0;
}

static int cleanup_discardable(image_info_t *image) {
    //TODO
    return 0;
}

static int load_native_dll(image_info_t *image, int fd) {
    int ret;
    NTSTATUS status;

    mmap_info_t *fmi;
    ret = mmap_pe_file(fd, &fmi);
    if (ret) {
        fprintf(stderr, "ERR: load_native_dll mmap_pe_file return %d\n", ret);
        return 1;
    }
    image->filemap = fmi;

    status = load_image(image);
    rewine_mmap_free(fmi);
    if (status) {
        fprintf(stderr, "ERR: load_native_dll load_image return %x\n", status);
        return 2;
    }

    ret = relocate(image);
    if (ret) {
        fprintf(stderr, "ERR: load_native_dll relocate: %d\n", ret);
        return 3;
    }

    ret = load_exports(image);
    if (ret) {
        fprintf(stderr, "ERR: load_native_dll load_exports: %d\n", ret);
        return 4;
    }

    if ((image->is_dll) || (image->subsystem == IMAGE_SUBSYSTEM_NATIVE)) {
        ret = fixup_imports(image);
        if (ret) {
            fprintf(stderr, "ERR: load_native_dll fixup_imports: %d\n", ret);
            return 5;
        }
    }

    cleanup_discardable(image);

    fprintf(stdout, "INFO: loaded %s (%p)\n", image->exportname->str, image->filename->str);
    
    return 0;
}

static int load_dll(PBSTR filename, OUT image_info_t **out_image) {
    int ret;

    if (!filename) {
        return 1;
    }

    *out_image = find_loaded_dll_by_filename(filename);
    if (*out_image) {
        return 0;
    }

    image_info_t *image = MALLOC_S(image_info_t, 1);
    ll_push(image_info_ll, image);
    *out_image = image;

    image->filename = bstrdup(filename);

    RAII_FD int fd;
    fd = open(image->filename->str, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    ret = load_native_dll(image, fd);
    if (ret) {
        fprintf(stderr, "ERR: load_dll load_native_dll: %d\n", ret);
        return 2;
    }

    add_loaded_dll(image);
    return 0;
}

static int load_dll_c(PCSTR filename, OUT image_info_t **out_image) {
    int ret;
    PBSTR bname = cstr2bstr(filename);
    ret = load_dll(bname, out_image);
    free(bname);
    return ret;
}

HMODULE rewine_LoadLibrary(LPCSTR lpLibFileName) {
    int ret;
    image_info_t *dll;
    ret = load_dll_c(lpLibFileName, &dll);
    if (ret) {
        fprintf(stderr, "ERR: LoadLibrary load_dll: %d\n", ret);
        return (HMODULE)NULL;
    }
    return dll;
}

FARPROC rewine_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName) {
    return get_export_by_name((image_info_t *)hModule, -1, lpProcName);
}

FARPROC rewine_GetProcAddressByOrdinal(HMODULE hModule, WORD wOrdinal) {
    return get_export_by_ordinal((image_info_t *)hModule, wOrdinal);
}
