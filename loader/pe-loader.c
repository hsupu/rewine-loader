#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "misc/fs.h"
#include "misc/mem.h"
#include "misc/raii-fd.h"
#include "internal/types/primitive.h"
#include "internal/linker/pe.h"
#include "types/bstr.h"
#include "types/linkedlist.h"
#include "wintypes/ntstatus.h"
#include "wintypes/handle.h"
#include "wintypes/function.h"

#include "winapi/ldr.h"
#include "winapi/rtl.h"

#include "pe-loader.h"
#include "pe-stub/pe-stub.h"


static const DWORD sector_mask = 0x1ff; // 511

static DWORD page_mask;

static int fd_zero = -1;

static size_t nb_image_info = 0;
static ll_t *image_info_ll;

// initialize

static void init_page_mask() {
    if (!page_mask)
        page_mask = sysconf(_SC_PAGESIZE) - 1;
}

static void init_fd_zero() {
    if (fd_zero < 0)
        fd_zero = open("/dev/zero", O_RDWR);
}

static void init_image_info_ll() {
    if (!image_info_ll)
        image_info_ll = ll_new();
}

static void __attribute__((constructor)) init_this_file() {
    init_page_mask();
    init_fd_zero();
    init_image_info_ll();
}

// utils

static int get_page_size() {
    init_page_mask();
    return page_mask + 1;
}

static DWORD align_to(UINT_PTR addr, DWORD size, DWORD mask) {
    return (DWORD)(((size) + (addr & mask) + mask) & ~mask);
}

static DWORD align_to_page(UINT_PTR addr, DWORD size) {
    return align_to(addr, size, page_mask);
}

static DWORD align_to_sector(UINT_PTR addr, DWORD size) {
    return align_to(addr, size, sector_mask);
}

static mmap_info_t * mmap_zero(size_t size) {
    init_fd_zero();

    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd_zero, 0);
    if (addr == (void *)-1) return NULL;

    mmap_info_t *mi = MALLOC(mmap_info_t, 1);
    mi->addr = addr;
    mi->size = size;
    mi->offset = 0;
    return mi;
}

/**
 * get relative virtual address
 */
static PVOID rva2va(image_info_t *info, LONG_PTR offset) {
    return info->map->addr + offset;
}

// funcs

static int load_dll(PBSTR filename, OUT image_info_t **out_dll);

static int mmap_image_file(int fd, mmap_info_t *mi) {
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) < 0) {
        return 2;
    }
    mi->size = fd_stat.st_size;
    if ((mi->addr = mmap(NULL, mi->size, PROT_READ, MAP_SHARED, fd, 0)) == (void *)-1) {
        return 3;
    }
    close(fd);
    return 0;
}

static NTSTATUS get_nt_from_mmap(mmap_info_t *mi, image_nt_headers_t **pnt) {
    rewine_mmap_rewind(mi);

    IMAGE_DOS_HEADER *dos;
    dos = (IMAGE_DOS_HEADER *)rewine_mmap_next(mi, sizeof(*dos));
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_NOT_MZ;

    image_nt_headers_t *nt;
    nt = (image_nt_headers_t *)rewine_mmap_jump(mi, dos->e_lfanew, sizeof(nt->Signature));
    if (!nt) return STATUS_INVALID_IMAGE_FORMAT;
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        IMAGE_OS2_HEADER *os2 = (IMAGE_OS2_HEADER *)nt;
        if (os2->ne_magic != IMAGE_OS2_SIGNATURE) return STATUS_INVALID_IMAGE_PROTECT;
        if (os2->ne_exetyp == 2) return STATUS_INVALID_IMAGE_WIN_16;
        if (os2->ne_exetyp == 5) return STATUS_INVALID_IMAGE_PROTECT;
        return STATUS_INVALID_IMAGE_NE_FORMAT;
    }
    *pnt = nt;
    return STATUS_SUCCESS;
}

static void before_remmap_image32(image_info_t *image, IMAGE_OPTIONAL_HEADER32 *hdr) {
    image->image_base        = hdr->ImageBase;
    image->image_size        = align_to_page(0, hdr->SizeOfImage);
    image->headers_size      = hdr->SizeOfHeaders;
    image->is_flatmap        = (hdr->SectionAlignment & page_mask) ? TRUE : FALSE;
}

static void before_remmap_image64(image_info_t *image, IMAGE_OPTIONAL_HEADER64 *hdr) {
    image->image_base        = hdr->ImageBase;
    image->image_size        = align_to_page(0, hdr->SizeOfImage);
    image->headers_size      = hdr->SizeOfHeaders;
    image->is_flatmap        = (hdr->SectionAlignment & page_mask) ? TRUE : FALSE;
}

/**
 * remap image (partial) after base/size is set
 * - copy headers
 * - reset nt pointer
 * use file mmap if flatmap (non page-unaligned binary, for native subsystem binary)
 * we can use rva2va() after this
 */
static int remmap_image(image_info_t *image) {
    NTSTATUS status;

    if (image->is_flatmap) {
        image->map = image->filemap;
    } else {
        image->map = mmap_zero(image->image_size);
        if (!image->map) {
            return 1;
        }
        memcpy(image->map->addr, image->filemap->addr, image->headers_size);
    }
    status = get_nt_from_mmap(image->map, &image->nt);
    if (status) {
        fprintf(stderr, "remmap_image() get_nt_from_mmap() %x\n", status);
        return 2;
    }
    return 0;
}

static NTSTATUS load_optional_header32(image_info_t *image, IMAGE_OPTIONAL_HEADER32 *hdr) {
    image->entrypoint = hdr->AddressOfEntryPoint;
    image->dll_charact = hdr->DllCharacteristics;
    image->subsystem  = hdr->Subsystem;

    UINT file_flags = 0;
    
    int has_code = hdr->SizeOfCode || hdr->AddressOfEntryPoint || (hdr->SectionAlignment & page_mask);
    int has_clr = hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    if ((hdr->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) && has_code && !has_clr)
        file_flags |= IMAGE_FILE_FLAGS_ALREADY_RELOCATED;

    image->file_flags = file_flags;

    if (image->is_flatmap) {
        if (hdr->FileAlignment != hdr->SectionAlignment) return STATUS_INVALID_FILE_FOR_SECTION;
    }
    
    image->data_dir_tbl = hdr->DataDirectory;

    return STATUS_SUCCESS;
}

static NTSTATUS load_optional_header64(image_info_t *image, IMAGE_OPTIONAL_HEADER64 *hdr) {
    image->entrypoint       = hdr->AddressOfEntryPoint;
    image->dll_charact      = hdr->DllCharacteristics;
    image->subsystem        = hdr->Subsystem;

    UINT file_flags = 0;
    
    int has_code = hdr->SizeOfCode || hdr->AddressOfEntryPoint || (hdr->SectionAlignment & page_mask);
    int has_clr = hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    if ((hdr->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) && has_code && !has_clr)
        file_flags |= IMAGE_FILE_FLAGS_ALREADY_RELOCATED;

    image->file_flags = file_flags;

    if (image->is_flatmap) {
        if (hdr->FileAlignment != hdr->SectionAlignment) return STATUS_INVALID_FILE_FOR_SECTION;
    }
    
    image->data_dir_tbl = hdr->DataDirectory;

    return STATUS_SUCCESS;
}

static NTSTATUS load_image(image_info_t *image) {
    int ret;
    NTSTATUS status;

    // from wine/server/mapping.c get_image_params()

    mmap_info_t *fmi = image->filemap;

    image_nt_headers_t *nt;
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

    image->file_charact = nt->FileHeader.Characteristics;

    if (!nt->FileHeader.SizeOfOptionalHeader ||
            !rewine_mmap_next(fmi, nt->FileHeader.SizeOfOptionalHeader)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    cpu_bits_t bits;
    switch (nt->OptionalHeader.hdr32.Magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        bits = CPU_BITS_32;
        break;

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        bits = CPU_BITS_64;
        break;

    default:
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (bits != image->bits) return STATUS_INVALID_IMAGE_FORMAT;

    switch (bits) {
    case CPU_BITS_32: {
        before_remmap_image32(image, &(nt->OptionalHeader.hdr32));
        ret = remmap_image(image);
        if (ret) return ret;
        nt = image->nt;
        ret = load_optional_header32(image, &(nt->OptionalHeader.hdr32));
        if (ret) return ret;
    } break;

    case CPU_BITS_64: {
        before_remmap_image64(image, &(nt->OptionalHeader.hdr64));
        ret = remmap_image(image);
        if (ret) return ret;
        nt = image->nt;
        ret = load_optional_header64(image, &(nt->OptionalHeader.hdr64));
        if (ret) return ret;
    } break;
    }

    image->map->pos = fmi->pos;
    image->map->carry = fmi->carry;

    // clr contains continuous sections from clr->VirtualAddress
    //TODO: load_clr()

    size_t nb_section = image->nb_section = nt->FileHeader.NumberOfSections;
    if (!rewine_mmap_next(image->map, sizeof(IMAGE_SECTION_HEADER) * nb_section)) {
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    PIMAGE_SECTION_HEADER sec_tbl = (PIMAGE_SECTION_HEADER)rewine_mmap_current(image->map);
    image->sec_mmap_tbl = MALLOC(mmap_info_t, nb_section);

    PIMAGE_SECTION_HEADER sec = sec_tbl;
    mmap_info_t *sec_mmap = image->sec_mmap_tbl;

    if (image->is_flatmap) {
        // non page-unaligned binary (native subsystem binary)
        // just mmap the whole file

        for (int i = 0; i < nb_section; i++, sec++, sec_mmap++) {
            // check if sections are loaded to the right offset
            if (sec->VirtualAddress != sec->PointerToRawData)
                return STATUS_INVALID_FILE_FOR_SECTION;
            
            sec_mmap->offset = sec->VirtualAddress;
            sec_mmap->addr = rva2va(image, sec_mmap->offset);
            sec_mmap->size = sec->SizeOfRawData;
        }
    } else {
        for (int i = 0; i < nb_section; i++, sec++, sec_mmap++) {
            size_t file_offset = align_to_sector(0, sec->PointerToRawData);
            size_t file_size = align_to_sector(sec->PointerToRawData, sec->SizeOfRawData);
            if (!file_offset || !file_size) continue;

            sec_mmap->offset = sec->VirtualAddress;
            sec_mmap->addr = rva2va(image, sec_mmap->offset);
            sec_mmap->size = align_to_page(0, (sec->Misc.VirtualSize) ? sec->Misc.VirtualSize : sec->SizeOfRawData);

            memcpy(sec_mmap->addr, fmi->addr + file_offset, sec_mmap->size);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS relocate(image_info_t *image) {

    // from wine/dlls/ntdll/loader.c perform_relocations()

    if (image->is_flatmap) {
        // cannot relocate on non page-aligned binary
        fprintf(stdout, "cannot relocate on non page-aligned binary\n");
        return STATUS_SUCCESS;
    }

    if (!(image->nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        // we only relocate DLL now
        fprintf(stdout, "we only relocate DLL now\n");
        return STATUS_SUCCESS;
    }

    if (image->nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        // relocation info is stripped
        return STATUS_CONFLICTING_ADDRESSES;
    }

    ULONG size;
    PIMAGE_BASE_RELOCATION reld = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size);
    if (!reld) return STATUS_CONFLICTING_ADDRESSES;

    INT_PTR delta = (LONG_PTR)(image->map->addr - image->image_base);

    size_t used = 0;
    while (used < size) {
        used += reld->SizeOfBlock;

        if (reld->VirtualAddress >= image->image_size) {
            return STATUS_ACCESS_VIOLATION;
        }

        // reld is followed by some Type/Offset field entries
        UINT nb_block = (reld->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        // returned address of the next reld
        reld = LdrProcessRelocationBlock(rva2va(image, reld->VirtualAddress), nb_block, (PWORD)(reld + 1), delta);
        if (!reld) return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS load_exports(image_info_t *image) {
    ULONG size;
    PIMAGE_EXPORT_DIRECTORY expd = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (!expd) return STATUS_SUCCESS;

    image->export_name = cstr2bstr(rva2va(image, expd->Name));
    fprintf(stdout, "INFO: load_exports export_name=\"%s\"\n", image->export_name->str);

    size_t nb_export;
    nb_export = image->nb_export = expd->NumberOfFunctions;

    DWORD ordinal_base = image->exp_ordinal_base = expd->Base;

    PDWORD fn_tbl = rva2va(image, expd->AddressOfFunctions);
    PDWORD name_tbl = rva2va(image, expd->AddressOfNames);
    PWORD ordinal_tbl = rva2va(image, expd->AddressOfNameOrdinals);

    image_export_t *export;
    export = image->exp_tbl = MALLOC(image_export_t, nb_export);
    for (int i = 0; i < nb_export; i++, export++) {
        export->ordinal = ordinal_base + i;
        export->addr = rva2va(image, fn_tbl[i]);

        if ((export->addr >= (PVOID)expd) && (export->addr < ((PVOID)expd) + size)) {
            // addr is point to a null-term ASCII string in .export section
            export->type = IMAGE_EXPORT_FORWARDER;
        } else {
            // addr is point to the exported symbol
            export->type = IMAGE_EXPORT_EXPORT;
        }
    }

    for (int i = 0; i < expd->NumberOfNames; i++) {
        PCSTR name = rva2va(image, name_tbl[i]);
        WORD index = ordinal_tbl[i]; // not absolute ordinal
        image->exp_tbl[index].name = name;
    }

    return STATUS_SUCCESS;
}

static int find_dll_in_ll(ll_t *ll, size_t offset, void *ptr, void *arg, void **result) {
    image_info_t *image = (image_info_t *)ptr;
    if (image->export_name) {
        PBSTR name = (PBSTR)arg;
        if (strcmp(image->export_name->str, name->str) == 0) {
            *((image_info_t **)result) = image;
            return 1;
        }
    }
    return 0;
}

static image_info_t * find_dll_in_memory(PBSTR name) {
    if (!name) return NULL;
    void *result = ll_enumerate(image_info_ll, find_dll_in_ll, name);
    return (image_info_t *)result;
}

static PVOID get_forwarded_export(image_info_t *image, PCSTR label) {
    fprintf(stderr, "FIXME: forward export: %s\n", label);
    return NULL;
}

static PVOID get_export(image_info_t *image, image_export_t *export) {
    if (export->type == IMAGE_EXPORT_EXPORT) {
        return export->addr;
    } else {
        return get_forwarded_export(image, export->addr);
    }
}

static PVOID get_export_by_ordinal(image_info_t *image, WORD ordinal) {
    int index = ordinal - image->exp_ordinal_base;
    image_export_t *export = image->exp_tbl + index;
    return get_export(image, export);
}

/**
 * TODO: try names[hint] first, then bsearch(name)
 */
static PVOID get_export_by_name(image_info_t *image, WORD hint, PCSTR name) {
    for (int i = 0; i < image->nb_export; i++) {
        image_export_t *export = image->exp_tbl + i;
        if (!export->name) continue;
        if (strcmp(export->name, name) == 0) {
            return get_export(image, export);
        }
    }
    return NULL;
}

static int import_dll(image_info_t *master, PIMAGE_IMPORT_DESCRIPTOR impd, OUT image_info_t **out_dll) {
    int ret;

    // from wine/dlls/ntdll/loader.c import_dll()

    PSTR name = rva2va(master, impd->Name);
    size_t name_len = strlen(name);
    fprintf(stdout, "INFO: import_dll \"%s\" import \"%s\"\n", master->export_name->str, name);

    while (name_len && name[name_len-1] == ' ') name_len--; // remove trailing spaces
    if (!name_len) {
        return 1;
    }
    name[name_len] = '\0';

    PBSTR bname = cstr2bstr(name);
    image_info_t *dll;
    ret = load_dll(bname, &dll);
    if (ret) {
        fprintf(stderr, "ERR: import_dll load_dll: %d %s\n", ret, bname->str);
        return 2;
    }

    PIMAGE_THUNK_DATA ilt = rva2va(master, impd->u.OriginalFirstThunk); // readonly
    PIMAGE_THUNK_DATA iat = rva2va(master, impd->FirstThunk); // rw

    while (ilt->u1.Ordinal) {
        PVOID va;
        if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) {
            WORD ordinal = IMAGE_ORDINAL(ilt->u1.Ordinal);
            va = get_export_by_ordinal(dll, ordinal);
            fprintf(stdout, "#%d %p\n", ordinal, va);
            if (!va) {
                va = stub(dll, ordinal, NULL);
            }
        } else {
            PIMAGE_IMPORT_BY_NAME symbol = rva2va(master, ilt->u1.AddressOfData);
            va = get_export_by_name(dll, symbol->Hint, symbol->Name);
            fprintf(stdout, "%s %p\n", symbol->Name, va);
            if (!va) {
                va = stub(dll, 0, symbol->Name);
            }
        }
        iat->u1.Function = (LONG_PTR)va;
        ilt++;
        iat++;
    }

    *out_dll = dll;
    return 0;
}

static int fixup_imports(image_info_t *info) {
    int ret;

    // from wine/dlls/ntdll/loader.c fixup_imports()

    if (info->map_flags & IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP) return 0;
    info->map_flags ^= IMAGE_MAP_FLAGS_IMPORTS_FIXED_UP;

    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR impd_tbl = RtlImageDirectoryEntryToData(info->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    if (!impd_tbl) return 0;

    size_t nb_imports = -1; // last one is placeholder
    PIMAGE_IMPORT_DESCRIPTOR impd = impd_tbl;
    while (impd->Name && impd->FirstThunk) {
        nb_imports++;
        impd++;
    }
    fprintf(stdout, "INFO: fixup_imports nb_imports=%lu\n", nb_imports);
    if (!nb_imports) return 0;

    image_info_t *dll;

    info->dep_count = nb_imports;
    info->deps = MALLOC(image_info_t *, nb_imports);

    for (int i = 0; i < nb_imports; i++) {
        dll = info->deps[i];
        ret = import_dll(info, impd_tbl + i, &dll);
        if (ret) {
            fprintf(stderr, "ERR: fixup_imports import_dll: %d\n", ret);
        }
    }

    return 0;
}

static int load_native_dll(PBSTR filename, int fd, OUT image_info_t **out_dll) {
    int ret;
    NTSTATUS status;

    mmap_info_t *fmi;
    fmi = MALLOC(mmap_info_t, 1);

    ret = mmap_image_file(fd, fmi);
    if (ret) {
        fprintf(stderr, "ERR: load_native_dll mmap_image_file: %d\n", ret);
        return 1;
    }

    image_info_t *dll;
    dll = MALLOC(image_info_t, 1);
    dll->filemap = fmi;
    dll->filename = filename;

    status = load_image(dll);
    if (status) {
        fprintf(stderr, "ERR: load_native_dll load_image: %x\n", status);
        return 2;
    }

    status = relocate(dll);
    if (status) {
        fprintf(stderr, "ERR: load_native_dll relocate: %x\n", status);
        return 3;
    }

    status = load_exports(dll);
    if (status) {
        fprintf(stderr, "ERR: load_native_dll load_exports: %x\n", status);
        return 4;
    }

    if ((dll->file_charact & IMAGE_FILE_DLL)
            || (dll->subsystem == IMAGE_SUBSYSTEM_NATIVE)) {
        ret = fixup_imports(dll);
        if (ret) {
            fprintf(stderr, "ERR: load_native_dll fixup_imports: %d\n", ret);
            return 5;
        }
    }

    fprintf(stdout, "INFO: loaded %s (%p)\n", dll->export_name->str, filename);
    
    *out_dll = dll;
    return 0;
}

static int load_dll(PBSTR filename, OUT image_info_t **out_dll) {
    int ret;

    PBSTR basename = cstr2bstr(get_basename(filename->str));

    fprintf(stdout, "INFO: load_dll %s\n", basename->str);

    *out_dll = find_dll_in_memory(basename);
    if (*out_dll) return 0;

    RAII_FD int fd;
    fd = open(filename->str, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    ret = load_native_dll(basename, fd, out_dll);
    if (ret) {
        fprintf(stderr, "ERR: load_dll load_native_dll: %d\n", ret);
        return 2;
    }

    return 0;
}

HMODULE rewine_LoadLibrary(PCSTR filename) {
    int ret;

    PBSTR bfilename = cstr2bstr(filename);

    image_info_t *dll;
    ret = load_dll(bfilename, &dll);
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
