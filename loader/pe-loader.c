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
#include "misc/raii-mem.h"
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

    mmap_info_t *mi = MALLOC_S(mmap_info_t, 1);
    mi->addr = addr;
    mi->size = size;
    return mi;
}

/**
 * get relative virtual address
 */
static PVOID rva2va(image_info_t *image, LONG_PTR offset) {
    if (offset >= image->map->size) {
        fprintf(stderr, "ERR: rva2va: out of range: offset=%#zx size=%#zx\n", offset, image->map->size);
        return NULL;
    }
    return image->map->addr + offset;
}

// funcs

static int load_dll_c(PCSTR filename, OUT image_info_t **out_image);

static int mmap_image_file(int fd, OUT mmap_info_t **out_mi) {
    struct stat fd_stat;
    if (fstat(fd, &fd_stat) < 0) {
        return 1;
    }
    mmap_info_t *mi = MALLOC_S(mmap_info_t, 1);
    if (!mi) {
        return 2;
    }
    *out_mi = mi;

    mi->offset = 0;
    mi->size = fd_stat.st_size;
    mi->addr = mmap(NULL, mi->size, PROT_READ, MAP_SHARED, fd, mi->offset);
    if (mi->addr == (void *)-1) {
        return 3;
    }
    return 0;
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

static void before_remmap_image(image_info_t *image, PIMAGE_OPTIONAL_HEADER hdr) {
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
        fprintf(stderr, "FIXME: remmap but nt check violation\n");
        return 2;
    }
    return 0;
}

static NTSTATUS load_optional_header(image_info_t *image, PIMAGE_OPTIONAL_HEADER hdr) {
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

    image->file_charact = nt->FileHeader.Characteristics;

    if (!nt->FileHeader.SizeOfOptionalHeader ||
            !rewine_mmap_next(fmi, nt->FileHeader.SizeOfOptionalHeader)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    cpu_bits_t bits;
    switch (nt->OptionalHeader.Magic) {
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

    before_remmap_image(image, &(nt->OptionalHeader));
    ret = remmap_image(image);
    if (ret) return STATUS_NO_MEMORY;
    nt = image->nt;
    ret = load_optional_header(image, &(nt->OptionalHeader));
    if (ret) return ret;
 
    image->map->pos = fmi->pos;
    image->map->carry = fmi->carry;

    // clr contains continuous sections from clr->VirtualAddress
    //TODO: load_clr()

    size_t nb_section = image->nb_section = nt->FileHeader.NumberOfSections;
    if (!rewine_mmap_next(image->map, sizeof(IMAGE_SECTION_HEADER) * nb_section)) {
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    PIMAGE_SECTION_HEADER sec_tbl = (PIMAGE_SECTION_HEADER)rewine_mmap_current(image->map);
    image->sec_mmap_tbl = MALLOC_S(mmap_info_t, nb_section);

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
            //fprintf(stdout, "INFO: load_image offset=%#zx mapping=%p+%#zx\n", sec_mmap->offset, sec_mmap->addr, sec_mmap->size);

            memcpy(sec_mmap->addr, fmi->addr + file_offset, sec_mmap->size);
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

    if (!(image->dll_charact & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
        fprintf(stderr, "ERR: relocate: fixed image base\n");
        return 1;
    }

    if (image->nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        fprintf(stderr, "ERR: relocate: relocation info is stripped\n");
        return 2;
    }

    ULONG size;
    PIMAGE_BASE_RELOCATION reld = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size);
    if (!reld) return 0;

    INT_PTR delta = (LONG_PTR)(image->map->addr - image->image_base);

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
    PIMAGE_EXPORT_DIRECTORY expd = RtlImageDirectoryEntryToData(image->map->addr, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    if (!expd) return 0;

    image->exportname = cstr2bstr(rva2va(image, expd->Name));

    size_t nb_export;
    nb_export = image->nb_export = expd->NumberOfFunctions;

    DWORD ordinal_base = image->exp_ordinal_base = expd->Base;

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

static int find_dll_by_filename_in_ll(ll_t *ll, size_t offset, void *ptr, void *arg, void **presult) {
    image_info_t *image = (image_info_t *)ptr;
    if (image->filename) {
        PBSTR name = (PBSTR)arg;
        if (bstrcmp(image->filename, name) == 0) {
            *((image_info_t **)presult) = image;
            return 1;
        }
    }
    return 0;
}

static image_info_t * find_loaded_dll_by_filename(PBSTR name) {
    if (!name) return NULL;
    void *result = ll_enumerate(image_info_ll, find_dll_by_filename_in_ll, name);
    return (image_info_t *)result;
}

static int find_dll_by_exportname_in_ll(ll_t *ll, size_t offset, void *ptr, void *arg, void **presult) {
    image_info_t *image = (image_info_t *)ptr;
    if (image->exportname) {
        PBSTR name = (PBSTR)arg;
        if (bstrcmp(image->exportname, name) == 0) {
            *((image_info_t **)presult) = image;
            return 1;
        }
    }
    return 0;
}

static image_info_t * find_loaded_dll_by_exportname(PBSTR name) {
    if (!name) return NULL;
    void *result = ll_enumerate(image_info_ll, find_dll_by_exportname_in_ll, name);
    return (image_info_t *)result;
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

static int load_native_dll(image_info_t *image, int fd) {
    int ret;
    NTSTATUS status;

    mmap_info_t *fmi;
    ret = mmap_image_file(fd, &fmi);
    if (ret) {
        fprintf(stderr, "ERR: load_native_dll mmap_image_file: %d\n", ret);
        return 1;
    }
    image->filemap = fmi;

    status = load_image(image);
    if (status) {
        fprintf(stderr, "ERR: load_native_dll load_image: %x\n", status);
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

    if ((image->file_charact & IMAGE_FILE_DLL)
            || (image->subsystem == IMAGE_SUBSYSTEM_NATIVE)) {
        ret = fixup_imports(image);
        if (ret) {
            fprintf(stderr, "ERR: load_native_dll fixup_imports: %d\n", ret);
            return 5;
        }
    }

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
    close(fd); fd = 0; // avoid RAII
    if (ret) {
        fprintf(stderr, "ERR: load_dll load_native_dll: %d\n", ret);
        return 2;
    }

    return 0;
}

static int load_dll_c(PCSTR filename, OUT image_info_t **out_image) {
    int ret;
    PBSTR bname = cstr2bstr(filename);
    ret = load_dll(bname, out_image);
    free(bname);
    return ret;
}

HMODULE rewine_LoadLibrary(PCSTR filename) {
    int ret;
    image_info_t *dll;
    ret = load_dll_c(filename, &dll);
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
