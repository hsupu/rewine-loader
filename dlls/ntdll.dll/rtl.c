#include "winapi/rtl.h"


PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(
  PVOID Base
) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)Base;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS *nt;
        nt = (IMAGE_NT_HEADERS *)((PVOID)dos + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            return nt;
        }
    }
    return NULL;
}

PIMAGE_SECTION_HEADER WINAPI RtlImageRvaToSection(
  PIMAGE_NT_HEADERS NtHeaders,
  PVOID             Base,
  ULONG             Rva
) {
    PIMAGE_SECTION_HEADER sec = (IMAGE_SECTION_HEADER *)((PVOID)(&NtHeaders->OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, sec++) {
        if ((sec->VirtualAddress <= Rva) && (sec->VirtualAddress + sec->SizeOfRawData > Rva))
            return (PIMAGE_SECTION_HEADER)sec;
    }
    return NULL;
}

PVOID WINAPI RtlImageRvaToVa(
  PIMAGE_NT_HEADERS NtHeaders,
  PVOID Base,
  ULONG Rva,
  OUT PIMAGE_SECTION_HEADER *LastRvaSection
) {
    PIMAGE_SECTION_HEADER sec;
    if (LastRvaSection && *LastRvaSection) {
        sec = *LastRvaSection;
        if ((sec->VirtualAddress <= Rva) && (sec->VirtualAddress + sec->SizeOfRawData > Rva)) goto found;
    }
    if (!(sec = RtlImageRvaToSection(NtHeaders, Base, Rva))) return NULL;

  found:
    if (LastRvaSection) *LastRvaSection = sec;
    return Base + sec->PointerToRawData + (Rva - sec->VirtualAddress);
}

static PIMAGE_DATA_DIRECTORY get_image_data_directory32(PIMAGE_OPTIONAL_HEADER32 opt, WORD dir) {
    if (dir >= opt->NumberOfRvaAndSizes) return NULL;
    return opt->DataDirectory + dir;
}

static PIMAGE_DATA_DIRECTORY get_image_data_directory64(PIMAGE_OPTIONAL_HEADER64 opt, WORD dir) {
    if (dir >= opt->NumberOfRvaAndSizes) return NULL;
    return opt->DataDirectory + dir;
}

PVOID WINAPI RtlImageDirectoryEntryToData(
  PVOID Base,
  BOOLEAN MappedAsImage,
  USHORT DirectoryEntry,
  OUT PULONG Size
) {
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader(Base);
    if (!nt) return NULL;

    DWORD headers_size;
    const IMAGE_DATA_DIRECTORY *entry;
    switch (nt->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC: {
        PIMAGE_OPTIONAL_HEADER32 opt = (PIMAGE_OPTIONAL_HEADER32)(&nt->OptionalHeader);
        headers_size = opt->SizeOfHeaders;
        entry = get_image_data_directory32(opt, DirectoryEntry);
    } break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC: {
        PIMAGE_OPTIONAL_HEADER64 opt = (PIMAGE_OPTIONAL_HEADER64)(&nt->OptionalHeader);
        headers_size = opt->SizeOfHeaders;
        entry = get_image_data_directory64(opt, DirectoryEntry);
    } break;
    default:
        return NULL;
    }
    if (entry == NULL) return NULL;

    *Size = entry->Size;
    DWORD addr = entry->VirtualAddress;

    if (MappedAsImage || addr < headers_size) {
        return Base + addr;
    } else {
        // find the section containing the virtual address
        return RtlImageRvaToVa(nt, Base, addr, NULL);
    }
}
