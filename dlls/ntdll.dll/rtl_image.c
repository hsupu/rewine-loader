#include <stdio.h>

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
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((PVOID)(&NtHeaders->OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader);
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

PVOID WINAPI RtlImageDirectoryEntryToData(
  PVOID Base,
  BOOLEAN MappedAsImage,
  USHORT DirectoryEntry,
  OUT PULONG Size
) {
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader(Base);
    if (!nt) return NULL;

    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    if (DirectoryEntry >= nt->OptionalHeader.NumberOfRvaAndSizes) return NULL;
    const PIMAGE_DATA_DIRECTORY entry = nt->OptionalHeader.DataDirectory + DirectoryEntry;
    if (!entry || !entry->VirtualAddress) return NULL;

    DWORD address = entry->VirtualAddress;
    *Size = entry->Size;

    if (MappedAsImage || address < headers_size) {
        return Base + address;
    } else {
        // find the section containing the virtual address
        return RtlImageRvaToVa(nt, Base, address, NULL);
    }
}
