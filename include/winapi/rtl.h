#pragma once

#include "wintypes/hint.h"
#include "wintypes/primitive.h"
#include "wintypes/pe.h"

PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(
  PVOID Base
);

PIMAGE_SECTION_HEADER WINAPI RtlImageRvaToSection(
  PIMAGE_NT_HEADERS NtHeaders,
  PVOID             Base,
  ULONG             Rva
);

PVOID WINAPI RtlImageRvaToVa(
  PIMAGE_NT_HEADERS NtHeaders,
  PVOID Base,
  ULONG Rva,
  OUT PIMAGE_SECTION_HEADER *LastRvaSection
);

PVOID WINAPI RtlImageDirectoryEntryToData(
  PVOID Base,
  BOOLEAN MappedAsImage,
  USHORT DirectoryEntry,
  OUT PULONG Size
);