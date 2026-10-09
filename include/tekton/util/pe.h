#ifndef TEKTON_PE_H
#define TEKTON_PE_H

/*
 * edr-tekton :: PE Parser Utilities
 * Portable Executable parsing for export table walking,
 * section enumeration, and relocation processing.
 */

#include "../core/types.h"

/* ── PE Structures (minimal, for non-Windows builds) ──── */

#ifndef _WIN32

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER_T {
    WORD    e_magic;        /* MZ = 0x5A4D */
    WORD    e_cblp;
    WORD    e_cp;
    WORD    e_crlc;
    WORD    e_cparhdr;
    WORD    e_minalloc;
    WORD    e_maxalloc;
    WORD    e_ss;
    WORD    e_sp;
    WORD    e_csum;
    WORD    e_ip;
    WORD    e_cs;
    WORD    e_lfarlc;
    WORD    e_ovno;
    WORD    e_res[4];
    WORD    e_oemid;
    WORD    e_oeminfo;
    WORD    e_res2[10];
    long    e_lfanew;       /* Offset to PE header */
} IMAGE_DOS_HEADER_T;

typedef struct _IMAGE_FILE_HEADER_T {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER_T;

typedef struct _IMAGE_DATA_DIRECTORY_T {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY_T;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES_T 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT_T     0

typedef struct _IMAGE_OPTIONAL_HEADER64_T {
    WORD    Magic;          /* 0x20b = PE32+ */
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    QWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    QWORD   SizeOfStackReserve;
    QWORD   SizeOfStackCommit;
    QWORD   SizeOfHeapReserve;
    QWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_T DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES_T];
} IMAGE_OPTIONAL_HEADER64_T;

typedef struct _IMAGE_NT_HEADERS64_T {
    DWORD                       Signature;  /* PE\0\0 = 0x00004550 */
    IMAGE_FILE_HEADER_T         FileHeader;
    IMAGE_OPTIONAL_HEADER64_T   OptionalHeader;
} IMAGE_NT_HEADERS64_T;

typedef struct _IMAGE_SECTION_HEADER_T {
    BYTE    Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER_T;

typedef struct _IMAGE_EXPORT_DIRECTORY_T {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_T;

#pragma pack(pop)

#endif /* !_WIN32 */

/* ── PE Parsing API ───────────────────────────────────── */

/* Parse PE headers from a base address */
typedef struct _TEKTON_PE_INFO {
    PVOID   base;
    PVOID   nt_headers;
    PVOID   export_dir;
    PVOID   text_section;
    DWORD   text_section_size;
    DWORD   num_exports;
    BOOL    is_64bit;
} TEKTON_PE_INFO, *PTEKTON_PE_INFO;

TEKTON_STATUS TektonPeParse(PVOID base_address, PTEKTON_PE_INFO out_info);

/* Find export by name (walks export directory) */
PVOID TektonPeFindExport(PVOID base_address, const char* func_name);

/* Find export by hash (walks export directory, applies hash function) */
typedef DWORD (*TEKTON_HASH_FUNC)(const char*);
PVOID TektonPeFindExportByHash(
    PVOID            base_address,
    DWORD            target_hash,
    TEKTON_HASH_FUNC hash_func
);

/* Find the .text section base and size */
TEKTON_STATUS TektonPeFindTextSection(
    PVOID   base_address,
    PVOID*  out_text_base,
    DWORD*  out_text_size
);

/* Find a byte pattern within a section */
PVOID TektonPeFindPattern(
    PVOID       base,
    SIZE_T      size,
    const BYTE* pattern,
    SIZE_T      pattern_size
);

/* Check if an export is a forwarder (points into export dir range) */
BOOL TektonPeIsForwarder(PVOID base_address, PVOID export_address);

/* Resolve a forwarder string (e.g., "NTDLL.RtlExitUserThread") */
PVOID TektonPeResolveForwarder(const char* forwarder_string);

#endif /* TEKTON_PE_H */
