/*
 * edr-tekton :: PE Parser Utilities
 * Export table walking, section enumeration, pattern search.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "tekton/util/pe.h"
#include "tekton/core/log.h"

/* ── Internal PE access helpers ──────────────────────────── */

#ifdef _WIN32

/* On Windows, use native PE structures */

static PIMAGE_NT_HEADERS get_nt_headers(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;
    return nt;
}

static PIMAGE_EXPORT_DIRECTORY get_export_dir(PVOID base, PIMAGE_NT_HEADERS nt) {
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) return NULL;
    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + rva);
}

static DWORD get_export_dir_size(PIMAGE_NT_HEADERS nt) {
    return nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
}

#else

/* On Linux, use our portable structures */

static IMAGE_NT_HEADERS64_T* get_nt_headers_p(PVOID base) {
    IMAGE_DOS_HEADER_T* dos = (IMAGE_DOS_HEADER_T*)base;
    if (dos->e_magic != 0x5A4D) return NULL;
    IMAGE_NT_HEADERS64_T* nt = (IMAGE_NT_HEADERS64_T*)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;
    return nt;
}

#endif

/* ── Public API ──────────────────────────────────────────── */

TEKTON_STATUS TektonPeParse(PVOID base_address, PTEKTON_PE_INFO out_info) {
    if (!base_address || !out_info) return TEKTON_ERR_INVALID_PARAM;

    memset(out_info, 0, sizeof(TEKTON_PE_INFO));
    out_info->base = base_address;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = get_nt_headers(base_address);
    if (!nt) {
        TLOG_ERROR("Invalid PE signature");
        return TEKTON_ERR_INVALID_PARAM;
    }

    out_info->nt_headers = nt;
    out_info->is_64bit = (nt->OptionalHeader.Magic == 0x20b);

    PIMAGE_EXPORT_DIRECTORY exports = get_export_dir(base_address, nt);
    if (exports) {
        out_info->export_dir = exports;
        out_info->num_exports = exports->NumberOfNames;
    }

    /* Find .text section */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            out_info->text_section = (BYTE*)base_address + section[i].VirtualAddress;
            out_info->text_section_size = section[i].Misc.VirtualSize;
            break;
        }
    }

#else
    IMAGE_NT_HEADERS64_T* nt = get_nt_headers_p(base_address);
    if (!nt) {
        TLOG_ERROR("Invalid PE signature");
        return TEKTON_ERR_INVALID_PARAM;
    }

    out_info->nt_headers = nt;
    out_info->is_64bit = (nt->OptionalHeader.Magic == 0x20b);

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].VirtualAddress;
    if (export_rva) {
        IMAGE_EXPORT_DIRECTORY_T* exports = (IMAGE_EXPORT_DIRECTORY_T*)((BYTE*)base_address + export_rva);
        out_info->export_dir = exports;
        out_info->num_exports = exports->NumberOfNames;
    }

    IMAGE_SECTION_HEADER_T* section = (IMAGE_SECTION_HEADER_T*)(
        (BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader
    );

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            out_info->text_section = (BYTE*)base_address + section[i].VirtualAddress;
            out_info->text_section_size = section[i].Misc.VirtualSize;
            break;
        }
    }
#endif

    TLOG_DEBUG("PE parsed: base=%p exports=%lu .text=%p (%lu bytes)",
        base_address, (unsigned long)out_info->num_exports,
        out_info->text_section, (unsigned long)out_info->text_section_size);

    return TEKTON_OK;
}

PVOID TektonPeFindExport(PVOID base_address, const char* func_name) {
    if (!base_address || !func_name) return NULL;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = get_nt_headers(base_address);
    if (!nt) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = get_export_dir(base_address, nt);
    if (!exports) return NULL;

    DWORD* names    = (DWORD*)((BYTE*)base_address + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)base_address + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)base_address + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)base_address + names[i]);
        if (strcmp(name, func_name) == 0) {
            DWORD func_rva = funcs[ordinals[i]];
            PVOID func_addr = (BYTE*)base_address + func_rva;

            /* Check for forwarder */
            DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                /* This is a forwarder string */
                return TektonPeResolveForwarder((const char*)func_addr);
            }

            return func_addr;
        }
    }

#else
    IMAGE_NT_HEADERS64_T* nt = get_nt_headers_p(base_address);
    if (!nt) return NULL;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].Size;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY_T* exports = (IMAGE_EXPORT_DIRECTORY_T*)((BYTE*)base_address + export_rva);

    DWORD* names    = (DWORD*)((BYTE*)base_address + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)base_address + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)base_address + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)base_address + names[i]);
        if (strcmp(name, func_name) == 0) {
            DWORD func_rva_val = funcs[ordinals[i]];
            PVOID func_addr = (BYTE*)base_address + func_rva_val;

            if (func_rva_val >= export_rva && func_rva_val < export_rva + export_size) {
                return TektonPeResolveForwarder((const char*)func_addr);
            }

            return func_addr;
        }
    }
#endif

    return NULL;
}

PVOID TektonPeFindExportByHash(
    PVOID            base_address,
    DWORD            target_hash,
    TEKTON_HASH_FUNC hash_func
) {
    if (!base_address || !hash_func) return NULL;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = get_nt_headers(base_address);
    if (!nt) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = get_export_dir(base_address, nt);
    if (!exports) return NULL;

    DWORD* names    = (DWORD*)((BYTE*)base_address + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)base_address + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)base_address + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)base_address + names[i]);
        DWORD hash = hash_func(name);

        if (hash == target_hash) {
            DWORD func_rva = funcs[ordinals[i]];
            PVOID func_addr = (BYTE*)base_address + func_rva;

            DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                return TektonPeResolveForwarder((const char*)func_addr);
            }

            return func_addr;
        }
    }

#else
    IMAGE_NT_HEADERS64_T* nt = get_nt_headers_p(base_address);
    if (!nt) return NULL;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].Size;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY_T* exports = (IMAGE_EXPORT_DIRECTORY_T*)((BYTE*)base_address + export_rva);

    DWORD* names    = (DWORD*)((BYTE*)base_address + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)base_address + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)base_address + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)base_address + names[i]);
        DWORD hash = hash_func(name);

        if (hash == target_hash) {
            DWORD func_rva_val = funcs[ordinals[i]];
            PVOID func_addr = (BYTE*)base_address + func_rva_val;

            if (func_rva_val >= export_rva && func_rva_val < export_rva + export_size) {
                return TektonPeResolveForwarder((const char*)func_addr);
            }

            return func_addr;
        }
    }
#endif

    return NULL;
}

TEKTON_STATUS TektonPeFindTextSection(
    PVOID   base_address,
    PVOID*  out_text_base,
    DWORD*  out_text_size
) {
    if (!base_address || !out_text_base || !out_text_size) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    TEKTON_PE_INFO info;
    TEKTON_STATUS status = TektonPeParse(base_address, &info);
    if (status != TEKTON_OK) return status;

    if (!info.text_section) {
        return TEKTON_ERR_NOT_FOUND;
    }

    *out_text_base = info.text_section;
    *out_text_size = info.text_section_size;
    return TEKTON_OK;
}

PVOID TektonPeFindPattern(
    PVOID       base,
    SIZE_T      size,
    const BYTE* pattern,
    SIZE_T      pattern_size
) {
    if (!base || !pattern || pattern_size == 0 || size < pattern_size) {
        return NULL;
    }

    BYTE* p = (BYTE*)base;
    SIZE_T limit = size - pattern_size;

    for (SIZE_T i = 0; i <= limit; i++) {
        if (memcmp(p + i, pattern, pattern_size) == 0) {
            return p + i;
        }
    }

    return NULL;
}

BOOL TektonPeIsForwarder(PVOID base_address, PVOID export_address) {
    if (!base_address || !export_address) return FALSE;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = get_nt_headers(base_address);
    if (!nt) return FALSE;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD addr_rva = (DWORD)((BYTE*)export_address - (BYTE*)base_address);

    return (addr_rva >= export_rva && addr_rva < export_rva + export_size);
#else
    IMAGE_NT_HEADERS64_T* nt = get_nt_headers_p(base_address);
    if (!nt) return FALSE;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT_T].Size;
    DWORD addr_rva = (DWORD)((BYTE*)export_address - (BYTE*)base_address);

    return (addr_rva >= export_rva && addr_rva < export_rva + export_size);
#endif
}

PVOID TektonPeResolveForwarder(const char* forwarder_string) {
    if (!forwarder_string) return NULL;

    /* Forwarder format: "MODULE.FunctionName" */
    char buf[256];
    size_t len = strlen(forwarder_string);
    if (len >= sizeof(buf)) return NULL;

    memcpy(buf, forwarder_string, len + 1);

    char* dot = strchr(buf, '.');
    if (!dot) return NULL;

    *dot = '\0';
    const char* dll_name = buf;
    const char* func_name = dot + 1;

    /* Append .dll if not present */
    char dll_full[256];
    if (!strstr(dll_name, ".dll") && !strstr(dll_name, ".DLL")) {
        snprintf(dll_full, sizeof(dll_full), "%s.dll", dll_name);
    } else {
        snprintf(dll_full, sizeof(dll_full), "%s", dll_name);
    }

#ifdef _WIN32
    HMODULE hMod = GetModuleHandleA(dll_full);
    if (!hMod) {
        hMod = LoadLibraryA(dll_full);
    }
    if (!hMod) return NULL;

    return TektonPeFindExport((PVOID)hMod, func_name);
#else
    /* On Linux dev builds, forwarder resolution is a no-op */
    TLOG_DEBUG("Forwarder resolution not available on non-Windows: %s.%s",
        dll_full, func_name);
    return NULL;
#endif
}
