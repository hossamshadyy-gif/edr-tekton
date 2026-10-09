/*
 * edr-tekton :: PEB Walking API Resolution Module
 * Cat 1.2: Zero-import resolution via PEB traversal
 *
 * Accesses PEB directly (gs:[0x60] x64, fs:[0x30] x86),
 * walks InLoadOrderModuleList to find DLL bases, then
 * parses PE export tables manually.
 *
 * Zero API imports required. Fully self-contained resolution.
 * Highest stealth among Cat 1 techniques.
 */

#include "tekton/modules/api_resolve.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _PEB_WALK_STATE {
    BOOL    initialized;
    PVOID   ntdll_base;
} PEB_WALK_STATE;

/* ── Wide string helpers (no wcslen dependency) ─────────── */

static SIZE_T wstr_len(const wchar_t* s) {
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

/* Convert narrow ASCII to wide (stack buffer) */
static void narrow_to_wide(const char* src, wchar_t* dst, SIZE_T max_chars) {
    SIZE_T i = 0;
    while (src[i] && i < max_chars - 1) {
        dst[i] = (wchar_t)src[i];
        i++;
    }
    dst[i] = L'\0';
}

/* ── Resolution table (same Nt* APIs, resolved by PE walking) */

typedef struct _PEB_API_ENTRY {
    const wchar_t*  dll_name_w;
    const char*     func_name;
    SIZE_T          offset_in_resolved;
} PEB_API_ENTRY;

#define RESOLVED_OFFSET(field) \
    ((SIZE_T)&((PTEKTON_RESOLVED_STATE)0)->field)

static const PEB_API_ENTRY g_peb_api_table[] = {
    { L"ntdll.dll", "NtAllocateVirtualMemory",   RESOLVED_OFFSET(fn_nt_allocate_virtual_memory)     },
    { L"ntdll.dll", "NtWriteVirtualMemory",       RESOLVED_OFFSET(fn_nt_write_virtual_memory)        },
    { L"ntdll.dll", "NtProtectVirtualMemory",     RESOLVED_OFFSET(fn_nt_protect_virtual_memory)      },
    { L"ntdll.dll", "NtCreateThreadEx",           RESOLVED_OFFSET(fn_nt_create_thread_ex)            },
    { L"ntdll.dll", "NtCreateSection",            RESOLVED_OFFSET(fn_nt_create_section)              },
    { L"ntdll.dll", "NtMapViewOfSection",         RESOLVED_OFFSET(fn_nt_map_view_of_section)         },
    { L"ntdll.dll", "NtUnmapViewOfSection",       RESOLVED_OFFSET(fn_nt_unmap_view_of_section)       },
    { L"ntdll.dll", "NtQueueApcThread",           RESOLVED_OFFSET(fn_nt_queue_apc_thread)            },
    { L"ntdll.dll", "NtOpenProcess",              RESOLVED_OFFSET(fn_nt_open_process)                },
    { L"ntdll.dll", "NtClose",                    RESOLVED_OFFSET(fn_nt_close)                       },
    { L"ntdll.dll", "NtWaitForSingleObject",      RESOLVED_OFFSET(fn_nt_wait_for_single_object)      },
    { L"ntdll.dll", "NtSuspendThread",            RESOLVED_OFFSET(fn_nt_suspend_thread)              },
    { L"ntdll.dll", "NtResumeThread",             RESOLVED_OFFSET(fn_nt_resume_thread)               },
    { L"ntdll.dll", "NtSetInformationProcess",    RESOLVED_OFFSET(fn_nt_set_information_process)     },
    { L"ntdll.dll", "NtQuerySystemInformation",   RESOLVED_OFFSET(fn_nt_query_system_information)    },
    { L"ntdll.dll", "NtQueryInformationProcess",  RESOLVED_OFFSET(fn_nt_query_information_process)   },
    { L"ntdll.dll", "RtlInitUnicodeString",       RESOLVED_OFFSET(fn_rtl_init_unicode_string)        },
};

#define PEB_API_TABLE_SIZE (sizeof(g_peb_api_table) / sizeof(g_peb_api_table[0]))

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS peb_walk_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    PEB_WALK_STATE* state = (PEB_WALK_STATE*)malloc(sizeof(PEB_WALK_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("peb_walk: init");
    return TEKTON_OK;
}

static TEKTON_STATUS peb_walk_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    PEB_WALK_STATE* state = (PEB_WALK_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("peb_walk: [DRY RUN] would resolve %lu APIs via PEB walk + PE export parse",
            (unsigned long)PEB_API_TABLE_SIZE);
        return TEKTON_OK;
    }

    /*
     * Step 1: Get ntdll base via PEB walk
     * PEB -> Ldr -> InLoadOrderModuleList -> find ntdll.dll
     */
    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) {
        TLOG_ERROR("peb_walk: failed to find ntdll.dll via PEB");
        return TEKTON_ERR_API_RESOLVE;
    }

    state->ntdll_base = ntdll_base;
    TLOG_DEBUG("peb_walk: ntdll.dll base = %p", ntdll_base);

    /*
     * Step 2: For each API, find the export in ntdll's PE export table
     * Walk export directory names, strcmp each one
     */
    DWORD resolved = 0;
    DWORD failed = 0;

    /* Cache the last DLL base to avoid re-walking PEB for every entry */
    const wchar_t* last_dll = L"ntdll.dll";
    PVOID last_base = ntdll_base;

    for (DWORD i = 0; i < PEB_API_TABLE_SIZE; i++) {
        const PEB_API_ENTRY* entry = &g_peb_api_table[i];

        /* Get DLL base (check cache first) */
        PVOID dll_base = last_base;
        if (entry->dll_name_w != last_dll) {
            dll_base = TektonPebGetModuleBase(entry->dll_name_w);
            if (!dll_base) {
                TLOG_WARN("peb_walk: DLL not found in PEB: <wide>");
                failed++;
                continue;
            }
            last_dll = entry->dll_name_w;
            last_base = dll_base;
        }

        /* Walk PE export table to find function */
        PVOID func = TektonPeFindExport(dll_base, entry->func_name);
        if (!func) {
            TLOG_WARN("peb_walk: export not found: %s", entry->func_name);
            failed++;
            continue;
        }

        /* Store the resolved pointer */
        PVOID* slot = (PVOID*)((BYTE*)&ctx->resolved + entry->offset_in_resolved);
        *slot = func;

        TLOG_TRACE("peb_walk: %s -> %p", entry->func_name, func);
        resolved++;
    }

    ctx->resolved.apis_resolved = TRUE;
    state->initialized = TRUE;

    TLOG_INFO("peb_walk: resolved %lu/%lu APIs via PEB walk (zero imports)",
        (unsigned long)resolved, (unsigned long)PEB_API_TABLE_SIZE);

    if (failed > 0 && resolved == 0) {
        return TEKTON_ERR_API_RESOLVE;
    }

    return TEKTON_OK;
}

static VOID peb_walk_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(PEB_WALK_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD peb_walk_risk_score(PTEKTON_MODULE self) {
    (void)self;
    return 15; /* Low: no API imports at all for resolution */
}

static BOOL peb_walk_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE; /* PEB structure is stable across Windows versions */
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_peb_walk = {
    .name           = "peb_walk",
    .description    = "Zero-import API resolution via PEB walking + PE export parsing (Cat 1.2)",
    .category       = TEKTON_CAT_API_RESOLVE,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "1.2",
    .init           = peb_walk_init,
    .execute        = peb_walk_execute,
    .cleanup        = peb_walk_cleanup,
    .get_risk_score = peb_walk_risk_score,
    .check_compat   = peb_walk_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_peb_walk);
