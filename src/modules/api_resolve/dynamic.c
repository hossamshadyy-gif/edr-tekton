/*
 * edr-tekton :: Dynamic API Resolution Module
 * Cat 1.1: GetModuleHandle + GetProcAddress runtime resolution
 *
 * Resolves APIs dynamically at runtime instead of static imports.
 * Reduces IAT footprint from ~40/70 to ~13/70 detectable entries.
 * Simplest resolution strategy, moderate stealth.
 */

#include "tekton/modules/api_resolve.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _DYNAMIC_RESOLVE_STATE {
    BOOL    initialized;
    PVOID   ntdll_base;
    PVOID   kernel32_base;
} DYNAMIC_RESOLVE_STATE;

/* ── API resolution table ───────────────────────────────── */

typedef struct _API_ENTRY {
    const char* dll_name;
    const char* func_name;
    SIZE_T      offset_in_resolved;   /* byte offset into TEKTON_RESOLVED_STATE */
} API_ENTRY;

#define RESOLVED_OFFSET(field) \
    ((SIZE_T)&((PTEKTON_RESOLVED_STATE)0)->field)

static const API_ENTRY g_api_table[] = {
    { "ntdll.dll", "NtAllocateVirtualMemory",     RESOLVED_OFFSET(fn_nt_allocate_virtual_memory)     },
    { "ntdll.dll", "NtWriteVirtualMemory",         RESOLVED_OFFSET(fn_nt_write_virtual_memory)        },
    { "ntdll.dll", "NtProtectVirtualMemory",       RESOLVED_OFFSET(fn_nt_protect_virtual_memory)      },
    { "ntdll.dll", "NtCreateThreadEx",             RESOLVED_OFFSET(fn_nt_create_thread_ex)            },
    { "ntdll.dll", "NtCreateSection",              RESOLVED_OFFSET(fn_nt_create_section)              },
    { "ntdll.dll", "NtMapViewOfSection",           RESOLVED_OFFSET(fn_nt_map_view_of_section)         },
    { "ntdll.dll", "NtUnmapViewOfSection",         RESOLVED_OFFSET(fn_nt_unmap_view_of_section)       },
    { "ntdll.dll", "NtQueueApcThread",             RESOLVED_OFFSET(fn_nt_queue_apc_thread)            },
    { "ntdll.dll", "NtOpenProcess",                RESOLVED_OFFSET(fn_nt_open_process)                },
    { "ntdll.dll", "NtClose",                      RESOLVED_OFFSET(fn_nt_close)                       },
    { "ntdll.dll", "NtWaitForSingleObject",        RESOLVED_OFFSET(fn_nt_wait_for_single_object)      },
    { "ntdll.dll", "NtSuspendThread",              RESOLVED_OFFSET(fn_nt_suspend_thread)              },
    { "ntdll.dll", "NtResumeThread",               RESOLVED_OFFSET(fn_nt_resume_thread)               },
    { "ntdll.dll", "NtSetInformationProcess",      RESOLVED_OFFSET(fn_nt_set_information_process)     },
    { "ntdll.dll", "NtQuerySystemInformation",     RESOLVED_OFFSET(fn_nt_query_system_information)    },
    { "ntdll.dll", "NtQueryInformationProcess",    RESOLVED_OFFSET(fn_nt_query_information_process)   },
    { "ntdll.dll", "RtlInitUnicodeString",         RESOLVED_OFFSET(fn_rtl_init_unicode_string)        },
};

#define API_TABLE_SIZE (sizeof(g_api_table) / sizeof(g_api_table[0]))

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS dynamic_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    DYNAMIC_RESOLVE_STATE* state = (DYNAMIC_RESOLVE_STATE*)malloc(sizeof(DYNAMIC_RESOLVE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("dynamic_resolve: init");
    return TEKTON_OK;
}

static TEKTON_STATUS dynamic_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    DYNAMIC_RESOLVE_STATE* state = (DYNAMIC_RESOLVE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("dynamic_resolve: [DRY RUN] would resolve %lu APIs via GetModuleHandle+GetProcAddress",
            (unsigned long)API_TABLE_SIZE);
        return TEKTON_OK;
    }

#ifdef _WIN32
    DWORD resolved = 0;
    DWORD failed = 0;

    for (DWORD i = 0; i < API_TABLE_SIZE; i++) {
        const API_ENTRY* entry = &g_api_table[i];

        HMODULE hMod = GetModuleHandleA(entry->dll_name);
        if (!hMod) {
            /* DLL not loaded, try loading it */
            hMod = LoadLibraryA(entry->dll_name);
            if (!hMod) {
                TLOG_WARN("dynamic_resolve: failed to load %s", entry->dll_name);
                failed++;
                continue;
            }
        }

        PVOID func = (PVOID)GetProcAddress(hMod, entry->func_name);
        if (!func) {
            TLOG_WARN("dynamic_resolve: failed to resolve %s!%s",
                entry->dll_name, entry->func_name);
            failed++;
            continue;
        }

        /* Store function pointer at the correct offset in resolved state */
        PVOID* slot = (PVOID*)((BYTE*)&ctx->resolved + entry->offset_in_resolved);
        *slot = func;

        TLOG_TRACE("dynamic_resolve: %s!%s -> %p", entry->dll_name, entry->func_name, func);
        resolved++;
    }

    /* Cache module bases */
    state->ntdll_base = (PVOID)GetModuleHandleA("ntdll.dll");
    state->kernel32_base = (PVOID)GetModuleHandleA("kernel32.dll");

    ctx->resolved.apis_resolved = TRUE;
    state->initialized = TRUE;

    TLOG_INFO("dynamic_resolve: resolved %lu/%lu APIs (%lu failed)",
        (unsigned long)resolved, (unsigned long)API_TABLE_SIZE, (unsigned long)failed);

    if (failed > 0 && resolved == 0) {
        return TEKTON_ERR_API_RESOLVE;
    }

#else
    TLOG_INFO("dynamic_resolve: non-Windows stub, marking resolved");
    ctx->resolved.apis_resolved = TRUE;
    state->initialized = TRUE;
#endif

    return TEKTON_OK;
}

static VOID dynamic_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(DYNAMIC_RESOLVE_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD dynamic_risk_score(PTEKTON_MODULE self) {
    (void)self;
    return 40; /* Moderate: still uses GetProcAddress in IAT */
}

static BOOL dynamic_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE; /* Works on all Windows versions */
}

/* ── Public helper: resolve single API by name ──────────── */

TEKTON_STATUS TektonApiResolveByName(
    PTEKTON_CONTEXT ctx,
    const char*     dll_name,
    const char*     func_name,
    PVOID*          out_func_ptr
) {
    if (!ctx || !dll_name || !func_name || !out_func_ptr) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    *out_func_ptr = NULL;

#ifdef _WIN32
    HMODULE hMod = GetModuleHandleA(dll_name);
    if (!hMod) {
        hMod = LoadLibraryA(dll_name);
        if (!hMod) return TEKTON_ERR_API_RESOLVE;
    }

    *out_func_ptr = (PVOID)GetProcAddress(hMod, func_name);
    if (!*out_func_ptr) return TEKTON_ERR_API_RESOLVE;
#else
    (void)dll_name; (void)func_name;
    TLOG_DEBUG("TektonApiResolveByName: non-Windows stub");
#endif

    return TEKTON_OK;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_dynamic_resolve = {
    .name           = "dynamic_resolve",
    .description    = "Dynamic API resolution via GetModuleHandle + GetProcAddress (Cat 1.1)",
    .category       = TEKTON_CAT_API_RESOLVE,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = 0,
    .skill_ref      = "1.1",
    .init           = dynamic_init,
    .execute        = dynamic_execute,
    .cleanup        = dynamic_cleanup,
    .get_risk_score = dynamic_risk_score,
    .check_compat   = dynamic_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_dynamic_resolve);
