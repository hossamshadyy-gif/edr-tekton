/*
 * edr-tekton :: Hash-Based API Resolution Module
 * Cat 1.3/1.8/1.9: CRC32B, Djb2, Additive hash resolution
 *
 * Resolves APIs by hashing names at runtime and matching against
 * compile-time hash values. No plaintext API name strings in binary.
 *
 * Supports multiple hash algorithms:
 *   - CRC32B  (Cat 1.8): best collision resistance, forwarded fn support
 *   - Djb2    (Cat 1.9): compact, used in sRDI shellcode
 *   - Additive (Cat 1.3): simplest, adequate for most use cases
 *
 * Combined with PEB walking (Cat 1.2) for zero-import resolution.
 */

#include "tekton/modules/api_resolve.h"
#include "tekton/util/hash.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _HASH_RESOLVE_STATE {
    BOOL                initialized;
    TEKTON_HASH_ALGO    algo;
    TEKTON_HASH_FUNC    hash_fn;        /* char* -> DWORD */
    TEKTON_HASH_FUNC_W  hash_fn_w;      /* wchar_t* -> DWORD (for DLL names) */
    PVOID               ntdll_base;
} HASH_RESOLVE_STATE;

/* ── Pre-computed hash table ────────────────────────────── */
/*
 * These hashes are for CRC32B by default.
 * When using other algorithms, the module re-hashes at init
 * or the profile supplies the correct pre-computed values.
 *
 * For CRC32B case-sensitive:
 *   NtAllocateVirtualMemory -> TektonHashCrc32bStringA("NtAllocateVirtualMemory")
 *
 * We compute them at init time from the function name strings
 * so the module works with any selected algorithm.
 */

typedef struct _HASH_API_ENTRY {
    const char*     func_name;          /* Used to compute hash at init */
    DWORD           dll_name_hash;      /* Computed at init from dll name */
    DWORD           func_hash;          /* Computed at init from func name */
    SIZE_T          offset_in_resolved;
} HASH_API_ENTRY;

#define RESOLVED_OFFSET(field) \
    ((SIZE_T)&((PTEKTON_RESOLVED_STATE)0)->field)

/*
 * Note: func_name stored here for hash computation at init time.
 * In a production build, these would be stripped and only the
 * pre-computed hashes retained. The framework supports both modes.
 */
static HASH_API_ENTRY g_hash_api_table[] = {
    { "NtAllocateVirtualMemory",   0, 0, RESOLVED_OFFSET(fn_nt_allocate_virtual_memory)   },
    { "NtWriteVirtualMemory",      0, 0, RESOLVED_OFFSET(fn_nt_write_virtual_memory)      },
    { "NtProtectVirtualMemory",    0, 0, RESOLVED_OFFSET(fn_nt_protect_virtual_memory)    },
    { "NtCreateThreadEx",          0, 0, RESOLVED_OFFSET(fn_nt_create_thread_ex)          },
    { "NtCreateSection",           0, 0, RESOLVED_OFFSET(fn_nt_create_section)            },
    { "NtMapViewOfSection",        0, 0, RESOLVED_OFFSET(fn_nt_map_view_of_section)       },
    { "NtUnmapViewOfSection",      0, 0, RESOLVED_OFFSET(fn_nt_unmap_view_of_section)     },
    { "NtQueueApcThread",          0, 0, RESOLVED_OFFSET(fn_nt_queue_apc_thread)          },
    { "NtOpenProcess",             0, 0, RESOLVED_OFFSET(fn_nt_open_process)              },
    { "NtClose",                   0, 0, RESOLVED_OFFSET(fn_nt_close)                     },
    { "NtWaitForSingleObject",     0, 0, RESOLVED_OFFSET(fn_nt_wait_for_single_object)    },
    { "NtSuspendThread",           0, 0, RESOLVED_OFFSET(fn_nt_suspend_thread)            },
    { "NtResumeThread",            0, 0, RESOLVED_OFFSET(fn_nt_resume_thread)             },
    { "NtSetInformationProcess",   0, 0, RESOLVED_OFFSET(fn_nt_set_information_process)   },
    { "NtQuerySystemInformation",  0, 0, RESOLVED_OFFSET(fn_nt_query_system_information)  },
    { "NtQueryInformationProcess", 0, 0, RESOLVED_OFFSET(fn_nt_query_information_process) },
    { "RtlInitUnicodeString",      0, 0, RESOLVED_OFFSET(fn_rtl_init_unicode_string)      },
};

#define HASH_API_TABLE_SIZE (sizeof(g_hash_api_table) / sizeof(g_hash_api_table[0]))

/* ── Hash function wrappers ─────────────────────────────── */

static DWORD hash_wrap_crc32b(const char* str) {
    return TektonHashCrc32bStringA(str);
}

static DWORD hash_wrap_crc32b_w(const wchar_t* str) {
    return TektonHashCrc32bStringWi(str);
}

static DWORD hash_wrap_djb2(const char* str) {
    return TektonHashDjb2StringA(str);
}

static DWORD hash_wrap_djb2_w(const wchar_t* str) {
    /* Djb2 on narrow version of wide string (DLL names are ASCII) */
    char narrow[256];
    int i = 0;
    while (str[i] && i < 255) {
        wchar_t c = str[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        narrow[i] = (char)c;
        i++;
    }
    narrow[i] = '\0';
    return TektonHashDjb2StringA(narrow);
}

static DWORD hash_wrap_additive(const char* str) {
    return TektonHashAdditive(str);
}

static DWORD hash_wrap_additive_w(const wchar_t* str) {
    char narrow[256];
    int i = 0;
    while (str[i] && i < 255) {
        wchar_t c = str[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        narrow[i] = (char)c;
        i++;
    }
    narrow[i] = '\0';
    return TektonHashAdditive(narrow);
}

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS hash_resolve_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    HASH_RESOLVE_STATE* state = (HASH_RESOLVE_STATE*)malloc(sizeof(HASH_RESOLVE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /*
     * Select hash algorithm from config.
     * Default to CRC32B if not specified.
     */
    state->algo = TEKTON_HASH_CRC32B;

    /* TODO: read from ctx config when available */

    switch (state->algo) {
        case TEKTON_HASH_CRC32B:
            state->hash_fn   = hash_wrap_crc32b;
            state->hash_fn_w = hash_wrap_crc32b_w;
            break;
        case TEKTON_HASH_DJB2:
            state->hash_fn   = hash_wrap_djb2;
            state->hash_fn_w = hash_wrap_djb2_w;
            break;
        case TEKTON_HASH_ADDITIVE:
            state->hash_fn   = hash_wrap_additive;
            state->hash_fn_w = hash_wrap_additive_w;
            break;
        default:
            free(state);
            return TEKTON_ERR_INVALID_PARAM;
    }

    /* Pre-compute hashes for all target APIs */
    DWORD ntdll_hash = state->hash_fn("ntdll.dll");

    for (DWORD i = 0; i < HASH_API_TABLE_SIZE; i++) {
        g_hash_api_table[i].dll_name_hash = ntdll_hash;
        g_hash_api_table[i].func_hash = state->hash_fn(g_hash_api_table[i].func_name);

        TLOG_TRACE("hash_resolve: %s -> 0x%08lX",
            g_hash_api_table[i].func_name,
            (unsigned long)g_hash_api_table[i].func_hash);
    }

    self->private_data = state;

    TLOG_DEBUG("hash_resolve: init with algo=%d", state->algo);
    return TEKTON_OK;
}

static TEKTON_STATUS hash_resolve_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    HASH_RESOLVE_STATE* state = (HASH_RESOLVE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("hash_resolve: [DRY RUN] would resolve %lu APIs via hash matching (algo=%d)",
            (unsigned long)HASH_API_TABLE_SIZE, state->algo);
        return TEKTON_OK;
    }

    /*
     * Step 1: Find ntdll base via PEB walking + hash match
     * Uses TektonPebGetModuleBaseByHash to match DLL name by hash
     */
    PVOID ntdll_base = TektonPebGetModuleBaseByHash(
        g_hash_api_table[0].dll_name_hash,
        state->hash_fn_w
    );

    if (!ntdll_base) {
        /* Fallback: try name-based PEB walk */
        ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    }

    if (!ntdll_base) {
        TLOG_ERROR("hash_resolve: failed to find ntdll.dll");
        return TEKTON_ERR_API_RESOLVE;
    }

    state->ntdll_base = ntdll_base;
    TLOG_DEBUG("hash_resolve: ntdll.dll base = %p", ntdll_base);

    /*
     * Step 2: Walk PE export table, hash each name, match against targets
     * Uses TektonPeFindExportByHash for single-pass resolution
     */
    DWORD resolved = 0;
    DWORD failed = 0;

    for (DWORD i = 0; i < HASH_API_TABLE_SIZE; i++) {
        HASH_API_ENTRY* entry = &g_hash_api_table[i];

        PVOID func = TektonPeFindExportByHash(
            ntdll_base,
            entry->func_hash,
            state->hash_fn
        );

        if (!func) {
            TLOG_WARN("hash_resolve: hash 0x%08lX not found in exports",
                (unsigned long)entry->func_hash);
            failed++;
            continue;
        }

        PVOID* slot = (PVOID*)((BYTE*)&ctx->resolved + entry->offset_in_resolved);
        *slot = func;

        TLOG_TRACE("hash_resolve: 0x%08lX -> %p",
            (unsigned long)entry->func_hash, func);
        resolved++;
    }

    ctx->resolved.apis_resolved = TRUE;
    state->initialized = TRUE;

    TLOG_INFO("hash_resolve: resolved %lu/%lu APIs via hash (algo=%d, zero string imports)",
        (unsigned long)resolved, (unsigned long)HASH_API_TABLE_SIZE, state->algo);

    if (failed > 0 && resolved == 0) {
        return TEKTON_ERR_API_RESOLVE;
    }

    return TEKTON_OK;
}

static VOID hash_resolve_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        /* Zero out hash tables to prevent forensic recovery */
        for (DWORD i = 0; i < HASH_API_TABLE_SIZE; i++) {
            g_hash_api_table[i].dll_name_hash = 0;
            g_hash_api_table[i].func_hash = 0;
        }

        TEKTON_SECURE_ZERO(self->private_data, sizeof(HASH_RESOLVE_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD hash_resolve_risk_score(PTEKTON_MODULE self) {
    (void)self;
    return 10; /* Very low: no API name strings, no import dependencies */
}

static BOOL hash_resolve_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE; /* Hash-based resolution works on all Windows versions */
}

/* ── Public helper: resolve single API by hash ──────────── */

TEKTON_STATUS TektonApiResolveByHash(
    PTEKTON_CONTEXT ctx,
    DWORD           dll_hash,
    DWORD           func_hash,
    PVOID*          out_func_ptr
) {
    if (!ctx || !out_func_ptr) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    *out_func_ptr = NULL;

    /* Use CRC32B as default hash for this helper */
    PVOID dll_base = TektonPebGetModuleBaseByHash(
        dll_hash,
        (TEKTON_HASH_FUNC_W)TektonHashCrc32bStringWi
    );

    if (!dll_base) {
        return TEKTON_ERR_API_RESOLVE;
    }

    *out_func_ptr = TektonPeFindExportByHash(
        dll_base,
        func_hash,
        (TEKTON_HASH_FUNC)TektonHashCrc32bStringA
    );

    if (!*out_func_ptr) {
        return TEKTON_ERR_API_RESOLVE;
    }

    return TEKTON_OK;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_hash_resolve = {
    .name           = "hash_resolve",
    .description    = "Hash-based API resolution: CRC32B/Djb2/Additive (Cat 1.3/1.8/1.9)",
    .category       = TEKTON_CAT_API_RESOLVE,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "1.8",
    .init           = hash_resolve_init,
    .execute        = hash_resolve_execute,
    .cleanup        = hash_resolve_cleanup,
    .get_risk_score = hash_resolve_risk_score,
    .check_compat   = hash_resolve_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_hash_resolve);
