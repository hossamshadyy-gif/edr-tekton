/*
 * edr-tekton :: NtQueryInformationProcess Anti-Debug (Cat 8.3)
 * Detect debuggers via ProcessDebugPort, ProcessDebugObjectHandle,
 * and ProcessDebugFlags information classes.
 *
 * NtQueryInformationProcess is a native API that returns internal
 * process state from the kernel. Three information classes reveal
 * debugger attachment:
 *
 *   ProcessDebugPort (0x07):
 *     Returns the debug port handle. Non-zero means a debugger is
 *     attached. This is the same check CheckRemoteDebuggerPresent()
 *     performs internally, but calling Nt* directly avoids user-mode
 *     hooks on kernel32.
 *
 *   ProcessDebugObjectHandle (0x1E):
 *     Returns a handle to the debug object. If a debugger is attached,
 *     this returns a valid handle (non-zero). If no debugger, the call
 *     returns STATUS_PORT_NOT_SET.
 *
 *   ProcessDebugFlags (0x1F):
 *     Returns the NoDebugInherit flag. Value 0 means a debugger is
 *     present (the flag indicates "do not inherit debug" was NOT set,
 *     so a debugger is active). Value 1 = no debugger.
 *
 * Risk: 15. NtQueryInformationProcess with debug-related classes is a
 * well-known anti-debug technique. Some EDRs monitor these calls
 * specifically, and emulators may intercept them. More detectable than
 * PEB reads because it involves a syscall.
 */

#include "tekton/modules/antidebug.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── NQIP information classes ──────────────────────────────── */

#define PROCESS_DEBUG_PORT              0x07
#define PROCESS_DEBUG_OBJECT_HANDLE     0x1E
#define PROCESS_DEBUG_FLAGS             0x1F

/* ── Internal state ────────────────────────────────────────── */

typedef struct _NTQUERY_STATE {
    BOOL    debug_port_found;       /* Non-zero DebugPort           */
    BOOL    debug_object_found;     /* Valid DebugObjectHandle       */
    BOOL    debug_flags_found;      /* DebugFlags == 0              */
    BOOL    detected;
} NTQUERY_STATE;

/* ── NtQueryInformationProcess typedef ─────────────────────── */

#ifdef _WIN32
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE  ProcessHandle,
    DWORD   ProcessInformationClass,    /* PROCESSINFOCLASS */
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength
);
#endif

/* ── Module vtable implementation ──────────────────────────── */

static TEKTON_STATUS ntquery_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    NTQUERY_STATE* state = (NTQUERY_STATE*)malloc(sizeof(NTQUERY_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("antidebug_ntquery: init");
    return TEKTON_OK;
}

static TEKTON_STATUS ntquery_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    NTQUERY_STATE* state = (NTQUERY_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("antidebug_ntquery: [DRY RUN] would query DebugPort, "
            "DebugObjectHandle, DebugFlags");
        return TEKTON_OK;
    }

#ifdef _WIN32
    /*
     * Resolve NtQueryInformationProcess from ntdll.dll directly.
     * If the pipeline has already resolved it (ctx->resolved), we
     * could use that, but resolving our own copy avoids depending on
     * pipeline ordering.
     */
    pfnNtQueryInformationProcess pNtQIP = NULL;

    /* Prefer the pre-resolved pointer if available */
    if (ctx->resolved.fn_nt_query_information_process) {
        pNtQIP = (pfnNtQueryInformationProcess)ctx->resolved.fn_nt_query_information_process;
    } else {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pNtQIP = (pfnNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }

    if (!pNtQIP) {
        TLOG_ERROR("antidebug_ntquery: failed to resolve NtQueryInformationProcess");
        return TEKTON_ERR_API_RESOLVE;
    }

    HANDLE hProcess = (HANDLE)(LONG_PTR)-1;  /* NtCurrentProcess() = (HANDLE)-1 */
    NTSTATUS status;
    ULONG ret_len = 0;

    /* ── Check 1: ProcessDebugPort (0x07) ────────────── */
    {
        /*
         * On x64, the DebugPort value is a DWORD_PTR (8 bytes).
         * Non-zero = debugger attached.
         */
        ULONG_PTR debug_port = 0;

        status = pNtQIP(
            hProcess,
            PROCESS_DEBUG_PORT,
            &debug_port,
            sizeof(debug_port),
            &ret_len
        );

        if (NT_SUCCESS(status)) {
            if (debug_port != 0) {
                state->debug_port_found = TRUE;
                TLOG_INFO("antidebug_ntquery: ProcessDebugPort = 0x%llX (debugger attached)",
                    (unsigned long long)debug_port);
            } else {
                TLOG_DEBUG("antidebug_ntquery: ProcessDebugPort = 0 (clean)");
            }
        } else {
            TLOG_WARN("antidebug_ntquery: NtQIP(DebugPort) failed, status=0x%08lX",
                (unsigned long)status);
        }
    }

    /* ── Check 2: ProcessDebugObjectHandle (0x1E) ────── */
    {
        /*
         * If a debugger is attached, this returns a valid handle to the
         * debug object. If no debugger, the call fails with
         * STATUS_PORT_NOT_SET (0xC0000353).
         */
        HANDLE debug_object = NULL;

        status = pNtQIP(
            hProcess,
            PROCESS_DEBUG_OBJECT_HANDLE,
            &debug_object,
            sizeof(debug_object),
            &ret_len
        );

        if (NT_SUCCESS(status) && debug_object != NULL) {
            state->debug_object_found = TRUE;
            TLOG_INFO("antidebug_ntquery: ProcessDebugObjectHandle returned valid handle");
        } else {
            TLOG_DEBUG("antidebug_ntquery: ProcessDebugObjectHandle not present (clean)");
        }
    }

    /* ── Check 3: ProcessDebugFlags (0x1F) ───────────── */
    {
        /*
         * Returns a DWORD. Value 0 means a debugger IS present
         * (NoDebugInherit is not set). Value 1 = no debugger.
         * This is the inverse of the other checks.
         */
        DWORD debug_flags = 1;  /* Default to "no debugger" */

        status = pNtQIP(
            hProcess,
            PROCESS_DEBUG_FLAGS,
            &debug_flags,
            sizeof(debug_flags),
            &ret_len
        );

        if (NT_SUCCESS(status)) {
            if (debug_flags == 0) {
                state->debug_flags_found = TRUE;
                TLOG_INFO("antidebug_ntquery: ProcessDebugFlags = 0 (debugger present)");
            } else {
                TLOG_DEBUG("antidebug_ntquery: ProcessDebugFlags = %lu (clean)",
                    (unsigned long)debug_flags);
            }
        } else {
            TLOG_WARN("antidebug_ntquery: NtQIP(DebugFlags) failed, status=0x%08lX",
                (unsigned long)status);
        }
    }

    /* ── Final decision ──────────────────────────────── */
    state->detected = state->debug_port_found ||
                      state->debug_object_found ||
                      state->debug_flags_found;

    if (state->detected) {
        TLOG_INFO("antidebug_ntquery: DEBUGGER DETECTED "
            "(port=%d, object=%d, flags=%d)",
            state->debug_port_found,
            state->debug_object_found,
            state->debug_flags_found);
        return TEKTON_ERR_COMPAT_FAIL;
    }

    TLOG_INFO("antidebug_ntquery: no debugger detected via NtQueryInformationProcess");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    (void)state;
    TLOG_INFO("[DEV] antidebug_ntquery: skipped (non-Windows)");
    return TEKTON_OK;
#endif
}

static VOID ntquery_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(NTQUERY_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD ntquery_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Moderate risk. NtQueryInformationProcess with debug info classes
     * is a well-known anti-debug technique monitored by some EDRs.
     * The syscall itself is normal (used by Task Manager, etc.), but
     * the specific information classes 0x07, 0x1E, 0x1F are suspicious
     * in combination.
     */
    return 15;
}

static BOOL ntquery_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /*
     * NtQueryInformationProcess is available on all NT-based Windows.
     * However, if ntdll hooks are detected (which might intercept NQIP),
     * we warn that the result may be unreliable.
     */
    if (ctx->edr.hooks_detected) {
        TLOG_WARN("antidebug_ntquery: ntdll hooks detected, "
            "NQIP results may be spoofed by EDR/debugger");
    }
    return TRUE;
}

/* ── Module definition ─────────────────────────────────────── */

TEKTON_MODULE tekton_mod_antidebug_ntquery = {
    .name           = "antidebug_ntquery",
    .description    = "NtQueryInformationProcess debug port/object/flags detection (Cat 8.3)",
    .category       = TEKTON_CAT_ANTIDEBUG,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_NONE,
    .skill_ref      = "8.3",
    .init           = ntquery_init,
    .execute        = ntquery_execute,
    .cleanup        = ntquery_cleanup,
    .get_risk_score = ntquery_risk_score,
    .check_compat   = ntquery_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_antidebug_ntquery);
