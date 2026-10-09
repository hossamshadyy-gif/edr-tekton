/*
 * edr-tekton :: PEB Anti-Debug Check (Cat 8.1)
 * Detect debuggers via PEB.BeingDebugged and PEB.NtGlobalFlag
 *
 * The Process Environment Block (PEB) is a user-mode structure that
 * the OS maintains for every process. When a debugger attaches:
 *
 *   1. PEB->BeingDebugged (offset 0x02, BYTE) is set to 1.
 *      This is what IsDebuggerPresent() reads internally.
 *
 *   2. PEB->NtGlobalFlag (offset 0xBC on x64, 0x68 on x86) gets
 *      the following heap debug flags OR'd in by the NT loader when
 *      the process is created under a debugger:
 *        FLG_HEAP_ENABLE_TAIL_CHECK       (0x10)
 *        FLG_HEAP_ENABLE_FREE_CHECK        (0x20)
 *        FLG_HEAP_VALIDATE_PARAMETERS      (0x40)
 *      Combined mask: 0x70
 *
 * Both fields are readable from user mode with no API calls, making
 * this check impossible to intercept via API hooking alone. An EDR
 * or debugger must patch the PEB itself to defeat it.
 *
 * Risk: very low (5). Reading your own PEB is normal process behavior
 * and generates no ETW events or syscalls.
 */

#include "tekton/modules/antidebug.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── PEB offsets ───────────────────────────────────────────── */

#ifdef _WIN32
    #ifdef _WIN64
        #define PEB_BEING_DEBUGGED_OFFSET   0x02
        #define PEB_NT_GLOBAL_FLAG_OFFSET   0xBC
    #else
        #define PEB_BEING_DEBUGGED_OFFSET   0x02
        #define PEB_NT_GLOBAL_FLAG_OFFSET   0x68
    #endif
#endif

/* Heap debug flags set by ntdll loader under a debugger */
#define FLG_HEAP_ENABLE_TAIL_CHECK          0x10
#define FLG_HEAP_ENABLE_FREE_CHECK          0x20
#define FLG_HEAP_VALIDATE_PARAMETERS        0x40
#define FLG_HEAP_DEBUG_MASK                 0x70

/* ── Internal state ────────────────────────────────────────── */

typedef struct _PEB_CHECK_STATE {
    BOOL    being_debugged;     /* Result of BeingDebugged check  */
    BOOL    ntglobal_flagged;   /* Result of NtGlobalFlag check   */
    BOOL    detected;           /* Combined result                */
} PEB_CHECK_STATE;

/* ── Module vtable implementation ──────────────────────────── */

static TEKTON_STATUS peb_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    PEB_CHECK_STATE* state = (PEB_CHECK_STATE*)malloc(sizeof(PEB_CHECK_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("antidebug_peb: init");
    return TEKTON_OK;
}

static TEKTON_STATUS peb_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    PEB_CHECK_STATE* state = (PEB_CHECK_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("antidebug_peb: [DRY RUN] would check PEB.BeingDebugged + NtGlobalFlag");
        return TEKTON_OK;
    }

#ifdef _WIN32
    /*
     * Read the PEB base address from the TEB (Thread Environment Block).
     * On x64: gs:[0x60] holds the PEB pointer.
     * On x86: fs:[0x30] holds the PEB pointer.
     */
    BYTE* peb_base = NULL;

    #ifdef _WIN64
        peb_base = (BYTE*)__readgsqword(0x60);
    #else
        peb_base = (BYTE*)__readfsdword(0x30);
    #endif

    if (!peb_base) {
        TLOG_ERROR("antidebug_peb: failed to read PEB address from TEB");
        return TEKTON_ERR_GENERIC;
    }

    /* ── Check 1: PEB.BeingDebugged ──────────────────── */
    BYTE being_debugged = *(BYTE*)(peb_base + PEB_BEING_DEBUGGED_OFFSET);

    if (being_debugged != 0) {
        state->being_debugged = TRUE;
        TLOG_INFO("antidebug_peb: PEB.BeingDebugged = %u (debugger attached)",
            (unsigned)being_debugged);
    } else {
        TLOG_DEBUG("antidebug_peb: PEB.BeingDebugged = 0 (clean)");
    }

    /* ── Check 2: PEB.NtGlobalFlag ───────────────────── */
    DWORD nt_global_flag = *(DWORD*)(peb_base + PEB_NT_GLOBAL_FLAG_OFFSET);

    if (nt_global_flag & FLG_HEAP_DEBUG_MASK) {
        state->ntglobal_flagged = TRUE;
        TLOG_INFO("antidebug_peb: NtGlobalFlag = 0x%08lX (heap debug flags present: %s%s%s)",
            (unsigned long)nt_global_flag,
            (nt_global_flag & FLG_HEAP_ENABLE_TAIL_CHECK)     ? "TAIL_CHECK " : "",
            (nt_global_flag & FLG_HEAP_ENABLE_FREE_CHECK)     ? "FREE_CHECK " : "",
            (nt_global_flag & FLG_HEAP_VALIDATE_PARAMETERS)   ? "VALIDATE_PARAMS " : "");
    } else {
        TLOG_DEBUG("antidebug_peb: NtGlobalFlag = 0x%08lX (no heap debug flags)",
            (unsigned long)nt_global_flag);
    }

    /* ── Final decision ──────────────────────────────── */
    state->detected = state->being_debugged || state->ntglobal_flagged;

    if (state->detected) {
        TLOG_INFO("antidebug_peb: DEBUGGER DETECTED (BeingDebugged=%d, NtGlobalFlag=0x%lX)",
            state->being_debugged, (unsigned long)nt_global_flag);
        return TEKTON_ERR_COMPAT_FAIL;
    }

    TLOG_INFO("antidebug_peb: no debugger indicators found in PEB");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    (void)state;
    TLOG_INFO("[DEV] antidebug_peb: skipped (non-Windows)");
    return TEKTON_OK;
#endif
}

static VOID peb_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(PEB_CHECK_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD peb_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Extremely low risk. Reading the PEB is a direct memory access
     * to a user-mode structure with no API call, no syscall, and no
     * ETW event. Every process reads its own PEB constantly during
     * normal execution (CRT startup, heap operations, etc.).
     */
    return 5;
}

static BOOL peb_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* PEB is always present and readable in every Windows process */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────────── */

TEKTON_MODULE tekton_mod_antidebug_peb = {
    .name           = "antidebug_peb",
    .description    = "PEB.BeingDebugged + NtGlobalFlag debugger detection (Cat 8.1)",
    .category       = TEKTON_CAT_ANTIDEBUG,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "8.1",
    .init           = peb_init,
    .execute        = peb_execute,
    .cleanup        = peb_cleanup,
    .get_risk_score = peb_risk_score,
    .check_compat   = peb_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_antidebug_peb);
