/*
 * edr-tekton :: Hardware Breakpoint Detection (Cat 8.4)
 * Detect debuggers via debug register inspection (Dr0-Dr3)
 *
 * x86/x64 CPUs have four debug address registers (DR0-DR3) that
 * hold breakpoint addresses. When a debugger sets a hardware
 * breakpoint, it writes the target address into one of these
 * registers and configures DR7 (debug control register) to enable
 * the breakpoint.
 *
 * Detection method:
 *   Call GetThreadContext() with CONTEXT_DEBUG_REGISTERS to read
 *   the current thread's DR0-DR3. If any register is non-zero,
 *   a hardware breakpoint is set, which is strong evidence of an
 *   attached debugger or instrumentation framework.
 *
 * Caveats:
 *   - Some EDR/sandbox tools use hardware breakpoints for their own
 *     hooking (e.g., to intercept API calls without patching code).
 *     In that case, this check detects the EDR itself.
 *   - Anti-cheat engines also use Dr0-Dr3, so non-zero does not
 *     always mean a human analyst is present.
 *   - A sophisticated debugger can intercept GetThreadContext and
 *     zero out the debug registers in the returned CONTEXT.
 *
 * Risk: 10. GetThreadContext is a normal Win32 API. Querying your
 * own thread context is unremarkable, but specifically requesting
 * CONTEXT_DEBUG_REGISTERS is a known anti-debug pattern.
 */

#include "tekton/modules/antidebug.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ────────────────────────────────────────── */

typedef struct _HWBP_STATE {
    BOOL        detected;
    ULONG_PTR   dr0;
    ULONG_PTR   dr1;
    ULONG_PTR   dr2;
    ULONG_PTR   dr3;
    ULONG_PTR   dr7;        /* Debug control register (for logging) */
} HWBP_STATE;

/* ── Win32 context flags ───────────────────────────────────── */

#ifdef _WIN32
    #ifndef CONTEXT_DEBUG_REGISTERS
        #ifdef _WIN64
            #define CONTEXT_AMD64               0x00100000L
            #define CONTEXT_DEBUG_REGISTERS_FLAG (CONTEXT_AMD64 | 0x00000010L)
        #else
            #define CONTEXT_i386                0x00010000L
            #define CONTEXT_DEBUG_REGISTERS_FLAG (CONTEXT_i386 | 0x00000010L)
        #endif
    #else
        #define CONTEXT_DEBUG_REGISTERS_FLAG CONTEXT_DEBUG_REGISTERS
    #endif
#endif

/* ── Module vtable implementation ──────────────────────────── */

static TEKTON_STATUS hwbp_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    HWBP_STATE* state = (HWBP_STATE*)malloc(sizeof(HWBP_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("antidebug_hwbp: init");
    return TEKTON_OK;
}

static TEKTON_STATUS hwbp_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    HWBP_STATE* state = (HWBP_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("antidebug_hwbp: [DRY RUN] would check Dr0-Dr3 via GetThreadContext");
        return TEKTON_OK;
    }

#ifdef _WIN32
    /*
     * Resolve GetThreadContext and GetCurrentThread from kernel32.
     * Using dynamic resolution to match the framework pattern and
     * avoid IAT entries that static analysis could flag.
     */
    typedef HANDLE (WINAPI *pfnGetCurrentThread)(void);
    typedef BOOL   (WINAPI *pfnGetThreadContext)(HANDLE, PVOID);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        TLOG_ERROR("antidebug_hwbp: cannot get kernel32 handle");
        return TEKTON_ERR_API_RESOLVE;
    }

    pfnGetCurrentThread pGetCurrentThread = (pfnGetCurrentThread)
        GetProcAddress(hKernel32, "GetCurrentThread");
    pfnGetThreadContext pGetThreadContext = (pfnGetThreadContext)
        GetProcAddress(hKernel32, "GetThreadContext");

    if (!pGetCurrentThread || !pGetThreadContext) {
        TLOG_ERROR("antidebug_hwbp: failed to resolve GetCurrentThread/GetThreadContext");
        return TEKTON_ERR_API_RESOLVE;
    }

    /*
     * Allocate a CONTEXT structure. On x64 this is ~1232 bytes and
     * must be 16-byte aligned. We allocate on the heap and align
     * manually to be safe across compilers.
     */
    CONTEXT thread_ctx;
    memset(&thread_ctx, 0, sizeof(thread_ctx));
    thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_FLAG;

    HANDLE hThread = pGetCurrentThread();

    if (!pGetThreadContext(hThread, &thread_ctx)) {
        TLOG_ERROR("antidebug_hwbp: GetThreadContext failed (err=%lu)",
            (unsigned long)GetLastError());
        return TEKTON_ERR_SYSCALL_FAIL;
    }

    /* Read debug registers from the returned context */
    state->dr0 = (ULONG_PTR)thread_ctx.Dr0;
    state->dr1 = (ULONG_PTR)thread_ctx.Dr1;
    state->dr2 = (ULONG_PTR)thread_ctx.Dr2;
    state->dr3 = (ULONG_PTR)thread_ctx.Dr3;
    state->dr7 = (ULONG_PTR)thread_ctx.Dr7;

    TLOG_DEBUG("antidebug_hwbp: Dr0=0x%llX Dr1=0x%llX Dr2=0x%llX Dr3=0x%llX Dr7=0x%llX",
        (unsigned long long)state->dr0,
        (unsigned long long)state->dr1,
        (unsigned long long)state->dr2,
        (unsigned long long)state->dr3,
        (unsigned long long)state->dr7);

    /* Any non-zero Dr0-Dr3 indicates a hardware breakpoint is set */
    state->detected = (state->dr0 != 0) ||
                      (state->dr1 != 0) ||
                      (state->dr2 != 0) ||
                      (state->dr3 != 0);

    if (state->detected) {
        TLOG_INFO("antidebug_hwbp: HARDWARE BREAKPOINTS DETECTED");

        if (state->dr0) TLOG_INFO("  Dr0 = 0x%llX", (unsigned long long)state->dr0);
        if (state->dr1) TLOG_INFO("  Dr1 = 0x%llX", (unsigned long long)state->dr1);
        if (state->dr2) TLOG_INFO("  Dr2 = 0x%llX", (unsigned long long)state->dr2);
        if (state->dr3) TLOG_INFO("  Dr3 = 0x%llX", (unsigned long long)state->dr3);

        TLOG_INFO("  Dr7 = 0x%llX (control: local=%d global=%d)",
            (unsigned long long)state->dr7,
            (int)(state->dr7 & 0x55),       /* Local enable bits  */
            (int)((state->dr7 >> 1) & 0x55) /* Global enable bits */
        );

        return TEKTON_ERR_COMPAT_FAIL;
    }

    TLOG_INFO("antidebug_hwbp: no hardware breakpoints set");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    (void)state;
    TLOG_INFO("[DEV] antidebug_hwbp: skipped (non-Windows)");
    return TEKTON_OK;
#endif
}

static VOID hwbp_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(HWBP_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD hwbp_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low-moderate risk. GetThreadContext is a common Win32 API used
     * by crash handlers, profilers, and exception dispatchers. However,
     * the specific request for CONTEXT_DEBUG_REGISTERS is a known
     * anti-debug indicator in YARA rules and sandbox heuristics.
     */
    return 10;
}

static BOOL hwbp_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* GetThreadContext with debug registers works on all Windows versions */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────────── */

TEKTON_MODULE tekton_mod_antidebug_hwbp = {
    .name           = "antidebug_hwbp",
    .description    = "Hardware breakpoint detection via Dr0-Dr3 registers (Cat 8.4)",
    .category       = TEKTON_CAT_ANTIDEBUG,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "8.4",
    .init           = hwbp_init,
    .execute        = hwbp_execute,
    .cleanup        = hwbp_cleanup,
    .get_risk_score = hwbp_risk_score,
    .check_compat   = hwbp_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_antidebug_hwbp);
