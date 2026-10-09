/*
 * edr-tekton :: INT 2D / Trap Flag Detection (Cat 8.5)
 * Detect debuggers via exception-swallowing behavior
 *
 * This module uses two complementary techniques that exploit how
 * debuggers intercept CPU exceptions differently than the OS:
 *
 * Technique 1: INT 2D
 *   The INT 2D instruction is a "debug service" interrupt. When
 *   executed under a debugger:
 *     - The debugger's breakpoint handler intercepts the exception
 *     - It may skip the next byte (depending on debugger implementation)
 *     - The structured exception handler (SEH) is NOT called
 *   Without a debugger:
 *     - The exception is dispatched through SEH normally
 *     - Our __except handler catches it
 *   By placing code inside __try/__except and checking whether the
 *   exception handler was called, we detect debugger interception.
 *
 * Technique 2: Single-Step Trap Flag (TF)
 *   The Trap Flag (bit 8 of EFLAGS/RFLAGS) causes a single-step
 *   exception (#DB, EXCEPTION_SINGLE_STEP) after each instruction.
 *   Under a debugger:
 *     - The debugger silently consumes single-step exceptions
 *       (they're its primary single-step mechanism)
 *     - The SEH handler is NOT called
 *   Without a debugger:
 *     - The single-step exception goes through SEH
 *     - Our handler catches it
 *   We push flags, set TF, and popf. If the exception reaches our
 *   SEH handler, no debugger is present.
 *
 * Risk: 20. These techniques are well-documented anti-debug methods.
 * INT 2D is a classic signature that YARA rules and AV heuristics
 * detect. The trap flag trick is similarly catalogued. Both involve
 * exception-based control flow that is unusual in legitimate code.
 */

#include "tekton/modules/antidebug.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ────────────────────────────────────────── */

typedef struct _TRAP_STATE {
    BOOL    int2d_detected;     /* SEH was NOT called after INT 2D  */
    BOOL    trapflag_detected;  /* SEH was NOT called after TF set  */
    BOOL    detected;
} TRAP_STATE;

/* ── Module vtable implementation ──────────────────────────── */

static TEKTON_STATUS trap_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    TRAP_STATE* state = (TRAP_STATE*)malloc(sizeof(TRAP_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("antidebug_trap: init");
    return TEKTON_OK;
}

static TEKTON_STATUS trap_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    TRAP_STATE* state = (TRAP_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("antidebug_trap: [DRY RUN] would check INT 2D + trap flag via SEH");
        return TEKTON_OK;
    }

#ifdef _WIN32

    /* ── Check 1: INT 2D exception swallowing ────────── */
    {
        /*
         * Execute INT 2D inside __try/__except. Without a debugger,
         * this triggers an EXCEPTION_BREAKPOINT that our handler catches.
         * With a debugger, the debugger intercepts it and our handler
         * never fires.
         *
         * We use a flag to track whether the exception handler ran.
         */
        volatile BOOL seh_called = FALSE;

        __try {
            /*
             * INT 2D: raises a debug break exception. Under a debugger,
             * the debugger handles it. Under normal execution, it falls
             * through to __except.
             *
             * NOP after INT 2D: some debuggers skip one byte after
             * INT 2D when resuming. The NOP ensures we don't skip
             * into invalid code.
             */
            #ifdef _MSC_VER
                __asm {
                    int 2dh
                    nop
                }
            #elif defined(__GNUC__) || defined(__clang__)
                #ifdef _WIN64
                    __asm__ __volatile__ (
                        "int $0x2d\n\t"
                        "nop"
                        ::: "memory"
                    );
                #else
                    __asm__ __volatile__ (
                        "int $0x2d\n\t"
                        "nop"
                        ::: "memory"
                    );
                #endif
            #endif
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            seh_called = TRUE;
        }

        if (!seh_called) {
            state->int2d_detected = TRUE;
            TLOG_INFO("antidebug_trap: INT 2D exception swallowed by debugger");
        } else {
            TLOG_DEBUG("antidebug_trap: INT 2D exception caught by SEH (clean)");
        }
    }

    /* ── Check 2: Single-Step Trap Flag via SEH ──────── */
    {
        /*
         * Set the Trap Flag (bit 8 of EFLAGS) via pushfd/popfd.
         * This causes a SINGLE_STEP exception after the next instruction.
         *
         * Without a debugger: exception is dispatched through SEH.
         * With a debugger: the debugger silently consumes it (it uses
         * TF for its own single-step feature).
         */
        volatile BOOL seh_called = FALSE;

        __try {
            #ifdef _MSC_VER
                #ifdef _WIN64
                    /*
                     * MSVC x64 does not support inline __asm blocks.
                     * Use an intrinsic-based approach: set the trap flag
                     * via __readeflags / __writeeflags.
                     */
                    unsigned __int64 eflags = __readeflags();
                    eflags |= 0x100;  /* Set TF (bit 8) */
                    __writeeflags(eflags);
                    __nop();  /* This instruction triggers the #DB */
                #else
                    __asm {
                        pushfd
                        or dword ptr [esp], 0x100
                        popfd
                        nop
                    }
                #endif
            #elif defined(__GNUC__) || defined(__clang__)
                #ifdef _WIN64
                    __asm__ __volatile__ (
                        "pushfq\n\t"
                        "orq $0x100, (%%rsp)\n\t"
                        "popfq\n\t"
                        "nop"
                        ::: "memory", "cc"
                    );
                #else
                    __asm__ __volatile__ (
                        "pushfl\n\t"
                        "orl $0x100, (%%esp)\n\t"
                        "popfl\n\t"
                        "nop"
                        ::: "memory", "cc"
                    );
                #endif
            #endif
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            seh_called = TRUE;
        }

        if (!seh_called) {
            state->trapflag_detected = TRUE;
            TLOG_INFO("antidebug_trap: trap flag exception consumed by debugger");
        } else {
            TLOG_DEBUG("antidebug_trap: trap flag exception caught by SEH (clean)");
        }
    }

    /* ── Final decision ──────────────────────────────── */
    state->detected = state->int2d_detected || state->trapflag_detected;

    if (state->detected) {
        TLOG_INFO("antidebug_trap: DEBUGGER DETECTED (int2d=%d, trapflag=%d)",
            state->int2d_detected, state->trapflag_detected);
        return TEKTON_ERR_COMPAT_FAIL;
    }

    TLOG_INFO("antidebug_trap: no debugger detected via exception checks");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    (void)state;
    TLOG_INFO("[DEV] antidebug_trap: skipped (non-Windows)");
    return TEKTON_OK;
#endif
}

static VOID trap_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(TRAP_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD trap_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Elevated risk. INT 2D is a classic anti-debug instruction that
     * appears in many YARA signatures and AV heuristic databases.
     * The trap flag technique is similarly well-known. Both involve
     * exception-based control flow that is uncommon in legitimate
     * software and may trigger behavioral analysis alerts.
     */
    return 20;
}

static BOOL trap_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /*
     * Both techniques require x86/x64 architecture (INT instruction
     * and EFLAGS register) and SEH support (Windows only).
     * They work on all Windows versions.
     */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────────── */

TEKTON_MODULE tekton_mod_antidebug_trap = {
    .name           = "antidebug_trap",
    .description    = "INT 2D / trap flag debugger detection via SEH (Cat 8.5)",
    .category       = TEKTON_CAT_ANTIDEBUG,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_NONE,
    .skill_ref      = "8.5",
    .init           = trap_init,
    .execute        = trap_execute,
    .cleanup        = trap_cleanup,
    .get_risk_score = trap_risk_score,
    .check_compat   = trap_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_antidebug_trap);
