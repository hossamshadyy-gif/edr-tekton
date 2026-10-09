/*
 * edr-tekton :: Timing-Based Anti-Debug (Cat 8.2)
 * Detect debuggers via RDTSC delta and QueryPerformanceCounter
 *
 * When a debugger single-steps through code or sets software
 * breakpoints, each instruction takes orders of magnitude longer
 * than on bare hardware. Two timing techniques exploit this:
 *
 *   1. RDTSC (Read Time-Stamp Counter): Execute __rdtsc() before
 *      and after a short instruction sequence. On bare metal the
 *      delta is typically < 1000 cycles. Under a debugger (single-
 *      stepping, breakpoints, or instruction-level tracing) the
 *      delta easily exceeds 0x10000 cycles.
 *
 *   2. QueryPerformanceCounter: Bracket a Sleep(1) or small
 *      computation with QPC reads. Under a debugger, wall-clock
 *      time spent is dramatically larger than the requested delay,
 *      because the debugger pauses between instructions.
 *
 * Both techniques are passive reads of CPU/OS timers and generate
 * no detectable events. However, sophisticated debuggers (ScyllaHide,
 * TitanHide) hook RDTSC via VEH or hypervisor-level TSC offsetting,
 * so this should be one check among several.
 *
 * Risk: 10. RDTSC is a normal instruction, but repeated use of
 * timing checks in a tight loop can be signature-matched by static
 * analysis tools.
 */

#include "tekton/modules/antidebug.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Thresholds ────────────────────────────────────────────── */

#define RDTSC_THRESHOLD         0x10000     /* ~65536 cycles        */
#define QPC_THRESHOLD_MS        100         /* 100ms for a 1ms op   */

/* ── Internal state ────────────────────────────────────────── */

typedef struct _TIMING_STATE {
    DWORD   rdtsc_threshold;
    DWORD   qpc_threshold_ms;
    BOOL    rdtsc_detected;
    BOOL    qpc_detected;
    BOOL    detected;
} TIMING_STATE;

/* ── Module vtable implementation ──────────────────────────── */

static TEKTON_STATUS timing_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    TIMING_STATE* state = (TIMING_STATE*)malloc(sizeof(TIMING_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->rdtsc_threshold = RDTSC_THRESHOLD;
    state->qpc_threshold_ms = QPC_THRESHOLD_MS;

    self->private_data = state;

    TLOG_DEBUG("antidebug_timing: init (rdtsc_thresh=0x%lX, qpc_thresh=%lu ms)",
        (unsigned long)state->rdtsc_threshold,
        (unsigned long)state->qpc_threshold_ms);
    return TEKTON_OK;
}

static TEKTON_STATUS timing_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    TIMING_STATE* state = (TIMING_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("antidebug_timing: [DRY RUN] would check RDTSC + QPC timing");
        return TEKTON_OK;
    }

#ifdef _WIN32
    /* ── Check 1: RDTSC delta across a NOP sled ──────── */
    {
        /*
         * Execute RDTSC, run a short NOP sled to give the debugger
         * something to instrument, then RDTSC again. The sled is
         * volatile-asm to prevent the compiler from optimizing it out.
         */
        unsigned long long tsc_start, tsc_end, tsc_delta;

        #ifdef _MSC_VER
            tsc_start = __rdtsc();

            /* NOP sled: 16 NOPs that a debugger must step through */
            __nop(); __nop(); __nop(); __nop();
            __nop(); __nop(); __nop(); __nop();
            __nop(); __nop(); __nop(); __nop();
            __nop(); __nop(); __nop(); __nop();

            tsc_end = __rdtsc();
        #else
            /* GCC/Clang inline assembly for RDTSC */
            unsigned int lo1, hi1, lo2, hi2;

            __asm__ __volatile__ ("rdtsc" : "=a"(lo1), "=d"(hi1));

            __asm__ __volatile__ (
                "nop\n\tnop\n\tnop\n\tnop\n\t"
                "nop\n\tnop\n\tnop\n\tnop\n\t"
                "nop\n\tnop\n\tnop\n\tnop\n\t"
                "nop\n\tnop\n\tnop\n\tnop"
                ::: "memory"
            );

            __asm__ __volatile__ ("rdtsc" : "=a"(lo2), "=d"(hi2));

            tsc_start = ((unsigned long long)hi1 << 32) | lo1;
            tsc_end   = ((unsigned long long)hi2 << 32) | lo2;
        #endif

        tsc_delta = tsc_end - tsc_start;

        TLOG_DEBUG("antidebug_timing: RDTSC delta = 0x%llX (%llu cycles)",
            (unsigned long long)tsc_delta, (unsigned long long)tsc_delta);

        if (tsc_delta > state->rdtsc_threshold) {
            state->rdtsc_detected = TRUE;
            TLOG_INFO("antidebug_timing: RDTSC anomaly, delta 0x%llX > threshold 0x%lX",
                (unsigned long long)tsc_delta, (unsigned long)state->rdtsc_threshold);
        }
    }

    /* ── Check 2: QueryPerformanceCounter timing ─────── */
    {
        /*
         * Bracket a brief Sleep(1) with QPC reads. On bare metal the
         * elapsed time is ~1-16ms (timer resolution). Under a debugger,
         * especially with single-stepping active, the wall-clock delta
         * is far larger because the debugger injects pauses.
         */
        typedef BOOL (WINAPI *pfnQPC)(LARGE_INTEGER*);
        typedef BOOL (WINAPI *pfnQPF)(LARGE_INTEGER*);

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pfnQPC pQPC = (pfnQPC)GetProcAddress(hKernel32, "QueryPerformanceCounter");
        pfnQPF pQPF = (pfnQPF)GetProcAddress(hKernel32, "QueryPerformanceFrequency");

        if (pQPC && pQPF) {
            LARGE_INTEGER freq, t1, t2;

            if (pQPF(&freq) && freq.QuadPart > 0) {
                pQPC(&t1);
                Sleep(1);
                pQPC(&t2);

                long long elapsed_ms = ((t2.QuadPart - t1.QuadPart) * 1000) / freq.QuadPart;

                TLOG_DEBUG("antidebug_timing: QPC delta = %lld ms for Sleep(1)",
                    (long long)elapsed_ms);

                if (elapsed_ms > (long long)state->qpc_threshold_ms) {
                    state->qpc_detected = TRUE;
                    TLOG_INFO("antidebug_timing: QPC anomaly, %lld ms > %lu ms threshold",
                        (long long)elapsed_ms, (unsigned long)state->qpc_threshold_ms);
                }
            }
        } else {
            TLOG_WARN("antidebug_timing: QPC/QPF not resolved, skipping QPC check");
        }
    }

    /* ── Final decision ──────────────────────────────── */
    state->detected = state->rdtsc_detected || state->qpc_detected;

    if (state->detected) {
        TLOG_INFO("antidebug_timing: DEBUGGER DETECTED (rdtsc=%d, qpc=%d)",
            state->rdtsc_detected, state->qpc_detected);
        return TEKTON_ERR_COMPAT_FAIL;
    }

    TLOG_INFO("antidebug_timing: no timing anomalies detected");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    (void)state;
    TLOG_INFO("[DEV] antidebug_timing: skipped (non-Windows)");
    return TEKTON_OK;
#endif
}

static VOID timing_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(TIMING_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD timing_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low-moderate risk. RDTSC and QPC are normal instructions/APIs
     * used by every performance-sensitive application. However, the
     * pattern of back-to-back RDTSC with a NOP sled in between is
     * a known anti-debug signature in static analysis rules.
     */
    return 10;
}

static BOOL timing_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* RDTSC is available on all x86/x64 processors since Pentium */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────────── */

TEKTON_MODULE tekton_mod_antidebug_timing = {
    .name           = "antidebug_timing",
    .description    = "RDTSC + QPC timing-based debugger detection (Cat 8.2)",
    .category       = TEKTON_CAT_ANTIDEBUG,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "8.2",
    .init           = timing_init,
    .execute        = timing_execute,
    .cleanup        = timing_cleanup,
    .get_risk_score = timing_risk_score,
    .check_compat   = timing_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_antidebug_timing);
