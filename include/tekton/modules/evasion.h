#ifndef TEKTON_MOD_EVASION_H
#define TEKTON_MOD_EVASION_H

/*
 * edr-tekton :: Evasion Modules
 * Cat 6: ETW blinding
 * Cat 7, 48: AMSI bypass
 * Cat 9: PPID spoofing
 * Cat 10: Anti-sandbox/analysis
 */

#include "../core/module.h"

/* ── Available Evasion Modules ────────────────────────── */

/* Cat 6.1: Patch EtwEventWrite (single-byte ret) */
extern TEKTON_MODULE tekton_mod_etw_patch;

/* Cat 6.x: ETW provider blinding (disable specific providers) */
extern TEKTON_MODULE tekton_mod_etw_blind;

/* Cat 7.1: Patch AmsiScanBuffer */
extern TEKTON_MODULE tekton_mod_amsi_patch;

/* Cat 48.1: CLR method hooking for managed AMSI bypass */
extern TEKTON_MODULE tekton_mod_amsi_clr;

/* Cat 9: Parent PID spoofing */
extern TEKTON_MODULE tekton_mod_ppid_spoof;

/* Cat 10: Anti-sandbox checks */
extern TEKTON_MODULE tekton_mod_sandbox_detect;

/* ── ETW Configuration ────────────────────────────────── */

typedef struct _TEKTON_ETW_CFG {
    BOOL    patch_etw_event_write;      /* Cat 6.1: Patch EtwEventWrite  */
    BOOL    blind_threat_intel;          /* Cat 6.x: Disable EtwTi       */
    BOOL    flush_trace_sessions;        /* Cat 6.x: Stop active traces  */
} TEKTON_ETW_CFG, *PTEKTON_ETW_CFG;

/* ── AMSI Configuration ───────────────────────────────── */

typedef enum _TEKTON_AMSI_METHOD {
    TEKTON_AMSI_PATCH_SCAN_BUFFER   = 0,    /* Cat 7.1 */
    TEKTON_AMSI_PATCH_OPEN_SESSION  = 1,    /* Cat 7.x */
    TEKTON_AMSI_CLR_HOOK            = 2,    /* Cat 48.1 */
    TEKTON_AMSI_HARDWARE_BP         = 3,    /* Cat 7.x: HW breakpoint */
} TEKTON_AMSI_METHOD;

typedef struct _TEKTON_AMSI_CFG {
    TEKTON_AMSI_METHOD  method;
    BOOL                target_clr;     /* Also hook CLR layer */
} TEKTON_AMSI_CFG, *PTEKTON_AMSI_CFG;

/* ── Sandbox Detection Configuration ──────────────────── */

typedef enum _TEKTON_SANDBOX_CHECK {
    TEKTON_SANDBOX_TIMING       = 0,    /* RDTSC timing anomalies  */
    TEKTON_SANDBOX_USERNAME     = 1,    /* Known sandbox usernames */
    TEKTON_SANDBOX_DISK_SIZE    = 2,    /* Small disk = sandbox    */
    TEKTON_SANDBOX_MAC_ADDR     = 3,    /* VM MAC prefixes         */
    TEKTON_SANDBOX_PROCESSES    = 4,    /* Analysis tool processes  */
    TEKTON_SANDBOX_REGISTRY     = 5,    /* VM registry keys        */
    TEKTON_SANDBOX_CPUID        = 6,    /* Hypervisor CPUID leaf   */
    TEKTON_SANDBOX_MOUSE        = 7,    /* No mouse movement       */
    TEKTON_SANDBOX_MAX          = 8,
} TEKTON_SANDBOX_CHECK;

typedef struct _TEKTON_SANDBOX_CFG {
    BOOL    checks[TEKTON_SANDBOX_MAX];
    DWORD   timing_threshold_ms;        /* Minimum RDTSC delta */
    BOOL    exit_on_detect;             /* Exit process if sandbox found */
    DWORD   sleep_before_check_ms;      /* Delay before sandbox checks */
} TEKTON_SANDBOX_CFG, *PTEKTON_SANDBOX_CFG;

/* ── PPID Spoofing Configuration ──────────────────────── */

typedef struct _TEKTON_PPID_CFG {
    char    parent_process[256];    /* "explorer.exe" */
    DWORD   parent_pid;             /* Specific PID (0 = find by name) */
} TEKTON_PPID_CFG, *PTEKTON_PPID_CFG;

#endif /* TEKTON_MOD_EVASION_H */
