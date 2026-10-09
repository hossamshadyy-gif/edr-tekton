#ifndef TEKTON_MOD_ANTIDEBUG_H
#define TEKTON_MOD_ANTIDEBUG_H

/*
 * edr-tekton :: Anti-Debug Modules
 * Cat 8: Detect debuggers before payload execution
 *
 * Techniques:
 *   8.1  PEB.BeingDebugged + NtGlobalFlag
 *   8.2  RDTSC / QueryPerformanceCounter timing checks
 *   8.3  NtQueryInformationProcess (DebugPort, DebugObjectHandle, DebugFlags)
 *   8.4  Hardware breakpoint detection via debug registers (Dr0-Dr3)
 *   8.5  INT 2D / trap flag detection via SEH
 */

#include "../core/module.h"

/* ── Available Anti-Debug Modules ────────────────────────── */

/* Cat 8.1: PEB.BeingDebugged + NtGlobalFlag check */
extern TEKTON_MODULE tekton_mod_antidebug_peb;

/* Cat 8.2: RDTSC / QPC timing-based debugger detection */
extern TEKTON_MODULE tekton_mod_antidebug_timing;

/* Cat 8.3: NtQueryInformationProcess debug queries */
extern TEKTON_MODULE tekton_mod_antidebug_ntquery;

/* Cat 8.4: Hardware breakpoint detection (Dr0-Dr3) */
extern TEKTON_MODULE tekton_mod_antidebug_hwbp;

/* Cat 8.5: INT 2D / trap flag detection via SEH */
extern TEKTON_MODULE tekton_mod_antidebug_trap;

/* ── Anti-Debug Configuration ────────────────────────────── */

typedef enum _TEKTON_ANTIDEBUG_ACTION {
    TEKTON_ANTIDEBUG_ABORT      = 0,    /* Abort pipeline on detection  */
    TEKTON_ANTIDEBUG_EVADE      = 1,    /* Attempt to clear debug state */
    TEKTON_ANTIDEBUG_CONTINUE   = 2,    /* Log and continue             */
} TEKTON_ANTIDEBUG_ACTION;

typedef struct _TEKTON_ANTIDEBUG_CFG {
    TEKTON_ANTIDEBUG_ACTION on_detect;      /* What to do when debugger found */
    DWORD   timing_threshold_ticks;         /* RDTSC delta threshold          */
    DWORD   timing_threshold_qpc_ms;        /* QPC elapsed-time threshold     */
    BOOL    check_peb_being_debugged;       /* 8.1: BeingDebugged flag        */
    BOOL    check_peb_nt_global_flag;       /* 8.1: NtGlobalFlag (0x70)       */
    BOOL    check_debug_port;               /* 8.3: ProcessDebugPort          */
    BOOL    check_debug_object_handle;      /* 8.3: ProcessDebugObjectHandle  */
    BOOL    check_debug_flags;              /* 8.3: ProcessDebugFlags         */
} TEKTON_ANTIDEBUG_CFG, *PTEKTON_ANTIDEBUG_CFG;

#endif /* TEKTON_MOD_ANTIDEBUG_H */
