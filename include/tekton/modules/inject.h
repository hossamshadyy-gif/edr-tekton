#ifndef TEKTON_MOD_INJECT_H
#define TEKTON_MOD_INJECT_H

/*
 * edr-tekton :: Injection Modules
 * Cat 4: Classic injection
 * Cat 5: APC, threadless, module stomping
 * Cat 46: PoolParty thread pool variants
 */

#include "../core/module.h"

/* ── Available Injection Modules ──────────────────────── */

/* Cat 4: Classic remote injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) */
extern TEKTON_MODULE tekton_mod_inject_classic;

/* Cat 5: Early Bird APC injection */
extern TEKTON_MODULE tekton_mod_inject_apc;

/* Cat 5.x: Threadless injection via function pointer hijack */
extern TEKTON_MODULE tekton_mod_inject_threadless;

/* Cat 5.x: Module stomping (overwrite legitimate DLL .text) */
extern TEKTON_MODULE tekton_mod_inject_module_stomp;

/* Cat 4.x: Callback-based execution (EnumWindows, etc) */
extern TEKTON_MODULE tekton_mod_inject_callback;

/* Cat 46.1: PoolParty - Worker factory start routine */
extern TEKTON_MODULE tekton_mod_inject_poolparty_worker;

/* Cat 46.2: PoolParty - TP_WORK work item insertion */
extern TEKTON_MODULE tekton_mod_inject_poolparty_work;

/* Cat 46.3: PoolParty - TP_WAIT wait completion */
extern TEKTON_MODULE tekton_mod_inject_poolparty_wait;

/* Cat 46.5: PoolParty - TP_IO I/O completion */
extern TEKTON_MODULE tekton_mod_inject_poolparty_io;

/* Cat 46.7: PoolParty - TP_TIMER timer expiry */
extern TEKTON_MODULE tekton_mod_inject_poolparty_timer;

/* ── Injection Configuration ──────────────────────────── */

typedef struct _TEKTON_INJECT_CFG {
    char        target_process[256];    /* "explorer.exe", "svchost.exe" */
    DWORD       target_pid;             /* Specific PID (0 = find by name) */
    BOOL        create_suspended;       /* Create process in suspended state */
    char        spawn_process[512];     /* Process to spawn for injection */
    BOOL        use_syscalls;           /* Use syscall engine for injection APIs */
    DWORD       allocation_type;        /* MEM_COMMIT | MEM_RESERVE */
} TEKTON_INJECT_CFG, *PTEKTON_INJECT_CFG;

/* ── Process Utilities ────────────────────────────────── */

/* Find PID by process name */
DWORD TektonInjectFindProcess(
    PTEKTON_CONTEXT ctx,
    const char*     process_name
);

/* Open handle to target process */
TEKTON_STATUS TektonInjectOpenTarget(
    PTEKTON_CONTEXT ctx,
    DWORD           pid,
    DWORD           desired_access
);

/* Allocate memory in target process */
TEKTON_STATUS TektonInjectAllocRemote(
    PTEKTON_CONTEXT ctx,
    SIZE_T          size,
    DWORD           protect
);

/* Write payload to allocated region */
TEKTON_STATUS TektonInjectWriteRemote(
    PTEKTON_CONTEXT ctx,
    const BYTE*     data,
    SIZE_T          size
);

#endif /* TEKTON_MOD_INJECT_H */
