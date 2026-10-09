#ifndef TEKTON_MOD_SYSCALL_H
#define TEKTON_MOD_SYSCALL_H

/*
 * edr-tekton :: Syscall Engine Modules
 * Cat 2: Direct/indirect syscalls
 * Cat 44: Call stack spoofing
 * Cat 45: Advanced SSN resolution
 */

#include "../core/module.h"

/* ── Available Syscall Modules ────────────────────────── */

/* Cat 2.1: Direct syscalls via MASM stubs */
extern TEKTON_MODULE tekton_mod_direct_syscall;

/* Cat 2.4: Indirect syscalls (JMP to ntdll gadget) */
extern TEKTON_MODULE tekton_mod_indirect_syscall;

/* Cat 2.14: Tampered syscalls via HW breakpoints */
extern TEKTON_MODULE tekton_mod_tampered_syscall;

/* Cat 2.5/2.6/2.13: ntdll unhooking variants */
extern TEKTON_MODULE tekton_mod_unhook_disk;
extern TEKTON_MODULE tekton_mod_unhook_suspended;
extern TEKTON_MODULE tekton_mod_unhook_knowndlls;

/* Cat 44.2: SilentMoonwalk call stack spoofing */
extern TEKTON_MODULE tekton_mod_callstack_spoof;

/* ── SSN Resolution Methods (Cat 2.2, 2.3, 45) ───────── */

typedef enum _TEKTON_SSN_METHOD {
    TEKTON_SSN_SORT         = 0,    /* Cat 2.2: Zw* sorting by RVA     */
    TEKTON_SSN_HELLS_GATE   = 1,    /* Cat 2.3: Read from stub bytes   */
    TEKTON_SSN_HALOS_GATE   = 2,    /* Cat 2.3: Neighbor stub fallback */
    TEKTON_SSN_FRESHYCALLS  = 3,    /* Cat 45.1: Hybrid sort+gate      */
    TEKTON_SSN_RECYCLED     = 4,    /* Cat 45.2: RecycledGate           */
    TEKTON_SSN_SYSWHISPERS4 = 5,    /* Cat 45.5: EGG hunting in .text  */
} TEKTON_SSN_METHOD;

/* ── Syscall Configuration ────────────────────────────── */

typedef struct _TEKTON_SYSCALL_CFG {
    TEKTON_SSN_METHOD   ssn_method;
    BOOL                use_indirect;       /* Execute syscall from ntdll    */
    BOOL                use_win32u;         /* Cat 2.12: win32u.dll gadgets  */
    BOOL                spoof_callstack;    /* Cat 44: Enable stack spoofing */
    BOOL                use_tampered;       /* Cat 2.14: HW breakpoint swap  */
    char                unhook_method[32];  /* "disk", "suspended", "knowndlls", "none" */
} TEKTON_SYSCALL_CFG, *PTEKTON_SYSCALL_CFG;

/* ── Syscall Invocation ───────────────────────────────── */

/*
 * Generic syscall wrapper. After the syscall module initializes,
 * all downstream modules call through this interface instead of
 * calling Nt* functions directly.
 */

/* Execute a syscall by SSN with up to 12 arguments */
NTSTATUS TektonSyscall(
    PTEKTON_CONTEXT ctx,
    DWORD           ssn,
    DWORD           arg_count,
    ...
);

/* Named syscall wrappers for common operations */
NTSTATUS TektonNtAllocateVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    SIZE_T          ZeroBits,
    PSIZE_T         RegionSize,
    DWORD           AllocationType,
    DWORD           Protect
);

NTSTATUS TektonNtWriteVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE          ProcessHandle,
    PVOID           BaseAddress,
    PVOID           Buffer,
    SIZE_T          NumberOfBytesToWrite,
    PSIZE_T         NumberOfBytesWritten
);

NTSTATUS TektonNtProtectVirtualMemory(
    PTEKTON_CONTEXT ctx,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    PSIZE_T         RegionSize,
    DWORD           NewProtect,
    DWORD*          OldProtect
);

NTSTATUS TektonNtCreateThreadEx(
    PTEKTON_CONTEXT ctx,
    HANDLE*         ThreadHandle,
    DWORD           DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartRoutine,
    PVOID           Argument,
    DWORD           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList
);

NTSTATUS TektonNtOpenProcess(
    PTEKTON_CONTEXT ctx,
    HANDLE*         ProcessHandle,
    DWORD           DesiredAccess,
    PVOID           ObjectAttributes,
    PVOID           ClientId
);

#endif /* TEKTON_MOD_SYSCALL_H */
