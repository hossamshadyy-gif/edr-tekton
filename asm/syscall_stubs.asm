;
; edr-tekton :: x64 Syscall Stubs (MASM / ml64)
; github.com/hayman-eng/edr-tekton
;
; Provides two families of stubs:
;
;   1. DIRECT stubs: execute the `syscall` instruction inline.
;      The return address on the call stack points into this module,
;      not ntdll.  Fast, simple, but stack-frame analysis will flag
;      the non-ntdll caller.
;
;   2. INDIRECT stub (TektonIndirectSyscallStub): JMPs to a
;      `syscall; ret` gadget inside ntdll or win32u so the return
;      address in the stack points back to a legitimate DLL.
;
; Windows x64 syscall convention:
;   - RCX holds the first argument, but the kernel expects it in R10.
;   - EAX holds the System Service Number (SSN).
;   - Remaining args go in RDX, R8, R9, and the shadow stack.
;
; SSN values are written as 0 (placeholder) and patched at runtime
; by the SSN resolver (ssn_resolve.c) before any stub is called.
;
; Build with:  ml64 /c /Fo syscall_stubs.obj syscall_stubs.asm
;

; =====================================================================
; Exported symbols visible to the C linker
; =====================================================================
PUBLIC TektonSyscallStub
PUBLIC TektonIndirectSyscallStub

PUBLIC TektonNtAllocateVirtualMemoryStub
PUBLIC TektonNtWriteVirtualMemoryStub
PUBLIC TektonNtProtectVirtualMemoryStub
PUBLIC TektonNtCreateThreadExStub
PUBLIC TektonNtOpenProcessStub
PUBLIC TektonNtCloseStub
PUBLIC TektonNtFreeVirtualMemoryStub
PUBLIC TektonNtQueueApcThreadStub
PUBLIC TektonNtCreateSectionStub
PUBLIC TektonNtMapViewOfSectionStub
PUBLIC TektonNtUnmapViewOfSectionStub
PUBLIC TektonNtWaitForSingleObjectStub
PUBLIC TektonNtDelayExecutionStub
PUBLIC TektonNtQueryInformationProcessStub
PUBLIC TektonNtSetInformationThreadStub
PUBLIC TektonNtSuspendThreadStub
PUBLIC TektonNtResumeThreadStub
PUBLIC TektonNtQuerySystemInformationStub

; =====================================================================
; Data section: SSN slots and the indirect gadget address.
; These are written at runtime by the C-side SSN resolver before any
; stub is called.  Keeping them in .data avoids the need to VirtualProtect
; the code section.
; =====================================================================
.data

; Indirect syscall gadget address (patched at runtime by the resolver)
; Points to a `syscall; ret` (0F 05 C3) sequence inside ntdll or win32u.
TektonSyscallGadgetAddr  DQ 0    ; patched at runtime

; Per-function SSN slots (DWORD each, zero until patched)
ssnNtAllocateVirtualMemory       DD 0   ; patched at runtime by SSN resolver
ssnNtWriteVirtualMemory          DD 0   ; patched at runtime by SSN resolver
ssnNtProtectVirtualMemory        DD 0   ; patched at runtime by SSN resolver
ssnNtCreateThreadEx              DD 0   ; patched at runtime by SSN resolver
ssnNtOpenProcess                 DD 0   ; patched at runtime by SSN resolver
ssnNtClose                       DD 0   ; patched at runtime by SSN resolver
ssnNtFreeVirtualMemory           DD 0   ; patched at runtime by SSN resolver
ssnNtQueueApcThread              DD 0   ; patched at runtime by SSN resolver
ssnNtCreateSection               DD 0   ; patched at runtime by SSN resolver
ssnNtMapViewOfSection            DD 0   ; patched at runtime by SSN resolver
ssnNtUnmapViewOfSection          DD 0   ; patched at runtime by SSN resolver
ssnNtWaitForSingleObject         DD 0   ; patched at runtime by SSN resolver
ssnNtDelayExecution              DD 0   ; patched at runtime by SSN resolver
ssnNtQueryInformationProcess     DD 0   ; patched at runtime by SSN resolver
ssnNtSetInformationThread        DD 0   ; patched at runtime by SSN resolver
ssnNtSuspendThread               DD 0   ; patched at runtime by SSN resolver
ssnNtResumeThread                DD 0   ; patched at runtime by SSN resolver
ssnNtQuerySystemInformation      DD 0   ; patched at runtime by SSN resolver

; =====================================================================
; Code section
; =====================================================================
.code

; ---------------------------------------------------------------------
; TektonSyscallStub - Generic direct syscall
;
; Call from C as:
;   extern NTSTATUS TektonSyscallStub(void);
;
; Before calling, the SSN must be placed in EAX and all Windows x64
; calling convention registers set up by the caller.  This is typically
; invoked through a C wrapper that does:
;   mov eax, <ssn>
;   mov r10, rcx        (already done by each named stub below)
;   call TektonSyscallStub
;
; In practice the named stubs below are preferred; this exists as a
; generic fallback for dynamically-dispatched SSNs.
; ---------------------------------------------------------------------
TektonSyscallStub PROC
    mov     r10, rcx            ; Windows kernel ABI: 1st arg goes in R10
    syscall                     ; Transition to kernel
    ret
TektonSyscallStub ENDP

; ---------------------------------------------------------------------
; TektonIndirectSyscallStub - Indirect syscall via gadget JMP
;
; Instead of executing `syscall` inline (which leaves our module's
; address in the call stack), this stub JMPs to a legitimate
; `syscall; ret` gadget located in ntdll or win32u .text section.
;
; The gadget address must be stored in TektonSyscallGadgetAddr before
; calling.  The SSN must already be in EAX.
;
; Stack effect: when the `syscall; ret` inside ntdll executes, the
; return address points back to ntdll, satisfying stack-frame analysis.
;
; Call from C as:
;   mov eax, ssn
;   mov r10, rcx
;   call TektonIndirectSyscallStub
; ---------------------------------------------------------------------
TektonIndirectSyscallStub PROC
    mov     r10, rcx                        ; 1st arg -> R10 for kernel
    mov     rax, [TektonSyscallGadgetAddr]  ; Load gadget address
    jmp     rax                             ; JMP to `syscall; ret` in ntdll
    ; Control does not return here; the `ret` in the gadget returns
    ; to our caller directly.
TektonIndirectSyscallStub ENDP

; =====================================================================
; Named Direct Syscall Stubs
;
; Each stub follows the same pattern:
;   1. mov r10, rcx       Save first arg for the kernel (Windows ABI)
;   2. mov eax, <SSN>     Load the syscall number from .data
;   3. syscall             Enter kernel mode
;   4. ret                 Return NTSTATUS to caller
;
; The SSN slots (ssnNt*) are zero-initialized and patched at runtime
; by the SSN resolver.  Calling a stub before patching yields SSN 0,
; which is NtAccessCheck on most Windows builds, so the resolver
; MUST run first.
;
; The stubs preserve the Windows x64 calling convention: RCX, RDX,
; R8, R9 carry the first four arguments, additional args on stack.
; The `mov r10, rcx` instruction moves the first argument to R10,
; which is where the Windows kernel reads it from.
; =====================================================================

; --- NtAllocateVirtualMemory ---
; Allocate or reserve virtual memory in a process.
; RCX=ProcessHandle, RDX=*BaseAddress, R8=ZeroBits,
; R9=*RegionSize, stack=AllocationType, Protect
TektonNtAllocateVirtualMemoryStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtAllocateVirtualMemory]    ; patched at runtime
    syscall
    ret
TektonNtAllocateVirtualMemoryStub ENDP

; --- NtWriteVirtualMemory ---
; Write data into a process's address space.
; RCX=ProcessHandle, RDX=BaseAddress, R8=Buffer,
; R9=NumberOfBytesToWrite, stack=*NumberOfBytesWritten
TektonNtWriteVirtualMemoryStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtWriteVirtualMemory]       ; patched at runtime
    syscall
    ret
TektonNtWriteVirtualMemoryStub ENDP

; --- NtProtectVirtualMemory ---
; Change memory protection flags.
; RCX=ProcessHandle, RDX=*BaseAddress, R8=*RegionSize,
; R9=NewProtect, stack=*OldProtect
TektonNtProtectVirtualMemoryStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtProtectVirtualMemory]     ; patched at runtime
    syscall
    ret
TektonNtProtectVirtualMemoryStub ENDP

; --- NtCreateThreadEx ---
; Create a new thread in a process (11 parameters, 7 on stack).
; RCX=*ThreadHandle, RDX=DesiredAccess, R8=ObjectAttributes,
; R9=ProcessHandle, stack=StartRoutine, Argument, CreateFlags,
;    ZeroBits, StackSize, MaximumStackSize, AttributeList
TektonNtCreateThreadExStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtCreateThreadEx]            ; patched at runtime
    syscall
    ret
TektonNtCreateThreadExStub ENDP

; --- NtOpenProcess ---
; Open a handle to an existing process.
; RCX=*ProcessHandle, RDX=DesiredAccess, R8=ObjectAttributes,
; R9=ClientId
TektonNtOpenProcessStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtOpenProcess]               ; patched at runtime
    syscall
    ret
TektonNtOpenProcessStub ENDP

; --- NtClose ---
; Close a kernel object handle.
; RCX=Handle
TektonNtCloseStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtClose]                     ; patched at runtime
    syscall
    ret
TektonNtCloseStub ENDP

; --- NtFreeVirtualMemory ---
; Release or decommit virtual memory.
; RCX=ProcessHandle, RDX=*BaseAddress, R8=*RegionSize,
; R9=FreeType
TektonNtFreeVirtualMemoryStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtFreeVirtualMemory]         ; patched at runtime
    syscall
    ret
TektonNtFreeVirtualMemoryStub ENDP

; --- NtQueueApcThread ---
; Queue an APC to a thread (used in early-bird / APC injection).
; RCX=ThreadHandle, RDX=ApcRoutine, R8=ApcArgument1,
; R9=ApcArgument2, stack=ApcArgument3
TektonNtQueueApcThreadStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtQueueApcThread]            ; patched at runtime
    syscall
    ret
TektonNtQueueApcThreadStub ENDP

; --- NtCreateSection ---
; Create a section object (for section-based injection / mapping).
; RCX=*SectionHandle, RDX=DesiredAccess, R8=ObjectAttributes,
; R9=MaximumSize, stack=SectionPageProtection, AllocationAttributes, FileHandle
TektonNtCreateSectionStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtCreateSection]             ; patched at runtime
    syscall
    ret
TektonNtCreateSectionStub ENDP

; --- NtMapViewOfSection ---
; Map a section into a process (10 parameters, 6 on stack).
; RCX=SectionHandle, RDX=ProcessHandle, R8=*BaseAddress,
; R9=ZeroBits, stack=CommitSize, SectionOffset, *ViewSize,
;    InheritDisposition, AllocationType, Win32Protect
TektonNtMapViewOfSectionStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtMapViewOfSection]          ; patched at runtime
    syscall
    ret
TektonNtMapViewOfSectionStub ENDP

; --- NtUnmapViewOfSection ---
; Unmap a previously mapped section view.
; RCX=ProcessHandle, RDX=BaseAddress
TektonNtUnmapViewOfSectionStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtUnmapViewOfSection]        ; patched at runtime
    syscall
    ret
TektonNtUnmapViewOfSectionStub ENDP

; --- NtWaitForSingleObject ---
; Wait on a kernel object (handle, event, mutex, etc.).
; RCX=Handle, RDX=Alertable, R8=Timeout
TektonNtWaitForSingleObjectStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtWaitForSingleObject]       ; patched at runtime
    syscall
    ret
TektonNtWaitForSingleObjectStub ENDP

; --- NtDelayExecution ---
; Sleep the current thread (replaces Sleep / SleepEx).
; RCX=Alertable, RDX=DelayInterval
TektonNtDelayExecutionStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtDelayExecution]            ; patched at runtime
    syscall
    ret
TektonNtDelayExecutionStub ENDP

; --- NtQueryInformationProcess ---
; Query process information (PEB address, debug port, etc.).
; RCX=ProcessHandle, RDX=ProcessInformationClass,
; R8=ProcessInformation, R9=ProcessInformationLength,
; stack=ReturnLength
TektonNtQueryInformationProcessStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtQueryInformationProcess]   ; patched at runtime
    syscall
    ret
TektonNtQueryInformationProcessStub ENDP

; --- NtSetInformationThread ---
; Set thread information (hide thread from debugger via
; ThreadHideFromDebugger, etc.).
; RCX=ThreadHandle, RDX=ThreadInformationClass,
; R8=ThreadInformation, R9=ThreadInformationLength
TektonNtSetInformationThreadStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtSetInformationThread]      ; patched at runtime
    syscall
    ret
TektonNtSetInformationThreadStub ENDP

; --- NtSuspendThread ---
; Suspend a thread (used in process hollowing, thread hijacking).
; RCX=ThreadHandle, RDX=PreviousSuspendCount
TektonNtSuspendThreadStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtSuspendThread]             ; patched at runtime
    syscall
    ret
TektonNtSuspendThreadStub ENDP

; --- NtResumeThread ---
; Resume a suspended thread.
; RCX=ThreadHandle, RDX=PreviousSuspendCount
TektonNtResumeThreadStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtResumeThread]              ; patched at runtime
    syscall
    ret
TektonNtResumeThreadStub ENDP

; --- NtQuerySystemInformation ---
; Query system-wide information (process list, handle list, etc.).
; RCX=SystemInformationClass, RDX=SystemInformation,
; R8=SystemInformationLength, R9=ReturnLength
TektonNtQuerySystemInformationStub PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [ssnNtQuerySystemInformation]    ; patched at runtime
    syscall
    ret
TektonNtQuerySystemInformationStub ENDP

END
