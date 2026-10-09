;
; edr-tekton :: x64 Syscall Stubs (NASM / MinGW / GCC)
; github.com/hayman-eng/edr-tekton
;
; NASM equivalent of syscall_stubs.asm for cross-compilation with
; MinGW-w64 or GCC targeting Windows x64.
;
; Windows x64 syscall convention:
;   - RCX holds the first argument, kernel expects it in R10.
;   - EAX holds the System Service Number (SSN).
;   - Remaining args in RDX, R8, R9, and shadow stack space.
;
; SSN slots live in the .data section as DWORD (dd) values, patched
; at runtime by the SSN resolver before any stub is called.
;
; Build with:
;   nasm -f win64 -o syscall_stubs_nasm.obj syscall_stubs_nasm.asm
;   (or -f elf64 for ELF targets used in cross-compilation tooling)
;
; Link the resulting .obj alongside the C objects.
;

; =====================================================================
; Data section: SSN slots and indirect gadget address
; =====================================================================
section .data

; Indirect syscall gadget address (QWORD, patched at runtime).
; Points to a `syscall; ret` (0F 05 C3) sequence in ntdll or win32u.
global TektonSyscallGadgetAddr
TektonSyscallGadgetAddr:    dq 0        ; patched at runtime

; Per-function SSN slots (DWORD each, zero until patched).
global ssnNtAllocateVirtualMemory
global ssnNtWriteVirtualMemory
global ssnNtProtectVirtualMemory
global ssnNtCreateThreadEx
global ssnNtOpenProcess
global ssnNtClose
global ssnNtFreeVirtualMemory
global ssnNtQueueApcThread
global ssnNtCreateSection
global ssnNtMapViewOfSection
global ssnNtUnmapViewOfSection
global ssnNtWaitForSingleObject
global ssnNtDelayExecution
global ssnNtQueryInformationProcess
global ssnNtSetInformationThread
global ssnNtSuspendThread
global ssnNtResumeThread
global ssnNtQuerySystemInformation

ssnNtAllocateVirtualMemory:     dd 0    ; patched at runtime by SSN resolver
ssnNtWriteVirtualMemory:        dd 0    ; patched at runtime by SSN resolver
ssnNtProtectVirtualMemory:      dd 0    ; patched at runtime by SSN resolver
ssnNtCreateThreadEx:            dd 0    ; patched at runtime by SSN resolver
ssnNtOpenProcess:               dd 0    ; patched at runtime by SSN resolver
ssnNtClose:                     dd 0    ; patched at runtime by SSN resolver
ssnNtFreeVirtualMemory:         dd 0    ; patched at runtime by SSN resolver
ssnNtQueueApcThread:            dd 0    ; patched at runtime by SSN resolver
ssnNtCreateSection:             dd 0    ; patched at runtime by SSN resolver
ssnNtMapViewOfSection:          dd 0    ; patched at runtime by SSN resolver
ssnNtUnmapViewOfSection:        dd 0    ; patched at runtime by SSN resolver
ssnNtWaitForSingleObject:      dd 0    ; patched at runtime by SSN resolver
ssnNtDelayExecution:            dd 0    ; patched at runtime by SSN resolver
ssnNtQueryInformationProcess:   dd 0    ; patched at runtime by SSN resolver
ssnNtSetInformationThread:      dd 0    ; patched at runtime by SSN resolver
ssnNtSuspendThread:             dd 0    ; patched at runtime by SSN resolver
ssnNtResumeThread:              dd 0    ; patched at runtime by SSN resolver
ssnNtQuerySystemInformation:    dd 0    ; patched at runtime by SSN resolver

; =====================================================================
; Code section
; =====================================================================
section .text

; Export all stub symbols for the C linker.
global TektonSyscallStub
global TektonIndirectSyscallStub

global TektonNtAllocateVirtualMemoryStub
global TektonNtWriteVirtualMemoryStub
global TektonNtProtectVirtualMemoryStub
global TektonNtCreateThreadExStub
global TektonNtOpenProcessStub
global TektonNtCloseStub
global TektonNtFreeVirtualMemoryStub
global TektonNtQueueApcThreadStub
global TektonNtCreateSectionStub
global TektonNtMapViewOfSectionStub
global TektonNtUnmapViewOfSectionStub
global TektonNtWaitForSingleObjectStub
global TektonNtDelayExecutionStub
global TektonNtQueryInformationProcessStub
global TektonNtSetInformationThreadStub
global TektonNtSuspendThreadStub
global TektonNtResumeThreadStub
global TektonNtQuerySystemInformationStub

; ---------------------------------------------------------------------
; TektonSyscallStub - Generic direct syscall
;
; The caller places the SSN in EAX and sets up args per x64 convention.
; This stub moves RCX -> R10 (kernel ABI) and executes syscall inline.
; ---------------------------------------------------------------------
TektonSyscallStub:
    mov     r10, rcx            ; 1st arg: RCX -> R10 for kernel
    syscall                     ; Enter kernel mode
    ret

; ---------------------------------------------------------------------
; TektonIndirectSyscallStub - Indirect syscall via gadget JMP
;
; Reads the gadget address from TektonSyscallGadgetAddr and JMPs to it.
; The gadget is a `syscall; ret` sequence inside ntdll or win32u, so
; the return address on the stack points to legitimate OS code.
;
; EAX must already contain the SSN before calling.
; ---------------------------------------------------------------------
TektonIndirectSyscallStub:
    mov     r10, rcx                                ; 1st arg -> R10
    mov     rax, qword [rel TektonSyscallGadgetAddr] ; Load gadget ptr
    jmp     rax                                     ; JMP to syscall;ret
    ; The `ret` in the gadget returns directly to our caller.

; =====================================================================
; Named Direct Syscall Stubs
;
; Each follows the same pattern:
;   1. mov r10, rcx         (Windows kernel ABI, 1st arg in R10)
;   2. mov eax, [ssnXxx]    (load runtime-patched SSN)
;   3. syscall               (enter kernel)
;   4. ret                   (return NTSTATUS)
;
; The `rel` prefix enables RIP-relative addressing, which is the
; default for x64 position-independent code under NASM/win64.
; =====================================================================

; --- NtAllocateVirtualMemory ---
; RCX=ProcessHandle, RDX=*BaseAddress, R8=ZeroBits,
; R9=*RegionSize, stack=AllocationType, Protect
TektonNtAllocateVirtualMemoryStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtAllocateVirtualMemory]
    syscall
    ret

; --- NtWriteVirtualMemory ---
; RCX=ProcessHandle, RDX=BaseAddress, R8=Buffer,
; R9=NumberOfBytesToWrite, stack=*NumberOfBytesWritten
TektonNtWriteVirtualMemoryStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtWriteVirtualMemory]
    syscall
    ret

; --- NtProtectVirtualMemory ---
; RCX=ProcessHandle, RDX=*BaseAddress, R8=*RegionSize,
; R9=NewProtect, stack=*OldProtect
TektonNtProtectVirtualMemoryStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtProtectVirtualMemory]
    syscall
    ret

; --- NtCreateThreadEx ---
; 11 parameters. RCX=*ThreadHandle, RDX=DesiredAccess,
; R8=ObjectAttributes, R9=ProcessHandle, rest on stack.
TektonNtCreateThreadExStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtCreateThreadEx]
    syscall
    ret

; --- NtOpenProcess ---
; RCX=*ProcessHandle, RDX=DesiredAccess, R8=ObjectAttributes,
; R9=ClientId
TektonNtOpenProcessStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtOpenProcess]
    syscall
    ret

; --- NtClose ---
; RCX=Handle
TektonNtCloseStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtClose]
    syscall
    ret

; --- NtFreeVirtualMemory ---
; RCX=ProcessHandle, RDX=*BaseAddress, R8=*RegionSize, R9=FreeType
TektonNtFreeVirtualMemoryStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtFreeVirtualMemory]
    syscall
    ret

; --- NtQueueApcThread ---
; RCX=ThreadHandle, RDX=ApcRoutine, R8=ApcArgument1,
; R9=ApcArgument2, stack=ApcArgument3
TektonNtQueueApcThreadStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtQueueApcThread]
    syscall
    ret

; --- NtCreateSection ---
; RCX=*SectionHandle, RDX=DesiredAccess, R8=ObjectAttributes,
; R9=MaximumSize, stack=SectionPageProtection, AllocationAttributes, FileHandle
TektonNtCreateSectionStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtCreateSection]
    syscall
    ret

; --- NtMapViewOfSection ---
; 10 parameters. RCX=SectionHandle, RDX=ProcessHandle,
; R8=*BaseAddress, R9=ZeroBits, rest on stack.
TektonNtMapViewOfSectionStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtMapViewOfSection]
    syscall
    ret

; --- NtUnmapViewOfSection ---
; RCX=ProcessHandle, RDX=BaseAddress
TektonNtUnmapViewOfSectionStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtUnmapViewOfSection]
    syscall
    ret

; --- NtWaitForSingleObject ---
; RCX=Handle, RDX=Alertable, R8=Timeout
TektonNtWaitForSingleObjectStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtWaitForSingleObject]
    syscall
    ret

; --- NtDelayExecution ---
; RCX=Alertable, RDX=DelayInterval
TektonNtDelayExecutionStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtDelayExecution]
    syscall
    ret

; --- NtQueryInformationProcess ---
; RCX=ProcessHandle, RDX=ProcessInformationClass,
; R8=ProcessInformation, R9=ProcessInformationLength,
; stack=ReturnLength
TektonNtQueryInformationProcessStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtQueryInformationProcess]
    syscall
    ret

; --- NtSetInformationThread ---
; RCX=ThreadHandle, RDX=ThreadInformationClass,
; R8=ThreadInformation, R9=ThreadInformationLength
TektonNtSetInformationThreadStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtSetInformationThread]
    syscall
    ret

; --- NtSuspendThread ---
; RCX=ThreadHandle, RDX=PreviousSuspendCount
TektonNtSuspendThreadStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtSuspendThread]
    syscall
    ret

; --- NtResumeThread ---
; RCX=ThreadHandle, RDX=PreviousSuspendCount
TektonNtResumeThreadStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtResumeThread]
    syscall
    ret

; --- NtQuerySystemInformation ---
; RCX=SystemInformationClass, RDX=SystemInformation,
; R8=SystemInformationLength, R9=ReturnLength
TektonNtQuerySystemInformationStub:
    mov     r10, rcx
    mov     eax, dword [rel ssnNtQuerySystemInformation]
    syscall
    ret
