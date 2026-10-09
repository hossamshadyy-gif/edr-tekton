/*
 * edr-tekton :: PEB-Based System Info Queries Module
 * Cat 1.5: Replace WinAPI system-info calls with direct PEB/TEB reads
 *
 * Replaces the following imports with PEB/TEB structure accesses:
 *
 *   GetTempPathW            -> PEB -> ProcessParameters -> Environment -> %TEMP%
 *   GetEnvironmentVariableW -> PEB -> ProcessParameters -> Environment block scan
 *   GetCurrentDirectoryW    -> PEB -> ProcessParameters -> CurrentDirectory.DosPath
 *   GetCommandLineW         -> PEB -> ProcessParameters -> CommandLine
 *   GetNumberOfProcessors   -> PEB -> NumberOfProcessors (offset 0xB8 on x64)
 *
 * Why: These WinAPI functions are commonly hooked by EDRs or appear in
 * import tables, providing indicators of suspicious binaries.  Reading
 * the data directly from the PEB avoids both the import and the hook.
 *
 * The PEB pointer is obtained via gs:[0x60] (x64) or fs:[0x30] (x86),
 * which is a TEB access that never touches any API.
 */

#include "tekton/modules/api_resolve.h"
#include "tekton/util/peb.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _PEB_SYSINFO_STATE {
    BOOL        initialized;
    PVOID       peb_ptr;            /* Cached PEB address                */
    DWORD       processor_count;    /* Cached processor count from PEB   */
} PEB_SYSINFO_STATE;

/* ── PEB offsets for x64 (used in Windows-specific code) ── */

/*
 * These offsets are stable across all x64 Windows releases (Vista+).
 * PEB structure at gs:[0x60]:
 *   +0x000  InheritedAddressSpace   (BYTE)
 *   +0x002  BeingDebugged           (BYTE)
 *   +0x010  ImageBaseAddress        (PVOID)
 *   +0x018  Ldr                     (PPEB_LDR_DATA)
 *   +0x020  ProcessParameters       (PRTL_USER_PROCESS_PARAMETERS)
 *   +0x0B8  NumberOfProcessors      (DWORD)
 *
 * RTL_USER_PROCESS_PARAMETERS:
 *   +0x010  CurrentDirectory.DosPath  (UNICODE_STRING)
 *   +0x020  DllPath                   (UNICODE_STRING)
 *   +0x030  ImagePathName             (UNICODE_STRING)
 *   +0x040  CommandLine               (UNICODE_STRING)
 *   +0x050  Environment               (PVOID, environment block)
 */

#ifdef _WIN32

/* ── Wide string helpers (avoiding wcslen/wcscpy imports) ── */

static SIZE_T psi_wcslen(const wchar_t* s) {
    SIZE_T len = 0;
    while (s[len]) len++;
    return len;
}

static int psi_wcsnicmp(const wchar_t* a, const wchar_t* b, SIZE_T count) {
    for (SIZE_T i = 0; i < count; i++) {
        wchar_t ca = a[i];
        wchar_t cb = b[i];
        /* Lowercase ASCII range only (sufficient for env var names) */
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return (int)(ca - cb);
        if (ca == L'\0') return 0;
    }
    return 0;
}

static void psi_wcscpy_safe(wchar_t* dst, const wchar_t* src, DWORD max_chars) {
    DWORD i = 0;
    while (src[i] && i < max_chars - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = L'\0';
}

/*
 * Scan the PEB environment block for a variable by name.
 * The environment block is a contiguous sequence of null-terminated
 * wide strings of the form "NAME=VALUE", terminated by a double-null.
 *
 * Returns TRUE and copies the value into out_buffer, or FALSE if not found.
 */
static BOOL psi_env_lookup(
    PVOID env_block,
    const wchar_t* var_name,
    wchar_t* out_buffer,
    DWORD buffer_chars
) {
    if (!env_block || !var_name || !out_buffer || buffer_chars == 0)
        return FALSE;

    SIZE_T name_len = psi_wcslen(var_name);
    const wchar_t* ptr = (const wchar_t*)env_block;

    while (*ptr != L'\0') {
        SIZE_T entry_len = psi_wcslen(ptr);

        /* Check if this entry starts with "NAME=" (case-insensitive) */
        if (entry_len > name_len + 1 && ptr[name_len] == L'=') {
            if (psi_wcsnicmp(ptr, var_name, name_len) == 0) {
                /* Found it: copy the value portion after the '=' */
                const wchar_t* value = ptr + name_len + 1;
                psi_wcscpy_safe(out_buffer, value, buffer_chars);
                return TRUE;
            }
        }

        /* Advance past this entry (including its null terminator) */
        ptr += entry_len + 1;
    }

    return FALSE;
}

#endif /* _WIN32 */

/* ── Module vtable implementation ──────────────────────── */

static TEKTON_STATUS peb_sysinfo_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    PEB_SYSINFO_STATE* state = (PEB_SYSINFO_STATE*)malloc(sizeof(PEB_SYSINFO_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("peb_sysinfo: init");
    return TEKTON_OK;
}

static TEKTON_STATUS peb_sysinfo_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    PEB_SYSINFO_STATE* state = (PEB_SYSINFO_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("peb_sysinfo: [DRY RUN] would read system info from PEB/TEB");
        return TEKTON_OK;
    }

#ifdef _WIN32
    /*
     * Step 1: Get the PEB pointer.
     * On x64: mov rax, gs:[0x60]
     * This is a TEB access that reads the PEB pointer from the TEB.
     */
    PVOID peb = TektonPebGet();
    if (!peb) {
        TLOG_ERROR("peb_sysinfo: failed to read PEB");
        return TEKTON_ERR_API_RESOLVE;
    }
    state->peb_ptr = peb;

    /*
     * Step 2: Read ProcessParameters from PEB.
     * PEB+0x20 on x64 = PRTL_USER_PROCESS_PARAMETERS.
     */
    PVOID proc_params = *(PVOID*)((BYTE*)peb + 0x20);
    if (!proc_params) {
        TLOG_ERROR("peb_sysinfo: PEB->ProcessParameters is NULL");
        return TEKTON_ERR_API_RESOLVE;
    }

    /*
     * Step 3: Read NumberOfProcessors from PEB.
     * PEB+0xB8 on x64 = DWORD NumberOfProcessors.
     */
    DWORD num_procs = *(DWORD*)((BYTE*)peb + 0xB8);
    state->processor_count = num_procs;

    TLOG_DEBUG("peb_sysinfo: PEB=%p, ProcessParameters=%p, CPUs=%lu",
        peb, proc_params, (unsigned long)num_procs);

    /*
     * Step 4: Read CurrentDirectory.DosPath (UNICODE_STRING at offset +0x10).
     * UNICODE_STRING layout: [WORD Length][WORD MaxLength][padding][PWSTR Buffer]
     * On x64 with padding, Buffer is at +0x08 from the start of the UNICODE_STRING.
     */
    WORD cur_dir_len    = *(WORD*)((BYTE*)proc_params + 0x10);
    LPWSTR cur_dir_buf  = *(LPWSTR*)((BYTE*)proc_params + 0x18);
    if (cur_dir_buf && cur_dir_len > 0) {
        TLOG_TRACE("peb_sysinfo: CurrentDirectory length = %u chars",
            (unsigned)(cur_dir_len / sizeof(wchar_t)));
    }

    /*
     * Step 5: Read CommandLine (UNICODE_STRING at offset +0x40 on x64).
     */
    WORD cmd_len    = *(WORD*)((BYTE*)proc_params + 0x40);
    LPWSTR cmd_buf  = *(LPWSTR*)((BYTE*)proc_params + 0x48);
    if (cmd_buf && cmd_len > 0) {
        TLOG_TRACE("peb_sysinfo: CommandLine length = %u chars",
            (unsigned)(cmd_len / sizeof(wchar_t)));
    }

    /*
     * Step 6: Read the Environment block pointer (offset +0x50 on x64).
     * The environment block is a dense array of L"NAME=VALUE\0" entries
     * terminated by a double null.
     */
    PVOID env_block = *(PVOID*)((BYTE*)proc_params + 0x50);

    if (env_block) {
        /* Verify we can read TEMP from the environment */
        wchar_t temp_path[260];
        memset(temp_path, 0, sizeof(temp_path));
        if (psi_env_lookup(env_block, L"TEMP", temp_path, 260)) {
            TLOG_TRACE("peb_sysinfo: %%TEMP%% resolved from PEB environment");
        } else {
            /* Fall back to TMP (some systems use TMP instead of TEMP) */
            if (psi_env_lookup(env_block, L"TMP", temp_path, 260)) {
                TLOG_TRACE("peb_sysinfo: %%TMP%% resolved from PEB environment");
            } else {
                TLOG_WARN("peb_sysinfo: neither TEMP nor TMP found in environment");
            }
        }
    } else {
        TLOG_WARN("peb_sysinfo: Environment block pointer is NULL");
    }

    /*
     * Step 7: Also verify TEB-based PID/TID retrieval works.
     * TEB+0x40 = ClientId.UniqueProcess (PID)
     * TEB+0x48 = ClientId.UniqueThread  (TID)
     * These are read by TektonTebGetProcessId/ThreadId in peb.h.
     */
    DWORD pid = TektonTebGetProcessId();
    DWORD tid = TektonTebGetThreadId();
    TLOG_DEBUG("peb_sysinfo: TEB PID=%lu, TID=%lu",
        (unsigned long)pid, (unsigned long)tid);

    state->initialized = TRUE;

    TLOG_INFO("peb_sysinfo: all system info resolved from PEB/TEB (zero API imports)");
    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_DEBUG("peb_sysinfo: non-Windows stub, skipping PEB reads");
    state->processor_count = 4; /* Fake value for testing */
    state->initialized = TRUE;
    return TEKTON_OK;
#endif
}

static VOID peb_sysinfo_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(PEB_SYSINFO_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD peb_sysinfo_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Very low risk: reads only from the PEB/TEB, which are in-process
     * structures.  No API calls, no cross-process access, no hooks to
     * trigger.  The only detection vector is behavioral: an EDR that
     * instruments PEB reads at the instruction level (rare).
     */
    return 5;
}

static BOOL peb_sysinfo_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /*
     * PEB structure layout for the fields we access is stable across
     * all x64 Windows versions from Vista through Windows 11.  The
     * offsets for ProcessParameters, NumberOfProcessors, and the
     * RTL_USER_PROCESS_PARAMETERS sub-fields have not changed.
     */
    return TRUE;
}

/* ── Convenience wrappers (callable by other modules) ────── */

/*
 * These wrap the TektonPeb* helpers from peb.h into a module-oriented
 * interface.  Downstream modules call these instead of importing
 * GetTempPathW, GetEnvironmentVariableW, etc.
 */

BOOL TektonPebSysinfoGetTempPath(wchar_t* out_buffer, DWORD buffer_chars) {
    return TektonPebGetTempPath(out_buffer, buffer_chars);
}

BOOL TektonPebSysinfoGetEnvVar(
    const wchar_t* var_name,
    wchar_t* out_buffer,
    DWORD buffer_chars
) {
    return TektonPebGetEnvVar(var_name, out_buffer, buffer_chars);
}

BOOL TektonPebSysinfoGetCurrentDir(wchar_t* out_buffer, DWORD buffer_chars) {
    return TektonPebGetCurrentDir(out_buffer, buffer_chars);
}

const wchar_t* TektonPebSysinfoGetCommandLine(void) {
    return TektonPebGetCommandLine();
}

DWORD TektonPebSysinfoGetProcessorCount(void) {
    return TektonPebGetProcessorCount();
}

/* ── Module definition + auto-registration ─────────────── */

TEKTON_MODULE tekton_mod_peb_sysinfo = {
    .name           = "peb_sysinfo",
    .description    = "PEB/TEB-based system info queries, replacing "
                      "GetTempPathW, GetEnvironmentVariableW, "
                      "GetCurrentDirectoryW, GetCommandLineW, "
                      "GetNumberOfProcessors (Cat 1.5)",
    .category       = TEKTON_CAT_API_RESOLVE,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "1.5",
    .init           = peb_sysinfo_init,
    .execute        = peb_sysinfo_execute,
    .cleanup        = peb_sysinfo_cleanup,
    .get_risk_score = peb_sysinfo_risk_score,
    .check_compat   = peb_sysinfo_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_peb_sysinfo);
