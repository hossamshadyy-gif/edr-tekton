#ifndef TEKTON_MOD_SLEEP_H
#define TEKTON_MOD_SLEEP_H

/*
 * edr-tekton :: Sleep Obfuscation Modules
 * Cat 47: BeaconGate architecture
 * Cat 50: Advanced sleep obfuscation (Ekko, Foliage, Zilean)
 */

#include "../core/module.h"

/* ── Available Sleep Modules ──────────────────────────── */

/* Cat 50: Ekko - timer-based ROP chain sleep with RX->RW->RX cycling */
extern TEKTON_MODULE tekton_mod_sleep_ekko;

/* Cat 50: Foliage - APC-based sleep with memory permission cycling */
extern TEKTON_MODULE tekton_mod_sleep_foliage;

/* Cat 50: Zilean - clean variant using NtContinue */
extern TEKTON_MODULE tekton_mod_sleep_zilean;

/* Cat 47: BeaconGate - trampoline architecture for Beacon API hooking */
extern TEKTON_MODULE tekton_mod_sleep_beacongate;

/* ── Sleep Configuration ──────────────────────────────── */

typedef struct _TEKTON_SLEEP_CFG {
    DWORD   interval_ms;            /* Sleep duration          */
    BOOL    encrypt_on_sleep;       /* Encrypt payload in memory during sleep */
    BOOL    cycle_permissions;      /* RX -> RW -> RX cycling  */
    BOOL    spoof_thread_stack;     /* Spoof call stack during sleep */
    BYTE    sleep_encrypt_key[16];  /* Key for sleep-time encryption */
    SIZE_T  sleep_encrypt_key_len;
} TEKTON_SLEEP_CFG, *PTEKTON_SLEEP_CFG;

/* ── BeaconGate Configuration (Cat 47) ────────────────── */

typedef struct _TEKTON_BEACONGATE_CFG {
    BOOL    hook_nt_allocate;       /* Hook NtAllocateVirtualMemory */
    BOOL    hook_nt_protect;        /* Hook NtProtectVirtualMemory  */
    BOOL    hook_nt_write;          /* Hook NtWriteVirtualMemory    */
    BOOL    hook_nt_create_thread;  /* Hook NtCreateThreadEx        */
    BOOL    use_indirect_syscall;   /* Route hooked calls through indirect syscall */
    BOOL    use_callstack_spoof;    /* Spoof call stack on hooked calls */
} TEKTON_BEACONGATE_CFG, *PTEKTON_BEACONGATE_CFG;

#endif /* TEKTON_MOD_SLEEP_H */
