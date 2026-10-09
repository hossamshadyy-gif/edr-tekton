#ifndef TEKTON_CONTEXT_H
#define TEKTON_CONTEXT_H

/*
 * edr-tekton :: Runtime Context
 * Holds target environment info, resolved state, and shared data
 * between pipeline stages.
 */

#include "types.h"

/* ── OS Build Info ────────────────────────────────────── */

typedef struct _TEKTON_OS_INFO {
    DWORD   major_version;      /* 10 for Win10/11                */
    DWORD   minor_version;      /* 0                              */
    DWORD   build_number;       /* 19041, 19045, 22621, etc       */
    DWORD   update_build;       /* UBR from registry              */
    BOOL    is_x64;             /* TRUE if 64-bit OS              */
    BOOL    is_wow64;           /* TRUE if 32-bit on 64-bit       */
    BOOL    is_win11;           /* TRUE if build >= 22000         */
    BOOL    has_cet;            /* TRUE if CET shadow stack active */
    BOOL    has_hvci;           /* TRUE if HVCI enabled           */
    char    hostname[256];
    char    username[256];
    char    domain[256];
} TEKTON_OS_INFO, *PTEKTON_OS_INFO;

/* ── Detected EDR Info ────────────────────────────────── */

#define TEKTON_MAX_EDR_DLLS  32

typedef struct _TEKTON_EDR_INFO {
    char    name[64];                           /* "crowdstrike", "sentinelone", etc */
    BOOL    hooks_detected;                     /* ntdll hooks found                 */
    DWORD   hooked_count;                       /* number of hooked Nt* functions    */
    char    hooked_dlls[TEKTON_MAX_EDR_DLLS][64]; /* DLLs injected by EDR           */
    DWORD   hooked_dll_count;
    BOOL    etw_provider_active;                /* EtwTi consumer detected           */
    BOOL    minifilter_active;                  /* Filesystem filter detected        */
    BOOL    kernel_callbacks_active;            /* Process/thread callbacks detected  */
} TEKTON_EDR_INFO, *PTEKTON_EDR_INFO;

/* ── Resolved API / Syscall State ─────────────────────── */

typedef struct _TEKTON_RESOLVED_STATE {
    /* API resolution */
    PVOID   fn_nt_allocate_virtual_memory;
    PVOID   fn_nt_write_virtual_memory;
    PVOID   fn_nt_protect_virtual_memory;
    PVOID   fn_nt_create_thread_ex;
    PVOID   fn_nt_create_section;
    PVOID   fn_nt_map_view_of_section;
    PVOID   fn_nt_unmap_view_of_section;
    PVOID   fn_nt_queue_apc_thread;
    PVOID   fn_nt_open_process;
    PVOID   fn_nt_close;
    PVOID   fn_nt_wait_for_single_object;
    PVOID   fn_nt_suspend_thread;
    PVOID   fn_nt_resume_thread;
    PVOID   fn_nt_set_information_process;
    PVOID   fn_nt_query_system_information;
    PVOID   fn_nt_query_information_process;
    PVOID   fn_rtl_init_unicode_string;

    /* SSN table (syscall numbers) */
    DWORD   ssn_nt_allocate_virtual_memory;
    DWORD   ssn_nt_write_virtual_memory;
    DWORD   ssn_nt_protect_virtual_memory;
    DWORD   ssn_nt_create_thread_ex;
    DWORD   ssn_nt_create_section;
    DWORD   ssn_nt_map_view_of_section;
    DWORD   ssn_nt_queue_apc_thread;
    DWORD   ssn_nt_open_process;
    DWORD   ssn_nt_close;

    /* Indirect syscall gadget address */
    PVOID   syscall_gadget;        /* Address of `syscall; ret` in ntdll/win32u */
    PVOID   syscall_gadget_alt;    /* Alternative gadget (win32u.dll)           */

    /* Clean ntdll copy (for unhooking) */
    PVOID   clean_ntdll_text;
    SIZE_T  clean_ntdll_text_size;

    BOOL    apis_resolved;
    BOOL    ssns_resolved;
    BOOL    unhook_complete;
} TEKTON_RESOLVED_STATE, *PTEKTON_RESOLVED_STATE;

/* ── Main Context ─────────────────────────────────────── */

struct _TEKTON_CONTEXT {
    /* Environment */
    TEKTON_OS_INFO          os;
    TEKTON_EDR_INFO         edr;
    TEKTON_RESOLVED_STATE   resolved;

    /* Payload */
    TEKTON_BUFFER           payload;        /* Raw/encrypted payload    */
    TEKTON_BUFFER           decrypted;      /* Decrypted payload buffer */

    /* Injection target */
    DWORD                   target_pid;
    HANDLE                  target_handle;
    PVOID                   remote_base;    /* Allocated region in target */

    /* Pipeline state */
    DWORD                   pipeline_stage;
    TEKTON_STATUS           last_error;
    char                    last_error_msg[512];

    /* Flags */
    BOOL                    verbose;
    BOOL                    dry_run;        /* Plan but don't execute */
};

/* ── Context API ──────────────────────────────────────── */

TEKTON_STATUS TektonContextInit(PTEKTON_CONTEXT ctx);
TEKTON_STATUS TektonContextFingerprint(PTEKTON_CONTEXT ctx);
TEKTON_STATUS TektonContextDetectEDR(PTEKTON_CONTEXT ctx);
VOID          TektonContextCleanup(PTEKTON_CONTEXT ctx);

/* Set error with formatted message */
VOID TektonContextSetError(
    PTEKTON_CONTEXT ctx,
    TEKTON_STATUS   status,
    const char*     fmt,
    ...
);

#endif /* TEKTON_CONTEXT_H */
