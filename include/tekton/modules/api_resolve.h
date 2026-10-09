#ifndef TEKTON_MOD_API_RESOLVE_H
#define TEKTON_MOD_API_RESOLVE_H

/*
 * edr-tekton :: API Resolution Modules
 * Cat 1: Multiple strategies for resolving Windows APIs
 * without suspicious static imports.
 */

#include "../core/module.h"

/* ── Available API Resolution Modules ─────────────────── */

/* Cat 1.1: Dynamic resolution via GetModuleHandle + GetProcAddress */
extern TEKTON_MODULE tekton_mod_dynamic_resolve;

/* Cat 1.2: PEB walking, zero-import resolution */
extern TEKTON_MODULE tekton_mod_peb_walk;

/* Cat 1.3/1.5/1.8: Hash-based resolution (CRC32B, Djb2, Additive) */
extern TEKTON_MODULE tekton_mod_hash_resolve;

/* Cat 1.5: PEB/TEB-based system info (replaces GetTempPathW, etc.) */
extern TEKTON_MODULE tekton_mod_peb_sysinfo;

/* ── Module Configuration ─────────────────────────────── */

typedef enum _TEKTON_HASH_ALGO {
    TEKTON_HASH_CRC32B      = 0,    /* Cat 1.5, 1.8 */
    TEKTON_HASH_DJB2         = 1,    /* Cat 1.9      */
    TEKTON_HASH_ADDITIVE     = 2,    /* Cat 1.3      */
    TEKTON_HASH_CUSTOM       = 3,
} TEKTON_HASH_ALGO;

typedef struct _TEKTON_API_RESOLVE_CFG {
    TEKTON_HASH_ALGO    hash_algo;
    BOOL                use_peb_sysinfo;    /* Cat 1.5: Replace WinAPI with PEB reads */
    BOOL                use_teb_ids;        /* Cat 1.6: TEB-based PID/TID             */
    BOOL                encrypt_strings;    /* Cat 1.4: XOR-encrypt API name strings  */
    BYTE                string_key[16];     /* Key for string encryption              */
    SIZE_T              string_key_len;
} TEKTON_API_RESOLVE_CFG, *PTEKTON_API_RESOLVE_CFG;

/* ── Resolved API Set ─────────────────────────────────── */

/*
 * After the API resolve module runs, all needed function
 * pointers are stored in ctx->resolved and available
 * to downstream modules.
 */

/* Helper: resolve a single API by name into ctx->resolved */
TEKTON_STATUS TektonApiResolveByName(
    PTEKTON_CONTEXT ctx,
    const char*     dll_name,
    const char*     func_name,
    PVOID*          out_func_ptr
);

/* Helper: resolve a single API by hash */
TEKTON_STATUS TektonApiResolveByHash(
    PTEKTON_CONTEXT ctx,
    DWORD           dll_hash,
    DWORD           func_hash,
    PVOID*          out_func_ptr
);

#endif /* TEKTON_MOD_API_RESOLVE_H */
