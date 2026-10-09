#ifndef TEKTON_CONFIG_H
#define TEKTON_CONFIG_H

/*
 * edr-tekton :: Configuration Parser
 * Reads YAML profile files that define which technique modules
 * to chain for a specific EDR target.
 */

#include "types.h"

/* ── Config value types ───────────────────────────────── */

typedef enum _TEKTON_CFG_TYPE {
    TEKTON_CFG_STRING   = 0,
    TEKTON_CFG_INT      = 1,
    TEKTON_CFG_BOOL     = 2,
    TEKTON_CFG_LIST     = 3,
    TEKTON_CFG_MAP      = 4,
} TEKTON_CFG_TYPE;

/* ── Config node (simplified YAML tree) ───────────────── */

#define TEKTON_CFG_MAX_KEY      64
#define TEKTON_CFG_MAX_VALUE    256
#define TEKTON_CFG_MAX_CHILDREN 64

typedef struct _TEKTON_CFG_NODE {
    char                        key[TEKTON_CFG_MAX_KEY];
    char                        value[TEKTON_CFG_MAX_VALUE];
    TEKTON_CFG_TYPE             type;
    struct _TEKTON_CFG_NODE*    children[TEKTON_CFG_MAX_CHILDREN];
    DWORD                       child_count;
    struct _TEKTON_CFG_NODE*    parent;
} TEKTON_CFG_NODE, *PTEKTON_CFG_NODE;

/* ── Parsed Profile ───────────────────────────────────── */

#define TEKTON_MAX_ENCRYPT_LAYERS 4
#define TEKTON_MAX_SANDBOX_CHECKS 8

typedef struct _TEKTON_ENCRYPT_LAYER {
    char    type[32];           /* "xor", "aes256", "rc4"          */
    char    key_source[32];    /* "env", "static", "derived"      */
    BYTE    static_key[32];    /* For static key source           */
    DWORD   key_length;
} TEKTON_ENCRYPT_LAYER, *PTEKTON_ENCRYPT_LAYER;

struct _TEKTON_CONFIG {
    /* Profile metadata */
    char    profile_name[64];
    char    profile_version[16];

    /* Target */
    char    target_edr[64];
    DWORD   target_os_build;
    char    target_arch[8];         /* "x64" or "x86" */

    /* Pipeline selections (module names) */
    char    api_resolve[64];        /* e.g., "peb_walk"              */

    /* Syscall config */
    char    syscall_method[64];     /* e.g., "indirect"              */
    char    ssn_resolve[64];        /* e.g., "hells_gate"            */
    char    callstack_spoof[64];    /* e.g., "silentmoonwalk"        */

    /* Encryption layers */
    TEKTON_ENCRYPT_LAYER encrypt_layers[TEKTON_MAX_ENCRYPT_LAYERS];
    DWORD   encrypt_layer_count;

    /* Injection */
    char    inject_method[64];      /* e.g., "poolparty_worker"      */
    char    inject_target[256];     /* e.g., "explorer.exe"          */

    /* Evasion */
    char    etw_method[64];         /* e.g., "patch_etw_event_write" */
    char    amsi_method[64];        /* e.g., "patch_amsi_scan_buffer"*/
    char    sandbox_checks[TEKTON_MAX_SANDBOX_CHECKS][64];
    DWORD   sandbox_check_count;

    /* Sleep */
    char    sleep_method[64];       /* e.g., "foliage"               */
    DWORD   sleep_interval_ms;

    /* Payload */
    char    payload_path[512];
    char    payload_format[16];     /* "raw", "pe", "dotnet"         */

    /* Raw config tree for custom extensions */
    PTEKTON_CFG_NODE root;
};

/* ── Config API ───────────────────────────────────────── */

/* Parse a YAML profile file into a config struct */
TEKTON_STATUS TektonConfigLoad(
    const char*     profile_path,
    PTEKTON_CONFIG  out_config
);

/* Parse a YAML string (for embedded profiles) */
TEKTON_STATUS TektonConfigParse(
    const char*     yaml_string,
    SIZE_T          yaml_length,
    PTEKTON_CONFIG  out_config
);

/* Query a config value by dotted path (e.g., "pipeline.syscall.method") */
const char* TektonConfigGet(
    PTEKTON_CONFIG  config,
    const char*     path
);

/* Get integer value */
int TektonConfigGetInt(
    PTEKTON_CONFIG  config,
    const char*     path,
    int             default_val
);

/* Get boolean value */
BOOL TektonConfigGetBool(
    PTEKTON_CONFIG  config,
    const char*     path,
    BOOL            default_val
);

/* Free config resources */
VOID TektonConfigFree(PTEKTON_CONFIG config);

#endif /* TEKTON_CONFIG_H */
