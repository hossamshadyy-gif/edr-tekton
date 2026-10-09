/*
 * edr-tekton :: CLI Entry Point
 * Composable Evasion Payload Builder
 *
 * Usage:
 *   tekton --auto                             Auto-detect EDR, run pipeline
 *   tekton --profile <name>                   Use built-in profile by name
 *   tekton --profile-file <path.yaml>         Load custom YAML profile
 *   tekton --profile <name> --dry-run         Show plan without executing
 *   tekton --list-modules                     List registered modules
 *   tekton --list-profiles                    List loaded EDR profiles
 *   tekton --hash <algo> <string>             Hash a string (for config)
 *   tekton --help                             This message
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tekton/core/types.h"
#include "tekton/core/config.h"
#include "tekton/core/builder.h"
#include "tekton/core/module.h"
#include "tekton/core/loader.h"
#include "tekton/core/profile.h"
#include "tekton/core/context.h"
#include "tekton/core/log.h"
#include "tekton/util/hash.h"

/* ── Module registration ─────────────────────────────────── */

/*
 * On MSVC, auto-registration via .CRT$XCU runs before main().
 * On GCC/Clang, __attribute__((constructor)) does the same.
 * Modules that use TEKTON_DECLARE_MODULE self-register.
 *
 * For manual builds or static linking, call the init functions:
 */

extern void tekton_register_all_modules(void);

/* Fallback: explicit registration for compilers without auto-init */
__attribute__((weak))
void tekton_register_all_modules(void) {
    /* Auto-registered modules don't need this.
     * Add manual TektonModuleRegister() calls here if needed. */
}

/* ── Version ─────────────────────────────────────────────── */

#define TEKTON_VERSION_MAJOR    0
#define TEKTON_VERSION_MINOR    2
#define TEKTON_VERSION_PATCH    0
#define TEKTON_VERSION_STRING   "0.2.0"

/* ── CLI helpers ─────────────────────────────────────────── */

static const char* category_names[] = {
    "API_RESOLVE",
    "SYSCALL",
    "ENCRYPT",
    "INJECT",
    "EVASION",
    "ANTIDEBUG",
    "SLEEP",
};

static void print_usage(const char* argv0) {
    printf(
        "\n"
        "  edr-tekton v%s :: Composable Evasion Payload Builder\n"
        "  =====================================================\n"
        "\n"
        "  Usage:\n"
        "    %s --auto                             Auto-detect EDR + run\n"
        "    %s --profile <name>                   Use built-in profile\n"
        "    %s --profile-file <path.yaml>         Custom YAML profile\n"
        "    %s --profile <name> --dry-run         Show plan only\n"
        "    %s --list-modules                     List modules\n"
        "    %s --list-profiles                    List EDR profiles\n"
        "    %s --hash <algo> <string>             Hash a string\n"
        "    %s --help                             This message\n"
        "\n"
        "  Profiles: crowdstrike, sentinelone, defender, sophos,\n"
        "            carbon_black, elastic, generic, none\n"
        "\n"
        "  Hash algorithms: crc32b, djb2, additive, rotate\n"
        "\n",
        TEKTON_VERSION_STRING,
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0
    );
}

static void print_profiles(void) {
    PTEKTON_PROFILE_REGISTRY reg = TektonProfileGetRegistry();

    printf("\n  Loaded EDR Profiles (%lu)\n", (unsigned long)reg->count);
    printf("  %-20s %-28s %-10s %s\n",
        "NAME", "DISPLAY", "VENDOR", "RISK BUDGET");
    printf("  %-20s %-28s %-10s %s\n",
        "--------------------", "----------------------------", "----------",
        "-----------");

    for (DWORD i = 0; i < reg->count; i++) {
        PTEKTON_EDR_PROFILE p = &reg->profiles[i];
        printf("  %-20s %-28s %-10s %lu\n",
            p->name,
            p->display_name,
            TektonVendorToString(p->vendor),
            (unsigned long)p->max_total_risk);
    }
    printf("\n");
}

static void print_modules(void) {
    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();

    printf("\n  Registered Modules (%lu total)\n", (unsigned long)reg->count);
    printf("  %-24s %-14s %-8s %-8s %s\n",
        "NAME", "CATEGORY", "FLAGS", "RISK", "DESCRIPTION");
    printf("  %-24s %-14s %-8s %-8s %s\n",
        "------------------------", "--------------", "--------", "--------",
        "-------------------------------");

    for (DWORD cat = 0; cat < TEKTON_CAT_MAX; cat++) {
        PTEKTON_MODULE modules[64];
        DWORD count = TektonModuleList((TEKTON_CATEGORY)cat, modules, 64);

        for (DWORD i = 0; i < count; i++) {
            PTEKTON_MODULE mod = modules[i];

            char flags[32] = "";
            if (mod->flags & TEKTON_MOD_REQUIRES_X64)  strcat(flags, "x64 ");
            if (mod->flags & TEKTON_MOD_REQUIRES_ADMIN) strcat(flags, "adm ");
            if (mod->flags & TEKTON_MOD_STEALTHY)       strcat(flags, "stl ");
            if (mod->flags & TEKTON_MOD_EXPERIMENTAL)    strcat(flags, "exp ");

            DWORD risk = 0;
            if (mod->get_risk_score) risk = mod->get_risk_score(mod);

            printf("  %-24s %-14s %-8s %-8lu %s\n",
                mod->name,
                cat < TEKTON_CAT_MAX ? category_names[cat] : "???",
                flags[0] ? flags : "-",
                (unsigned long)risk,
                mod->description ? mod->description : "");
        }
    }
    printf("\n");
}

static void run_hash(const char* algo, const char* input) {
    DWORD result = 0;

    if (strcmp(algo, "crc32b") == 0) {
        result = TektonHashCrc32bStringA(input);
    } else if (strcmp(algo, "djb2") == 0) {
        result = TektonHashDjb2StringA(input);
    } else if (strcmp(algo, "additive") == 0) {
        result = TektonHashAdditive(input);
    } else if (strcmp(algo, "rotate") == 0) {
        result = TektonHashRotate(input, 0x5AFE);
    } else {
        fprintf(stderr, "Unknown hash algorithm: %s\n", algo);
        fprintf(stderr, "Available: crc32b, djb2, additive, rotate\n");
        return;
    }

    printf("  %s(\"%s\") = 0x%08lX (%lu)\n",
        algo, input, (unsigned long)result, (unsigned long)result);
}

/* ── Main ────────────────────────────────────────────────── */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Initialize logging */
    TektonLogSetLevel(TEKTON_LOG_INFO);

    /* Register modules (auto + manual) */
    tekton_register_all_modules();

    /* Load built-in profiles */
    TektonProfileLoadDefaults();

    /* Parse CLI */
    const char* profile_name = NULL;
    const char* profile_file = NULL;
    BOOL auto_mode    = FALSE;
    BOOL dry_run      = FALSE;
    BOOL list_mods    = FALSE;
    BOOL list_profs   = FALSE;
    const char* hash_algo  = NULL;
    const char* hash_input = NULL;
    BOOL verbose __attribute__((unused)) = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--auto") == 0 || strcmp(argv[i], "-a") == 0) {
            auto_mode = TRUE;
        }
        else if (strcmp(argv[i], "--profile") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) profile_name = argv[++i];
            else { fprintf(stderr, "--profile requires a name\n"); return 1; }
        }
        else if (strcmp(argv[i], "--profile-file") == 0 || strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) profile_file = argv[++i];
            else { fprintf(stderr, "--profile-file requires a path\n"); return 1; }
        }
        else if (strcmp(argv[i], "--dry-run") == 0 || strcmp(argv[i], "-d") == 0) {
            dry_run = TRUE;
        }
        else if (strcmp(argv[i], "--list-modules") == 0 || strcmp(argv[i], "-l") == 0) {
            list_mods = TRUE;
        }
        else if (strcmp(argv[i], "--list-profiles") == 0) {
            list_profs = TRUE;
        }
        else if (strcmp(argv[i], "--hash") == 0) {
            if (i + 2 < argc) {
                hash_algo = argv[++i];
                hash_input = argv[++i];
            } else {
                fprintf(stderr, "--hash requires <algorithm> <string>\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = TRUE;
            TektonLogSetLevel(TEKTON_LOG_DEBUG);
        }
        else if (strcmp(argv[i], "--trace") == 0) {
            TektonLogSetLevel(TEKTON_LOG_TRACE);
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* ── Execute info commands ───────────────────────────── */

    if (list_mods) {
        print_modules();
        return 0;
    }

    if (list_profs) {
        print_profiles();
        return 0;
    }

    if (hash_algo && hash_input) {
        run_hash(hash_algo, hash_input);
        return 0;
    }

    /* ── Determine profile source ────────────────────────── */

    printf("\n  edr-tekton v%s\n", TEKTON_VERSION_STRING);

    TEKTON_CONFIG config;
    TEKTON_STATUS status;
    memset(&config, 0, sizeof(config));

    if (auto_mode) {
        /*
         * Auto-detect: fingerprint the environment, identify the
         * running EDR, pick the best profile, and compose the
         * pipeline automatically via the selector engine.
         */
        printf("  Mode: auto-detect\n");
        printf("  Fingerprinting environment...\n");

        TEKTON_CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        TektonContextInit(&ctx);

        TEKTON_EDR_VENDOR vendor = TektonDetectVendor(&ctx);
        printf("  Detected EDR: %s\n", TektonVendorToString(vendor));

        PTEKTON_EDR_PROFILE prof = TektonAutoProfile(&ctx);
        if (!prof) {
            fprintf(stderr, "  No matching profile found, falling back to generic\n");
            prof = TektonProfileFindByName("generic");
        }
        if (!prof) {
            fprintf(stderr, "  Failed to load any profile\n");
            return 1;
        }

        printf("  Selected profile: %s (%s)\n", prof->name, prof->display_name);
        printf("  Composing pipeline via selector engine...\n\n");

        status = TektonSelectModules(prof, &ctx, &config);
        if (status != TEKTON_OK) {
            fprintf(stderr, "  Module selection failed: error %d\n", status);
            return 1;
        }
    }
    else if (profile_file) {
        /* Load from explicit YAML file path */
        printf("  Loading profile: %s\n\n", profile_file);

        status = TektonConfigLoad(profile_file, &config);
        if (status != TEKTON_OK) {
            fprintf(stderr, "  Failed to load profile: error %d\n", status);
            return 1;
        }
    }
    else if (profile_name) {
        /*
         * Look up by name: first check built-in profiles, then
         * try loading as a YAML file path for backwards compat.
         */
        PTEKTON_EDR_PROFILE prof = TektonProfileFindByName(profile_name);
        if (prof) {
            printf("  Using built-in profile: %s (%s)\n\n",
                prof->name, prof->display_name);

            TEKTON_CONTEXT ctx;
            memset(&ctx, 0, sizeof(ctx));
            TektonContextInit(&ctx);

            status = TektonSelectModules(prof, &ctx, &config);
            if (status != TEKTON_OK) {
                fprintf(stderr, "  Module selection failed: error %d\n", status);
                return 1;
            }
        } else {
            /* Fallback: treat as file path */
            printf("  Loading profile file: %s\n\n", profile_name);

            status = TektonConfigLoad(profile_name, &config);
            if (status != TEKTON_OK) {
                fprintf(stderr, "  Failed to load profile '%s': error %d\n",
                    profile_name, status);
                fprintf(stderr, "  (not a built-in profile name or valid file path)\n");
                return 1;
            }
        }
    }
    else {
        fprintf(stderr, "No profile specified. Use --auto, --profile, or --profile-file\n");
        return 1;
    }

    /* ── Build and execute pipeline ──────────────────────── */

    TEKTON_PIPELINE pipeline;
    status = TektonPipelineBuild(&config, &pipeline);
    if (status != TEKTON_OK) {
        fprintf(stderr, "  Failed to build pipeline: error %d\n", status);
        TektonConfigFree(&config);
        return 1;
    }

    if (dry_run) {
        status = TektonPipelineDryRun(&pipeline);
    } else {
        status = TektonPipelineExecute(&pipeline);
    }

    int ret = (status == TEKTON_OK) ? 0 : 1;

    if (status == TEKTON_OK) {
        printf("\n  Pipeline %s successfully.\n\n",
            dry_run ? "validated" : "executed");
    } else {
        fprintf(stderr, "\n  Pipeline failed: error %d\n\n", status);
    }

    TektonPipelineDestroy(&pipeline);
    return ret;
}
