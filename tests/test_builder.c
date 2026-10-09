/*
 * edr-tekton :: Pipeline Builder Tests
 * Tests pipeline construction, stage management, dry-run, and cleanup.
 */

#include "test_framework.h"
#include "tekton/core/builder.h"
#include "tekton/core/module.h"
#include "tekton/core/config.h"

/* ── Registry Reset ─────────────────────────────────────── */

static void reset_registry(void) {
    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    memset(reg, 0, sizeof(TEKTON_MODULE_REGISTRY));
}

/* ── Mock Module Helpers ────────────────────────────────── */

static TEKTON_STATUS mock_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self; (void)ctx;
    return TEKTON_OK;
}

static TEKTON_STATUS mock_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self; (void)ctx;
    return TEKTON_OK;
}

static void mock_cleanup(PTEKTON_MODULE self) {
    (void)self;
}

static DWORD mock_risk(PTEKTON_MODULE self) {
    (void)self;
    return 15;
}

static BOOL mock_compat_pass(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self; (void)ctx;
    return TRUE;
}

/*
 * Persistent mock modules (static storage so pointers remain valid
 * across the lifetime of the test suite).
 */
static TEKTON_MODULE g_mock_modules[8];
static int g_mock_count = 0;

static PTEKTON_MODULE register_mock(
    const char*     name,
    TEKTON_CATEGORY category,
    const char*     skill_ref
) {
    if (g_mock_count >= 8) return NULL;

    PTEKTON_MODULE mod = &g_mock_modules[g_mock_count++];
    memset(mod, 0, sizeof(TEKTON_MODULE));
    mod->name = name;
    mod->description = "Mock module";
    mod->category = category;
    mod->target_surface = TEKTON_SURFACE_USER_HOOKS;
    mod->flags = TEKTON_MOD_NONE;
    mod->skill_ref = skill_ref;
    mod->init = mock_init;
    mod->execute = mock_execute;
    mod->cleanup = mock_cleanup;
    mod->get_risk_score = mock_risk;
    mod->check_compat = mock_compat_pass;
    mod->next = NULL;

    TektonModuleRegister(mod);
    return mod;
}

/* Register a standard set of mock modules for pipeline tests */
static void setup_mock_modules(void) {
    reset_registry();
    g_mock_count = 0;
    memset(g_mock_modules, 0, sizeof(g_mock_modules));

    register_mock("peb_walk",          TEKTON_CAT_API_RESOLVE, "1.2");
    register_mock("indirect_syscall",  TEKTON_CAT_SYSCALL,     "2.4");
    register_mock("etw_patch",         TEKTON_CAT_EVASION,     "4.1");
    register_mock("amsi_patch",        TEKTON_CAT_EVASION,     "4.2");
    register_mock("inject_poolparty",  TEKTON_CAT_INJECT,      "5.6");
    register_mock("sleep_foliage",     TEKTON_CAT_SLEEP,       "6.2");
}

/* ── Test YAML ──────────────────────────────────────────── */

static const char* PIPELINE_YAML =
    "profile: test_pipeline\n"
    "version: 1.0\n"
    "target:\n"
    "  edr: test\n"
    "  os_build: 19045\n"
    "  arch: x64\n"
    "pipeline:\n"
    "  api_resolve: peb_walk\n"
    "  syscall:\n"
    "    method: indirect\n"
    "  inject:\n"
    "    method: poolparty\n"
    "  evasion:\n"
    "    etw: etw_patch\n"
    "    amsi: amsi_patch\n"
    "  sleep:\n"
    "    method: foliage\n"
    "    interval_ms: 10000\n";

/* ── Pipeline Build Tests ───────────────────────────────── */

TEST(pipeline_build_valid) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    TEKTON_STATUS s = TektonPipelineBuild(&cfg, &pipeline);
    ASSERT_OK(s);
    ASSERT_TRUE(pipeline.built);
    ASSERT_TRUE(pipeline.entry_count > 0);

    /*
     * TektonPipelineBuild does a shallow memcpy of cfg into pipeline.config,
     * so both share the same root pointer. TektonPipelineDestroy frees it,
     * so NULL the original to prevent double-free.
     */
    cfg.root = NULL;

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_build_null_params) {
    TEKTON_CONFIG cfg;
    TEKTON_PIPELINE pipeline;

    ASSERT_EQ(TektonPipelineBuild(NULL, &pipeline), TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonPipelineBuild(&cfg, NULL), TEKTON_ERR_INVALID_PARAM);
}

TEST(pipeline_build_resolves_modules) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Verify entries have valid module pointers */
    for (DWORD i = 0; i < pipeline.entry_count; i++) {
        ASSERT_NOT_NULL(pipeline.entries[i].module);
        ASSERT_NOT_NULL(pipeline.entries[i].module->name);
    }

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_build_stage_ordering) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Verify stages are in ascending order (the builder adds them in order) */
    for (DWORD i = 1; i < pipeline.entry_count; i++) {
        ASSERT_TRUE(pipeline.entries[i].stage >= pipeline.entries[i-1].stage);
    }

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_build_missing_module) {
    setup_mock_modules();

    /* Config references a module that does not exist */
    const char* yaml =
        "profile: broken\n"
        "pipeline:\n"
        "  api_resolve: nonexistent_resolver\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    TEKTON_PIPELINE pipeline;
    TEKTON_STATUS s = TektonPipelineBuild(&cfg, &pipeline);
    ASSERT_EQ(s, TEKTON_ERR_MODULE_MISSING);

    TektonConfigFree(&cfg);
}

/* ── Pipeline with No Modules ───────────────────────────── */

TEST(pipeline_build_empty_config) {
    setup_mock_modules();

    /* Minimal config with no pipeline stages specified */
    const char* yaml = "profile: empty\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;
    ASSERT_TRUE(pipeline.built);
    ASSERT_EQ(pipeline.entry_count, 0);

    TektonPipelineDestroy(&pipeline);
}

/* ── Dry Run Tests ──────────────────────────────────────── */

TEST(pipeline_dry_run) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Dry run should set the flag and validate */
    TEKTON_STATUS s = TektonPipelineDryRun(&pipeline);
    ASSERT_OK(s);
    ASSERT_TRUE(pipeline.context.dry_run);

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_dry_run_not_built) {
    TEKTON_PIPELINE pipeline;
    memset(&pipeline, 0, sizeof(pipeline));
    pipeline.built = FALSE;

    TEKTON_STATUS s = TektonPipelineDryRun(&pipeline);
    ASSERT_EQ(s, TEKTON_ERR_INVALID_PARAM);
}

TEST(pipeline_dry_run_null) {
    ASSERT_EQ(TektonPipelineDryRun(NULL), TEKTON_ERR_INVALID_PARAM);
}

/* ── Execute Stage Tests ────────────────────────────────── */

TEST(pipeline_execute_stage_null) {
    ASSERT_EQ(TektonPipelineExecuteStage(NULL, TEKTON_STAGE_API_RESOLVE),
              TEKTON_ERR_INVALID_PARAM);
}

TEST(pipeline_execute_stage_no_entries) {
    setup_mock_modules();

    const char* yaml = "profile: empty\n";
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Executing a stage with no entries should succeed (nothing to do) */
    ASSERT_OK(TektonPipelineExecuteStage(&pipeline, TEKTON_STAGE_API_RESOLVE));

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_execute_single_stage) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Mark as validated to skip fingerprint/EDR detection */
    pipeline.validated = TRUE;

    /* Execute just the API resolve stage */
    ASSERT_OK(TektonPipelineExecuteStage(&pipeline, TEKTON_STAGE_API_RESOLVE));

    /* Check that API resolve entries got executed */
    for (DWORD i = 0; i < pipeline.entry_count; i++) {
        if (pipeline.entries[i].stage == TEKTON_STAGE_API_RESOLVE) {
            ASSERT_TRUE(pipeline.entries[i].executed);
            ASSERT_EQ(pipeline.entries[i].result, TEKTON_OK);
        }
    }

    TektonPipelineDestroy(&pipeline);
}

/* ── Pipeline Destroy Tests ─────────────────────────────── */

TEST(pipeline_destroy_null_safe) {
    /* Should not crash */
    TektonPipelineDestroy(NULL);
}

TEST(pipeline_destroy_clears_state) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;
    ASSERT_TRUE(pipeline.built);
    ASSERT_TRUE(pipeline.entry_count > 0);

    TektonPipelineDestroy(&pipeline);

    /* After destroy, state should be zeroed */
    ASSERT_FALSE(pipeline.built);
    ASSERT_EQ(pipeline.entry_count, 0);
}

/* ── Pipeline Print Tests ───────────────────────────────── */

TEST(pipeline_print_null_safe) {
    /* Should not crash */
    TektonPipelinePrint(NULL);
}

TEST(pipeline_print_with_entries) {
    setup_mock_modules();

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(PIPELINE_YAML, strlen(PIPELINE_YAML), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Should not crash; output goes to stdout */
    TektonPipelinePrint(&pipeline);

    TektonPipelineDestroy(&pipeline);
}

/* ── Pipeline Validate Tests ────────────────────────────── */

TEST(pipeline_validate_null) {
    ASSERT_EQ(TektonPipelineValidate(NULL), TEKTON_ERR_INVALID_PARAM);
}

TEST(pipeline_validate_not_built) {
    TEKTON_PIPELINE pipeline;
    memset(&pipeline, 0, sizeof(pipeline));
    pipeline.built = FALSE;

    ASSERT_EQ(TektonPipelineValidate(&pipeline), TEKTON_ERR_INVALID_PARAM);
}

/* ── Execute Full Pipeline (no modules) ─────────────────── */

TEST(pipeline_execute_empty) {
    setup_mock_modules();

    const char* yaml = "profile: empty\n";
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    TEKTON_PIPELINE pipeline;
    ASSERT_OK(TektonPipelineBuild(&cfg, &pipeline));
    cfg.root = NULL;

    /* Full execute with no entries should succeed after validation */
    TEKTON_STATUS s = TektonPipelineExecute(&pipeline);
    ASSERT_OK(s);

    TektonPipelineDestroy(&pipeline);
}

TEST(pipeline_execute_not_built) {
    TEKTON_PIPELINE pipeline;
    memset(&pipeline, 0, sizeof(pipeline));
    ASSERT_EQ(TektonPipelineExecute(&pipeline), TEKTON_ERR_INVALID_PARAM);
}

/* ── Suite Runner ───────────────────────────────────────── */

int test_builder_run(void) {
    test_state_t _tf_state_val;
    test_state_t* _tf_state = &_tf_state_val;
    tf_init(_tf_state, "Pipeline Builder");

    /* Build */
    RUN_TEST(pipeline_build_valid);
    RUN_TEST(pipeline_build_null_params);
    RUN_TEST(pipeline_build_resolves_modules);
    RUN_TEST(pipeline_build_stage_ordering);
    RUN_TEST(pipeline_build_missing_module);
    RUN_TEST(pipeline_build_empty_config);

    /* Dry run */
    RUN_TEST(pipeline_dry_run);
    RUN_TEST(pipeline_dry_run_not_built);
    RUN_TEST(pipeline_dry_run_null);

    /* Execute stage */
    RUN_TEST(pipeline_execute_stage_null);
    RUN_TEST(pipeline_execute_stage_no_entries);
    RUN_TEST(pipeline_execute_single_stage);

    /* Destroy */
    RUN_TEST(pipeline_destroy_null_safe);
    RUN_TEST(pipeline_destroy_clears_state);

    /* Print */
    RUN_TEST(pipeline_print_null_safe);
    RUN_TEST(pipeline_print_with_entries);

    /* Validate */
    RUN_TEST(pipeline_validate_null);
    RUN_TEST(pipeline_validate_not_built);

    /* Execute full */
    RUN_TEST(pipeline_execute_empty);
    RUN_TEST(pipeline_execute_not_built);

    return tf_summary(_tf_state);
}
