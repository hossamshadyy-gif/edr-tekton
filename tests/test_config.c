/*
 * edr-tekton :: Configuration Parser Tests
 * Tests YAML parsing, field extraction, and error handling.
 */

#include "test_framework.h"
#include "tekton/core/config.h"

/* ── Test YAML Profile ──────────────────────────────────── */

static const char* TEST_YAML =
    "profile: crowdstrike_evasion\n"
    "version: 2.1\n"
    "target:\n"
    "  edr: crowdstrike\n"
    "  os_build: 19045\n"
    "  arch: x64\n"
    "pipeline:\n"
    "  api_resolve: peb_walk\n"
    "  syscall:\n"
    "    method: indirect\n"
    "    ssn_resolve: hells_gate\n"
    "    callstack: silentmoonwalk\n"
    "  inject:\n"
    "    method: poolparty_worker\n"
    "    target_process: explorer.exe\n"
    "  evasion:\n"
    "    etw: patch_etw_event_write\n"
    "    amsi: patch_amsi_scan_buffer\n"
    "    sandbox:\n"
    "      checks: [hardware, timing, user_activity]\n"
    "  sleep:\n"
    "    method: foliage\n"
    "    interval_ms: 15000\n"
    "  encrypt:\n"
    "    layers:\n"
    "      - { type: xor, key_source: static }\n"
    "      - { type: aes256, key_source: env }\n"
    "payload:\n"
    "  source: payload.bin\n"
    "  format: raw\n";

/* ── Parse Tests ────────────────────────────────────────── */

TEST(config_parse_valid_yaml) {
    TEKTON_CONFIG cfg;
    TEKTON_STATUS s = TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg);
    ASSERT_OK(s);
    ASSERT_NOT_NULL(cfg.root);
    TektonConfigFree(&cfg);
}

TEST(config_parse_null_params) {
    TEKTON_CONFIG cfg;
    ASSERT_EQ(TektonConfigParse(NULL, 0, &cfg), TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), NULL), TEKTON_ERR_INVALID_PARAM);
}

TEST(config_parse_extracts_profile_name) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.profile_name, "crowdstrike_evasion");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_version) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.profile_version, "2.1");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_target) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.target_edr, "crowdstrike");
    ASSERT_EQ(cfg.target_os_build, 19045);
    ASSERT_STR_EQ(cfg.target_arch, "x64");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_pipeline) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.api_resolve, "peb_walk");
    ASSERT_STR_EQ(cfg.syscall_method, "indirect");
    ASSERT_STR_EQ(cfg.ssn_resolve, "hells_gate");
    ASSERT_STR_EQ(cfg.callstack_spoof, "silentmoonwalk");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_injection) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.inject_method, "poolparty_worker");
    ASSERT_STR_EQ(cfg.inject_target, "explorer.exe");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_evasion) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.etw_method, "patch_etw_event_write");
    ASSERT_STR_EQ(cfg.amsi_method, "patch_amsi_scan_buffer");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_sleep) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.sleep_method, "foliage");
    ASSERT_EQ(cfg.sleep_interval_ms, 15000);
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_payload) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_STR_EQ(cfg.payload_path, "payload.bin");
    ASSERT_STR_EQ(cfg.payload_format, "raw");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_sandbox_checks) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_EQ(cfg.sandbox_check_count, 3);
    ASSERT_STR_EQ(cfg.sandbox_checks[0], "hardware");
    ASSERT_STR_EQ(cfg.sandbox_checks[1], "timing");
    ASSERT_STR_EQ(cfg.sandbox_checks[2], "user_activity");
    TektonConfigFree(&cfg);
}

TEST(config_parse_extracts_encrypt_layers) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));
    ASSERT_EQ(cfg.encrypt_layer_count, 2);
    ASSERT_STR_EQ(cfg.encrypt_layers[0].type, "xor");
    ASSERT_STR_EQ(cfg.encrypt_layers[0].key_source, "static");
    ASSERT_STR_EQ(cfg.encrypt_layers[1].type, "aes256");
    ASSERT_STR_EQ(cfg.encrypt_layers[1].key_source, "env");
    TektonConfigFree(&cfg);
}

/* ── Config Query Tests ─────────────────────────────────── */

TEST(config_get_simple_key) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    const char* val = TektonConfigGet(&cfg, "profile");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "crowdstrike_evasion");

    TektonConfigFree(&cfg);
}

TEST(config_get_nested_key) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    const char* val = TektonConfigGet(&cfg, "target.edr");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "crowdstrike");

    TektonConfigFree(&cfg);
}

TEST(config_get_deep_nested) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    const char* val = TektonConfigGet(&cfg, "pipeline.syscall.method");
    ASSERT_NOT_NULL(val);
    ASSERT_STR_EQ(val, "indirect");

    TektonConfigFree(&cfg);
}

TEST(config_get_nonexistent) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    ASSERT_NULL(TektonConfigGet(&cfg, "nonexistent"));
    ASSERT_NULL(TektonConfigGet(&cfg, "target.nonexistent"));
    ASSERT_NULL(TektonConfigGet(&cfg, "a.b.c.d.e"));

    TektonConfigFree(&cfg);
}

TEST(config_get_null_params) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    ASSERT_NULL(TektonConfigGet(NULL, "profile"));
    ASSERT_NULL(TektonConfigGet(&cfg, NULL));

    TektonConfigFree(&cfg);
}

TEST(config_get_int) {
    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(TEST_YAML, strlen(TEST_YAML), &cfg));

    int val = TektonConfigGetInt(&cfg, "target.os_build", -1);
    ASSERT_EQ(val, 19045);

    /* Default for missing key */
    int def = TektonConfigGetInt(&cfg, "nonexistent", 42);
    ASSERT_EQ(def, 42);

    TektonConfigFree(&cfg);
}

TEST(config_get_bool) {
    /* Create a YAML with boolean values */
    const char* yaml =
        "flag_true: true\n"
        "flag_yes: yes\n"
        "flag_one: 1\n"
        "flag_false: false\n"
        "flag_no: no\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    ASSERT_TRUE(TektonConfigGetBool(&cfg, "flag_true", FALSE));
    ASSERT_TRUE(TektonConfigGetBool(&cfg, "flag_yes", FALSE));
    ASSERT_TRUE(TektonConfigGetBool(&cfg, "flag_one", FALSE));
    ASSERT_FALSE(TektonConfigGetBool(&cfg, "flag_false", TRUE));
    ASSERT_FALSE(TektonConfigGetBool(&cfg, "flag_no", TRUE));

    /* Default for missing key */
    ASSERT_TRUE(TektonConfigGetBool(&cfg, "nonexistent", TRUE));
    ASSERT_FALSE(TektonConfigGetBool(&cfg, "nonexistent", FALSE));

    TektonConfigFree(&cfg);
}

/* ── File Load Tests ────────────────────────────────────── */

TEST(config_load_missing_file) {
    TEKTON_CONFIG cfg;
    TEKTON_STATUS s = TektonConfigLoad("/nonexistent/path/profile.yaml", &cfg);
    ASSERT_EQ(s, TEKTON_ERR_NOT_FOUND);
}

TEST(config_load_null_params) {
    TEKTON_CONFIG cfg;
    ASSERT_EQ(TektonConfigLoad(NULL, &cfg), TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonConfigLoad("/some/path", NULL), TEKTON_ERR_INVALID_PARAM);
}

/* ── Edge Cases ─────────────────────────────────────────── */

TEST(config_parse_comments_ignored) {
    const char* yaml =
        "# This is a comment\n"
        "key: value\n"
        "# Another comment\n"
        "other: data\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));

    ASSERT_STR_EQ(TektonConfigGet(&cfg, "key"), "value");
    ASSERT_STR_EQ(TektonConfigGet(&cfg, "other"), "data");

    TektonConfigFree(&cfg);
}

TEST(config_parse_empty_yaml) {
    /* Empty or comments-only YAML */
    const char* yaml = "# only comments\n\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));
    ASSERT_NOT_NULL(cfg.root);
    ASSERT_EQ(cfg.root->child_count, 0);

    TektonConfigFree(&cfg);
}

TEST(config_free_null_safe) {
    /* Should not crash */
    TektonConfigFree(NULL);

    TEKTON_CONFIG cfg;
    memset(&cfg, 0, sizeof(cfg));
    TektonConfigFree(&cfg); /* root is NULL, should be safe */
}

TEST(config_parse_inline_list) {
    const char* yaml = "items: [alpha, bravo, charlie]\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));
    ASSERT_NOT_NULL(cfg.root);

    /* The "items" node should have children for each list element */
    ASSERT_TRUE(cfg.root->child_count >= 1);

    TektonConfigFree(&cfg);
}

TEST(config_default_sleep_interval) {
    /* When sleep interval is not specified, default should apply */
    const char* yaml = "profile: minimal\n";

    TEKTON_CONFIG cfg;
    ASSERT_OK(TektonConfigParse(yaml, strlen(yaml), &cfg));
    /* Default sleep interval is 30000 per config.c */
    ASSERT_EQ(cfg.sleep_interval_ms, 30000);

    TektonConfigFree(&cfg);
}

/* ── Suite Runner ───────────────────────────────────────── */

int test_config_run(void) {
    test_state_t _tf_state_val;
    test_state_t* _tf_state = &_tf_state_val;
    tf_init(_tf_state, "Configuration Parser");

    /* Parse */
    RUN_TEST(config_parse_valid_yaml);
    RUN_TEST(config_parse_null_params);
    RUN_TEST(config_parse_extracts_profile_name);
    RUN_TEST(config_parse_extracts_version);
    RUN_TEST(config_parse_extracts_target);
    RUN_TEST(config_parse_extracts_pipeline);
    RUN_TEST(config_parse_extracts_injection);
    RUN_TEST(config_parse_extracts_evasion);
    RUN_TEST(config_parse_extracts_sleep);
    RUN_TEST(config_parse_extracts_payload);
    RUN_TEST(config_parse_extracts_sandbox_checks);
    RUN_TEST(config_parse_extracts_encrypt_layers);

    /* Query */
    RUN_TEST(config_get_simple_key);
    RUN_TEST(config_get_nested_key);
    RUN_TEST(config_get_deep_nested);
    RUN_TEST(config_get_nonexistent);
    RUN_TEST(config_get_null_params);
    RUN_TEST(config_get_int);
    RUN_TEST(config_get_bool);

    /* File load */
    RUN_TEST(config_load_missing_file);
    RUN_TEST(config_load_null_params);

    /* Edge cases */
    RUN_TEST(config_parse_comments_ignored);
    RUN_TEST(config_parse_empty_yaml);
    RUN_TEST(config_free_null_safe);
    RUN_TEST(config_parse_inline_list);
    RUN_TEST(config_default_sleep_interval);

    return tf_summary(_tf_state);
}
