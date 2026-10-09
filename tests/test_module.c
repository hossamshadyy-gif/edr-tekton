/*
 * edr-tekton :: Module System Tests
 * Tests module registration, lookup, and registry management.
 */

#include "test_framework.h"
#include "tekton/core/module.h"

/* ── Registry Reset Helper ──────────────────────────────── */

/*
 * The module registry is a global static. We need to reset it
 * between tests to avoid cross-contamination.
 */
static void reset_registry(void) {
    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    memset(reg, 0, sizeof(TEKTON_MODULE_REGISTRY));
}

/* ── Mock Modules ───────────────────────────────────────── */

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
    return 10;
}

/* Create and return a stack-allocated mock module.
 * IMPORTANT: caller must keep the struct alive while it is registered. */
static TEKTON_MODULE make_mock_module(
    const char*     name,
    TEKTON_CATEGORY category,
    const char*     skill_ref
) {
    TEKTON_MODULE mod;
    memset(&mod, 0, sizeof(mod));
    mod.name = name;
    mod.description = "Mock module for testing";
    mod.category = category;
    mod.target_surface = TEKTON_SURFACE_USER_HOOKS;
    mod.flags = TEKTON_MOD_NONE;
    mod.skill_ref = skill_ref;
    mod.init = mock_init;
    mod.execute = mock_execute;
    mod.cleanup = mock_cleanup;
    mod.get_risk_score = mock_risk;
    mod.check_compat = NULL;
    mod.private_data = NULL;
    mod.next = NULL;
    return mod;
}

/* ── Registration Tests ─────────────────────────────────── */

TEST(module_register_single) {
    reset_registry();

    TEKTON_MODULE mod = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TEKTON_STATUS s = TektonModuleRegister(&mod);
    ASSERT_OK(s);

    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    ASSERT_EQ(reg->count, 1);
    ASSERT_NOT_NULL(reg->head);
    ASSERT_STR_EQ(reg->head->name, "peb_walk");
}

TEST(module_register_multiple) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TEKTON_MODULE m2 = make_mock_module("indirect_syscall", TEKTON_CAT_SYSCALL, "2.4");
    TEKTON_MODULE m3 = make_mock_module("etw_patch", TEKTON_CAT_EVASION, "4.1");

    ASSERT_OK(TektonModuleRegister(&m1));
    ASSERT_OK(TektonModuleRegister(&m2));
    ASSERT_OK(TektonModuleRegister(&m3));

    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    ASSERT_EQ(reg->count, 3);
}

TEST(module_register_null) {
    reset_registry();

    TEKTON_STATUS s = TektonModuleRegister(NULL);
    ASSERT_EQ(s, TEKTON_ERR_INVALID_PARAM);

    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    ASSERT_EQ(reg->count, 0);
}

TEST(module_register_null_name) {
    reset_registry();

    TEKTON_MODULE mod = make_mock_module("test", TEKTON_CAT_API_RESOLVE, "1.0");
    mod.name = NULL; /* Null name */

    TEKTON_STATUS s = TektonModuleRegister(&mod);
    ASSERT_EQ(s, TEKTON_ERR_INVALID_PARAM);
}

TEST(module_register_duplicate) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TEKTON_MODULE m2 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");

    ASSERT_OK(TektonModuleRegister(&m1));
    /* Duplicate registration should succeed (returns OK) but not add */
    ASSERT_OK(TektonModuleRegister(&m2));

    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    ASSERT_EQ(reg->count, 1); /* Only one entry */
}

TEST(module_register_category_index) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("mod_a", TEKTON_CAT_SYSCALL, "2.1");
    TEKTON_MODULE m2 = make_mock_module("mod_b", TEKTON_CAT_SYSCALL, "2.2");
    TEKTON_MODULE m3 = make_mock_module("mod_c", TEKTON_CAT_EVASION, "4.1");

    ASSERT_OK(TektonModuleRegister(&m1));
    ASSERT_OK(TektonModuleRegister(&m2));
    ASSERT_OK(TektonModuleRegister(&m3));

    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    ASSERT_EQ(reg->category_count[TEKTON_CAT_SYSCALL], 2);
    ASSERT_EQ(reg->category_count[TEKTON_CAT_EVASION], 1);
    ASSERT_EQ(reg->category_count[TEKTON_CAT_API_RESOLVE], 0);
}

/* ── Find Tests ─────────────────────────────────────────── */

TEST(module_find_by_name) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TEKTON_MODULE m2 = make_mock_module("indirect_syscall", TEKTON_CAT_SYSCALL, "2.4");

    TektonModuleRegister(&m1);
    TektonModuleRegister(&m2);

    PTEKTON_MODULE found = TektonModuleFind("peb_walk");
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->name, "peb_walk");
    ASSERT_EQ(found->category, TEKTON_CAT_API_RESOLVE);

    found = TektonModuleFind("indirect_syscall");
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->name, "indirect_syscall");
}

TEST(module_find_not_found) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TektonModuleRegister(&m1);

    PTEKTON_MODULE found = TektonModuleFind("nonexistent_module");
    ASSERT_NULL(found);
}

TEST(module_find_null_name) {
    reset_registry();
    ASSERT_NULL(TektonModuleFind(NULL));
}

TEST(module_find_by_ref) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TEKTON_MODULE m2 = make_mock_module("indirect_syscall", TEKTON_CAT_SYSCALL, "2.4");
    TEKTON_MODULE m3 = make_mock_module("etw_patch", TEKTON_CAT_EVASION, "4.1");

    TektonModuleRegister(&m1);
    TektonModuleRegister(&m2);
    TektonModuleRegister(&m3);

    PTEKTON_MODULE found = TektonModuleFindByRef("2.4");
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->name, "indirect_syscall");

    found = TektonModuleFindByRef("4.1");
    ASSERT_NOT_NULL(found);
    ASSERT_STR_EQ(found->name, "etw_patch");
}

TEST(module_find_by_ref_not_found) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TektonModuleRegister(&m1);

    ASSERT_NULL(TektonModuleFindByRef("99.99"));
}

TEST(module_find_by_ref_null) {
    reset_registry();
    ASSERT_NULL(TektonModuleFindByRef(NULL));
}

TEST(module_find_by_ref_null_skill_ref) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("no_ref_mod", TEKTON_CAT_API_RESOLVE, NULL);
    TektonModuleRegister(&m1);

    /* Module has NULL skill_ref, search should skip it without crashing */
    ASSERT_NULL(TektonModuleFindByRef("1.0"));
}

/* ── List Tests ─────────────────────────────────────────── */

TEST(module_list_by_category) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("direct_syscall", TEKTON_CAT_SYSCALL, "2.1");
    TEKTON_MODULE m2 = make_mock_module("indirect_syscall", TEKTON_CAT_SYSCALL, "2.4");
    TEKTON_MODULE m3 = make_mock_module("tampered_syscall", TEKTON_CAT_SYSCALL, "2.5");
    TEKTON_MODULE m4 = make_mock_module("etw_patch", TEKTON_CAT_EVASION, "4.1");

    TektonModuleRegister(&m1);
    TektonModuleRegister(&m2);
    TektonModuleRegister(&m3);
    TektonModuleRegister(&m4);

    PTEKTON_MODULE list[8];
    DWORD count = TektonModuleList(TEKTON_CAT_SYSCALL, list, 8);
    ASSERT_EQ(count, 3);

    count = TektonModuleList(TEKTON_CAT_EVASION, list, 8);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(list[0]->name, "etw_patch");
}

TEST(module_list_empty_category) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("peb_walk", TEKTON_CAT_API_RESOLVE, "1.2");
    TektonModuleRegister(&m1);

    PTEKTON_MODULE list[8];
    DWORD count = TektonModuleList(TEKTON_CAT_SLEEP, list, 8);
    ASSERT_EQ(count, 0);
}

TEST(module_list_max_count_limit) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("m1", TEKTON_CAT_INJECT, "5.1");
    TEKTON_MODULE m2 = make_mock_module("m2", TEKTON_CAT_INJECT, "5.2");
    TEKTON_MODULE m3 = make_mock_module("m3", TEKTON_CAT_INJECT, "5.3");

    TektonModuleRegister(&m1);
    TektonModuleRegister(&m2);
    TektonModuleRegister(&m3);

    PTEKTON_MODULE list[2]; /* Only room for 2 */
    DWORD count = TektonModuleList(TEKTON_CAT_INJECT, list, 2);
    ASSERT_EQ(count, 2);
}

TEST(module_list_invalid_category) {
    reset_registry();

    PTEKTON_MODULE list[4];
    DWORD count = TektonModuleList(TEKTON_CAT_MAX, list, 4);
    ASSERT_EQ(count, 0);

    count = TektonModuleList((TEKTON_CATEGORY)99, list, 4);
    ASSERT_EQ(count, 0);
}

TEST(module_list_null_output) {
    reset_registry();
    DWORD count = TektonModuleList(TEKTON_CAT_API_RESOLVE, NULL, 4);
    ASSERT_EQ(count, 0);
}

/* ── Registry State Tests ───────────────────────────────── */

TEST(registry_get_returns_same_pointer) {
    PTEKTON_MODULE_REGISTRY r1 = TektonGetRegistry();
    PTEKTON_MODULE_REGISTRY r2 = TektonGetRegistry();
    ASSERT_TRUE(r1 == r2);
}

TEST(registry_linked_list_integrity) {
    reset_registry();

    TEKTON_MODULE m1 = make_mock_module("alpha", TEKTON_CAT_API_RESOLVE, "1.1");
    TEKTON_MODULE m2 = make_mock_module("bravo", TEKTON_CAT_SYSCALL, "2.1");
    TEKTON_MODULE m3 = make_mock_module("charlie", TEKTON_CAT_EVASION, "4.1");

    TektonModuleRegister(&m1);
    TektonModuleRegister(&m2);
    TektonModuleRegister(&m3);

    /* Walk the linked list and count entries */
    PTEKTON_MODULE_REGISTRY reg = TektonGetRegistry();
    int count = 0;
    PTEKTON_MODULE cur = reg->head;
    while (cur) {
        count++;
        cur = cur->next;
        if (count > 10) break; /* safety */
    }
    ASSERT_EQ(count, 3);
    ASSERT_EQ(reg->count, 3);
}

/* ── Suite Runner ───────────────────────────────────────── */

int test_module_run(void) {
    test_state_t _tf_state_val;
    test_state_t* _tf_state = &_tf_state_val;
    tf_init(_tf_state, "Module System");

    /* Registration */
    RUN_TEST(module_register_single);
    RUN_TEST(module_register_multiple);
    RUN_TEST(module_register_null);
    RUN_TEST(module_register_null_name);
    RUN_TEST(module_register_duplicate);
    RUN_TEST(module_register_category_index);

    /* Find by name */
    RUN_TEST(module_find_by_name);
    RUN_TEST(module_find_not_found);
    RUN_TEST(module_find_null_name);

    /* Find by skill ref */
    RUN_TEST(module_find_by_ref);
    RUN_TEST(module_find_by_ref_not_found);
    RUN_TEST(module_find_by_ref_null);
    RUN_TEST(module_find_by_ref_null_skill_ref);

    /* List */
    RUN_TEST(module_list_by_category);
    RUN_TEST(module_list_empty_category);
    RUN_TEST(module_list_max_count_limit);
    RUN_TEST(module_list_invalid_category);
    RUN_TEST(module_list_null_output);

    /* Registry state */
    RUN_TEST(registry_get_returns_same_pointer);
    RUN_TEST(registry_linked_list_integrity);

    return tf_summary(_tf_state);
}
