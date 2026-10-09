#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

/*
 * edr-tekton :: Minimal Test Framework
 * Lightweight C test macros with colored output and pass/fail tracking.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── ANSI Color Codes ───────────────────────────────────── */

#define TF_GREEN    "\033[32m"
#define TF_RED      "\033[31m"
#define TF_YELLOW   "\033[33m"
#define TF_CYAN     "\033[36m"
#define TF_BOLD     "\033[1m"
#define TF_RESET    "\033[0m"

/* ── Test State ─────────────────────────────────────────── */

typedef struct {
    int         total;
    int         passed;
    int         failed;
    const char* suite_name;
} test_state_t;

/* ── Suite Lifecycle ────────────────────────────────────── */

static inline void tf_init(test_state_t* st, const char* suite) {
    st->total = 0;
    st->passed = 0;
    st->failed = 0;
    st->suite_name = suite;
    printf("\n" TF_BOLD TF_CYAN "=== %s ===" TF_RESET "\n", suite);
}

static inline int tf_summary(test_state_t* st) {
    printf("\n" TF_BOLD "--- %s: " TF_RESET, st->suite_name);
    if (st->failed == 0) {
        printf(TF_GREEN "%d/%d passed" TF_RESET "\n", st->passed, st->total);
    } else {
        printf(TF_RED "%d failed" TF_RESET ", "
               TF_GREEN "%d passed" TF_RESET " / %d total\n",
               st->failed, st->passed, st->total);
    }
    return st->failed;
}

/* ── Test Declaration ───────────────────────────────────── */

/* Declare a test function. Usage: TEST(my_test_name) { ... } */
#define TEST(name) static void test_##name(test_state_t* _tf_state)

/* ── Test Runner ────────────────────────────────────────── */

/* Run a single test, track pass/fail, print result. */
#define RUN_TEST(name) do {                                         \
    _tf_state->total++;                                             \
    int _tf_prev_fail = _tf_state->failed;                          \
    printf("  [....] %s", #name);                                   \
    fflush(stdout);                                                 \
    test_##name(_tf_state);                                         \
    if (_tf_state->failed == _tf_prev_fail) {                       \
        _tf_state->passed++;                                        \
        printf("\r  [" TF_GREEN "PASS" TF_RESET "] %s\n", #name);  \
    } else {                                                        \
        printf("\r  [" TF_RED "FAIL" TF_RESET "] %s\n", #name);    \
    }                                                               \
} while(0)

/* ── Assertion Macros ───────────────────────────────────── */

/*
 * All asserts increment failed count and return from the test
 * function on failure, preventing cascading failures.
 */

#define ASSERT_TRUE(expr) do {                                      \
    if (!(expr)) {                                                  \
        printf("\n    " TF_RED "ASSERT_TRUE failed" TF_RESET        \
               ": %s\n    at %s:%d\n", #expr, __FILE__, __LINE__);  \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_FALSE(expr) do {                                     \
    if ((expr)) {                                                   \
        printf("\n    " TF_RED "ASSERT_FALSE failed" TF_RESET       \
               ": %s\n    at %s:%d\n", #expr, __FILE__, __LINE__);  \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_EQ(a, b) do {                                        \
    unsigned long long _a_v = (unsigned long long)(a);               \
    unsigned long long _b_v = (unsigned long long)(b);               \
    if (_a_v != _b_v) {                                             \
        printf("\n    " TF_RED "ASSERT_EQ failed" TF_RESET          \
               ": %s == %s\n"                                       \
               "    left:  0x%llx (%llu)\n"                         \
               "    right: 0x%llx (%llu)\n"                         \
               "    at %s:%d\n",                                    \
               #a, #b, _a_v, _a_v, _b_v, _b_v,                     \
               __FILE__, __LINE__);                                 \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_NEQ(a, b) do {                                       \
    unsigned long long _a_v = (unsigned long long)(a);               \
    unsigned long long _b_v = (unsigned long long)(b);               \
    if (_a_v == _b_v) {                                             \
        printf("\n    " TF_RED "ASSERT_NEQ failed" TF_RESET         \
               ": %s != %s\n"                                       \
               "    both:  0x%llx (%llu)\n"                         \
               "    at %s:%d\n",                                    \
               #a, #b, _a_v, _a_v,                                  \
               __FILE__, __LINE__);                                 \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_NULL(ptr) do {                                       \
    if ((ptr) != NULL) {                                            \
        printf("\n    " TF_RED "ASSERT_NULL failed" TF_RESET        \
               ": %s is %p, expected NULL\n"                        \
               "    at %s:%d\n",                                    \
               #ptr, (void*)(ptr), __FILE__, __LINE__);             \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_NOT_NULL(ptr) do {                                   \
    if ((ptr) == NULL) {                                            \
        printf("\n    " TF_RED "ASSERT_NOT_NULL failed" TF_RESET    \
               ": %s is NULL\n"                                     \
               "    at %s:%d\n",                                    \
               #ptr, __FILE__, __LINE__);                           \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_STR_EQ(a, b) do {                                    \
    const char* _a_s = (a);                                         \
    const char* _b_s = (b);                                         \
    if (_a_s == NULL || _b_s == NULL) {                              \
        if (_a_s != _b_s) {                                         \
            printf("\n    " TF_RED "ASSERT_STR_EQ failed" TF_RESET  \
                   ": %s == %s\n"                                   \
                   "    left:  %s\n"                                \
                   "    right: %s\n"                                \
                   "    at %s:%d\n",                                \
                   #a, #b,                                          \
                   _a_s ? _a_s : "(null)",                          \
                   _b_s ? _b_s : "(null)",                          \
                   __FILE__, __LINE__);                              \
            _tf_state->failed++;                                    \
            return;                                                 \
        }                                                           \
    } else if (strcmp(_a_s, _b_s) != 0) {                           \
        printf("\n    " TF_RED "ASSERT_STR_EQ failed" TF_RESET      \
               ": %s == %s\n"                                       \
               "    left:  \"%s\"\n"                                \
               "    right: \"%s\"\n"                                \
               "    at %s:%d\n",                                    \
               #a, #b, _a_s, _b_s,                                  \
               __FILE__, __LINE__);                                 \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

/* ── Memory Comparison ──────────────────────────────────── */

#define ASSERT_MEM_EQ(a, b, len) do {                               \
    if (memcmp((a), (b), (len)) != 0) {                             \
        printf("\n    " TF_RED "ASSERT_MEM_EQ failed" TF_RESET      \
               ": %s == %s (%d bytes)\n"                            \
               "    at %s:%d\n",                                    \
               #a, #b, (int)(len), __FILE__, __LINE__);             \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_MEM_NEQ(a, b, len) do {                              \
    if (memcmp((a), (b), (len)) == 0) {                             \
        printf("\n    " TF_RED "ASSERT_MEM_NEQ failed" TF_RESET     \
               ": %s and %s are identical (%d bytes)\n"             \
               "    at %s:%d\n",                                    \
               #a, #b, (int)(len), __FILE__, __LINE__);             \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

/* ── Status Code Check ──────────────────────────────────── */

#define ASSERT_OK(status) do {                                      \
    TEKTON_STATUS _s = (status);                                    \
    if (_s != TEKTON_OK) {                                          \
        printf("\n    " TF_RED "ASSERT_OK failed" TF_RESET          \
               ": %s returned %d (expected TEKTON_OK)\n"            \
               "    at %s:%d\n",                                    \
               #status, (int)_s, __FILE__, __LINE__);               \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#define ASSERT_ERR(status, expected) do {                            \
    TEKTON_STATUS _s = (status);                                    \
    TEKTON_STATUS _e = (expected);                                  \
    if (_s != _e) {                                                 \
        printf("\n    " TF_RED "ASSERT_ERR failed" TF_RESET         \
               ": %s returned %d (expected %d)\n"                   \
               "    at %s:%d\n",                                    \
               #status, (int)_s, (int)_e, __FILE__, __LINE__);      \
        _tf_state->failed++;                                        \
        return;                                                     \
    }                                                               \
} while(0)

#endif /* TEST_FRAMEWORK_H */
