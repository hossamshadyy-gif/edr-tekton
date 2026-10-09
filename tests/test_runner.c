/*
 * edr-tekton :: Test Runner
 * Runs all test suites and prints a final summary.
 *
 * Build:
 *   cd build && cmake .. -DTEKTON_BUILD_TESTS=ON && make test_runner
 *
 * Run:
 *   ./test_runner
 *
 * Exit code: 0 if all tests pass, 1 if any fail.
 */

#include <stdio.h>
#include "tekton/core/log.h"

/* Suite entry points (defined in each test_*.c file) */
extern int test_hash_run(void);
extern int test_crypto_run(void);
extern int test_config_run(void);
extern int test_module_run(void);
extern int test_builder_run(void);

/* ── Color codes ────────────────────────────────────────── */

#define C_GREEN  "\033[32m"
#define C_RED    "\033[31m"
#define C_BOLD   "\033[1m"
#define C_RESET  "\033[0m"

int main(void) {
    /* Suppress library logging during tests */
    TektonLogSetLevel(TEKTON_LOG_SILENT);

    printf(C_BOLD "\n"
           "========================================\n"
           "  edr-tekton Test Suite\n"
           "========================================\n"
           C_RESET);

    int total_failures = 0;
    int suites_run = 0;
    int suites_failed = 0;

    struct {
        const char* name;
        int (*run)(void);
    } suites[] = {
        { "Hash Functions",          test_hash_run    },
        { "Cryptographic Primitives",test_crypto_run  },
        { "Configuration Parser",   test_config_run  },
        { "Module System",          test_module_run  },
        { "Pipeline Builder",       test_builder_run },
    };

    int suite_count = (int)(sizeof(suites) / sizeof(suites[0]));

    for (int i = 0; i < suite_count; i++) {
        int failures = suites[i].run();
        total_failures += failures;
        suites_run++;
        if (failures > 0) suites_failed++;
    }

    /* Final summary */
    printf(C_BOLD "\n"
           "========================================\n"
           "  Final Results\n"
           "========================================\n"
           C_RESET);
    printf("  Suites run:    %d\n", suites_run);
    printf("  Suites failed: %d\n", suites_failed);

    if (total_failures == 0) {
        printf("\n  " C_BOLD C_GREEN
               "ALL TESTS PASSED" C_RESET "\n\n");
    } else {
        printf("\n  " C_BOLD C_RED
               "%d TEST(S) FAILED" C_RESET "\n\n",
               total_failures);
    }

    return (total_failures > 0) ? 1 : 0;
}
