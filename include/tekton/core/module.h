#ifndef TEKTON_MODULE_H
#define TEKTON_MODULE_H

/*
 * edr-tekton :: Module Interface
 * Every technique module implements this vtable.
 * Modules are self-registering via constructor attributes.
 */

#include "types.h"
#include "context.h"

/* ── Module vtable ────────────────────────────────────── */

struct _TEKTON_MODULE {
    /* Identity */
    const char*         name;           /* "peb_walk", "indirect_syscall"  */
    const char*         description;    /* Human-readable description      */
    TEKTON_CATEGORY     category;       /* Which pipeline stage            */
    TEKTON_SURFACE      target_surface; /* Which detection layer it evades */
    DWORD               flags;          /* TEKTON_MOD_* flags              */

    /* Skill reference (category.technique from the skill file) */
    const char*         skill_ref;      /* "1.2", "2.4", "44.2", etc      */

    /* Lifecycle */
    TEKTON_STATUS (*init)(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx);
    TEKTON_STATUS (*execute)(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx);
    VOID          (*cleanup)(PTEKTON_MODULE self);

    /* Introspection */
    DWORD (*get_risk_score)(PTEKTON_MODULE self);
    BOOL  (*check_compat)(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx);

    /* Internal state */
    PVOID               private_data;

    /* Linked list for registry */
    PTEKTON_MODULE      next;
};

/* ── Module Registration ──────────────────────────────── */

#define TEKTON_MAX_MODULES 128

typedef struct _TEKTON_MODULE_REGISTRY {
    PTEKTON_MODULE  head;
    DWORD           count;
    PTEKTON_MODULE  by_category[TEKTON_CAT_MAX][TEKTON_MAX_MODULES];
    DWORD           category_count[TEKTON_CAT_MAX];
} TEKTON_MODULE_REGISTRY, *PTEKTON_MODULE_REGISTRY;

/* Global registry */
PTEKTON_MODULE_REGISTRY TektonGetRegistry(void);

/* Register a module (called at startup) */
TEKTON_STATUS TektonModuleRegister(PTEKTON_MODULE mod);

/* Find module by name */
PTEKTON_MODULE TektonModuleFind(const char* name);

/* Find module by skill reference (e.g., "2.4") */
PTEKTON_MODULE TektonModuleFindByRef(const char* skill_ref);

/* List all modules in a category */
DWORD TektonModuleList(
    TEKTON_CATEGORY category,
    PTEKTON_MODULE* out_modules,
    DWORD           max_count
);

/* ── Module Declaration Macro ─────────────────────────── */

/*
 * Use TEKTON_DECLARE_MODULE in each module .c file.
 * Example:
 *   TEKTON_DECLARE_MODULE(peb_walk_module);
 *
 * Then define the module struct:
 *   TEKTON_MODULE peb_walk_module = {
 *       .name = "peb_walk",
 *       .category = TEKTON_CAT_API_RESOLVE,
 *       ...
 *   };
 *
 * On Windows, use CRT section tricks for auto-registration.
 * On Linux (dev builds), call TektonModuleRegister() manually.
 */

#ifdef _MSC_VER
    /* MSVC: CRT initializer section for auto-registration */
    #pragma section(".CRT$XCU", read)
    #define TEKTON_DECLARE_MODULE(mod) \
        static void __cdecl _tekton_reg_##mod(void) { TektonModuleRegister(&mod); } \
        __declspec(allocate(".CRT$XCU")) static void (__cdecl *_tekton_pf_##mod)(void) = _tekton_reg_##mod;
#elif defined(__GNUC__) || defined(__clang__)
    /* GCC/Clang: constructor attribute */
    #define TEKTON_DECLARE_MODULE(mod) \
        __attribute__((constructor)) static void _tekton_reg_##mod(void) { TektonModuleRegister(&mod); }
#else
    /* Fallback: manual registration required */
    #define TEKTON_DECLARE_MODULE(mod) /* manual call to TektonModuleRegister(&mod) needed */
#endif

#endif /* TEKTON_MODULE_H */
