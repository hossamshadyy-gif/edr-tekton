/*
 * edr-tekton :: Module Registration & Registry
 */

#include <string.h>
#include "tekton/core/module.h"
#include "tekton/core/log.h"

static TEKTON_MODULE_REGISTRY g_registry = { 0 };

PTEKTON_MODULE_REGISTRY TektonGetRegistry(void) {
    return &g_registry;
}

TEKTON_STATUS TektonModuleRegister(PTEKTON_MODULE mod) {
    if (!mod || !mod->name) {
        TLOG_ERROR("Cannot register NULL module");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (g_registry.count >= TEKTON_MAX_MODULES) {
        TLOG_ERROR("Module registry full (max %d)", TEKTON_MAX_MODULES);
        return TEKTON_ERR_GENERIC;
    }

    /* Check for duplicate */
    PTEKTON_MODULE existing = g_registry.head;
    while (existing) {
        if (strcmp(existing->name, mod->name) == 0) {
            TLOG_WARN("Module '%s' already registered, skipping", mod->name);
            return TEKTON_OK;
        }
        existing = existing->next;
    }

    /* Add to linked list */
    mod->next = g_registry.head;
    g_registry.head = mod;
    g_registry.count++;

    /* Index by category */
    if (mod->category < TEKTON_CAT_MAX) {
        DWORD idx = g_registry.category_count[mod->category];
        if (idx < TEKTON_MAX_MODULES) {
            g_registry.by_category[mod->category][idx] = mod;
            g_registry.category_count[mod->category]++;
        }
    }

    TLOG_DEBUG("Registered module '%s' [cat=%d, ref=%s]",
        mod->name, mod->category, mod->skill_ref ? mod->skill_ref : "none");

    return TEKTON_OK;
}

PTEKTON_MODULE TektonModuleFind(const char* name) {
    if (!name) return NULL;

    PTEKTON_MODULE mod = g_registry.head;
    while (mod) {
        if (strcmp(mod->name, name) == 0) {
            return mod;
        }
        mod = mod->next;
    }

    return NULL;
}

PTEKTON_MODULE TektonModuleFindByRef(const char* skill_ref) {
    if (!skill_ref) return NULL;

    PTEKTON_MODULE mod = g_registry.head;
    while (mod) {
        if (mod->skill_ref && strcmp(mod->skill_ref, skill_ref) == 0) {
            return mod;
        }
        mod = mod->next;
    }

    return NULL;
}

DWORD TektonModuleList(
    TEKTON_CATEGORY category,
    PTEKTON_MODULE* out_modules,
    DWORD           max_count
) {
    if (category >= TEKTON_CAT_MAX || !out_modules) return 0;

    DWORD count = g_registry.category_count[category];
    if (count > max_count) count = max_count;

    for (DWORD i = 0; i < count; i++) {
        out_modules[i] = g_registry.by_category[category][i];
    }

    return count;
}
