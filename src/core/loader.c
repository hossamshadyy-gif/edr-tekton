/*
 * edr-tekton :: Module Loader Implementation
 *
 * Responsibilities:
 *   1. Register all built-in modules compiled into the binary.
 *   2. Load external modules from DLLs at runtime.
 *   3. Track loaded DLL handles for orderly cleanup.
 *
 * On Windows, external modules are standard DLLs that export a
 * TEKTON_MODULE struct named "tekton_module_export".  The loader
 * calls LoadLibraryA to map the DLL, GetProcAddress to find the
 * export, and TektonModuleRegister to plug it into the registry.
 *
 * On Linux (dev builds), built-in registration works identically
 * but external DLL loading stubs out.
 */

#include "tekton/core/loader.h"
#include "tekton/core/log.h"
#include <string.h>

/* ── Extern references to all built-in module structs ──────── */

/* Category 1: API Resolution (Cat 1.*) */
extern TEKTON_MODULE tekton_mod_dynamic_resolve;    /* Cat 1.1  */
extern TEKTON_MODULE tekton_mod_peb_walk;           /* Cat 1.2  */
extern TEKTON_MODULE tekton_mod_hash_resolve;       /* Cat 1.3+ */
extern TEKTON_MODULE tekton_mod_peb_sysinfo;        /* Cat 1.5  */

/* Category 2: Syscall (Cat 2.*) */
extern TEKTON_MODULE tekton_mod_direct_syscall;     /* Cat 2.1  */
extern TEKTON_MODULE tekton_mod_indirect_syscall;   /* Cat 2.4  */
extern TEKTON_MODULE tekton_mod_tampered_syscall;   /* Cat 2.14 */
extern TEKTON_MODULE tekton_mod_unhook_disk;        /* Cat 2.5  */
extern TEKTON_MODULE tekton_mod_unhook_suspended;   /* Cat 2.6  */
extern TEKTON_MODULE tekton_mod_unhook_knowndlls;   /* Cat 2.13 */
extern TEKTON_MODULE tekton_mod_callstack_spoof;    /* Cat 44.2 */

/* Category 3: Encryption (Cat 3.*) */
extern TEKTON_MODULE tekton_mod_xor_encrypt;        /* Cat 3.1  */
extern TEKTON_MODULE tekton_mod_aes_encrypt;        /* Cat 3.2  */
extern TEKTON_MODULE tekton_mod_rc4_encrypt;        /* Cat 3.3  */
extern TEKTON_MODULE tekton_mod_triple_encrypt;     /* Cat 3.4  */

/* Category 4: Injection (Cat 4.*) */
extern TEKTON_MODULE tekton_mod_classic_inject;     /* Cat 4.1  */
extern TEKTON_MODULE tekton_mod_apc_inject;         /* Cat 4.2  */
extern TEKTON_MODULE tekton_mod_threadless_inject;  /* Cat 4.7  */
extern TEKTON_MODULE tekton_mod_module_stomp;       /* Cat 4.6  */
extern TEKTON_MODULE tekton_mod_callback_inject;    /* Cat 4.4  */
extern TEKTON_MODULE tekton_mod_poolparty_inject;   /* Cat 4.9  */

/* Category 5: Evasion (Cat 5.*, 6.*, 7.*) */
extern TEKTON_MODULE tekton_mod_etw_patch;          /* Cat 5.1  */
extern TEKTON_MODULE tekton_mod_amsi_patch;         /* Cat 5.2  */
extern TEKTON_MODULE tekton_mod_sandbox_detect;     /* Cat 7.1  */
extern TEKTON_MODULE tekton_mod_ppid_spoof;         /* Cat 6.1  */

/* Category 6: Sleep obfuscation (Cat 8.*) */
extern TEKTON_MODULE tekton_mod_ekko;               /* Cat 8.1  */
extern TEKTON_MODULE tekton_mod_foliage;            /* Cat 8.2  */
extern TEKTON_MODULE tekton_mod_zilean;             /* Cat 8.3  */
extern TEKTON_MODULE tekton_mod_beacongate;         /* Cat 8.4  */

/* ── Built-in module table ─────────────────────────────────── */
/*
 * Central list of all built-in modules.  TektonLoaderRegisterAll()
 * iterates this array and calls TektonModuleRegister() for each.
 *
 * If TEKTON_DECLARE_MODULE auto-registration already ran via CRT
 * initializers or __attribute__((constructor)), TektonModuleRegister()
 * silently skips duplicates, so calling this is always safe.
 */

static PTEKTON_MODULE g_builtin_modules[] = {
    /* API Resolution */
    &tekton_mod_dynamic_resolve,
    &tekton_mod_peb_walk,
    &tekton_mod_hash_resolve,
    &tekton_mod_peb_sysinfo,

    /* Syscall */
    &tekton_mod_direct_syscall,
    &tekton_mod_indirect_syscall,
    &tekton_mod_tampered_syscall,
    &tekton_mod_unhook_disk,
    &tekton_mod_unhook_suspended,
    &tekton_mod_unhook_knowndlls,
    &tekton_mod_callstack_spoof,

    /* Encryption */
    &tekton_mod_xor_encrypt,
    &tekton_mod_aes_encrypt,
    &tekton_mod_rc4_encrypt,
    &tekton_mod_triple_encrypt,

    /* Injection */
    &tekton_mod_classic_inject,
    &tekton_mod_apc_inject,
    &tekton_mod_threadless_inject,
    &tekton_mod_module_stomp,
    &tekton_mod_callback_inject,
    &tekton_mod_poolparty_inject,

    /* Evasion */
    &tekton_mod_etw_patch,
    &tekton_mod_amsi_patch,
    &tekton_mod_sandbox_detect,
    &tekton_mod_ppid_spoof,

    /* Sleep obfuscation */
    &tekton_mod_ekko,
    &tekton_mod_foliage,
    &tekton_mod_zilean,
    &tekton_mod_beacongate,
};

#define BUILTIN_MODULE_COUNT \
    (sizeof(g_builtin_modules) / sizeof(g_builtin_modules[0]))

/* ── Global loader state ───────────────────────────────────── */

static TEKTON_LOADER_STATE g_loader = { 0 };

/* ── Loader API Implementation ─────────────────────────────── */

TEKTON_STATUS TektonLoaderInit(void) {
    if (g_loader.initialized) {
        TLOG_WARN("loader: already initialized");
        return TEKTON_OK;
    }

    memset(&g_loader, 0, sizeof(g_loader));
    g_loader.initialized = TRUE;

    TLOG_DEBUG("loader: initialized (built-in modules available: %lu)",
        (unsigned long)BUILTIN_MODULE_COUNT);

    return TEKTON_OK;
}

TEKTON_STATUS TektonLoaderRegisterAll(void) {
    if (!g_loader.initialized) {
        TEKTON_STATUS st = TektonLoaderInit();
        if (st != TEKTON_OK) return st;
    }

    DWORD registered = 0;
    DWORD skipped    = 0;

    for (DWORD i = 0; i < BUILTIN_MODULE_COUNT; i++) {
        PTEKTON_MODULE mod = g_builtin_modules[i];
        if (!mod || !mod->name) {
            TLOG_WARN("loader: NULL entry at index %lu, skipping",
                (unsigned long)i);
            skipped++;
            continue;
        }

        TEKTON_STATUS st = TektonModuleRegister(mod);
        if (st == TEKTON_OK) {
            registered++;
        } else {
            TLOG_WARN("loader: failed to register '%s' (status=%d)",
                mod->name, st);
            skipped++;
        }
    }

    g_loader.builtin_count = registered;

    TLOG_INFO("loader: registered %lu built-in modules (%lu skipped/duplicate)",
        (unsigned long)registered, (unsigned long)skipped);

    return (registered > 0) ? TEKTON_OK : TEKTON_ERR_INIT_FAILED;
}

TEKTON_STATUS TektonLoaderLoadExternal(const char* path) {
    if (!path || path[0] == '\0') {
        TLOG_ERROR("loader: NULL or empty path");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (!g_loader.initialized) {
        TLOG_ERROR("loader: not initialized, call TektonLoaderInit() first");
        return TEKTON_ERR_INVALID_STATE;
    }

    if (g_loader.external_count >= TEKTON_MAX_EXTERNAL_MODULES) {
        TLOG_ERROR("loader: external module limit reached (%d)",
            TEKTON_MAX_EXTERNAL_MODULES);
        return TEKTON_ERR_OVERFLOW;
    }

#ifdef _WIN32
    /*
     * Windows: Load the DLL and find the exported module struct.
     *
     * The DLL must export a TEKTON_MODULE struct with the symbol name
     * "tekton_module_export".  Example DLL code:
     *
     *   __declspec(dllexport) TEKTON_MODULE tekton_module_export = {
     *       .name = "my_custom_module",
     *       .category = TEKTON_CAT_EVASION,
     *       ...
     *   };
     */

    HMODULE hDll = LoadLibraryA(path);
    if (!hDll) {
        DWORD err = GetLastError();
        TLOG_ERROR("loader: LoadLibraryA('%s') failed (err=%lu)",
            path, (unsigned long)err);
        return TEKTON_ERR_PAYLOAD_LOAD;
    }

    /* Look for the canonical export name */
    PTEKTON_MODULE mod = (PTEKTON_MODULE)GetProcAddress(hDll, "tekton_module_export");
    if (!mod) {
        TLOG_ERROR("loader: DLL '%s' has no 'tekton_module_export' symbol", path);
        FreeLibrary(hDll);
        return TEKTON_ERR_NOT_FOUND;
    }

    /* Basic sanity checks before trusting the struct */
    if (!mod->name || !mod->init || !mod->execute) {
        TLOG_ERROR("loader: DLL '%s' export is malformed (missing name/init/execute)",
            path);
        FreeLibrary(hDll);
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (mod->category >= TEKTON_CAT_MAX) {
        TLOG_ERROR("loader: DLL '%s' module '%s' has invalid category %d",
            path, mod->name, mod->category);
        FreeLibrary(hDll);
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Register into the module registry */
    TEKTON_STATUS st = TektonModuleRegister(mod);
    if (st != TEKTON_OK) {
        TLOG_ERROR("loader: failed to register external module '%s'", mod->name);
        FreeLibrary(hDll);
        return st;
    }

    /* Track the handle for cleanup */
    DWORD idx = g_loader.external_count;
    g_loader.external_handles[idx] = hDll;

    /* Store the path for diagnostics (truncate if necessary) */
    SIZE_T path_len = strlen(path);
    if (path_len >= sizeof(g_loader.external_paths[idx])) {
        path_len = sizeof(g_loader.external_paths[idx]) - 1;
    }
    memcpy(g_loader.external_paths[idx], path, path_len);
    g_loader.external_paths[idx][path_len] = '\0';

    g_loader.external_count++;

    TLOG_INFO("loader: loaded external module '%s' from '%s'",
        mod->name, path);

    return TEKTON_OK;

#else
    /* Linux dev stub: external DLL loading is Windows-only */
    TLOG_WARN("loader: external module loading not supported on this platform");
    TLOG_WARN("loader: path='%s' (ignored)", path);

    (void)path;
    return TEKTON_ERR_UNSUPPORTED;
#endif
}

PTEKTON_LOADER_STATE TektonLoaderGetState(void) {
    return &g_loader;
}

VOID TektonLoaderCleanup(void) {
    if (!g_loader.initialized) {
        return;
    }

#ifdef _WIN32
    /* Free all loaded external DLLs */
    for (DWORD i = 0; i < g_loader.external_count; i++) {
        if (g_loader.external_handles[i]) {
            TLOG_DEBUG("loader: unloading external module '%s'",
                g_loader.external_paths[i]);
            FreeLibrary(g_loader.external_handles[i]);
            g_loader.external_handles[i] = NULL;
        }
    }
#endif

    TLOG_INFO("loader: cleanup complete (freed %lu external modules)",
        (unsigned long)g_loader.external_count);

    /* Zero out state, including paths (may contain filesystem info) */
    TEKTON_SECURE_ZERO(&g_loader, sizeof(g_loader));
}
