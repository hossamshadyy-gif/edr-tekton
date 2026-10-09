#ifndef TEKTON_LOADER_H
#define TEKTON_LOADER_H

/*
 * edr-tekton :: Module Loader
 * Registers built-in modules and loads external ones from DLLs.
 *
 * Built-in modules are compiled into the binary and registered
 * during TektonLoaderRegisterAll().  External modules are packaged
 * as DLLs that export a TEKTON_MODULE struct named
 * "tekton_module_export"; these are loaded at runtime via
 * TektonLoaderLoadExternal().
 *
 * On Linux (dev builds), external loading stubs out because there
 * is no real LoadLibrary/dlopen interop with ntdll.  Built-in
 * registration works the same way on both platforms.
 */

#include "types.h"
#include "module.h"

/* ── Loader State ────────────────────────────────────────── */

#define TEKTON_MAX_EXTERNAL_MODULES 32

typedef struct _TEKTON_LOADER_STATE {
    BOOL    initialized;
    DWORD   builtin_count;      /* Modules registered from built-ins  */
    DWORD   external_count;     /* Modules loaded from external DLLs  */

    /* Track loaded DLL handles so we can free them on cleanup */
    HMODULE external_handles[TEKTON_MAX_EXTERNAL_MODULES];
    char    external_paths[TEKTON_MAX_EXTERNAL_MODULES][260];
} TEKTON_LOADER_STATE, *PTEKTON_LOADER_STATE;

/* ── Loader API ──────────────────────────────────────────── */

/*
 * TektonLoaderInit
 *   Initialize loader internal state.
 *   Call once before any other loader function.
 */
TEKTON_STATUS TektonLoaderInit(void);

/*
 * TektonLoaderRegisterAll
 *   Register every built-in module compiled into the binary.
 *   Calls TektonModuleRegister() for each module struct.
 *
 *   On MSVC/GCC builds with auto-registration macros, the CRT
 *   initializers already ran TektonModuleRegister() for each
 *   TEKTON_DECLARE_MODULE.  This function acts as a fallback
 *   for configurations that lack auto-registration (e.g., the
 *   plain #define fallback), and as the canonical "make sure
 *   everything is registered" call.
 */
TEKTON_STATUS TektonLoaderRegisterAll(void);

/*
 * TektonLoaderLoadExternal
 *   Load a single external module from a DLL (Windows) or shared
 *   object (Linux stub).
 *
 *   On Windows: calls LoadLibraryA(path), finds an exported symbol
 *   named "tekton_module_export" (a TEKTON_MODULE struct), and
 *   registers it via TektonModuleRegister().
 *
 *   On Linux: returns TEKTON_ERR_UNSUPPORTED (dev builds only).
 *
 *   path: Filesystem path to the DLL / .so file.
 */
TEKTON_STATUS TektonLoaderLoadExternal(const char* path);

/*
 * TektonLoaderGetState
 *   Return a pointer to the global loader state for introspection.
 */
PTEKTON_LOADER_STATE TektonLoaderGetState(void);

/*
 * TektonLoaderCleanup
 *   Free all external DLL handles and reset loader state.
 *   Does not unregister built-in modules (they live in .data).
 */
VOID TektonLoaderCleanup(void);

#endif /* TEKTON_LOADER_H */
