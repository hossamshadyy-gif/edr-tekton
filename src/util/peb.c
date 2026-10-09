/*
 * edr-tekton :: PEB/TEB Walking
 * Cat 1.2 (PEB-Walking), 1.5 (PEB System Queries), 1.6 (TEB Access).
 */

#include <string.h>
#include <stdlib.h>
#include "tekton/util/peb.h"
#include "tekton/core/log.h"

/* ── PEB Access ──────────────────────────────────────────── */

PVOID TektonPebGet(void) {
#if defined(_WIN64)
    /* gs:[0x60] on x64 */
    PVOID peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
#elif defined(_WIN32)
    /* fs:[0x30] on x86 */
    PVOID peb;
    __asm__ volatile ("mov %%fs:0x30, %0" : "=r"(peb));
    return peb;
#elif defined(_MSC_VER) && defined(_M_X64)
    return (PVOID)__readgsqword(0x60);
#elif defined(_MSC_VER) && defined(_M_IX86)
    return (PVOID)__readfsdword(0x30);
#else
    /* Non-Windows dev stub */
    TLOG_DEBUG("PEB access not available on non-Windows");
    return NULL;
#endif
}

/* ── Module enumeration via PEB ──────────────────────────── */

/* Case-insensitive wide string compare (no wcsicmp dependency) */
static BOOL wstr_iequal(const wchar_t* a, const wchar_t* b) {
    if (!a || !b) return FALSE;
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (*a + 32) : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (*b + 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == *b);
}

PVOID TektonPebGetModuleBase(const wchar_t* dll_name) {
    if (!dll_name) return NULL;

#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb || !peb->Ldr) return NULL;

    /* Walk InLoadOrderModuleList */
    LIST_ENTRY_T* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY_T* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY_T* ldr_entry = (LDR_DATA_TABLE_ENTRY_T*)entry;

        if (ldr_entry->BaseDllName.Buffer && ldr_entry->BaseDllName.Length > 0) {
            if (wstr_iequal(ldr_entry->BaseDllName.Buffer, dll_name)) {
                return ldr_entry->DllBase;
            }
        }

        entry = entry->Flink;
    }

    return NULL;
#else
    TLOG_DEBUG("PEB module walk not available on non-Windows");
    (void)dll_name;
    return NULL;
#endif
}

PVOID TektonPebGetModuleBaseByHash(
    DWORD               dll_name_hash,
    TEKTON_HASH_FUNC_W  hash_func
) {
    if (!hash_func) return NULL;

#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY_T* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY_T* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY_T* ldr_entry = (LDR_DATA_TABLE_ENTRY_T*)entry;

        if (ldr_entry->BaseDllName.Buffer && ldr_entry->BaseDllName.Length > 0) {
            DWORD hash = hash_func(ldr_entry->BaseDllName.Buffer);
            if (hash == dll_name_hash) {
                return ldr_entry->DllBase;
            }
        }

        entry = entry->Flink;
    }

    return NULL;
#else
    TLOG_DEBUG("PEB module hash walk not available on non-Windows");
    (void)dll_name_hash;
    return NULL;
#endif
}

/* ── TEB Access (Cat 1.6) ────────────────────────────────── */

DWORD TektonTebGetProcessId(void) {
#if defined(_WIN64) && defined(_MSC_VER)
    return __readgsdword(0x40);
#elif defined(_WIN32) && defined(_MSC_VER)
    return __readfsdword(0x20);
#elif defined(_WIN64)
    DWORD pid;
    __asm__ volatile ("mov %%gs:0x40, %0" : "=r"(pid));
    return pid;
#elif defined(_WIN32)
    DWORD pid;
    __asm__ volatile ("mov %%fs:0x20, %0" : "=r"(pid));
    return pid;
#else
    return 0;
#endif
}

DWORD TektonTebGetThreadId(void) {
#if defined(_WIN64) && defined(_MSC_VER)
    return __readgsdword(0x48);
#elif defined(_WIN32) && defined(_MSC_VER)
    return __readfsdword(0x24);
#elif defined(_WIN64)
    DWORD tid;
    __asm__ volatile ("mov %%gs:0x48, %0" : "=r"(tid));
    return tid;
#elif defined(_WIN32)
    DWORD tid;
    __asm__ volatile ("mov %%fs:0x24, %0" : "=r"(tid));
    return tid;
#else
    return 0;
#endif
}

/* ── PEB-Based System Queries (Cat 1.5) ──────────────────── */

/* Walk the environment block for a variable */
BOOL TektonPebGetEnvVar(
    const wchar_t*  var_name,
    wchar_t*        out_buffer,
    DWORD           buffer_size
) {
    if (!var_name || !out_buffer || buffer_size == 0) return FALSE;

#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb || !peb->ProcessParameters) return FALSE;

    wchar_t* env = (wchar_t*)peb->ProcessParameters->Environment;
    if (!env) return FALSE;

    SIZE_T var_len = 0;
    const wchar_t* p = var_name;
    while (*p++) var_len++;

    /* Walk null-terminated entries (double-null terminated block) */
    while (*env) {
        /* Check if this entry starts with var_name= */
        BOOL match = TRUE;
        for (SIZE_T i = 0; i < var_len; i++) {
            wchar_t a = env[i];
            wchar_t b = var_name[i];
            /* Case-insensitive */
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { match = FALSE; break; }
        }

        if (match && env[var_len] == L'=') {
            /* Found it, copy value */
            const wchar_t* value = env + var_len + 1;
            DWORD i = 0;
            while (value[i] && i < buffer_size - 1) {
                out_buffer[i] = value[i];
                i++;
            }
            out_buffer[i] = L'\0';
            return TRUE;
        }

        /* Skip to next entry */
        while (*env) env++;
        env++;
    }

    return FALSE;
#else
    (void)var_name; (void)out_buffer; (void)buffer_size;
    return FALSE;
#endif
}

BOOL TektonPebGetTempPath(wchar_t* out_buffer, DWORD buffer_size) {
    /* Try TMP first, then TEMP */
    if (TektonPebGetEnvVar(L"TMP", out_buffer, buffer_size)) return TRUE;
    if (TektonPebGetEnvVar(L"TEMP", out_buffer, buffer_size)) return TRUE;
    return FALSE;
}

BOOL TektonPebGetCurrentDir(wchar_t* out_buffer, DWORD buffer_size) {
    if (!out_buffer || buffer_size == 0) return FALSE;

#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb || !peb->ProcessParameters) return FALSE;

    UNICODE_STRING_T* dos_path = &peb->ProcessParameters->CurrentDirectory.DosPath;
    if (!dos_path->Buffer || dos_path->Length == 0) return FALSE;

    DWORD chars = dos_path->Length / sizeof(wchar_t);
    if (chars >= buffer_size) chars = buffer_size - 1;

    for (DWORD i = 0; i < chars; i++) {
        out_buffer[i] = dos_path->Buffer[i];
    }
    out_buffer[chars] = L'\0';
    return TRUE;
#else
    (void)out_buffer; (void)buffer_size;
    return FALSE;
#endif
}

const wchar_t* TektonPebGetCommandLine(void) {
#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb || !peb->ProcessParameters) return NULL;
    return peb->ProcessParameters->CommandLine.Buffer;
#else
    return NULL;
#endif
}

DWORD TektonPebGetProcessorCount(void) {
#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb) return 1;

    /* NumberOfProcessors is at offset 0xB8 (x64) / 0x64 (x86) */
#if defined(_WIN64)
    return *(DWORD*)((BYTE*)peb + 0xB8);
#else
    return *(DWORD*)((BYTE*)peb + 0x64);
#endif

#else
    return 1;
#endif
}

BOOL TektonPebIsBeingDebugged(void) {
#ifdef _WIN32
    PEB_T* peb = (PEB_T*)TektonPebGet();
    if (!peb) return FALSE;
    return peb->BeingDebugged;
#else
    return FALSE;
#endif
}
