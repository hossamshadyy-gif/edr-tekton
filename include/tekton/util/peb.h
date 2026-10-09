#ifndef TEKTON_PEB_H
#define TEKTON_PEB_H

/*
 * edr-tekton :: PEB/TEB Walking Helpers
 * Cat 1.2, 1.5, 1.6, 1.7 from technique library.
 * Direct PEB access for API resolution without imports.
 */

#include "../core/types.h"

/* ── PEB Structures (undocumented) ────────────────────── */

#ifndef _WIN32

typedef struct _UNICODE_STRING_T {
    WORD    Length;
    WORD    MaximumLength;
    LPWSTR  Buffer;
} UNICODE_STRING_T, *PUNICODE_STRING_T;

typedef struct _LIST_ENTRY_T {
    struct _LIST_ENTRY_T *Flink;
    struct _LIST_ENTRY_T *Blink;
} LIST_ENTRY_T;

typedef struct _PEB_LDR_DATA_T {
    DWORD           Length;
    BOOL            Initialized;
    PVOID           SsHandle;
    LIST_ENTRY_T    InLoadOrderModuleList;
    LIST_ENTRY_T    InMemoryOrderModuleList;
    LIST_ENTRY_T    InInitializationOrderModuleList;
} PEB_LDR_DATA_T, *PPEB_LDR_DATA_T;

typedef struct _LDR_DATA_TABLE_ENTRY_T {
    LIST_ENTRY_T        InLoadOrderLinks;
    LIST_ENTRY_T        InMemoryOrderLinks;
    LIST_ENTRY_T        InInitializationOrderLinks;
    PVOID               DllBase;
    PVOID               EntryPoint;
    DWORD               SizeOfImage;
    UNICODE_STRING_T    FullDllName;
    UNICODE_STRING_T    BaseDllName;
    /* ... more fields we don't need */
} LDR_DATA_TABLE_ENTRY_T, *PLDR_DATA_TABLE_ENTRY_T;

typedef struct _CURDIR_T {
    UNICODE_STRING_T    DosPath;
    PVOID               Handle;
} CURDIR_T;

typedef struct _RTL_USER_PROCESS_PARAMETERS_T {
    DWORD               MaximumLength;
    DWORD               Length;
    DWORD               Flags;
    DWORD               DebugFlags;
    PVOID               ConsoleHandle;
    DWORD               ConsoleFlags;
    PVOID               StandardInput;
    PVOID               StandardOutput;
    PVOID               StandardError;
    CURDIR_T            CurrentDirectory;
    UNICODE_STRING_T    DllPath;
    UNICODE_STRING_T    ImagePathName;
    UNICODE_STRING_T    CommandLine;
    PVOID               Environment;
    /* ... more fields */
} RTL_USER_PROCESS_PARAMETERS_T, *PRTL_USER_PROCESS_PARAMETERS_T;

typedef struct _PEB_T {
    BYTE                        InheritedAddressSpace;
    BYTE                        ReadImageFileExecOptions;
    BYTE                        BeingDebugged;
    BYTE                        BitField;
    BYTE                        Padding0[4];
    PVOID                       Mutant;
    PVOID                       ImageBaseAddress;
    PPEB_LDR_DATA_T             Ldr;
    PRTL_USER_PROCESS_PARAMETERS_T ProcessParameters;
    /* ... offset 0xB8 (x64) = NumberOfProcessors */
} PEB_T, *PPEB_T;

#endif /* !_WIN32 */

/* ── PEB Access ───────────────────────────────────────── */

/* Get PEB pointer (inline asm for x64/x86) */
PVOID TektonPebGet(void);

/* Get module base by walking PEB InLoadOrderModuleList */
PVOID TektonPebGetModuleBase(const wchar_t* dll_name);

/* Get module base by hash (case-insensitive DLL name hash) */
typedef DWORD (*TEKTON_HASH_FUNC_W)(const wchar_t*);
PVOID TektonPebGetModuleBaseByHash(
    DWORD               dll_name_hash,
    TEKTON_HASH_FUNC_W  hash_func
);

/* ── TEB Access (Cat 1.6) ─────────────────────────────── */

/* Get current process ID without GetCurrentProcessId import */
DWORD TektonTebGetProcessId(void);

/* Get current thread ID without GetCurrentThreadId import */
DWORD TektonTebGetThreadId(void);

/* ── PEB-Based System Queries (Cat 1.5) ───────────────── */

/* Get environment variable from PEB ProcessParameters */
BOOL TektonPebGetEnvVar(
    const wchar_t*  var_name,
    wchar_t*        out_buffer,
    DWORD           buffer_size
);

/* Get TEMP path from PEB environment */
BOOL TektonPebGetTempPath(wchar_t* out_buffer, DWORD buffer_size);

/* Get current directory from PEB ProcessParameters */
BOOL TektonPebGetCurrentDir(wchar_t* out_buffer, DWORD buffer_size);

/* Get command line from PEB ProcessParameters */
const wchar_t* TektonPebGetCommandLine(void);

/* Get processor count from PEB */
DWORD TektonPebGetProcessorCount(void);

/* Check if being debugged (PEB.BeingDebugged) */
BOOL TektonPebIsBeingDebugged(void);

#endif /* TEKTON_PEB_H */
