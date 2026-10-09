#ifndef TEKTON_TYPES_H
#define TEKTON_TYPES_H

/*
 * edr-tekton :: Core Type Definitions
 * Composable Evasion Payload Builder
 * github.com/hayman-eng/edr-tekton
 */

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
/* Cross-platform stubs for development on Linux */
#include <stddef.h>  /* wchar_t, NULL, size_t */

typedef unsigned long       DWORD;
typedef unsigned long long  QWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;
typedef int                 BOOL;
typedef void*               PVOID;
typedef void*               HANDLE;
typedef void*               HMODULE;
typedef const char*         LPCSTR;
typedef const wchar_t*      LPCWSTR;
typedef char*               LPSTR;
typedef wchar_t*            LPWSTR;
typedef unsigned long long  SIZE_T;
typedef SIZE_T*             PSIZE_T;
typedef long                NTSTATUS;
typedef void                VOID;
typedef PVOID               LPVOID;
typedef unsigned long long  ULONG_PTR;
typedef DWORD*              PDWORD;
typedef unsigned long       ULONG;

#define TRUE  1
#define FALSE 0
#ifndef NULL
#define NULL  ((void*)0)
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40

#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_RELEASE             0x00008000

#define INFINITE                0xFFFFFFFF

/* Process access rights */
#define PROCESS_ALL_ACCESS           0x001FFFFF
#define PROCESS_VM_OPERATION         0x0008
#define PROCESS_VM_READ              0x0010
#define PROCESS_VM_WRITE             0x0020
#define PROCESS_CREATE_THREAD        0x0002
#define PROCESS_QUERY_INFORMATION    0x0400
#define PROCESS_DUP_HANDLE           0x0040

/* Thread creation flags */
#define CREATE_SUSPENDED             0x00000004
#define CREATE_NO_WINDOW             0x08000000

/* Section access */
#define SECTION_ALL_ACCESS           0x000F001F
#define SEC_COMMIT                   0x08000000

/* Wait return values */
#define WAIT_OBJECT_0                0x00000000

/* Thread pool placeholder types */
typedef PVOID PTP_CALLBACK_INSTANCE;
typedef PVOID PTP_WORK;
typedef PVOID PTP_TIMER;
typedef PVOID PTP_WAIT;
typedef PVOID PTP_IO;
typedef PVOID PTP_POOL;
typedef PVOID TP_CALLBACK_ENVIRON;

/* IO_STATUS_BLOCK stub */
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/* LARGE_INTEGER stub */
typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        long  HighPart;
    };
    long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

/* UNICODE_STRING stub */
typedef struct _UNICODE_STRING {
    WORD  Length;
    WORD  MaximumLength;
    LPWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* OBJECT_ATTRIBUTES stub */
typedef struct _OBJECT_ATTRIBUTES {
    DWORD           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    DWORD           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                           \
    (p)->ObjectName = n;                              \
    (p)->Attributes = a;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;              \
}

#endif /* _WIN32 */

/* ── Error Codes ───────────────────────────────────────── */

typedef enum _TEKTON_STATUS {
    TEKTON_OK                   = 0,
    TEKTON_ERR_GENERIC          = 1,
    TEKTON_ERR_ALLOC            = 2,
    TEKTON_ERR_NOT_FOUND        = 3,
    TEKTON_ERR_INVALID_PARAM    = 4,
    TEKTON_ERR_INIT_FAILED      = 5,
    TEKTON_ERR_MODULE_MISSING   = 6,
    TEKTON_ERR_COMPAT_FAIL      = 7,
    TEKTON_ERR_SYSCALL_FAIL     = 8,
    TEKTON_ERR_INJECT_FAIL      = 9,
    TEKTON_ERR_ENCRYPT_FAIL     = 10,
    TEKTON_ERR_CONFIG_PARSE     = 11,
    TEKTON_ERR_PIPELINE_BUILD   = 12,
    TEKTON_ERR_PAYLOAD_LOAD     = 13,
    TEKTON_ERR_UNSUPPORTED      = 14,
    TEKTON_ERR_INVALID_STATE    = 15,
    TEKTON_ERR_API_RESOLVE      = 16,
    TEKTON_ERR_TIMEOUT          = 17,
    TEKTON_ERR_PERMISSION       = 18,
    TEKTON_ERR_OVERFLOW         = 19,
} TEKTON_STATUS;

/* ── Module Categories ────────────────────────────────── */

typedef enum _TEKTON_CATEGORY {
    TEKTON_CAT_API_RESOLVE      = 0,
    TEKTON_CAT_SYSCALL          = 1,
    TEKTON_CAT_ENCRYPT          = 2,
    TEKTON_CAT_INJECT           = 3,
    TEKTON_CAT_EVASION          = 4,
    TEKTON_CAT_ANTIDEBUG        = 5,
    TEKTON_CAT_SLEEP            = 6,
    TEKTON_CAT_MAX              = 7,
} TEKTON_CATEGORY;

/* ── Module Flags ─────────────────────────────────────── */

#define TEKTON_MOD_NONE              0x00000000
#define TEKTON_MOD_REQUIRES_ADMIN    0x00000001
#define TEKTON_MOD_REQUIRES_X64      0x00000002
#define TEKTON_MOD_REQUIRES_WIN10    0x00000004
#define TEKTON_MOD_REQUIRES_WIN11    0x00000008
#define TEKTON_MOD_DESTRUCTIVE       0x00000010  /* Modifies target process */
#define TEKTON_MOD_STEALTHY          0x00000020  /* Low detection risk      */
#define TEKTON_MOD_EXPERIMENTAL      0x00000040  /* Unstable / WIP          */

/* ── Detection Surfaces ───────────────────────────────── */

typedef enum _TEKTON_SURFACE {
    TEKTON_SURFACE_USER_HOOKS   = 0,
    TEKTON_SURFACE_KERNEL_CB    = 1,
    TEKTON_SURFACE_ETW          = 2,
    TEKTON_SURFACE_MINIFILTER   = 3,
    TEKTON_SURFACE_WFP          = 4,
    TEKTON_SURFACE_SCANNER      = 5,
    TEKTON_SURFACE_ELAM         = 6,
    TEKTON_SURFACE_NIRVANA      = 7,
    TEKTON_SURFACE_HYPERVISOR   = 8,
    TEKTON_SURFACE_MAX          = 9,
} TEKTON_SURFACE;

/* ── Payload Buffer ───────────────────────────────────── */

typedef struct _TEKTON_BUFFER {
    BYTE*   data;
    SIZE_T  length;
    SIZE_T  capacity;
} TEKTON_BUFFER, *PTEKTON_BUFFER;

/* ── Forward Declarations ─────────────────────────────── */

typedef struct _TEKTON_MODULE   TEKTON_MODULE,  *PTEKTON_MODULE;
typedef struct _TEKTON_CONTEXT  TEKTON_CONTEXT, *PTEKTON_CONTEXT;
typedef struct _TEKTON_CONFIG   TEKTON_CONFIG,  *PTEKTON_CONFIG;
typedef struct _TEKTON_PIPELINE TEKTON_PIPELINE,*PTEKTON_PIPELINE;

/* ── Utility Macros ───────────────────────────────────── */

#define TEKTON_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define TEKTON_ALIGN_UP(val, align) \
    (((val) + ((align) - 1)) & ~((align) - 1))

#define TEKTON_ZERO(ptr, size) \
    do { volatile BYTE* _p = (volatile BYTE*)(ptr); \
         SIZE_T _n = (size); while (_n--) *_p++ = 0; } while(0)

/* Secure zero that won't be optimized out */
#define TEKTON_SECURE_ZERO(ptr, size) TEKTON_ZERO(ptr, size)

#endif /* TEKTON_TYPES_H */
