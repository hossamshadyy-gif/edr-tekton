# edr-tekton Architecture

## Directory Structure

```
edr-tekton/
├── CMakeLists.txt                  # Top-level CMake build
├── README.md                       # Project overview + usage
├── LICENSE                         # MIT
├── .gitignore
├── profiles/                       # EDR-specific YAML configs
│   ├── crowdstrike.yaml
│   ├── sentinelone.yaml
│   ├── defender.yaml
│   └── generic.yaml
├── include/
│   └── tekton/
│       ├── core/
│       │   ├── types.h             # Common types, error codes, macros
│       │   ├── config.h            # YAML config parser interface
│       │   ├── module.h            # Module interface (vtable pattern)
│       │   ├── loader.h            # Module loader / registry
│       │   ├── builder.h           # Pipeline builder (chains modules)
│       │   ├── context.h           # Runtime context (target info, flags)
│       │   └── log.h               # Debug/operational logging
│       ├── modules/
│       │   ├── api_resolve.h       # Cat 1: API resolution strategies
│       │   ├── syscall.h           # Cat 2,44,45: Syscall engine
│       │   ├── encrypt.h           # Cat 3: Payload encryption
│       │   ├── inject.h            # Cat 4,5,46: Injection methods
│       │   ├── evasion.h           # Cat 6,7,10,48,50: Evasion techniques
│       │   ├── antidebug.h         # Cat 8: Anti-analysis
│       │   └── sleep.h            # Cat 47,50: Sleep obfuscation
│       └── util/
│           ├── pe.h                # PE parser utilities
│           ├── peb.h               # PEB walking helpers
│           ├── hash.h              # Hashing algorithms (CRC32B, Djb2, etc)
│           ├── crypto.h            # XOR, AES, RC4 primitives
│           └── winternl.h          # NT internal structures
├── src/
│   ├── core/
│   │   ├── config.c                # YAML profile parser
│   │   ├── module.c                # Module registration + lifecycle
│   │   ├── loader.c                # Dynamic module loading
│   │   ├── builder.c               # Pipeline construction
│   │   ├── context.c               # Environment fingerprinting
│   │   └── log.c                   # Logging implementation
│   ├── modules/
│   │   ├── api_resolve/
│   │   │   ├── dynamic.c           # Cat 1.1: GetModuleHandle+GetProcAddress
│   │   │   ├── peb_walk.c          # Cat 1.2: PEB walking
│   │   │   ├── hash_resolve.c      # Cat 1.3,1.8: Hash-based resolution
│   │   │   └── peb_sysinfo.c       # Cat 1.5-1.7: PEB/TEB system queries
│   │   ├── syscall/
│   │   │   ├── direct.c            # Cat 2.1: Direct syscalls (MASM stubs)
│   │   │   ├── indirect.c          # Cat 2.4: Indirect syscalls
│   │   │   ├── ssn_resolve.c       # Cat 2.2,2.3,45: SSN resolution methods
│   │   │   ├── unhook.c            # Cat 2.5,2.6,2.13: ntdll unhooking
│   │   │   ├── callstack.c         # Cat 44: Call stack spoofing
│   │   │   └── tampered.c          # Cat 2.14,45: Tampered/gate syscalls
│   │   ├── encrypt/
│   │   │   ├── xor.c               # Cat 3.1: XOR encryption
│   │   │   ├── aes.c               # Cat 3.2: AES-256
│   │   │   ├── rc4.c               # Cat 3.3: RC4 stream cipher
│   │   │   └── triple.c            # Cat 3.4: Triple encryption chain
│   │   ├── inject/
│   │   │   ├── classic.c           # Cat 4: Standard injection (VirtualAllocEx)
│   │   │   ├── apc.c               # Cat 5: APC injection
│   │   │   ├── threadless.c        # Cat 5.x: Threadless injection
│   │   │   ├── module_stomp.c      # Cat 5.x: Module stomping
│   │   │   ├── poolparty.c         # Cat 46: PoolParty variants
│   │   │   └── callback.c          # Cat 4.x: Callback-based execution
│   │   ├── evasion/
│   │   │   ├── etw.c               # Cat 6: ETW patching/blinding
│   │   │   ├── amsi.c              # Cat 7,48: AMSI bypass
│   │   │   ├── sandbox.c           # Cat 10: Anti-sandbox/analysis
│   │   │   └── ppid_spoof.c        # Cat 9: PPID spoofing
│   │   ├── antidebug/
│   │   │   ├── peb_check.c         # Cat 8.1: PEB.BeingDebugged + NtGlobalFlag
│   │   │   ├── timing_check.c      # Cat 8.2: RDTSC + QPC timing detection
│   │   │   ├── ntquery.c           # Cat 8.3: NtQueryInformationProcess
│   │   │   ├── hardware_bp.c       # Cat 8.4: Debug register Dr0-Dr3 check
│   │   │   └── trap_flag.c         # Cat 8.5: INT 2D / trap flag via SEH
│   │   └── sleep/
│   │       ├── ekko.c              # Cat 50: Ekko sleep obfuscation
│   │       ├── foliage.c           # Cat 50: Foliage timer-based
│   │       ├── zilean.c            # Cat 50: Zilean APC-based
│   │       └── beacongate.c        # Cat 47: BeaconGate architecture
│   ├── util/
│   │   ├── pe.c
│   │   ├── peb.c
│   │   ├── hash.c
│   │   └── crypto.c
│   └── main.c                      # CLI entry point
├── asm/
│   ├── syscall_stubs.asm           # MASM syscall stubs (x64)
│   └── syscall_stubs_nasm.asm      # NASM equivalent (MinGW/GCC)
└── tests/
    ├── test_framework.h            # Minimal test macros (ASSERT_*, RUN_TEST)
    ├── test_runner.c               # Main runner (5 suites)
    ├── test_hash.c                 # 32 tests: CRC32B, DJB2, additive, rotating
    ├── test_crypto.c               # 28 tests: XOR, RC4, AES, FNV-1a, triple
    ├── test_config.c               # 26 tests: YAML parser, dotted-path queries
    ├── test_module.c               # 20 tests: registration, find, category listing
    └── test_builder.c              # 20 tests: pipeline build, dry-run, execute
```

## Module Interface (vtable pattern)

```c
typedef struct _TEKTON_MODULE {
    const char*         name;            // "peb_walk", "indirect_syscall", etc.
    const char*         description;     // Human-readable description
    const char*         skill_ref;       // Skill reference ("1.2", "2.4", etc.)
    TEKTON_CATEGORY     category;        // Enum: API_RESOLVE, SYSCALL, etc.
    TEKTON_SURFACE      target_surface;  // Detection surface this module targets
    DWORD               flags;           // TEKTON_MOD_REQUIRES_ADMIN, STEALTHY, etc.

    // Lifecycle (returns TEKTON_STATUS)
    TEKTON_STATUS (*init)(struct _TEKTON_MODULE* self, PTEKTON_CONTEXT ctx);
    TEKTON_STATUS (*execute)(struct _TEKTON_MODULE* self, PTEKTON_CONTEXT ctx);
    VOID          (*cleanup)(struct _TEKTON_MODULE* self);

    // Introspection
    DWORD (*get_risk_score)(struct _TEKTON_MODULE* self);       // 0-100
    BOOL  (*check_compat)(struct _TEKTON_MODULE* self,
                          PTEKTON_CONTEXT ctx);                 // Runtime check

    // Internal
    PVOID               private_data;
    struct _TEKTON_MODULE* next;         // Registry linked list
} TEKTON_MODULE, *PTEKTON_MODULE;
```

## Pipeline Builder

The builder chains modules in the correct execution order:
1. Environment fingerprint (context)
2. API resolution setup
3. Pre-execution evasion (ETW, AMSI, anti-debug)
4. Syscall engine initialization
5. Payload decryption
6. Injection execution
7. Sleep obfuscation (post-inject, for beacons)
8. Cleanup

## Config Schema (YAML)

```yaml
profile: crowdstrike
version: "2024.1"

target:
  edr: crowdstrike
  os_build: 19045
  arch: x64

pipeline:
  api_resolve: peb_walk          # Cat 1.2
  syscall:
    method: indirect             # Cat 2.4
    ssn_resolve: hells_gate      # Cat 2.3
    callstack: silentmoonwalk    # Cat 44.2
  encrypt:
    layers:
      - { type: aes256, key_source: env }
      - { type: rc4, key_source: static }
      - { type: xor }
  inject:
    method: poolparty_worker     # Cat 46.1
    target_process: explorer.exe
  evasion:
    etw: patch_etw_event_write   # Cat 6.1
    amsi: patch_amsi_scan_buffer # Cat 7.1
    sandbox:
      checks: [timing, username, disk_size]
  sleep:
    method: foliage              # Cat 50
    interval_ms: 30000

payload:
  source: shellcode.bin
  format: raw
```

## Build System

CMake with MSVC toolchain (required for MASM `.asm` integration):
- Release builds with /O2, no debug symbols
- Static linking (/MT) for standalone binaries
- x64 only (primary target)
- Optional: MinGW cross-compile from Linux (no MASM, uses NASM)
