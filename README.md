# edr-tekton

Composable EDR evasion payload builder. Config-driven, modular C framework that auto-selects optimal technique stacks per target EDR.

## What It Does

edr-tekton takes a target EDR (CrowdStrike, SentinelOne, Defender, etc.) and builds an execution pipeline by selecting the best evasion technique for each detection surface. Instead of hardcoding one bypass chain, it composes modules at runtime based on YAML profiles that encode each EDR's strengths and weaknesses.

**Core idea:** every EDR has a different detection architecture. CrowdStrike is heavy on kernel callbacks and user-mode hooks. Defender relies on ETW and AMSI. Elastic uses open-source YARA rules. The optimal evasion stack is different for each one. edr-tekton encodes that knowledge as config and lets the pipeline builder do the composition.

## Architecture

```
YAML Profile ──> Profile Parser ──> Selector Engine ──> Pipeline Builder ──> Execute
                                         │
                                    Module Registry
                                    (auto-registered)
```

### 8-Stage Pipeline

| # | Stage | Purpose |
|---|-------|---------|
| 0 | **Fingerprint** | Detect target OS, EDR vendor, architecture |
| 1 | **API Resolve** | Resolve NT API addresses (PEB walk, hash, dynamic) |
| 2 | **Evasion Pre** | Patch ETW, AMSI, detect sandboxes, spoof PPID |
| 3 | **Syscall Init** | Set up syscall engine (direct, indirect, tampered) |
| 4 | **Decrypt** | Decrypt payload (XOR, AES-256, RC4, triple-layer) |
| 5 | **Inject** | Execute payload in target process |
| 6 | **Sleep Init** | Encrypt-in-memory sleep obfuscation |
| 7 | **Cleanup** | Wipe traces, restore hooks |

### Module System

Every technique is a self-contained module implementing a vtable interface:

```c
typedef struct _TEKTON_MODULE {
    const char*  name;            // "indirect_syscall", "inject_threadless", etc.
    const char*  description;
    TEKTON_CATEGORY category;
    TEKTON_SURFACE  target_surface;
    DWORD        flags;

    BOOL (*init)(struct _TEKTON_MODULE* self, PTEKTON_CONTEXT ctx);
    BOOL (*execute)(struct _TEKTON_MODULE* self, PTEKTON_CONTEXT ctx);
    VOID (*cleanup)(struct _TEKTON_MODULE* self);
    DWORD (*get_risk_score)(void);
    BOOL  (*check_compat)(PTEKTON_CONTEXT ctx);
} TEKTON_MODULE;
```

Modules auto-register via CRT section tricks (MSVC) or `__attribute__((constructor))` (GCC/Clang):

```c
TEKTON_DECLARE_MODULE(indirect_syscall_module);
```

### Profile-Driven Selection

Each YAML profile declares:
- **Threat levels** per detection surface (user_hooks, kernel_cb, etw, minifilter, scanner, etc.)
- **Primary technique + fallback chain** for each pipeline stage
- **Risk budget** (max cumulative risk score across all selected modules)
- **Constraints** (stealth preference, x64 requirement, minimum OS build)

The selector engine walks each stage, tries the primary module, falls back through alternatives if the primary is unavailable or exceeds the risk budget, and assembles the final pipeline.

## Supported Modules

### API Resolution (4 modules)
- `dynamic_resolve` : GetModuleHandle + GetProcAddress runtime resolution
- `peb_walk` : Zero-import PEB walking (gs:[0x60] / fs:[0x30])
- `hash_resolve` : CRC32B / Djb2 hash-based resolution with forwarded function support
- `peb_sysinfo` : PEB/TEB-based system queries (replaces GetTempPathW, GetEnvironmentVariableW, etc.)

### Syscall Engine (6 modules)
- `direct_syscall` : MASM assembly stubs (mov r10,rcx; mov eax,SSN; syscall)
- `indirect_syscall` : Jump to syscall gadget inside ntdll.dll .text section
- `tampered_syscall` : Hardware breakpoint SSN swap via VEH (@rad9800 technique)
- `ssn_resolve` : Zw* sorting + Hell's Gate / Halo's Gate SSN extraction
- `unhook_ntdll` : Remap clean ntdll from disk, suspended process, or KnownDlls
- `callstack_spoof` : Return address manipulation for clean call stacks

### Encryption (4 modules)
- `encrypt_xor` : Single/multi-byte XOR
- `encrypt_aes` : AES-256-CBC with environment-keyed derivation
- `encrypt_rc4` : RC4 stream cipher with FNV-1a seeding
- `encrypt_triple` : Triple-layer encryption (AES > RC4 > XOR)

### Injection (7 modules)
- `inject_classic` : VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
- `inject_apc` : QueueUserAPC with alertable thread targeting
- `inject_threadless` : Threadless injection via function pointer hijack
- `inject_module_stomp` : Overwrite legitimate DLL .text section
- `inject_callback` : Windows callback execution (EnumWindows, etc.)
- `inject_poolparty` : PoolParty work item variants (worker, timer, wait, I/O)
- Shared utilities: process enumeration, PPID-aware spawning, W^X memory helpers

### Evasion (4 modules)
- `etw_patch` : Patch EtwEventWrite / blind EtwTi providers
- `amsi_patch` : Patch AmsiScanBuffer prologue (multiple methods)
- `sandbox_detect` : 8-category score-based sandbox detection
- `ppid_spoof` : STARTUPINFOEX parent process spoofing

### Anti-Debug (5 modules)
- `antidebug_peb` : PEB.BeingDebugged + NtGlobalFlag detection
- `antidebug_timing` : RDTSC + QueryPerformanceCounter timing checks
- `antidebug_ntquery` : NtQueryInformationProcess (DebugPort, DebugObjectHandle, DebugFlags)
- `antidebug_hwbp` : Debug register Dr0-Dr3 detection
- `antidebug_trap` : INT 2D / trap flag via SEH

### Sleep Obfuscation (4 modules)
- `sleep_ekko` : CreateTimerQueueTimer with ROP chain (RX > RW > encrypt > sleep > decrypt > RX)
- `sleep_foliage` : NtCreateTimer + APC-based with SystemFunction032 RC4
- `sleep_zilean` : NtSetTimer2-based with custom APC chain
- `sleep_beacongate` : Hardware breakpoint hooking of sleep-related APIs

## EDR Profiles

Pre-built profiles in `profiles/`:

| Profile | Primary Evasion Strategy |
|---------|------------------------|
| `crowdstrike.yaml` | Indirect syscalls, threadless inject, foliage sleep, ETW + stack spoof |
| `sentinelone.yaml` | Tampered syscalls, module stomp, zilean sleep, full ETW blind |
| `defender.yaml` | Direct syscalls, APC inject, ekko sleep, AMSI + ETW patch |
| `sophos.yaml` | Indirect syscalls, poolparty inject, foliage sleep, scanner evasion |
| `carbon_black.yaml` | Direct syscalls, APC inject, ekko sleep, PPID spoof priority |
| `elastic.yaml` | Indirect syscalls, threadless inject, foliage sleep, YARA defeat |
| `generic.yaml` | Balanced defaults for unknown EDR |
| `none.yaml` | Minimal evasion for unprotected targets |

### Auto-Detection

edr-tekton can auto-detect the running EDR via three methods:
1. **Process enumeration** : Scan for known EDR process names (40+ signatures)
2. **Loaded DLL check** : Detect EDR hook DLLs in current process
3. **Registry keys** : Check vendor-specific service/driver registry entries

## Building

### Requirements
- **MSVC** (Visual Studio 2019+ or Build Tools) for Windows targets
- **CMake** 3.15+
- Windows 10 SDK

### Build Commands

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Cross-Platform Development

The codebase compiles on Linux for development and testing (non-Windows APIs are stubbed in `types.h`). Actual payload execution requires Windows.

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## Usage

```bash
# Auto-detect EDR, select profile, build + execute pipeline
edr-tekton.exe --auto

# Specify profile explicitly
edr-tekton.exe --profile crowdstrike

# Load profile from YAML file
edr-tekton.exe --profile-file profiles/crowdstrike.yaml

# Dry run (show selected modules without executing)
edr-tekton.exe --profile generic --dry-run

# List registered modules
edr-tekton.exe --list-modules

# List loaded EDR profiles
edr-tekton.exe --list-profiles

# Hash a string (for config/API hashing)
edr-tekton.exe --hash crc32b NtAllocateVirtualMemory

# Verbose / trace logging
edr-tekton.exe --profile defender --verbose
edr-tekton.exe --profile defender --trace
```

## Project Structure

```
edr-tekton/
├── include/tekton/
│   ├── core/           # Framework infrastructure
│   │   ├── types.h     # Common types, error codes, platform stubs
│   │   ├── context.h   # Runtime context, resolved API state
│   │   ├── module.h    # Module vtable interface + auto-registration
│   │   ├── loader.h    # Module loader / dynamic loading
│   │   ├── config.h    # YAML config parser
│   │   ├── profile.h   # EDR profile system + selector engine
│   │   ├── builder.h   # Pipeline builder
│   │   └── log.h       # Logging
│   ├── modules/        # Module-specific types and externs
│   │   ├── api_resolve.h
│   │   ├── syscall.h
│   │   ├── encrypt.h
│   │   ├── inject.h
│   │   ├── evasion.h
│   │   ├── antidebug.h
│   │   └── sleep.h
│   └── util/           # Low-level utilities
│       ├── hash.h      # CRC32B, Djb2, additive, rotating
│       ├── pe.h        # PE parser, export walking, pattern scan
│       ├── peb.h       # PEB/TEB walking
│       └── crypto.h    # XOR, AES-256, RC4, FNV-1a
├── src/
│   ├── core/           # Framework implementation
│   ├── modules/        # Technique implementations
│   │   ├── api_resolve/
│   │   ├── syscall/
│   │   ├── encrypt/
│   │   ├── inject/
│   │   ├── evasion/
│   │   ├── antidebug/
│   │   └── sleep/
│   ├── util/           # Utility implementations
│   └── main.c          # CLI entry point
├── asm/                # Assembly stubs
│   ├── syscall_stubs.asm       # MASM x64 (MSVC)
│   └── syscall_stubs_nasm.asm  # NASM x64 (MinGW/GCC)
├── tests/              # Test suite (126 tests, 5 suites)
│   ├── test_framework.h
│   ├── test_runner.c
│   ├── test_hash.c
│   ├── test_crypto.c
│   ├── test_config.c
│   ├── test_module.c
│   └── test_builder.c
└── profiles/           # YAML EDR profiles
```

## Research References

Built from published offensive security research:
- Zhussupov, "Malware Development for Ethical Hackers"
- Mez0, "Evading EDR" (No Starch Press)
- MalDev Academy modules (94, 98, 99, 112, 118, 132, 134)
- goodboy-framework stages 02-07
- @modexpblog SSN resolution
- @rad9800 tampered syscalls
- @C5pिdr hardware breakpoint hooking
- hasherezade PE-bear/PE-sieve research
- PoolParty (SafeBreach Labs)
- Ekko/Foliage/Zilean sleep research

## Disclaimer

This framework is built for authorized security testing, red team operations, and EDR detection gap research. It is intended for use by security professionals with proper authorization. The techniques implemented are derived entirely from published academic and conference research.

## License

MIT
