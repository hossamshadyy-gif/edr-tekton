cmake_minimum_required(VERSION 3.15)
project(edr-tekton C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Platform detection ---
if(WIN32)
    add_definitions(-D_WIN32 -DWIN32_LEAN_AND_MEAN -DUNICODE -D_UNICODE)
    if(MSVC)
        # Static CRT, optimize, disable warnings for Windows internals
        set(CMAKE_C_FLAGS_RELEASE "/MT /O2 /DNDEBUG")
        set(CMAKE_C_FLAGS_DEBUG "/MTd /Od /Zi /DDEBUG")
        add_compile_options(/W3 /wd4996 /wd4100)
    endif()
else()
    # Linux/macOS dev build (stubs, no execution)
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-function)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0 -DDEBUG)
    else()
        add_compile_options(-O2 -DNDEBUG)
    endif()
endif()

# --- Include paths ---
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- Core library ---
set(CORE_SOURCES
    src/core/log.c
    src/core/module.c
    src/core/context.c
    src/core/config.c
    src/core/profile.c
    src/core/builder.c
    src/core/loader.c
)

# --- Utility library ---
set(UTIL_SOURCES
    src/util/hash.c
    src/util/pe.c
    src/util/peb.c
    src/util/crypto.c
)

# --- Module sources ---
set(MODULE_SOURCES
    # API Resolution
    src/modules/api_resolve/dynamic.c
    src/modules/api_resolve/peb_walk.c
    src/modules/api_resolve/hash_resolve.c
    src/modules/api_resolve/peb_sysinfo.c

    # Syscall engine
    src/modules/syscall/ssn_resolve.c
    src/modules/syscall/direct.c
    src/modules/syscall/indirect.c
    src/modules/syscall/unhook.c
    src/modules/syscall/tampered.c
    src/modules/syscall/callstack.c

    # Encryption
    src/modules/encrypt/xor.c
    src/modules/encrypt/aes.c
    src/modules/encrypt/rc4.c
    src/modules/encrypt/triple.c

    # Injection
    src/modules/inject/classic.c
    src/modules/inject/apc.c
    src/modules/inject/threadless.c
    src/modules/inject/module_stomp.c
    src/modules/inject/callback.c
    src/modules/inject/poolparty.c
    src/modules/inject/inject_utils.c

    # Evasion
    src/modules/evasion/etw.c
    src/modules/evasion/amsi.c
    src/modules/evasion/sandbox.c
    src/modules/evasion/ppid_spoof.c

    # Anti-debug
    src/modules/antidebug/peb_check.c
    src/modules/antidebug/timing_check.c
    src/modules/antidebug/ntquery.c
    src/modules/antidebug/hardware_bp.c
    src/modules/antidebug/trap_flag.c

    # Sleep obfuscation
    src/modules/sleep/ekko.c
    src/modules/sleep/foliage.c
    src/modules/sleep/zilean.c
    src/modules/sleep/beacongate.c
)

# --- Assembly stubs (Windows only) ---
if(WIN32)
    if(MSVC)
        enable_language(ASM_MASM)
        set(ASM_SOURCES asm/syscall_stubs.asm)
    else()
        # MinGW / GCC: use NASM
        enable_language(ASM_NASM)
        set(ASM_SOURCES asm/syscall_stubs_nasm.asm)
    endif()
else()
    set(ASM_SOURCES "")
endif()

# --- Static library (all modules) ---
add_library(tekton STATIC
    ${CORE_SOURCES}
    ${UTIL_SOURCES}
    ${MODULE_SOURCES}
    ${ASM_SOURCES}
)

# --- Main executable ---
add_executable(edr-tekton src/main.c)
target_link_libraries(edr-tekton tekton)

if(WIN32)
    target_link_libraries(edr-tekton ntdll advapi32 user32)
endif()

# --- Tests ---
option(TEKTON_BUILD_TESTS "Build the test suite" OFF)

if(TEKTON_BUILD_TESTS)
    set(TEST_SOURCES
        tests/test_runner.c
        tests/test_hash.c
        tests/test_crypto.c
        tests/test_config.c
        tests/test_module.c
        tests/test_builder.c
    )

    add_executable(test_runner ${TEST_SOURCES})
    target_link_libraries(test_runner tekton)
    target_include_directories(test_runner PRIVATE ${CMAKE_SOURCE_DIR}/tests)

    # CTest integration
    enable_testing()
    add_test(NAME tekton_tests COMMAND test_runner)
endif()

# --- Install ---
install(TARGETS edr-tekton DESTINATION bin)
install(DIRECTORY profiles/ DESTINATION share/edr-tekton/profiles)
install(DIRECTORY include/tekton DESTINATION include)
