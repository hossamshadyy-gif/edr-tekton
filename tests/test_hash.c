/*
 * edr-tekton :: Hash Function Tests
 * Tests CRC32B, DJB2, Additive, and Rotating hash algorithms.
 */

#include "test_framework.h"
#include "tekton/util/hash.h"

/*
 * DWORD is unsigned long (64-bit on Linux x86_64). The CRC32B function
 * uses ~crc which inverts all bits, setting the upper 32 bits. We mask
 * to 32 bits when comparing against standard CRC32 test vectors.
 */
#define CRC32_MASK(v) ((v) & 0xFFFFFFFF)

/* ── CRC32B Tests ───────────────────────────────────────── */

TEST(crc32b_known_vector) {
    /* Standard CRC32 test vector: "123456789" => 0xCBF43926 */
    DWORD hash = TektonHashCrc32bStringA("123456789");
    ASSERT_EQ(CRC32_MASK(hash), 0xCBF43926);
}

TEST(crc32b_empty_string) {
    /* Empty string: seed 0xFFFFFFFF with no bytes processed, ~seed lower 32 bits = 0 */
    DWORD hash = TektonHashCrc32bStringA("");
    ASSERT_EQ(CRC32_MASK(hash), 0x00000000);
}

TEST(crc32b_null_returns_zero) {
    DWORD hash = TektonHashCrc32bStringA(NULL);
    ASSERT_EQ(hash, 0);
}

TEST(crc32b_deterministic) {
    DWORD h1 = TektonHashCrc32bStringA("NtAllocateVirtualMemory");
    DWORD h2 = TektonHashCrc32bStringA("NtAllocateVirtualMemory");
    ASSERT_EQ(h1, h2);
}

TEST(crc32b_different_strings_differ) {
    DWORD h1 = TektonHashCrc32bStringA("NtAllocateVirtualMemory");
    DWORD h2 = TektonHashCrc32bStringA("NtWriteVirtualMemory");
    DWORD h3 = TektonHashCrc32bStringA("NtProtectVirtualMemory");
    ASSERT_NEQ(h1, h2);
    ASSERT_NEQ(h1, h3);
    ASSERT_NEQ(h2, h3);
}

TEST(crc32b_case_sensitive) {
    DWORD h_lower = TektonHashCrc32bStringA("ntdll.dll");
    DWORD h_upper = TektonHashCrc32bStringA("NTDLL.DLL");
    DWORD h_mixed = TektonHashCrc32bStringA("Ntdll.Dll");
    ASSERT_NEQ(h_lower, h_upper);
    ASSERT_NEQ(h_lower, h_mixed);
    ASSERT_NEQ(h_upper, h_mixed);
}

TEST(crc32b_case_insensitive) {
    /* The case-insensitive variant should produce identical hashes */
    DWORD h_lower = TektonHashCrc32bStringAi("ntdll.dll");
    DWORD h_upper = TektonHashCrc32bStringAi("NTDLL.DLL");
    DWORD h_mixed = TektonHashCrc32bStringAi("Ntdll.Dll");
    ASSERT_EQ(h_lower, h_upper);
    ASSERT_EQ(h_lower, h_mixed);
}

TEST(crc32b_case_insensitive_null) {
    ASSERT_EQ(TektonHashCrc32bStringAi(NULL), 0);
}

TEST(crc32b_raw_bytes) {
    BYTE data[] = { 0x00, 0x01, 0x02, 0x03 };
    DWORD h1 = TektonHashCrc32b(data, sizeof(data));
    DWORD h2 = TektonHashCrc32b(data, sizeof(data));
    ASSERT_EQ(h1, h2);
    ASSERT_NEQ(h1, 0);
}

TEST(crc32b_single_char) {
    /* Single character should produce a non-trivial hash */
    DWORD h = TektonHashCrc32bStringA("A");
    ASSERT_NEQ(h, 0);
    ASSERT_NEQ(h, (DWORD)'A');
}

TEST(crc32b_wide_string) {
    wchar_t ws1[] = L"kernel32.dll";
    wchar_t ws2[] = L"kernel32.dll";
    DWORD h1 = TektonHashCrc32bStringW(ws1);
    DWORD h2 = TektonHashCrc32bStringW(ws2);
    ASSERT_EQ(h1, h2);
    ASSERT_NEQ(h1, 0);
}

TEST(crc32b_wide_null) {
    ASSERT_EQ(TektonHashCrc32bStringW(NULL), 0);
}

TEST(crc32b_wide_case_insensitive) {
    wchar_t ws_lower[] = L"ntdll.dll";
    wchar_t ws_upper[] = L"NTDLL.DLL";
    DWORD h_lower = TektonHashCrc32bStringWi(ws_lower);
    DWORD h_upper = TektonHashCrc32bStringWi(ws_upper);
    ASSERT_EQ(h_lower, h_upper);
}

TEST(crc32b_wide_case_insensitive_null) {
    ASSERT_EQ(TektonHashCrc32bStringWi(NULL), 0);
}

/* ── DJB2 Tests ─────────────────────────────────────────── */

TEST(djb2_empty_string) {
    /* Empty string returns the seed value */
    DWORD hash = TektonHashDjb2StringA("");
    ASSERT_EQ(hash, DJB2_SEED);
}

TEST(djb2_null_returns_zero) {
    DWORD hash = TektonHashDjb2StringA(NULL);
    ASSERT_EQ(hash, 0);
}

TEST(djb2_deterministic) {
    DWORD h1 = TektonHashDjb2StringA("LoadLibraryA");
    DWORD h2 = TektonHashDjb2StringA("LoadLibraryA");
    ASSERT_EQ(h1, h2);
}

TEST(djb2_different_strings_differ) {
    DWORD h1 = TektonHashDjb2StringA("LoadLibraryA");
    DWORD h2 = TektonHashDjb2StringA("GetProcAddress");
    ASSERT_NEQ(h1, h2);
}

TEST(djb2_case_sensitive) {
    DWORD h1 = TektonHashDjb2StringA("test");
    DWORD h2 = TektonHashDjb2StringA("TEST");
    DWORD h3 = TektonHashDjb2StringA("Test");
    ASSERT_NEQ(h1, h2);
    ASSERT_NEQ(h1, h3);
}

TEST(djb2_raw_bytes) {
    BYTE data[] = { 0x41, 0x42, 0x43 }; /* "ABC" */
    DWORD h1 = TektonHashDjb2(data, sizeof(data));
    DWORD h2 = TektonHashDjb2StringA("ABC");
    ASSERT_EQ(h1, h2);
}

TEST(djb2_non_trivial) {
    /* Hash should differ from the seed for any non-empty input */
    DWORD h = TektonHashDjb2StringA("x");
    ASSERT_NEQ(h, DJB2_SEED);
    ASSERT_NEQ(h, 0);
}

/* ── Additive Hash Tests ────────────────────────────────── */

TEST(additive_empty_string) {
    DWORD hash = TektonHashAdditive("");
    ASSERT_EQ(hash, ADDITIVE_SEED);
}

TEST(additive_null_returns_zero) {
    DWORD hash = TektonHashAdditive(NULL);
    ASSERT_EQ(hash, 0);
}

TEST(additive_deterministic) {
    DWORD h1 = TektonHashAdditive("VirtualAlloc");
    DWORD h2 = TektonHashAdditive("VirtualAlloc");
    ASSERT_EQ(h1, h2);
}

TEST(additive_different_strings_differ) {
    DWORD h1 = TektonHashAdditive("VirtualAlloc");
    DWORD h2 = TektonHashAdditive("VirtualFree");
    ASSERT_NEQ(h1, h2);
}

TEST(additive_case_sensitive) {
    DWORD h1 = TektonHashAdditive("hello");
    DWORD h2 = TektonHashAdditive("HELLO");
    ASSERT_NEQ(h1, h2);
}

/* ── Rotating Hash Tests ────────────────────────────────── */

TEST(rotate_empty_returns_seed) {
    DWORD seed = 0xDEADBEEF;
    DWORD hash = TektonHashRotate("", seed);
    ASSERT_EQ(hash, seed);
}

TEST(rotate_null_returns_zero) {
    DWORD hash = TektonHashRotate(NULL, 0x12345678);
    ASSERT_EQ(hash, 0);
}

TEST(rotate_deterministic) {
    DWORD h1 = TektonHashRotate("NtCreateThreadEx", 0x1234);
    DWORD h2 = TektonHashRotate("NtCreateThreadEx", 0x1234);
    ASSERT_EQ(h1, h2);
}

TEST(rotate_different_seeds_differ) {
    DWORD h1 = TektonHashRotate("test", 0x1111);
    DWORD h2 = TektonHashRotate("test", 0x2222);
    ASSERT_NEQ(h1, h2);
}

TEST(rotate_different_strings_differ) {
    DWORD h1 = TektonHashRotate("alpha", 0xABCD);
    DWORD h2 = TektonHashRotate("bravo", 0xABCD);
    ASSERT_NEQ(h1, h2);
}

/* ── Cross-Algorithm Tests ──────────────────────────────── */

TEST(algorithms_produce_different_hashes) {
    /* Same input through different algorithms should differ */
    const char* input = "NtAllocateVirtualMemory";
    DWORD crc  = TektonHashCrc32bStringA(input);
    DWORD djb  = TektonHashDjb2StringA(input);
    DWORD add  = TektonHashAdditive(input);
    DWORD rot  = TektonHashRotate(input, 0x1234);

    ASSERT_NEQ(crc, djb);
    ASSERT_NEQ(crc, add);
    ASSERT_NEQ(crc, rot);
    ASSERT_NEQ(djb, add);
}

/* ── Suite Runner ───────────────────────────────────────── */

int test_hash_run(void) {
    test_state_t _tf_state_val;
    test_state_t* _tf_state = &_tf_state_val;
    tf_init(_tf_state, "Hash Functions");

    /* CRC32B */
    RUN_TEST(crc32b_known_vector);
    RUN_TEST(crc32b_empty_string);
    RUN_TEST(crc32b_null_returns_zero);
    RUN_TEST(crc32b_deterministic);
    RUN_TEST(crc32b_different_strings_differ);
    RUN_TEST(crc32b_case_sensitive);
    RUN_TEST(crc32b_case_insensitive);
    RUN_TEST(crc32b_case_insensitive_null);
    RUN_TEST(crc32b_raw_bytes);
    RUN_TEST(crc32b_single_char);
    RUN_TEST(crc32b_wide_string);
    RUN_TEST(crc32b_wide_null);
    RUN_TEST(crc32b_wide_case_insensitive);
    RUN_TEST(crc32b_wide_case_insensitive_null);

    /* DJB2 */
    RUN_TEST(djb2_empty_string);
    RUN_TEST(djb2_null_returns_zero);
    RUN_TEST(djb2_deterministic);
    RUN_TEST(djb2_different_strings_differ);
    RUN_TEST(djb2_case_sensitive);
    RUN_TEST(djb2_raw_bytes);
    RUN_TEST(djb2_non_trivial);

    /* Additive */
    RUN_TEST(additive_empty_string);
    RUN_TEST(additive_null_returns_zero);
    RUN_TEST(additive_deterministic);
    RUN_TEST(additive_different_strings_differ);
    RUN_TEST(additive_case_sensitive);

    /* Rotating */
    RUN_TEST(rotate_empty_returns_seed);
    RUN_TEST(rotate_null_returns_zero);
    RUN_TEST(rotate_deterministic);
    RUN_TEST(rotate_different_seeds_differ);
    RUN_TEST(rotate_different_strings_differ);

    /* Cross-algorithm */
    RUN_TEST(algorithms_produce_different_hashes);

    return tf_summary(_tf_state);
}
