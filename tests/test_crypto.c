/*
 * edr-tekton :: Cryptographic Primitives Tests
 * Tests XOR, RC4, AES-256-CBC, FNV-1a, and triple encryption.
 */

#include "test_framework.h"
#include "tekton/util/crypto.h"

/* ── XOR Tests ──────────────────────────────────────────── */

TEST(xor_roundtrip) {
    BYTE original[] = "Hello, edr-tekton!";
    BYTE data[32];
    SIZE_T len = sizeof(original) - 1; /* exclude null terminator */
    BYTE key[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    memcpy(data, original, len);

    /* Encrypt */
    TektonCryptoXor(data, len, key, sizeof(key));
    ASSERT_MEM_NEQ(data, original, len);

    /* Decrypt (XOR is self-inverse) */
    TektonCryptoXor(data, len, key, sizeof(key));
    ASSERT_MEM_EQ(data, original, len);
}

TEST(xor_single_byte_key) {
    BYTE original[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    BYTE data[6];
    SIZE_T len = sizeof(original);
    BYTE key[] = { 0xFF };

    memcpy(data, original, len);
    TektonCryptoXor(data, len, key, 1);
    ASSERT_MEM_NEQ(data, original, len);

    /* Each byte should be XORed with 0xFF */
    ASSERT_EQ(data[0], 0xFF);
    ASSERT_EQ(data[1], 0xEE);
    ASSERT_EQ(data[2], 0xDD);

    /* Roundtrip */
    TektonCryptoXor(data, len, key, 1);
    ASSERT_MEM_EQ(data, original, len);
}

TEST(xor_byte_convenience) {
    BYTE original[] = { 0x41, 0x42, 0x43, 0x44 }; /* "ABCD" */
    BYTE data[4];
    memcpy(data, original, 4);

    TektonCryptoXorByte(data, 4, 0xAA);
    ASSERT_MEM_NEQ(data, original, 4);

    TektonCryptoXorByte(data, 4, 0xAA);
    ASSERT_MEM_EQ(data, original, 4);
}

TEST(xor_null_safety) {
    BYTE key[] = { 0x41 };
    /* Should not crash on NULL data */
    TektonCryptoXor(NULL, 10, key, 1);
    /* Should not crash on NULL key */
    BYTE data[] = { 0x01 };
    TektonCryptoXor(data, 1, NULL, 0);
    /* data should be unchanged */
    ASSERT_EQ(data[0], 0x01);
}

TEST(xor_zero_length) {
    BYTE data[] = { 0x41, 0x42 };
    BYTE key[] = { 0xFF };
    TektonCryptoXor(data, 0, key, 1);
    /* Data should be unchanged */
    ASSERT_EQ(data[0], 0x41);
    ASSERT_EQ(data[1], 0x42);
}

TEST(xor_large_key) {
    BYTE original[] = "Short";
    BYTE data[8];
    SIZE_T len = 5;
    BYTE key[32];
    memset(key, 0xAB, sizeof(key));

    memcpy(data, original, len);
    TektonCryptoXor(data, len, key, sizeof(key));
    ASSERT_MEM_NEQ(data, original, len);

    TektonCryptoXor(data, len, key, sizeof(key));
    ASSERT_MEM_EQ(data, original, len);
}

TEST(xor_key_wrapping) {
    /* Verify key cycles correctly (key_len < data_len) */
    BYTE data[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE key[3] = { 0xAA, 0xBB, 0xCC };

    TektonCryptoXor(data, 6, key, 3);
    /* Key should wrap: AA BB CC AA BB CC */
    ASSERT_EQ(data[0], 0xAA);
    ASSERT_EQ(data[1], 0xBB);
    ASSERT_EQ(data[2], 0xCC);
    ASSERT_EQ(data[3], 0xAA);
    ASSERT_EQ(data[4], 0xBB);
    ASSERT_EQ(data[5], 0xCC);
}

/* ── RC4 Tests ──────────────────────────────────────────── */

TEST(rc4_roundtrip) {
    BYTE original[] = "The quick brown fox jumps over the lazy dog";
    SIZE_T len = sizeof(original) - 1;
    BYTE encrypted[64];
    BYTE decrypted[64];
    BYTE key[] = "SecretKey123";

    memcpy(encrypted, original, len);

    /* Encrypt */
    TektonCryptoRc4(encrypted, len, key, strlen((char*)key));
    ASSERT_MEM_NEQ(encrypted, original, len);

    /* Decrypt: RC4 with same key from fresh state */
    memcpy(decrypted, encrypted, len);
    TektonCryptoRc4(decrypted, len, key, strlen((char*)key));
    ASSERT_MEM_EQ(decrypted, original, len);
}

TEST(rc4_init_process_match_oneshot) {
    /* Manual init+process should produce same result as one-shot */
    BYTE data1[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    BYTE data2[16];
    BYTE key[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    memcpy(data2, data1, 16);

    /* One-shot */
    TektonCryptoRc4(data1, 16, key, 4);

    /* Manual init + process */
    TEKTON_RC4_STATE state;
    TektonCryptoRc4Init(&state, key, 4);
    TektonCryptoRc4Process(&state, data2, 16);

    ASSERT_MEM_EQ(data1, data2, 16);
}

TEST(rc4_different_keys_differ) {
    BYTE data1[8] = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    BYTE data2[8];
    memcpy(data2, data1, 8);

    BYTE key1[] = "KeyAlpha";
    BYTE key2[] = "KeyBravo";

    TektonCryptoRc4(data1, 8, key1, strlen((char*)key1));
    TektonCryptoRc4(data2, 8, key2, strlen((char*)key2));

    ASSERT_MEM_NEQ(data1, data2, 8);
}

TEST(rc4_null_safety) {
    TEKTON_RC4_STATE state;
    BYTE key[] = { 0x01 };
    /* NULL state should not crash */
    TektonCryptoRc4Init(NULL, key, 1);
    /* NULL key should not crash */
    TektonCryptoRc4Init(&state, NULL, 0);
    /* NULL data should not crash */
    TektonCryptoRc4Process(&state, NULL, 10);
}

/* ── AES-256-CBC Tests ──────────────────────────────────── */

TEST(aes_init_valid_key) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    memset(key, 0x42, TEKTON_AES_KEY_SIZE);

    TEKTON_STATUS status = TektonCryptoAesInit(&ctx, key, TEKTON_AES_KEY_SIZE);
    ASSERT_OK(status);
    ASSERT_EQ(ctx.num_rounds, 14); /* AES-256 = 14 rounds */
}

TEST(aes_init_bad_key_size) {
    TEKTON_AES_CTX ctx;
    BYTE key[16]; /* Too short for AES-256 */
    memset(key, 0x42, 16);

    TEKTON_STATUS status = TektonCryptoAesInit(&ctx, key, 16);
    ASSERT_EQ(status, TEKTON_ERR_INVALID_PARAM);
}

TEST(aes_init_null_params) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    memset(key, 0x42, TEKTON_AES_KEY_SIZE);

    ASSERT_EQ(TektonCryptoAesInit(NULL, key, TEKTON_AES_KEY_SIZE), TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoAesInit(&ctx, NULL, TEKTON_AES_KEY_SIZE), TEKTON_ERR_INVALID_PARAM);
}

TEST(aes_cbc_roundtrip) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    BYTE iv[TEKTON_AES_IV_SIZE];

    /* Initialize key and IV */
    for (int i = 0; i < TEKTON_AES_KEY_SIZE; i++) key[i] = (BYTE)(i + 1);
    for (int i = 0; i < TEKTON_AES_IV_SIZE; i++) iv[i] = (BYTE)(i + 0x10);

    ASSERT_OK(TektonCryptoAesInit(&ctx, key, TEKTON_AES_KEY_SIZE));

    /* Original plaintext (13 bytes, not block-aligned) */
    BYTE original[] = "Hello Tekton!";
    SIZE_T orig_len = 13;

    /* Encrypt buffer (needs room for padding) */
    BYTE buffer[64];
    memcpy(buffer, original, orig_len);
    SIZE_T data_len = orig_len;

    ASSERT_OK(TektonCryptoAesCbcEncrypt(&ctx, buffer, &data_len, sizeof(buffer), iv));

    /* Encrypted length should be block-aligned (16 for 13 bytes input) */
    ASSERT_EQ(data_len, 16);
    /* Encrypted data should differ from plaintext */
    ASSERT_MEM_NEQ(buffer, original, orig_len);

    /* Decrypt with same key and IV */
    ASSERT_OK(TektonCryptoAesCbcDecrypt(&ctx, buffer, data_len, iv));

    /* Strip PKCS7 padding manually */
    BYTE pad_val = buffer[data_len - 1];
    ASSERT_TRUE(pad_val > 0 && pad_val <= TEKTON_AES_BLOCK_SIZE);
    SIZE_T plaintext_len = data_len - pad_val;
    ASSERT_EQ(plaintext_len, orig_len);

    /* Verify plaintext matches */
    ASSERT_MEM_EQ(buffer, original, orig_len);
}

TEST(aes_cbc_block_aligned_roundtrip) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    BYTE iv[TEKTON_AES_IV_SIZE];
    memset(key, 0xAB, TEKTON_AES_KEY_SIZE);
    memset(iv, 0xCD, TEKTON_AES_IV_SIZE);

    ASSERT_OK(TektonCryptoAesInit(&ctx, key, TEKTON_AES_KEY_SIZE));

    /* 16-byte input (exactly one block) */
    BYTE original[16] = "AABBCCDDAABBCCDD";
    BYTE buffer[48]; /* needs room for extra padding block */
    memcpy(buffer, original, 16);
    SIZE_T data_len = 16;

    ASSERT_OK(TektonCryptoAesCbcEncrypt(&ctx, buffer, &data_len, sizeof(buffer), iv));
    /* Should be 32 bytes: original block + full padding block */
    ASSERT_EQ(data_len, 32);

    ASSERT_OK(TektonCryptoAesCbcDecrypt(&ctx, buffer, data_len, iv));
    BYTE pad_val = buffer[data_len - 1];
    SIZE_T plaintext_len = data_len - pad_val;
    ASSERT_EQ(plaintext_len, 16);
    ASSERT_MEM_EQ(buffer, original, 16);
}

TEST(aes_cbc_decrypt_invalid_size) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    BYTE iv[TEKTON_AES_IV_SIZE];
    memset(key, 0x11, TEKTON_AES_KEY_SIZE);
    memset(iv, 0x22, TEKTON_AES_IV_SIZE);

    ASSERT_OK(TektonCryptoAesInit(&ctx, key, TEKTON_AES_KEY_SIZE));

    BYTE data[10]; /* Not a multiple of 16 */
    TEKTON_STATUS s = TektonCryptoAesCbcDecrypt(&ctx, data, 10, iv);
    ASSERT_EQ(s, TEKTON_ERR_INVALID_PARAM);

    /* Zero length */
    s = TektonCryptoAesCbcDecrypt(&ctx, data, 0, iv);
    ASSERT_EQ(s, TEKTON_ERR_INVALID_PARAM);
}

TEST(aes_cbc_encrypt_buffer_too_small) {
    TEKTON_AES_CTX ctx;
    BYTE key[TEKTON_AES_KEY_SIZE];
    BYTE iv[TEKTON_AES_IV_SIZE];
    memset(key, 0x33, TEKTON_AES_KEY_SIZE);
    memset(iv, 0x44, TEKTON_AES_IV_SIZE);

    ASSERT_OK(TektonCryptoAesInit(&ctx, key, TEKTON_AES_KEY_SIZE));

    BYTE buffer[14]; /* Too small for padding: 14 bytes needs 16-byte output */
    memset(buffer, 0x41, 14);
    SIZE_T data_len = 14;

    TEKTON_STATUS s = TektonCryptoAesCbcEncrypt(&ctx, buffer, &data_len, 14, iv);
    ASSERT_EQ(s, TEKTON_ERR_ALLOC);
}

/* ── FNV-1a Tests ───────────────────────────────────────── */

TEST(fnv1a_deterministic) {
    BYTE data[] = "test_seed_material";
    DWORD h1 = TektonCryptoFnv1a32(data, sizeof(data) - 1);
    DWORD h2 = TektonCryptoFnv1a32(data, sizeof(data) - 1);
    ASSERT_EQ(h1, h2);
    ASSERT_NEQ(h1, 0);
}

TEST(fnv1a_empty_returns_basis) {
    DWORD h = TektonCryptoFnv1a32(NULL, 0);
    /* No bytes processed, returns offset basis */
    ASSERT_EQ(h, FNV1A_OFFSET_BASIS_32);
}

TEST(fnv1a_different_data_differ) {
    BYTE d1[] = "alpha";
    BYTE d2[] = "bravo";
    DWORD h1 = TektonCryptoFnv1a32(d1, 5);
    DWORD h2 = TektonCryptoFnv1a32(d2, 5);
    ASSERT_NEQ(h1, h2);
}

/* ── Environment Key Derivation Tests ───────────────────── */

TEST(env_key_derive_custom_seed) {
    BYTE key1[32];
    BYTE key2[32];

    ASSERT_OK(TektonCryptoDeriveEnvKey(key1, 32, "custom-seed-123"));
    ASSERT_OK(TektonCryptoDeriveEnvKey(key2, 32, "custom-seed-123"));

    /* Same seed should produce same key */
    ASSERT_MEM_EQ(key1, key2, 32);
}

TEST(env_key_derive_different_seeds_differ) {
    BYTE key1[32];
    BYTE key2[32];

    ASSERT_OK(TektonCryptoDeriveEnvKey(key1, 32, "seed-alpha"));
    ASSERT_OK(TektonCryptoDeriveEnvKey(key2, 32, "seed-bravo"));

    ASSERT_MEM_NEQ(key1, key2, 32);
}

TEST(env_key_derive_null_params) {
    BYTE key[32];
    ASSERT_EQ(TektonCryptoDeriveEnvKey(NULL, 32, "seed"), TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoDeriveEnvKey(key, 0, "seed"), TEKTON_ERR_INVALID_PARAM);
}

TEST(env_key_derive_different_lengths) {
    BYTE key16[16];
    BYTE key32[32];

    ASSERT_OK(TektonCryptoDeriveEnvKey(key16, 16, "same-seed"));
    ASSERT_OK(TektonCryptoDeriveEnvKey(key32, 32, "same-seed"));

    /* First 16 bytes of 32-byte key should match the 16-byte key */
    ASSERT_MEM_EQ(key16, key32, 16);
}

/* ── Triple Encryption Tests ────────────────────────────── */

TEST(triple_encrypt_decrypt_roundtrip) {
    BYTE aes_key[TEKTON_AES_KEY_SIZE];
    BYTE rc4_key[16];
    BYTE xor_key[8];
    BYTE iv[TEKTON_AES_IV_SIZE];

    /* Set up keys */
    for (int i = 0; i < TEKTON_AES_KEY_SIZE; i++) aes_key[i] = (BYTE)(i + 0x10);
    for (int i = 0; i < 16; i++) rc4_key[i] = (BYTE)(i + 0x30);
    for (int i = 0; i < 8; i++) xor_key[i] = (BYTE)(i + 0x50);
    for (int i = 0; i < TEKTON_AES_IV_SIZE; i++) iv[i] = (BYTE)(i + 0x70);

    TEKTON_TRIPLE_CTX ctx;
    ASSERT_OK(TektonCryptoTripleInit(&ctx,
        aes_key, TEKTON_AES_KEY_SIZE,
        rc4_key, 16,
        xor_key, 8,
        iv));
    ASSERT_TRUE(ctx.initialized);

    /* Original data */
    BYTE original[] = "Triple encrypted payload data for testing";
    SIZE_T orig_len = sizeof(original) - 1;
    BYTE buffer[128];
    memcpy(buffer, original, orig_len);
    SIZE_T data_len = orig_len;

    /* Encrypt */
    ASSERT_OK(TektonCryptoTripleEncrypt(&ctx, buffer, &data_len, sizeof(buffer)));
    ASSERT_MEM_NEQ(buffer, original, orig_len);
    ASSERT_TRUE(data_len >= orig_len); /* AES padding increases size */

    /* Re-initialize context (RC4 state is consumed by copies, but AES IV needs fresh ctx) */
    TEKTON_TRIPLE_CTX ctx2;
    ASSERT_OK(TektonCryptoTripleInit(&ctx2,
        aes_key, TEKTON_AES_KEY_SIZE,
        rc4_key, 16,
        xor_key, 8,
        iv));

    /* Decrypt */
    ASSERT_OK(TektonCryptoTripleDecrypt(&ctx2, buffer, &data_len));
    ASSERT_EQ(data_len, orig_len);
    ASSERT_MEM_EQ(buffer, original, orig_len);
}

TEST(triple_init_null_params) {
    TEKTON_TRIPLE_CTX ctx;
    BYTE key[32];
    BYTE iv[16];
    memset(key, 0, 32);
    memset(iv, 0, 16);

    ASSERT_EQ(TektonCryptoTripleInit(NULL, key, 32, key, 16, key, 8, iv),
              TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoTripleInit(&ctx, NULL, 32, key, 16, key, 8, iv),
              TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoTripleInit(&ctx, key, 32, NULL, 16, key, 8, iv),
              TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoTripleInit(&ctx, key, 32, key, 16, NULL, 8, iv),
              TEKTON_ERR_INVALID_PARAM);
    ASSERT_EQ(TektonCryptoTripleInit(&ctx, key, 32, key, 16, key, 8, NULL),
              TEKTON_ERR_INVALID_PARAM);
}

TEST(triple_decrypt_uninitialized) {
    TEKTON_TRIPLE_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    BYTE data[32];
    SIZE_T len = 32;

    ASSERT_EQ(TektonCryptoTripleDecrypt(&ctx, data, &len), TEKTON_ERR_INVALID_PARAM);
}

/* ── Suite Runner ───────────────────────────────────────── */

int test_crypto_run(void) {
    test_state_t _tf_state_val;
    test_state_t* _tf_state = &_tf_state_val;
    tf_init(_tf_state, "Cryptographic Primitives");

    /* XOR */
    RUN_TEST(xor_roundtrip);
    RUN_TEST(xor_single_byte_key);
    RUN_TEST(xor_byte_convenience);
    RUN_TEST(xor_null_safety);
    RUN_TEST(xor_zero_length);
    RUN_TEST(xor_large_key);
    RUN_TEST(xor_key_wrapping);

    /* RC4 */
    RUN_TEST(rc4_roundtrip);
    RUN_TEST(rc4_init_process_match_oneshot);
    RUN_TEST(rc4_different_keys_differ);
    RUN_TEST(rc4_null_safety);

    /* AES-256-CBC */
    RUN_TEST(aes_init_valid_key);
    RUN_TEST(aes_init_bad_key_size);
    RUN_TEST(aes_init_null_params);
    RUN_TEST(aes_cbc_roundtrip);
    RUN_TEST(aes_cbc_block_aligned_roundtrip);
    RUN_TEST(aes_cbc_decrypt_invalid_size);
    RUN_TEST(aes_cbc_encrypt_buffer_too_small);

    /* FNV-1a */
    RUN_TEST(fnv1a_deterministic);
    RUN_TEST(fnv1a_empty_returns_basis);
    RUN_TEST(fnv1a_different_data_differ);

    /* Environment key derivation */
    RUN_TEST(env_key_derive_custom_seed);
    RUN_TEST(env_key_derive_different_seeds_differ);
    RUN_TEST(env_key_derive_null_params);
    RUN_TEST(env_key_derive_different_lengths);

    /* Triple encryption */
    RUN_TEST(triple_encrypt_decrypt_roundtrip);
    RUN_TEST(triple_init_null_params);
    RUN_TEST(triple_decrypt_uninitialized);

    return tf_summary(_tf_state);
}
