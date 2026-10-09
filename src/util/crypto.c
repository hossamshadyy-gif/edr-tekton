/*
 * edr-tekton :: Cryptographic Primitives
 * XOR, RC4, AES-256-CBC, FNV-1a, env-key derivation, triple encryption.
 * Cat 3.1, 3.2, 3.3, 3.4.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tekton/util/crypto.h"
#include "tekton/core/log.h"

/* ── XOR Encryption (Cat 3.1) ────────────────────────────── */

VOID TektonCryptoXor(
    BYTE*       data,
    SIZE_T      data_len,
    const BYTE* key,
    SIZE_T      key_len
) {
    if (!data || !key || key_len == 0) return;
    for (SIZE_T i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

VOID TektonCryptoXorByte(
    BYTE*   data,
    SIZE_T  data_len,
    BYTE    key
) {
    if (!data) return;
    for (SIZE_T i = 0; i < data_len; i++) {
        data[i] ^= key;
    }
}

/* ── RC4 Stream Cipher (Cat 3.3) ─────────────────────────── */

VOID TektonCryptoRc4Init(
    PTEKTON_RC4_STATE   state,
    const BYTE*         key,
    SIZE_T              key_len
) {
    if (!state || !key || key_len == 0) return;

    /* KSA (Key Scheduling Algorithm) */
    for (int i = 0; i < 256; i++) {
        state->S[i] = (BYTE)i;
    }

    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + state->S[i] + key[i % key_len];
        BYTE tmp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = tmp;
    }

    state->i = 0;
    state->j = 0;
}

VOID TektonCryptoRc4Process(
    PTEKTON_RC4_STATE   state,
    BYTE*               data,
    SIZE_T              data_len
) {
    if (!state || !data) return;

    /* PRGA (Pseudo-Random Generation Algorithm) */
    BYTE i = state->i;
    BYTE j = state->j;

    for (SIZE_T k = 0; k < data_len; k++) {
        i++;
        j += state->S[i];
        BYTE tmp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = tmp;
        data[k] ^= state->S[(BYTE)(state->S[i] + state->S[j])];
    }

    state->i = i;
    state->j = j;
}

VOID TektonCryptoRc4(
    BYTE*       data,
    SIZE_T      data_len,
    const BYTE* key,
    SIZE_T      key_len
) {
    TEKTON_RC4_STATE state;
    TektonCryptoRc4Init(&state, key, key_len);
    TektonCryptoRc4Process(&state, data, data_len);
    TEKTON_SECURE_ZERO(&state, sizeof(state));
}

/* ── FNV-1a Hash (Cat 3.3) ──────────────────────────────── */

DWORD TektonCryptoFnv1a32(const BYTE* data, SIZE_T length) {
    DWORD hash = FNV1A_OFFSET_BASIS_32;
    for (SIZE_T i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= FNV1A_PRIME_32;
    }
    return hash;
}

/* ── AES-256-CBC ─────────────────────────────────────────── */

/*
 * Minimal self-contained AES-256 implementation.
 * No external crypto library dependency.
 */

static const BYTE aes_sbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static const BYTE aes_inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static const BYTE aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* Galois field multiplication */
static BYTE gf_mul(BYTE a, BYTE b) {
    BYTE result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        BYTE hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

/* Key expansion for AES-256 */
static void aes_key_expansion(PTEKTON_AES_CTX ctx, const BYTE* key) {
    DWORD* rk = ctx->round_keys;
    int nk = 8;  /* AES-256: 8 32-bit words */
    int nr = 14; /* AES-256: 14 rounds */
    ctx->num_rounds = nr;

    /* Copy initial key */
    for (int i = 0; i < nk; i++) {
        rk[i] = ((DWORD)key[4*i] << 24) |
                ((DWORD)key[4*i+1] << 16) |
                ((DWORD)key[4*i+2] << 8) |
                ((DWORD)key[4*i+3]);
    }

    /* Expand */
    for (int i = nk; i < 4 * (nr + 1); i++) {
        DWORD temp = rk[i - 1];

        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            temp = ((DWORD)aes_sbox[(temp >> 16) & 0xFF] << 24) |
                   ((DWORD)aes_sbox[(temp >> 8)  & 0xFF] << 16) |
                   ((DWORD)aes_sbox[temp & 0xFF] << 8) |
                   ((DWORD)aes_sbox[(temp >> 24) & 0xFF]);
            temp ^= ((DWORD)aes_rcon[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            /* Extra SubWord for AES-256 */
            temp = ((DWORD)aes_sbox[(temp >> 24) & 0xFF] << 24) |
                   ((DWORD)aes_sbox[(temp >> 16) & 0xFF] << 16) |
                   ((DWORD)aes_sbox[(temp >> 8)  & 0xFF] << 8) |
                   ((DWORD)aes_sbox[temp & 0xFF]);
        }

        rk[i] = rk[i - nk] ^ temp;
    }
}

/* AES block operations */

static void aes_add_round_key(BYTE state[16], const DWORD* rk) {
    for (int col = 0; col < 4; col++) {
        state[col*4+0] ^= (BYTE)(rk[col] >> 24);
        state[col*4+1] ^= (BYTE)(rk[col] >> 16);
        state[col*4+2] ^= (BYTE)(rk[col] >> 8);
        state[col*4+3] ^= (BYTE)(rk[col]);
    }
}

static void aes_sub_bytes(BYTE state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_sbox[state[i]];
}

static void aes_inv_sub_bytes(BYTE state[16]) {
    for (int i = 0; i < 16; i++) state[i] = aes_inv_sbox[state[i]];
}

static void aes_shift_rows(BYTE state[16]) {
    BYTE tmp;
    /* Row 1: shift left 1 */
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    /* Row 2: shift left 2 */
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    /* Row 3: shift left 3 (= shift right 1) */
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
}

static void aes_inv_shift_rows(BYTE state[16]) {
    BYTE tmp;
    /* Row 1: shift right 1 */
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    /* Row 2: shift right 2 */
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    /* Row 3: shift right 3 (= shift left 1) */
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
}

static void aes_mix_columns(BYTE state[16]) {
    for (int col = 0; col < 4; col++) {
        BYTE* s = &state[col * 4];
        BYTE a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
        s[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

static void aes_inv_mix_columns(BYTE state[16]) {
    for (int col = 0; col < 4; col++) {
        BYTE* s = &state[col * 4];
        BYTE a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3];
        s[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/* Decrypt a single AES block */
static void aes_decrypt_block(PTEKTON_AES_CTX ctx, BYTE block[16]) {
    DWORD nr = ctx->num_rounds;
    DWORD* rk = ctx->round_keys;

    /* Column-major state */
    BYTE state[16];
    for (int col = 0; col < 4; col++) {
        state[col*4+0] = block[col*4+0];
        state[col*4+1] = block[col*4+1];
        state[col*4+2] = block[col*4+2];
        state[col*4+3] = block[col*4+3];
    }

    aes_add_round_key(state, &rk[nr * 4]);

    for (int round = (int)nr - 1; round >= 1; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, &rk[round * 4]);
        aes_inv_mix_columns(state);
    }

    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &rk[0]);

    memcpy(block, state, 16);
}

/* Encrypt a single AES block */
static void aes_encrypt_block(PTEKTON_AES_CTX ctx, BYTE block[16]) {
    DWORD nr = ctx->num_rounds;
    DWORD* rk = ctx->round_keys;

    BYTE state[16];
    memcpy(state, block, 16);

    aes_add_round_key(state, &rk[0]);

    for (DWORD round = 1; round < nr; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &rk[round * 4]);
    }

    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &rk[nr * 4]);

    memcpy(block, state, 16);
}

/* ── AES Public API ──────────────────────────────────────── */

TEKTON_STATUS TektonCryptoAesInit(
    PTEKTON_AES_CTX ctx,
    const BYTE*     key,
    SIZE_T          key_len
) {
    if (!ctx || !key) return TEKTON_ERR_INVALID_PARAM;
    if (key_len != TEKTON_AES_KEY_SIZE) {
        TLOG_ERROR("AES key must be %d bytes (got %lu)", TEKTON_AES_KEY_SIZE, (unsigned long)key_len);
        return TEKTON_ERR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(TEKTON_AES_CTX));
    aes_key_expansion(ctx, key);
    return TEKTON_OK;
}

TEKTON_STATUS TektonCryptoAesCbcDecrypt(
    PTEKTON_AES_CTX ctx,
    BYTE*           data,
    SIZE_T          data_len,
    const BYTE*     iv
) {
    if (!ctx || !data || !iv) return TEKTON_ERR_INVALID_PARAM;
    if (data_len == 0 || data_len % TEKTON_AES_BLOCK_SIZE != 0) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    SIZE_T num_blocks = data_len / TEKTON_AES_BLOCK_SIZE;
    BYTE prev_cipher[TEKTON_AES_BLOCK_SIZE];
    BYTE saved_cipher[TEKTON_AES_BLOCK_SIZE];

    memcpy(prev_cipher, iv, TEKTON_AES_BLOCK_SIZE);

    for (SIZE_T i = 0; i < num_blocks; i++) {
        BYTE* block = data + (i * TEKTON_AES_BLOCK_SIZE);

        /* Save ciphertext before decryption (needed for CBC chain) */
        memcpy(saved_cipher, block, TEKTON_AES_BLOCK_SIZE);

        /* Decrypt block */
        aes_decrypt_block(ctx, block);

        /* XOR with previous ciphertext (or IV for first block) */
        for (int j = 0; j < TEKTON_AES_BLOCK_SIZE; j++) {
            block[j] ^= prev_cipher[j];
        }

        memcpy(prev_cipher, saved_cipher, TEKTON_AES_BLOCK_SIZE);
    }

    TEKTON_SECURE_ZERO(prev_cipher, TEKTON_AES_BLOCK_SIZE);
    TEKTON_SECURE_ZERO(saved_cipher, TEKTON_AES_BLOCK_SIZE);

    return TEKTON_OK;
}

TEKTON_STATUS TektonCryptoAesCbcEncrypt(
    PTEKTON_AES_CTX ctx,
    BYTE*           data,
    SIZE_T*         data_len,
    SIZE_T          buffer_cap,
    const BYTE*     iv
) {
    if (!ctx || !data || !data_len || !iv) return TEKTON_ERR_INVALID_PARAM;

    SIZE_T plain_len = *data_len;

    /* PKCS7 padding */
    BYTE pad_val = TEKTON_AES_BLOCK_SIZE - (BYTE)(plain_len % TEKTON_AES_BLOCK_SIZE);
    SIZE_T padded_len = plain_len + pad_val;

    if (padded_len > buffer_cap) {
        TLOG_ERROR("Buffer too small for PKCS7 padding (%lu need %lu)",
            (unsigned long)buffer_cap, (unsigned long)padded_len);
        return TEKTON_ERR_ALLOC;
    }

    /* Apply padding */
    for (SIZE_T i = plain_len; i < padded_len; i++) {
        data[i] = pad_val;
    }
    *data_len = padded_len;

    SIZE_T num_blocks = padded_len / TEKTON_AES_BLOCK_SIZE;
    BYTE chain[TEKTON_AES_BLOCK_SIZE];
    memcpy(chain, iv, TEKTON_AES_BLOCK_SIZE);

    for (SIZE_T i = 0; i < num_blocks; i++) {
        BYTE* block = data + (i * TEKTON_AES_BLOCK_SIZE);

        /* XOR with previous ciphertext (or IV) */
        for (int j = 0; j < TEKTON_AES_BLOCK_SIZE; j++) {
            block[j] ^= chain[j];
        }

        /* Encrypt block */
        aes_encrypt_block(ctx, block);

        /* This ciphertext becomes next chain value */
        memcpy(chain, block, TEKTON_AES_BLOCK_SIZE);
    }

    TEKTON_SECURE_ZERO(chain, TEKTON_AES_BLOCK_SIZE);
    return TEKTON_OK;
}

/* ── Environment-Keyed Derivation (Cat 3.2) ──────────────── */

TEKTON_STATUS TektonCryptoDeriveEnvKey(
    BYTE*       out_key,
    SIZE_T      key_len,
    const char* custom_seed
) {
    if (!out_key || key_len == 0) return TEKTON_ERR_INVALID_PARAM;

    BYTE seed_data[512];
    SIZE_T seed_len = 0;

    if (custom_seed) {
        /* Use provided seed */
        size_t slen = strlen(custom_seed);
        if (slen > sizeof(seed_data)) slen = sizeof(seed_data);
        memcpy(seed_data, custom_seed, slen);
        seed_len = slen;
    } else {
#ifdef _WIN32
        /* Derive from machine attributes: hostname + username + domain */
        char hostname[128] = {0};
        char username[128] = {0};
        char domain[128]   = {0};

        DWORD h_len = sizeof(hostname);
        DWORD u_len = sizeof(username);

        GetComputerNameA(hostname, &h_len);
        GetUserNameA(username, &u_len);
        GetEnvironmentVariableA("USERDOMAIN", domain, sizeof(domain));

        seed_len = (SIZE_T)snprintf((char*)seed_data, sizeof(seed_data),
            "%s:%s:%s:tekton-v1", hostname, username, domain);
#else
        /* Dev mode: use a test seed */
        const char* dev_seed = "dev:researcher:WORKGROUP:tekton-v1";
        size_t slen = strlen(dev_seed);
        memcpy(seed_data, dev_seed, slen);
        seed_len = slen;
#endif
    }

    /* Stretch seed into key material using iterated FNV-1a */
    SIZE_T offset = 0;
    DWORD counter = 0;

    while (offset < key_len) {
        /* Hash: seed + counter */
        BYTE block_input[520];
        memcpy(block_input, seed_data, seed_len);
        block_input[seed_len]   = (BYTE)(counter & 0xFF);
        block_input[seed_len+1] = (BYTE)((counter >> 8) & 0xFF);
        block_input[seed_len+2] = (BYTE)((counter >> 16) & 0xFF);
        block_input[seed_len+3] = (BYTE)((counter >> 24) & 0xFF);

        DWORD hash = TektonCryptoFnv1a32(block_input, seed_len + 4);

        SIZE_T copy = key_len - offset;
        if (copy > 4) copy = 4;

        out_key[offset]     = (BYTE)(hash & 0xFF);
        if (copy > 1) out_key[offset+1] = (BYTE)((hash >> 8) & 0xFF);
        if (copy > 2) out_key[offset+2] = (BYTE)((hash >> 16) & 0xFF);
        if (copy > 3) out_key[offset+3] = (BYTE)((hash >> 24) & 0xFF);

        offset += copy;
        counter++;
    }

    TEKTON_SECURE_ZERO(seed_data, sizeof(seed_data));
    return TEKTON_OK;
}

/* ── Triple Encryption (Cat 3.4) ─────────────────────────── */

TEKTON_STATUS TektonCryptoTripleInit(
    PTEKTON_TRIPLE_CTX  ctx,
    const BYTE*         aes_key,    SIZE_T aes_key_len,
    const BYTE*         rc4_key,    SIZE_T rc4_key_len,
    const BYTE*         xor_key,    SIZE_T xor_key_len,
    const BYTE*         aes_iv
) {
    if (!ctx || !aes_key || !rc4_key || !xor_key || !aes_iv) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(TEKTON_TRIPLE_CTX));

    /* Layer 1: AES-256 */
    TEKTON_STATUS status = TektonCryptoAesInit(&ctx->aes, aes_key, aes_key_len);
    if (status != TEKTON_OK) return status;

    memcpy(ctx->aes_iv, aes_iv, TEKTON_AES_IV_SIZE);

    /* Layer 2: RC4 */
    TektonCryptoRc4Init(&ctx->rc4, rc4_key, rc4_key_len);

    /* Layer 3: XOR */
    SIZE_T xlen = xor_key_len;
    if (xlen > sizeof(ctx->xor_key)) xlen = sizeof(ctx->xor_key);
    memcpy(ctx->xor_key, xor_key, xlen);
    ctx->xor_key_len = xlen;

    ctx->initialized = TRUE;
    return TEKTON_OK;
}

TEKTON_STATUS TektonCryptoTripleDecrypt(
    PTEKTON_TRIPLE_CTX  ctx,
    BYTE*               data,
    SIZE_T*             data_len
) {
    if (!ctx || !ctx->initialized || !data || !data_len) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Decrypt order: AES (outer) -> RC4 (middle) -> XOR (inner) */

    /* Layer 1: AES-256-CBC decrypt */
    TEKTON_STATUS status = TektonCryptoAesCbcDecrypt(&ctx->aes, data, *data_len, ctx->aes_iv);
    if (status != TEKTON_OK) return status;

    /* Remove PKCS7 padding */
    BYTE pad = data[*data_len - 1];
    if (pad > 0 && pad <= TEKTON_AES_BLOCK_SIZE) {
        BOOL valid_pad = TRUE;
        for (BYTE i = 0; i < pad; i++) {
            if (data[*data_len - 1 - i] != pad) {
                valid_pad = FALSE;
                break;
            }
        }
        if (valid_pad) {
            *data_len -= pad;
        }
    }

    /* Layer 2: RC4 decrypt */
    TEKTON_RC4_STATE rc4_copy;
    memcpy(&rc4_copy, &ctx->rc4, sizeof(TEKTON_RC4_STATE));
    TektonCryptoRc4Process(&rc4_copy, data, *data_len);
    TEKTON_SECURE_ZERO(&rc4_copy, sizeof(rc4_copy));

    /* Layer 3: XOR decrypt */
    TektonCryptoXor(data, *data_len, ctx->xor_key, ctx->xor_key_len);

    return TEKTON_OK;
}

TEKTON_STATUS TektonCryptoTripleEncrypt(
    PTEKTON_TRIPLE_CTX  ctx,
    BYTE*               data,
    SIZE_T*             data_len,
    SIZE_T              buffer_cap
) {
    if (!ctx || !ctx->initialized || !data || !data_len) {
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Encrypt order: XOR (inner) -> RC4 (middle) -> AES (outer) */

    /* Layer 3: XOR encrypt */
    TektonCryptoXor(data, *data_len, ctx->xor_key, ctx->xor_key_len);

    /* Layer 2: RC4 encrypt */
    TEKTON_RC4_STATE rc4_copy;
    memcpy(&rc4_copy, &ctx->rc4, sizeof(TEKTON_RC4_STATE));
    TektonCryptoRc4Process(&rc4_copy, data, *data_len);
    TEKTON_SECURE_ZERO(&rc4_copy, sizeof(rc4_copy));

    /* Layer 1: AES-256-CBC encrypt (applies PKCS7 padding) */
    return TektonCryptoAesCbcEncrypt(&ctx->aes, data, data_len, buffer_cap, ctx->aes_iv);
}
