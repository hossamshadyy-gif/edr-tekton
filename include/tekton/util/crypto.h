#ifndef TEKTON_CRYPTO_H
#define TEKTON_CRYPTO_H

/*
 * edr-tekton :: Cryptographic Primitives
 * XOR, AES-256, RC4, and multi-layer encryption.
 * Cat 3.1, 3.2, 3.3, 3.4 from technique library.
 */

#include "../core/types.h"

/* ── XOR Encryption (Cat 3.1) ─────────────────────────── */

VOID TektonCryptoXor(
    BYTE*       data,
    SIZE_T      data_len,
    const BYTE* key,
    SIZE_T      key_len
);

/* Single-byte XOR (convenience) */
VOID TektonCryptoXorByte(
    BYTE*   data,
    SIZE_T  data_len,
    BYTE    key
);

/* ── RC4 Stream Cipher (Cat 3.3) ──────────────────────── */

typedef struct _TEKTON_RC4_STATE {
    BYTE    S[256];
    BYTE    i;
    BYTE    j;
} TEKTON_RC4_STATE, *PTEKTON_RC4_STATE;

VOID TektonCryptoRc4Init(
    PTEKTON_RC4_STATE   state,
    const BYTE*         key,
    SIZE_T              key_len
);

VOID TektonCryptoRc4Process(
    PTEKTON_RC4_STATE   state,
    BYTE*               data,
    SIZE_T              data_len
);

/* One-shot RC4 encrypt/decrypt */
VOID TektonCryptoRc4(
    BYTE*       data,
    SIZE_T      data_len,
    const BYTE* key,
    SIZE_T      key_len
);

/* ── AES-256 (Cat 3.2) ───────────────────────────────── */

#define TEKTON_AES_BLOCK_SIZE   16
#define TEKTON_AES_KEY_SIZE     32  /* 256 bits */
#define TEKTON_AES_IV_SIZE      16

typedef struct _TEKTON_AES_CTX {
    DWORD   round_keys[60];
    DWORD   num_rounds;
} TEKTON_AES_CTX, *PTEKTON_AES_CTX;

TEKTON_STATUS TektonCryptoAesInit(
    PTEKTON_AES_CTX ctx,
    const BYTE*     key,
    SIZE_T          key_len
);

/* CBC mode decrypt (in-place) */
TEKTON_STATUS TektonCryptoAesCbcDecrypt(
    PTEKTON_AES_CTX ctx,
    BYTE*           data,
    SIZE_T          data_len,
    const BYTE*     iv
);

/* CBC mode encrypt (in-place, with PKCS7 padding) */
TEKTON_STATUS TektonCryptoAesCbcEncrypt(
    PTEKTON_AES_CTX ctx,
    BYTE*           data,
    SIZE_T*         data_len,       /* In/out: padded length */
    SIZE_T          buffer_cap,     /* Buffer capacity       */
    const BYTE*     iv
);

/* ── FNV-1a Hash for Key Derivation (Cat 3.3) ─────────── */

#define FNV1A_OFFSET_BASIS_32  0x811C9DC5
#define FNV1A_PRIME_32         0x01000193

DWORD TektonCryptoFnv1a32(const BYTE* data, SIZE_T length);

/* ── Environment-Keyed Derivation (Cat 3.2) ───────────── */

/*
 * Derive a key from machine attributes:
 * hostname + username + domain (or custom seed).
 * Payload only decrypts on the target machine.
 */
TEKTON_STATUS TektonCryptoDeriveEnvKey(
    BYTE*   out_key,
    SIZE_T  key_len,
    const char* custom_seed     /* NULL for default env derivation */
);

/* ── Triple Encryption (Cat 3.4) ──────────────────────── */

typedef struct _TEKTON_TRIPLE_CTX {
    TEKTON_AES_CTX      aes;
    TEKTON_RC4_STATE    rc4;
    BYTE                xor_key[16];
    SIZE_T              xor_key_len;
    BYTE                aes_iv[TEKTON_AES_IV_SIZE];
    BOOL                initialized;
} TEKTON_TRIPLE_CTX, *PTEKTON_TRIPLE_CTX;

/* Initialize triple encryption with 3 separate keys */
TEKTON_STATUS TektonCryptoTripleInit(
    PTEKTON_TRIPLE_CTX  ctx,
    const BYTE*         aes_key,    SIZE_T aes_key_len,
    const BYTE*         rc4_key,    SIZE_T rc4_key_len,
    const BYTE*         xor_key,    SIZE_T xor_key_len,
    const BYTE*         aes_iv
);

/* Decrypt: AES outer -> RC4 middle -> XOR inner */
TEKTON_STATUS TektonCryptoTripleDecrypt(
    PTEKTON_TRIPLE_CTX  ctx,
    BYTE*               data,
    SIZE_T*             data_len
);

/* Encrypt: XOR inner -> RC4 middle -> AES outer */
TEKTON_STATUS TektonCryptoTripleEncrypt(
    PTEKTON_TRIPLE_CTX  ctx,
    BYTE*               data,
    SIZE_T*             data_len,
    SIZE_T              buffer_cap
);

#endif /* TEKTON_CRYPTO_H */
