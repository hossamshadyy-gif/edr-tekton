#ifndef TEKTON_MOD_ENCRYPT_H
#define TEKTON_MOD_ENCRYPT_H

/*
 * edr-tekton :: Encryption Modules
 * Cat 3: Payload encryption/decryption chains.
 */

#include "../core/module.h"

/* ── Available Encryption Modules ─────────────────────── */

/* Cat 3.1: XOR encryption */
extern TEKTON_MODULE tekton_mod_encrypt_xor;

/* Cat 3.2: AES-256 with environment keying */
extern TEKTON_MODULE tekton_mod_encrypt_aes;

/* Cat 3.3: RC4 stream cipher */
extern TEKTON_MODULE tekton_mod_encrypt_rc4;

/* Cat 3.4: Triple encryption (AES -> RC4 -> XOR) */
extern TEKTON_MODULE tekton_mod_encrypt_triple;

/* ── Encryption Configuration ─────────────────────────── */

typedef enum _TEKTON_KEY_SOURCE {
    TEKTON_KEY_STATIC       = 0,    /* Hardcoded key in config   */
    TEKTON_KEY_ENV           = 1,    /* Derived from machine env  */
    TEKTON_KEY_DERIVED       = 2,    /* Custom derivation         */
    TEKTON_KEY_RANDOM        = 3,    /* Generated at build time   */
} TEKTON_KEY_SOURCE;

typedef struct _TEKTON_ENCRYPT_CFG {
    TEKTON_KEY_SOURCE   key_source;
    BYTE                static_key[32];
    SIZE_T              static_key_len;
    char                env_seed[256];      /* Custom env seed string */
} TEKTON_ENCRYPT_CFG, *PTEKTON_ENCRYPT_CFG;

#endif /* TEKTON_MOD_ENCRYPT_H */
