/*
 * edr-tekton :: RC4 Stream Cipher Module
 * Cat 3.3: RC4 encryption with FNV-1a key seeding
 *
 * Wraps TektonCryptoRc4 into the module vtable.
 * RC4 is a stream cipher: no block alignment, no padding.
 * Small code footprint, hard to signature.
 *
 * Key seeding via FNV-1a: hash the raw key material through
 * FNV-1a to produce the actual RC4 key. This adds a layer
 * of indirection so the raw key never appears directly in
 * the KSA. The FNV-1a hash of key material generates 4 bytes
 * per iteration, stretched to the desired key length.
 */

#include "tekton/modules/encrypt.h"
#include "tekton/util/crypto.h"
#include "tekton/core/log.h"
#include <string.h>
#include <stdlib.h>

/* ── Internal state ─────────────────────────────────────── */

typedef struct _RC4_MODULE_STATE {
    TEKTON_KEY_SOURCE   key_source;
    BYTE                key[32];
    SIZE_T              key_len;
    BOOL                use_fnv1a_seed;     /* Hash key through FNV-1a first */
    BOOL                initialized;
} RC4_MODULE_STATE;

/* ── FNV-1a key stretching ──────────────────────────────── */

/*
 * Stretch raw key material into RC4 key using iterated FNV-1a.
 * Similar to env-key derivation but takes raw bytes as input.
 */
static void rc4_fnv1a_stretch_key(
    const BYTE* raw_key,
    SIZE_T      raw_len,
    BYTE*       out_key,
    SIZE_T      out_len
) {
    SIZE_T offset = 0;
    DWORD counter = 0;
    BYTE block[288];

    while (offset < out_len) {
        /* Build: raw_key + counter bytes */
        SIZE_T blen = raw_len;
        if (blen > 256) blen = 256;
        memcpy(block, raw_key, blen);

        block[blen]   = (BYTE)(counter & 0xFF);
        block[blen+1] = (BYTE)((counter >> 8) & 0xFF);
        block[blen+2] = (BYTE)((counter >> 16) & 0xFF);
        block[blen+3] = (BYTE)((counter >> 24) & 0xFF);

        DWORD hash = TektonCryptoFnv1a32(block, blen + 4);

        SIZE_T copy = out_len - offset;
        if (copy > 4) copy = 4;

        out_key[offset]     = (BYTE)(hash & 0xFF);
        if (copy > 1) out_key[offset+1] = (BYTE)((hash >> 8) & 0xFF);
        if (copy > 2) out_key[offset+2] = (BYTE)((hash >> 16) & 0xFF);
        if (copy > 3) out_key[offset+3] = (BYTE)((hash >> 24) & 0xFF);

        offset += copy;
        counter++;
    }

    TEKTON_SECURE_ZERO(block, sizeof(block));
}

/* ── Module vtable implementation ───────────────────────── */

static TEKTON_STATUS rc4_init(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)ctx;

    RC4_MODULE_STATE* state = (RC4_MODULE_STATE*)malloc(sizeof(RC4_MODULE_STATE));
    if (!state) return TEKTON_ERR_ALLOC;

    memset(state, 0, sizeof(*state));
    state->key_source = TEKTON_KEY_STATIC;
    state->use_fnv1a_seed = TRUE; /* Default: FNV-1a seeded */

    /* Default key (overridden by config) */
    static const BYTE default_key[] = {
        0x41, 0x72, 0x63, 0x34, 0x5F, 0x6B, 0x33, 0x79,
        0x5F, 0x74, 0x33, 0x6B, 0x74, 0x30, 0x6E, 0x21
    };
    memcpy(state->key, default_key, sizeof(default_key));
    state->key_len = sizeof(default_key);

    self->private_data = state;

    TLOG_DEBUG("encrypt_rc4: init (fnv1a_seed=%d)", state->use_fnv1a_seed);
    return TEKTON_OK;
}

static TEKTON_STATUS rc4_execute(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    RC4_MODULE_STATE* state = (RC4_MODULE_STATE*)self->private_data;
    if (!state) return TEKTON_ERR_INVALID_STATE;

    if (ctx->dry_run) {
        TLOG_INFO("encrypt_rc4: [DRY RUN] would RC4 decrypt payload (%lu bytes)",
            (unsigned long)ctx->payload.length);
        return TEKTON_OK;
    }

    /* Resolve key if environment-derived */
    if (state->key_source == TEKTON_KEY_ENV && !state->initialized) {
        TEKTON_STATUS ks = TektonCryptoDeriveEnvKey(state->key, 16, NULL);
        if (ks != TEKTON_OK) {
            TLOG_ERROR("encrypt_rc4: env key derivation failed");
            return ks;
        }
        state->key_len = 16;
        TLOG_DEBUG("encrypt_rc4: env key derived");
    }

    /* Validate payload */
    if (!ctx->payload.data || ctx->payload.length == 0) {
        TLOG_ERROR("encrypt_rc4: no payload to decrypt");
        return TEKTON_ERR_INVALID_PARAM;
    }

    /* Prepare the actual RC4 key */
    BYTE rc4_key[32];
    SIZE_T rc4_key_len;

    if (state->use_fnv1a_seed) {
        /* Stretch through FNV-1a for additional obfuscation */
        rc4_key_len = state->key_len;
        if (rc4_key_len > 32) rc4_key_len = 32;

        BYTE seed_buf[288];
        SIZE_T seed_len = state->key_len;
        if (seed_len > 256) seed_len = 256;

        rc4_fnv1a_stretch_key(state->key, state->key_len, rc4_key, rc4_key_len);
        TLOG_DEBUG("encrypt_rc4: FNV-1a stretched key (%lu -> %lu bytes)",
            (unsigned long)state->key_len, (unsigned long)rc4_key_len);
    } else {
        /* Use raw key directly */
        rc4_key_len = state->key_len;
        if (rc4_key_len > 32) rc4_key_len = 32;
        memcpy(rc4_key, state->key, rc4_key_len);
    }

    /* Allocate decrypted buffer */
    if (!ctx->decrypted.data) {
        ctx->decrypted.data = (BYTE*)malloc(ctx->payload.length);
        if (!ctx->decrypted.data) {
            TEKTON_SECURE_ZERO(rc4_key, sizeof(rc4_key));
            return TEKTON_ERR_ALLOC;
        }
        memcpy(ctx->decrypted.data, ctx->payload.data, ctx->payload.length);
        ctx->decrypted.length = ctx->payload.length;
        ctx->decrypted.capacity = ctx->payload.length;
    }

    /* RC4 decrypt (symmetric: encrypt == decrypt) */
    TektonCryptoRc4(ctx->decrypted.data, ctx->decrypted.length,
                    rc4_key, rc4_key_len);

    TEKTON_SECURE_ZERO(rc4_key, sizeof(rc4_key));
    state->initialized = TRUE;

    TLOG_INFO("encrypt_rc4: decrypted %lu bytes (fnv1a=%d)",
        (unsigned long)ctx->decrypted.length, state->use_fnv1a_seed);
    return TEKTON_OK;
}

static VOID rc4_cleanup(PTEKTON_MODULE self) {
    if (self->private_data) {
        TEKTON_SECURE_ZERO(self->private_data, sizeof(RC4_MODULE_STATE));
        free(self->private_data);
        self->private_data = NULL;
    }
}

static DWORD rc4_risk_score(PTEKTON_MODULE self) {
    (void)self;
    /* Low: RC4 KSA/PRGA are simple loops, hard to signature */
    return 6;
}

static BOOL rc4_check_compat(PTEKTON_MODULE self, PTEKTON_CONTEXT ctx) {
    (void)self;
    (void)ctx;
    return TRUE;
}

/* ── Module definition + auto-registration ──────────────── */

TEKTON_MODULE tekton_mod_encrypt_rc4 = {
    .name           = "encrypt_rc4",
    .description    = "RC4 stream cipher with FNV-1a seeding (Cat 3.3)",
    .category       = TEKTON_CAT_ENCRYPT,
    .target_surface = TEKTON_SURFACE_SCANNER,
    .flags          = 0,
    .skill_ref      = "3.3",
    .init           = rc4_init,
    .execute        = rc4_execute,
    .cleanup        = rc4_cleanup,
    .get_risk_score = rc4_risk_score,
    .check_compat   = rc4_check_compat,
    .private_data   = NULL,
    .next           = NULL,
};

TEKTON_DECLARE_MODULE(tekton_mod_encrypt_rc4);
