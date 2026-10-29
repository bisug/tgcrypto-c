#ifndef AES_CONTEXT_H
#define AES_CONTEXT_H

#include "aes256.h"
#include "aesni.h"

/*
 * AES-NI round keys are stored as raw bytes, not ``__m128i``.
 *
 * This struct is embedded in a Python object, and CPython's object allocator
 * only guarantees 8-byte alignment on 32-bit targets. A ``__m128i`` member
 * would let the compiler assume 16-byte alignment and emit aligned 16-byte
 * moves, which raise an access violation when the context lands on an
 * 8-byte-aligned address. Bytes carry no alignment requirement, and the
 * round-key helpers move them in with unaligned loads.
 */
#define TGCRYPTO_AESNI_ROUND_KEY_BYTES 240

typedef struct tgcrypto_aes_context {
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
#if TGCRYPTO_AESNI
    uint8_t roundKeyBytes[TGCRYPTO_AESNI_ROUND_KEY_BYTES];
    int use_aesni;
#endif
} tgcrypto_aes_context;

static inline void tgcrypto_aes_context_init(tgcrypto_aes_context *context,
                                              const uint8_t key[32],
                                              uint8_t decrypt) {
#if TGCRYPTO_AESNI
    context->use_aesni = tgcrypto_aesni_available();

    if (context->use_aesni) {
        __m128i roundKeys[15];

        tgcrypto_aesni_expand_key(key, context->expandedKey, decrypt);
        tgcrypto_aesni_load_round_keys(context->expandedKey, roundKeys);
        tgcrypto_aesni_store_keys(roundKeys, context->roundKeyBytes);
        tgcrypto_wipe(roundKeys, sizeof(roundKeys));
        tgcrypto_wipe(context->expandedKey, sizeof(context->expandedKey));
        return;
    }
#endif

    (decrypt ? aes256_set_decryption_key : aes256_set_encryption_key)(
        key, context->expandedKey);
}

static inline void tgcrypto_aes_context_wipe(tgcrypto_aes_context *context) {
#if TGCRYPTO_AESNI
    tgcrypto_wipe(context->roundKeyBytes, sizeof(context->roundKeyBytes));
#endif
    tgcrypto_wipe(context->expandedKey, sizeof(context->expandedKey));
}

#endif  // AES_CONTEXT_H
