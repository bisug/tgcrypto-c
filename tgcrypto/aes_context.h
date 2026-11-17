#ifndef AES_CONTEXT_H
#define AES_CONTEXT_H

#include "aes256.h"
#include "aesni.h"

/*
 * The 240-byte key buffer is plain integers, not ``__m128i``.
 *
 * This struct is embedded in a Python object, and CPython's object allocator
 * only guarantees 8-byte alignment on 32-bit targets. A ``__m128i`` member
 * would let the compiler assume 16-byte alignment and emit aligned 16-byte
 * moves, which fault on a misaligned context. Software uses the buffer as 60
 * uint32 words; AES-NI uses the same bytes for 15 round keys and loads them
 * with unaligned moves into an aligned local array.
 */
typedef struct tgcrypto_aes_context {
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
#if TGCRYPTO_AESNI
    int use_aesni;
#endif
} tgcrypto_aes_context;

static inline void tgcrypto_aes_context_init(tgcrypto_aes_context *context,
                                              const uint8_t key[32],
                                              uint8_t decrypt) {
#if TGCRYPTO_AESNI
    context->use_aesni = tgcrypto_aesni_available();

    if (context->use_aesni) {
        tgcrypto_aesni_expand_key(key, (uint8_t *) context->expandedKey, decrypt);
        return;
    }
#endif

    (decrypt ? aes256_set_decryption_key : aes256_set_encryption_key)(
        key, context->expandedKey);
}

static inline void tgcrypto_aes_context_wipe(tgcrypto_aes_context *context) {
    tgcrypto_wipe(context->expandedKey, sizeof(context->expandedKey));
}

#endif  // AES_CONTEXT_H
