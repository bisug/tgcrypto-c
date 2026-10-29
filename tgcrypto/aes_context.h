#ifndef AES_CONTEXT_H
#define AES_CONTEXT_H

#include "aes256.h"
#include "aesni.h"

typedef struct tgcrypto_aes_context {
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
#if TGCRYPTO_AESNI
    __m128i roundKeys[15];
    int use_aesni;
#endif
} tgcrypto_aes_context;

static inline void tgcrypto_aes_context_init(tgcrypto_aes_context *context,
                                              const uint8_t key[32],
                                              uint8_t decrypt) {
#if TGCRYPTO_AESNI
    context->use_aesni = tgcrypto_aesni_available();

    if (context->use_aesni) {
        tgcrypto_aesni_expand_key(key, context->expandedKey, decrypt);
        tgcrypto_aesni_load_round_keys(context->expandedKey, context->roundKeys);
        return;
    }
#endif

    (decrypt ? aes256_set_decryption_key : aes256_set_encryption_key)(
        key, context->expandedKey);
}

static inline void tgcrypto_aes_context_wipe(tgcrypto_aes_context *context) {
#if TGCRYPTO_AESNI
    tgcrypto_wipe(context->roundKeys, sizeof(context->roundKeys));
#endif
    tgcrypto_wipe(context->expandedKey, sizeof(context->expandedKey));
}

#endif  // AES_CONTEXT_H
