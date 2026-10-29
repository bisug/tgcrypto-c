/*
 * Pyrogram - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-present Dan <https://github.com/delivrance>
 *
 * This file is part of Pyrogram.
 *
 * Pyrogram is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyrogram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "aes_context.h"

void cbc256_ctx(const uint8_t in[], uint8_t out[], uint32_t length,
        const tgcrypto_aes_context *context, uint8_t iv[16],
        uint8_t encrypt) {
    uint8_t nextIv[AES_BLOCK_SIZE];
    uint32_t i, j;

    /* The AES-NI path reads the input directly and builds its round keys with
     * AES instructions; the software path below copies in -> out first and
     * needs the table-based expanded key. */
#if TGCRYPTO_AESNI
    if (context->use_aesni) {
        __m128i ivm, next, t;

        if (encrypt) {
            ivm = _mm_loadu_si128((const __m128i *) iv);

            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                t = _mm_loadu_si128((const __m128i *) &in[i]);
                t = _mm_xor_si128(t, ivm);
                t = tgcrypto_aesni_encrypt_block(t, context->roundKeys);
                _mm_storeu_si128((__m128i *) &out[i], t);
                ivm = t;
            }
        } else {
            ivm = _mm_loadu_si128((const __m128i *) iv);

            for (i = 0; i < length; i += AES_BLOCK_SIZE) {
                next = _mm_loadu_si128((const __m128i *) &in[i]);
                t = tgcrypto_aesni_decrypt_block(next, context->roundKeys);
                t = _mm_xor_si128(t, ivm);
                _mm_storeu_si128((__m128i *) &out[i], t);
                ivm = next;
            }
        }

        _mm_storeu_si128((__m128i *) iv, ivm);

        return;
    }
#endif

    /* The software path operates in place on out, so the input has to be
     * copied first. The AES-NI path above reads in directly and returns
     * before reaching this point, so it never pays for this copy. */
    memcpy(out, in, length);

    if (encrypt) {
        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= iv[j];

            aes256_encrypt(&out[i], &out[i], context->expandedKey);
            memcpy(iv, &out[i], AES_BLOCK_SIZE);
        }
    } else {
        for (i = 0; i < length; i += AES_BLOCK_SIZE) {
            memcpy(nextIv, &out[i], AES_BLOCK_SIZE);
            aes256_decrypt(&out[i], &out[i], context->expandedKey);

            for (j = 0; j < AES_BLOCK_SIZE; ++j)
                out[i + j] ^= iv[j];

            memcpy(iv, nextIv, AES_BLOCK_SIZE);
        }
    }

    tgcrypto_wipe(nextIv, sizeof(nextIv));
}

void cbc256(const uint8_t in[], uint8_t out[], uint32_t length,
            const uint8_t key[32], uint8_t iv[16], uint8_t encrypt) {
    tgcrypto_aes_context context;

    tgcrypto_aes_context_init(&context, key, (uint8_t) (encrypt ? 0 : 1));
    cbc256_ctx(in, out, length, &context, iv, encrypt);
    tgcrypto_aes_context_wipe(&context);
}
