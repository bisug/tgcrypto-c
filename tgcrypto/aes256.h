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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef AES256_H
#define AES256_H

#define AES_BLOCK_SIZE 16
#define EXPANDED_KEY_SIZE 60

void aes256_set_encryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_set_decryption_key(const uint8_t key[32], uint32_t expandedKey[60]);

void aes256_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

void aes256_decrypt(const uint8_t in[16], uint8_t out[16], const uint32_t expandedKey[60]);

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define TGCRYPTO_WIPE_SSE2 1
#endif

/*
 * Best-effort memory wipe for key material. Stores go through volatile
 * pointers so the compiler cannot drop them. Where SSE2 is available, 16
 * bytes are cleared per store; otherwise 4 bytes per store. A byte-wise
 * volatile loop is the fallback for the tail and for other platforms.
 */
static inline void tgcrypto_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *) p;

#if TGCRYPTO_WIPE_SSE2
    /* Bring the pointer to a 16-byte boundary (at most 15 bytes). */
    while (n != 0 && (((uintptr_t) v) & 15) != 0) {
        *v++ = 0;
        --n;
    }

    const __m128i zero = _mm_setzero_si128();

    while (n >= 16) {
        *(volatile __m128i *) v = zero;
        v += 16;
        n -= 16;
    }
#endif

    /* Bring the pointer up to a 4-byte boundary (at most 3 bytes). */
    while (n != 0 && (((uintptr_t) v) & 3) != 0) {
        *v++ = 0;
        --n;
    }

    while (n >= 4) {
        *(volatile uint32_t *) v = 0;
        v += 4;
        n -= 4;
    }

    while (n != 0) {
        *v++ = 0;
        --n;
    }
}

#endif  // AES256_H
