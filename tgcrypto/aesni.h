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

#include "aes256.h"

#ifndef TGCRYPTO_AESNI_H
#define TGCRYPTO_AESNI_H

/*
 * Optional AES-NI acceleration for x86/x86-64.
 *
 * The pure software implementation remains the default and the fallback:
 * - On non-x86 targets (e.g. arm64) nothing from this header is compiled in.
 * - CPU support is detected at runtime; without hardware support the
 *   software code paths are used.
 * - Defining TGCRYPTO_NO_AESNI (e.g. CFLAGS="-DTGCRYPTO_NO_AESNI") always
 *   compiles out the hardware path entirely.
 */

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && \
    !defined(TGCRYPTO_NO_AESNI) && \
    (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER))
#define TGCRYPTO_AESNI 1
#endif

#if TGCRYPTO_AESNI

#include <wmmintrin.h>
#include <tmmintrin.h>
#include <emmintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#define TGCRYPTO_AESNI_TARGET
#else
#define TGCRYPTO_AESNI_TARGET __attribute__((target("aes,ssse3"), unused))
#endif

static TGCRYPTO_AESNI_TARGET int tgcrypto_aesni_available(void) {
    static int cached = -1;

    if (cached < 0) {
#if defined(_MSC_VER)
        int info[4];

        __cpuid(info, 1);
        cached = (info[2] >> 25) & 1;
#else
        cached = __builtin_cpu_supports("aes") ? 1 : 0;
#endif
    }

    return cached;
}

static TGCRYPTO_AESNI_TARGET __m128i tgcrypto_aesni_encrypt_block(__m128i block, const __m128i roundKeys[15]) {
    int i;

    block = _mm_xor_si128(block, roundKeys[0]);

    for (i = 1; i < 14; ++i)
        block = _mm_aesenc_si128(block, roundKeys[i]);

    return _mm_aesenclast_si128(block, roundKeys[14]);
}

/* Encrypt four independent blocks with rounds interleaved so AESENC latency
 * overlaps across blocks. Used by CTR where consecutive counters are
 * independent. */
static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_encrypt_4blocks(
    __m128i c0, __m128i c1, __m128i c2, __m128i c3,
    const __m128i roundKeys[15],
    __m128i *ks0, __m128i *ks1, __m128i *ks2, __m128i *ks3) {
    int r;
    __m128i b0 = _mm_xor_si128(c0, roundKeys[0]);
    __m128i b1 = _mm_xor_si128(c1, roundKeys[0]);
    __m128i b2 = _mm_xor_si128(c2, roundKeys[0]);
    __m128i b3 = _mm_xor_si128(c3, roundKeys[0]);

    for (r = 1; r < 14; ++r) {
        b0 = _mm_aesenc_si128(b0, roundKeys[r]);
        b1 = _mm_aesenc_si128(b1, roundKeys[r]);
        b2 = _mm_aesenc_si128(b2, roundKeys[r]);
        b3 = _mm_aesenc_si128(b3, roundKeys[r]);
    }

    *ks0 = _mm_aesenclast_si128(b0, roundKeys[14]);
    *ks1 = _mm_aesenclast_si128(b1, roundKeys[14]);
    *ks2 = _mm_aesenclast_si128(b2, roundKeys[14]);
    *ks3 = _mm_aesenclast_si128(b3, roundKeys[14]);
}

/* Eight independent blocks at once, to fill the AES pipeline on CPUs that
 * can issue more than four AESENC instructions per cycle. */
static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_encrypt_8blocks(
    __m128i c0, __m128i c1, __m128i c2, __m128i c3,
    __m128i c4, __m128i c5, __m128i c6, __m128i c7,
    const __m128i roundKeys[15],
    __m128i *ks0, __m128i *ks1, __m128i *ks2, __m128i *ks3,
    __m128i *ks4, __m128i *ks5, __m128i *ks6, __m128i *ks7) {
    int r;
    __m128i b0 = _mm_xor_si128(c0, roundKeys[0]);
    __m128i b1 = _mm_xor_si128(c1, roundKeys[0]);
    __m128i b2 = _mm_xor_si128(c2, roundKeys[0]);
    __m128i b3 = _mm_xor_si128(c3, roundKeys[0]);
    __m128i b4 = _mm_xor_si128(c4, roundKeys[0]);
    __m128i b5 = _mm_xor_si128(c5, roundKeys[0]);
    __m128i b6 = _mm_xor_si128(c6, roundKeys[0]);
    __m128i b7 = _mm_xor_si128(c7, roundKeys[0]);

    for (r = 1; r < 14; ++r) {
        __m128i rk = roundKeys[r];
        b0 = _mm_aesenc_si128(b0, rk);
        b1 = _mm_aesenc_si128(b1, rk);
        b2 = _mm_aesenc_si128(b2, rk);
        b3 = _mm_aesenc_si128(b3, rk);
        b4 = _mm_aesenc_si128(b4, rk);
        b5 = _mm_aesenc_si128(b5, rk);
        b6 = _mm_aesenc_si128(b6, rk);
        b7 = _mm_aesenc_si128(b7, rk);
    }

    *ks0 = _mm_aesenclast_si128(b0, roundKeys[14]);
    *ks1 = _mm_aesenclast_si128(b1, roundKeys[14]);
    *ks2 = _mm_aesenclast_si128(b2, roundKeys[14]);
    *ks3 = _mm_aesenclast_si128(b3, roundKeys[14]);
    *ks4 = _mm_aesenclast_si128(b4, roundKeys[14]);
    *ks5 = _mm_aesenclast_si128(b5, roundKeys[14]);
    *ks6 = _mm_aesenclast_si128(b6, roundKeys[14]);
    *ks7 = _mm_aesenclast_si128(b7, roundKeys[14]);
}

/*
 * Copy serialized round keys into a local, naturally aligned array.
 *
 * Round keys live in the containing context as bytes rather than ``__m128i``,
 * because that context is embedded in a Python object and Python's allocator
 * only guarantees 8-byte alignment on 32-bit targets. A ``__m128i`` member
 * lets the compiler assume 16-byte alignment and emit aligned moves, which
 * fault on a misaligned context. Unaligned loads plus a local array keep the
 * round keys correctly aligned for the AES instructions regardless of how the
 * caller allocated the context.
 */
static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_load_keys(const uint8_t roundKeyBytes[240],
                                                                    __m128i roundKeys[15]) {
    int i;

    for (i = 0; i < 15; ++i)
        roundKeys[i] = _mm_loadu_si128((const __m128i *) &roundKeyBytes[16 * i]);
}


static TGCRYPTO_AESNI_TARGET __m128i tgcrypto_aesni_decrypt_block(__m128i block, const __m128i roundKeys[15]) {
    int i;

    block = _mm_xor_si128(block, roundKeys[0]);

    for (i = 1; i < 14; ++i)
        block = _mm_aesdec_si128(block, roundKeys[i]);

    return _mm_aesdeclast_si128(block, roundKeys[14]);
}

/*
 * AES-NI key expansion.
 *
 * Stores the 15 round keys directly in the byte order aesenc/aesdec consume,
 * so each mode call only needs unaligned loads. For decryption the keys are
 * transformed with aesimc (inverse MixColumns) and reversed:
 * dec[0] = K14, dec[i] = InvMix(K(14-i)), dec[14] = K0.
 */
static TGCRYPTO_AESNI_TARGET void tgcrypto_aesni_expand_key(const uint8_t key[32],
                                                            uint8_t roundKeyBytes[240],
                                                            uint8_t decrypt) {
    __m128i rk[15];
    __m128i lo, hi, t;
    int i;

    lo = _mm_loadu_si128((const __m128i *) key);
    hi = _mm_loadu_si128((const __m128i *) (key + 16));

#define TGCRYPTO_AESNI_NEXT_LO(rcon)                   \
    t = _mm_aeskeygenassist_si128(hi, rcon);           \
    t = _mm_shuffle_epi32(t, 0xFF);                    \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, _mm_slli_si128(lo, 4));     \
    lo = _mm_xor_si128(lo, t)
#define TGCRYPTO_AESNI_NEXT_HI()                       \
    t = _mm_aeskeygenassist_si128(lo, 0x00);           \
    t = _mm_shuffle_epi32(t, 0xAA);                    \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, _mm_slli_si128(hi, 4));     \
    hi = _mm_xor_si128(hi, t)

    rk[0] = lo;
    rk[1] = hi;

    TGCRYPTO_AESNI_NEXT_LO(0x01); rk[2] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[3] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x02); rk[4] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[5] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x04); rk[6] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[7] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x08); rk[8] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[9] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x10); rk[10] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[11] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x20); rk[12] = lo;
    TGCRYPTO_AESNI_NEXT_HI();     rk[13] = hi;
    TGCRYPTO_AESNI_NEXT_LO(0x40); rk[14] = lo;

#undef TGCRYPTO_AESNI_NEXT_LO
#undef TGCRYPTO_AESNI_NEXT_HI

    if (decrypt) {
        for (i = 1; i < 14; ++i)
            rk[i] = _mm_aesimc_si128(rk[i]);

        for (i = 0; i < 7; ++i) {
            t = rk[i];
            rk[i] = rk[14 - i];
            rk[14 - i] = t;
        }
    }

    for (i = 0; i < 15; ++i)
        _mm_storeu_si128((__m128i *) &roundKeyBytes[16 * i], rk[i]);

    tgcrypto_wipe(rk, sizeof(rk));
}

#endif  // TGCRYPTO_AESNI

#endif  // TGCRYPTO_AESNI_H
