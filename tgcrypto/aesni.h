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

/* VAES processes two independent 128-bit AES lanes per 256-bit instruction.
 * Needs GCC 10+ / Clang 14+ for __builtin_cpu_supports("vaes"); older
 * compilers and MSVC keep the verified 128-bit AES-NI path. */
#if (defined(__clang__) && __clang_major__ >= 14) || \
    (!defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 10)
#include <immintrin.h>
#define TGCRYPTO_VAES 1
#define TGCRYPTO_VAES_TARGET __attribute__((target("vaes,avx2"), unused))

static TGCRYPTO_VAES_TARGET int tgcrypto_vaes_available(void) {
    static int cached = -1;
    if (cached < 0) {
        __builtin_cpu_init();
        cached = (__builtin_cpu_supports("vaes") &&
                  __builtin_cpu_supports("avx2")) ? 1 : 0;
    }
    return cached;
}

/* Encrypt 16 CTR blocks (8 vectors x 2 lanes), then advance iv by 16.
 * The counter is a big-endian 128-bit value; lanes hold consecutive counters. */
static TGCRYPTO_VAES_TARGET void tgcrypto_vaes_ctr16(
    const uint8_t in[], uint8_t out[], const __m128i rk128[15], uint8_t iv[16]) {
    __m256i rk[15];
    __m256i v[8];
    uint8_t ctr[16];
    int i, r, k;

    for (i = 0; i < 15; ++i)
        rk[i] = _mm256_broadcastsi128_si256(rk128[i]);

    memcpy(ctr, iv, 16);

    for (i = 0; i < 8; ++i) {
        __m128i lo = _mm_loadu_si128((const __m128i *) ctr);
        for (k = 15; k >= 0; --k)
            if (++ctr[k]) break;
        __m128i hi = _mm_loadu_si128((const __m128i *) ctr);
        for (k = 15; k >= 0; --k)
            if (++ctr[k]) break;
        v[i] = _mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1);
    }

    memcpy(iv, ctr, 16);

    for (i = 0; i < 8; ++i)
        v[i] = _mm256_xor_si256(v[i], rk[0]);

    for (r = 1; r < 14; ++r)
        for (i = 0; i < 8; ++i)
            v[i] = _mm256_aesenc_epi128(v[i], rk[r]);

    for (i = 0; i < 8; ++i) {
        v[i] = _mm256_aesenclast_epi128(v[i], rk[14]);
        __m256i x = _mm256_loadu_si256((const __m256i *) (in + i * 32));
        _mm256_storeu_si256((__m256i *) (out + i * 32), _mm256_xor_si256(x, v[i]));
    }

    tgcrypto_wipe(rk, sizeof(rk));
}

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

#if TGCRYPTO_VAES
/* Compare the VAES kernel against the verified 128-bit path on a fixed vector.
 * Runs once on VAES hardware; if the kernel is wrong we fall back rather than
 * emit bad ciphertext. Kept non-inline so it lives outside the hot path. */
static TGCRYPTO_VAES_TARGET int tgcrypto_vaes_selftest_impl(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    uint8_t iv[16], in[16 * 16], out_vaes[16 * 16], out_ref[16 * 16];
    __m128i rk[15];
    int i, j, k;

    {
        uint8_t rkbytes[240];
        tgcrypto_aesni_expand_key(key, rkbytes, 0);
        for (i = 0; i < 15; ++i)
            rk[i] = _mm_loadu_si128((const __m128i *) &rkbytes[16 * i]);
        tgcrypto_wipe(rkbytes, sizeof(rkbytes));
    }

    for (i = 0; i < 16; ++i) iv[i] = (uint8_t) i;
    for (i = 0; i < (int) sizeof(in); ++i) in[i] = (uint8_t) (i * 7 + 3);

    memcpy(out_vaes, in, sizeof(in));
    {
        uint8_t civ[16];
        memcpy(civ, iv, 16);
        tgcrypto_vaes_ctr16(in, out_vaes, rk, civ);
    }

    {
        uint8_t civ[16];
        memcpy(civ, iv, 16);
        for (i = 0; i < 16; ++i) {
            uint8_t ksbuf[16];
            _mm_storeu_si128((__m128i *) ksbuf,
                tgcrypto_aesni_encrypt_block(_mm_loadu_si128((const __m128i *) civ), rk));
            for (j = 0; j < 16; ++j)
                out_ref[i * 16 + j] = in[i * 16 + j] ^ ksbuf[j];
            for (k = 15; k >= 0; --k)
                if (++civ[k]) break;
        }
    }

    return memcmp(out_vaes, out_ref, sizeof(in)) == 0;
}

static __attribute__((unused)) int tgcrypto_vaes_selftest(void) {
    static int cached = -1;
    if (cached < 0) {
        if (tgcrypto_vaes_available())
            cached = tgcrypto_vaes_selftest_impl() ? 1 : 0;
        else
            cached = 0;
    }
    return cached;
}
#endif

#endif  // TGCRYPTO_AESNI

#endif  // TGCRYPTO_AESNI_H
