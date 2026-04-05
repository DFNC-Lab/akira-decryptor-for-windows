// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file chacha8.c
 * @brief ChaCha8 stream cipher -- host-side implementation (opaque ADT).
 *
 * Implements the ChaCha family cipher with 8 rounds (4 double-rounds) and
 * a 16-byte key.  Akira uses the "expand 16-byte k" (tau) constant, which
 * duplicates the 16-byte key to fill the 32-byte key slot of standard
 * ChaCha20.
 *
 * The struct Chacha8 definition is private to this file; external code
 * accesses it only via the pointer-based API declared in chacha8.h.
 *
 * Reference: D.J. Bernstein, "ChaCha, a variant of Salsa20", 2008.
 *
 */

#include "chacha8.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================================
 *  ChaCha "tau" constant: "expand 16-byte k" in little-endian uint32_t
 *
 *  tau[0] = 0x61707865  ("expa")
 *  tau[1] = 0x3120646e  ("nd 1")
 *  tau[2] = 0x79622d36  ("6-by")
 *  tau[3] = 0x6b206574  ("te k")
 * ========================================================================= */

static const uint32_t CHACHA_TAU[4] = {0x61707865u, 0x3120646eu, 0x79622d36u, 0x6b206574u};

/* =========================================================================
 *  Internal ChaCha8 state (hidden from callers)
 * ========================================================================= */

struct Chacha8 {
    uint32_t key[4]; ///< 128-bit key as four LE words.
    uint32_t iv_lo;  ///< IV lower 32 bits (LE).
    uint32_t iv_hi;  ///< IV upper 32 bits (LE).
    uint32_t ctr_lo; ///< 64-bit block counter, low word.
    uint32_t ctr_hi; ///< 64-bit block counter, high word.
};

/* =========================================================================
 *  Utility functions
 * ========================================================================= */

/**
 * @brief 32-bit left rotation.
 */
static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

/**
 * @brief Load a little-endian uint32_t from a byte pointer.
 */
static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * @brief Store a uint32_t in little-endian byte order.
 */
static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* =========================================================================
 *  ChaCha quarter-round macro
 * ========================================================================= */

#define QR(s, a, b, c, d)                                                                          \
    do {                                                                                           \
        s[a] += s[b];                                                                              \
        s[d] ^= s[a];                                                                              \
        s[d] = rotl32(s[d], 16);                                                                   \
        s[c] += s[d];                                                                              \
        s[b] ^= s[c];                                                                              \
        s[b] = rotl32(s[b], 12);                                                                   \
        s[a] += s[b];                                                                              \
        s[d] ^= s[a];                                                                              \
        s[d] = rotl32(s[d], 8);                                                                    \
        s[c] += s[d];                                                                              \
        s[b] ^= s[c];                                                                              \
        s[b] = rotl32(s[b], 7);                                                                    \
    } while (0)

/* =========================================================================
 *  Core block function
 * ========================================================================= */

/**
 * @brief Generate one 64-byte keystream block and advance the counter.
 *
 * Builds the initial ChaCha state matrix from tau + key + counter + IV,
 * runs 4 double-rounds (= 8 rounds), then adds the initial state back
 * to produce the keystream block.
 *
 * @param cc   Active cipher context.
 * @param out  64-byte output buffer.
 */
static void chacha8_block(Chacha8* cc, uint8_t out[64]) {
    uint32_t s[16] = {
        CHACHA_TAU[0], CHACHA_TAU[1], CHACHA_TAU[2], CHACHA_TAU[3], cc->key[0], cc->key[1],
        cc->key[2],    cc->key[3],    cc->key[0],    cc->key[1],    cc->key[2], cc->key[3],
        cc->ctr_lo,    cc->ctr_hi,    cc->iv_lo,     cc->iv_hi,
    };
    uint32_t w[16];
    memcpy(w, s, sizeof(s));

    /* 4 double-rounds = 8 rounds total */
    for (int i = 0; i < 4; i++) {
        QR(w, 0, 4, 8, 12);
        QR(w, 1, 5, 9, 13);
        QR(w, 2, 6, 10, 14);
        QR(w, 3, 7, 11, 15);
        QR(w, 0, 5, 10, 15);
        QR(w, 1, 6, 11, 12);
        QR(w, 2, 7, 8, 13);
        QR(w, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++)
        store32_le(out + i * 4, w[i] + s[i]);

    /* Increment 64-bit block counter */
    cc->ctr_lo++;
    if (cc->ctr_lo == 0)
        cc->ctr_hi++;
}

/* =========================================================================
 *  Public API
 * ========================================================================= */

Chacha8* chacha8_create(const uint8_t key[16], const uint8_t iv[8]) {
    if (!key || !iv)
        return NULL;

    Chacha8* ctx = (Chacha8*)calloc(1, sizeof(Chacha8));
    if (!ctx)
        return NULL;

    for (int i = 0; i < 4; i++)
        ctx->key[i] = load32_le(key + i * 4);
    ctx->iv_lo = load32_le(iv);
    ctx->iv_hi = load32_le(iv + 4);
    ctx->ctr_lo = 0;
    ctx->ctr_hi = 0;

    return ctx;
}

void chacha8_destroy(Chacha8* ctx) {
    if (ctx) {
        volatile uint8_t* p = (volatile uint8_t*)ctx;
        for (size_t i = 0; i < sizeof(*ctx); i++)
            p[i] = 0;
        free(ctx);
    }
}

void chacha8_xor(Chacha8* ctx, uint8_t* data, size_t len) {
    uint8_t block[64];
    /* Process full 64-byte blocks, then XOR remaining bytes in the
     * final partial block.  Counter advances by ceil(len/64). */
    size_t off = 0;

    /* Full 64-byte blocks */
    while (off + 64 <= len) {
        chacha8_block(ctx, block);
        uint64_t* dst = (uint64_t*)(data + off);
        const uint64_t* src = (const uint64_t*)block;
        dst[0] ^= src[0];
        dst[1] ^= src[1];
        dst[2] ^= src[2];
        dst[3] ^= src[3];
        dst[4] ^= src[4];
        dst[5] ^= src[5];
        dst[6] ^= src[6];
        dst[7] ^= src[7];
        off += 64;
    }

    /* Final partial block: XOR only the remaining bytes */
    if (off < len) {
        chacha8_block(ctx, block);
        size_t rem = len - off;
        for (size_t i = 0; i < rem; i++)
            data[off + i] ^= block[i];
    }
}

void chacha8_discard(Chacha8* ctx, size_t len) {
    /* Advance counter by ceil(len/64) blocks, including partial blocks. */
    uint8_t dummy[64];
    const size_t n_blocks = (len + 63) / 64; /* ceil division */
    for (size_t b = 0; b < n_blocks; b++)
        chacha8_block(ctx, dummy);
}
