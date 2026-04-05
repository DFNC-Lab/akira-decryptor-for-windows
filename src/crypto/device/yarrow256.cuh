// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file yarrow256.cuh
 * @brief Yarrow-256 PRNG -- CUDA device implementation.
 *
 * Implements the seed-to-random-bytes pipeline used by Akira ransomware:
 *   1. SHA-256 hash of the decimal QPC seed string,
 *   2. Yarrow iterate (repeated hashing to stretch entropy),
 *   3. AES-256-CTR keystream generation.
 *
 * The Yarrow-256 construction follows the design described in:
 *   J. Kelsey, B. Schneier, N. Ferguson, "Yarrow-160: Notes on the
 *   Design and Analysis of the Yarrow Cryptographic Pseudorandom Number
 *   Generator", SAC 1999.
 * Akira uses a 256-bit variant (SHA-256 + AES-256) with 1500 iterate
 * rounds instead of the original 160-bit design.
 *
 * Reference: Kelsey, Schneier, Ferguson, "Yarrow-160", SAC 1999.
 *
 */
#pragma once

#include "crypto/device/sha256.cuh"
#include "crypto/device/aes256.cuh"
#include "common/constants.h"

/* =========================================================================
 *  Internal helpers
 * ========================================================================= */

/**
 * @brief Increment a 128-bit big-endian counter by one.
 *
 * Used as the AES-256-CTR mode counter; propagates carry from the
 * least-significant byte (index 15) upward.
 *
 * @param ctr  16-byte big-endian counter (modified in place).
 */
__device__ __forceinline__ void inc128_be(uint8_t ctr[16]) {
#pragma unroll
    for (int i = 15; i >= 0; --i) {
        uint8_t nv = (uint8_t)(ctr[i] + 1);
        ctr[i] = nv;
        if (nv != 0)
            break; // No carry -- stop propagation
    }
}

/**
 * @brief Convert a uint64 to its decimal ASCII representation.
 *
 * Akira's Yarrow seed is the decimal string of a QPC value, not its
 * binary encoding.  This function replicates that conversion on-device
 * without printf / snprintf.
 *
 * @param x       Value to convert.
 * @param out     Output character buffer.
 * @param maxlen  Maximum characters to write (including NUL).
 * @return        Number of characters written (excluding NUL).
 */
__device__ int u64_to_dec(uint64_t x, char* out, int maxlen) {
    if (maxlen <= 0)
        return 0;
    if (x == 0) {
        if (maxlen > 1) {
            out[0] = '0';
            out[1] = '\0';
            return 1;
        }
        out[0] = '0';
        return 1;
    }
    char buf[32];
    int i = 0;
    while (x && i < (int)sizeof(buf)) {
        uint64_t q = x / 10, r = x - q * 10;
        buf[i++] = char('0' + r);
        x = q;
    }
    int n = (i < maxlen - 1) ? i : (maxlen - 1);
    for (int k = 0; k < n; ++k)
        out[k] = buf[i - 1 - k];
    if (n < maxlen)
        out[n] = '\0';
    return n;
}

/* =========================================================================
 *  Yarrow iterate
 * ========================================================================= */

/**
 * @brief Yarrow-256 iterate: stretch a 32-byte digest through repeated hashing.
 *
 * Performs YARROW_ITERATE_ROUNDS rounds of:
 *   digest = SHA-256(digest || v0 || round_index)
 * where v0 is the original (round-0) digest, cached as uint32_t words.
 *
 * This uses the raw sha256_compress() to avoid byte-level repacking:
 *   Block 1 (64 bytes): current digest (32 bytes) || v0 (32 bytes)
 *   Block 2 (4+ bytes): big-endian round index + Merkle-Damgard padding
 *   Total message length per round = 68 bytes = 544 bits.
 *
 * @param digest  [in/out] 32-byte hash; overwritten with iterated result.
 */
__device__ void yarrow_iterate_device(uint8_t digest[32]) {
    // Convert initial digest to uint32_t words (big-endian) once
    uint32_t v0_w[8], cur_w[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        uint32_t w = ((uint32_t)digest[4 * i] << 24) | ((uint32_t)digest[4 * i + 1] << 16) |
                     ((uint32_t)digest[4 * i + 2] << 8) | (uint32_t)digest[4 * i + 3];
        v0_w[i] = w;
        cur_w[i] = w;
    }

    uint32_t st[8], m[16];

    for (unsigned r = 1; r < YARROW_ITERATE_ROUNDS; ++r) {
        st[0] = 0x6a09e667u;
        st[1] = 0xbb67ae85u;
        st[2] = 0x3c6ef372u;
        st[3] = 0xa54ff53au;
        st[4] = 0x510e527fu;
        st[5] = 0x9b05688cu;
        st[6] = 0x1f83d9abu;
        st[7] = 0x5be0cd19u;

        // Block 1: current digest words (no byte serialize/deserialize round-trip)
#pragma unroll
        for (int i = 0; i < 8; ++i)
            m[i] = cur_w[i];
#pragma unroll
        for (int i = 0; i < 8; ++i)
            m[i + 8] = v0_w[i];

        sha256_compress(st, m);

        // Block 2: round index + padding (fixed layout)
        m[0] = r;
        m[1] = 0x80000000u;
        m[2] = 0u;
        m[3] = 0u;
        m[4] = 0u;
        m[5] = 0u;
        m[6] = 0u;
        m[7] = 0u;
        m[8] = 0u;
        m[9] = 0u;
        m[10] = 0u;
        m[11] = 0u;
        m[12] = 0u;
        m[13] = 0u;
        m[14] = 0u;
        m[15] = 544u;  // Message length in bits (68 bytes = 544 bits).
                       // sha256_compress() is a word-level API (no byte-swap),
                       // so storing 544 as a native uint32 is correct.

        sha256_compress(st, m);

        // Carry forward as uint32_t words -- avoid byte conversion until final round
#pragma unroll
        for (int i = 0; i < 8; ++i)
            cur_w[i] = st[i];
    }

    // Final: serialize back to bytes only once
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (uint8_t)(cur_w[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(cur_w[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(cur_w[i] >> 8);
        digest[4 * i + 3] = (uint8_t)(cur_w[i]);
    }
}

/* =========================================================================
 *  Full PRNG pipeline
 * ========================================================================= */

/**
 * @brief Generate pseudo-random bytes from a QPC seed value.
 *
 * Executes the complete Yarrow-256 pipeline:
 *   1. Convert seed to decimal ASCII string.
 *   2. SHA-256 hash the string to get a 32-byte digest.
 *   3. Run yarrow_iterate_device() to stretch the digest.
 *   4. Use the iterated digest as an AES-256 key.
 *   5. Generate a CTR-mode keystream (the first encrypted counter
 *      block becomes the IV for subsequent blocks).
 *
 * @param buffer  Output buffer for random bytes (device memory).
 * @param size    Number of random bytes to generate.
 * @param seed    QPC tick value used as the PRNG seed.
 * @param sbox    Pointer to a 256-byte AES S-Box.
 */
__device__ void generate_random(char* buffer, int size, uint64_t seed, const uint8_t* sbox) {
    if (size <= 0)
        return;

    // Step 1: Convert seed to decimal string
    uint8_t seedbuf[32];
    for (int i = 0; i < 32; ++i)
        seedbuf[i] = 0;
    int seed_len = u64_to_dec(seed, reinterpret_cast<char*>(seedbuf), 32);

    // Step 2: SHA-256 hash of seed string
    uint8_t digest[32];
    {
        Sha256Context ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, seedbuf, (size_t)seed_len);
        sha256_final(&ctx, digest);
    }

    // Step 3: Yarrow iterate (entropy stretching)
    yarrow_iterate_device(digest);

    // Step 4: AES-256 key expansion from iterated digest
    uint8_t rk[240];
    aes_key_expand_256_bytes(digest, rk, sbox);

    // Step 5: AES-256-CTR keystream generation
    // First block encryption establishes the counter IV
    uint8_t ctr[16] = {0}, tmp[16];
    aes_encrypt_block(ctr, tmp, rk, sbox);
#pragma unroll
    for (int i = 0; i < 16; i++)
        ctr[i] = tmp[i];

    size_t pos = 0;
    uint8_t* out = reinterpret_cast<uint8_t*>(buffer);
    while (pos < (size_t)size) {
        aes_encrypt_block(ctr, tmp, rk, sbox);
        size_t take = ((size_t)size - pos) < 16 ? ((size_t)size - pos) : 16;
#pragma unroll
        for (size_t j = 0; j < take; j++)
            out[pos + j] = tmp[j];
        pos += take;
        inc128_be(ctr);
    }
}
