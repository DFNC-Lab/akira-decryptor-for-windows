// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file sha256.cuh
 * @brief SHA-256 cryptographic hash -- CUDA device implementation.
 *
 * Provides both a streaming interface (init / update / final) and a raw
 * compression function for Yarrow-256 key derivation.  The streaming API
 * handles arbitrary-length messages with proper Merkle-Damgard padding;
 * the raw compression function (sha256_compress) is exposed separately
 * so that Yarrow's iterate loop can avoid re-packing message words.
 *
 * Reference: NIST FIPS 180-4 -- Secure Hash Standard (SHS), 2015.
 *
 */
#pragma once

#include <cstdint>
#include "common/device_math.cuh"

/* =========================================================================
 *  Constants
 * ========================================================================= */

/// SHA-256 digest length in bytes.
constexpr int SHA256_DIGEST_SIZE = 32;

/* -------------------------------------------------------------------------
 *  SHA-256 round constants (FIPS 180-4, Section 4.2.2)
 *
 *  First 32 bits of the fractional parts of the cube roots of the first
 *  64 prime numbers.
 * ------------------------------------------------------------------------- */

__device__ __constant__ uint32_t sha_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* =========================================================================
 *  Internal logical functions (FIPS 180-4, Section 4.1.2)
 * ========================================================================= */

/**
 * @brief Right-rotate a 32-bit word using PTX funnel-shift intrinsic.
 *
 * @param a  Value to rotate.
 * @param b  Rotation amount in bits.
 * @return   a rotated right by b bits.
 */
__device__ __forceinline__ uint32_t sha_rotright(uint32_t a, int b) {
    return __funnelshift_r(a, a, b);
}

/**
 * @brief Ch(x, y, z) = (x AND y) XOR (NOT x AND z).
 *
 * Uses PTX lop3.b32 instruction (truth table 0xCA) to compute all three
 * bitwise operations in a single cycle.
 */
__device__ __forceinline__ uint32_t sha_ch(uint32_t x, uint32_t y, uint32_t z) {
    uint32_t result;
    asm("lop3.b32 %0, %1, %2, %3, 0xCA;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

/**
 * @brief Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z).
 *
 * Uses PTX lop3.b32 instruction (truth table 0xE8) to compute the
 * majority function in a single cycle.
 */
__device__ __forceinline__ uint32_t sha_maj(uint32_t x, uint32_t y, uint32_t z) {
    uint32_t result;
    asm("lop3.b32 %0, %1, %2, %3, 0xE8;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

/** @brief Sigma_0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x). */
__device__ __forceinline__ uint32_t sha_ep0(uint32_t x) {
    return sha_rotright(x, 2) ^ sha_rotright(x, 13) ^ sha_rotright(x, 22);
}

/** @brief Sigma_1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x). */
__device__ __forceinline__ uint32_t sha_ep1(uint32_t x) {
    return sha_rotright(x, 6) ^ sha_rotright(x, 11) ^ sha_rotright(x, 25);
}

/** @brief sigma_0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x). */
__device__ __forceinline__ uint32_t sha_sig0(uint32_t x) {
    return sha_rotright(x, 7) ^ sha_rotright(x, 18) ^ (x >> 3);
}

/** @brief sigma_1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x). */
__device__ __forceinline__ uint32_t sha_sig1(uint32_t x) {
    return sha_rotright(x, 17) ^ sha_rotright(x, 19) ^ (x >> 10);
}

/* =========================================================================
 *  Streaming SHA-256 context
 * ========================================================================= */

/**
 * @brief Device-side SHA-256 hash context for incremental hashing.
 *
 * Maintains a 64-byte message buffer, partial byte count, total bit
 * count, and the intermediate 8-word hash state.
 */
struct Sha256Context {
    uint8_t data[64];          ///< Partial message block buffer.
    uint32_t datalen;          ///< Number of valid bytes in data[].
    unsigned long long bitlen; ///< Total bits hashed so far.
    uint32_t state[8];         ///< Intermediate hash state H_0..H_7.
};

/* =========================================================================
 *  Streaming API
 * ========================================================================= */

/**
 * @brief Process one 512-bit (64-byte) message block.
 *
 * Performs the message schedule expansion (16 -> 64 words) and executes
 * 64 compression rounds, updating the hash state in place.
 *
 * @param ctx   Hash context with current state.
 * @param data  Pointer to a 64-byte message block.
 */
__device__ __forceinline__ void sha256_transform(Sha256Context* ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

#pragma unroll
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);

    for (; i < 64; ++i)
        m[i] = sha_sig1(m[i - 2]) + m[i - 7] + sha_sig0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

#pragma unroll
    for (i = 0; i < 64; ++i) {
        t1 = h + sha_ep1(e) + sha_ch(e, f, g) + sha_k[i] + m[i];
        t2 = sha_ep0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

/**
 * @brief Initialize SHA-256 context with the standard IV.
 *
 * Sets the hash state to the initial values defined in FIPS 180-4
 * Section 5.3.3 (first 32 bits of fractional parts of the square roots
 * of the first 8 primes).
 *
 * @param ctx  Hash context to initialize.
 */
__device__ __forceinline__ void sha256_init(Sha256Context* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

/**
 * @brief Feed data into the SHA-256 hash.
 *
 * Buffers input bytes and processes complete 64-byte blocks as they
 * accumulate.  May be called multiple times with arbitrary chunk sizes.
 *
 * @param ctx   Hash context (maintains partial block state).
 * @param data  Input bytes.
 * @param len   Number of bytes to hash.
 */
__device__ __forceinline__ void sha256_update(Sha256Context* ctx, const uint8_t data[],
                                              size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/**
 * @brief Finalize the hash and produce the 32-byte digest.
 *
 * Applies Merkle-Damgard padding (1-bit, zeros, 64-bit big-endian
 * length) and writes the final hash value to the output buffer.
 *
 * @param ctx   Hash context (consumed; do not reuse after this call).
 * @param hash  Output buffer for the 32-byte (256-bit) digest.
 */
__device__ __forceinline__ void sha256_final(Sha256Context* ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        for (int z = 0; z < 56; ++z)
            ctx->data[z] = 0;
    } else {
        while (i < 56)
            ctx->data[i++] = 0x00;
    }

    ctx->bitlen += (unsigned long long)ctx->datalen * 8ull;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

// Serialize state words to big-endian bytes
#pragma unroll
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xFF;
    }
}

/* =========================================================================
 *  Raw compression function
 * ========================================================================= */

/**
 * @brief Raw SHA-256 compression on pre-packed 32-bit message words.
 *
 * Performs message schedule expansion (16 -> 64 words) and 64 compression
 * rounds, adding the results back into the running hash state.  This
 * entry point is used by Yarrow-256 iterate, which constructs message
 * blocks directly as uint32_t arrays to avoid byte-packing overhead.
 *
 * @param state  [in/out] 8-word hash state (H_0..H_7), updated in place.
 * @param m_in   [in]     16 big-endian message words.
 */
__device__ __noinline__ void sha256_compress(uint32_t state[8], const uint32_t m_in[16]) {
    uint32_t m[64];
#pragma unroll
    for (int i = 0; i < 16; ++i)
        m[i] = m_in[i];

#pragma unroll
    for (int i = 16; i < 64; ++i)
        m[i] = sha_sig1(m[i - 2]) + m[i - 7] + sha_sig0(m[i - 15]) + m[i - 16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

#pragma unroll
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + sha_ep1(e) + sha_ch(e, f, g) + sha_k[i] + m[i];
        uint32_t t2 = sha_ep0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}
