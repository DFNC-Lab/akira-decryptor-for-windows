// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file aes256.cuh
 * @brief AES-256 block cipher -- CUDA device implementation.
 *
 * Implements the 14-round AES-256 encryption algorithm for GPU-accelerated
 * key schedule expansion and single-block encryption.  The S-Box lookup
 * table is embedded directly in this file (as device constant memory)
 * since it is an integral part of the AES specification and is also
 * shared by KCipher-2.
 *
 * The S-Box pointer is passed as a parameter to all functions so that
 * callers may supply a shared-memory copy for latency-critical paths.
 *
 * Reference: NIST FIPS 197 -- Advanced Encryption Standard (AES), 2001.
 *
 */
#pragma once

#include <cstdint>

/* =========================================================================
 *  AES S-Box (FIPS 197, Section 5.1.1)
 *
 *  Substitution values for the SubBytes() transformation.  Defined once
 *  in __constant__ memory and referenced by both AES-256 and KCipher-2
 *  device-side implementations.
 * ========================================================================= */

__device__ __constant__ uint8_t device_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/* =========================================================================
 *  AES-256 round constants (FIPS 197, Section 5.2)
 *
 *  RCON[i] = { rc_i, 0x00, 0x00, 0x00 } packed big-endian.
 *  Only indices 1..7 are used for AES-256 key expansion (Nk=8 yields
 *  60 round-key words, requiring 7 RCON applications).  Extra entries
 *  are included for generality.
 * ========================================================================= */

__device__ __constant__ uint32_t RCON[15] = {0x00000000u, 0x01000000u, 0x02000000u, 0x04000000u,
                                             0x08000000u, 0x10000000u, 0x20000000u, 0x40000000u,
                                             0x80000000u, 0x1B000000u, 0x36000000u, 0x6C000000u,
                                             0xD8000000u, 0xAB000000u, 0x4D000000u};

/* =========================================================================
 *  Internal helpers
 * ========================================================================= */

/**
 * @brief Rotate a 32-bit word left by 8 bits (RotWord in FIPS 197).
 *
 * @param w  Input word.
 * @return   w cyclically shifted left by one byte.
 */
__device__ __forceinline__ uint32_t aes_rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/**
 * @brief Apply SubWord (four independent S-Box lookups) to a 32-bit word.
 *
 * @param w     Input word.
 * @param sbox  Pointer to a 256-byte S-Box (constant or shared memory).
 * @return      Word with each byte independently substituted.
 */
__device__ __forceinline__ uint32_t aes_sub_word(uint32_t w, const uint8_t* sbox) {
    return ((uint32_t)sbox[(w >> 24) & 0xFF] << 24) | ((uint32_t)sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xFF] << 8) | ((uint32_t)sbox[(w) & 0xFF]);
}

/**
 * @brief GF(2^8) doubling with irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 *
 * Core operation for MixColumns: multiplies a byte by {02} in GF(2^8).
 *
 * @param x  Input byte.
 * @return   x * {02} mod m(x).
 */
__device__ __forceinline__ uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

/* =========================================================================
 *  Public API
 * ========================================================================= */

/**
 * @brief Expand a 256-bit AES key into 15 round keys (240 bytes).
 *
 * Implements the AES-256 key schedule (FIPS 197, Section 5.2) producing
 * 60 x 32-bit words, serialized to big-endian bytes for direct use in
 * AddRoundKey.
 *
 * @param key       32-byte encryption key.
 * @param rk_bytes  Output buffer for 240 bytes of expanded round keys.
 * @param sbox      Pointer to a 256-byte S-Box.
 */
__device__ void aes_key_expand_256_bytes(const uint8_t key[32], uint8_t rk_bytes[240],
                                         const uint8_t* sbox) {
    uint32_t w[60];

#pragma unroll
    for (int i = 0; i < 8; ++i) {
        w[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
    }
    for (int i = 8; i < 60; ++i) {
        uint32_t temp = w[i - 1];
        if (i % 8 == 0)
            temp = aes_sub_word(aes_rot_word(temp), sbox) ^ RCON[i / 8];
        else if (i % 8 == 4)
            temp = aes_sub_word(temp, sbox);
        w[i] = w[i - 8] ^ temp;
    }

#pragma unroll
    for (int r = 0; r <= 14; ++r) {
#pragma unroll
        for (int c = 0; c < 4; ++c) {
            const uint32_t t = w[4 * r + c];
            const int base = 16 * r + 4 * c;
            rk_bytes[base + 0] = (uint8_t)(t >> 24);
            rk_bytes[base + 1] = (uint8_t)(t >> 16);
            rk_bytes[base + 2] = (uint8_t)(t >> 8);
            rk_bytes[base + 3] = (uint8_t)(t);
        }
    }
}

/**
 * @brief MixColumns transformation (FIPS 197, Section 5.1.3).
 *
 * Applies the fixed polynomial {03}x^3 + {01}x^2 + {01}x + {02}
 * to each column of the state matrix.
 *
 * @param s  16-byte state array (modified in place).
 */
__device__ void aes_mix_columns(uint8_t s[16]) {
#pragma unroll
    for (int c = 0; c < 4; ++c) {
        const int i = 4 * c;
        const uint8_t a0 = s[i + 0], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        const uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        const uint8_t u0 = a0, u1 = a1, u2 = a2, u3 = a3;
        s[i + 0] ^= t ^ aes_xtime((uint8_t)(u0 ^ u1));
        s[i + 1] ^= t ^ aes_xtime((uint8_t)(u1 ^ u2));
        s[i + 2] ^= t ^ aes_xtime((uint8_t)(u2 ^ u3));
        s[i + 3] ^= t ^ aes_xtime((uint8_t)(u3 ^ u0));
    }
}

/**
 * @brief SubBytes transformation (FIPS 197, Section 5.1.1).
 *
 * Independently substitutes each byte of the state through the S-Box.
 *
 * @param s     16-byte state array (modified in place).
 * @param sbox  Pointer to a 256-byte S-Box.
 */
__device__ void aes_sub_bytes(uint8_t s[16], const uint8_t* sbox) {
#pragma unroll
    for (int i = 0; i < 16; ++i)
        s[i] = sbox[s[i]];
}

/**
 * @brief ShiftRows transformation (FIPS 197, Section 5.1.2).
 *
 * Cyclically shifts rows 1-3 of the state matrix by 1, 2, and 3
 * positions respectively.  Row 0 is unchanged.
 *
 * @param s  16-byte state array (column-major, modified in place).
 */
__device__ void aes_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

/**
 * @brief AddRoundKey transformation (FIPS 197, Section 5.1.4).
 *
 * XORs the 16-byte state with one round key.
 *
 * @param s         16-byte state array (modified in place).
 * @param rk_round  Pointer to 16 bytes of the current round key.
 */
__device__ void aes_add_round_key(uint8_t s[16], const uint8_t* rk_round) {
#pragma unroll
    for (int i = 0; i < 16; ++i)
        s[i] ^= rk_round[i];
}

/**
 * @brief Encrypt a single 128-bit block with AES-256 (14 rounds).
 *
 * Performs the full AES-256 encryption pipeline: initial AddRoundKey,
 * 13 main rounds (SubBytes + ShiftRows + MixColumns + AddRoundKey),
 * and a final round (no MixColumns).
 *
 * @param in    16-byte plaintext input.
 * @param out   16-byte ciphertext output.
 * @param rk    240-byte expanded round keys (from aes_key_expand_256_bytes).
 * @param sbox  Pointer to a 256-byte S-Box.
 */
__device__ void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[240],
                                  const uint8_t* sbox) {
    uint8_t s[16];

#pragma unroll
    for (int i = 0; i < 16; ++i)
        s[i] = in[i];

    aes_add_round_key(s, rk + 0 * 16);

    for (int r = 1; r <= 13; ++r) {
        aes_sub_bytes(s, sbox);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, rk + 16 * r);
    }

    // Final round omits MixColumns per FIPS 197 Section 5.1
    aes_sub_bytes(s, sbox);
    aes_shift_rows(s);
    aes_add_round_key(s, rk + 16 * 14);

#pragma unroll
    for (int i = 0; i < 16; ++i)
        out[i] = s[i];
}
