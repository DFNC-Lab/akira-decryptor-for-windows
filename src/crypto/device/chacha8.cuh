// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file chacha8.cuh
 * @brief ChaCha8 stream cipher -- CUDA device implementation.
 *
 * Implements the reduced-round (8-round) variant of the ChaCha stream
 * cipher with a 16-byte key and 64-bit IV.  Akira ransomware uses
 * ChaCha8 for tail-block encryption within each file region; the
 * decryptor's Phase 2 kernel validates candidate seeds by decrypting
 * tail ciphertext and checking against known file signatures.
 *
 * The 16-byte key variant uses the "tau" constant ("expand 16-byte k")
 * per Bernstein's specification.  The key bytes are duplicated across
 * matrix rows 1 and 2 (words 4-7 and 8-11).
 *
 * Reference: D. J. Bernstein, "ChaCha, a variant of Salsa20", 2008.
 *            https://cr.yp.to/chacha/chacha-20080128.pdf
 *
 */
#pragma once

#include <cstdint>
#include "common/device_math.cuh"

/* =========================================================================
 *  Byte-order helpers
 * ========================================================================= */

/**
 * @brief Load a 32-bit word from a byte array in little-endian order.
 *
 * @param p  Pointer to 4 bytes.
 * @return   32-bit word assembled in little-endian.
 */
__device__ __forceinline__ uint32_t chacha8_load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * @brief Store a 32-bit word to a byte array in little-endian order.
 *
 * @param p  Destination pointer (4 bytes).
 * @param v  Value to store.
 */
__device__ __forceinline__ void chacha8_store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* =========================================================================
 *  Quarter-round
 * ========================================================================= */

/**
 * @brief ChaCha quarter-round operation.
 *
 * The fundamental mixing operation: four ARX (add-rotate-xor) steps
 * that diffuse bits across the four input words.  Each double-round
 * applies this to all four columns, then all four diagonals.
 *
 * @param a  First word (modified in place).
 * @param b  Second word (modified in place).
 * @param c  Third word (modified in place).
 * @param d  Fourth word (modified in place).
 */
__device__ __forceinline__ void chacha8_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c,
                                                      uint32_t& d) {
    a += b;
    d ^= a;
    d = rol32(d, 16);
    c += d;
    b ^= c;
    b = rol32(b, 12);
    a += b;
    d ^= a;
    d = rol32(d, 8);
    c += d;
    b ^= c;
    b = rol32(b, 7);
}

/* =========================================================================
 *  Block function
 * ========================================================================= */

/**
 * @brief Generate one 64-byte ChaCha8 keystream block (16-byte key variant).
 *
 * Sets up the 4x4 state matrix as:
 *
 *     tau[0]  tau[1]  tau[2]  tau[3]      <-- constants
 *     k[0]    k[1]    k[2]    k[3]       <-- key words
 *     k[0]    k[1]    k[2]    k[3]       <-- key words (duplicated for 16-byte key)
 *     ctr_lo  ctr_hi  iv_lo   iv_hi      <-- counter + IV
 *
 * The "tau" constant is the ASCII encoding of "expand 16-byte k":
 *   tau[0] = 0x61707865  ("expa")
 *   tau[1] = 0x3120646E  ("nd 1")
 *   tau[2] = 0x79622D36  ("6-by")
 *   tau[3] = 0x6B206574  ("te k")
 *
 * For 32-byte keys, the "sigma" constant "expand 32-byte k" would be
 * used instead, and key words would not be duplicated.  Akira uses
 * only 16-byte keys, so only tau is implemented here.
 *
 * Performs 4 double-rounds (= 8 quarter-rounds = "ChaCha8"), then adds
 * the initial state back and serializes to little-endian bytes.
 *
 * @param key16    16-byte ChaCha8 key.
 * @param ctr_lo   Lower 32 bits of the 64-bit block counter.
 * @param ctr_hi   Upper 32 bits of the 64-bit block counter.
 * @param iv_lo    Lower 32 bits of the 64-bit IV (nonce).
 * @param iv_hi    Upper 32 bits of the 64-bit IV (nonce).
 * @param keystream Output: 64-byte keystream block.
 */
__device__ __forceinline__ void chacha8_generate_block(const uint8_t key16[16], uint32_t ctr_lo,
                                                       uint32_t ctr_hi, uint32_t iv_lo,
                                                       uint32_t iv_hi, uint8_t keystream[64]) {
    // "expand 16-byte k" (tau) -- identifies the 128-bit key variant
    const uint32_t c0 = 0x61707865u; // "expa"
    const uint32_t c1 = 0x3120646eu; // "nd 1"
    const uint32_t c2 = 0x79622d36u; // "6-by"
    const uint32_t c3 = 0x6b206574u; // "te k"

    const uint32_t k0 = chacha8_load32_le(key16 + 0);
    const uint32_t k1 = chacha8_load32_le(key16 + 4);
    const uint32_t k2 = chacha8_load32_le(key16 + 8);
    const uint32_t k3 = chacha8_load32_le(key16 + 12);

    // Initial state: constants | key | key (duplicated) | counter+IV
    uint32_t s0 = c0, s1 = c1, s2 = c2, s3 = c3;
    uint32_t s4 = k0, s5 = k1, s6 = k2, s7 = k3;
    uint32_t s8 = k0, s9 = k1, s10 = k2, s11 = k3; // Duplicated for 16-byte key
    uint32_t s12 = ctr_lo, s13 = ctr_hi, s14 = iv_lo, s15 = iv_hi;

    uint32_t x0 = s0, x1 = s1, x2 = s2, x3 = s3, x4 = s4, x5 = s5, x6 = s6, x7 = s7, x8 = s8,
             x9 = s9, x10 = s10, x11 = s11, x12 = s12, x13 = s13, x14 = s14, x15 = s15;

// 4 double-rounds = 8 rounds total (ChaCha8)
#pragma unroll
    for (int i = 0; i < 4; i++) {
        // Column rounds
        chacha8_quarter_round(x0, x4, x8, x12);
        chacha8_quarter_round(x1, x5, x9, x13);
        chacha8_quarter_round(x2, x6, x10, x14);
        chacha8_quarter_round(x3, x7, x11, x15);

        // Diagonal rounds
        chacha8_quarter_round(x0, x5, x10, x15);
        chacha8_quarter_round(x1, x6, x11, x12);
        chacha8_quarter_round(x2, x7, x8, x13);
        chacha8_quarter_round(x3, x4, x9, x14);
    }

    // Add initial state back (ChaCha's Davies-Meyer-like finalization)
    x0 += s0;
    x1 += s1;
    x2 += s2;
    x3 += s3;
    x4 += s4;
    x5 += s5;
    x6 += s6;
    x7 += s7;
    x8 += s8;
    x9 += s9;
    x10 += s10;
    x11 += s11;
    x12 += s12;
    x13 += s13;
    x14 += s14;
    x15 += s15;

    // Serialize to little-endian bytes
    chacha8_store32_le(keystream + 0, x0);
    chacha8_store32_le(keystream + 4, x1);
    chacha8_store32_le(keystream + 8, x2);
    chacha8_store32_le(keystream + 12, x3);
    chacha8_store32_le(keystream + 16, x4);
    chacha8_store32_le(keystream + 20, x5);
    chacha8_store32_le(keystream + 24, x6);
    chacha8_store32_le(keystream + 28, x7);
    chacha8_store32_le(keystream + 32, x8);
    chacha8_store32_le(keystream + 36, x9);
    chacha8_store32_le(keystream + 40, x10);
    chacha8_store32_le(keystream + 44, x11);
    chacha8_store32_le(keystream + 48, x12);
    chacha8_store32_le(keystream + 52, x13);
    chacha8_store32_le(keystream + 56, x14);
    chacha8_store32_le(keystream + 60, x15);
}

/* =========================================================================
 *  Higher-level operations
 * ========================================================================= */

/**
 * @brief Decrypt ciphertext at a ChaCha8 stream offset and verify against a known signature.
 *
 * Used by the Phase 2 kernel to validate (qpc1, qpc2) candidates.
 * Decrypts ciphertext at the given stream byte position and checks
 * whether the result matches the expected plaintext signature.
 *
 * @param enc_bytes   Pointer to ciphertext bytes (device memory).
 * @param sig_bytes   Pointer to expected plaintext signature (device memory).
 * @param len         Number of bytes to check (must fit within a single 64-byte block).
 * @param stream_off  Byte offset within the ChaCha8 stream (determines block counter + intra-block
 * position).
 * @param key16       16-byte ChaCha8 key.
 * @param iv8         8-byte ChaCha8 IV (nonce).
 * @return            true if decrypted bytes match the signature.
 */
__device__ __forceinline__ bool chacha8_signature_match(const uint8_t* __restrict__ enc_bytes,
                                                        const uint8_t* __restrict__ sig_bytes,
                                                        int len, uint64_t stream_off,
                                                        const uint8_t key16[16],
                                                        const uint8_t iv8[8]) {
    if (len <= 0)
        return true;

    const uint32_t iv_lo = chacha8_load32_le(iv8 + 0);
    const uint32_t iv_hi = chacha8_load32_le(iv8 + 4);

    // Derive block counter and byte offset within the 64-byte block
    const uint64_t block_num = stream_off / 64ULL;
    const int byte_in_block = (int)(stream_off % 64ULL);

    uint32_t ctr_lo = (uint32_t)(block_num);
    uint32_t ctr_hi = (uint32_t)(block_num >> 32);

    uint8_t ks[64];
    chacha8_generate_block(key16, ctr_lo, ctr_hi, iv_lo, iv_hi, ks);

    // Early-exit comparison: bail on first mismatch
    for (int i = 0; i < len; ++i) {
        const uint8_t c = __ldg(enc_bytes + i);
        if ((uint8_t)(c ^ ks[byte_in_block + i]) != sig_bytes[i]) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Compute first 8 ChaCha8 keystream bytes as a little-endian uint64_t.
 *
 * Optimized variant that skips full 64-byte serialization: only the first
 * two state words (x0, x1) are finalized and returned.  Saves ~30% of the
 * quarter-round add-back and all store operations for words 2-15.
 *
 * Loads key and IV directly as uint32_t from the precompute buffer,
 * avoiding per-byte chacha8_load32_le overhead.
 *
 * @param key_ptr    Pointer to 16-byte Yarrow key output (device global memory).
 * @param iv_ptr     Pointer to 16-byte Yarrow IV output (first 8 bytes used).
 * @param stream_off Byte offset within the ChaCha8 stream (typically 0).
 * @return           First 8 keystream bytes as little-endian uint64_t.
 */
__device__ __forceinline__ uint64_t chacha8_first8(const uint8_t* __restrict__ key_ptr,
                                                          const uint8_t* __restrict__ iv_ptr,
                                                          uint64_t stream_off) {
    const uint64_t block_num = stream_off / 64ULL;
    const uint32_t ctr_lo = (uint32_t)(block_num);
    const uint32_t ctr_hi = (uint32_t)(block_num >> 32);

    // Direct uint32_t loads (GPU is little-endian, matching ChaCha's wire format)
    const uint32_t k0 = *(const uint32_t*)(key_ptr + 0);
    const uint32_t k1 = *(const uint32_t*)(key_ptr + 4);
    const uint32_t k2 = *(const uint32_t*)(key_ptr + 8);
    const uint32_t k3 = *(const uint32_t*)(key_ptr + 12);
    const uint32_t iv_lo = *(const uint32_t*)(iv_ptr + 0);
    const uint32_t iv_hi = *(const uint32_t*)(iv_ptr + 4);

    // Initial state: tau | key | key (duplicated) | counter+IV
    uint32_t x0 = 0x61707865u, x1 = 0x3120646eu, x2 = 0x79622d36u, x3 = 0x6b206574u;
    uint32_t x4 = k0, x5 = k1, x6 = k2, x7 = k3;
    uint32_t x8 = k0, x9 = k1, x10 = k2, x11 = k3;
    uint32_t x12 = ctr_lo, x13 = ctr_hi, x14 = iv_lo, x15 = iv_hi;

    // 4 double-rounds (ChaCha8)
#pragma unroll
    for (int i = 0; i < 4; i++) {
        chacha8_quarter_round(x0, x4, x8, x12);
        chacha8_quarter_round(x1, x5, x9, x13);
        chacha8_quarter_round(x2, x6, x10, x14);
        chacha8_quarter_round(x3, x7, x11, x15);
        chacha8_quarter_round(x0, x5, x10, x15);
        chacha8_quarter_round(x1, x6, x11, x12);
        chacha8_quarter_round(x2, x7, x8, x13);
        chacha8_quarter_round(x3, x4, x9, x14);
    }

    // Add-back only x0 and x1 (the two output words we need).
    // ChaCha add-back is per-word independent: x_out[i] = x_work[i] + x_init[i].
    // Skipping x2..x15 is safe because they are never used.
    x0 += 0x61707865u;
    x1 += 0x3120646eu;

    return (uint64_t)x0 | ((uint64_t)x1 << 32);
}

/**
 * @brief XOR a byte buffer with ChaCha8 keystream (generic stream decryption).
 *
 * Processes arbitrary-length input by generating successive 64-byte
 * keystream blocks and XORing them with the ciphertext.
 *
 * @param key16      16-byte ChaCha8 key.
 * @param iv8        8-byte ChaCha8 IV (nonce).
 * @param in         Input ciphertext (device memory).
 * @param len        Length in bytes.
 * @param counter64  Initial 64-bit block counter.
 * @param out        Output plaintext buffer (device memory).
 */
__device__ __forceinline__ void chacha8_xor_stream(const uint8_t* key16, const uint8_t* iv8,
                                                   const uint8_t* in, size_t len,
                                                   uint64_t counter64, uint8_t* out) {
    uint32_t ctr_lo = (uint32_t)(counter64);
    uint32_t ctr_hi = (uint32_t)(counter64 >> 32);
    const uint32_t iv_lo = chacha8_load32_le(iv8 + 0);
    const uint32_t iv_hi = chacha8_load32_le(iv8 + 4);

    uint8_t ks[64];

    size_t off = 0;
    while (off < len) {
        chacha8_generate_block(key16, ctr_lo, ctr_hi, iv_lo, iv_hi, ks);

        const size_t n = (len - off < 64) ? (len - off) : 64;
#pragma unroll
        for (size_t i = 0; i < n; i++) {
            out[off + i] = in[off + i] ^ ks[i];
        }

        off += n;
        ctr_lo += 1u;
        if (ctr_lo == 0u)
            ctr_hi += 1u; // 64-bit counter carry
    }
}
