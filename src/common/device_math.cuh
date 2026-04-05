// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file device_math.cuh
 * @brief Shared device-side utility functions for CUDA kernels.
 *
 * Provides common bit-rotation and QPC alignment functions used across
 * multiple cryptographic implementations and kernel files.
 * Kept in a dedicated header to eliminate include-order dependencies
 * between the crypto primitives (KCipher-2, ChaCha8, SHA-256).
 *
 */

#pragma once

#include <cstdint>

/**
 * @brief 32-bit left rotation (circular shift).
 *
 * Maps to a single PTX funnel-shift instruction on SM 3.5+, avoiding
 * the two-shift-plus-or pattern that the compiler may not always fuse.
 *
 * Used by KCipher-2 (ISO/IEC 18033-4, key expansion and NLF) and
 * ChaCha8 (D. J. Bernstein, "ChaCha, a variant of Salsa20", 2008)
 * quarter-round operations.
 *
 * @param x  Value to rotate.
 * @param n  Rotation amount in bits (0..31).
 * @return   x rotated left by n bits.
 */
__device__ __forceinline__ uint32_t rol32(uint32_t x, int n) {
    return __funnelshift_l(x, x, n);
}

/**
 * @brief Align a QPC tick value down to the nearest STEP boundary.
 *
 * The Akira ransomware seeds its Yarrow-256 PRNG with QPC values that
 * are quantized to SEED_SCALE_NS boundaries. This function replicates
 * that quantization for the brute-force search.
 *
 * @param x     Raw QPC tick value.
 * @param step  Alignment step (= SEED_SCALE_NS, e.g. 100 at QPF=10 MHz).
 * @return      Largest multiple of step that is <= x.
 */
__host__ __device__ __forceinline__ unsigned long long align_down_step(unsigned long long x,
                                                                       unsigned long long step) {
    return x - (x % step);
}

/**
 * @brief Align a QPC tick value up to the nearest STEP boundary.
 *
 * @param x     Raw QPC tick value.
 * @param step  Alignment step (= SEED_SCALE_NS, e.g. 100 at QPF=10 MHz).
 * @return      Smallest multiple of step that is >= x.
 */
__host__ __device__ __forceinline__ unsigned long long align_up_step(unsigned long long x,
                                                                     unsigned long long step) {
    unsigned long long r = x % step;
    return r ? (x + (step - r)) : x;
}

/**
 * @brief Convenience wrapper: align down to a fixed step of 100 (QPF=10 MHz).
 *
 * Retained for backward compatibility with kernel code that hardcodes
 * the default 10 MHz QPC frequency.
 *
 * @param x  Raw QPC tick value.
 * @return   Largest multiple of 100 that is <= x.
 */
__host__ __device__ __forceinline__ unsigned long long align_down_100(unsigned long long x) {
    return align_down_step(x, 100ULL);
}

/**
 * @brief Convenience wrapper: align up to a fixed step of 100 (QPF=10 MHz).
 * @param x  Raw QPC tick value.
 * @return   Smallest multiple of 100 that is >= x.
 */
__host__ __device__ __forceinline__ unsigned long long align_up_100(unsigned long long x) {
    return align_up_step(x, 100ULL);
}
