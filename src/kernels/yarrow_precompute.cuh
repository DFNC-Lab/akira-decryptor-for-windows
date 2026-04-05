// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file yarrow_precompute.cuh
 * @brief GPU kernel for precomputing Yarrow-256 PRNG outputs over a QPC seed range.
 *
 * Instead of computing Yarrow inline for every (qpc3, qpc4) or (qpc1, qpc2)
 * candidate pair (expensive: ~1500 SHA-256 rounds each), this kernel
 * precomputes ALL Yarrow outputs once into a flat GPU buffer.  Subsequent
 * Phase 2 and Phase 3 kernels then perform cheap 16-byte lookups by index
 * rather than recomputing the PRNG each time.
 *
 * Thread mapping:
 *   global_idx  ->  seed = aligned_end - (global_idx * step)
 *   output:        device_output16[global_idx * 16 .. global_idx * 16 + 15]
 *
 * Reference: J. Kelsey, B. Schneier, N. Ferguson, "Yarrow-160: Notes on
 *            the Design and Analysis of the Yarrow Cryptographic
 *            Pseudorandom Number Generator", SAC 1999.
 *            Akira uses a 256-bit variant with 1500 iterate rounds.
 *
 */
#pragma once

#include <cuda_runtime.h>
#include <cstdint>
#include "common/constants.h"
#include "common/error.h"
#include "common/device_math.cuh"
#include "crypto/device/yarrow256.cuh"

/* =========================================================================
 *  Precompute kernel
 * ========================================================================= */

/**
 * @brief Precompute Yarrow outputs for a contiguous range of QPC seed values.
 *
 * Each thread independently evaluates Yarrow-256 for one seed and writes
 * 16 bytes of output into the flat buffer.  A grid-stride loop ensures
 * coverage when total_candidates exceeds the grid size.
 *
 * @param device_output16          Output buffer: 16 bytes per candidate (pre-allocated,
 *                         size >= total_candidates * 16).
 * @param aligned_end      The highest (first) seed value in the descending range.
 * @param step             QPC step between consecutive candidates (typically 100).
 * @param total_candidates Number of candidates to compute.
 */
extern "C" __global__
__launch_bounds__(256, 2) void precompute_yarrow_kernel(uint8_t* __restrict__ device_output16,
                                                        uint64_t aligned_end, uint64_t step,
                                                        uint64_t total_candidates) {
    // Load AES S-Box into shared memory for faster random-access lookups
    __shared__ uint8_t shared_sbox[256];
    if (threadIdx.x < 256) {
        shared_sbox[threadIdx.x] = device_sbox[threadIdx.x];
    }
    __syncthreads();

    const uint64_t grid_stride = (uint64_t)blockDim.x * (uint64_t)gridDim.x;

    for (uint64_t global_idx = (uint64_t)blockIdx.x * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;
         global_idx < total_candidates; global_idx += grid_stride) {
        const uint64_t seed = aligned_end - (global_idx * step);

        uint8_t buf[16];
        generate_random(reinterpret_cast<char*>(buf), 16, seed, shared_sbox);

        uint8_t* dst = device_output16 + global_idx * 16;
#pragma unroll
        for (int i = 0; i < 16; ++i) {
            dst[i] = buf[i];
        }
    }
}

/* =========================================================================
 *  Host-side launch wrapper
 * ========================================================================= */

/**
 * @brief Launch precompute_yarrow_kernel over the full candidate range.
 *
 * Computes the grid dimensions, launches the kernel, and synchronizes.
 * The caller must ensure device_output16 is pre-allocated with at least
 * total_candidates * 16 bytes.
 *
 * @param device_output16          Device buffer for Yarrow outputs.
 * @param aligned_end      Highest seed value (descending order).
 * @param step             QPC step size (typically 100).
 * @param total_candidates Number of seeds to precompute.
 * @param stream           CUDA stream for asynchronous execution.
 */
inline void precompute_all_yarrow(uint8_t* device_output16, uint64_t aligned_end, uint64_t step,
                                  uint64_t total_candidates, cudaStream_t stream = 0) {
    if (total_candidates == 0)
        return;

    constexpr int BLOCK = CUDA_BLOCK_SIZE;
    const int grid =
        (int)min((uint64_t)(total_candidates / BLOCK + 1), (uint64_t)MAX_CUDA_GRID_DIM);

    precompute_yarrow_kernel<<<grid, BLOCK, 0, stream>>>(device_output16, aligned_end, step,
                                                         total_candidates);

    cudaStreamSynchronize(stream);
}
