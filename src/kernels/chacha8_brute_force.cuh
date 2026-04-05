// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file chacha8_brute_force.cuh
 * @brief Phase 3 GPU kernel: ChaCha8 seed brute-force.
 *
 * After Phase 2 recovers a candidate (qpc3, qpc4) pair for the KCipher-2
 * layer, Phase 3 searches for the (qpc1, qpc2) pair that seeds ChaCha8.
 * ChaCha8 encrypts the tail block of each file region; by decrypting
 * candidate tail ciphertext and matching against known file signatures,
 * we can confirm or reject each (qpc1, qpc2) candidate.
 *
 * Design: each block handles one qpc2 value (IV seed), generating the
 * Yarrow-derived IV once in shared memory.  Threads within the block
 * independently search different qpc1 (ChaCha8 key) candidates.
 *
 * Reference: D. J. Bernstein, "ChaCha, a variant of Salsa20", 2008.
 *
 */
#pragma once

#include <cuda_runtime.h>
#include <cstdint>
#include "common/constants.h"
#include "common/error.h"
#include "common/device_math.cuh"
#include "crypto/device/yarrow256.cuh"
#include "crypto/device/chacha8.cuh"
#include "kernels/device_globals.cuh"
#include "kernels/yarrow_precompute.cuh"

/* =========================================================================
 *  Precomputed Yarrow + ChaCha8 brute-force
 *
 *  ALL Yarrow outputs are precomputed once into a flat GPU buffer using
 *  precompute_yarrow_kernel (same as Phase 2).  This kernel performs
 *  cheap 16-byte buffer lookups + ChaCha8 only.
 *
 *  Speedup: ~50-100x (100M Yarrow calls -> 20K precompute + 100M ChaCha8).
 * ========================================================================= */

/**
 * @brief Phase 3 kernel: precomputed Yarrow + ChaCha8 seed brute-force.
 *
 * @param device_precompute        Precomputed Yarrow outputs (16 bytes each).
 * @param precompute_hi       Highest seed value in the precomputed buffer.
 * @param step             QPC step size.
 * @param qpc2_hi          Upper bound of qpc2 search range.
 * @param qpc2_lo          Lower bound of qpc2 search range.
 * @param max_offset       Maximum Yarrow inter-call gap.
 * @param enc_bytes        Encrypted ciphertext at the ChaCha8 stream offset.
 * @param sig_bytes        Expected plaintext signature bytes.
 * @param chacha8_stream_off  Byte offset within the ChaCha8 stream.
 * @param signature_length Number of signature bytes to verify.
 */
extern "C" __global__ __launch_bounds__(256, 4) void chacha8_brute_force_kernel(
    const uint8_t* __restrict__ device_precompute, uint64_t precompute_hi, uint64_t step,
    uint64_t qpc2_hi, uint64_t qpc2_lo, uint64_t max_offset, const uint8_t* __restrict__ enc_bytes,
    const uint8_t* __restrict__ sig_bytes, uint64_t chacha8_stream_off, int signature_length,
    bool benchmark_enabled) {
    // Benign race: global_phase3_found may be stale, causing extra work
    // but never incorrect results.  Acceptable for early-exit optimization.
    if (global_phase3_found)
        return;
    if (qpc2_hi < qpc2_lo)
        return;

    const uint64_t total_q2 = ((qpc2_hi - qpc2_lo) / step) + 1ULL;

    // Each block processes one qpc2 value (grid-stride over qpc2 dimension)
    for (uint64_t q2_idx = (uint64_t)blockIdx.x; q2_idx < total_q2 && !global_phase3_found;
         q2_idx += (uint64_t)gridDim.x) {
        const uint64_t qpc2_seed = qpc2_hi - q2_idx * step;

        // IV lookup: read first 8 bytes of precomputed Yarrow(qpc2)
        const uint64_t iv_buf_idx = (precompute_hi - qpc2_seed) / step;
        const uint8_t* iv_ptr = device_precompute + iv_buf_idx * 16;

        // qpc1 range for this qpc2
        const uint64_t q1_hi_raw = (qpc2_seed > step) ? (qpc2_seed - step) : 0ULL;
        const uint64_t q1_lo_raw = (qpc2_seed > max_offset) ? (qpc2_seed - max_offset) : 0ULL;
        const uint64_t q1_hi = align_down_100(q1_hi_raw);
        const uint64_t q1_lo = align_up_100(q1_lo_raw);

        if (q1_hi < q1_lo)
            continue;

        // Precompute expected keystream: enc XOR sig as LE uint64_t (once per qpc2)
        uint64_t expected_ks8 = 0;
        for (int b = 0; b < 8 && b < signature_length; ++b) {
            uint8_t e = __ldg(enc_bytes + b) ^ __ldg(sig_bytes + b);
            expected_ks8 |= (uint64_t)e << (b * 8);
        }

        // Thread-stride over qpc1 candidates
        for (uint64_t q1_cand = q1_hi - (uint64_t)threadIdx.x * step;
             q1_cand >= q1_lo && !global_phase3_found; q1_cand -= step * (uint64_t)blockDim.x) {
            if (benchmark_enabled)
                atomicAdd(&global_actual_phase3_pairs, 1ULL);
            // Key lookup from shared precompute buffer
            const uint64_t key_buf_idx = (precompute_hi - q1_cand) / step;
            const uint8_t* key_ptr = device_precompute + key_buf_idx * 16;

            // Fast 8-byte comparison without full 64-byte block generation
            if (chacha8_first8(key_ptr, iv_ptr, chacha8_stream_off) == expected_ks8) {
                if (atomicCAS((int*)&global_phase3_found, 0, 1) == 0) {
                    global_phase3_qpc1 = q1_cand;
                    global_phase3_qpc2 = qpc2_seed;
                }
                return;
            }

            // Underflow guard
            if (q1_cand < q1_lo + step * (uint64_t)blockDim.x)
                break;
        }
    }
}

/* =========================================================================
 *  Host-side helpers
 * ========================================================================= */

/**
 * @brief Count the number of qpc4 (IV) candidates for a given qpc3 (key seed).
 *
 * Used by the host to estimate the Phase 3 search-space size for progress
 * display and resource allocation.
 *
 * @param qpc3        Key seed under consideration.
 * @param end_qpc     Upper bound of the global QPC range.
 * @param step        QPC step size.
 * @param max_offset  Maximum Yarrow inter-call gap.
 * @return            Number of valid qpc4 candidates for this qpc3.
 */
static inline uint64_t count_qpc4_for_qpc3(uint64_t qpc3, uint64_t end_qpc, uint64_t step,
                                           uint64_t max_offset) {
    uint64_t q4_hi_lim = qpc3 + max_offset;
    if (q4_hi_lim >= end_qpc)
        q4_hi_lim = end_qpc - 1ULL;

    uint64_t q4_hi = align_down_100(q4_hi_lim);
    uint64_t q4_lo = align_up_100(qpc3 + step);
    if (q4_hi < q4_lo)
        return 0ULL;

    return ((q4_hi - q4_lo) / step) + 1ULL;
}

/**
 * @brief Host-side driver: run Phase 3 using precomputed Yarrow + ChaCha8.
 *
 * Computes the unified precompute range covering all qpc2 AND qpc1 seeds,
 * fills the Yarrow buffer, launches the precomputed verification kernel,
 * and reads back the result.
 *
 * @param stream          CUDA stream for asynchronous execution.
 * @param phase2_params   Full Phase2Params range for Phase 3 search.
 * @param device_encrypted           Device pointer to encrypted ciphertext bytes.
 * @param device_signature           Device pointer to expected plaintext signature bytes.
 * @param[out] out_qpc1   Found qpc1 (ChaCha8 key seed).
 * @param[out] out_qpc2   Found qpc2 (ChaCha8 IV seed).
 * @return                true if a valid (qpc1, qpc2) pair was found.
 */
inline bool run_chacha8_brute_force_tiled(cudaStream_t stream, const Phase2Params& phase2_params,
                                     const uint8_t* device_encrypted,
                                     const uint8_t* device_signature, unsigned long long& out_qpc1,
                                     unsigned long long& out_qpc2, bool benchmark_enabled = false) {
    out_qpc1 = 0ULL;
    out_qpc2 = 0ULL;

    const uint64_t step = phase2_params.step;
    const uint64_t max_offset = phase2_params.max_offset;
    const uint64_t qpc2_hi = phase2_params.batch_qpc_hi;
    const uint64_t qpc2_lo = phase2_params.batch_qpc_lo;

    if (qpc2_hi < qpc2_lo)
        return false;

    const uint64_t total_q2 = ((qpc2_hi - qpc2_lo) / step) + 1ULL;
    if (total_q2 == 0ULL)
        return false;

    // Compute unified precompute range: [qpc2_lo - max_offset, qpc2_hi]
    const uint64_t precompute_hi = qpc2_hi;
    const uint64_t precompute_lo_raw = (qpc2_lo > max_offset) ? (qpc2_lo - max_offset) : 0ULL;
    const uint64_t precompute_lo = align_up_100(precompute_lo_raw);

    if (precompute_hi < precompute_lo)
        return false;

    const uint64_t total_precompute = ((precompute_hi - precompute_lo) / step) + 1ULL;

    // Allocate and fill precompute buffer
    uint8_t* device_precompute = nullptr;
    CUDA_CHECK(cudaMalloc(&device_precompute, total_precompute * 16));
    precompute_all_yarrow(device_precompute, precompute_hi, step, total_precompute, stream);

    // Reset Phase 3 device variables
    void* device_found_addr = nullptr;
    CUDA_CHECK(cudaGetSymbolAddress(&device_found_addr, global_phase3_found));
    void* device_qpc1_addr = nullptr;
    CUDA_CHECK(cudaGetSymbolAddress(&device_qpc1_addr, global_phase3_qpc1));
    void* device_qpc2_addr = nullptr;
    CUDA_CHECK(cudaGetSymbolAddress(&device_qpc2_addr, global_phase3_qpc2));
    CUDA_CHECK(cudaMemset(device_found_addr, 0, sizeof(int)));
    CUDA_CHECK(cudaMemset(device_qpc1_addr, 0, sizeof(unsigned long long)));
    CUDA_CHECK(cudaMemset(device_qpc2_addr, 0, sizeof(unsigned long long)));

    // Launch precomputed validation kernel
    int num_sms = 0;
    cudaDeviceGetAttribute(&num_sms, cudaDevAttrMultiProcessorCount, 0);
    const int precompute_grid = num_sms * 2;

    chacha8_brute_force_kernel<<<precompute_grid, 256, 0, stream>>>(
        device_precompute, precompute_hi, step, qpc2_hi, qpc2_lo, max_offset, device_encrypted,
        device_signature, phase2_params.chacha8_stream_off, phase2_params.signature_length,
        benchmark_enabled);
    CUDA_CHECK(cudaStreamSynchronize(stream));

    // Read back result
    int phase3_found = 0;
    CUDA_CHECK(cudaMemcpyFromSymbol(&phase3_found, global_phase3_found, sizeof(int), 0,
                                    cudaMemcpyDeviceToHost));

    bool is_hit = false;
    if (phase3_found) {
        CUDA_CHECK(cudaMemcpyFromSymbol(&out_qpc1, global_phase3_qpc1, sizeof(unsigned long long),
                                        0, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpyFromSymbol(&out_qpc2, global_phase3_qpc2, sizeof(unsigned long long),
                                        0, cudaMemcpyDeviceToHost));
        is_hit = true;
    }

    CUDA_CHECK(cudaFree(device_precompute));
    return is_hit;
}
