// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file device_globals.cuh
 * @brief Consolidated CUDA __device__ global variable definitions.
 *
 * Every GPU-visible global variable used across the kernel layer is
 * defined here exactly once.  Other translation units that reference
 * these symbols must declare them with `extern __device__`.
 *
 * Naming convention: `global_` prefix + descriptive snake_case name.
 *
 * Terminology mapping (legacy -> current):
 *   Stage 1  ->  Phase 2 (KCipher-2 offset brute-force)
 *   Stage 2  ->  Phase 3 (ChaCha8 tail-block verification)
 *
 */
#pragma once

#include <cstdint>
#include <cuda_runtime.h>
#include "common/constants.h"

/* =========================================================================
 *  Phase 2 results (KCipher-2 offset brute-force)
 *
 *  Written by kcipher2_multifile_brute_force_kernel when a valid
 *  (qpc3, qpc4) pair is found.  Per-file results are stored in
 *  the global_found_per_file / global_qpc3_per_file / global_qpc4_per_file
 *  arrays below.
 * ========================================================================= */

/* =========================================================================
 *  Phase 3 results (ChaCha8 tail-block verification)
 *
 *  Written by chacha8_brute_force_kernel when a valid (qpc1, qpc2) pair
 *  is found that passes the tail-block signature check.
 * ========================================================================= */

/// Set to 1 by the first thread that finds a Phase 3 hit.
__device__ volatile int global_phase3_found = 0;

/// Yarrow seed for the ChaCha8 key (Phase 3 result).
__device__ unsigned long long global_phase3_qpc1 = 0;

/// Yarrow seed for the ChaCha8 IV (Phase 3 result).
__device__ unsigned long long global_phase3_qpc2 = 0;

/* =========================================================================
 *  Persistent-kernel work counter
 *
 *  Used by persistent brute-force kernels to distribute work across thread
 *  blocks without a fixed grid mapping.  Each block atomically increments
 *  this counter to claim the next work unit (offset step or candidate chunk).
 * ========================================================================= */

/// Monotonically increasing work-unit index for persistent kernels.
__device__ uint32_t global_brute_force_work_counter = 0;

/* =========================================================================
 *  Benchmark counters (--benchmark mode only)
 *
 *  Track the actual number of (candidate, offset) pairs evaluated by GPU
 *  kernels, as opposed to the theoretical maximum.  Only incremented when
 *  benchmark mode is enabled to avoid atomic contention in production runs.
 * ========================================================================= */

/// Actual Phase 2 (KCipher-2 brute-force) pairs evaluated by GPU threads.
__device__ unsigned long long global_actual_phase2_pairs = 0;

/// Actual Phase 3 (ChaCha8 brute-force) pairs evaluated by GPU threads.
__device__ unsigned long long global_actual_phase3_pairs = 0;

/* =========================================================================
 *  Multi-file batch results (Phase 2, multi-file path)
 *
 *  When processing multiple encrypted files in a single kernel launch,
 *  per-file found/qpc3/qpc4 arrays allow independent completion tracking.
 * ========================================================================= */

/// Per-file found flag (1 = hit, 0 = still searching).
__device__ int global_found_per_file[MAX_BATCH_FILES] = {};

/// Per-file qpc3 result (KCipher-2 key seed).
__device__ unsigned long long global_qpc3_per_file[MAX_BATCH_FILES] = {};

/// Per-file qpc4 result (KCipher-2 IV seed).
__device__ unsigned long long global_qpc4_per_file[MAX_BATCH_FILES] = {};

/// Running total of files that have found a valid Phase 2 hit.
__device__ int global_total_files_found = 0;

/* =========================================================================
 *  Constant-memory metadata cache
 *
 *  For small file counts (<= MAX_CONST_META), per-file header offsets
 *  and lengths are cached in __constant__ memory to avoid global-memory
 *  indirections during signature matching.
 * ========================================================================= */

/// Packed 32-bit byte offset into the concatenated header buffer.
__constant__ uint32_t constant_offset32[MAX_CONST_META];

/// Per-file header length (bytes, capped at HEAD_MAX).
__constant__ uint8_t constant_length8[MAX_CONST_META];

/// Number of files whose metadata resides in constant memory.
__constant__ int constant_num_heads;

/* =========================================================================
 *  Device-side metadata accessor
 *
 *  Transparently reads per-file offset/length from constant memory when
 *  available, falling back to global-memory arrays for large batches.
 * ========================================================================= */

/**
 * @brief Read per-file header offset and length from the fastest available source.
 *
 * Files indexed below constant_num_heads are served from __constant__ memory;
 * the remainder fall through to the global-memory arrays.
 *
 * @param file_index  File index within the current batch.
 * @param[out] offset Byte offset into the concatenated header buffer.
 * @param[out] length Header length for this file.
 * @param offsets_global  Global-memory offset array (fallback).
 * @param lengths_global  Global-memory length array (fallback).
 */
__device__ __forceinline__ void get_file_meta(int file_index, size_t& offset, int& length,
                                              const size_t* __restrict__ offsets_global,
                                              const uint8_t* __restrict__ lengths_global) {
    const int n_const = constant_num_heads;
    if (file_index < n_const) {
        offset = (size_t)constant_offset32[file_index];
        length = (int)constant_length8[file_index];
    } else {
        offset = offsets_global[file_index];
        length = (int)lengths_global[file_index];
    }
}

/* =========================================================================
 *  Host-side constant-memory upload
 * ========================================================================= */

/**
 * @brief Upload per-file metadata into constant memory if the batch fits.
 *
 * Copies header offsets and lengths into constant_offset32 / constant_length8 when the number
 * of files does not exceed MAX_CONST_META.  Returns false (and sets
 * n_used = 0) for oversized batches, leaving global-memory arrays as
 * the sole data source.
 *
 * @param heads   Host-side vector of file header data.
 * @param[out] n_used  Number of files actually placed in constant memory.
 * @return  true if all files fit in constant memory.
 */
static bool upload_meta_constant_if_fits(const std::vector<AkiraHead>& heads, int& n_used) {
    const int N = (int)heads.size();
    if (N <= 0) {
        n_used = 0;
        int zero = 0;
        CUDA_CHECK(cudaMemcpyToSymbol(constant_num_heads, &zero, sizeof(int)));
        return true;
    }

    std::vector<uint32_t> off32;
    std::vector<uint8_t> len8;
    off32.reserve(N);
    len8.reserve(N);

    size_t total = 0;
    for (int i = 0; i < N; ++i) {
        const size_t L = std::min<size_t>(HEAD_MAX, heads[i].head.size());
        off32.push_back((uint32_t)total);
        len8.push_back((uint8_t)L);
        total += L;
    }

    if (N > MAX_CONST_META) {
        int zero = 0;
        CUDA_CHECK(cudaMemcpyToSymbol(constant_num_heads, &zero, sizeof(int)));
        n_used = 0;
        return false;
    }

    CUDA_CHECK(cudaMemcpyToSymbol(constant_offset32, off32.data(), sizeof(uint32_t) * N, 0,
                                  cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpyToSymbol(constant_length8, len8.data(), sizeof(uint8_t) * N, 0,
                                  cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpyToSymbol(constant_num_heads, &N, sizeof(int)));
    n_used = N;
    return true;
}
