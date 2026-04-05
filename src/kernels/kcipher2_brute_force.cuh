// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file kcipher2_brute_force.cuh
 * @brief Persistent mega-kernels for KCipher-2 offset brute-force (Phase 2).
 *
 * Provides the persistent GPU kernel that searches for the (qpc3, qpc4)
 * seed pair used by the Akira ransomware's KCipher-2 encryption:
 *
 *   kcipher2_multifile_brute_force_kernel  -- multi-file batch mode.
 *
 * The kernel is "persistent": thread blocks stay resident and atomically
 * claim successive work units from a global counter, which avoids
 * kernel-launch overhead for the large search space.
 *
 * Each candidate (qpc3, qpc4) pair is formed from two entries in the
 * precomputed Yarrow buffer.  The KCipher-2 first-8-bytes fast path
 * is checked against per-file mask/value patterns before committing
 * to a full signature validation (see signature_match.cuh).
 *
 * Index layout:
 *   device_precompute[idx * 16]  ->  Yarrow(aligned_end - idx * step),
 *                             idx = 0 .. total_candidates-1
 *
 * Reference: ISO/IEC 18033-4:2011 (KCipher-2 stream cipher).
 *
 */
#pragma once

#include <cuda_runtime.h>
#include <cstdint>
#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include "common/constants.h"
#include "common/error.h"
#include "common/logger.h"
#include "common/device_math.cuh"
#include "crypto/device/kcipher2.cuh"
#include "kernels/device_globals.cuh"
#include "kernels/signature_match.cuh"

/* =========================================================================
 *  Validator hint bitmask
 *
 *  Each file is tagged with a bitmask indicating which signature validators
 *  apply.  This prevents false positives from running, e.g., a JPEG check
 *  on a PDF file.
 * ========================================================================= */

#define VHINT_JPEG   (1u << 0)
#define VHINT_PNG    (1u << 1)
#define VHINT_PDF    (1u << 2)
#define VHINT_ZIP    (1u << 3)
#define VHINT_SQLITE (1u << 4)
#define VHINT_OLE    (1u << 5)
#define VHINT_ALL    0xFFFFu ///< Fallback: try every validator.

/* =========================================================================
 *  Full validation cascade
 *
 *  Runs the applicable subset of signature validators (selected by the
 *  hint bitmask) against an already-initialized KCipher-2 state.
 *  Returns on the first match to avoid unnecessary computation.
 * ========================================================================= */

/**
 * @brief Run all hint-selected validators against one KCipher-2 state.
 *
 * The state is cloned before each validator so that a failed check does
 * not consume keystream needed by subsequent validators.
 *
 * @param state_init  Initialized KCipher-2 state for this (key, IV) pair.
 * @param head        Pointer to encrypted header bytes (device memory).
 * @param head_len    Number of available header bytes.
 * @param vhint       Bitmask of validators to try (default: VHINT_ALL).
 * @return            true if any validator matched.
 */
__device__ __forceinline__ bool kcipher2_validate_cascade(const KCipher2State& state_init,
                                                      const uint8_t* head, int head_len,
                                                      unsigned int vhint = VHINT_ALL) {
    KCipher2State state_copy;

#define TRY_VALIDATOR(bit, fn)                                                                     \
    if (vhint & (bit)) {                                                                           \
        state_copy = state_init;                                                                   \
        if (fn(state_copy, head, 0, head_len))                                                     \
            return true;                                                                           \
    }

    TRY_VALIDATOR(VHINT_JPEG, kcipher2_validate_jpeg)
    TRY_VALIDATOR(VHINT_PNG, kcipher2_validate_png)
    TRY_VALIDATOR(VHINT_PDF, kcipher2_validate_pdf)
    TRY_VALIDATOR(VHINT_ZIP, kcipher2_validate_zip)
    TRY_VALIDATOR(VHINT_SQLITE, kcipher2_validate_sqlite)
    TRY_VALIDATOR(VHINT_OLE, kcipher2_validate_ole)

#undef TRY_VALIDATOR
    return false;
}

/* =========================================================================
 *  Multi-file batch persistent brute-force
 *
 *  Processes ALL files simultaneously.  The outer loop iterates candidate
 *  chunks (not offsets) for better L2-cache locality -- the IV (qpc4
 *  Yarrow output) is loaded once per candidate, and keys at increasing
 *  offsets are read sequentially.
 *
 *  Per-file found flags enable independent early termination.
 * ========================================================================= */

/**
 * @brief Persistent KCipher-2 brute-force kernel (multi-file batch path).
 *
 * @param device_precompute          Precomputed Yarrow buffer (16 bytes per candidate).
 * @param aligned_end        Highest seed value in the buffer.
 * @param step               QPC step between consecutive candidates.
 * @param total_candidates   Number of entries in device_precompute.
 * @param max_offset_steps   Maximum offset distance to search.
 * @param min_offset_steps   Skip physically impossible offsets below this value.
 * @param device_match_values     Sorted quick-check expected values (per mask group).
 * @param device_match_file_index   File index for each sorted value entry.
 * @param n_matches          Total number of value entries across all groups.
 * @param device_group_masks       Per-group mask value (NUM_MASK_GROUPS entries).
 * @param device_group_starts      Per-group start index into sorted arrays.
 * @param device_group_counts      Per-group entry count.
 * @param n_groups            Number of active mask groups.
 * @param device_file_heads       Concatenated first-16-byte headers (nfiles * 16).
 * @param device_file_head_lengths   Actual header length per file.
 * @param device_file_vhints      Validator hint bitmask per file.
 * @param nfiles             Number of files in the batch.
 * @param device_file_start_index   Per-file lower bound on candidate index (nullable).
 * @param device_file_end_index     Per-file upper bound on candidate index (nullable).
 */
extern "C" __global__ __launch_bounds__(256, 2) void kcipher2_multifile_brute_force_kernel(
    const uint8_t* __restrict__ device_precompute, uint64_t aligned_end, uint64_t step,
    uint64_t total_candidates, uint64_t max_offset_steps, uint64_t min_offset_steps,
    const uint64_t* __restrict__ device_match_values,
    const int* __restrict__ device_match_file_index, int n_matches,
    const uint64_t* __restrict__ device_group_masks,
    const int* __restrict__ device_group_starts,
    const int* __restrict__ device_group_counts, int n_groups,
    const uint8_t* __restrict__ device_file_heads,
    const int* __restrict__ device_file_head_lengths,
    const unsigned int* __restrict__ device_file_vhints, int nfiles,
    const uint64_t* __restrict__ device_file_start_index,
    const uint64_t* __restrict__ device_file_end_index, bool benchmark_enabled) {
    /* -- Load KCipher-2 tables into shared memory --------------------- */
    /* Bank padding: 257 entries per T-table to avoid 4-way bank conflicts */
    __shared__ uint32_t shared_T0[257];
    __shared__ uint32_t shared_T1[257];
    __shared__ uint32_t shared_T2[257];
    __shared__ uint32_t shared_T3[257];
    __shared__ uint32_t shared_amul0[256];
    __shared__ uint32_t shared_amul1[256];
    __shared__ uint32_t shared_amul2[256];
    __shared__ uint32_t shared_amul3[256];

    shared_T0[threadIdx.x] = device_subk2_T0[threadIdx.x];
    shared_T1[threadIdx.x] = device_subk2_T1[threadIdx.x];
    shared_T2[threadIdx.x] = device_subk2_T2[threadIdx.x];
    shared_T3[threadIdx.x] = device_subk2_T3[threadIdx.x];
    shared_amul0[threadIdx.x] = device_amul0[threadIdx.x];
    shared_amul1[threadIdx.x] = device_amul1[threadIdx.x];
    shared_amul2[threadIdx.x] = device_amul2[threadIdx.x];
    shared_amul3[threadIdx.x] = device_amul3[threadIdx.x];
    // Zero-initialize bank-conflict padding slot (index 256, never accessed)
    if (threadIdx.x == 0) {
        shared_T0[256] = 0; shared_T1[256] = 0;
        shared_T2[256] = 0; shared_T3[256] = 0;
    }
    __syncthreads();

    KCipher2SharedTables tables;
    tables.T0 = shared_T0;
    tables.T1 = shared_T1;
    tables.T2 = shared_T2;
    tables.T3 = shared_T3;
    tables.amul0 = shared_amul0;
    tables.amul1 = shared_amul1;
    tables.amul2 = shared_amul2;
    tables.amul3 = shared_amul3;

    /* -- Load sorted match values, file indices, and group info into shared memory -- */
    extern __shared__ char shared_dynamic[];
    uint64_t* shared_values = (uint64_t*)shared_dynamic;
    int* shared_file_index = (int*)(shared_dynamic + n_matches * sizeof(uint64_t));
    const size_t group_offset =
        ((n_matches * (sizeof(uint64_t) + sizeof(int))) + 7ULL) & ~7ULL;
    uint64_t* shared_group_masks = (uint64_t*)(shared_dynamic + group_offset);
    int* shared_group_starts = (int*)(shared_group_masks + NUM_MASK_GROUPS);
    int* shared_group_counts = shared_group_starts + NUM_MASK_GROUPS;

    for (int i = threadIdx.x; i < n_matches; i += blockDim.x) {
        shared_values[i] = device_match_values[i];
        shared_file_index[i] = device_match_file_index[i];
    }
    if (threadIdx.x < NUM_MASK_GROUPS) {
        shared_group_masks[threadIdx.x] =
            (threadIdx.x < n_groups) ? device_group_masks[threadIdx.x] : 0;
        shared_group_starts[threadIdx.x] =
            (threadIdx.x < n_groups) ? device_group_starts[threadIdx.x] : 0;
        shared_group_counts[threadIdx.x] =
            (threadIdx.x < n_groups) ? device_group_counts[threadIdx.x] : 0;
    }
    __syncthreads();

    /* -- Candidate-outer persistent work loop -------------------------
     *
     *  Loop reorder optimization: candidates in the OUTER loop, offsets
     *  in the INNER loop.
     *
     *  Benefits vs offset-outer ordering:
     *    - IV (qpc4 Yarrow) loaded ONCE per candidate (was once per pair)
     *    - Key reads (idx+1, idx+2, ...) are sequential -> L2-friendly
     *    - IVw[4] stays in registers across all offset iterations
     * ----------------------------------------------------------------- */

    const uint64_t max_valid =
        (total_candidates > max_offset_steps) ? (total_candidates - max_offset_steps) : 0ULL;
    const uint64_t total_chunks = (max_valid + (uint64_t)blockDim.x - 1ULL) / (uint64_t)blockDim.x;

    while (true) {
        __shared__ uint32_t shared_my_chunk;
        if (threadIdx.x == 0)
            shared_my_chunk = atomicAdd(&global_brute_force_work_counter, 1);
        __syncthreads();

        if (shared_my_chunk >= total_chunks || global_total_files_found >= nfiles)
            return;

        const uint64_t my_idx =
            (uint64_t)shared_my_chunk * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;

        if (my_idx < max_valid) {
            // Load IV -- single 128-bit read, loaded ONCE per candidate
            const uint4 iv_raw =
                __ldg((const uint4*)(device_precompute + my_idx * 16));
            const uint32_t IVw[4] = {__byte_perm(iv_raw.x, 0, 0x0123),
                                     __byte_perm(iv_raw.y, 0, 0x0123),
                                     __byte_perm(iv_raw.z, 0, 0x0123),
                                     __byte_perm(iv_raw.w, 0, 0x0123)};

            // Inner loop: sequential offset scan
            for (uint64_t os = min_offset_steps; os <= max_offset_steps; ++os) {
                if (global_total_files_found >= nfiles)
                    break;
                if (benchmark_enabled)
                    atomicAdd(&global_actual_phase2_pairs, 1ULL);

                const uint64_t actual_i3 = my_idx + os;
                // Single 128-bit coalesced read via read-only cache
                const uint4 key_raw =
                    __ldg((const uint4*)(device_precompute + actual_i3 * 16));
                const uint32_t K[4] = {__byte_perm(key_raw.x, 0, 0x0123),
                                       __byte_perm(key_raw.y, 0, 0x0123),
                                       __byte_perm(key_raw.z, 0, 0x0123),
                                       __byte_perm(key_raw.w, 0, 0x0123)};

                uint64_t ks8 = kcipher2_first8_smem(K, IVw, tables);

                // Quick-check: binary search within each mask group
                for (int g = 0; g < n_groups; ++g) {
                    const uint64_t masked_ks8 = ks8 & shared_group_masks[g];
                    int lo = shared_group_starts[g];
                    int hi = lo + shared_group_counts[g] - 1;

                    int found = -1;
                    while (lo <= hi) {
                        int mid = (lo + hi) >> 1;
                        uint64_t v = shared_values[mid];
                        if (v == masked_ks8) {
                            found = mid;
                            break;
                        }
                        if (v < masked_ks8)
                            lo = mid + 1;
                        else
                            hi = mid - 1;
                    }
                    if (found < 0)
                        continue;

                    int file_idx = shared_file_index[found];
                    if (global_found_per_file[file_idx])
                        continue;

                    // Per-file window bounds check
                    if (device_file_start_index && device_file_end_index) {
                        if (my_idx < device_file_start_index[file_idx] ||
                            my_idx > device_file_end_index[file_idx])
                            continue;
                    }

                    // Full signature validation
                    KCipher2State state;
                    kcipher2_init_state_smem(state, K, IVw, tables);

                    const uint8_t* file_head = device_file_heads + file_idx * 16;
                    int file_head_len = device_file_head_lengths[file_idx];
                    unsigned int vhint = device_file_vhints[file_idx];

                    if (kcipher2_validate_cascade(state, file_head, file_head_len, vhint)) {
                        if (atomicCAS(&global_found_per_file[file_idx], 0, 1) == 0) {
                            uint64_t qpc3_val = aligned_end - actual_i3 * step;
                            uint64_t qpc4_val = aligned_end - my_idx * step;
                            global_qpc3_per_file[file_idx] = qpc3_val;
                            global_qpc4_per_file[file_idx] = qpc4_val;
                            atomicAdd(&global_total_files_found, 1);
                        }
                    }
                    break; // At most one match per ks8
                }
            }
        }
        __syncthreads();
    }
}

/* =========================================================================
 *  Host-side result structures
 * ========================================================================= */

/// Result of a multi-file batch offset brute-force.
struct MultifileBruteForceResult {
    std::vector<bool> found;    ///< Per-file hit flag.
    std::vector<uint64_t> qpc3; ///< Per-file key seed.
    std::vector<uint64_t> qpc4; ///< Per-file IV seed.
    int total_found;            ///< Running total of hits.
};

/* =========================================================================
 *  Host wrapper: multi-file batch brute-force
 * ========================================================================= */

/**
 * @brief Launch the multi-file KCipher-2 persistent brute-force with progress display.
 *
 * Resets per-file device state, launches kcipher2_multifile_brute_force_kernel,
 * polls progress at 500 ms intervals (displaying a progress bar), and
 * reads back per-file results upon completion.
 *
 * @param device_precompute          Precomputed Yarrow buffer.
 * @param aligned_end        Highest seed value.
 * @param step               QPC step size.
 * @param total_candidates   Number of Yarrow entries.
 * @param max_offset_steps   Maximum offset budget.
 * @param min_offset_steps   Minimum offset (skip impossible gaps).
 * @param device_match_values     Sorted quick-check value array (all groups).
 * @param device_match_file_index   File index for each sorted entry.
 * @param n_matches          Total value entries across all groups.
 * @param device_group_masks       Per-group mask value.
 * @param device_group_starts      Per-group start index into sorted arrays.
 * @param device_group_counts      Per-group entry count.
 * @param n_groups            Number of active mask groups.
 * @param device_file_heads       Concatenated file headers (nfiles * 16).
 * @param device_file_head_lengths   Per-file header length.
 * @param device_file_vhints      Per-file validator hint bitmask.
 * @param nfiles             Number of files in the batch.
 * @param device_file_start_index   Per-file lower candidate bound (nullable).
 * @param device_file_end_index     Per-file upper candidate bound (nullable).
 * @param stream             CUDA stream.
 * @return                   MultifileBruteForceResult with per-file results.
 */
inline MultifileBruteForceResult run_multifile_offset_brute_force(
    const uint8_t* device_precompute, uint64_t aligned_end, uint64_t step,
    uint64_t total_candidates, uint64_t max_offset_steps, uint64_t min_offset_steps,
    const uint64_t* device_match_values, const int* device_match_file_index, int n_matches,
    const uint64_t* device_group_masks, const int* device_group_starts,
    const int* device_group_counts, int n_groups, const uint8_t* device_file_heads,
    const int* device_file_head_lengths, const unsigned int* device_file_vhints, int nfiles,
    const uint64_t* device_file_start_index = nullptr,
    const uint64_t* device_file_end_index = nullptr, cudaStream_t stream = 0,
    bool benchmark_enabled = false, int batch_id = 1) {
    MultifileBruteForceResult result;
    result.found.resize(nfiles, false);
    result.qpc3.resize(nfiles, 0);
    result.qpc4.resize(nfiles, 0);
    result.total_found = 0;

    /* -- Reset device-side state -------------------------------------- */
    {
        uint32_t zero32 = 0;
        int zero_i = 0;

        cudaMemcpyToSymbol(global_brute_force_work_counter, &zero32, sizeof(uint32_t));
        cudaMemcpyToSymbol(global_total_files_found, &zero_i, sizeof(int));

        int zero_arr[MAX_BATCH_FILES] = {};
        unsigned long long zero_ull_arr[MAX_BATCH_FILES] = {};
        cudaMemcpyToSymbol(global_found_per_file, zero_arr, nfiles * sizeof(int));
        cudaMemcpyToSymbol(global_qpc3_per_file, zero_ull_arr, nfiles * sizeof(unsigned long long));
        cudaMemcpyToSymbol(global_qpc4_per_file, zero_ull_arr, nfiles * sizeof(unsigned long long));
        cudaDeviceSynchronize();
    }

    int num_sms = 0;
    cudaDeviceGetAttribute(&num_sms, cudaDevAttrMultiProcessorCount, 0);
    int grid = num_sms * 2;

    // Prefer larger L1 cache for sequential precompute buffer reads
    cudaFuncSetCacheConfig(kcipher2_multifile_brute_force_kernel, cudaFuncCachePreferL1);

    // Dynamic shared memory: values(8B) + file_idx(4B) per entry, aligned, + group info
    size_t group_offset =
        (((size_t)n_matches * (sizeof(uint64_t) + sizeof(int))) + 7ULL) & ~7ULL;
    size_t smem_bytes =
        group_offset + (size_t)NUM_MASK_GROUPS * (sizeof(uint64_t) + 2 * sizeof(int));

    kcipher2_multifile_brute_force_kernel<<<grid, 256, smem_bytes, stream>>>(
        device_precompute, aligned_end, step, total_candidates, max_offset_steps, min_offset_steps,
        device_match_values, device_match_file_index, n_matches, device_group_masks,
        device_group_starts, device_group_counts, n_groups, device_file_heads,
        device_file_head_lengths, device_file_vhints, nfiles, device_file_start_index,
        device_file_end_index, benchmark_enabled);

    /* -- Poll progress with in-place console update -------------------- */
    {
        const uint64_t max_valid_cand =
            (total_candidates > max_offset_steps) ? (total_candidates - max_offset_steps) : 0ULL;
        const uint64_t total_chunks = (max_valid_cand + 255ULL) / 256ULL;

        ConsoleProgress progress;
        progress.begin();

        int last_pct = -1;
        auto t0 = std::chrono::steady_clock::now();
        while (cudaStreamQuery(stream) == cudaErrorNotReady) {
            uint32_t chunks_done = 0;
            int files_found_so_far = 0;
            cudaMemcpyFromSymbol(&chunks_done, global_brute_force_work_counter, sizeof(uint32_t));
            cudaMemcpyFromSymbol(&files_found_so_far, global_total_files_found, sizeof(int));
            double elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

            double frac = (total_chunks > 0) ? (double)chunks_done / (double)total_chunks : 0;
            if (frac > 1.0) frac = 1.0;
            int cur_pct = (int)(frac * 100.0);

            if (cur_pct > last_pct) {
                last_pct = cur_pct;
                std::string speed_str;
                if (elapsed > 1.0 && chunks_done > 0) {
                    uint64_t eff_offsets = (max_offset_steps > min_offset_steps)
                                               ? (max_offset_steps - min_offset_steps)
                                               : 1ULL;
                    double cand_per_sec =
                        (double)chunks_done * 256.0 * (double)eff_offsets / elapsed;
                    speed_str = " | " + fmt_speed((uint64_t)cand_per_sec);
                }
                double eta = (frac > 0) ? elapsed * (1.0 - frac) / frac : 0;
                std::string eta_str =
                    (frac > 0 && frac < 1.0) ? " | ETA " + fmt_time(eta) : "";

                char line[512];
                std::snprintf(line, sizeof(line),
                              "\033[92m[%s] [Batch %d] [Phase2]\033[0m %d%% | %d/%d hits%s%s",
                              now_time_short().c_str(), batch_id, cur_pct,
                              files_found_so_far, nfiles, speed_str.c_str(), eta_str.c_str());
                progress.update(line);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Final progress snapshot with early-exit indicator
        {
            uint32_t chunks_done = 0;
            int files_found_so_far = 0;
            cudaMemcpyFromSymbol(&chunks_done, global_brute_force_work_counter, sizeof(uint32_t));
            cudaMemcpyFromSymbol(&files_found_so_far, global_total_files_found, sizeof(int));
            double elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            double frac = (total_chunks > 0) ? (double)chunks_done / (double)total_chunks : 1.0;
            if (frac > 1.0) frac = 1.0;
            const char* tag = (files_found_so_far >= nfiles) ? " (all found)" : "";

            char line[512];
            std::snprintf(line, sizeof(line),
                          "\033[92m[%s] [Batch %d] [Phase2]\033[0m %.3f%% | %d/%d hits | %s%s",
                          now_time_short().c_str(), batch_id, frac * 100.0,
                          files_found_so_far, nfiles, fmt_time(elapsed).c_str(), tag);
            progress.update(line);
        }
        progress.end();
    }

    /* -- Read back per-file results ----------------------------------- */
    {
        int found_arr[MAX_BATCH_FILES] = {};
        unsigned long long q3_arr[MAX_BATCH_FILES] = {};
        unsigned long long q4_arr[MAX_BATCH_FILES] = {};

        cudaMemcpyFromSymbol(found_arr, global_found_per_file, nfiles * sizeof(int));
        cudaMemcpyFromSymbol(q3_arr, global_qpc3_per_file, nfiles * sizeof(unsigned long long));
        cudaMemcpyFromSymbol(q4_arr, global_qpc4_per_file, nfiles * sizeof(unsigned long long));

        for (int f = 0; f < nfiles; ++f) {
            if (found_arr[f]) {
                result.found[f] = true;
                result.qpc3[f] = q3_arr[f];
                result.qpc4[f] = q4_arr[f];
                ++result.total_found;
            }
        }
    }

    return result;
}
