// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file types.cuh
 * @brief Shared data structures for the GPU seed-search pipeline.
 *
 * Defines all value types exchanged between pipeline stages: CLI arguments,
 * GPU device info, QPC timing calibration, per-file metadata, mtime-based
 * batch grouping, prepared search data, and accumulated search state.
 *
 * No logic resides here — only POD-like structs and trivial predicates.
 *
 */
#pragma once

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>
#include <filesystem>
#include <cuda_runtime.h>

#include "common/constants.h"

namespace fs = std::filesystem;

/* ===========================================================================
 *  CLI arguments
 * =========================================================================== */

/// Parsed command-line arguments supplied by the user.
struct CLIArgs {
    fs::path root_path;               ///< Root directory to scan for .akira files.
    std::string ref_time_str;         ///< Reference timestamp string ("YYYY-MM-DD HH:MM:SS.mmm").
    uint64_t ref_qpc = 0;             ///< Reference QPC counter captured alongside ref_time_str.
    size_t threads = 1;               ///< Number of CPU worker threads for filesystem scanning.
    uint64_t min_offset = MIN_OFFSET; ///< Minimum Yarrow inter-call gap (nanoseconds).
    uint64_t max_offset = MAX_OFFSET; ///< Maximum Yarrow inter-call gap (nanoseconds).
    uint64_t max_batch_window_ns = MAX_BATCH_WINDOW_NS; ///< Per-file lookback window (nanoseconds).
    bool enable_benchmark = false; ///< --benchmark: enable GPU counters + JSON report.
    bool test_mode = false;        ///< --test: search ChaCha8 seeds for all extensions.
};

/* ===========================================================================
 *  GPU device info
 * =========================================================================== */

/// Cached CUDA device properties and a pre-formatted info string for logging.
struct GPUInfo {
    cudaDeviceProp props{};  ///< Full device properties from cudaGetDeviceProperties.
    int device_id = 0;       ///< CUDA device ordinal.
    std::string info_string; ///< "RTX 4090 | SM=128 | CC=8.9" style summary.
};

/* ===========================================================================
 *  QPC timing calibration
 * =========================================================================== */

/// Parameters that relate Windows FILETIME timestamps to QPC counter values.
struct TimingParams {
    uint64_t ref_ft = 0;        ///< Reference FILETIME (100 ns ticks since 1601-01-01).
    uint64_t ref_qpc = 0;       ///< Reference QPC counter value captured at ref_ft.
    uint64_t qpf = 0;           ///< QueryPerformanceFrequency result (ticks per second).
    uint64_t seed_scale_ns = 0; ///< Nanoseconds per QPC tick: 1e9 / qpf.
    uint64_t step = 0;          ///< Search step size (== seed_scale_ns).
};

/* ===========================================================================
 *  Per-file metadata
 * =========================================================================== */

/// Metadata for a single .akira file that passed extension filtering.
struct FileMeta {
    size_t orig_idx;           ///< Index into the global files[] vector.
    uint64_t end_qpc;          ///< Upper bound of the QPC search window (ns).
    uint64_t start_qpc;        ///< Lower bound of the QPC search window (ns).
    std::vector<uint8_t> head; ///< First bytes of the encrypted header (up to 16).
    int head_len;              ///< Number of valid bytes in head[].

    /// Phase 3 (ChaCha8) known-plaintext signature.  Empty if Phase 3 is not
    /// applicable for this file (e.g. insufficient region size).
    std::vector<uint8_t> chacha8_signature;
    uint64_t chacha8_file_offset = 0; ///< Absolute file offset for ChaCha8 verification.
};

/* ===========================================================================
 *  Mtime-based batch
 * =========================================================================== */

/// A group of files whose mtime-derived QPC ranges overlap enough to share
/// a single precompute buffer.
struct MtimeBatch {
    std::vector<int> file_indices; ///< Indices into the file_metas[] vector.
    uint64_t batch_start;          ///< min(start_qpc) across all files in the batch.
    uint64_t batch_end;            ///< max(end_qpc) across all files in the batch.
};

/* ===========================================================================
 *  Prepared data (output of the file scanning / preparation phase)
 * =========================================================================== */

/// Consolidated output of the file-scanning and batch-building stages.
struct PreparedData {
    std::vector<FileInfo> files;            ///< All .akira files sorted by mtime.
    std::vector<FileMeta> file_metas;       ///< Filtered files with QPC ranges.
    std::vector<MtimeBatch> mtime_batches;  ///< Batches grouped by mtime proximity.
    std::vector<std::string> original_exts; ///< Per-FileMeta original extension (lowercase).
    uint64_t aligned_start = 0;             ///< Global search range lower bound (aligned).
    uint64_t aligned_end = 0;               ///< Global search range upper bound (aligned).
    uint64_t total_candidates = 0;          ///< Total Yarrow candidates in the range.
    uint64_t min_offset_steps = 0;          ///< min_offset / step.
    uint64_t max_offset_steps = 0;          ///< max_offset / step.
    uint64_t effective_offset_steps = 0;    ///< max_offset_steps - min_offset_steps.
    int nfiles_total = 0;                   ///< Number of files that passed filtering.
};

/* ===========================================================================
 *  Per-batch statistics
 * =========================================================================== */

/// Timing and hit statistics for a single mtime batch.
struct BatchStat {
    int nfiles;            ///< Number of files in the batch.
    uint64_t candidates;   ///< Total Yarrow candidates for this batch.
    double precompute_ms;  ///< Yarrow precompute wall time (milliseconds).
    double brute_force_ms; ///< KCipher-2 brute-force wall time (milliseconds).
    int hits;              ///< Phase 2 hits found in this batch.
};

/* ===========================================================================
 *  Phase 3 (ChaCha8) single-hit result
 * =========================================================================== */

/// Result of running Phase 3 (ChaCha8 verification) for one KCipher-2 hit.
struct Phase3Result {
    bool is_hit = false;                ///< true if a valid (qpc1, qpc2) pair was found.
    double precompute_ms = 0;           ///< Yarrow precompute time (ms).
    double brute_force_ms = 0;          ///< ChaCha8 brute-force time (ms).
    uint64_t precompute_candidates = 0; ///< Number of Yarrow candidates precomputed.
    uint64_t brute_force_pairs = 0;     ///< Number of (qpc1, qpc2) pairs evaluated.
};

/* ===========================================================================
 *  Accumulated search state
 * =========================================================================== */

/// Mutable state accumulated across all batches during the search loop.
struct SearchState {
    size_t total_hits = 0;      ///< Total files with confirmed KCipher-2 seeds.
    size_t files_processed = 0; ///< Files examined so far (regardless of outcome).
    int nfiles_total = 0;       ///< Total files to search (for progress display).

    std::vector<bool> per_file_hit;              ///< Per-file found flag.
    std::vector<unsigned long long> result_qpc3; ///< Per-file KCipher-2 key seed.
    std::vector<unsigned long long> result_qpc4; ///< Per-file KCipher-2 IV seed.

    std::chrono::system_clock::time_point search_start; ///< Wall-clock start of the search.
    std::string log_filename;                           ///< Path to the CSV result log.

    /* -- Phase 2 (KCipher-2 brute-force) timing ------------------------------ */
    double total_precompute_ms = 0;           ///< Cumulative Yarrow precompute time (ms).
    double total_brute_force_ms = 0;          ///< Cumulative KCipher-2 brute-force time (ms).
    uint64_t total_precompute_candidates = 0; ///< Total Yarrow outputs precomputed.
    uint64_t total_brute_force_pairs =
        0; ///< Actual (candidate x offset) pairs tested (GPU counter, benchmark only).
    uint64_t total_brute_force_pairs_theoretical =
        0; ///< Theoretical maximum pairs (tile_cands x offset_steps).

    std::vector<BatchStat> batch_stats; ///< Per-batch statistics.

    /* -- Phase 3 (ChaCha8 verification) timing ------------------------- */
    double total_phase3_brute_force_ms = 0; ///< Cumulative Phase 3 brute-force time (ms).
    uint64_t total_phase3_candidates = 0;   ///< Total Phase 3 Yarrow candidates.
    uint64_t total_phase3_pairs = 0;        ///< Theoretical Phase 3 (qpc1, qpc2) pairs.
    uint64_t total_phase3_pairs_actual = 0; ///< Actual Phase 3 pairs (GPU counter, benchmark only).
    int phase3_attempts = 0;                ///< Number of Phase 3 invocations.
    int phase3_hits = 0;                    ///< Number of Phase 3 successes.

    /**
     * @brief Check whether all target files have been recovered.
     * @return true if total_hits >= nfiles_total.
     */
    bool all_found() const { return (int)total_hits >= nfiles_total; }
};

/* ===========================================================================
 *  Log-file initialization data
 * =========================================================================== */

/// Timestamped filenames created at program startup.
struct LogFiles {
    std::string log_filename;                       ///< "found_seeds_YYYYMMDD_HHMMSS.csv".
    std::string file_list_filename;                 ///< "file_list_YYYYMMDD_HHMMSS.txt".
    std::time_t start_time;                         ///< Program start as time_t.
    std::chrono::system_clock::time_point start_tp; ///< Program start as time_point.
};
