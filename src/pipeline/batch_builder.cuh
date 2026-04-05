// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file batch_builder.cuh
 * @brief Mtime-based batch grouping and unified file preparation.
 *
 * Groups FileMeta entries into MtimeBatch objects whose QPC search ranges
 * are close enough to share a single precompute buffer, and provides the
 * top-level prepare_all_files() entry point that orchestrates the full
 * file-scanning and batch-construction pipeline.
 *
 */
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/constants.h"
#include "common/error.h"
#include "common/logger.h"
#include "common/device_math.cuh"
#include "pipeline/types.cuh"
#include "pipeline/file_scanner.cuh"

/* ===========================================================================
 *  Mtime batch construction
 * =========================================================================== */

/**
 * @brief Group FileMeta entries into batches by mtime proximity.
 *
 * Files are processed in order (assumed sorted by mtime).  A new batch is
 * started when either:
 *   - The combined QPC span would exceed 3 x max_batch_window_ns, OR
 *   - The batch already contains MAX_BATCH_FILES entries.
 *
 * @param file_metas          Sorted FileMeta vector.
 * @param max_batch_window_ns Per-file QPC lookback window (nanoseconds).
 * @param[out] mtime_batches  Populated with batch groupings.
 */
inline void build_mtime_batches(const std::vector<FileMeta>& file_metas,
                                uint64_t max_batch_window_ns,
                                std::vector<MtimeBatch>& mtime_batches) {
    MtimeBatch current;
    current.batch_start = UINT64_MAX;
    current.batch_end = 0;

    for (int file_index = 0; file_index < (int)file_metas.size(); ++file_index) {
        const auto& file_meta = file_metas[file_index];
        uint64_t new_start = std::min(current.batch_start, file_meta.start_qpc);
        uint64_t new_end = std::max(current.batch_end, file_meta.end_qpc);
        uint64_t span = (new_end > new_start) ? (new_end - new_start) : 0;

        bool is_overflow = (int)current.file_indices.size() >= MAX_BATCH_FILES;
        bool is_too_wide = !current.file_indices.empty() && span > 10 * max_batch_window_ns;

        if (is_overflow || is_too_wide) {
            mtime_batches.push_back(std::move(current));
            current = {};
            current.batch_start = file_meta.start_qpc;
            current.batch_end = file_meta.end_qpc;
        } else {
            current.batch_start = new_start;
            current.batch_end = new_end;
        }

        current.file_indices.push_back(file_index);
    }

    if (!current.file_indices.empty())
        mtime_batches.push_back(std::move(current));
}

/* ===========================================================================
 *  Unified file preparation entry point
 * =========================================================================== */

/**
 * @brief Scan the filesystem, build metadata, and partition into batches.
 *
 * Orchestrates the full file-preparation pipeline:
 *   1. collect_and_index_headers  — filesystem scan + header extraction.
 *   2. prepare_file_metas         — QPC range computation + extension filter.
 *   3. Compute aligned global search range.
 *   4. build_mtime_batches        — group into GPU-friendly batches.
 *   5. log_extension_breakdown    — diagnostic output.
 *
 * @param args         Parsed CLI arguments.
 * @param timing       QPC calibration parameters.
 * @param target_file  Path for the target-list CSV output.
 * @return             Fully populated PreparedData.
 */
inline PreparedData prepare_all_files(const CLIArgs& args, const TimingParams& timing,
                                      const std::string& target_file) {
    PreparedData data;

    // 1. Collect headers
    std::unordered_map<std::string, std::vector<uint8_t>> head_by_path;
    collect_and_index_headers(args.root_path, args.threads, target_file, data.files, head_by_path);

    if (data.files.empty()) {
        LOG_WARN("PREP", "No headers to test. Exiting.");
        std::exit(0);
    }

    // 2. Build per-file metadata
    uint64_t global_min_start = 0, global_max_end = 0;
    prepare_file_metas(data.files, head_by_path, timing, args, data.file_metas, data.original_exts,
                       global_min_start, global_max_end);

    data.nfiles_total = (int)data.file_metas.size();
    if (data.nfiles_total == 0) {
        LOG_WARN("PREP", "No supported files found. Exiting.");
        std::exit(0);
    }

    // 3. Compute aligned search range
    data.aligned_start = align_up_step(global_min_start, timing.step);
    data.aligned_end = align_down_step(global_max_end, timing.step);
    if (data.aligned_end < data.aligned_start) {
        LOG_ERR("PREP", "Invalid search range after alignment");
        std::exit(1);
    }
    data.total_candidates = ((data.aligned_end - data.aligned_start) / timing.step) + 1ULL;
    data.min_offset_steps = args.min_offset / timing.step;
    data.max_offset_steps = args.max_offset / timing.step;
    data.effective_offset_steps = data.max_offset_steps - data.min_offset_steps;

    // 4. Group into mtime batches
    build_mtime_batches(data.file_metas, args.max_batch_window_ns, data.mtime_batches);

    LOG_INFO("PREP", data.nfiles_total
                         << " files | " << fmt_count(data.effective_offset_steps) << " offsets"
                         << " [" << (args.min_offset / 1e6) << "ms.." << (args.max_offset / 1e6)
                         << "ms]"
                         << " | per-file window=" << fmt_time(args.max_batch_window_ns / 1e9));
    LOG_INFO("PREP", data.mtime_batches.size()
                         << " mtime batches | "
                         << "global range: [" << data.aligned_start << " .. " << data.aligned_end
                         << "] (" << fmt_time((data.aligned_end - data.aligned_start) / 1e9)
                         << ")");

    // 5. Log extension breakdown
    log_extension_breakdown(data.original_exts, data.nfiles_total);

    return data;
}
