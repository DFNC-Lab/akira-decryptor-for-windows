// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file result_writer.cuh
 * @brief Benchmark JSON output and final summary display.
 *
 * Writes a structured JSON file containing GPU configuration, search
 * parameters, timing statistics, per-batch breakdowns, and Phase 3
 * (ChaCha8 verification) aggregates.  Intended for automated performance
 * analysis and regression tracking.
 *
 */
#pragma once

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include "common/constants.h"
#include "common/logger.h"
#include "pipeline/types.cuh"

/**
 * @brief Write a JSON benchmark report summarizing the search run.
 *
 * The output file is named "benchmark_YYYYMMDD_HHMMSS.json" based on
 * the program start time.  The JSON contains:
 *   - GPU device properties.
 *   - CUDA kernel configuration.
 *   - Search parameters (step, offsets, batch window).
 *   - File counts and hit statistics.
 *   - Timing breakdown (precompute vs. brute-force).
 *   - Per-batch statistics array.
 *   - Phase 3 (ChaCha8) aggregate statistics (if any attempts were made).
 *
 * @param gpu         GPU device info.
 * @param args        CLI arguments.
 * @param timing      QPC calibration parameters.
 * @param state       Final accumulated search state.
 * @param data        PreparedData with file metadata.
 * @param start_time  Program start time (for filename generation).
 */
inline void write_benchmark(const GPUInfo& gpu, const CLIArgs& args, const TimingParams& timing,
                            const SearchState& state, const PreparedData& data,
                            std::time_t start_time) {
    char bench_name[64];
    std::strftime(bench_name, sizeof(bench_name), "search_report_%Y%m%d_%H%M%S.json",
                  std::localtime(&start_time));

    const auto search_end = std::chrono::system_clock::now();
    double total_elapsed_sec =
        std::chrono::duration<double>(search_end - state.search_start).count();
    double precompute_sec = state.total_precompute_ms / 1000.0;
    double brute_force_sec = state.total_brute_force_ms / 1000.0;

    /* Phase 1 throughput: Yarrow precompute candidates per second */
    double precompute_throughput =
        (precompute_sec > 0) ? (state.total_precompute_candidates / precompute_sec) : 0;

    /* Phase 2 throughput: actual (GPU counter) and theoretical (tile*offsets) */
    double brute_force_throughput_actual =
        (brute_force_sec > 0) ? ((double)state.total_brute_force_pairs / brute_force_sec) : 0;
    double brute_force_throughput_theoretical =
        (brute_force_sec > 0)
            ? ((double)state.total_brute_force_pairs_theoretical / brute_force_sec)
            : 0;

    /* Phase 3 derived values (precompute is included in Phase 1) */
    double phase3_brute_force_sec = state.total_phase3_brute_force_ms / 1000.0;
    double phase3_tput_actual =
        (phase3_brute_force_sec > 0)
            ? ((double)state.total_phase3_pairs_actual / phase3_brute_force_sec)
            : 0;
    double phase3_tput_theoretical =
        (phase3_brute_force_sec > 0) ? ((double)state.total_phase3_pairs / phase3_brute_force_sec)
                                     : 0;

    std::ostringstream json;
    json << std::fixed << std::setprecision(3);

    json << "{\n"
         << "  \"gpu\": {"
         << "\"name\": \"" << gpu.props.name << "\", "
         << "\"sm_count\": " << gpu.props.multiProcessorCount << ", "
         << "\"compute_capability\": \"" << gpu.props.major << "." << gpu.props.minor << "\", "
         << "\"memory_mb\": " << (gpu.props.totalGlobalMem >> 20) << "},\n"

         << "  \"kernel_config\": {"
         << "\"block_size\": " << CUDA_BLOCK_SIZE << ", "
         << "\"max_grid_dim\": " << MAX_CUDA_GRID_DIM << "},\n"

         << "  \"search_params\": {"
         << "\"step\": " << timing.step << ", "
         << "\"seed_scale_ns\": " << timing.seed_scale_ns << ", "
         << "\"max_offset\": " << args.max_offset << ", "
         << "\"max_batch_window_ns\": " << args.max_batch_window_ns << "},\n"

         << "  \"files\": {"
         << "\"processed\": " << data.nfiles_total << ", "
         << "\"total\": " << data.files.size() << ", "
         << "\"hits\": " << state.total_hits
         << "},\n"

         /* Global timing: wall-clock and per-file average */
         << "  \"timing\": {\n"
         << "    \"total_elapsed_sec\": " << total_elapsed_sec << ",\n"
         << "    \"per_file_avg_sec\": " << std::setprecision(1)
         << (state.files_processed > 0 ? total_elapsed_sec / state.files_processed : 0.0) << "\n"
         << "  },\n"

         /* Phase 1: Yarrow precompute */
         << "  \"phase1_precompute\": {\n"
         << "    \"elapsed_sec\": " << std::setprecision(3) << precompute_sec << ",\n"
         << "    \"total_candidates\": " << state.total_precompute_candidates << ",\n"
         << "    \"throughput_per_sec\": " << std::setprecision(0) << precompute_throughput << "\n"
         << "  },\n"

         /* Phase 2: KCipher-2 brute-force — actual vs. theoretical */
         << "  \"phase2_kcipher2\": {\n"
         << "    \"elapsed_sec\": " << std::setprecision(3) << brute_force_sec << ",\n"
         << "    \"pairs_actual\": " << state.total_brute_force_pairs << ",\n"
         << "    \"pairs_theoretical\": " << state.total_brute_force_pairs_theoretical << ",\n"
         << "    \"throughput_per_sec\": " << std::setprecision(0) << brute_force_throughput_actual
         << ",\n"
         << "    \"throughput_theoretical_per_sec\": " << brute_force_throughput_theoretical << "\n"
         << "  },\n"

         /* Phase 3: ChaCha8 verification — actual vs. theoretical */
         << "  \"phase3_chacha8\": {\n"
         << "    \"elapsed_sec\": " << std::setprecision(3) << phase3_brute_force_sec << ",\n"
         << "    \"pairs_actual\": " << state.total_phase3_pairs_actual << ",\n"
         << "    \"pairs_theoretical\": " << state.total_phase3_pairs << ",\n"
         << "    \"throughput_per_sec\": " << std::setprecision(0) << phase3_tput_actual << ",\n"
         << "    \"throughput_theoretical_per_sec\": " << phase3_tput_theoretical << ",\n"
         << "    \"attempts\": " << state.phase3_attempts << ",\n"
         << "    \"hits\": " << state.phase3_hits << "\n"
         << "  },\n"

         /* Cross-phase totals for quick comparison */
         << "  \"total\": {\n"
         << "    \"pairs_actual\": "
         << (state.total_brute_force_pairs + state.total_phase3_pairs_actual) << ",\n"
         << "    \"pairs_theoretical\": "
         << (state.total_brute_force_pairs_theoretical + state.total_phase3_pairs) << ",\n"
         << "    \"precompute_candidates\": " << state.total_precompute_candidates << "\n"
         << "  },\n"

         << "  \"batches\": [\n";

    for (size_t i = 0; i < state.batch_stats.size(); ++i) {
        const auto& bs = state.batch_stats[i];
        json << std::setprecision(3) << "    {\"nfiles\": " << bs.nfiles
             << ", \"candidates\": " << bs.candidates
             << ", \"precompute_sec\": " << (bs.precompute_ms / 1000.0)
             << ", \"brute_force_sec\": " << (bs.brute_force_ms / 1000.0)
             << ", \"hits\": " << bs.hits << "}";
        if (i + 1 < state.batch_stats.size())
            json << ",";
        json << "\n";
    }
    json << "  ]\n}\n";

    std::ofstream bench_file(bench_name);
    if (bench_file)
        bench_file << json.str();
}
