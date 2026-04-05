// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file find_seeds_main.cu
 * @brief Akira ransomware decryptor -- GPU pipeline orchestration entry point.
 *
 * Coordinates the two-phase brute-force search for Akira encryption seeds:
 *   Phase 2: KCipher-2 key seeds (qpc3, qpc4) via persistent GPU brute-force.
 *   Phase 3: ChaCha8 key seeds (qpc1, qpc2) via tail-block verification.
 *
 * This file is the single CUDA translation unit (.cu) that pulls together
 * all device-side kernels, pipeline modules, and device global definitions.
 * Device globals are defined in kernels/device_globals.cuh and are NOT
 * redefined here.
 *
 * Usage:
 *   Step2_SeedScanner <root_path> "YYYY-MM-DD HH:MM:SS.mmm" <ref_qpc> [threads]
 *
 * Implementation details are in pipeline/ and kernels/ headers.
 * Only the high-level flow is visible here.
 *
 */

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <numeric>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <windows.h>
#include <unordered_map>
#include <map>
#include <set>
#include <cuda_runtime.h>

#include "../common/error.h"
#include "../common/constants.h"
#include "../common/device_math.cuh"
#include "../crypto/device/aes256.cuh"
#include "../crypto/device/sha256.cuh"
#include "../crypto/device/kcipher2.cuh"
#include "../crypto/device/chacha8.cuh"

/* =========================================================================
 *  Device-side globals
 *
 *  All __device__ global variables are defined in device_globals.cuh.
 *  This is the single .cu translation unit, so including device_globals.cuh
 *  here provides the one-definition-rule (ODR) compliant definitions.
 * ========================================================================= */

#include "../kernels/device_globals.cuh"

/* =========================================================================
 *  Kernel includes (order matters: Yarrow -> validators -> kernels)
 *
 *  These are header-only .cuh files containing __global__ and __device__
 *  functions that must be compiled within a single translation unit
 *  alongside the device global definitions above.
 * ========================================================================= */

#include "../crypto/device/yarrow256.cuh"
#include "../kernels/signature_match.cuh"
#include "../kernels/yarrow_precompute.cuh"
#include "../kernels/kcipher2_brute_force.cuh"
#include "../kernels/chacha8_brute_force.cuh"

/* =========================================================================
 *  Pipeline modules (host-side orchestration, after all kernel definitions)
 * ========================================================================= */

#include "../pipeline/types.cuh"
#include "../pipeline/cli.cuh"
#include "../pipeline/file_scanner.cuh"
#include "../pipeline/batch_builder.cuh"
#include "../pipeline/search_engine.cuh"
#include "../pipeline/result_writer.cuh"

/* =========================================================================
 *  main() -- readable five-step pipeline
 * ========================================================================= */

/**
 * @brief Entry point for the GPU-accelerated QPC seed finder.
 *
 * Orchestrates the full pipeline:
 *   1. Initialize console, GPU device, and log files.
 *   2. Calibrate QPC timing from the reference timestamp.
 *   3. Scan .akira files, build per-file metadata and batches.
 *   4. Launch GPU kernels for brute-force seed search.
 *   5. Report results and write benchmark data.
 */
int main(int argc, char** argv) {

    /* 1. Initialize */
    init_console();
    auto gpu = init_gpu();
    auto logs = init_log_files();
    auto args = parse_cli(argc, argv);

    ElapsedTimer elapsed_timer;
    elapsed_timer.start();

    /* 2. QPC calibration */
    auto timing = calibrate_qpc(args);

    /* 3. Collect .akira files, build metadata and batches */
    auto data = prepare_all_files(args, timing, logs.file_list_filename);

    /* 4. Brute-force search: batch -> GPU kernels */
    auto state = search_all_batches(gpu, args, timing, data, logs.log_filename);

    /* 5. Summary */
    elapsed_timer.stop();
    const auto prog_end = std::chrono::system_clock::now();
    double total_elapsed = std::chrono::duration<double>(prog_end - logs.start_tp).count();
    log_summary(state.total_hits, data.files.size(), total_elapsed, logs.log_filename);

    if (args.enable_benchmark)
        write_benchmark(gpu, args, timing, state, data, logs.start_time);

    return 0;
}
