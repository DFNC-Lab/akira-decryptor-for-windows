// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file search_engine.cuh
 * @brief GPU search orchestration: initialization, calibration, tile sizing,
 *        and the main batch search loop.
 *
 * Pipeline order (called from find_seeds_main.cu):
 *   1. init_console()              — Windows console setup.
 *   2. init_gpu()                  — CUDA device query + banner display.
 *   3. init_log_files()            — Timestamped CSV/target file creation.
 *   4. calibrate_qpc()             — QPC-to-FILETIME calibration.
 *   5. search_all_batches()        — Full search loop with tiled precompute.
 *
 * The tiling strategy (splitting large batches into GPU-VRAM-sized tiles)
 * is entirely internal — callers see only batch-level progress.
 *
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <Windows.h>
#include <cuda_runtime.h>

#include "common/constants.h"
#include "common/error.h"
#include "common/logger.h"
#include "common/device_math.cuh"
#include "pipeline/types.cuh"
#include "pipeline/file_scanner.cuh"
#include "kernels/yarrow_precompute.cuh"
#include "kernels/kcipher2_brute_force.cuh"
#include "kernels/chacha8_brute_force.cuh"

/* ===========================================================================
 *  Console initialization (Windows)
 * =========================================================================== */

/**
 * @brief Enable UTF-8 output and ANSI escape sequences on the Windows console.
 *
 * Sets the console output code page to UTF-8 (CP_UTF8) and enables virtual
 * terminal processing for ANSI color codes.
 */
inline void init_console() {
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode))
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

/* ===========================================================================
 *  GPU initialization
 * =========================================================================== */

/**
 * @brief Query the CUDA device and display the startup banner.
 *
 * Reads the current CUDA device properties and formats a summary string
 * that includes the GPU name, SM count, and compute capability.
 *
 * @return  GPUInfo with populated props, device_id, and info_string.
 */
inline GPUInfo init_gpu() {
    GPUInfo gpu;
    CUDA_CHECK(cudaGetDevice(&gpu.device_id));
    CUDA_CHECK(cudaGetDeviceProperties(&gpu.props, gpu.device_id));
    gpu.info_string =
        std::string(gpu.props.name) + " | SM=" + std::to_string(gpu.props.multiProcessorCount) +
        " | CC=" + std::to_string(gpu.props.major) + "." + std::to_string(gpu.props.minor);
    log_banner(gpu.info_string);
    return gpu;
}

/* ===========================================================================
 *  Log file initialization
 * =========================================================================== */

/**
 * @brief Create timestamped log and target-list filenames.
 *
 * Generates "found_seeds_YYYYMMDD_HHMMSS.csv" for the result CSV and
 * "file_list_YYYYMMDD_HHMMSS.txt" for the file enumeration output.
 *
 * @return  LogFiles with populated filenames, start_time, and start_tp.
 */
inline LogFiles init_log_files() {
    LogFiles lf;
    lf.start_tp = std::chrono::system_clock::now();
    lf.start_time = std::chrono::system_clock::to_time_t(lf.start_tp);

    char buf[64];
    std::strftime(buf, sizeof(buf), "found_seeds_%Y%m%d_%H%M%S.csv",
                  std::localtime(&lf.start_time));
    lf.log_filename = buf;
    init_log_file(lf.log_filename);

    std::strftime(buf, sizeof(buf), "file_list_%Y%m%d_%H%M%S.txt", std::localtime(&lf.start_time));
    lf.file_list_filename = buf;

    return lf;
}

/* ===========================================================================
 *  QPC-to-FILETIME calibration
 * =========================================================================== */

/**
 * @brief Calibrate the QPC-to-FILETIME relationship from user-supplied
 *        reference values.
 *
 * Parses the reference timestamp string into a FILETIME, queries the
 * Windows performance counter frequency, and derives the seed_scale_ns
 * (nanoseconds per QPC tick) and step values.
 *
 * @param args  CLI arguments containing ref_time_str and ref_qpc.
 * @return      Populated TimingParams.
 */
inline TimingParams calibrate_qpc(const CLIArgs& args) {
    TimingParams timing;
    timing.ref_qpc = args.ref_qpc;

    timing.ref_ft = local_string_to_filetime_100ns(args.ref_time_str);
    if (timing.ref_ft == 0) {
        LOG_ERR("CALIB", "Invalid ref_time string: " << args.ref_time_str);
        std::exit(1);
    }

    LARGE_INTEGER fr{};
    if (!QueryPerformanceFrequency(&fr) || fr.QuadPart <= 0) {
        LOG_ERR("CALIB", "QueryPerformanceFrequency failed");
        std::exit(1);
    }
    timing.qpf = (uint64_t)fr.QuadPart;

    timing.seed_scale_ns = 1'000'000'000ULL / timing.qpf;
    timing.step = timing.seed_scale_ns;

    LOG_INFO("CALIB", "ref_qpc=" << timing.ref_qpc << " | qpf=" << timing.qpf
                                 << " | scale=" << timing.seed_scale_ns << "ns");

    return timing;
}

/* ===========================================================================
 *  GPU VRAM tile size computation
 * =========================================================================== */

/**
 * @brief Determine the maximum number of Yarrow candidates that fit in GPU
 *        memory for a single precompute tile.
 *
 * Reserves 128 MB for brute_force buffers and other allocations, then divides the
 * remaining free memory by 16 bytes per Yarrow output.  The result is
 * clamped to [1M, 500M] candidates.
 *
 * @return  Tile capacity in Yarrow candidates.
 */
inline uint64_t compute_tile_size() {
    size_t gpu_free = 0, gpu_total = 0;
    CUDA_CHECK(cudaMemGetInfo(&gpu_free, &gpu_total));

    const size_t reserve = (size_t)128 * 1024 * 1024; // 128 MB for brute_force buffers
    const size_t usable = (gpu_free > reserve) ? (gpu_free - reserve) : gpu_free / 2;
    uint64_t tile_candidates = usable / 16ULL; // 16 bytes per Yarrow output

    if (tile_candidates > 500'000'000ULL)
        tile_candidates = 500'000'000ULL;
    if (tile_candidates < 1'000'000ULL)
        tile_candidates = 1'000'000ULL;

    return tile_candidates;
}

/* ===========================================================================
 *  Phase 3 (ChaCha8 verification) for a single KCipher-2 hit
 * =========================================================================== */

/**
 * @brief Run Phase 3 (ChaCha8 tail-block verification) for one KCipher-2 hit.
 *
 * Reads the encrypted bytes at the ChaCha8 verification offset, uploads
 * them along with the expected signature to the GPU, and calls the tiled
 * ChaCha8 verification kernel.
 *
 * @param stream            CUDA stream.
 * @param args              CLI arguments (for max_offset).
 * @param timing            QPC calibration parameters.
 * @param f                 FileInfo for the target file.
 * @param file_meta         FileMeta for the target file.
 * @param qpc3_kcipher2     KCipher-2 key seed found in Phase 2.
 * @param[out] qpc1_out     ChaCha8 key seed (valid on success).
 * @param[out] qpc2_out     ChaCha8 IV seed (valid on success).
 * @return                  Phase3Result with found flag and timing.
 */
inline Phase3Result run_phase3_for_hit(cudaStream_t stream, const CLIArgs& args,
                                       const TimingParams& timing, const FileInfo& f,
                                       const FileMeta& file_meta, unsigned long long qpc3_kcipher2,
                                       unsigned long long& qpc1_out, unsigned long long& qpc2_out) {
    Phase3Result result{};
    const size_t sig_len = file_meta.chacha8_signature.size();
    if (file_meta.chacha8_file_offset + sig_len > f.size)
        return result;

    std::ifstream ifs(f.path, std::ios::binary);
    if (!ifs)
        return result;

    ifs.seekg((std::streamoff)file_meta.chacha8_file_offset, std::ios::beg);
    std::vector<uint8_t> enc_host(sig_len);
    ifs.read(reinterpret_cast<char*>(enc_host.data()), (std::streamsize)sig_len);
    if ((size_t)ifs.gcount() != sig_len)
        return result;

    uint8_t *device_encrypted = nullptr, *device_signature = nullptr;
    CUDA_CHECK(cudaMalloc(&device_encrypted, sig_len));
    CUDA_CHECK(cudaMemcpy(device_encrypted, enc_host.data(), sig_len, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMalloc(&device_signature, sig_len));
    CUDA_CHECK(cudaMemcpy(device_signature, file_meta.chacha8_signature.data(), sig_len,
                          cudaMemcpyHostToDevice));

    Phase2Params phase2_params{};
    // qpc2 search range: use inter-cipher gap (qpc3 -> qpc2 distance),
    // which is independent of --max-offset and typically wider.
    const uint64_t q2_search_range = std::max(args.max_offset, (uint64_t)MAX_QPC2_DISTANCE);
    unsigned long long q2_lo_raw =
        (qpc3_kcipher2 > q2_search_range) ? (qpc3_kcipher2 - q2_search_range) : 0ULL;
    unsigned long long q2_hi_raw =
        (qpc3_kcipher2 > timing.step) ? (qpc3_kcipher2 - timing.step) : 0ULL;
    phase2_params.batch_qpc_lo = align_up_step(q2_lo_raw, timing.step);
    phase2_params.batch_qpc_hi = align_down_step(q2_hi_raw, timing.step);
    phase2_params.step = timing.step;
    phase2_params.max_offset = args.max_offset;
    // ChaCha8 counter starts at 0 for the first middle block (Block 1)
    phase2_params.chacha8_stream_off = 0;
    phase2_params.signature_length = (int)sig_len;

    // Compute Phase 3 candidate count (theoretical)
    uint64_t q2_range =
        (phase2_params.batch_qpc_hi > phase2_params.batch_qpc_lo)
            ? (phase2_params.batch_qpc_hi - phase2_params.batch_qpc_lo) / timing.step + 1
            : 0;
    uint64_t offset_steps = args.max_offset / timing.step;
    result.precompute_candidates = q2_range;
    result.brute_force_pairs = q2_range * offset_steps;

    const bool bench = args.enable_benchmark;

    /* Phase 3 timing: only measure when benchmark is active */
    cudaEvent_t t0 = nullptr, t1 = nullptr;
    if (bench) {
        CUDA_CHECK(cudaEventCreate(&t0));
        CUDA_CHECK(cudaEventCreate(&t1));
        CUDA_CHECK(cudaEventRecord(t0, stream));
    }

    result.is_hit = run_chacha8_brute_force_tiled(stream, phase2_params, device_encrypted,
                                             device_signature, qpc1_out, qpc2_out, bench);

    if (bench) {
        CUDA_CHECK(cudaEventRecord(t1, stream));
        CUDA_CHECK(cudaEventSynchronize(t1));
        float elapsed_ms = 0;
        CUDA_CHECK(cudaEventElapsedTime(&elapsed_ms, t0, t1));
        result.brute_force_ms = (double)elapsed_ms;
        CUDA_CHECK(cudaEventDestroy(t0));
        CUDA_CHECK(cudaEventDestroy(t1));
    }

    CUDA_CHECK(cudaFree(device_encrypted));
    CUDA_CHECK(cudaFree(device_signature));
    return result;
}

/* ===========================================================================
 *  Process brute_force hits (Phase 2 -> Phase 3 chaining)
 * =========================================================================== */

/**
 * @brief Process KCipher-2 brute_force hits: log results and run batched Phase 3.
 *
 * Records KCipher-2 seeds for each hit, then runs Phase 3 (ChaCha8 brute-force)
 * for all eligible files using a SHARED Yarrow precompute buffer.  This avoids
 * redundant precomputation when multiple hits share a similar qpc3 range.
 *
 * @param brute_force    Multi-file brute_force result from the KCipher-2 kernel.
 * @param nfiles          Number of files in the batch.
 * @param active_indices  Mapping from batch-local to global file indices.
 * @param data            PreparedData with file_metas and files.
 * @param args            CLI arguments.
 * @param timing          QPC calibration parameters.
 * @param stream          CUDA stream.
 * @param[in,out] state   Accumulated search state (updated in place).
 * @param phase1_buffer   Phase 1 precompute buffer (reused for Phase 3 overlap).
 * @param phase1_hi       Highest seed in the Phase 1 buffer.
 * @param phase1_count    Number of candidates in the Phase 1 buffer.
 */
inline void process_brute_force_hits(const MultifileBruteForceResult& brute_force, int nfiles,
                                     const std::vector<int>& active_indices,
                                     const PreparedData& data, const CLIArgs& args,
                                     const TimingParams& timing, cudaStream_t stream,
                                     SearchState& state, uint8_t* phase1_buffer,
                                     uint64_t phase1_hi, uint64_t phase1_count,
                                     int batch_id = 1) {
    /* -- Pass 1: record KC2 results and collect Phase 3 eligible hits -- */
    struct Phase3Hit {
        int batch_idx;
        int global_fi;
        unsigned long long qpc3;
        unsigned long long qpc4;
    };
    std::vector<Phase3Hit> phase3_hits_vec;

    for (int bi = 0; bi < nfiles; ++bi) {
        if (!brute_force.found[bi])
            continue;
        int global_fi = active_indices[bi];
        if (state.per_file_hit[global_fi])
            continue;

        state.per_file_hit[global_fi] = true;
        state.result_qpc3[global_fi] = brute_force.qpc3[bi];
        state.result_qpc4[global_fi] = brute_force.qpc4[bi];

        const auto& file_meta = data.file_metas[global_fi];
        if (!file_meta.chacha8_signature.empty()) {
            phase3_hits_vec.push_back({bi, global_fi, brute_force.qpc3[bi], brute_force.qpc4[bi]});
        }
    }

    /* -- Pass 2: reuse Phase 1 precompute buffer for Phase 3 ------------ */
    // Phase 1's precompute range was extended to cover Phase 3 needs,
    // so no additional Yarrow precomputation is required here.
    const uint64_t q2_search_range = std::max(args.max_offset, (uint64_t)MAX_QPC2_DISTANCE);
    uint8_t* shared_precompute = phase1_buffer;
    uint64_t shared_precompute_hi = phase1_hi;
    uint64_t shared_precompute_count = phase1_count;

    /* -- Pass 3: per-file Phase 3 kernel, reusing shared precompute ----- */
    const bool bench = args.enable_benchmark;
    cudaEvent_t t0 = nullptr, t1 = nullptr;
    if (bench && !phase3_hits_vec.empty()) {
        CUDA_CHECK(cudaEventCreate(&t0));
        CUDA_CHECK(cudaEventCreate(&t1));
    }

    int phase3_total = (int)phase3_hits_vec.size();
    int phase3_done = 0;
    int phase3_last_pct = -1;
    ConsoleProgress phase3_progress;
    if (phase3_total > 0) {
        LOG_PHASE2("[Batch " << batch_id << "] [Phase3]",
                   "ChaCha8 brute-force: " << phase3_total << " files");
        phase3_progress.begin();
    }

    for (int bi = 0; bi < nfiles; ++bi) {
        if (!brute_force.found[bi])
            continue;
        int global_fi = active_indices[bi];
        const auto& file_meta = data.file_metas[global_fi];
        const auto& f = data.files[file_meta.orig_idx];

        unsigned long long qpc3_kcipher2 = brute_force.qpc3[bi];
        unsigned long long qpc4_kcipher2 = brute_force.qpc4[bi];
        unsigned long long qpc1_chacha8 = 0, qpc2_chacha8 = 0;
        bool is_chacha8_found = false;

        if (!file_meta.chacha8_signature.empty() && shared_precompute != nullptr) {
            ++state.phase3_attempts;
            const size_t sig_len = file_meta.chacha8_signature.size();

            // Read encrypted bytes at ChaCha8 verification offset
            std::ifstream ifs(f.path, std::ios::binary);
            bool file_ok = false;
            std::vector<uint8_t> enc_host(sig_len);
            if (ifs && file_meta.chacha8_file_offset + sig_len <= f.size) {
                ifs.seekg((std::streamoff)file_meta.chacha8_file_offset, std::ios::beg);
                ifs.read(reinterpret_cast<char*>(enc_host.data()), (std::streamsize)sig_len);
                file_ok = ((size_t)ifs.gcount() == sig_len);
            }

            if (!file_ok) {
                LOG_WARN("PHASE3",
                         "Cannot read ChaCha8 verification bytes: " << f.path.u8string());
            }

            if (file_ok) {
                uint8_t *dev_enc = nullptr, *dev_sig = nullptr;
                CUDA_CHECK(cudaMalloc(&dev_enc, sig_len));
                CUDA_CHECK(cudaMemcpy(dev_enc, enc_host.data(), sig_len, cudaMemcpyHostToDevice));
                CUDA_CHECK(cudaMalloc(&dev_sig, sig_len));
                CUDA_CHECK(cudaMemcpy(dev_sig, file_meta.chacha8_signature.data(), sig_len,
                                      cudaMemcpyHostToDevice));

                // Per-file qpc2 search range
                uint64_t q2_hi = align_down_step(
                    (qpc3_kcipher2 > timing.step) ? (qpc3_kcipher2 - timing.step) : 0ULL,
                    timing.step);
                uint64_t q2_lo = align_up_step(
                    (qpc3_kcipher2 > q2_search_range) ? (qpc3_kcipher2 - q2_search_range) : 0ULL,
                    timing.step);

                // Reset single-file Phase 3 device state
                void* dev_found = nullptr;
                CUDA_CHECK(cudaGetSymbolAddress(&dev_found, global_phase3_found));
                CUDA_CHECK(cudaMemset(dev_found, 0, sizeof(int)));
                void* dev_q1 = nullptr;
                CUDA_CHECK(cudaGetSymbolAddress(&dev_q1, global_phase3_qpc1));
                CUDA_CHECK(cudaMemset(dev_q1, 0, sizeof(unsigned long long)));
                void* dev_q2 = nullptr;
                CUDA_CHECK(cudaGetSymbolAddress(&dev_q2, global_phase3_qpc2));
                CUDA_CHECK(cudaMemset(dev_q2, 0, sizeof(unsigned long long)));

                int num_sms = 0;
                cudaDeviceGetAttribute(&num_sms, cudaDevAttrMultiProcessorCount, 0);

                if (bench)
                    CUDA_CHECK(cudaEventRecord(t0, stream));

                chacha8_brute_force_kernel<<<num_sms * 2, 256, 0, stream>>>(
                    shared_precompute, shared_precompute_hi, timing.step, q2_hi, q2_lo,
                    args.max_offset, dev_enc, dev_sig, 0, (int)sig_len, bench);
                CUDA_CHECK(cudaStreamSynchronize(stream));

                if (bench) {
                    CUDA_CHECK(cudaEventRecord(t1, stream));
                    CUDA_CHECK(cudaEventSynchronize(t1));
                    float ms = 0;
                    CUDA_CHECK(cudaEventElapsedTime(&ms, t0, t1));
                    state.total_phase3_brute_force_ms += (double)ms;
                    uint64_t q2_cnt = (q2_hi > q2_lo) ? (q2_hi - q2_lo) / timing.step + 1 : 0;
                    state.total_phase3_candidates += q2_cnt;
                    state.total_phase3_pairs += q2_cnt * (args.max_offset / timing.step);
                }

                int found_flag = 0;
                CUDA_CHECK(cudaMemcpyFromSymbol(&found_flag, global_phase3_found, sizeof(int), 0,
                                                cudaMemcpyDeviceToHost));
                if (found_flag) {
                    CUDA_CHECK(cudaMemcpyFromSymbol(&qpc1_chacha8, global_phase3_qpc1,
                                                    sizeof(unsigned long long), 0,
                                                    cudaMemcpyDeviceToHost));
                    CUDA_CHECK(cudaMemcpyFromSymbol(&qpc2_chacha8, global_phase3_qpc2,
                                                    sizeof(unsigned long long), 0,
                                                    cudaMemcpyDeviceToHost));
                    is_chacha8_found = true;
                    ++state.phase3_hits;
                }

                CUDA_CHECK(cudaFree(dev_enc));
                CUDA_CHECK(cudaFree(dev_sig));
            }
            ++phase3_done;
            double p3_frac = (phase3_total > 0) ? (double)phase3_done / phase3_total : 0;
            int p3_pct = (int)(p3_frac * 100.0);
            if (p3_pct > phase3_last_pct) {
                phase3_last_pct = p3_pct;
                char p3_line[512];
                std::snprintf(p3_line, sizeof(p3_line),
                              "\033[92m[%s] [Batch %d] [Phase3]\033[0m %d%% | %d/%d hits",
                              now_time_short().c_str(), batch_id, p3_pct,
                              state.phase3_hits, phase3_total);
                phase3_progress.update(p3_line);
            }
        }

        const auto hit_tp = std::chrono::system_clock::now();
        append_combined_log(state.log_filename, f.path, file_meta.start_qpc, file_meta.end_qpc,
                            is_chacha8_found, qpc1_chacha8, qpc2_chacha8, true, qpc3_kcipher2,
                            qpc4_kcipher2, state.search_start, hit_tp, f.type);
        ++state.total_hits;
    }

    if (phase3_total > 0) {
        const char* p3_tag = (state.phase3_hits >= phase3_total) ? " (all found)" : "";
        char p3_final[512];
        std::snprintf(p3_final, sizeof(p3_final),
                      "\033[92m[%s] [Batch %d] [Phase3]\033[0m 100%% | %d/%d hits%s",
                      now_time_short().c_str(), batch_id, state.phase3_hits, phase3_total, p3_tag);
        phase3_progress.update(p3_final);
        phase3_progress.end();
    }

    if (bench && t0) {
        CUDA_CHECK(cudaEventDestroy(t0));
        CUDA_CHECK(cudaEventDestroy(t1));
    }
}

/* ===========================================================================
 *  Internal: search a single tile
 *
 *  A tile is a contiguous sub-range of the batch's QPC search window that
 *  fits in GPU memory.  This function is not exposed to external callers.
 * =========================================================================== */

/**
 * @brief Execute one tile of the Phase 1 (precompute) + Phase 2 (brute_force) pipeline.
 *
 * Allocates the Yarrow precompute buffer, runs the precompute kernel, sets
 * the L2 persistence hint, uploads per-file mask/value/header data, launches
 * the multi-file KCipher-2 brute_force kernel, and processes any hits.
 *
 * @param mb_idx             Batch index (for log messages).
 * @param tile_end           Highest seed in this tile.
 * @param tile_cands         Number of Yarrow candidates in this tile.
 * @param active_indices     Batch-local to global file-index mapping.
 * @param nfiles             Number of active files.
 * @param h_masks            Host mask array (all files in batch).
 * @param h_values           Host value array (all files in batch).
 * @param h_file_idx         Host file-index array for mask/value entries.
 * @param mask_groups        Sorted mask-group boundaries (from sort_matches_by_mask_group).
 * @param n_mask_groups      Number of active mask groups.
 * @param h_file_heads       Host concatenated headers (nfiles * 16).
 * @param h_file_head_lens   Host header lengths.
 * @param h_file_vhints      Host validator hint bitmasks.
 * @param data               PreparedData.
 * @param args               CLI arguments.
 * @param timing             QPC calibration parameters.
 * @param[in,out] state      Accumulated search state.
 * @param[out] out_precompute_ms  Precompute elapsed time (ms).
 * @param[out] out_brute_force_ms    Brute-force elapsed time (ms).
 * @param[out] out_brute_force_hits  Number of Phase 2 hits in this tile.
 */
inline void search_tile_(
    size_t mb_idx, uint64_t tile_end, uint64_t tile_cands, const std::vector<int>& active_indices,
    int nfiles, const std::vector<uint64_t>& h_masks, const std::vector<uint64_t>& h_values,
    const std::vector<int>& h_file_idx, const MaskGroupInfo mask_groups[NUM_MASK_GROUPS],
    int n_mask_groups, const std::vector<uint8_t>& h_file_heads,
    const std::vector<int>& h_file_head_lens, const std::vector<unsigned int>& h_file_vhints,
    const PreparedData& data, const CLIArgs& args, const TimingParams& timing, SearchState& state,
    float& out_precompute_ms, float& out_brute_force_ms, int& out_brute_force_hits,
    uint8_t*& out_phase1_buffer, uint64_t& out_phase1_hi, uint64_t& out_phase1_count) {
    int n_matches = (int)h_masks.size();

    cudaStream_t stream;
    CUDA_CHECK(cudaStreamCreate(&stream));

    /* Timing events are only needed when benchmark mode is active */
    const bool bench = args.enable_benchmark;
    cudaEvent_t evt_start = nullptr, evt_stop = nullptr;
    if (bench) {
        CUDA_CHECK(cudaEventCreate(&evt_start));
        CUDA_CHECK(cudaEventCreate(&evt_stop));
    }

    // Phase 1: Precompute Yarrow buffer + KC2 extended precompute
    LOG_PHASE1("[Batch " << (mb_idx + 1) << "] [Phase1]",
               "Precomputing " << fmt_count(tile_cands) << " Yarrow outputs...");

    const size_t precompute_bytes = (size_t)tile_cands * 16ULL;
    uint8_t* device_precompute = nullptr;
    CUDA_CHECK(cudaMalloc(&device_precompute, precompute_bytes));

    if (bench)
        CUDA_CHECK(cudaEventRecord(evt_start, stream));
    precompute_all_yarrow(device_precompute, tile_end, timing.step, tile_cands, stream);
    if (bench) {
        CUDA_CHECK(cudaEventRecord(evt_stop, stream));
        CUDA_CHECK(cudaStreamSynchronize(stream));
        cudaEventElapsedTime(&out_precompute_ms, evt_start, evt_stop);
    } else {
        CUDA_CHECK(cudaStreamSynchronize(stream));
    }

    LOG_PHASE1("[Batch " << (mb_idx + 1) << "] [Phase1]",
               "Precompute done in " << fmt_time(out_precompute_ms / 1000.0));

    // L2 cache persistence hint (Compute Capability >= 8.0)
    {
        cudaAccessPolicyWindow window{};
        window.base_ptr = device_precompute;
        window.num_bytes = precompute_bytes;
        window.hitRatio = 1.0f;
        window.hitProp = cudaAccessPropertyPersisting;
        window.missProp = cudaAccessPropertyStreaming;
        cudaStreamAttrValue attr{};
        attr.accessPolicyWindow = window;
        cudaStreamSetAttribute(stream, cudaStreamAttributeAccessPolicyWindow, &attr);
    }

    // Phase 2: Multi-file KCipher-2 offset brute-force
    LOG_PHASE2("[Batch " << (mb_idx + 1) << "] [Phase2]",
               "KCipher-2 brute-force: " << fmt_count(data.effective_offset_steps) << " offsets x "
                               << fmt_count(tile_cands) << " candidates (" << nfiles << " files)");

    // Compute per-file candidate index bounds within this tile
    std::vector<uint64_t> h_file_start_idx(nfiles);
    std::vector<uint64_t> h_file_end_idx(nfiles);
    for (int bi = 0; bi < nfiles; ++bi) {
        int global_fi = active_indices[bi];
        const auto& file_meta = data.file_metas[global_fi];
        uint64_t idx_lo =
            (file_meta.end_qpc <= tile_end) ? (tile_end - file_meta.end_qpc) / timing.step : 0;
        uint64_t idx_hi = (file_meta.start_qpc <= tile_end)
                              ? (tile_end - file_meta.start_qpc) / timing.step
                              : tile_cands - 1;
        h_file_start_idx[bi] = idx_lo;
        h_file_end_idx[bi] = std::min(idx_hi, tile_cands - 1);
    }

    // Upload sorted value/file_index and group info to device
    uint64_t* device_match_values = nullptr;
    int* device_match_file_index = nullptr;
    uint64_t* device_group_masks = nullptr;
    int* device_group_starts = nullptr;
    int* device_group_counts = nullptr;
    uint8_t* device_file_heads = nullptr;
    int* device_file_head_lengths = nullptr;
    unsigned int* device_file_vhints = nullptr;
    uint64_t* device_file_start_index = nullptr;
    uint64_t* device_file_end_index = nullptr;

    if (n_matches > 0) {
        CUDA_CHECK(cudaMalloc(&device_match_values, n_matches * sizeof(uint64_t)));
        CUDA_CHECK(cudaMalloc(&device_match_file_index, n_matches * sizeof(int)));
        CUDA_CHECK(cudaMemcpy(device_match_values, h_values.data(), n_matches * sizeof(uint64_t),
                              cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(device_match_file_index, h_file_idx.data(), n_matches * sizeof(int),
                              cudaMemcpyHostToDevice));

        // Upload mask-group boundaries for binary-search quick-check
        uint64_t h_group_masks[NUM_MASK_GROUPS] = {};
        int h_group_starts[NUM_MASK_GROUPS] = {};
        int h_group_counts[NUM_MASK_GROUPS] = {};
        for (int g = 0; g < n_mask_groups; ++g) {
            h_group_masks[g] = mask_groups[g].mask;
            h_group_starts[g] = mask_groups[g].start;
            h_group_counts[g] = mask_groups[g].count;
        }
        CUDA_CHECK(cudaMalloc(&device_group_masks, NUM_MASK_GROUPS * sizeof(uint64_t)));
        CUDA_CHECK(cudaMalloc(&device_group_starts, NUM_MASK_GROUPS * sizeof(int)));
        CUDA_CHECK(cudaMalloc(&device_group_counts, NUM_MASK_GROUPS * sizeof(int)));
        CUDA_CHECK(cudaMemcpy(device_group_masks, h_group_masks,
                              NUM_MASK_GROUPS * sizeof(uint64_t), cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(device_group_starts, h_group_starts, NUM_MASK_GROUPS * sizeof(int),
                              cudaMemcpyHostToDevice));
        CUDA_CHECK(cudaMemcpy(device_group_counts, h_group_counts, NUM_MASK_GROUPS * sizeof(int),
                              cudaMemcpyHostToDevice));
    }

    CUDA_CHECK(cudaMalloc(&device_file_heads, nfiles * 16 * sizeof(uint8_t)));
    CUDA_CHECK(cudaMalloc(&device_file_head_lengths, nfiles * sizeof(int)));
    CUDA_CHECK(cudaMalloc(&device_file_vhints, nfiles * sizeof(unsigned int)));
    CUDA_CHECK(cudaMalloc(&device_file_start_index, nfiles * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&device_file_end_index, nfiles * sizeof(uint64_t)));

    CUDA_CHECK(cudaMemcpy(device_file_heads, h_file_heads.data(), nfiles * 16 * sizeof(uint8_t),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_file_head_lengths, h_file_head_lens.data(), nfiles * sizeof(int),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_file_vhints, h_file_vhints.data(), nfiles * sizeof(unsigned int),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_file_start_index, h_file_start_idx.data(),
                          nfiles * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_file_end_index, h_file_end_idx.data(), nfiles * sizeof(uint64_t),
                          cudaMemcpyHostToDevice));

    // Launch multi-file brute_force (always runs; only timing is conditional)
    if (bench)
        CUDA_CHECK(cudaEventRecord(evt_start, stream));
    MultifileBruteForceResult brute_force = run_multifile_offset_brute_force(
        device_precompute, tile_end, timing.step, tile_cands, data.max_offset_steps,
        data.min_offset_steps, device_match_values, device_match_file_index, n_matches,
        device_group_masks, device_group_starts, device_group_counts, n_mask_groups,
        device_file_heads, device_file_head_lengths, device_file_vhints, nfiles,
        device_file_start_index, device_file_end_index, stream, bench,
        (int)(mb_idx + 1));
    if (bench) {
        CUDA_CHECK(cudaEventRecord(evt_stop, stream));
        CUDA_CHECK(cudaStreamSynchronize(stream));
        cudaEventElapsedTime(&out_brute_force_ms, evt_start, evt_stop);
    } else {
        CUDA_CHECK(cudaStreamSynchronize(stream));
    }
    out_brute_force_hits = brute_force.total_found;

    // Pass Phase 1 precompute buffer out before Phase 3 (so it can reuse it)
    out_phase1_buffer = device_precompute;
    out_phase1_hi = tile_end;
    out_phase1_count = tile_cands;

    // Process hits (may chain into Phase 3, reusing Phase 1 buffer)
    process_brute_force_hits(brute_force, nfiles, active_indices, data, args, timing, stream,
                             state, device_precompute, tile_end, tile_cands,
                             (int)(mb_idx + 1));

    // Free device memory
    if (device_match_values)
        cudaFree(device_match_values);
    if (device_match_file_index)
        cudaFree(device_match_file_index);
    if (device_group_masks)
        cudaFree(device_group_masks);
    if (device_group_starts)
        cudaFree(device_group_starts);
    if (device_group_counts)
        cudaFree(device_group_counts);
    if (device_file_heads)
        cudaFree(device_file_heads);
    if (device_file_head_lengths)
        cudaFree(device_file_head_lengths);
    if (device_file_vhints)
        cudaFree(device_file_vhints);
    if (device_file_start_index)
        cudaFree(device_file_start_index);
    if (device_file_end_index)
        cudaFree(device_file_end_index);
    if (bench) {
        CUDA_CHECK(cudaEventDestroy(evt_start));
        CUDA_CHECK(cudaEventDestroy(evt_stop));
    }
    CUDA_CHECK(cudaStreamDestroy(stream));
}

/* ===========================================================================
 *  Main search entry point
 * =========================================================================== */

/**
 * @brief Execute the full batch search loop across all mtime batches.
 *
 * For each mtime batch:
 *   1. Filters out already-found files.
 *   2. Computes the batch-local aligned search range.
 *   3. Splits the range into GPU-VRAM tiles.
 *   4. For each tile: runs Phase 1 (precompute) + Phase 2 (brute_force).
 *   5. Any Phase 2 hits automatically trigger Phase 3 (ChaCha8 brute-force).
 *   6. Logs batch-level summary (Phase 2 + Phase 3 hit counts and timing).
 *
 * Tile splitting is an internal optimization — callers see only
 * batch-level progress.
 *
 * @param gpu           GPU device info.
 * @param args          CLI arguments.
 * @param timing        QPC calibration parameters.
 * @param data          PreparedData from prepare_all_files().
 * @param log_filename  Path to the CSV result log.
 * @return              Final SearchState with all results.
 */
/** @brief Dummy kernel for GPU warm-up (forces JIT + context init). */
__global__ void warmup_kernel() {}

inline SearchState search_all_batches(const GPUInfo& gpu, const CLIArgs& args,
                                      const TimingParams& timing, const PreparedData& data,
                                      const std::string& log_filename) {
    // GPU warm-up: force JIT compilation and context initialization
    // before timing begins, avoiding first-batch bias.
    warmup_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();

    // Compute tile capacity from GPU VRAM (internal detail)
    const uint64_t tile_candidates = compute_tile_size();

    SearchState state;
    state.nfiles_total = data.nfiles_total;
    state.per_file_hit.assign(data.nfiles_total, false);
    state.result_qpc3.assign(data.nfiles_total, 0);
    state.result_qpc4.assign(data.nfiles_total, 0);
    state.search_start = std::chrono::system_clock::now();
    state.log_filename = log_filename;

    /* Reset GPU benchmark counters (only when --benchmark is active).
     * These accumulate the actual number of pairs each kernel evaluates,
     * giving accurate throughput that accounts for early-termination. */
    if (args.enable_benchmark) {
        unsigned long long zero = 0;
        CUDA_CHECK(cudaMemcpyToSymbol(global_actual_phase2_pairs, &zero, sizeof(zero)));
        CUDA_CHECK(cudaMemcpyToSymbol(global_actual_phase3_pairs, &zero, sizeof(zero)));
    }

    /* -----------------------------------------------------------------------
     *  Main batch loop.  Each mtime batch groups files encrypted around the
     *  same time.  Per batch:
     *    1. Build mask/value patterns for binary-search quick-check.
     *    2. Phase 1: Precompute Yarrow outputs (extended range covers Phase 3).
     *    3. Phase 2: KCipher-2 brute-force — find (qpc3, qpc4) per file.
     *    4. Phase 3: ChaCha8 brute-force — find (qpc1, qpc2) per hit,
     *       reusing Phase 1's precompute buffer.
     *    5. Log results and accumulate statistics.
     * ----------------------------------------------------------------------- */
    for (size_t mb_idx = 0; mb_idx < data.mtime_batches.size(); ++mb_idx) {
        if (state.all_found())
            break;

        const auto& mb = data.mtime_batches[mb_idx];

        // Filter already-found files
        std::vector<int> active_indices;
        for (int file_index : mb.file_indices) {
            if (!state.per_file_hit[file_index])
                active_indices.push_back(file_index);
        }
        if (active_indices.empty())
            continue;
        int nfiles = (int)active_indices.size();

        // Compute batch search range
        uint64_t batch_start = UINT64_MAX, batch_end = 0;
        for (int file_index : active_indices) {
            batch_start = std::min(batch_start, data.file_metas[file_index].start_qpc);
            batch_end = std::max(batch_end, data.file_metas[file_index].end_qpc);
        }
        // Extend precompute range downward to cover Phase 3 (ChaCha8) needs.
        // Phase 3 searches qpc2 up to MAX_QPC2_DISTANCE below qpc3, and qpc1
        // up to max_offset below qpc2.  Since qpc3 >= batch_start, the worst-case
        // lower bound is batch_start - MAX_QPC2_DISTANCE - max_offset.
        const uint64_t phase3_extension =
            std::max(args.max_offset, (uint64_t)MAX_QPC2_DISTANCE) + args.max_offset;
        const uint64_t extended_start =
            (batch_start > phase3_extension) ? (batch_start - phase3_extension) : 0ULL;
        const uint64_t b_aligned_start = align_up_step(extended_start, timing.step);
        const uint64_t b_aligned_end = align_down_step(batch_end, timing.step);
        if (b_aligned_end < b_aligned_start)
            continue;
        const uint64_t batch_total_cands = ((b_aligned_end - b_aligned_start) / timing.step) + 1ULL;
        const uint64_t batch_num_tiles =
            (batch_total_cands + tile_candidates - 1) / tile_candidates;

        // Snapshot Phase 3 counters before this batch
        int phase3_attempts_before = state.phase3_attempts;
        int phase3_hits_before = state.phase3_hits;
        double phase3_ms_before = state.total_phase3_brute_force_ms;

        double batch_span_sec = (double)(b_aligned_end - b_aligned_start) / 1e9;
        log_separator("Batch " + std::to_string(mb_idx + 1) + "/" +
                      std::to_string(data.mtime_batches.size()) +
                      " | recovered: " + std::to_string(state.total_hits) + "/" +
                      std::to_string(state.files_processed) +
                      " | progress: " + std::to_string(state.files_processed) + "/" +
                      std::to_string(state.nfiles_total) + " | " + std::to_string(nfiles) +
                      " files" + " | " + fmt_time(batch_span_sec) + " span" + " | " +
                      fmt_count(batch_total_cands) + " candidates");

        // Build per-batch mask/value pairs for the GPU quick-check path
        std::vector<uint64_t> h_masks, h_values;
        std::vector<int> h_file_idx;
        std::vector<uint8_t> h_file_heads(nfiles * 16, 0);
        std::vector<int> h_file_head_lens(nfiles, 0);
        std::vector<unsigned int> h_file_vhints(nfiles, VHINT_ALL);

        for (int bi = 0; bi < nfiles; ++bi) {
            int global_fi = active_indices[bi];
            const auto& file_meta = data.file_metas[global_fi];
            h_file_vhints[bi] = build_file_masks(file_meta.head, bi, h_masks, h_values, h_file_idx,
                                                 data.original_exts[global_fi]);
            int copy_len = std::min(file_meta.head_len, 16);
            memcpy(h_file_heads.data() + bi * 16, file_meta.head.data(), copy_len);
            h_file_head_lens[bi] = copy_len;
        }

        // Sort match entries by mask group, then by value for binary search.
        MaskGroupInfo mask_groups[NUM_MASK_GROUPS] = {};
        int n_mask_groups = 0;
        sort_matches_by_mask_group(h_masks, h_values, h_file_idx, mask_groups, n_mask_groups);

        // Internal tile loop (transparent to user)
        float total_precompute_ms = 0, total_brute_force_ms = 0;
        int total_brute_force_hits = 0;
        uint8_t* phase1_buffer = nullptr;
        uint64_t phase1_hi = 0, phase1_count = 0;

        for (uint64_t tile_idx = 0; tile_idx < batch_num_tiles; ++tile_idx) {
            if (state.all_found())
                break;

            const uint64_t tile_start = b_aligned_start + tile_idx * tile_candidates * timing.step;
            const uint64_t tile_end =
                std::min(tile_start + (tile_candidates - 1) * timing.step, b_aligned_end);
            if (tile_end < tile_start)
                break;
            const uint64_t tile_cands = ((tile_end - tile_start) / timing.step) + 1ULL;

            // Free previous tile's buffer before allocating a new one
            if (phase1_buffer && tile_idx > 0) {
                CUDA_CHECK(cudaFree(phase1_buffer));
                phase1_buffer = nullptr;
            }

            float precompute_ms = 0, brute_force_ms = 0;
            int brute_force_hits = 0;

            search_tile_(mb_idx, tile_end, tile_cands, active_indices, nfiles, h_masks, h_values,
                         h_file_idx, mask_groups, n_mask_groups, h_file_heads, h_file_head_lens,
                         h_file_vhints, data, args, timing, state, precompute_ms, brute_force_ms,
                         brute_force_hits, phase1_buffer, phase1_hi, phase1_count);

            total_precompute_ms += precompute_ms;
            total_brute_force_ms += brute_force_ms;
            total_brute_force_hits += brute_force_hits;

            /* Accumulate global timing and theoretical pairs (benchmark only) */
            if (args.enable_benchmark) {
                state.total_precompute_ms += precompute_ms;
                state.total_brute_force_ms += brute_force_ms;
                state.total_precompute_candidates += tile_cands;
                state.total_brute_force_pairs_theoretical +=
                    (uint64_t)tile_cands * data.effective_offset_steps;
            }

            if (state.all_found())
                break;
        }

        // Free Phase 1 precompute buffer (kept alive for Phase 3 reuse)
        if (phase1_buffer) {
            CUDA_CHECK(cudaFree(phase1_buffer));
            phase1_buffer = nullptr;
        }

        // Batch-level Phase 2 (KCipher-2) summary
        LOG_PHASE2("[Batch " << (mb_idx + 1) << "] [Phase2]",
                   "Phase2(KCipher-2): "
                       << total_brute_force_hits << "/" << nfiles << " hits in "
                       << fmt_time(total_brute_force_ms / 1000.0)
                       << (total_brute_force_hits == nfiles ? " (all found)" : ""));

        // Batch-level Phase 3 (ChaCha8) summary
        {
            int batch_phase3_attempts = state.phase3_attempts - phase3_attempts_before;
            int batch_phase3_hits = state.phase3_hits - phase3_hits_before;
            double batch_phase3_sec =
                (state.total_phase3_brute_force_ms - phase3_ms_before) / 1000.0;
            if (batch_phase3_attempts > 0) {
                LOG_PHASE2(
                    "[Batch " << (mb_idx + 1) << "] [Phase3]",
                    "Phase3(ChaCha8):  "
                        << batch_phase3_hits << "/" << batch_phase3_attempts << " hits in "
                        << fmt_time(batch_phase3_sec)
                        << (batch_phase3_hits == batch_phase3_attempts ? " (all found)" : ""));
            }
        }

        if (args.enable_benchmark) {
            state.batch_stats.push_back({nfiles, batch_total_cands, (double)total_precompute_ms,
                                         (double)total_brute_force_ms, total_brute_force_hits});
        }

        state.files_processed += nfiles;

        if (state.all_found()) {
            LOG_INFO("SEARCH", "All " << state.nfiles_total
                                      << " files found — stopping early at batch " << (mb_idx + 1)
                                      << "/" << data.mtime_batches.size());
            break;
        }
    }

    /* Read back GPU benchmark counters into SearchState. */
    if (args.enable_benchmark) {
        unsigned long long p2 = 0, p3 = 0;
        CUDA_CHECK(cudaMemcpyFromSymbol(&p2, global_actual_phase2_pairs, sizeof(p2)));
        CUDA_CHECK(cudaMemcpyFromSymbol(&p3, global_actual_phase3_pairs, sizeof(p3)));
        state.total_brute_force_pairs = p2;
        state.total_phase3_pairs_actual = p3;
    }

    return state;
}
