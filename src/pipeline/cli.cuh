// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file cli.cuh
 * @brief Command-line argument parsing for the Step2_SeedScanner tool.
 *
 * Parses positional arguments (root path, reference timestamp, reference QPC)
 * and optional flags (--min-offset, --max-offset, --max-batch) into a CLIArgs
 * struct.  Exits with a usage message if mandatory arguments are missing.
 *
 */
#pragma once

#include <cerrno>
#include <cstdlib>
#include <string>
#include <thread>

#include "common/constants.h"
#include "common/logger.h"
#include "pipeline/types.cuh"

/**
 * @brief Parse command-line arguments into a CLIArgs structure.
 *
 * Positional parameters:
 *   argv[1] — root directory to scan for .akira files.
 *   argv[2] — reference local timestamp ("YYYY-MM-DD HH:MM:SS.mmm").
 *   argv[3] — reference QPC counter value (decimal).
 *   argv[4] — (optional) CPU thread count for filesystem scanning.
 *
 * Optional flags (may appear anywhere after argv[1]):
 *   --min-offset <ns>   Minimum Yarrow inter-call gap.
 *   --max-offset <ns>   Maximum Yarrow inter-call gap.
 *   --max-batch  <ns>   Per-file QPC lookback window.
 *   --benchmark         Enable GPU performance counters and JSON report output.
 *
 * @param argc  Argument count from main().
 * @param argv  Argument vector from main().
 * @return      Populated CLIArgs.
 */
inline CLIArgs parse_cli(int argc, char** argv) {
    if (argc >= 2) {
        std::string first(argv[1]);
        if (first == "--version" || first == "-v") {
            std::cout << "Step2_SeedScanner " << AKIRA_DECRYPTOR_VERSION << std::endl;
            std::exit(0);
        }
        if (first == "--help" || first == "-h") {
            std::cout << "Usage: " << argv[0]
                      << " <root_path> \"YYYY-MM-DD HH:MM:SS.mmm\" <ref_qpc> [threads]\n"
                      << "  --min-offset <ns>   Minimum Yarrow inter-call gap (default: 0)\n"
                      << "  --max-offset <ns>   Maximum Yarrow inter-call gap (default: "
                      << MAX_OFFSET << ")\n"
                      << "  --max-batch <ns>    Per-file QPC lookback window (default: "
                      << MAX_BATCH_WINDOW_NS << ")\n"
                      << "  --benchmark         Enable GPU performance counters and JSON report\n"
                      << "  --test              Enable test mode (zero-byte ChaCha8 signature)\n"
                      << "  --version, -v       Show version\n"
                      << "  --help, -h          Show this help\n";
            std::exit(0);
        }
    }

    if (argc < 4) {
        LOG_ERR("CLI", "Usage: " << argv[0]
                                 << " <root_path> \"YYYY-MM-DD HH:MM:SS.mmm\" <ref_qpc> [threads]");
        std::exit(1);
    }

    CLIArgs args;
    args.root_path = argv[1];
    args.ref_time_str = argv[2];
    args.ref_qpc = std::strtoull(argv[3], nullptr, 10);

    // Default thread count: hardware concurrency (clamped to >= 1)
    args.threads = std::thread::hardware_concurrency();
    if (args.threads == 0)
        args.threads = 1;

    // Optional positional: thread count (argv[4], only if not a flag)
    if (argc >= 5 && argv[4][0] != '-') {
        try {
            unsigned long long temp = std::stoull(argv[4], nullptr, 10);
            if (temp > 0ULL) {
                if (temp > (unsigned long long)MAX_CUDA_GRID_DIM)
                    temp = (unsigned long long)MAX_CUDA_GRID_DIM;
                args.threads = static_cast<size_t>(temp);
            }
        } catch (const std::exception&) {
            LOG_WARN("CLI", "Invalid threads argument \"" << argv[4]
                                                          << "\". Using default: " << args.threads);
        }
    }

    // Optional keyword flags
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--min-offset" && i + 1 < argc) {
            char* endptr = nullptr;
            errno = 0;
            args.min_offset = std::strtoull(argv[++i], &endptr, 10);
            if (errno == ERANGE || endptr == argv[i]) {
                LOG_ERR("CLI", "Invalid --min-offset value: " << argv[i]);
                std::exit(1);
            }
        } else if (arg == "--max-offset" && i + 1 < argc) {
            char* endptr = nullptr;
            errno = 0;
            args.max_offset = std::strtoull(argv[++i], &endptr, 10);
            if (errno == ERANGE || endptr == argv[i]) {
                LOG_ERR("CLI", "Invalid --max-offset value: " << argv[i]);
                std::exit(1);
            }
        } else if (arg == "--max-batch" && i + 1 < argc) {
            char* endptr = nullptr;
            errno = 0;
            args.max_batch_window_ns = std::strtoull(argv[++i], &endptr, 10);
            if (errno == ERANGE || endptr == argv[i]) {
                LOG_ERR("CLI", "Invalid --max-batch value: " << argv[i]);
                std::exit(1);
            }
        } else if (arg == "--benchmark") {
            args.enable_benchmark = true;
        } else if (arg == "--test") {
            args.test_mode = true;
        }
    }

    // Log non-default overrides
    if (args.min_offset != MIN_OFFSET || args.max_offset != MAX_OFFSET ||
        args.max_batch_window_ns != MAX_BATCH_WINDOW_NS) {
        LOG_INFO("CLI", "min_offset=" << args.min_offset << " max_offset=" << args.max_offset
                                      << " max_batch_window_ns=" << args.max_batch_window_ns);
    }

    return args;
}
