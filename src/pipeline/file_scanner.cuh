// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file file_scanner.cuh
 * @brief Filesystem scanning, header collection, encryption classification,
 *        and KCipher-2 / ChaCha8 signature building.
 *
 * Responsibilities:
 *   1. Recursively enumerate .akira files under a root directory.
 *   2. Classify each file's encryption mode (full / partial / half).
 *   3. Read the first 16 bytes of each file for KCipher-2 signature matching.
 *   4. Build per-file QPC search ranges from mtime-to-QPC calibration.
 *   5. Construct mask/value patterns for the GPU quick-check path.
 *   6. Look up known ChaCha8 plaintext signatures for Phase 3 verification.
 *
 * All filesystem I/O and Windows API calls are Windows-only (no Linux compat).
 *
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <Windows.h>

#include "common/constants.h"
#include "common/logger.h"
#include "pipeline/types.cuh"
#include "kernels/kcipher2_brute_force.cuh" // VHINT_* bitmask definitions

namespace fs = std::filesystem;

/* ===========================================================================
 *  Supported file extensions for GPU brute-force
 *
 *  Only files whose original extension (before .akira) matches one of these
 *  entries will be included in the search.  Extensions are stored in
 *  lowercase.
 * =========================================================================== */

static const std::set<std::string> SUPPORTED_EXTENSIONS = {
    ".png",  ".pdf",  ".jpg",  ".jpeg", ".sqlite", ".sqlite3", ".db",  ".zip",
    ".docx", ".xlsx", ".pptx", ".doc",  ".xls",    ".ppt",     ".hwp"};

/* ===========================================================================
 *  Low-level helpers (Windows only)
 * =========================================================================== */

/**
 * @brief Parse a local-time string into a Windows SYSTEMTIME structure.
 *
 * Accepts "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD HH:MM:SS.mmm".
 *
 * @param s         Input string.
 * @param[out] st   Populated SYSTEMTIME on success.
 * @return          true if parsing succeeded.
 */
static bool parse_local_time_string(const std::string& s, SYSTEMTIME& st) {
    int Y = 0, M = 0, D = 0, h = 0, m = 0;
    double sec = 0.0;
    if (sscanf_s(s.c_str(), "%d-%d-%d %d:%d:%lf", &Y, &M, &D, &h, &m, &sec) != 6)
        return false;
    int whole_sec = (int)sec;
    int ms = (int)((sec - whole_sec) * 1000.0 + 0.5);
    if (ms < 0)
        ms = 0;
    if (ms > 999)
        ms = 999;

    st.wYear = (WORD)Y;
    st.wMonth = (WORD)M;
    st.wDay = (WORD)D;
    st.wHour = (WORD)h;
    st.wMinute = (WORD)m;
    st.wSecond = (WORD)whole_sec;
    st.wMilliseconds = (WORD)ms;
    st.wDayOfWeek = 0;
    return true;
}

/**
 * @brief Convert a local-time string to a Windows FILETIME value (100 ns ticks).
 *
 * The string is interpreted as local time and converted through the system
 * timezone to UTC before encoding as a FILETIME.
 *
 * @param s  Local-time string ("YYYY-MM-DD HH:MM:SS[.mmm]").
 * @return   FILETIME in 100 ns ticks (0 on failure).
 */
static uint64_t local_string_to_filetime_100ns(const std::string& s) {
    SYSTEMTIME st_local{}, st_utc{};
    FILETIME filetime{};
    if (!parse_local_time_string(s, st_local))
        return 0ULL;
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &st_local, &st_utc))
        return 0ULL;
    if (!SystemTimeToFileTime(&st_utc, &filetime))
        return 0ULL;
    ULARGE_INTEGER u{};
    u.LowPart = filetime.dwLowDateTime;
    u.HighPart = filetime.dwHighDateTime;
    return u.QuadPart;
}

/**
 * @brief Read the last-write FILETIME of a file via the Win32 API.
 *
 * Uses GetFileAttributesExW to avoid opening a file handle.
 *
 * @param p  Path to the file.
 * @return   Last-write time in 100 ns FILETIME ticks (0 on failure).
 */
static inline uint64_t get_filetime_raw(const fs::path& p) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad))
        return 0ULL;
    ULARGE_INTEGER ull;
    ull.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    ull.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    return ull.QuadPart;
}

/**
 * @brief Convert a FILETIME delta (100 ns ticks) to QPC ticks.
 *
 * Overflow-safe: splits into seconds + remainder to stay within int64 range.
 *
 * @param ft_delta_100ns  Signed FILETIME difference.
 * @param qpf             QueryPerformanceFrequency value.
 * @return                Equivalent QPC tick delta.
 */
static inline int64_t ft100ns_to_qpc_ticks(int64_t ft_delta_100ns, uint64_t qpf) {
    const int64_t TEN_M = 10'000'000LL;
    int64_t sec_part = ft_delta_100ns / TEN_M;
    int64_t rem_part = ft_delta_100ns % TEN_M;
    // Clamp to prevent overflow: ±50 years (1.577e9 seconds)
    const int64_t MAX_SEC = 1'577'000'000LL;
    if (sec_part > MAX_SEC) sec_part = MAX_SEC;
    if (sec_part < -MAX_SEC) sec_part = -MAX_SEC;
    return sec_part * (int64_t)qpf + rem_part * (int64_t)qpf / TEN_M;
}

/**
 * @brief Format a time_point as a local-time string "YYYY-MM-DD HH:MM:SS".
 * @param tp  Time point to format.
 * @return    Formatted string.
 */
static inline std::string tp_local_str(std::chrono::system_clock::time_point tp) {
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    localtime_s(&tm, &tt);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

/* ===========================================================================
 *  Encryption-type classification
 * =========================================================================== */

/**
 * @brief Classify a .akira file into its encryption mode.
 *
 * Replicates the ransomware's own classification logic:
 *   - VM disk images (.vmdk, .vhd, etc.) or files >= 2 MB -> PARTIAL.
 *   - Database extensions (.sqlite, .mdb, etc.)            -> FULL.
 *   - Everything else                                      -> HALF.
 *   - Non-.akira files                                     -> EXCLUDE.
 *
 * @param file_path  Path to the .akira file.
 * @return           One of FULL_ENCRYPTION, PARTIAL_ENCRYPTION, HALF_ENCRYPTION,
 *                   or EXCLUDE_ENCRYPTION.
 */
static inline uint8_t classify_encryption_type_path(const fs::path& file_path) {
    const std::string akira = file_path.extension().string();
    const std::string ext = file_path.stem().extension().string();

    if (akira != ".akira")
        return EXCLUDE_ENCRYPTION;

    // Classification order (confirmed by ground truth validation):
    //   1. VM_ENCRYPT_EXT → PARTIAL (regardless of size)
    //   2. FULL_ENCRYPT_EXT → FULL (regardless of size)
    //   3. Size >= 2MB → PARTIAL
    //   4. Default → HALF
    for (const auto& e : VM_ENCRYPT_EXT)
        if (ext == e)
            return PARTIAL_ENCRYPTION;

    for (const auto& e : FULL_ENCRYPT_EXT)
        if (ext == e)
            return FULL_ENCRYPTION;

    std::error_code ec;
    const uintmax_t size = fs::file_size(file_path, ec);
    if (!ec && size >= PARTIAL_ENCRYPTION_SIZE_THRESHOLD)
        return PARTIAL_ENCRYPTION;

    return HALF_ENCRYPTION;
}

/* ===========================================================================
 *  CSV log file helpers
 * =========================================================================== */

/**
 * @brief Create (or overwrite) the CSV result log with a header row.
 * @param log_filename  Path to the output CSV file.
 */
static inline void init_log_file(const std::string& log_filename) {
    std::ofstream ofs(log_filename, std::ios::trunc);
    if (!ofs)
        return;
    ofs << "found_at,file_path,file_name,start_qpc,end_qpc,"
           "qpc1,qpc2,qpc3,qpc4,elapsed_seconds,enc_mode\n";
}

/**
 * @brief Append a single recovery result to the CSV log.
 *
 * Writes one row containing the timestamp, file identity, QPC seed values
 * for both KCipher-2 (qpc3/qpc4) and ChaCha8 (qpc1/qpc2), elapsed time
 * since search start, and encryption mode.
 *
 * @param log_filename    Path to the CSV log file.
 * @param filepath        .akira file path.
 * @param start_qpc       Lower QPC bound for the file.
 * @param end_qpc         Upper QPC bound for the file.
 * @param have_qpc1_qpc2  true if Phase 3 (ChaCha8) seeds are available.
 * @param qpc1            ChaCha8 key seed (valid only if have_qpc1_qpc2).
 * @param qpc2            ChaCha8 IV seed (valid only if have_qpc1_qpc2).
 * @param have_qpc3_qpc4  true if Phase 2 (KCipher-2) seeds are available.
 * @param qpc3            KCipher-2 key seed.
 * @param qpc4            KCipher-2 IV seed.
 * @param search_start_tp Time point when the search began.
 * @param hit_tp           Time point when this hit was found.
 * @param enc_type         Encryption mode code.
 */
static inline void append_combined_log(const std::string& log_filename, const fs::path& filepath,
                                       uint64_t start_qpc, uint64_t end_qpc, bool have_qpc1_qpc2,
                                       uint64_t qpc1, uint64_t qpc2, bool have_qpc3_qpc4,
                                       uint64_t qpc3, uint64_t qpc4,
                                       std::chrono::system_clock::time_point search_start_tp,
                                       std::chrono::system_clock::time_point hit_tp,
                                       uint8_t enc_type = HALF_ENCRYPTION) {
    if (!have_qpc1_qpc2 && !have_qpc3_qpc4)
        return;

    std::time_t hit_time_c = std::chrono::system_clock::to_time_t(hit_tp);

    std::ofstream ofs(log_filename, std::ios::app);
    if (!ofs)
        return;

    std::tm tm{};
    localtime_s(&tm, &hit_time_c);

    auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(hit_tp.time_since_epoch()) % 1000;
    ofs << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(3) << std::setfill('0')
        << ms.count() << ',';
    ofs << std::setfill(' ');

    const auto absolute_path = fs::absolute(filepath);
    const std::string file_path_str = absolute_path.u8string();
    const std::string file_name_str = filepath.filename().u8string();

    ofs << file_path_str << ',' << file_name_str << ',' << start_qpc << ',' << end_qpc << ',';

    if (have_qpc1_qpc2) {
        ofs << qpc1 << ',' << qpc2 << ',';
    } else {
        ofs << ',' << ',';
    }

    if (have_qpc3_qpc4) {
        ofs << qpc3 << ',' << qpc4;
    } else {
        ofs << ',';
    }

    const double elapsed_seconds = std::chrono::duration<double>(hit_tp - search_start_tp).count();
    ofs << ',' << std::fixed << std::setprecision(3) << elapsed_seconds << ','
        << enc_mode_str(enc_type) << '\n';
}

/* ===========================================================================
 *  Parallel filesystem scan + header extraction
 * =========================================================================== */

/**
 * @brief Recursively scan a directory for .akira files and extract headers.
 *
 * Multi-threaded: the candidate list is partitioned across num_workers
 * threads. Each thread independently reads file metadata (mtime, size,
 * encryption type) and the first 16 bytes of ciphertext.
 *
 * Side-effect: writes a file_list CSV file listing all found files.
 *
 * @param root                Root directory to scan.
 * @param[out] out_files      Populated with FileInfo for every valid .akira file,
 *                            sorted by mtime ascending.
 * @param[out] out_heads      Populated with AkiraHead for files whose header
 *                            could be read.
 * @param num_workers         Number of CPU threads (0 = 1).
 * @param print_progress      true to log progress messages.
 * @param file_list_filename  Path for the target-list CSV output.
 */
static void collect_akira_heads_parallel(const fs::path& root, std::vector<FileInfo>& out_files,
                                         std::vector<AkiraHead>& out_heads, size_t num_workers,
                                         bool print_progress,
                                         const std::string& file_list_filename) {
    out_files.clear();
    out_heads.clear();

    if (!fs::exists(root)) {
        LOG_ERR("SCAN", "Path not found: " << root);
        std::ofstream(file_list_filename, std::ios::trunc).close();
        return;
    }

    // Gather .akira candidates (case-insensitive extension match)
    std::vector<fs::path> candidates;
    for (auto it = fs::recursive_directory_iterator(root); it != fs::recursive_directory_iterator();
         ++it) {
        std::error_code ec;
        if (!it->is_regular_file(ec) || ec)
            continue;

        std::string ext = it->path().extension().string();
        for (char& c : ext)
            c = (char)std::tolower((unsigned char)c);
        if (ext == ".akira")
            candidates.push_back(it->path());
    }

    const size_t total = candidates.size();
    if (total == 0) {
        if (print_progress)
            LOG_INFO("SCAN", "No .akira files found");
        std::ofstream(file_list_filename, std::ios::trunc).close();
        return;
    }

    if (num_workers == 0)
        num_workers = 1;
    const size_t chunk = (total + num_workers - 1) / num_workers;

    std::atomic<size_t> processed{0};
    std::mutex merge_mtx;

    std::vector<FileInfo> final_files;
    final_files.reserve(total);
    std::vector<AkiraHead> final_heads;
    final_heads.reserve(total);

    auto worker = [&](size_t begin_idx, size_t end_idx) {
        std::vector<FileInfo> local_files;
        local_files.reserve(end_idx - begin_idx);
        std::vector<AkiraHead> local_heads;
        local_heads.reserve(end_idx - begin_idx);

        for (size_t i = begin_idx; i < end_idx; ++i) {
            const fs::path p = candidates[i];

            std::error_code ec;
            const uintmax_t fsize = fs::file_size(p, ec);
            const uint64_t mtime = get_filetime_raw(p);
            const uint8_t type = classify_encryption_type_path(p);

            if (type != EXCLUDE_ENCRYPTION) {
                local_files.push_back(FileInfo{type, mtime, (ec ? 0ULL : fsize), p});

                // Header extraction: read up to 16 bytes from the usable
                // front half (file size minus 512-byte Akira footer).
                uintmax_t usable = 0;
                uintmax_t front_half = 0;
                if (!ec && fsize > AKIRA_FOOTER_SIZE) {
                    usable = fsize - AKIRA_FOOTER_SIZE;
                    front_half = usable / 2;
                }

                if (front_half > 0) {
                    const size_t want =
                        static_cast<size_t>(std::min<uintmax_t>(HEAD_MAX, front_half));
                    std::ifstream ifs(p, std::ios::binary);
                    if (ifs) {
                        std::vector<uint8_t> buf(want, 0);
                        ifs.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)want);
                        const std::streamsize got = ifs.gcount();
                        if (got > 0) {
                            buf.resize(static_cast<size_t>(got));
                            local_heads.push_back(AkiraHead{p, std::move(buf)});
                        }
                    }
                }
            }

            ++processed;
        }

        std::lock_guard<std::mutex> lk(merge_mtx);
        final_files.insert(final_files.end(), std::make_move_iterator(local_files.begin()),
                           std::make_move_iterator(local_files.end()));
        final_heads.insert(final_heads.end(), std::make_move_iterator(local_heads.begin()),
                           std::make_move_iterator(local_heads.end()));
    };

    // Launch worker threads
    std::vector<std::thread> threads;
    threads.reserve(num_workers);
    for (size_t w = 0; w < num_workers; ++w) {
        size_t b = w * chunk;
        if (b >= total)
            break;
        size_t e = std::min(total, b + chunk);
        threads.emplace_back(worker, b, e);
    }
    for (auto& t : threads)
        t.join();
    if (print_progress)
        LOG_INFO("SCAN", total << " infected files found in " << root.u8string());

    // Sort by FILETIME ascending (tie-break on path)
    std::sort(final_files.begin(), final_files.end(), [](const FileInfo& a, const FileInfo& b) {
        if (a.mtime != b.mtime)
            return a.mtime < b.mtime;
        return a.path < b.path;
    });

    // Write target list CSV
    {
        std::ofstream csv(file_list_filename, std::ios::trunc);
        if (!csv) {
            LOG_ERR("SCAN", "Cannot open " << file_list_filename << " for write");
        } else {
            for (const auto& f : final_files) {
                csv << static_cast<int>(f.type) << "," << f.mtime << "," << f.size << ","
                    << fs::absolute(f.path).u8string() << "\n";
            }
        }
    }

    out_files.assign(std::make_move_iterator(final_files.begin()),
                     std::make_move_iterator(final_files.end()));
    out_heads.assign(std::make_move_iterator(final_heads.begin()),
                     std::make_move_iterator(final_heads.end()));
}

/* ===========================================================================
 *  Header indexing by path
 * =========================================================================== */

/**
 * @brief Collect encrypted headers and build a path-keyed lookup map.
 *
 * Delegates to collect_akira_heads_parallel for the heavy lifting, then
 * reorganises the flat AkiraHead vector into a hash map for O(1) lookup
 * during per-file metadata construction.
 *
 * @param root           Root scan directory.
 * @param threads        Number of worker threads.
 * @param target_file    Path for the target-list CSV output.
 * @param[out] files     Populated with sorted FileInfo entries.
 * @param[out] head_by_path  Map from absolute path (UTF-8) to header bytes.
 */
inline void
collect_and_index_headers(const fs::path& root, size_t threads, const std::string& target_file,
                          std::vector<FileInfo>& files,
                          std::unordered_map<std::string, std::vector<uint8_t>>& head_by_path) {
    std::vector<AkiraHead> heads;
    collect_akira_heads_parallel(root, files, heads, threads, true, target_file);

    head_by_path.reserve(heads.size());
    for (const auto& h : heads) {
        head_by_path.emplace(h.path.u8string(), h.head);
    }
}

/* ===========================================================================
 *  ChaCha8 known-plaintext signature lookup
 * =========================================================================== */

/**
 * @brief Look up the ChaCha8 known-plaintext signature for Phase 3 verification.
 *
 * In test mode (--test), the test dataset has 8 zero bytes injected at offset
 * 0xFFFF (Block 1 start) in every file with nblocks > 2.  This provides a
 * known-plaintext for verifying the ChaCha8 key recovery.
 *
 * In production mode, ChaCha8 verification requires file-format-specific
 * known plaintext at the middle-block offset, which is not yet implemented
 * for individual extensions.
 *
 * @param ext              Lowercase original file extension.
 * @param[out] out_sig     Populated with expected plaintext bytes on success.
 * @param[out] out_file_off  Absolute file offset for verification.
 * @param enc_type         Encryption mode (FULL / PARTIAL / HALF).
 * @param akira_file_size  Total .akira file size in bytes.
 * @param test_mode        If true, assume 8 zero bytes at offset 0xFFFF.
 * @return                 true if a signature was found and the file is large enough.
 */
inline bool lookup_chacha8_signature(const std::string& ext, std::vector<uint8_t>& out_sig,
                                     uint64_t& out_file_off, uint8_t enc_type,
                                     uint64_t akira_file_size, bool test_mode = false) {
    if (test_mode) {
        out_sig.assign(8, 0x00);
    } else {
        return false;  // Production: no CC8 known-plaintext available yet
    }

    const uint64_t content =
        (akira_file_size > AKIRA_FOOTER_SIZE) ? (akira_file_size - AKIRA_FOOTER_SIZE) : 0ULL;

    // Determine first encryption region size
    uint64_t region_size;
    if (enc_type == FULL_ENCRYPTION)
        region_size = content;
    else if (enc_type == HALF_ENCRYPTION)
        region_size = content / 2;
    else /* PARTIAL */
        region_size = content / 10;

    // Need > 2 blocks for a middle ChaCha8 block to exist
    if (region_size <= 2 * AKIRA_BLOCK_SIZE) {
        out_sig.clear();
        return false;
    }

    // ChaCha8 verification at Block 1 (first middle block) = file offset 0xFFFF
    out_file_off = AKIRA_BLOCK_SIZE;
    return true;
}

/* ===========================================================================
 *  KCipher-2 quick-check mask/value builder
 * =========================================================================== */

/**
 * @brief Build a KCipher-2 first-8-byte mask/value pair from the encrypted
 *        header and the known file magic.
 *
 * The GPU quick-check path XORs the first 8 KCipher-2 keystream bytes with
 * the encrypted header and compares against a masked magic value.  This
 * avoids a full KCipher-2 initialization for non-matching candidates.
 *
 * @param head          First 8+ bytes of the encrypted header.
 * @param file_idx      Batch-local file index (stored alongside the pattern).
 * @param[out] h_masks  Appended with the comparison mask.
 * @param[out] h_values Appended with the expected masked value.
 * @param[out] h_file_idx  Appended with file_idx.
 * @param ext           Lowercase original file extension.
 * @return              Validator hint bitmask for kcipher2_validate_cascade.
 */
inline unsigned int build_file_masks(const std::vector<uint8_t>& head, int file_idx,
                                     std::vector<uint64_t>& h_masks,
                                     std::vector<uint64_t>& h_values, std::vector<int>& h_file_idx,
                                     const std::string& ext) {
    if (head.size() < 8)
        return VHINT_ALL;
    uint64_t enc8 = 0;
    for (int i = 0; i < 8; ++i)
        enc8 = (enc8 << 8) | head[i];

    auto add = [&](uint64_t mask, uint64_t sig) {
        h_masks.push_back(mask);
        h_values.push_back((enc8 ^ sig) & mask);
        h_file_idx.push_back(file_idx);
    };

    unsigned int vhint = 0;

    if (ext == ".png") {
        add(0xFFFFFFFFFFFFFFFFULL, 0x89504E470D0A1A0AULL); // PNG magic
        vhint = VHINT_PNG;
    } else if (ext == ".pdf") {
        add(0xFFFFFFFFFF000000ULL, 0x255044462D000000ULL); // %PDF-
        vhint = VHINT_PDF;
    } else if (ext == ".jpg" || ext == ".jpeg") {
        add(0xFFFFFFFF00000000ULL, 0xFFD8FFE000000000ULL); // JFIF SOI + APP0
        vhint = VHINT_JPEG;
    } else if (ext == ".sqlite" || ext == ".sqlite3" || ext == ".db") {
        add(0xFFFFFFFFFFFFFFFFULL, 0x53514C6974652066ULL); // "SQLite f"
        vhint = VHINT_SQLITE;
    } else if (ext == ".zip" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx") {
        add(0xFFFFFFFF00000000ULL, 0x504B030400000000ULL); // PK\x03\x04
        vhint = VHINT_ZIP;
    } else if (ext == ".doc" || ext == ".xls" || ext == ".ppt" || ext == ".hwp") {
        add(0xFFFFFFFFFFFFFFFFULL, 0xD0CF11E0A1B11AE1ULL); // OLE2 compound
        vhint = VHINT_OLE;
    }

    return vhint;
}

/* ===========================================================================
 *  Mask-group sorting for binary-search quick-check
 * =========================================================================== */

/// Per-mask-group boundary descriptor for binary-search quick-check.
struct MaskGroupInfo {
    uint64_t mask; ///< The mask value shared by all entries in this group.
    int start;     ///< Start index into the sorted value/file_index arrays.
    int count;     ///< Number of entries in this group.
};

/**
 * @brief Sort mask/value/file_index arrays by mask group, then by value.
 *
 * Reorders the three parallel arrays so that entries with the same mask
 * are contiguous and sorted by value (ascending) for binary search.
 * Populates @p groups with per-group boundaries.
 *
 * @param[in,out] h_masks     Mask array (reordered in-place).
 * @param[in,out] h_values    Value array (reordered in-place).
 * @param[in,out] h_file_idx  File index array (reordered in-place).
 * @param[out]    groups       Group boundary descriptors (up to NUM_MASK_GROUPS).
 * @param[out]    n_groups     Number of distinct mask groups found.
 */
inline void sort_matches_by_mask_group(std::vector<uint64_t>& h_masks,
                                       std::vector<uint64_t>& h_values,
                                       std::vector<int>& h_file_idx,
                                       MaskGroupInfo groups[NUM_MASK_GROUPS], int& n_groups) {
    const int n = (int)h_masks.size();
    n_groups = 0;
    if (n == 0)
        return;

    // Build index array and sort: mask descending (wider masks first), value ascending.
    std::vector<int> idx(n);
    for (int i = 0; i < n; ++i)
        idx[i] = i;

    std::stable_sort(idx.begin(), idx.end(), [&](int a, int b) {
        if (h_masks[a] != h_masks[b])
            return h_masks[a] > h_masks[b]; // wider mask first
        return h_values[a] < h_values[b];   // value ascending
    });

    // Apply permutation
    std::vector<uint64_t> sorted_masks(n), sorted_values(n);
    std::vector<int> sorted_file_idx(n);
    for (int i = 0; i < n; ++i) {
        sorted_masks[i] = h_masks[idx[i]];
        sorted_values[i] = h_values[idx[i]];
        sorted_file_idx[i] = h_file_idx[idx[i]];
    }
    h_masks = std::move(sorted_masks);
    h_values = std::move(sorted_values);
    h_file_idx = std::move(sorted_file_idx);

    // Extract group boundaries
    int g_start = 0;
    for (int i = 1; i <= n; ++i) {
        if (i == n || h_masks[i] != h_masks[g_start]) {
            if (n_groups < NUM_MASK_GROUPS) {
                groups[n_groups].mask = h_masks[g_start];
                groups[n_groups].start = g_start;
                groups[n_groups].count = i - g_start;
                ++n_groups;
            }
            g_start = i;
        }
    }
}

/* ===========================================================================
 *  Per-file metadata builder
 * =========================================================================== */

/**
 * @brief Construct FileMeta entries from scanned files and timing calibration.
 *
 * For each file with a supported extension and a valid header, computes the
 * QPC search window [start_qpc, end_qpc] from mtime and the reference
 * QPC/FILETIME pair.  Also auto-detects the ChaCha8 known-plaintext
 * signature for Phase 3 eligibility.
 *
 * @param files            Sorted FileInfo vector (from collect_akira_heads_parallel).
 * @param head_by_path     Path-to-header map.
 * @param timing           QPC calibration parameters.
 * @param args             CLI arguments (for batch window size).
 * @param[out] file_metas  Populated with one FileMeta per supported file.
 * @param[out] original_exts  Parallel vector of lowercase original extensions.
 * @param[out] global_min_start  Smallest start_qpc across all file_metas.
 * @param[out] global_max_end    Largest end_qpc across all file_metas.
 */
inline void
prepare_file_metas(const std::vector<FileInfo>& files,
                   const std::unordered_map<std::string, std::vector<uint8_t>>& head_by_path,
                   const TimingParams& timing, const CLIArgs& args,
                   std::vector<FileMeta>& file_metas, std::vector<std::string>& original_exts,
                   uint64_t& global_min_start, uint64_t& global_max_end) {
    global_min_start = UINT64_MAX;
    global_max_end = 0;

    size_t head_miss = 0, ext_skip = 0;

    for (size_t file_index = 0; file_index < files.size(); ++file_index) {
        const auto& f = files[file_index];

        // Extract the original extension (before .akira)
        auto stem = f.path.stem();
        std::string ext_lc = stem.extension().u8string();
        std::transform(ext_lc.begin(), ext_lc.end(), ext_lc.begin(), ::tolower);

        if (SUPPORTED_EXTENSIONS.find(ext_lc) == SUPPORTED_EXTENSIONS.end()) {
            ext_skip++;
            continue;
        }

        // Validate file integrity: minimum size and readable
        if (f.size <= AKIRA_FOOTER_SIZE) {
            LOG_WARN("SCAN", "Skipping too-small file: " << f.path.filename());
            continue;
        }

        // Find this file's header in the lookup map
        auto it = head_by_path.find(f.path.u8string());
        if (it == head_by_path.end() || it->second.empty()) {
            head_miss++;
            continue;
        }

        FileMeta file_meta;
        file_meta.orig_idx = file_index;

        // Convert mtime to a QPC estimate via linear interpolation
        int64_t ft_delta_100ns = (int64_t)f.mtime - (int64_t)timing.ref_ft;
        int64_t qpc_delta_ticks = ft_delta_100ns * (int64_t)timing.qpf / 10'000'000LL;
        int64_t file_ref_qpc = (int64_t)timing.ref_qpc + qpc_delta_ticks;
        uint64_t file_ref_qpc_ns =
            (file_ref_qpc > 0) ? (uint64_t)file_ref_qpc * timing.seed_scale_ns : 0ULL;

        // Forward margin: 2% of max_batch_window_ns to account for
        // mtime vs. QPC-call timing jitter.
        const uint64_t fwd_margin = args.max_batch_window_ns / 50;
        file_meta.end_qpc = file_ref_qpc_ns + fwd_margin;
        file_meta.start_qpc = (file_ref_qpc_ns > args.max_batch_window_ns)
                                  ? (file_ref_qpc_ns - args.max_batch_window_ns)
                                  : 0ULL;

        global_min_start = std::min(global_min_start, file_meta.start_qpc);
        global_max_end = std::max(global_max_end, file_meta.end_qpc);

        file_meta.head = it->second;
        file_meta.head_len = (int)std::min(it->second.size(), (size_t)HEAD_MAX);

        // Auto-detect ChaCha8 known plaintext for Phase 3
        lookup_chacha8_signature(ext_lc, file_meta.chacha8_signature, file_meta.chacha8_file_offset,
                                 f.type, f.size, args.test_mode);

        original_exts.push_back(ext_lc);
        file_metas.push_back(std::move(file_meta));
    }

    LOG_INFO("SCAN", files.size() << " total .akira files | " << file_metas.size()
                                  << " supported extensions | " << ext_skip
                                  << " skipped (unsupported ext)");

    if (head_miss > 0 || ext_skip > 0) {
        LOG_WARN("SCAN", head_miss << " files skipped (unreadable header), " << ext_skip
                                   << " skipped (unsupported extension)");
    }
    if (!args.test_mode) {
        int cc8_eligible = 0;
        for (const auto& fm : file_metas)
            if (fm.chacha8_signature.empty()) ++cc8_eligible;
        if (cc8_eligible > 0)
            LOG_WARN("SCAN", "ChaCha8 verification disabled (use --test for known-plaintext mode)");
    }
}

/* ===========================================================================
 *  Extension breakdown diagnostic
 * =========================================================================== */

/**
 * @brief Log a count of files per original extension for diagnostics.
 *
 * @param original_exts  Per-FileMeta original extension vector.
 * @param nfiles_total   Number of files that passed filtering.
 */
inline void log_extension_breakdown(const std::vector<std::string>& original_exts,
                                    int nfiles_total) {
    std::map<std::string, int> ext_counts;
    for (int file_index = 0; file_index < nfiles_total; ++file_index)
        ext_counts[original_exts[file_index]]++;
    LOG_INFO("SIGS", "Extension breakdown:");
    for (auto& [e, c] : ext_counts)
        LOG_INFO("SIGS", "  " << e << ": " << c);
}
