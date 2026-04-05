// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file constants.h
 * @brief Global constants, data structures, and file-type classification
 *        for the Akira ransomware decryptor.
 *
 * Centralizes all magic numbers as named constants, encryption mode labels,
 * file extension lists (for determining encryption type), and CUDA kernel
 * configuration parameters. This file is pure data — no logic beyond the
 * trivial enc_mode_str() helper.
 *
 * Reference: Akira ransomware encryption scheme analysis —
 *   encryption type is determined by file extension and size, per the
 *   ransomware binary's own classification logic.
 *
 */

#pragma once

/// Tool version string displayed by --version.
constexpr const char* AKIRA_DECRYPTOR_VERSION = "1.0.0";

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <cuda_runtime.h>

namespace fs = std::filesystem;

/* ===========================================================================
 *  Banner
 * =========================================================================== */

constexpr const char* AKIRA_DECRYPTOR_BANNER = R"(
=======================================================================================================================================
=======================================================================================================================================

    ###    ##    ## #### ########     ###       ########  ########  ######  ########  ##    ## ########  ########  #######  ########
   ## ##   ##   ##   ##  ##     ##   ## ##      ##     ## ##       ##    ## ##     ##  ##  ##  ##     ##    ##    ##     ## ##     ##
  ##   ##  ##  ##    ##  ##     ##  ##   ##     ##     ## ##       ##       ##     ##   ####   ##     ##    ##    ##     ## ##     ##
 ##     ## #####     ##  ########  ##     ##    ##     ## ######   ##       ########     ##    ########     ##    ##     ## ########
 ######### ##  ##    ##  ##   ##   #########    ##     ## ##       ##       ##   ##      ##    ##           ##    ##     ## ##   ##
 ##     ## ##   ##   ##  ##    ##  ##     ##    ##     ## ##       ##    ## ##    ##     ##    ##           ##    ##     ## ##    ##
 ##     ## ##    ## #### ##     ## ##     ##    ########  ########  ######  ##     ##    ##    ##           ##     #######  ##     ##

=======================================================================================================================================
=======================================================================================================================================
)";

/* ===========================================================================
 *  QPC / Seed search parameters
 * =========================================================================== */

/// Fallback when QPF is unknown; real value computed at runtime as 1e9/QPF.
constexpr uint64_t DEFAULT_SEED_SCALE_NS = 100ULL;

/// Must equal SEED_SCALE_NS — kept as a separate symbol for clarity in brute-force kernels.
constexpr uint64_t DEFAULT_STEP = 100ULL;

/// Minimum Yarrow inter-call gap (0 = no lower bound).
constexpr uint64_t MIN_OFFSET = 0ULL;

/// Maximum Yarrow inter-call gap (~1 s at QPF=10MHz).
constexpr uint64_t MAX_OFFSET = 10'000'000ULL;

/// Maximum qpc3-to-qpc2 distance for Phase 3 ChaCha8 seed search (ns).
/// Independent of --max-offset; covers the inter-cipher gap between
/// the KCipher-2 key seed and the ChaCha8 IV seed.
/// 500 ms covers >P99 of the measured distribution (hook analysis: max 526 ms).
constexpr uint64_t MAX_QPC2_DISTANCE = 500'000'000ULL;

/// Per-file lookback window in nanoseconds (1 second default).
constexpr uint64_t MAX_BATCH_WINDOW_NS = 1'000'000'000ULL;

/// Maximum bytes read from the first block of an encrypted file for signature matching.
constexpr size_t HEAD_MAX = 16;

/* ===========================================================================
 *  Akira encryption geometry
 * =========================================================================== */

/// 0xFFFF bytes per encryption block — the ransomware processes files
/// in fixed-size blocks of this length.
constexpr uint64_t AKIRA_BLOCK_SIZE = 65535ULL;

/// Akira appends a 512-byte footer containing the encrypted symmetric key.
constexpr size_t AKIRA_FOOTER_SIZE = 512;

/// Files >= 2 MB use partial encryption (only specific regions encrypted).
constexpr uint64_t PARTIAL_ENCRYPTION_SIZE_THRESHOLD = 2'000'000ULL;

/* ===========================================================================
 *  Yarrow-256 PRNG
 *
 *  Reference: J. Kelsey, B. Schneier, N. Ferguson, "Yarrow-160: Notes on
 *  the Design and Analysis of the Yarrow Cryptographic Pseudorandom Number
 *  Generator", SAC 1999. Akira uses a 256-bit variant with 1500 iterate rounds.
 * =========================================================================== */

constexpr unsigned YARROW_ITERATE_ROUNDS = 1500;


/* ===========================================================================
 *  CUDA kernel configuration
 * =========================================================================== */

constexpr int CUDA_BLOCK_SIZE = 256;
constexpr int MAX_CUDA_GRID_DIM = 65535;

/* ===========================================================================
 *  Phase 2 (ChaCha8 verification) batch parameters
 * =========================================================================== */

/// Maximum encrypted files processed in a single Phase 2 kernel launch.
constexpr int MAX_BATCH_FILES = 1024;

/// Signature patterns per file (one magic-bytes check per supported extension).
constexpr int SIGS_PER_FILE = 1;

/// Shared memory capacity: MAX_BATCH_FILES * SIGS_PER_FILE.
constexpr int MAX_MATCH_SHARED = MAX_BATCH_FILES * SIGS_PER_FILE;

/// Number of distinct mask types used in quick-check binary search.
constexpr int NUM_MASK_GROUPS = 3;

/* ===========================================================================
 *  Phase 2 tail-block validation thresholds
 *
 *  Effective file size must exceed these minimums for the tail decryption
 *  check to be meaningful; otherwise the tail block overlaps the header
 *  and yields false positives.
 * =========================================================================== */

constexpr uint64_t FULL_ENC_MIN_EFF_SIZE = 0x1FFFEull;
constexpr uint64_t PARTIAL_ENC_MIN_EFF_SIZE = 0x1FFFFull * 10ull;
constexpr uint64_t HALF_ENC_MIN_EFF_SIZE = 0x1FFFEull * 2ull;
constexpr size_t TAIL_READ_BYTES = 16;

/// Tile size for Phase 2 ChaCha8 tiled execution (seeds per kernel launch).
constexpr uint64_t CHACHA8_TILE_SIZE = 2048ULL;

/* ===========================================================================
 *  Encryption type labels
 *
 *  Akira classifies each file into one of these modes based on extension
 *  and file size. The decryptor must replicate this classification exactly.
 * =========================================================================== */

constexpr uint8_t EXCLUDE_ENCRYPTION = 0;
constexpr uint8_t FULL_ENCRYPTION = 1;
constexpr uint8_t PARTIAL_ENCRYPTION = 2;
constexpr uint8_t HALF_ENCRYPTION = 3;

/**
 * @brief Return a human-readable label for an encryption type code.
 * @param type  One of FULL_ENCRYPTION, PARTIAL_ENCRYPTION, HALF_ENCRYPTION.
 * @return      Static string — "full", "partial", "half", or "unknown".
 */
static inline const char* enc_mode_str(uint8_t type) {
    switch (type) {
    case FULL_ENCRYPTION:
        return "full";
    case PARTIAL_ENCRYPTION:
        return "partial";
    case HALF_ENCRYPTION:
        return "half";
    default:
        return "unknown";
    }
}

/* ===========================================================================
 *  Compile-time tunables (overridable via -D flags)
 * =========================================================================== */

#ifndef QUICK_VERIFY_COUNT
#define QUICK_VERIFY_COUNT 4
#endif

#ifndef MAX_CONST_META
#define MAX_CONST_META 8192
#endif

/* ===========================================================================
 *  Data structures
 * =========================================================================== */

/// Per-file metadata collected during the initial filesystem scan.
struct FileInfo {
    uint8_t type;   ///< Encryption mode (FULL / PARTIAL / HALF).
    uint64_t mtime; ///< Last-write time in Windows FILETIME 100 ns ticks.
    uintmax_t size; ///< File size in bytes (including Akira footer).
    fs::path path;  ///< Absolute path to the .akira file.
};

/// First N plaintext-candidate bytes read from an encrypted file's header.
struct AkiraHead {
    fs::path path;             ///< Source file path.
    std::vector<uint8_t> head; ///< Up to HEAD_MAX bytes of ciphertext.
};

/// Parameters passed to the Phase 3 (ChaCha8 brute-force) kernel.
struct Phase2Params {
    unsigned long long batch_qpc_lo;       ///< Low bound of batch QPC search range.
    unsigned long long batch_qpc_hi;       ///< High bound of batch QPC search range.
    unsigned long long step;               ///< QPC alignment step (= SEED_SCALE_NS).
    unsigned long long max_offset;         ///< Max Yarrow inter-call gap.
    unsigned long long chacha8_stream_off; ///< ChaCha8 stream byte offset for counter calc.
    int signature_length;                  ///< Signature length in bytes.
};

/// GPU-resident copy of all file headers for signature matching.
struct HeadsGpu {
    uint8_t* device_heads = nullptr;   ///< Concatenated header bytes (device memory).
    size_t* device_offsets = nullptr;  ///< Per-file start offset into device_heads.
    uint8_t* device_lengths = nullptr; ///< Per-file header length.
    int nheads = 0;                    ///< Number of files with headers.
    size_t total_bytes = 0;            ///< Total bytes in device_heads.

    /**
     * @brief Free all device allocations and reset counters.
     */
    void release() {
        if (device_heads) {
            cudaFree(device_heads);
            device_heads = nullptr;
        }
        if (device_offsets) {
            cudaFree(device_offsets);
            device_offsets = nullptr;
        }
        if (device_lengths) {
            cudaFree(device_lengths);
            device_lengths = nullptr;
        }
        nheads = 0;
        total_bytes = 0;
    }
};

/* ===========================================================================
 *  File extension lists
 *
 *  Akira's binary classifies certain extensions as "full encryption" targets
 *  (typically database files) and VM disk images as "partial encryption".
 *  Every other .akira file defaults to half encryption.
 * =========================================================================== */

static const std::vector<std::string> FULL_ENCRYPT_EXT = {
    ".4dd",    ".4dl",    ".accdb",   ".accdc",    ".accde",      ".accdr",    ".accdt",
    ".accft",  ".adb",    ".ade",     ".adf",      ".adp",        ".arc",      ".ora",
    ".alf",    ".ask",    ".btr",     ".bdf",      ".cat",        ".cdb",      ".ckp",
    ".cma",    ".cpd",    ".dacpac",  ".dad",      ".dadiagrams", ".daschema", ".db",
    ".db-shm", ".db-wal", ".db3",     ".dbc",      ".dbf",        ".dbs",      ".dbt",
    ".dbv",    ".dbx",    ".dcb",     ".dct",      ".dcx",        ".ddl",      ".dlis",
    ".dp1",    ".dqy",    ".dsk",     ".dsn",      ".dtsx",       ".dxl",      ".eco",
    ".ecx",    ".edb",    ".epim",    ".exb",      ".fcd",        ".fdb",      ".fic",
    ".fmp",    ".fmp12",  ".fmpsl",   ".fol",      ".fp3",        ".fp4",      ".fp5",
    ".fp7",    ".fpt",    ".frm",     ".gdb",      ".grdb",       ".gwi",      ".hdb",
    ".his",    ".ib",     ".idb",     ".ihx",      ".itdb",       ".itw",      ".jet",
    ".jtx",    ".kdb",    ".kexi",    ".kexic",    ".kexis",      ".lgc",      ".lwx",
    ".maf",    ".maq",    ".mar",     ".mas",      ".mav",        ".mdb",      ".mdf",
    ".mpd",    ".mrg",    ".mud",     ".mwb",      ".myd",        ".ndf",      ".nnt",
    ".nrmlib", ".ns2",    ".ns3",     ".ns4",      ".nsf",        ".nv",       ".nv2",
    ".nwdb",   ".nyf",    ".odb",     ".oqy",      ".orx",        ".owc",      ".p96",
    ".p97",    ".pan",    ".pdb",     ".pdm",      ".pnz",        ".qry",      ".qvd",
    ".rbf",    ".rctd",   ".rod",     ".rodx",     ".rpd",        ".rsd",      ".sas7bdat",
    ".sbf",    ".scx",    ".sdb",     ".sdc",      ".sdf",        ".sis",      ".spq",
    ".sql",    ".sqlite", ".sqlite3", ".sqlitedb", ".te",         ".temx",     ".tmd",
    ".tps",    ".trc",    ".trm",     ".udb",      ".udl",        ".usr",      ".v12",
    ".vis",    ".vpd",    ".vvv",     ".wdb",      ".wmdb",       ".wrk",      ".xdb",
    ".xld",    ".xmlff",  ".abcddb",  ".abs",      ".abx",        ".accdw",    ".adn",
    ".db2",    ".fm5",    ".hjt",     ".icg",      ".icr",        ".lut",      ".maw",
    ".mdn",    ".mdt"};

static const std::vector<std::string> VM_ENCRYPT_EXT = {
    ".vdi",   ".vhd",    ".vmdk", ".pvm", ".vmem", ".vmsn", ".vmsd", ".nvram", ".vmx",  ".raw",
    ".qcow2", ".subvol", ".bin",  ".vsv", ".avhd", ".vmrs", ".vhdx", ".avdx",  ".vmcx", ".iso"};
