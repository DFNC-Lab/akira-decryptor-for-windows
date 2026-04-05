// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file seed_to_key_main.c
 * @brief Generate cryptographic keys from QPC seeds using Yarrow-256 CSPRNG.
 *
 * Takes a QPC (QueryPerformanceCounter) timestamp as seed, feeds it into
 * Nettle's Yarrow-256 PRNG, and outputs the derived key bytes.  Supports
 * both single-seed and batch (--range) modes.
 *
 * This tool replicates the key derivation path used by Akira ransomware:
 * the decimal string representation of the QPC value is seeded into
 * Yarrow-256, then the requested number of random bytes are drawn.
 *
 * Usage:
 *   SeedToKey <qpc_seed> [size] [--format hex|python|raw]
 *   SeedToKey --range <hi> <lo> <step> [size] [--format raw] [--output path]
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <io.h>

#include <nettle/yarrow.h>

/* =========================================================================
 *  Yarrow-256 key derivation
 *
 *  Akira converts the QPC value to a decimal string, seeds Yarrow-256
 *  with that string, then draws `size` random bytes as the key material.
 * ========================================================================= */

/**
 * @brief Derive key material from a single QPC seed via Yarrow-256.
 *
 * @param qpc_seed  QPC timestamp (decimal seed value).
 * @param buffer    Output buffer for derived key bytes.
 * @param size      Number of bytes to generate.
 */
static void derive_key_from_qpc(uint64_t qpc_seed, char* buffer, int size) {
    struct yarrow256_ctx ctx;
    yarrow256_init(&ctx, 0, NULL);

    char seed_str[32];
    _snprintf(seed_str, sizeof(seed_str), "%llu", (unsigned long long)qpc_seed);

    yarrow256_seed(&ctx, (unsigned)strlen(seed_str), (const uint8_t*)seed_str);
    yarrow256_random(&ctx, (unsigned)size, (uint8_t*)buffer);
}

/* =========================================================================
 *  CLI usage
 * ========================================================================= */

/**
 * @brief Print usage information to stderr.
 *
 * @param prog  Program name (argv[0]).
 */
static void print_usage(const char* prog) {
    fprintf(stderr,
            "SeedToKey - Key Derivation Tool\n\n"
            "Usage:\n"
            "  %s <qpc_seed> [size] [--format hex|python|raw]\n"
            "  %s --range <hi> <lo> <step> [size] [--format raw] [--output path]\n"
            "\n"
            "Arguments:\n"
            "  <qpc_seed>    QPC timestamp seed (decimal uint64)\n"
            "  [size]        Key size in bytes (default: 16, max: 4096)\n"
            "  --format fmt  Output format: hex (default), python, raw\n"
            "  --range       Batch mode: generate keys for seeds [hi, hi-step, ..., lo]\n"
            "  --output path Write batch output to file instead of stdout\n"
            "\n"
            "Examples:\n"
            "  %s 300079396800 16\n"
            "  %s --range 358857908500 358847908500 100 16 --format raw --output keys.bin\n"
            "\n"
            "Workflow:\n"
            "  Step1_QPCEstimator -> Step2_SeedScanner -> SeedToKey -> Step3_FileDecryptor\n",
            prog, prog, prog, prog);
}

/* =========================================================================
 *  Range (batch) mode
 * ========================================================================= */

/**
 * @brief Execute batch key generation over a range of QPC seeds.
 *
 * Iterates from @p hi down to @p lo (inclusive) in decrements of @p step,
 * generating Yarrow-256 derived keys for each seed value.
 *
 * @param argc  Argument count (from main).
 * @param argv  Argument vector (from main).
 * @return      0 on success, 1 on error.
 */
static int run_range_mode(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "[ERROR] --range requires <hi> <lo> <step>\n");
        return 1;
    }

    uint64_t hi = strtoull(argv[2], NULL, 10);
    uint64_t lo = strtoull(argv[3], NULL, 10);
    uint64_t step = strtoull(argv[4], NULL, 10);
    int size = 16;
    const char* format = "raw";
    const char* outpath = NULL;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc)
            format = argv[++i];
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
            outpath = argv[++i];
        else {
            char* endptr;
            long val = strtol(argv[i], &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > 4096) {
                fprintf(stderr, "[ERROR] invalid size '%s'\n", argv[i]);
                return 1;
            }
            size = (int)val;
        }
    }

    if (step == 0) {
        fprintf(stderr, "[ERROR] step must be > 0\n");
        return 1;
    }
    if (hi < lo) {
        fprintf(stderr, "[ERROR] hi must be >= lo\n");
        return 1;
    }
    if (size <= 0 || size > 4096) {
        fprintf(stderr, "[ERROR] size out of range (1..4096)\n");
        return 1;
    }

    uint64_t count = (hi - lo) / step + 1;
    char* buf = (char*)malloc((size_t)size);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    FILE* out = stdout;
    if (outpath) {
        out = fopen(outpath, "wb");
        if (!out) {
            perror(outpath);
            free(buf);
            return 1;
        }
    } else if (strcmp(format, "raw") == 0) {
        _setmode(_fileno(stdout), _O_BINARY);
    }

    fprintf(stderr, "[range] seeds: %llu, hi=%llu, lo=%llu, step=%llu, size=%d\n",
            (unsigned long long)count, (unsigned long long)hi, (unsigned long long)lo,
            (unsigned long long)step, size);

    for (uint64_t i = 0; i < count; i++) {
        uint64_t seed = hi - i * step;
        derive_key_from_qpc(seed, buf, size);

        if (strcmp(format, "raw") == 0) {
            size_t written = fwrite(buf, 1, (size_t)size, out);
            if (written != (size_t)size) {
                fprintf(stderr, "[ERROR] Write failed: %zu/%d bytes\n", written, size);
                free(buf);
                if (outpath) fclose(out);
                return 1;
            }
        } else {
            for (int j = 0; j < size; j++)
                fprintf(out, "%02X", (unsigned char)buf[j]);
            fprintf(out, "\n");
        }

        if ((i + 1) % 10000 == 0)
            fprintf(stderr, "[range] %llu / %llu done\n", (unsigned long long)(i + 1),
                    (unsigned long long)count);
    }

    fprintf(stderr, "[range] complete: %llu seeds\n", (unsigned long long)count);
    if (outpath)
        fclose(out);
    free(buf);
    return 0;
}

/* =========================================================================
 *  Single-seed mode (main)
 * ========================================================================= */

/** @brief CLI entry point. */
#define SEED_TO_KEY_VERSION "1.0.0"

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        printf("SeedToKey %s\n", SEED_TO_KEY_VERSION);
        return 0;
    }

    /* Dispatch to range mode if requested */
    if (strcmp(argv[1], "--range") == 0) {
        return run_range_mode(argc, argv);
    }

    /* Parse QPC seed */
    char* end = NULL;
    uint64_t qpc_seed = strtoull(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0') {
        fprintf(stderr, "[ERROR] Invalid QPC seed '%s' (expected decimal uint64)\n", argv[1]);
        return 1;
    }

    /* Parse optional size and format */
    int size = 16;
    const char* format = "hex";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            char* endptr;
            long val = strtol(argv[i], &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > 4096) {
                fprintf(stderr, "[ERROR] invalid size '%s'\n", argv[i]);
                return 1;
            }
            size = (int)val;
        }
    }

    if (size <= 0 || size > 4096) {
        fprintf(stderr, "[ERROR] Invalid size %d (must be 1..4096)\n", size);
        return 1;
    }

    /* Generate key */
    char* buf = (char*)malloc((size_t)size);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    derive_key_from_qpc(qpc_seed, buf, size);

    /* Output in requested format */
    if (strcmp(format, "python") == 0) {
        printf("bytes.fromhex(\"");
        for (int i = 0; i < size; i++) {
            printf("%02X", (unsigned char)buf[i]);
            if (i != size - 1)
                printf(" ");
        }
        printf("\")\n");
    } else if (strcmp(format, "raw") == 0) {
        _setmode(_fileno(stdout), _O_BINARY);
        fwrite(buf, 1, (size_t)size, stdout);
    } else {
        /* Default: hex — user-friendly single-mode output */
        printf("\n");
        printf("  QPC Seed:  %llu\n", (unsigned long long)qpc_seed);
        printf("  Key (hex): ");
        for (int i = 0; i < size; i++)
            printf("%02X", (unsigned char)buf[i]);
        printf("\n\n");
    }

    free(buf);
    return 0;
}
