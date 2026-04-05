// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file decrypt_file_main.c
 * @brief Akira ransomware decryption tool -- CLI entry point.
 *
 * Parses command-line arguments, reads the encrypted file, initializes
 * KCipher-2 (and optionally ChaCha8) cipher contexts through the opaque
 * ADT interfaces, applies block-level decryption, and writes the output.
 *
 * All cryptographic logic lives in crypto/host/; this file contains only
 * argument parsing, file I/O, and mode dispatch.
 *
 * Usage:
 *   Step3_FileDecryptor --key <hex32> --iv <hex32> --input <path>
 *                     [--output <path>] [--mode full|half|partial]
 *                     [--chacha-key <hex32>] [--chacha-iv <hex16>]
 *                     [--footer-size <N>]
 *
 * Build (MSVC):
 *   cl /O2 /Fe:Step3_FileDecryptor.exe decrypt_file_main.c kcipher2.c chacha8.c decrypt_region.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../crypto/host/kcipher2.h"
#include "../crypto/host/chacha8.h"
#include "../crypto/host/decrypt_region.h"

/** @brief Default Akira footer size in bytes. */
#define DEFAULT_FOOTER_SIZE 512

/** @brief Box inner width for banner display. */
#define BOX_WIDTH 52

/** @brief Maximum file path length. */
#define MAX_PATH_BUFFER 4096

/** @brief Length of the ".akira" file extension. */
#define AKIRA_EXT_LEN 6

/* =========================================================================
 *  Banner / UI helpers
 * ========================================================================= */

/**
 * @brief Print the Step 3 banner box to stdout.
 */
static void print_banner(void) {
    printf("\n+");
    for (int i = 0; i < BOX_WIDTH + 2; i++)
        printf("=");
    printf("+\n");
    printf("|  %-*s  |\n", BOX_WIDTH - 4, "Step 3. Akira File Decryptor");
    printf("+");
    for (int i = 0; i < BOX_WIDTH + 2; i++)
        printf("=");
    printf("+\n\n");
}

/**
 * @brief Format a byte count with comma separators.
 *
 * @param buf       Output buffer (should be at least 32 bytes).
 * @param bufsize   Size of output buffer.
 * @param value     The number to format.
 */
static void format_bytes(char* buf, size_t bufsize, size_t value) {
    char raw[32];
    _snprintf(raw, sizeof(raw), "%zu", value);
    int len = (int)strlen(raw);
    int commas = (len - 1) / 3;
    int total = len + commas;
    if ((size_t)total >= bufsize) {
        _snprintf(buf, bufsize, "%zu", value);
        return;
    }
    buf[total] = '\0';
    int src = len - 1;
    int dst = total - 1;
    int cnt = 0;
    while (src >= 0) {
        buf[dst--] = raw[src--];
        cnt++;
        if (cnt % 3 == 0 && src >= 0) {
            buf[dst--] = ',';
        }
    }
}

/* =========================================================================
 *  Hex parsing
 * ========================================================================= */

/**
 * @brief Convert a single hex character to its 4-bit value.
 *
 * @param c  ASCII hex character ('0'-'9', 'a'-'f', 'A'-'F').
 * @return   Value 0..15, or -1 on invalid input.
 */
static int hex_char(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/**
 * @brief Decode a hex string into a byte array.
 *
 * @param hex           Hex string (must be exactly expected_len * 2 chars).
 * @param out           Output byte buffer.
 * @param expected_len  Number of bytes expected.
 * @return              0 on success, -1 on format error.
 */
static int hex_to_bytes(const char* hex, uint8_t* out, int expected_len) {
    int slen = (int)strlen(hex);
    if (slen != expected_len * 2)
        return -1;
    for (int i = 0; i < expected_len; i++) {
        int hi = hex_char(hex[i * 2]);
        int lo = hex_char(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* =========================================================================
 *  File I/O (supports >2 GB on MSVC via _fseeki64)
 * ========================================================================= */

/**
 * @brief Read an entire file into a heap-allocated buffer.
 *
 * @param path      File path to read.
 * @param[out] out_len  Receives the file size in bytes.
 * @return          Heap-allocated buffer (caller must free), or NULL on error.
 */
static uint8_t* read_file(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  [ERROR] Cannot open: %s\n", path);
        return NULL;
    }

#ifdef _MSC_VER
    _fseeki64(f, 0, SEEK_END);
    int64_t sz = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
#else
    fseek(f, 0, SEEK_END);
    int64_t sz = (int64_t)ftell(f);
    fseek(f, 0, SEEK_SET);
#endif

    if (sz <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t bytes_read = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (bytes_read != (size_t)sz) {
        fprintf(stderr, "  [ERROR] fread failed: expected %zu bytes, got %zu\n",
                (size_t)sz, bytes_read);
        free(buf);
        return NULL;
    }
    *out_len = (size_t)sz;
    return buf;
}

/**
 * @brief Write a byte buffer to a file.
 *
 * @param path  Output file path.
 * @param data  Data to write.
 * @param len   Number of bytes.
 * @return      0 on success, -1 on error.
 */
static int write_file(const char* path, const uint8_t* data, size_t len) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "  [ERROR] Cannot write: %s\n", path);
        return -1;
    }
    size_t written = fwrite(data, 1, len, f);
    if (written != len) {
        fprintf(stderr, "  [ERROR] Write failed: %zu/%zu bytes written to %s\n",
                written, len, path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* =========================================================================
 *  Usage
 * ========================================================================= */

/**
 * @brief Print usage information to stderr.
 */
static void print_usage(const char* prog) {
    fprintf(stderr,
            "Step 3. Akira File Decryption Tool\n\n"
            "Usage:\n"
            "  %s --key <hex32> --iv <hex32> --input <path>\n"
            "     [--output <path>] [--mode full|half|partial]\n"
            "     [--chacha-key <hex32>] [--chacha-iv <hex16>]\n"
            "     [--footer-size <N>]\n\n"
            "Arguments:\n"
            "  --key          128-bit KCipher-2 key (32 hex chars)\n"
            "  --iv           128-bit KCipher-2 IV  (32 hex chars)\n"
            "  --input        Path to encrypted .akira file\n"
            "  --output       Output path (default: strip .akira extension)\n"
            "  --mode         Encryption mode: full, half, or partial (default: full)\n"
            "  --chacha-key   128-bit ChaCha8 key (32 hex chars, for middle blocks)\n"
            "  --chacha-iv    64-bit ChaCha8 IV  (16 hex chars)\n"
            "  --footer-size  Footer size in bytes (default: 512)\n"
            "\n"
            "Workflow:\n"
            "  Step1_QPCEstimator -> Step2_SeedScanner -> SeedToKey -> Step3_FileDecryptor\n",
            prog);
}

/* =========================================================================
 *  Mode name helper
 * ========================================================================= */

/**
 * @brief Return a human-readable description for the encryption mode.
 */
static const char* mode_desc(const char* mode) {
    if (!strcmp(mode, "full"))
        return "full (100%%)";
    if (!strcmp(mode, "half"))
        return "half (first 50%%)";
    if (!strcmp(mode, "partial"))
        return "partial (4 regions, 40%%)";

    return mode;
}

/* =========================================================================
 *  main()
 * ========================================================================= */

/** @brief CLI entry point for Akira file decryption. */
#define FILE_DECRYPTOR_VERSION "1.0.0"

int main(int argc, char** argv) {
    if (argc >= 2 && (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-v"))) {
        printf("Step3_FileDecryptor %s\n", FILE_DECRYPTOR_VERSION);
        return 0;
    }

    const char* key_hex = NULL;
    const char* iv_hex = NULL;
    const char* input_path = NULL;
    const char* output_path = NULL;
    const char* mode = "full";
    const char* chacha_key_hex = NULL;
    const char* chacha_iv_hex = NULL;
    int footer_size = DEFAULT_FOOTER_SIZE;
    int force_overwrite = 0;

    /* -- Parse arguments ------------------------------------------------- */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc)
            key_hex = argv[++i];
        else if (!strcmp(argv[i], "--iv") && i + 1 < argc)
            iv_hex = argv[++i];
        else if (!strcmp(argv[i], "--input") && i + 1 < argc)
            input_path = argv[++i];
        else if (!strcmp(argv[i], "--output") && i + 1 < argc)
            output_path = argv[++i];
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc)
            mode = argv[++i];
        else if (!strcmp(argv[i], "--chacha-key") && i + 1 < argc)
            chacha_key_hex = argv[++i];
        else if (!strcmp(argv[i], "--chacha-iv") && i + 1 < argc)
            chacha_iv_hex = argv[++i];
        else if (!strcmp(argv[i], "--footer-size") && i + 1 < argc) {
            char* endptr;
            long val = strtol(argv[++i], &endptr, 10);
            if (*endptr || val < 0 || val > 1000000) {
                fprintf(stderr, "  [ERROR] Invalid --footer-size value\n");
                return 1;
            }
            footer_size = (int)val;
        } else if (!strcmp(argv[i], "--force") || !strcmp(argv[i], "-f")) {
            force_overwrite = 1;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!key_hex || !iv_hex || !input_path) {
        print_usage(argv[0]);
        return 1;
    }
    if (strlen(key_hex) != 32 || strlen(iv_hex) != 32) {
        fprintf(stderr, "  [ERROR] key and iv must be 32 hex chars (128-bit)\n");
        return 1;
    }

    /* -- Banner ---------------------------------------------------------- */
    print_banner();

    /* -- Auto-generate output path: strip .akira extension --------------- */
    char auto_path[MAX_PATH_BUFFER] = {0};
    if (!output_path) {
        size_t ilen = strlen(input_path);
        if (ilen > AKIRA_EXT_LEN &&
            !strcmp(input_path + ilen - AKIRA_EXT_LEN, ".akira")) {
            memcpy(auto_path, input_path, ilen - AKIRA_EXT_LEN);
            auto_path[ilen - AKIRA_EXT_LEN] = 0;
        } else {
            /* ".decrypted" suffix = 10 chars + NUL */
            if (strlen(input_path) + 11 >= sizeof(auto_path)) {
                fprintf(stderr, "  [ERROR] Input path too long (max %zu chars)\n",
                        sizeof(auto_path) - 11);
                return 1;
            }
            _snprintf(auto_path, sizeof(auto_path), "%s.decrypted", input_path);
        }
        output_path = auto_path;
    }

    /* -- Read encrypted file --------------------------------------------- */
    size_t raw_len = 0;
    uint8_t* raw = read_file(input_path, &raw_len);
    if (!raw)
        return 1;

    if (raw_len <= (size_t)footer_size) {
        fprintf(stderr, "  [ERROR] File size (%zu) <= footer size (%d)\n", raw_len, footer_size);
        free(raw);
        return 1;
    }

    size_t body_len = raw_len - (size_t)footer_size;
    uint8_t* body = raw; /* in-place XOR */

    /* -- Print file info ------------------------------------------------- */
    {
        /* Extract filename from path */
        const char* fname = input_path;
        const char* p;
        for (p = input_path; *p; p++) {
            if (*p == '/' || *p == '\\')
                fname = p + 1;
        }

        char raw_fmt[32];
        format_bytes(raw_fmt, sizeof(raw_fmt), raw_len);

        printf("  Input:  %s (%s bytes)\n", fname, raw_fmt);
        printf("  Mode:   %s\n", mode_desc(mode));

        /* KC2 status */
        printf("  KC2:   \xe2\x9c\x93 (key/IV configured)\n");

        /* CC8 status */
        if (chacha_key_hex && chacha_iv_hex)
            printf("  CC8:   \xe2\x9c\x93 (key/IV configured)\n");
        else
            printf("  CC8:   \xe2\x9c\x97 (not used)\n");

        printf("\n");
    }

    /* -- Initialize KCipher-2 -------------------------------------------- */
    KCipher2* kcipher2 = kcipher2_create(key_hex, iv_hex);
    if (!kcipher2) {
        fprintf(stderr, "  [ERROR] Failed to create KCipher-2 context\n");
        free(raw);
        return 1;
    }

    /* -- Initialize ChaCha8 (optional) ----------------------------------- */
    Chacha8* chacha8 = NULL;
    if (chacha_key_hex && chacha_iv_hex) {
        if (strlen(chacha_key_hex) != 32 || strlen(chacha_iv_hex) != 16) {
            fprintf(stderr, "  [ERROR] chacha-key must be 32 hex, chacha-iv must be 16 hex\n");
            kcipher2_destroy(kcipher2);
            free(raw);
            return 1;
        }
        uint8_t ck[16], ci[8];
        hex_to_bytes(chacha_key_hex, ck, 16);
        hex_to_bytes(chacha_iv_hex, ci, 8);
        chacha8 = chacha8_create(ck, ci);
        if (!chacha8) {
            fprintf(stderr, "  [ERROR] Failed to create ChaCha8 context\n");
            kcipher2_destroy(kcipher2);
            free(raw);
            return 1;
        }
    }

    /* -- Mode dispatch --------------------------------------------------- */
    size_t decrypted_bytes = 0;

    printf("  Decrypting...");
    fflush(stdout);

    if (!strcmp(mode, "full")) {
        /* Always use block-level decrypt (KC2 first/last, CC8 middle).
         * Even without CC8 keys, KC2 must only XOR first/last blocks. */
        decrypt_region_blocks(kcipher2, chacha8, body, body_len);
        decrypted_bytes = body_len;

    } else if (!strcmp(mode, "half")) {
        size_t half = body_len / 2;
        decrypt_region_blocks(kcipher2, chacha8, body, half);
        decrypted_bytes = half;

    } else if (!strcmp(mode, "partial")) {
        /* Akira partial mode: 4 regions with integer-arithmetic offsets.
         * Must match Akira's exact calculation to avoid 1-byte misalignment:
         *   region_size = file_size / 10
         *   gap = (file_size - region_size * 4) / 5
         *   offsets = [0, gap, gap*2, gap*3]               */
        size_t chunk = body_len / 10;
        size_t gap = (body_len - chunk * 4) / 5;
        size_t offsets[4], lengths[4];

        for (int j = 0; j < 4; j++) {
            offsets[j] = gap * (size_t)j;
            size_t end = offsets[j] + chunk;
            if (end > body_len)
                end = body_len;
            lengths[j] = end - offsets[j];
            decrypted_bytes += lengths[j];
        }

        /* Neither KC2 nor CC8 advance through inter-region gaps.
         * Akira processes each region independently — cipher state
         * carries over from one region to the next without consuming
         * keystream for the unencrypted gap bytes between them. */
        for (int j = 0; j < 4; j++) {
            decrypt_region_blocks(kcipher2, chacha8, body + offsets[j], lengths[j]);
        }

    } else {
        fprintf(stderr, "\n  [ERROR] Unknown mode: %s\n", mode);
        chacha8_destroy(chacha8);
        kcipher2_destroy(kcipher2);
        free(raw);
        return 1;
    }

    /* Print completion with byte counts */
    {
        char dec_fmt[32], body_fmt[32];
        format_bytes(dec_fmt, sizeof(dec_fmt), decrypted_bytes);
        format_bytes(body_fmt, sizeof(body_fmt), body_len);
        printf(" complete (%s / %s bytes)\n\n", dec_fmt, body_fmt);
    }

    /* -- Write output (body only, no footer) ----------------------------- */
    {
        FILE* existing = fopen(output_path, "rb");
        if (existing) {
            fclose(existing);
            if (!force_overwrite) {
                fprintf(stderr, "  [ERROR] Output file already exists: %s\n", output_path);
                fprintf(stderr, "          Use --force to overwrite.\n");
                chacha8_destroy(chacha8);
                kcipher2_destroy(kcipher2);
                free(raw);
                return 1;
            }
        }
    }
    if (write_file(output_path, body, body_len) != 0) {
        chacha8_destroy(chacha8);
        kcipher2_destroy(kcipher2);
        free(raw);
        return 1;
    }

    /* Extract output filename */
    {
        const char* outname = output_path;
        const char* p;
        for (p = output_path; *p; p++) {
            if (*p == '/' || *p == '\\')
                outname = p + 1;
        }
        printf("  Output: %s\n", outname);
        printf("  Result: success \xe2\x9c\x93\n");
        printf("\n");
    }

    /* -- Cleanup --------------------------------------------------------- */
    chacha8_destroy(chacha8);
    kcipher2_destroy(kcipher2);
    free(raw);
    return 0;
}
