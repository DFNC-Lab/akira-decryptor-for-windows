// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file signature_match.cuh
 * @brief Device-side file-signature validators for KCipher-2 keystream matching.
 *
 * Each validator decrypts the first N bytes of an encrypted file header using
 * KCipher-2 keystream and checks whether the plaintext matches a known file
 * format signature (magic bytes).  Validators are branchless where possible
 * to avoid warp divergence on the GPU.
 *
 * Supported formats:
 *   - PNG  (89 50 4E 47 0D 0A 1A 0A ... "IHDR")
 *   - PDF  (%PDF-1.x)
 *   - JPEG (FF D8 FF Ex + optional JFIF/Exif)
 *   - ZIP  (PK\x03\x04 + version check)
 *   - SQLite ("SQLite f")
 *   - OLE Compound Document (D0 CF 11 E0 A1 B1 1A E1)
 *
 * Reference: Each signature follows the respective file format specification;
 *            see individual validator comments for byte-level details.
 *
 */
#pragma once

#include "crypto/device/kcipher2.cuh"

/* =========================================================================
 *  Low-level helpers
 * ========================================================================= */

/**
 * @brief Read-only byte load using texture cache on SM >= 3.5.
 *
 * Falls back to a plain dereference on older architectures.
 *
 * @param p  Device pointer to a single byte.
 * @return   The byte value at *p.
 */
__device__ __forceinline__ uint8_t read_only_byte(const uint8_t* p) {
#if __CUDA_ARCH__ >= 350
    return __ldg(p);
#else
    return *p;
#endif
}

/**
 * @brief Byte-swap a 32-bit word (little-endian <-> big-endian).
 *
 * @param x  Input word.
 * @return   Byte-reversed word.
 */
__device__ __forceinline__ uint32_t byte_swap32(uint32_t x) {
    return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) | ((x & 0x00FF0000u) >> 8) |
           ((x & 0xFF000000u) >> 24);
}

/* =========================================================================
 *  KCipher-2 keystream extraction helper
 *
 *  Every validator follows the same pattern: call kcipher2_stream() to
 *  obtain 8 keystream bytes (ZH || ZL), XOR with ciphertext, and compare
 *  against the expected magic bytes.  The macro below is intentionally
 *  NOT used -- the pattern is spelled out for readability.
 * ========================================================================= */

/* =========================================================================
 *  PNG validator
 *
 *  PNG signature: 89 50 4E 47 0D 0A 1A 0A  (8 bytes)
 *  Optional:      bytes 12-15 must be "IHDR" if 16 bytes are available.
 * ========================================================================= */

/**
 * @brief Validate a PNG file signature against KCipher-2 decrypted header.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match the PNG signature.
 */
__device__ __forceinline__ bool
kcipher2_validate_png(KCipher2State& state, const uint8_t* __restrict__ base, size_t off, int len) {
    if (len < 8)
        return false;

    const int need = (len >= 16) ? 16 : 8;
    int done = 0;
    bool is_valid = true;

    while (done < need) {
        uint32_t ZH, ZL;
        kcipher2_stream(state, ZH, ZL);
        uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                         (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};
        const int take = ((need - done) < 8) ? (need - done) : 8;

#pragma unroll
        for (int j = 0; j < take; ++j) {
            const int idx = done + j;
            const uint8_t c = read_only_byte(base + off + idx);
            const uint8_t p = (uint8_t)(c ^ ks[j]);

            // PNG 8-byte magic: 89 50 4E 47 0D 0A 1A 0A
            if (idx == 0 && p != 0x89)
                is_valid = false;
            if (idx == 1 && p != 0x50)
                is_valid = false;
            if (idx == 2 && p != 0x4E)
                is_valid = false;
            if (idx == 3 && p != 0x47)
                is_valid = false;
            if (idx == 4 && p != 0x0D)
                is_valid = false;
            if (idx == 5 && p != 0x0A)
                is_valid = false;
            if (idx == 6 && p != 0x1A)
                is_valid = false;
            if (idx == 7 && p != 0x0A)
                is_valid = false;

            // IHDR chunk type at bytes 12-15 (only checked if 16 bytes available)
            if (need >= 16) {
                if (idx == 12 && p != 'I')
                    is_valid = false;
                if (idx == 13 && p != 'H')
                    is_valid = false;
                if (idx == 14 && p != 'D')
                    is_valid = false;
                if (idx == 15 && p != 'R')
                    is_valid = false;
            }
        }
        done += take;
        kcipher2_next_state(state, 1);
    }

    return is_valid;
}

/* =========================================================================
 *  PDF validator
 *
 *  PDF signature: "%PDF-" (5 bytes), optionally followed by "1." (7 bytes).
 * ========================================================================= */

/**
 * @brief Validate a PDF file signature against KCipher-2 decrypted header.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match the PDF signature.
 */
__device__ __forceinline__ bool
kcipher2_validate_pdf(KCipher2State& state, const uint8_t* __restrict__ base, size_t off, int len) {
    if (len < 5)
        return false;

    const int need = (len >= 8) ? 8 : 5;
    int done = 0;
    bool is_valid = true;

    while (done < need) {
        uint32_t ZH, ZL;
        kcipher2_stream(state, ZH, ZL);
        uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                         (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};
        const int take = ((need - done) < 8) ? (need - done) : 8;

#pragma unroll
        for (int j = 0; j < take; ++j) {
            const int idx = done + j;
            const uint8_t c = read_only_byte(base + off + idx);
            const uint8_t p = (uint8_t)(c ^ ks[j]);

            if (idx == 0 && p != '%')
                is_valid = false;
            if (idx == 1 && p != 'P')
                is_valid = false;
            if (idx == 2 && p != 'D')
                is_valid = false;
            if (idx == 3 && p != 'F')
                is_valid = false;
            if (idx == 4 && p != '-')
                is_valid = false;

            if (need >= 8) {
                if (idx == 5 && p != '1')
                    is_valid = false;
                if (idx == 6 && p != '.')
                    is_valid = false;
            }
        }
        done += take;
        kcipher2_next_state(state, 1);
    }

    return is_valid;
}

/* =========================================================================
 *  JPEG validator
 *
 *  JPEG signature: FF D8 FF Ex (4 bytes basic).
 *  Extended check: "JFIF\0" or "Exif\0" at bytes 6-10 when available.
 * ========================================================================= */

/**
 * @brief Validate a JPEG file signature against KCipher-2 decrypted header.
 *
 * Checks the SOI+APP0/APP1 marker (FF D8 FF Ex) and, when enough bytes
 * are available, verifies that the JFIF or Exif identifier string follows.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match the JPEG signature.
 */
__device__ __forceinline__ bool kcipher2_validate_jpeg(KCipher2State& state,
                                                       const uint8_t* __restrict__ base, size_t off,
                                                       int len) {
    if (len < 4)
        return false;

    const int need = (len >= 11) ? 11 : len;
    int done = 0;

    bool is_basic_ok = true;
    bool is_jfif_ok = true;
    bool is_exif_ok = true;

    while (done < need) {
        uint32_t ZH, ZL;
        kcipher2_stream(state, ZH, ZL);
        uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                         (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};
        const int take = ((need - done) < 8) ? (need - done) : 8;

#pragma unroll
        for (int j = 0; j < take; ++j) {
            const int idx = done + j;
            const uint8_t c = read_only_byte(base + off + idx);
            const uint8_t p = (uint8_t)(c ^ ks[j]);

            // SOI + APP marker: FF D8 FF Ex
            if (idx == 0 && p != 0xFF)
                is_basic_ok = false;
            if (idx == 1 && p != 0xD8)
                is_basic_ok = false;
            if (idx == 2 && p != 0xFF)
                is_basic_ok = false;
            if (idx == 3 && ((p & 0xF0) != 0xE0))
                is_basic_ok = false;

            // Extended: "JFIF\0" or "Exif\0" at bytes 6-10
            if (idx == 6 && !(p == 'J' || p == 'E')) {
                is_jfif_ok = false;
                is_exif_ok = false;
            }
            if (idx == 7) {
                if (p != 'F')
                    is_jfif_ok = false;
                if (p != 'x')
                    is_exif_ok = false;
            }
            if (idx == 8) {
                if (p != 'I')
                    is_jfif_ok = false;
                if (p != 'i')
                    is_exif_ok = false;
            }
            if (idx == 9) {
                if (p != 'F')
                    is_jfif_ok = false;
                if (p != 'f')
                    is_exif_ok = false;
            }
            if (idx == 10 && p != 0x00) {
                is_jfif_ok = false;
                is_exif_ok = false;
            }
        }
        done += take;
        kcipher2_next_state(state, 1);
    }

    if (!is_basic_ok)
        return false;
    if (len >= 11 && !(is_jfif_ok || is_exif_ok))
        return false;

    return true;
}

/* =========================================================================
 *  ZIP validator
 *
 *  ZIP signature: PK\x03\x04 (4 bytes) + version check (byte 4 <= 63).
 * ========================================================================= */

/**
 * @brief Validate a ZIP file signature against KCipher-2 decrypted header.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match the ZIP local-file header.
 */
__device__ __forceinline__ bool
kcipher2_validate_zip(KCipher2State& state, const uint8_t* __restrict__ base, size_t off, int len) {
    if (len < 4)
        return false;

    const int need = (len >= 8) ? 8 : 4;
    int done = 0;
    bool is_valid = true;

    while (done < need) {
        uint32_t ZH, ZL;
        kcipher2_stream(state, ZH, ZL);
        uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                         (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};
        const int take = ((need - done) < 8) ? (need - done) : 8;

#pragma unroll
        for (int j = 0; j < take; ++j) {
            const int idx = done + j;
            const uint8_t p = (uint8_t)(read_only_byte(base + off + idx) ^ ks[j]);

            if (idx == 0 && p != 0x50)
                is_valid = false; // 'P'
            if (idx == 1 && p != 0x4B)
                is_valid = false; // 'K'
            if (idx == 2 && p != 0x03)
                is_valid = false;
            if (idx == 3 && p != 0x04)
                is_valid = false;
            // Byte 4: "version needed to extract" -- reasonable values <= 63
            if (idx == 4 && p > 63)
                is_valid = false;
            if (idx == 5 && p > 20)
                is_valid = false;
            if (idx == 7 && (p & 0xF1))
                is_valid = false;
        }
        done += take;
        kcipher2_next_state(state, 1);
    }

    return is_valid;
}

/* =========================================================================
 *  SQLite validator
 *
 *  SQLite magic: "SQLite f" = 53 51 4C 69 74 65 20 66 (8 bytes).
 * ========================================================================= */

/**
 * @brief Validate a SQLite database signature against KCipher-2 decrypted header.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match "SQLite f".
 */
__device__ __forceinline__ bool kcipher2_validate_sqlite(KCipher2State& state,
                                                         const uint8_t* __restrict__ base,
                                                         size_t off, int len) {
    if (len < 8)
        return false;

    uint32_t ZH, ZL;
    kcipher2_stream(state, ZH, ZL);
    uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                     (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};

    static const uint8_t sig[8] = {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66};
    bool is_valid = true;
#pragma unroll
    for (int i = 0; i < 8; ++i)
        is_valid = is_valid && ((uint8_t)(read_only_byte(base + off + i) ^ ks[i]) == sig[i]);

    kcipher2_next_state(state, 1);
    return is_valid;
}

/* =========================================================================
 *  OLE Compound Document validator
 *
 *  OLE magic: D0 CF 11 E0 A1 B1 1A E1 (8 bytes).
 *  Used by legacy Microsoft Office formats (.doc, .xls, .ppt, etc.).
 * ========================================================================= */

/**
 * @brief Validate an OLE Compound Document signature against KCipher-2 decrypted header.
 *
 * @param state     KCipher-2 state (consumed; caller should pass a copy).
 * @param base      Pointer to encrypted header bytes (device memory).
 * @param off       Byte offset within base (normally 0).
 * @param len       Available header length in bytes.
 * @return          true if decrypted bytes match the OLE magic.
 */
__device__ __forceinline__ bool
kcipher2_validate_ole(KCipher2State& state, const uint8_t* __restrict__ base, size_t off, int len) {
    if (len < 8)
        return false;

    uint32_t ZH, ZL;
    kcipher2_stream(state, ZH, ZL);
    uint8_t ks[8] = {(uint8_t)(ZH >> 24), (uint8_t)(ZH >> 16), (uint8_t)(ZH >> 8), (uint8_t)ZH,
                     (uint8_t)(ZL >> 24), (uint8_t)(ZL >> 16), (uint8_t)(ZL >> 8), (uint8_t)ZL};

    static const uint8_t sig[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    bool is_valid = true;
#pragma unroll
    for (int i = 0; i < 8; ++i)
        is_valid = is_valid && ((uint8_t)(read_only_byte(base + off + i) ^ ks[i]) == sig[i]);

    kcipher2_next_state(state, 1);
    return is_valid;
}

