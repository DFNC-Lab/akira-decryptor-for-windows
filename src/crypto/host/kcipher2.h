// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file kcipher2.h
 * @brief KCipher-2 stream cipher -- host-side opaque ADT interface.
 *
 * Provides an opaque handle to the KCipher-2 cipher state.  The internal
 * structure is hidden in kcipher2.c; callers interact only through the
 * pointer-based API below.
 *
 * KCipher-2 is specified in ISO/IEC 18033-4.  Akira ransomware uses it
 * for encrypting the first and last 0xFFFF-byte blocks of each region.
 *
 * Reference: K. Kiyomoto et al., "KCipher-2", KDDI R&D Laboratories, 2007.
 *
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque KCipher-2 cipher context.
 *
 * Internal layout is defined in kcipher2.c and not visible to callers.
 */
typedef struct KCipher2 KCipher2;

/**
 * @brief Allocate and initialize a KCipher-2 context.
 *
 * Performs key expansion and the 24-round initialization phase.
 *
 * @param key_hex  32-character hex string (128-bit key).
 * @param iv_hex   32-character hex string (128-bit IV).
 * @return         Heap-allocated context, or NULL on failure.
 *                 Caller must free with kcipher2_destroy().
 */
KCipher2* kcipher2_create(const char* key_hex, const char* iv_hex);

/**
 * @brief Free a KCipher-2 context and all associated resources.
 *
 * @param ctx  Context to destroy (NULL is safe).
 */
void kcipher2_destroy(KCipher2* ctx);

/**
 * @brief XOR data in-place with the KCipher-2 keystream.
 *
 * The cipher state advances by @p len keystream bytes.  Byte-level
 * continuity is maintained across calls (partial 8-byte blocks are
 * buffered internally).
 *
 * @param ctx   Active cipher context.
 * @param data  Buffer to XOR (modified in-place).
 * @param len   Number of bytes to process.
 */
void kcipher2_xor(KCipher2* ctx, uint8_t* data, size_t len);

/**
 * @brief Advance the keystream by @p n bytes without producing output.
 *
 * Used to skip over unencrypted gaps while maintaining correct
 * keystream position (e.g. middle blocks in Akira's scheme).
 *
 * @param ctx  Active cipher context.
 * @param n    Number of keystream bytes to discard.
 */
void kcipher2_discard(KCipher2* ctx, size_t n);

#ifdef __cplusplus
}
#endif
