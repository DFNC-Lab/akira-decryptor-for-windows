// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file chacha8.h
 * @brief ChaCha8 stream cipher -- host-side opaque ADT interface.
 *
 * Provides an opaque handle to the ChaCha8 cipher state.  The internal
 * structure is hidden in chacha8.c; callers interact only through the
 * pointer-based API below.
 *
 * Akira ransomware uses a 16-byte-key variant of ChaCha8 (8 rounds,
 * "expand 16-byte k" constant) for encrypting the middle blocks of each
 * file region.
 *
 * Reference: D.J. Bernstein, "ChaCha, a variant of Salsa20", 2008.
 *
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque ChaCha8 cipher context.
 *
 * Internal layout is defined in chacha8.c and not visible to callers.
 */
typedef struct Chacha8 Chacha8;

/**
 * @brief Allocate and initialize a ChaCha8 context.
 *
 * @param key  16-byte encryption key.
 * @param iv   8-byte initialization vector (nonce).
 * @return     Heap-allocated context, or NULL on failure.
 *             Caller must free with chacha8_destroy().
 */
Chacha8* chacha8_create(const uint8_t key[16], const uint8_t iv[8]);

/**
 * @brief Free a ChaCha8 context and all associated resources.
 *
 * @param ctx  Context to destroy (NULL is safe).
 */
void chacha8_destroy(Chacha8* ctx);

/**
 * @brief XOR data in-place with the ChaCha8 keystream.
 *
 * Processes full 64-byte blocks using 8-byte XOR operations for speed,
 * then handles any trailing partial block byte-by-byte.
 *
 * @param ctx   Active cipher context.
 * @param data  Buffer to XOR (modified in-place).
 * @param len   Number of bytes to process.
 */
void chacha8_xor(Chacha8* ctx, uint8_t* data, size_t len);

/**
 * @brief Advance ChaCha8 state by @p len bytes without modifying data.
 *
 * Used for blocks encrypted by KCipher-2 where ChaCha8 state must still
 * advance to stay synchronized across the file.
 *
 * @param ctx   Active cipher context.
 * @param len   Number of bytes to skip.
 */
void chacha8_discard(Chacha8* ctx, size_t len);

#ifdef __cplusplus
}
#endif
