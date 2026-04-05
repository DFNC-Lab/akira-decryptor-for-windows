// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file decrypt_region.h
 * @brief Block-level decryption for Akira ransomware encrypted regions.
 *
 * Akira divides each encrypted region into fixed-size blocks of
 * AKIRA_BLOCK_SIZE (0xFFFF = 65535) bytes.  The first and last blocks
 * are encrypted with KCipher-2; middle blocks use ChaCha8.
 *
 * This module applies that block-level decryption pattern to an
 * arbitrary-length region using caller-provided KCipher2 and Chacha8
 * cipher contexts.
 *
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "kcipher2.h"
#include "chacha8.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Encryption block size: 0xFFFF bytes (65535, not 65536). */
#define AKIRA_BLOCK_SIZE 65535

/**
 * @brief Decrypt one contiguous region using Akira's block scheme.
 *
 * Walks the region in AKIRA_BLOCK_SIZE blocks:
 *   - Block 0 (first)  : decrypted with KCipher-2
 *   - Block N (last)    : decrypted with KCipher-2
 *   - Middle blocks     : decrypted with ChaCha8 (if @p chacha8 is non-NULL)
 *
 * KCipher-2 state does NOT advance over middle blocks; only the first
 * and last blocks consume keystream.  The ChaCha8 state advances
 * continuously over all middle blocks.
 *
 * @param kcipher2    KCipher-2 context (must not be NULL).
 * @param chacha8     ChaCha8 context, or NULL if middle-block decryption
 *                    is not needed (e.g. KC2-only files).
 * @param data        Region data buffer (modified in-place).
 * @param region_len  Length of the region in bytes.
 */
void decrypt_region_blocks(KCipher2* kcipher2, Chacha8* chacha8, uint8_t* data, size_t region_len);

#ifdef __cplusplus
}
#endif
