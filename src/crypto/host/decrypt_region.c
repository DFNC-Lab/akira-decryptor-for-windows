// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file decrypt_region.c
 * @brief Block-level decryption for Akira ransomware encrypted regions.
 *
 * Implements the Akira block scheme: first and last 0xFFFF-byte blocks
 * use KCipher-2, middle blocks use ChaCha8.  The two cipher states are
 * independent — each only advances through its own blocks.
 *
 */

#include "decrypt_region.h"

void decrypt_region_blocks(KCipher2* kcipher2, Chacha8* chacha8, uint8_t* data, size_t region_len) {
    if (region_len == 0)
        return;

    size_t nblocks = (region_len + AKIRA_BLOCK_SIZE - 1) / AKIRA_BLOCK_SIZE;
    size_t off = 0;

    for (size_t b = 0; b < nblocks; b++) {
        size_t block_len =
            (off + AKIRA_BLOCK_SIZE <= region_len) ? AKIRA_BLOCK_SIZE : (region_len - off);

        if (b == 0 || b == nblocks - 1) {
            /* First/last block: KCipher-2 only */
            kcipher2_xor(kcipher2, data + off, block_len);
        } else {
            /* Middle block: ChaCha8 only — cipher states are independent */
            if (chacha8)
                chacha8_xor(chacha8, data + off, block_len);
        }
        off += block_len;
    }
}
