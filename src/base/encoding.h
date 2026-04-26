/**
 * encoding.h - Portable byte-order primitives
 *
 * Little-endian encode/decode for fixed-width integers. Each function
 * consumes or emits exactly the bytes its width implies, independent
 * of host byte order, so binary formats and MAC inputs reproduce bit-
 * for-bit across any architecture dotta runs on.
 *
 * The functions are branch-free on every target the compiler supports;
 * on little-endian hosts a modern optimizer lowers each body to a
 * single aligned load or store, and on big-endian hosts to a load or
 * store plus a bswap. Call overhead is one or two instructions —
 * negligible against the bandwidth-bound work that surrounds every
 * call (keyed-BLAKE2b absorption in `crypto/mac.c`, XChaCha20
 * keystream in `crypto/cipher.c`, and session-cache MAC computation
 * in `crypto/session.c`).
 *
 * Single source of truth for byte-order conversions across the crypto
 * stack:
 *   - `crypto/mac.c`      — canonical LE64 framing of every variable-
 *                           length input absorbed into keyed BLAKE2b.
 *   - `crypto/cipher.c`   — LE16 Argon2-params field in the encrypted-
 *                           blob header.
 *   - `crypto/session.c`  — LE16/LE64 numeric fields in the on-disk
 *                           session-cache layout.
 */

#ifndef DOTTA_ENCODING_H
#define DOTTA_ENCODING_H

#include <stdint.h>

/**
 * Store a uint16_t as 2 little-endian bytes.
 *
 * Writes exactly 2 bytes to `out`. Low-order byte first.
 *
 * @param out Output buffer; caller ensures ≥ 2 bytes of space
 * @param val Value to encode
 */
void store_le16(uint8_t out[2], uint16_t val);

/**
 * Load a uint16_t from 2 little-endian bytes.
 *
 * Reads exactly 2 bytes from `in`. Low-order byte first.
 *
 * @param in  Input buffer; caller ensures ≥ 2 bytes of content
 * @return    Decoded value
 */
uint16_t load_le16(const uint8_t in[2]);

/**
 * Store a uint64_t as 8 little-endian bytes.
 *
 * Writes exactly 8 bytes to `out`. Low-order byte first.
 *
 * @param out Output buffer; caller ensures ≥ 8 bytes of space
 * @param val Value to encode
 */
void store_le64(uint8_t out[8], uint64_t val);

/**
 * Load a uint64_t from 8 little-endian bytes.
 *
 * Reads exactly 8 bytes from `in`. Low-order byte first.
 *
 * @param in  Input buffer; caller ensures ≥ 8 bytes of content
 * @return    Decoded value
 */
uint64_t load_le64(const uint8_t in[8]);

#endif /* DOTTA_ENCODING_H */
