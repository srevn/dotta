/**
 * encoding.h - Portable byte-order primitives
 *
 * Little-endian encode/decode for fixed-width integers. Both functions
 * consume or emit exactly 8 bytes, independent of host byte order, so
 * binary formats and MAC inputs reproduce bit-for-bit across any
 * architecture dotta runs on.
 *
 * The functions are branch-free on every target the compiler supports;
 * on little-endian hosts a modern optimizer lowers the body to a single
 * aligned load or store, and on big-endian hosts to a load/store plus
 * bswap. Call overhead is the only observable cost, and it amortizes
 * across the hundreds-of-ms scale of the operations that use them
 * (balloon-hash block expansion, session-cache MAC computation).
 *
 * Single source of truth — previously duplicated in
 * `crypto/encryption.c` and `crypto/keymgr.c`.
 */

#ifndef DOTTA_ENCODING_H
#define DOTTA_ENCODING_H

#include <stdint.h>

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
