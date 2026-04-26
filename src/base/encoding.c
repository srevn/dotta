/**
 * encoding.c - Portable byte-order primitives
 */

#include "base/encoding.h"

/**
 * Store a uint16_t in little-endian byte order (portable)
 */
void store_le16(uint8_t out[2], uint16_t val) {
    out[0] = (uint8_t) (val);
    out[1] = (uint8_t) (val >> 8);
}

/**
 * Load a uint16_t from little-endian byte order (portable)
 *
 * The byte casts widen each operand to `unsigned` (via integer
 * promotion) before the OR; the explicit final cast back to
 * `uint16_t` makes the narrowing return-type conversion visible to
 * the reader and quiet under any narrowing-warning flag.
 */
uint16_t load_le16(const uint8_t in[2]) {
    return (uint16_t) ((uint16_t) in[0]
           | ((uint16_t) in[1] << 8));
}

/**
 * Store a uint64_t in little-endian byte order (portable)
 */
void store_le64(uint8_t out[8], uint64_t val) {
    out[0] = (uint8_t) (val);
    out[1] = (uint8_t) (val >> 8);
    out[2] = (uint8_t) (val >> 16);
    out[3] = (uint8_t) (val >> 24);
    out[4] = (uint8_t) (val >> 32);
    out[5] = (uint8_t) (val >> 40);
    out[6] = (uint8_t) (val >> 48);
    out[7] = (uint8_t) (val >> 56);
}

/**
 * Load a uint64_t from little-endian byte order (portable)
 */
uint64_t load_le64(const uint8_t in[8]) {
    return (uint64_t) in[0]
           | ((uint64_t) in[1] << 8)
           | ((uint64_t) in[2] << 16)
           | ((uint64_t) in[3] << 24)
           | ((uint64_t) in[4] << 32)
           | ((uint64_t) in[5] << 40)
           | ((uint64_t) in[6] << 48)
           | ((uint64_t) in[7] << 56);
}
