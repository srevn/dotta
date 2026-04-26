/**
 * balloon.h - Memory-hard passphrase derivation
 *
 * Implements balloon hashing (Boneh, Corrigan-Gibbs, Schechter, 2016) over
 * libhydrogen's keyed BLAKE2 (Gimli-based) sponge in long-output / XOF
 * mode, producing a single 32-byte key from a user passphrase under a
 * memory budget the attacker cannot trade away.
 *
 * Design goals:
 *   - One phase, one knob. The only meaningful security parameter is the
 *     memory budget; the attacker's parallelism is bounded by RAM, not cores.
 *   - Block content IS the hash output. Every block in the buffer is
 *     squeezed directly out of a keyed BLAKE2 sponge in XOF mode (1024
 *     bytes per block). There is no 32-byte intermediate seed between H
 *     and the block — the only compressed representation of a block IS
 *     the block, so a storage-tradeoff attacker cannot store labels
 *     smaller than a full block.
 *   - Full-block dependencies. Every hash absorption reads entire blocks,
 *     not 32-byte prefixes, so the chain has no stash-friendly shortcut.
 *   - Data-dependent indexing. Mixing indices are derived from a hash
 *     that absorbs the full current block, matching the Boneh paper's
 *     primary scheme.
 *
 * This module is consumed only by crypto/kdf for master-key derivation.
 * It is its own translation unit purely for review economy: the algorithm
 * is dense, the failure modes are subtle, and isolating it lets a reader
 * verify the construction end-to-end without the surrounding KDF/cipher
 * concerns leaking in.
 */

#ifndef DOTTA_CRYPTO_BALLOON_H
#define DOTTA_CRYPTO_BALLOON_H

#include <stddef.h>
#include <stdint.h>
#include <types.h>

/** Output key size in bytes (single keyed-BLAKE2 output) */
#define BALLOON_KEY_SIZE 32

/**
 * Memory budget bounds (bytes).
 *
 * memlimit_bytes must be a power of two so the index reduction
 * `value % n_blocks` is bias-free without rejection sampling. The minimum
 * is enough to derive a key in well under 50 ms (test/CI use); the default
 * is benched to land in a defender-acceptable wall-clock range on
 * commodity hardware.
 */
#define BALLOON_MIN_BYTES        ((size_t) 1 * 1024 * 1024)
#define BALLOON_DEFAULT_BYTES    ((size_t) 8 * 1024 * 1024)
#define BALLOON_DEFAULT_ROUNDS   3
#define BALLOON_DEFAULT_DELTA    3

/**
 * Algorithm parameters.
 *
 * memlimit_bytes  — total balloon-buffer size in bytes; power-of-two and
 *                   >= BALLOON_MIN_BYTES.
 * rounds          — mixing rounds over the buffer; >= 1.
 * delta           — random-block references absorbed per mix step; >= 1.
 *                   delta = 3 is the value used in the paper's provable
 *                   memory-hardness bound.
 */
typedef struct balloon_params {
    size_t memlimit_bytes;
    uint32_t rounds;
    uint32_t delta;
} balloon_params_t;

/**
 * Derive a 32-byte key from a passphrase under the supplied parameters.
 *
 * Deterministic: identical (passphrase, params) always produces the same
 * key. Same-passphrase / different-params produces unrelated keys (the
 * params are domain-mixed into the absorbed state).
 *
 * Performance: derivation runs roughly `n_blocks` keyed-hash block
 * fills in expansion plus `params.rounds × n_blocks` keyed-hash block
 * fills in mixing, each absorbing `delta + 2` predecessor blocks. The
 * buffer is mlock'd best-effort and zeroed before free; failure of
 * mlock is non-fatal and warns to stderr.
 *
 * @param passphrase     Passphrase bytes (must not be NULL; len > 0)
 * @param passphrase_len Passphrase length in bytes
 * @param params         Algorithm parameters (validated)
 * @param out_key        Output buffer for 32-byte key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *balloon_derive(
    const uint8_t *passphrase,
    size_t passphrase_len,
    balloon_params_t params,
    uint8_t out_key[BALLOON_KEY_SIZE]
);

#endif /* DOTTA_CRYPTO_BALLOON_H */
