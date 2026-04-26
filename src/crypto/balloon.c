/**
 * balloon.c - Memory-hard passphrase derivation implementation
 *
 * Single-phase balloon hashing (Boneh-Corrigan-Gibbs-Schechter, 2016) built
 * directly over libhydrogen primitives. The design is deliberately a flat
 * three-stage pipeline rather than the classic "CPU-pwhash → wrap with
 * memory-hard layer" split: the only attacker-bounding work is the
 * memory-hard mixing, so any wall-clock spent on a CPU-pwhash phase is
 * parallelizable across guesses and contributes nothing.
 *
 * Stages:
 *   0. ABSORB.   passphrase + params → 32-byte state. Single keyed hash.
 *                The state keys every subsequent hash, binding every block
 *                back to the passphrase.
 *   1. EXPAND.   block[0] = H(state, LE64(0))[BLOCK_SIZE].
 *                block[i] = H(state, LE64(i), block[i-1])[BLOCK_SIZE].
 *                Sequential — block i needs block i-1, so a parallel
 *                attacker cannot fill blocks out of order.
 *   2. MIX.      For each round r and block i, derive `delta` block
 *                indices from a hash of (state, position, FULL current
 *                block), then rewrite block i as
 *                H(state, pos, prev_block, current_block, delta random
 *                blocks)[BLOCK_SIZE]. Every input absorbed is a full
 *                block; the new block content IS the hash output.
 *   3. FINALIZE. Output = H(state, last_block, out_len=32).
 *
 * Why every block is a direct hash output (no PRG splice):
 *   The block content IS the hash output (BLAKE2's long-output / XOF mode,
 *   1024 bytes squeezed from the keyed sponge). There is no 32-byte
 *   "seed" sitting between H and the block that an attacker could stash —
 *   the only compressed representation of a block IS the block. A
 *   storage-tradeoff attacker who keeps fewer bytes per block must
 *   recompute the block by walking the dependency chain back to a
 *   stashed neighbour, which is the standard balloon-hashing TS bound.
 *
 *   This matches the construction the Boneh paper analyses (block size =
 *   hash output size) and the way Argon2 fills its 1024-byte blocks via
 *   BLAKE2b-Long. Splicing in a 32-byte PRG seed between the hash and the
 *   block would give the attacker a free 32x memory savings on top of any
 *   TS tradeoff.
 *
 * Memory hygiene:
 *   - Balloon buffer: best-effort mlock'd with a single warn-on-failure to
 *     stderr; wiped via buffer_secure_free on every exit path.
 *   - Function-scoped secrets (`state`): zeroed at cleanup.
 *   - Loop-scoped secrets (per-iteration hash state, idx_seed): zeroed at
 *     the end of every iteration. Defense in depth — bounds the window in
 *     which transient key material sits on the stack on both normal-
 *     completion and early-return error paths inside the loop.
 */

#include "crypto/balloon.h"

#include <errno.h>
#include <hydrogen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "base/buffer.h"
#include "base/encoding.h"
#include "base/error.h"

/**
 * Block size in bytes.
 *
 * 1024 amortizes per-block hash setup over enough rate-block absorptions
 * (BLOCK_SIZE / gimli_RATE = 64) that the keyed-hash framing overhead is
 * a few percent of total mix cost. Smaller blocks would need more blocks
 * for the same memory budget and pay a larger fraction of cost in setup
 * (the fixed init+finalize cost is the same regardless of block size).
 */
#define BALLOON_BLOCK_SIZE 1024

/* The bias-free index reduction (`raw % n_blocks`) requires n_blocks itself
 * to be a power of two. n_blocks = memlimit_bytes / BLOCK_SIZE; memlimit_bytes
 * is validated as a power of two, so BLOCK_SIZE must be one too for the
 * quotient to inherit the property. Currently 1024 = 2^10. */
_Static_assert(
    (BALLOON_BLOCK_SIZE & (BALLOON_BLOCK_SIZE - 1)) == 0,
    "BALLOON_BLOCK_SIZE must be a power of two"
);

/* Context strings. libhydrogen requires exactly 8 bytes of context per
 * keyed hash; these are domain separators so a hash family tied to one
 * stage can never collide with another even if the keys ever did. */
static const char CTX_ABSORB[8] = { 'd', 'o', 't', 't', 'a', 'b', 'l', '0' };
static const char CTX_EXPAND[8] = { 'd', 'o', 't', 't', 'a', 'b', 'l', '1' };
static const char CTX_INDEX[8] = { 'd', 'o', 't', 't', 'a', 'b', 'l', 'i' };
static const char CTX_MIX[8] = { 'd', 'o', 't', 't', 'a', 'b', 'l', 'm' };
static const char CTX_FINALIZE[8] = { 'd', 'o', 't', 't', 'a', 'b', 'l', 'f' };

/**
 * Hard-coded bounds on `delta` and `rounds`.
 *
 * `delta` lower bound: index extraction asks `hydro_hash_final` for
 * `8 * delta` bytes. libhydrogen rejects output sizes below
 * `hydro_hash_BYTES_MIN = 16`, so delta must be at least 2.
 *
 * `delta` upper bound: keeps `idx_seed[8 * BALLOON_DELTA_MAX]` a fixed
 * stack array. Eight references per mix is well beyond any sane
 * configuration; the paper's value is 3.
 *
 * `rounds` upper bound: defends against a misconfigured caller passing
 * a runaway value. The paper recommends 3-5; 16 is far above any
 * defensible setting and below anything that could lock the process up.
 */
#define BALLOON_DELTA_MIN  2
#define BALLOON_DELTA_MAX  8
#define BALLOON_ROUNDS_MAX 16

/**
 * Validate parameters — power-of-two memlimit, sane rounds/delta.
 *
 * Power-of-two requirement keeps the index reduction
 * `(load_le64(...) % n_blocks)` bias-free without rejection sampling.
 * This is enforced at the crypto boundary (defense in depth) even though
 * config parsing also checks it.
 */
static error_t *validate_params(balloon_params_t p) {
    if (p.memlimit_bytes < BALLOON_MIN_BYTES) {
        return ERROR(
            ERR_INVALID_ARG,
            "balloon memlimit %zu bytes is below minimum %zu bytes",
            p.memlimit_bytes, (size_t) BALLOON_MIN_BYTES
        );
    }
    if ((p.memlimit_bytes & (p.memlimit_bytes - 1)) != 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "balloon memlimit %zu bytes must be a power of two",
            p.memlimit_bytes
        );
    }
    if (p.memlimit_bytes % BALLOON_BLOCK_SIZE != 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "balloon memlimit %zu bytes is not a multiple of block size %d",
            p.memlimit_bytes, BALLOON_BLOCK_SIZE
        );
    }
    if (p.rounds == 0 || p.rounds > BALLOON_ROUNDS_MAX) {
        return ERROR(
            ERR_INVALID_ARG,
            "balloon rounds %u out of range (1..%d)",
            p.rounds, BALLOON_ROUNDS_MAX
        );
    }
    if (p.delta < BALLOON_DELTA_MIN || p.delta > BALLOON_DELTA_MAX) {
        return ERROR(
            ERR_INVALID_ARG,
            "balloon delta %u out of range (%d..%d)",
            p.delta, BALLOON_DELTA_MIN, BALLOON_DELTA_MAX
        );
    }
    return NULL;
}

/**
 * Stage 0 — absorb passphrase + params into a 32-byte state.
 *
 * Params are domain-mixed in so identical passphrases under different
 * (memlimit, rounds, delta) yield unrelated keys.
 */
static error_t *absorb_passphrase(
    const uint8_t *passphrase, size_t passphrase_len,
    balloon_params_t p,
    uint8_t out_state[32]
) {
    hydro_hash_state h;
    if (hydro_hash_init(&h, CTX_ABSORB, NULL) != 0) {
        return ERROR(ERR_CRYPTO, "balloon: absorb hash init failed");
    }

    /* Length-prefix the passphrase so a different-length passphrase that
     * happens to be a prefix of another cannot collide with it. */
    uint8_t pass_len_le[8];
    store_le64(pass_len_le, (uint64_t) passphrase_len);
    hydro_hash_update(&h, pass_len_le, sizeof(pass_len_le));
    hydro_hash_update(&h, passphrase, passphrase_len);

    /* Domain-mix the algorithm parameters. */
    uint8_t params_le[24];
    store_le64(params_le + 0, (uint64_t) p.memlimit_bytes);
    store_le64(params_le + 8, (uint64_t) p.rounds);
    store_le64(params_le + 16, (uint64_t) p.delta);
    hydro_hash_update(&h, params_le, sizeof(params_le));

    if (hydro_hash_final(&h, out_state, 32) != 0) {
        hydro_memzero(&h, sizeof(h));
        return ERROR(ERR_CRYPTO, "balloon: absorb hash final failed");
    }

    hydro_memzero(&h, sizeof(h));
    return NULL;
}

/**
 * Stage 1 — fill the buffer with sequential, full-block dependencies.
 *
 *   block[0] = H(state, LE64(0))[BLOCK_SIZE]
 *   block[i] = H(state, LE64(i), block[i-1])[BLOCK_SIZE]   (i >= 1)
 *
 * The hash absorbs the FULL previous block, so a parallel attacker
 * cannot fill blocks out of order. The hash output IS the block — there
 * is no 32-byte intermediate seed an attacker could stash to compress
 * the per-block storage cost.
 */
static error_t *expand_buffer(
    const uint8_t state[32],
    uint8_t *buf, size_t n_blocks
) {
    for (size_t i = 0; i < n_blocks; i++) {
        hydro_hash_state h;
        if (hydro_hash_init(&h, CTX_EXPAND, state) != 0) {
            return ERROR(
                ERR_CRYPTO, "balloon: expand hash init failed at block %zu", i
            );
        }

        uint8_t i_le[8];
        store_le64(i_le, (uint64_t) i);
        hydro_hash_update(&h, i_le, sizeof(i_le));

        /* Block 0 has no predecessor — the index alone domain-separates
         * it from later blocks that absorb their predecessor. */
        if (i > 0) {
            hydro_hash_update(
                &h, buf + (i - 1) * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
            );
        }

        /* Squeeze the full block content directly out of the sponge.
         * No intermediate 32-byte seed exists for an attacker to stash. */
        if (hydro_hash_final(
            &h, buf + i * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
            ) != 0) {
            hydro_memzero(&h, sizeof(h));
            return ERROR(
                ERR_CRYPTO, "balloon: expand hash final failed at block %zu", i
            );
        }

        hydro_memzero(&h, sizeof(h));
    }

    return NULL;
}

/**
 * Stage 2 — `params.rounds` mixing passes over the buffer.
 *
 * For each block i in each round r:
 *   idx_seed = H(state, pos, current_block, out_len = 8 * delta)
 *   block[i] = H(state, pos, prev_block, current_block,
 *                block[idx[0]], ..., block[idx[delta-1]],
 *                out_len = BLOCK_SIZE)
 *
 * Every input absorbed is a full BLOCK_SIZE — no 32-byte-prefix
 * shortcuts. The new block content IS the hash output; absorbing the
 * `current_block` for both index derivation and the mix completes
 * before any byte of the new block is written, so no aliasing exists
 * between absorb and squeeze.
 */
static error_t *mix_buffer(
    const uint8_t state[32],
    uint8_t *buf, size_t n_blocks,
    balloon_params_t p
) {
    for (uint32_t r = 0; r < p.rounds; r++) {
        for (size_t i = 0; i < n_blocks; i++) {
            size_t prev_idx = (i == 0) ? n_blocks - 1 : i - 1;

            /* (round, block_index) as 16 little-endian bytes. Domain-
             * separates each (r, i) pair so identical block contents at
             * different positions cannot collide. */
            uint8_t pos[16];
            store_le64(pos + 0, (uint64_t) r);
            store_le64(pos + 8, (uint64_t) i);

            /* Index derivation: full-block, data-dependent.
             *
             * Single hash absorbs (pos, full current block) keyed by
             * `state` and squeezes 8 * delta bytes for `delta` 64-bit
             * indices. The buffer is sized for BALLOON_DELTA_MAX so the
             * stack layout is fixed; only the first `8 * delta` bytes are
             * written by hash_final. Zero-initializing the whole array
             * keeps the unused tail well-defined and removes a partial-
             * write smell that static analyzers may flag. */
            uint8_t idx_seed[8 * BALLOON_DELTA_MAX] = { 0 };
            {
                hydro_hash_state h;
                if (hydro_hash_init(&h, CTX_INDEX, state) != 0) {
                    return ERROR(
                        ERR_CRYPTO, "balloon: index hash init failed (r=%u, i=%zu)",
                        r, i
                    );
                }

                hydro_hash_update(&h, pos, sizeof(pos));
                hydro_hash_update(
                    &h, buf + i * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
                );

                if (hydro_hash_final(&h, idx_seed, 8 * p.delta) != 0) {
                    hydro_memzero(&h, sizeof(h));
                    hydro_memzero(idx_seed, sizeof(idx_seed));
                    return ERROR(
                        ERR_CRYPTO, "balloon: index hash final failed (r=%u, i=%zu)",
                        r, i
                    );
                }

                hydro_memzero(&h, sizeof(h));
            }

            /* Mix: hash absorbs (pos, prev, current, delta randoms) and
             * squeezes BLOCK_SIZE bytes directly into buf[i]. The
             * absorb-current step completes before the squeeze writes,
             * so reading and writing the same memory region across the
             * single hash call is safe. */
            hydro_hash_state mix_hash;
            if (hydro_hash_init(&mix_hash, CTX_MIX, state) != 0) {
                hydro_memzero(idx_seed, sizeof(idx_seed));
                return ERROR(
                    ERR_CRYPTO, "balloon: mix hash init failed (r=%u, i=%zu)",
                    r, i
                );
            }

            hydro_hash_update(&mix_hash, pos, sizeof(pos));
            hydro_hash_update(
                &mix_hash, buf + prev_idx * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
            );

            hydro_hash_update(
                &mix_hash, buf + i * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
            );

            for (uint32_t d = 0; d < p.delta; d++) {
                uint64_t raw = load_le64(idx_seed + d * 8);
                /* Power-of-two n_blocks (validated above) makes this
                 * reduction bias-free. */
                size_t idx = (size_t) (raw % (uint64_t) n_blocks);
                hydro_hash_update(
                    &mix_hash, buf + idx * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
                );
            }

            /* Squeeze the new block content directly into buf[i]. No
             * 32-byte intermediate seed exists for an attacker to stash. */
            if (hydro_hash_final(
                &mix_hash,
                buf + i * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE
                ) != 0) {
                hydro_memzero(&mix_hash, sizeof(mix_hash));
                hydro_memzero(idx_seed, sizeof(idx_seed));
                return ERROR(
                    ERR_CRYPTO, "balloon: mix hash final failed (r=%u, i=%zu)",
                    r, i
                );
            }

            hydro_memzero(&mix_hash, sizeof(mix_hash));
            hydro_memzero(idx_seed, sizeof(idx_seed));
        }
    }

    return NULL;
}

/**
 * Stage 3 — derive output key from final block state.
 *
 * `state` (passphrase-bound) is the hash key, binding the entire
 * derivation back to the passphrase even though every Stage 2 mix
 * already absorbed `state`.
 */
static error_t *finalize_key(
    const uint8_t state[32],
    const uint8_t *buf, size_t n_blocks,
    uint8_t out_key[BALLOON_KEY_SIZE]
) {
    int rc = hydro_hash_hash(
        out_key,
        BALLOON_KEY_SIZE,
        buf + (n_blocks - 1) * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE,
        CTX_FINALIZE, state
    );

    if (rc != 0) {
        hydro_memzero(out_key, BALLOON_KEY_SIZE);
        return ERROR(ERR_CRYPTO, "balloon: finalize hash failed");
    }

    return NULL;
}

error_t *balloon_derive(
    const uint8_t *passphrase,
    size_t passphrase_len,
    balloon_params_t params,
    uint8_t out_key[BALLOON_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(out_key);

    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "balloon: passphrase cannot be empty");
    }

    error_t *err = validate_params(params);
    if (err) return err;

    const size_t n_blocks = params.memlimit_bytes / BALLOON_BLOCK_SIZE;

    /* Allocate the balloon buffer. malloc is fine — the buffer's lifetime
     * is exactly this call, and we wipe it through buffer_secure_free
     * before return on every exit path. */
    uint8_t *buf = malloc(params.memlimit_bytes);
    if (!buf) {
        return ERROR(
            ERR_MEMORY, "balloon: failed to allocate %zu bytes",
            params.memlimit_bytes
        );
    }

    /* Best-effort mlock the entire balloon buffer so transient secret state
     * cannot be paged out. Failure is non-fatal — the buffer's contents are
     * always wiped before free regardless — but we surface a warning because
     * the balloon buffer is much larger than RLIMIT_MEMLOCK's typical default
     * (65 KiB on macOS), so users on default-configured systems will
     * silently lose this protection if we don't say so. */
    if (mlock(buf, params.memlimit_bytes) != 0) {
        fprintf(
            stderr,
            "Warning: Failed to lock %zu MB balloon buffer: %s\n"
            "         Key derivation state may be paged to disk.\n"
            "         Raise RLIMIT_MEMLOCK (ulimit -l) or run with elevated\n"
            "         privileges to enable this protection.\n",
            params.memlimit_bytes / (1024 * 1024), strerror(errno)
        );
    }

    uint8_t state[32];
    err = absorb_passphrase(passphrase, passphrase_len, params, state);
    if (err) {
        goto cleanup;
    }

    err = expand_buffer(state, buf, n_blocks);
    if (err) {
        goto cleanup;
    }

    err = mix_buffer(state, buf, n_blocks, params);
    if (err) {
        goto cleanup;
    }

    err = finalize_key(state, buf, n_blocks, out_key);

cleanup:
    /* Wipe the buffer regardless of which stage failed. buffer_secure_free
     * runs the canonical zero-then-munlock-then-free sequence; do not
     * inline a hand-rolled three-liner here. */
    buffer_secure_free(buf, params.memlimit_bytes);
    hydro_memzero(state, sizeof(state));

    if (err) {
        hydro_memzero(out_key, BALLOON_KEY_SIZE);
    }

    return err;
}
