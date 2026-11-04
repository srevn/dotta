/**
 * kdf.c - Key derivation implementation
 *
 * Two derivations:
 *   1. `kdf_master_key`: passphrase + epoch → master_key via Argon2id. The only
 *      step where an attacker pays per-guess memory cost.
 *   2. `kdf_siv_subkeys`: master_key + profile → (mac_key, prf_key) via two
 *      domain-separated keyed-BLAKE2b calls.
 *
 * Argon2id work-area lifecycle: one `secure_alloc` mapping of the epoch's memory
 * (base/secure.h) — page-aligned, which is more than the u64 alignment monocypher's
 * `crypto_argon2` requires of its `blk *` (u64[128] per block); locked against
 * swap best-effort, with the one advisory the process prints when a lock fails;
 * wiped and unmapped by `secure_free`. monocypher zeroes the work area itself
 * on return, so the bytes are wiped twice: the second pass is `secure_free`'s
 * own, paid (about 0.24 ms per MiB, a cost no preset moves) so that every
 * secret-bearing mapping in the tree ends the one way and no site reasons about
 * which primitive wiped what.
 *
 * The lanes: Argon2 orders its lanes only where a slice ends, a quarter of a
 * pass, so `kdf_argon2` is monocypher's `crypto_argon2` with each slice's lanes
 * side by side (`kdf_slice`) — lane 0 on the caller, each other on a thread started
 * for that slice and joined at its end — in about the time one lane takes. The
 * threads compute into the work area the caller mapped and allocate nothing,
 * and none outlives the derivation, so nothing that forks later (a hook, the
 * editor, `dotta git`) meets one. No signal is masked in them: a terminating
 * signal's handler ends the process from whichever thread it strikes (main.c
 * terminating_signal), and a fault is delivered to the thread that made it.
 *
 * The epoch: the salt is generated once at `dotta init` via `entropy_fill` (see
 * KDF_SALT_SIZE for the 256-bit choice) beside the parameters `init` was told
 * to mint with, and both are stored at `refs/dotta/epoch`, where they sync with
 * the repository. This makes each dotta repo a distinct attack target: a
 * precomputation table built against one repo cannot be reused against any other,
 * even by an attacker who has both repos' encrypted blobs. The epoch is public
 * — the salt's job is uniqueness, not secrecy, and the parameters are the cost
 * of a guess — and is treated as ordinary input bytes (no mlock/wipe).
 */

#include "crypto/kdf.h"

#include <errno.h>
#include <monocypher.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "base/encoding.h"
#include "base/error.h"
#include "base/secure.h"
#include "crypto/mac.h"

/* The work-area size needs a 64-bit `size_t` to express the 4 GiB Argon2 ceiling.
 * On a 32-bit host, `(uint32_t) 4096 * 1024 * 1024` overflows to 0 silently.
 * Refuse to build on 32-bit hosts so the failure is at compile time, not at
 * allocation time. */
_Static_assert(
    sizeof(size_t) >= 8,
    "dotta requires a 64-bit host for Argon2 work-area sizing"
);

/* The params blob's fields, at the offsets the ref spells them in: an offset
 * moved is another format for every epoch (refs/dotta/epoch:params, and the tail
 * of the fingerprint's input). */
#define KDF_PARAMS_OFFSET_MEMORY 0      /* LE16, MiB */
#define KDF_PARAMS_OFFSET_PASSES 2
#define KDF_PARAMS_OFFSET_LANES  3

_Static_assert(
    KDF_PARAMS_OFFSET_PASSES == KDF_PARAMS_OFFSET_MEMORY + 2,
    "passes must come immediately after the LE16 memory"
);
_Static_assert(
    KDF_PARAMS_OFFSET_LANES == KDF_PARAMS_OFFSET_PASSES + 1,
    "lanes must come immediately after the passes"
);
_Static_assert(
    KDF_PARAMS_OFFSET_LANES + 1 == KDF_PARAMS_SIZE,
    "the params blob must end with its lanes"
);

const kdf_preset_t kdf_presets[KDF_PRESET_COUNT] = {
    { "fast",     { 64,   3, 4 } },  /* ~85 ms; CI / test; RFC 9106's second option */
    { "balanced", { 256,  3, 4 } },  /* ~0.3 s; recommended */
    { "paranoid", { 1024, 4, 4 } },  /* ~1.2 s; slow but firm */
};

error_t kdf_validate_params(kdf_params_t params) {
    if (params.memory < KDF_ARGON2_MEMORY_MIN || params.memory > KDF_ARGON2_MEMORY_MAX) {
        return error_create(
            ERR_CRYPTO,
            "Argon2 memory %u MiB out of range (%u..%u)",
            (unsigned) params.memory,
            (unsigned) KDF_ARGON2_MEMORY_MIN,
            (unsigned) KDF_ARGON2_MEMORY_MAX
        );
    }

    if (params.passes < KDF_ARGON2_PASSES_MIN || params.passes > KDF_ARGON2_PASSES_MAX) {
        return error_create(
            ERR_CRYPTO,
            "Argon2 passes %u out of range (%u..%u)",
            (unsigned) params.passes,
            (unsigned) KDF_ARGON2_PASSES_MIN,
            (unsigned) KDF_ARGON2_PASSES_MAX
        );
    }

    if (params.lanes < KDF_ARGON2_LANES_MIN || params.lanes > KDF_ARGON2_LANES_MAX) {
        return error_create(
            ERR_CRYPTO,
            "Argon2 lanes %u out of range (%u..%u)",
            (unsigned) params.lanes,
            (unsigned) KDF_ARGON2_LANES_MIN,
            (unsigned) KDF_ARGON2_LANES_MAX
        );
    }

    return NULL;
}

void kdf_params_store(uint8_t out[KDF_PARAMS_SIZE], kdf_params_t params) {
    store_le16(&out[KDF_PARAMS_OFFSET_MEMORY], params.memory);
    out[KDF_PARAMS_OFFSET_PASSES] = params.passes;
    out[KDF_PARAMS_OFFSET_LANES] = params.lanes;
}

kdf_params_t kdf_params_load(const uint8_t in[KDF_PARAMS_SIZE]) {
    return (kdf_params_t) {
        .memory = load_le16(&in[KDF_PARAMS_OFFSET_MEMORY]),
        .passes = in[KDF_PARAMS_OFFSET_PASSES],
        .lanes = in[KDF_PARAMS_OFFSET_LANES],
    };
}

bool kdf_params_equal(kdf_params_t a, kdf_params_t b) {
    return a.memory == b.memory && a.passes == b.passes && a.lanes == b.lanes;
}

void kdf_epoch_fingerprint(
    const kdf_epoch_t *epoch,
    uint8_t out_fp[KDF_EPOCH_FP_SIZE]
) {
    /* Public identity of a public value: plain BLAKE2b-8 over the epoch's canonical
     * bytes — the salt, then the params as the ref spells them. No key, no wipe.
     * The 8-byte output length is baked into BLAKE2b's parameter block, giving
     * this use domain separation from every 32-byte derivation for free. */
    uint8_t blob[KDF_PARAMS_SIZE];
    kdf_params_store(blob, epoch->params);

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KDF_EPOCH_FP_SIZE);
    crypto_blake2b_update(&ctx, epoch->salt, KDF_SALT_SIZE);
    crypto_blake2b_update(&ctx, blob, KDF_PARAMS_SIZE);
    crypto_blake2b_final(&ctx, out_fp);
}

/* The slices a pass is cut into, RFC 9106's SL: where the lanes meet */
#define KDF_ARGON2_SLICES 4

/* One lane's segment of one slice, handed to the thread that computes it */
typedef struct {
    const crypto_argon2_ctx *argon2;    /* the derivation: its config and work area */
    uint32_t pass;                      /* which pass over the memory */
    uint32_t slice;                     /* which quarter of the pass */
    uint32_t lane;                      /* which lane, a row of the memory */
    pthread_t thread;                   /* the thread computing it, once started */
} kdf_segment_t;

/* A thread's start, or the caller's where none would start: compute the segment */
static void *kdf_segment(void *payload) {
    const kdf_segment_t *segment = payload;
    crypto_argon2_segment(
        segment->argon2, segment->pass, segment->slice, segment->lane
    );

    return NULL;
}

/**
 * One slice of one pass: its lanes' segments side by side, lane 0 on this thread
 * and each other on a thread of its own, every thread joined before the return.
 *
 * The joins are the slice's barrier, which macOS's pthreads have no object for:
 * a segment reads its own lane and the other lanes' finished slices, never a
 * slice in progress (lib/monocypher/monocypher.c crypto_argon2_segment), so the
 * next slice may start once this one's threads have ended.
 */
static void kdf_slice(const crypto_argon2_ctx *argon2, uint32_t pass, uint32_t slice) {
    kdf_segment_t segments[KDF_ARGON2_LANES_MAX - 1];
    size_t segment_count = 0;

    /* A lane whose thread will not start is computed here, at once: the bytes
     * are the same whoever computes a lane, so a failed start costs time alone */
    for (uint32_t lane = 1; lane < argon2->config.nb_lanes; lane++) {
        kdf_segment_t *segment = &segments[segment_count];
        *segment = (kdf_segment_t) {
            .argon2 = argon2, .pass = pass, .slice = slice, .lane = lane,
        };
        if (pthread_create(&segment->thread, NULL, kdf_segment, segment) == 0) {
            segment_count++;
        } else {
            kdf_segment(segment);
        }
    }
    crypto_argon2_segment(argon2, pass, slice, 0);

    /* Each ours, joinable, and joined once: nothing to refuse */
    for (size_t i = 0; i < segment_count; i++) {
        (void) pthread_join(segments[i].thread, NULL);
    }
}

/**
 * monocypher's `crypto_argon2` with no extras, each slice's lanes side by side:
 * its steps in its order, so its bytes — the init fills each lane's first blocks,
 * each pass's slices run in turn (`kdf_slice`), and the final hashes the lanes'
 * last blocks into `hash` and zeroes the work area. Cannot fail.
 */
static void kdf_argon2(
    uint8_t *hash, uint32_t hash_size, void *work_area, crypto_argon2_config config,
    crypto_argon2_inputs inputs
) {
    crypto_argon2_ctx argon2;
    crypto_argon2_init(
        &argon2, hash_size, work_area, config, inputs, crypto_argon2_no_extras
    );
    for (uint32_t pass = 0; pass < config.nb_passes; pass++) {
        for (uint32_t slice = 0; slice < KDF_ARGON2_SLICES; slice++) {
            kdf_slice(&argon2, pass, slice);
        }
    }
    crypto_argon2_final(&argon2, hash);
}

error_t kdf_master_key(
    const uint8_t *passphrase, size_t passphrase_len, const kdf_epoch_t *epoch,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(epoch);
    CHECK_NULL(out_master_key);

    /* The lanes divide the memory and size the threads a slice starts (kdf_slice):
     * in range by the loader's validation, so out of it only in an epoch built
     * by hand, a caller's bug */
    CHECK_ARG(
        epoch->params.lanes >= KDF_ARGON2_LANES_MIN
        && epoch->params.lanes <= KDF_ARGON2_LANES_MAX,
        "the epoch's lanes are in range (kdf_validate_params)"
    );

    /* Validation early-returns wipe `out_master_key` so the contract "every error
     * path leaves the buffer scrubbed" holds uniformly, even though no write
     * has happened yet — defense against future code drift that could move a
     * partial write above the validation gate. The `crypto_wipe` on a never-written
     * buffer is a free no-op in practice (the bytes are already whatever the
     * caller's stack frame had), but it documents the invariant. */
    if (passphrase_len == 0) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return error_create(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Argon2 carries the passphrase length in a `uint32_t` field; a `size_t`
     * value above UINT32_MAX would silently truncate to a different value mod
     * 2^32 and derive the wrong master key from the user's intended passphrase.
     * This boundary check is cheap insurance against a future caller that bypasses
     * sys/passphrase's 4 KiB UX cap. */
    if (passphrase_len > UINT32_MAX) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return error_create(
            ERR_INVALID_ARG,
            "Passphrase too long: %zu bytes (accepted up to %u bytes)",
            passphrase_len, (unsigned int) UINT32_MAX
        );
    }

    /* `memory` ∈ [8, 4096] MiB by the ref's validation, so the product is at
     * most 2^32 bytes, which fits size_t on the 64-bit hosts the static assert
     * above admits. */
    const size_t bytes = (size_t) epoch->params.memory * 1024U * 1024U;

    /* The work area: a mapping of its own, page-aligned (Argon2 wants u64-aligned
     * blocks), locked best-effort, wiped and unmapped at the end. */
    void *work_area = secure_alloc(bytes);
    if (!work_area) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return error_create(
            ERR_MEMORY,
            "Failed to map %zu MiB Argon2 work area: %s",
            (size_t) epoch->params.memory, strerror(errno)
        );
    }

    /* Build Argon2 inputs. `nb_blocks` is in 1024-byte Argon2 blocks: `memory`
     * MiB is `memory` * 1024 blocks. Bounded by KDF_ARGON2_MEMORY_MAX (= 4096 *
     * 1024 = 4M blocks), well within `uint32_t`. The lanes are the epoch's, every
     * preset's four (crypto/kdf.h kdf_presets). */
    const crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = (uint32_t) epoch->params.memory * 1024U,
        .nb_passes = epoch->params.passes,
        .nb_lanes  = epoch->params.lanes,
    };
    const crypto_argon2_inputs inputs = {
        .pass      = passphrase,
        .salt      = epoch->salt,
        .pass_size = (uint32_t) passphrase_len,
        .salt_size = (uint32_t) KDF_SALT_SIZE,
    };

    /* `kdf_argon2` returns void — no failure mode inside the derivation. After
     * return, out_master_key holds the derived key and work_area is
     * monocypher-zeroed; secure_free wipes it once more (the file header says
     * why) and unmaps it. */
    kdf_argon2(out_master_key, KDF_KEY_SIZE, work_area, config, inputs);
    secure_free(work_area, bytes);

    return NULL;
}

void kdf_siv_subkeys(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    const size_t profile_len = strlen(profile);

    /* Two independent keyed-BLAKE2b derivations under distinct CRYPTO_DOMAIN_*
     * tags. Independence is essential to the SIV construction; the domain tags
     * absorbed at MAC init are what deliver it. */
    crypto_mac_oneshot(
        out_mac_key, master_key, CRYPTO_DOMAIN_SIV_MAC,
        (const uint8_t *) profile, profile_len,
        NULL, 0
    );
    crypto_mac_oneshot(
        out_prf_key, master_key, CRYPTO_DOMAIN_SIV_PRF,
        (const uint8_t *) profile, profile_len,
        NULL, 0
    );
}
