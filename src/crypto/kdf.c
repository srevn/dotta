/**
 * kdf.c - Key derivation implementation
 *
 * Two derivations:
 *   1. `kdf_master_key`: passphrase + epoch → master_key via Argon2id. The only
 *      step where an attacker pays per-guess memory cost.
 *   2. `kdf_siv_subkeys`: master_key + profile → (mac_key, prf_key) via two
 *      domain-separated keyed-BLAKE2b calls.
 *
 * Argon2id work-area lifecycle: one `secure_alloc` mapping of memory_mib MiB
 * (base/secure.h) — page-aligned, which is more than the u64 alignment
 * monocypher's `crypto_argon2` requires of its `blk *` (u64[128] per block);
 * locked against swap best-effort, with the one advisory the process prints when
 * a lock fails; wiped and unmapped by `secure_free`. monocypher zeroes the work
 * area itself on return, so the bytes are wiped twice: the second pass is
 * `secure_free`'s own, paid (about seven percent of a cold derivation) so that
 * every secret-bearing mapping in the tree ends the one way and no site reasons
 * about which primitive wiped what.
 *
 * The epoch: the salt is generated once at `dotta init` via `entropy_fill` (see
 * KDF_SALT_SIZE for the 256-bit choice) beside the pair `init` was told to mint
 * with, and both are stored at `refs/dotta/epoch`, where they sync with the
 * repository. This makes each dotta repo a distinct attack target: a precomputation
 * table built against one repo cannot be reused against any other, even by an
 * attacker who has both repos' encrypted blobs. The epoch is public — the salt's
 * job is uniqueness, not secrecy, and the pair is the cost of a guess — and is
 * treated as ordinary input bytes (no mlock/wipe).
 */

#include "crypto/kdf.h"

#include <errno.h>
#include <monocypher.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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

const kdf_preset_t kdf_presets[KDF_PRESET_COUNT] = {
    { "fast",     64,   3 },  /* ~250–400 ms; CI / test */
    { "balanced", 256,  3 },  /* ~1.0 s; recommended */
    { "paranoid", 1024, 4 },  /* ~4–6 s; slow but firm */
};

error_t *kdf_validate_params(uint16_t memory_mib, uint8_t passes) {
    if (memory_mib < KDF_ARGON2_MEMORY_MIB_MIN
        || memory_mib > KDF_ARGON2_MEMORY_MIB_MAX) {
        return ERROR(
            ERR_CRYPTO,
            "Argon2 memory %u MiB out of range (%u..%u)",
            (unsigned) memory_mib,
            (unsigned) KDF_ARGON2_MEMORY_MIB_MIN,
            (unsigned) KDF_ARGON2_MEMORY_MIB_MAX
        );
    }

    if (passes < KDF_ARGON2_PASSES_MIN || passes > KDF_ARGON2_PASSES_MAX) {
        return ERROR(
            ERR_CRYPTO,
            "Argon2 passes %u out of range (%u..%u)",
            (unsigned) passes,
            (unsigned) KDF_ARGON2_PASSES_MIN,
            (unsigned) KDF_ARGON2_PASSES_MAX
        );
    }

    return NULL;
}

void kdf_params_store(
    uint8_t out[KDF_PARAMS_SIZE],
    uint16_t memory_mib,
    uint8_t passes
) {
    store_le16(out, memory_mib);
    out[2] = passes;
}

void kdf_params_load(
    const uint8_t in[KDF_PARAMS_SIZE],
    uint16_t *out_memory_mib,
    uint8_t *out_passes
) {
    *out_memory_mib = load_le16(in);
    *out_passes = in[2];
}

void kdf_epoch_fingerprint(
    const kdf_epoch_t *epoch,
    uint8_t out_fp[KDF_EPOCH_FP_SIZE]
) {
    /* Public identity of a public value: plain BLAKE2b-8 over the epoch's canonical
     * bytes — the salt, then the params as the ref spells them. No key, no wipe.
     * The 8-byte output length is baked into BLAKE2b's parameter block, giving
     * this use domain separation from every 32-byte derivation for free. */
    uint8_t params[KDF_PARAMS_SIZE];
    kdf_params_store(params, epoch->memory_mib, epoch->passes);

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KDF_EPOCH_FP_SIZE);
    crypto_blake2b_update(&ctx, epoch->salt, KDF_SALT_SIZE);
    crypto_blake2b_update(&ctx, params, KDF_PARAMS_SIZE);
    crypto_blake2b_final(&ctx, out_fp);
}

error_t *kdf_master_key(
    const uint8_t *passphrase,
    size_t passphrase_len,
    const kdf_epoch_t *epoch,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(epoch);
    CHECK_NULL(out_master_key);

    /* Validation early-returns wipe `out_master_key` so the contract "every error
     * path leaves the buffer scrubbed" holds uniformly, even though no write
     * has happened yet — defense against future code drift that could move a
     * partial write above the validation gate. The `crypto_wipe` on a never-written
     * buffer is a free no-op in practice (the bytes are already whatever the
     * caller's stack frame had), but it documents the invariant. */
    if (passphrase_len == 0) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Argon2 carries the passphrase length in a `uint32_t` field; a `size_t`
     * value above UINT32_MAX would silently truncate to a different value mod
     * 2^32 and derive the wrong master key from the user's intended passphrase.
     * This boundary check is cheap insurance against a future caller that bypasses
     * sys/passphrase's 4 KiB UX cap. */
    if (passphrase_len > UINT32_MAX) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(
            ERR_INVALID_ARG,
            "Passphrase too long: %zu bytes (accepted up to %u bytes)",
            passphrase_len, (unsigned int) UINT32_MAX
        );
    }

    /* memory_mib ∈ [8, 4096] by the ref's validation; product is at most 4096 *
     * 2^20 = 2^32 bytes, fits size_t on the 64-bit hosts the static assert above
     * admits. */
    const size_t bytes = (size_t) epoch->memory_mib * 1024U * 1024U;

    /* The work area: a mapping of its own, page-aligned (Argon2 wants u64-aligned
     * blocks), locked best-effort, wiped and unmapped at the end. */
    void *work_area = secure_alloc(bytes);
    if (!work_area) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(
            ERR_MEMORY,
            "Failed to map %zu MiB Argon2 work area: %s",
            (size_t) epoch->memory_mib, strerror(errno)
        );
    }

    /* Build Argon2 inputs.
     *
     * lanes = 1: monocypher accepts nb_lanes > 1 only for output compatibility
     * with parallel Argon2 implementations — it simulates lanes sequentially,
     * so any value > 1 costs strictly more time for the same memory hardness.
     * RFC 9106's lanes = 4 recommendation assumes real parallelism that monocypher
     * does not provide. With lanes = 1 the memory hardness metric is `nb_blocks
     * * passes`; the presets compensate via pass count.
     *
     * `nb_blocks` is in 1024-byte Argon2 blocks: memory_mib MiB = memory_mib *
     * 1024 blocks. Bounded by KDF_ARGON2_MEMORY_MIB_MAX (= 4096 * 1024 = 4M
     * blocks), well within `uint32_t`. */
    const crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = (uint32_t) epoch->memory_mib * 1024U,
        .nb_passes = epoch->passes,
        .nb_lanes  = 1,
    };
    const crypto_argon2_inputs inputs = {
        .pass      = passphrase,
        .salt      = epoch->salt,
        .pass_size = (uint32_t) passphrase_len,
        .salt_size = (uint32_t) KDF_SALT_SIZE,
    };

    /* `crypto_argon2` returns void — no failure mode inside the primitive. After
     * return, out_master_key holds the derived key and work_area is
     * monocypher-zeroed; secure_free wipes it once more (the file header says
     * why) and unmaps it. */
    crypto_argon2(
        out_master_key, KDF_KEY_SIZE, work_area,
        config, inputs, crypto_argon2_no_extras
    );
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
