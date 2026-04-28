/**
 * kdf.c - Key derivation implementation
 *
 * Two derivations:
 *   1. `kdf_master_key`: passphrase → master_key via Argon2id. The
 *      only step where an attacker pays per-guess memory cost.
 *   2. `kdf_siv_subkeys`: master_key + profile → (mac_key, prf_key)
 *      via two domain-separated keyed-BLAKE2b calls.
 *
 * Argon2id work-area lifecycle:
 *   - aligned_alloc(_Alignof(uint64_t), memory_mib * 1024 * 1024).
 *     Size is always a multiple of 8 (1 MiB = 2^20), satisfying the
 *     aligned_alloc multiple-of-alignment rule. monocypher's
 *     `crypto_argon2` casts the work area to `blk *` (u64[128] per
 *     block) — 8-byte alignment is what the primitive requires.
 *   - Best-effort `mlock` to keep the work area off swap. Failure is
 *     non-fatal (the buffer is wiped before free regardless); on
 *     macOS the default RLIMIT_MEMLOCK is 64 KiB so failure is the
 *     common case. The advisory routes through `secure_mlock_warn`,
 *     a process-wide gate shared with keymgr and sys/passphrase.
 *   - Defense-in-depth wipe: monocypher already zeroes the work area
 *     on return, but we wipe again before free to defend against
 *     version drift, lane-rounding edge cases, and early-return paths
 *     where Argon2 never executed.
 *
 * Per-repository salt: the 32-byte `salt` parameter is generated once
 * at `dotta init` via `entropy_fill` (see KDF_SALT_SIZE for the 256-bit
 * choice) and stored at `refs/dotta/salt`, where it syncs with the
 * repository. This makes each dotta repo a distinct attack target: a
 * precomputation table built against one repo cannot be reused against
 * any other, even by an attacker who has both repos' encrypted blobs.
 * The salt is public — its job is uniqueness, not secrecy — and is
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

#include "base/error.h"
#include "base/secure.h"
#include "crypto/mac.h"

/* Plain `malloc` and `aligned_alloc` need 64-bit `size_t` to express
 * the 4 GiB Argon2 ceiling. On a 32-bit host, `(uint32_t) 4096 * 1024
 * * 1024` overflows to 0 silently. Refuse to build on 32-bit hosts so
 * the failure is at compile time, not at allocation time. */
_Static_assert(
    sizeof(size_t) >= 8,
    "dotta requires a 64-bit host for Argon2 work-area sizing"
);

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

error_t *kdf_master_key(
    const uint8_t *passphrase,
    size_t passphrase_len,
    const uint8_t salt[KDF_SALT_SIZE],
    uint16_t memory_mib,
    uint8_t passes,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(salt);
    CHECK_NULL(out_master_key);

    /* Validation early-returns wipe `out_master_key` so the contract
     * "every error path leaves the buffer scrubbed" holds uniformly,
     * even though no write has happened yet — defense against future
     * code drift that could move a partial write above the validation
     * gate. The `crypto_wipe` on a never-written buffer is a free
     * no-op in practice (the bytes are already whatever the caller's
     * stack frame had), but it documents the invariant. */
    if (passphrase_len == 0) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Argon2 carries the passphrase length in a `uint32_t` field; a
     * `size_t` value above UINT32_MAX would silently truncate to a
     * different value mod 2^32 and derive the wrong master key from
     * the user's intended passphrase. This boundary check is cheap
     * insurance against a future caller that bypasses sys/passphrase's
     * 4 KiB UX cap. */
    if (passphrase_len > UINT32_MAX) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(
            ERR_INVALID_ARG,
            "Passphrase too long: %zu bytes (accepted up to %u bytes)",
            passphrase_len, (unsigned int) UINT32_MAX
        );
    }

    /* Range-check params at the crypto boundary. cipher_peek_params
     * also calls kdf_validate_params before invoking us on the decrypt
     * path, but defense-in-depth here protects callers that haven't
     * yet been routed through cipher (e.g. fresh encrypts where the
     * config-load validation is the only earlier gate). */
    error_t *err = kdf_validate_params(memory_mib, passes);
    if (err) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return err;
    }

    /* memory_mib ∈ [8, 4096] (validated above); product is at most
     * 4096 * 2^20 = 2^32 bytes, fits size_t on the 64-bit hosts the
     * static assert above admits. */
    const size_t bytes = (size_t) memory_mib * 1024u * 1024u;

    /* Argon2 wants u64-aligned blocks. `aligned_alloc(_Alignof(uint64_t), bytes)`
     * makes the contract explicit; the multiple-of-alignment rule is
     * satisfied since `bytes` is a multiple of 1 MiB. */
    void *work_area = aligned_alloc(_Alignof(uint64_t), bytes);
    if (!work_area) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate %zu MiB Argon2 work area: %s",
            (size_t) memory_mib, strerror(errno)
        );
    }

    /* Best-effort mlock the entire work area. mlock pins pages so the
     * key-derivation transient state cannot leak to swap. On macOS the
     * default RLIMIT_MEMLOCK is 64 KiB — every non-trivial Argon2
     * setting exceeds that and falls through to the advisory path.
     * The advisory is gated by a process-wide `static bool` inside
     * `secure_mlock_warn`, so the user sees one warning per
     * process regardless of how many subsystems hit the limit. */
    bool mlocked = false;
    if (mlock(work_area, bytes) == 0) {
        mlocked = true;
    } else {
        secure_mlock_warn(
            errno, "%u MiB Argon2 work area", (unsigned) memory_mib
        );
    }

    /* Build Argon2 inputs.
     *
     * lanes = 1: monocypher accepts nb_lanes > 1 only for output
     * compatibility with parallel Argon2 implementations — it
     * simulates lanes sequentially, so any value > 1 costs strictly
     * more time for the same memory hardness. RFC 9106's lanes = 4
     * recommendation assumes real parallelism that monocypher does
     * not provide. With lanes = 1 the memory hardness metric is
     * `nb_blocks * passes`; sketch §3.2 documents how the preset
     * numbers compensate via pass count.
     *
     * `nb_blocks` is in 1024-byte Argon2 blocks: memory_mib MiB =
     * memory_mib * 1024 blocks. Bounded by KDF_ARGON2_MEMORY_MIB_MAX
     * (= 4096 * 1024 = 4M blocks), well within `uint32_t`. */
    const crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = (uint32_t) memory_mib * 1024u,
        .nb_passes = passes,
        .nb_lanes  = 1,
    };
    const crypto_argon2_inputs inputs = {
        .pass      = passphrase,
        .salt      = salt,
        .pass_size = (uint32_t) passphrase_len,
        .salt_size = (uint32_t) KDF_SALT_SIZE,
    };

    /* `crypto_argon2` returns void — no failure mode inside the
     * primitive. After return, out_master_key holds the derived key
     * and work_area is monocypher-zeroed. */
    crypto_argon2(
        out_master_key, KDF_KEY_SIZE, work_area,
        config, inputs, crypto_argon2_no_extras
    );

    /* Defense-in-depth wipe before free; cost is negligible against
     * the seconds-scale Argon2 runtime. */
    crypto_wipe(work_area, bytes);
    if (mlocked) munlock(work_area, bytes);
    free(work_area);

    return NULL;
}

error_t *kdf_siv_subkeys(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(master_key);
    CHECK_NULL(profile);
    CHECK_NULL(out_mac_key);
    CHECK_NULL(out_prf_key);

    if (profile[0] == '\0') {
        /* Wipe before early return — same scrub-on-every-error
         * contract as kdf_master_key. */
        crypto_wipe(out_mac_key, KDF_KEY_SIZE);
        crypto_wipe(out_prf_key, KDF_KEY_SIZE);
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    const size_t profile_len = strlen(profile);

    /* Two independent keyed-BLAKE2b derivations under distinct
     * CRYPTO_DOMAIN_* tags. Independence is essential to the SIV
     * construction; the domain tags absorbed at MAC init are what
     * deliver it. */
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

    /* `crypto_mac_oneshot` cannot fail today; the `error_t *` return
     * stays for forward-compat with future validation steps. */
    return NULL;
}
