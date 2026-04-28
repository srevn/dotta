/**
 * kdf.h - Key derivation
 *
 * Two derivation steps:
 *
 *     passphrase + (memory_mib, passes)  →  master_key   (Argon2id, RFC 9106)
 *     master_key + profile_name          →  (mac_key, prf_key)
 *                                            (two domain-separated
 *                                             keyed-BLAKE2b calls)
 *
 * keymgr is the only consumer that holds `master_key`; cipher receives
 * only the (mac_key, prf_key) pair derived per encrypt/decrypt
 * operation. Independence between mac_key and prf_key comes from
 * distinct `crypto_domain_t` tags absorbed at MAC init.
 *
 * Memory hardness is the only attacker-bounding work in the KDF.
 * Argon2id's `memory_mib × passes` product bounds the per-guess cost;
 * everything else (validation, framing, mlock attempts) is hygiene
 * around that one primitive call.
 *
 * Argon2 parameter bounds: the maxima below are DoS bounds, not
 * representational. Cipher blobs carry their own params in the
 * authenticated header, and `cipher_peek_params` validates against
 * KDF_ARGON2_*_MAX BEFORE any Argon2 work area is allocated — without
 * this gate, an attacker-planted blob with `memory_mib = 65535` would
 * force a 64 GiB allocation before the SIV check fires.
 *
 * Error contract: every error path scrubs partially-written output
 * buffers via `crypto_wipe` before return. Callers do not need
 * defensive zeroing on the error path.
 */

#ifndef DOTTA_CRYPTO_KDF_H
#define DOTTA_CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "crypto/mac.h"

#define KDF_KEY_SIZE 32            /* All keys in the hierarchy share this size. */
#define KDF_SALT_SIZE 32           /* Argon2id salt size — 32 bytes (256 bits). */

_Static_assert(
    KDF_KEY_SIZE == CRYPTO_KEY_SIZE,
    "kdf and mac must agree on key size"
);
_Static_assert(
    KDF_KEY_SIZE == CRYPTO_MAC_SIZE,
    "kdf and mac must agree on output size"
);

/**
 * Argon2id parameter bounds.
 *
 * `_MIN` is dotta's operational security floor (well above the Argon2
 * spec floor of ~8 KiB). `_MAX` is a DoS bound (see file-level
 * "Argon2 parameter bounds"). All values fit `uint16_t` / `uint8_t`
 * for the on-disk blob header.
 */
#define KDF_ARGON2_MEMORY_MIB_MIN 8       /* security floor */
#define KDF_ARGON2_MEMORY_MIB_MAX 4096    /* DoS bound: 4× paranoid (1024 MiB) */
#define KDF_ARGON2_PASSES_MIN     1
#define KDF_ARGON2_PASSES_MAX     20      /* DoS bound: RFC 9106 high-end */

/**
 * Validate Argon2id parameters against KDF_ARGON2_*_MIN/MAX.
 *
 * Exposed so `cipher_peek_params` can apply the same defense-in-depth
 * check at the blob-parse step. Returns ERR_CRYPTO on out-of-range
 * values so a tampered blob surfaces as an authentication-class error
 * rather than leaking format detail through the error code.
 *
 * @param memory_mib Argon2 memory in MiB
 * @param passes     Argon2 pass count
 * @return Error or NULL on success
 */
error_t *kdf_validate_params(uint16_t memory_mib, uint8_t passes);

/**
 * Derive the master key from a passphrase using Argon2id.
 *
 * Argon2id (RFC 9106), single-lane. The 32-byte `salt` is the
 * per-repository random tag stored at `refs/dotta/salt:salt`;
 * uniqueness across repositories forecloses cross-installation
 * precomputation attacks (a precomputed table built against one
 * dotta repo is useless against any other).
 *
 * Allocates `memory_mib * 1024 * 1024` bytes via aligned_alloc and
 * best-effort mlocks the work area; failure surfaces a one-time-per-
 * process advisory. The work area is wiped before free on every path.
 *
 * Validates `memory_mib` / `passes` against KDF_ARGON2_*_MIN/MAX
 * before allocation, and `passphrase_len` against UINT32_MAX (Argon2's
 * representational limit) to prevent silent truncation. Every error
 * path scrubs `out_master_key` before return.
 *
 * @param passphrase     Passphrase bytes (non-NULL; len > 0)
 * @param passphrase_len Passphrase length in bytes (≤ UINT32_MAX)
 * @param salt           Per-repo Argon2id salt (32 bytes; non-NULL)
 * @param memory_mib     Argon2 memory budget in MiB
 * @param passes         Argon2 pass count
 * @param out_master_key Output buffer for 32-byte master key
 * @return Error or NULL on success
 */
error_t *kdf_master_key(
    const uint8_t *passphrase,
    size_t passphrase_len,
    const uint8_t salt[KDF_SALT_SIZE],
    uint16_t memory_mib,
    uint8_t passes,
    uint8_t out_master_key[KDF_KEY_SIZE]
);

/**
 * Derive (mac_key, prf_key) for a profile from the master key.
 *
 *   mac_key = MAC(master, CRYPTO_DOMAIN_SIV_MAC, profile)
 *   prf_key = MAC(master, CRYPTO_DOMAIN_SIV_PRF, profile)
 *
 * Subkey independence is essential to the SIV construction and comes
 * from the distinct domain tags. Returns `error_t *` rather than
 * `void` for forward-compat (today `crypto_mac_oneshot` cannot fail).
 * Output buffers are wiped on any error path.
 *
 * @param master_key  Master key (32 bytes)
 * @param profile     Profile name (non-NULL, non-empty)
 * @param out_mac_key Output buffer for 32-byte MAC key
 * @param out_prf_key Output buffer for 32-byte PRF key
 * @return Error or NULL on success
 */
error_t *kdf_siv_subkeys(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
);

#endif /* DOTTA_CRYPTO_KDF_H */
