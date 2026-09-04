/**
 * kdf.h - Key derivation
 *
 * Two derivation steps:
 *
 *     passphrase + epoch          →  master_key   (Argon2id, RFC 9106)
 *     master_key + profile_name   →  (mac_key, prf_key)
 *                                     (two domain-separated keyed-BLAKE2b calls)
 *
 * The epoch is the repository's contribution to the master key: everything the
 * derivation takes but the passphrase — the 32-byte salt and the Argon2id pair
 * (memory_mib, passes) — as one value with one owner. It is minted once, at `dotta
 * init` (from a preset below), synced as `refs/dotta/epoch` (infra/epoch), and
 * immutable for as long as ciphertext sealed under it exists: a master is a
 * function of (passphrase, epoch) and nothing else, so two machines on one
 * repository derive one master from one passphrase, and a change of strength is
 * a new epoch — every blob re-sealed — never a second master beside the first.
 *
 * keymgr is the only consumer that holds `master_key`; cipher receives only the
 * (mac_key, prf_key) pair derived per encrypt/decrypt operation. Independence
 * between mac_key and prf_key comes from distinct `crypto_domain_t` tags absorbed
 * at MAC init.
 *
 * Memory hardness is the only attacker-bounding work in the KDF. Argon2id's
 * `memory_mib × passes` product bounds the per-guess cost; everything else
 * (framing, the fingerprint, the locked work area) is hygiene around that one
 * primitive call.
 *
 * Argon2 parameter bounds: the pair enters the process at two boundaries only —
 * a preset, in range by construction, when `init` mints; and the ref, validated
 * with `kdf_validate_params` where `infra/epoch` loads or fetches it. Everything
 * downstream trusts the epoch it is handed. The ceiling is an allocation bound
 * on the ref's own bytes, which the census and the reconcile already protect;
 * no blob carries parameters, so nothing pulled from a remote can choose the work.
 *
 * Error contract: every error path scrubs partially-written output buffers via
 * `crypto_wipe` before return. Callers do not need defensive zeroing on the error
 * path.
 */

#ifndef DOTTA_CRYPTO_KDF_H
#define DOTTA_CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "crypto/mac.h"

#define KDF_KEY_SIZE 32            /* All keys in the hierarchy share this size. */
#define KDF_SALT_SIZE 32           /* Argon2id salt size — 32 bytes (256 bits). */
#define KDF_PARAMS_SIZE 3          /* LE16 memory_mib ‖ passes — see kdf_params_store. */
#define KDF_EPOCH_FP_SIZE 8        /* Epoch fingerprint — see kdf_epoch_fingerprint. */

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
 * `_MIN` is dotta's operational security floor (well above the Argon2 spec floor
 * of ~8 KiB). `_MAX` is an allocation bound on the ref's bytes (see file-level
 * "Argon2 parameter bounds"). All values fit `uint16_t` / `uint8_t` for the ref's
 * params blob.
 */
#define KDF_ARGON2_MEMORY_MIB_MIN 8       /* security floor */
#define KDF_ARGON2_MEMORY_MIB_MAX 4096    /* allocation bound: 4× paranoid (1024 MiB) */
#define KDF_ARGON2_PASSES_MIN     1
#define KDF_ARGON2_PASSES_MAX     20      /* RFC 9106 high-end */

/**
 * The three tuning points the derivation is offered at.
 *
 * `dotta init --strength <name>` mints the repository's epoch with one of them;
 * `dotta key status` names an epoch's pair back by the row that matches it, and
 * a pair no row names prints as its numbers. Wall-clock figures are indicative
 * — measured on a 2024-era laptop, they scale with single-thread memory bandwidth
 * and L3 size. Adding a preset is a row; the lookups are linear over
 * KDF_PRESET_COUNT.
 */
typedef struct kdf_preset {
    const char *name;
    uint16_t memory_mib;
    uint8_t passes;
} kdf_preset_t;

#define KDF_PRESET_COUNT   3
#define KDF_PRESET_DEFAULT "balanced"   /* what `init` mints without --strength */

extern const kdf_preset_t kdf_presets[KDF_PRESET_COUNT];

/**
 * The epoch: the repository's contribution to the master key.
 *
 * The salt and the Argon2id pair, as `infra/epoch` loads them from the ref. Public
 * — the salt's job is uniqueness across repositories, not secrecy, and the pair
 * is the cost of a guess — so an epoch is ordinary input bytes: no mlock, no
 * wipe. Passed by pointer everywhere a salt went.
 */
typedef struct kdf_epoch {
    uint8_t salt[KDF_SALT_SIZE];
    uint16_t memory_mib;
    uint8_t passes;
} kdf_epoch_t;

/**
 * Validate an Argon2id pair against KDF_ARGON2_*_MIN/MAX.
 *
 * The ref's gate: `infra/epoch` runs it on the params blob it loads or fetches,
 * before the epoch reaches anything that derives under it. Returns ERR_CRYPTO
 * on an out-of-range value so a damaged or hostile ref surfaces as a crypto-class
 * error.
 *
 * @param memory_mib Argon2 memory in MiB
 * @param passes     Argon2 pass count
 * @return Error or NULL on success
 */
error_t *kdf_validate_params(uint16_t memory_mib, uint8_t passes);

/**
 * Encode / decode the Argon2id pair as the ref's params blob.
 *
 * Three bytes: LE16 memory_mib ‖ passes — the bytes `refs/dotta/epoch:params`
 * holds and the tail of the fingerprint's input, so the ref and the fingerprint
 * spell the pair one way. The decode does not validate; `kdf_validate_params`
 * is the boundary's, applied to what came back.
 *
 * @param out        Output buffer for KDF_PARAMS_SIZE bytes
 * @param memory_mib Argon2 memory in MiB
 * @param passes     Argon2 pass count
 */
void kdf_params_store(
    uint8_t out[KDF_PARAMS_SIZE],
    uint16_t memory_mib,
    uint8_t passes
);
void kdf_params_load(
    const uint8_t in[KDF_PARAMS_SIZE],
    uint16_t *out_memory_mib,
    uint8_t *out_passes
);

/**
 * Compute the public 8-byte fingerprint of an epoch.
 *
 * Unkeyed BLAKE2b with an 8-byte digest over salt ‖ params (35 bytes; the output
 * length is part of BLAKE2b's parameter block, so this cannot collide with any
 * other BLAKE2b use in the tree — every other call produces 32 bytes). The
 * fingerprint is *identity*, not key material: `cipher_encrypt` stamps it into
 * the authenticated blob header so any ciphertext names the epoch that keyed
 * it, letting key-free readers (the ciphertext census, decrypt's gate, the session
 * file's name) attribute a blob to an epoch without a passphrase. 64 bits is
 * far beyond collision concerns for the handful of epochs a repository ever sees,
 * and — like the epoch itself — the fingerprint is public.
 *
 * Cannot fail: pure hashing, no allocation, no validation.
 *
 * @param epoch  The epoch (non-NULL)
 * @param out_fp Output buffer for the 8-byte fingerprint
 */
void kdf_epoch_fingerprint(
    const kdf_epoch_t *epoch,
    uint8_t out_fp[KDF_EPOCH_FP_SIZE]
);

/**
 * Derive the master key from a passphrase under an epoch, using Argon2id.
 *
 * Argon2id (RFC 9106), single-lane, over the epoch's salt at the epoch's
 * (memory_mib, passes). The salt's uniqueness across repositories forecloses
 * cross-installation precomputation (a table built against one dotta repo is
 * useless against any other); the pair is the per-guess cost.
 *
 * Maps `memory_mib * 1024 * 1024` bytes for the work area with `secure_alloc`
 * (base/secure.h) — locked best-effort, with the one-time advisory on failure —
 * and ends it with `secure_free`: wiped and unmapped on every path.
 *
 * `epoch` is a loaded epoch: its pair is in range by the ref's validation
 * (`infra/epoch`) or a preset's construction, and is not re-checked here.
 * `passphrase_len` is checked against UINT32_MAX (Argon2's representational limit)
 * to prevent silent truncation. Every error path scrubs `out_master_key` before
 * return.
 *
 * @param passphrase     Passphrase bytes (non-NULL; len > 0)
 * @param passphrase_len Passphrase length in bytes (≤ UINT32_MAX)
 * @param epoch          The repository's epoch (non-NULL)
 * @param out_master_key Output buffer for 32-byte master key
 * @return Error or NULL on success
 */
error_t *kdf_master_key(
    const uint8_t *passphrase,
    size_t passphrase_len,
    const kdf_epoch_t *epoch,
    uint8_t out_master_key[KDF_KEY_SIZE]
);

/**
 * Derive (mac_key, prf_key) for a profile from the master key.
 *
 *   mac_key = MAC(master, CRYPTO_DOMAIN_SIV_MAC, profile) prf_key = MAC(master,
 *   CRYPTO_DOMAIN_SIV_PRF, profile)
 *
 * Subkey independence is essential to the SIV construction and comes from the
 * distinct domain tags. Cannot fail: two keyed BLAKE2b calls. `profile` is a
 * ref name — non-NULL, and non-empty by construction at every caller. Nothing
 * checks the second and nothing needs to: the name is absorbed under a length
 * prefix (crypto/mac.h), so an empty one would derive a valid nameless domain
 * rather than collide with a named profile's.
 *
 * @param master_key  Master key (32 bytes)
 * @param profile     Profile name (non-NULL)
 * @param out_mac_key Output buffer for 32-byte MAC key
 * @param out_prf_key Output buffer for 32-byte PRF key
 */
void kdf_siv_subkeys(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
);

#endif /* DOTTA_CRYPTO_KDF_H */
