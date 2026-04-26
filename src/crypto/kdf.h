/**
 * kdf.h - Key derivation
 *
 * Three derivations form the key hierarchy:
 *
 *   passphrase + balloon_params  →  master_key      (memory-hard, ~hundreds of ms)
 *   master_key + profile_name    →  profile_key     (cheap, one keyed hash)
 *   profile_key                  →  mac_key, prf_key (cheap, two KDF calls)
 *
 * The cipher layer never sees the master key or the profile key — it
 * receives the SIV subkeys directly. keymgr is the only consumer that
 * touches master_key, and only as long as it lives in its on-process cache.
 *
 * Error contract: on any error return, every output buffer this function
 * partially wrote is zeroed before return. Callers do not need defensive
 * zeroing on the error path; whatever was on the stack stays on the stack.
 */

#ifndef DOTTA_CRYPTO_KDF_H
#define DOTTA_CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "crypto/balloon.h"

/** All keys in the hierarchy share this size (single keyed-BLAKE2 output). */
#define KDF_KEY_SIZE 32

/* The master-key path is `balloon_derive` writing BALLOON_KEY_SIZE bytes
 * into a buffer the caller declared as `uint8_t[KDF_KEY_SIZE]`. The two
 * symbols live in independent headers for layering reasons, but the call
 * silently truncates or overruns if they ever drift apart — assert the
 * invariant once, here, where both values are visible. */
_Static_assert(
    BALLOON_KEY_SIZE == KDF_KEY_SIZE,
    "balloon and kdf must agree on key size — kdf_master_key writes "
    "BALLOON_KEY_SIZE bytes through a KDF_KEY_SIZE-sized output buffer"
);

/**
 * Derive the master key from a passphrase.
 *
 * Thin wrapper over balloon_derive. Lives in kdf rather than as a direct
 * call from keymgr because key derivation is a kdf-layer concern: keymgr
 * shouldn't have to know that the master comes from balloon while the
 * profile and SIV subkeys come from keyed BLAKE2. All three derivations
 * share the same `uint8_t[KDF_KEY_SIZE]` output shape, so callers don't
 * special-case the master.
 *
 * @param passphrase     Passphrase bytes (must not be NULL; len > 0)
 * @param passphrase_len Passphrase length in bytes
 * @param params         Balloon parameters
 * @param out_master_key Output buffer for 32-byte master key
 * @return Error or NULL on success
 */
error_t *kdf_master_key(
    const char *passphrase,
    size_t passphrase_len,
    balloon_params_t params,
    uint8_t out_master_key[KDF_KEY_SIZE]
);

/**
 * Derive a profile-specific key from the master key.
 *
 * Cheap: one keyed BLAKE2 over the profile name. Distinct profile names
 * yield independent profile keys; same name always yields the same key
 * under a given master.
 *
 * @param master_key      Master key (32 bytes)
 * @param profile         Profile name (must not be NULL; non-empty)
 * @param out_profile_key Output buffer for 32-byte profile key
 * @return Error or NULL on success
 */
error_t *kdf_profile_key(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_profile_key[KDF_KEY_SIZE]
);

/**
 * Derive the SIV MAC and PRF subkeys from a profile key.
 *
 * Two independent subkeys are required by the SIV construction:
 *   mac_key — keys the SIV computation over (path, plaintext)
 *   prf_key — keys the keystream-seed derivation from the SIV
 *
 * Cryptographic independence between the two is essential; deriving them
 * with distinct subkey_ids under the same context guarantees it.
 *
 * @param profile_key  Profile key (32 bytes)
 * @param out_mac_key  Output buffer for 32-byte MAC key
 * @param out_prf_key  Output buffer for 32-byte PRF key
 * @return Error or NULL on success
 */
error_t *kdf_siv_subkeys(
    const uint8_t profile_key[KDF_KEY_SIZE],
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
);

#endif /* DOTTA_CRYPTO_KDF_H */
