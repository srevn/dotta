/**
 * kdf.c - Key derivation implementation
 */

#include "crypto/kdf.h"

#include <hydrogen.h>
#include <string.h>

#include "base/error.h"
#include "crypto/balloon.h"

/* Context strings (8 bytes each, libhydrogen requirement). */
static const char CTX_PROFILE[8] = { 'p', 'r', 'o', 'f', 'i', 'l', 'e', ' ' };
static const char CTX_SIV[8] = { 'd', 'o', 't', 't', 'a', 's', 'i', 'v' };

error_t *kdf_master_key(
    const char *passphrase,
    size_t passphrase_len,
    balloon_params_t params,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(out_master_key);

    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    return balloon_derive(
        (const uint8_t *) passphrase,
        passphrase_len,
        params,
        out_master_key
    );
}

error_t *kdf_profile_key(
    const uint8_t master_key[KDF_KEY_SIZE],
    const char *profile,
    uint8_t out_profile_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(master_key);
    CHECK_NULL(profile);
    CHECK_NULL(out_profile_key);

    if (profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    /* Derive profile-specific key using keyed hashing
     *
     * We use hydro_hash_hash() with the master key as the key parameter.
     * This is a proper KDF for variable-length inputs (profile names).
     *
     * Security properties:
     * - Keyed BLAKE2 acts as a PRF (pseudorandom function)
     * - Different profile names → different keys (collision resistance)
     * - Requires master key (cannot derive without it)
     * - Per-profile cryptographic isolation
     *
     * This approach is more direct than hydro_kdf_derive_from_key() which
     * requires numeric subkey_id (not suitable for variable-length names).
     */
    int rc = hydro_hash_hash(
        out_profile_key,
        KDF_KEY_SIZE,
        profile,
        strlen(profile),
        CTX_PROFILE,        /* Context: "profile " */
        master_key          /* Master key as keying material */
    );

    if (rc != 0) {
        /* hash_hash may have streamed bytes into out_profile_key before
         * failing; wipe so callers never see partial key material on the
         * error path. */
        hydro_memzero(out_profile_key, KDF_KEY_SIZE);
        return ERROR(
            ERR_CRYPTO, "Failed to derive profile key for '%s'",
            profile
        );
    }
    return NULL;
}

/**
 * Derive subkeys for SIV construction
 *
 * Derives two independent subkeys from the profile key using KDF:
 *   mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")
 *   prf_key = KDF(profile_key, subkey_id=2, context="dottasiv")
 *
 * Cryptographic independence between the MAC key (used to compute the SIV
 * over the plaintext) and the PRF key (used to derive the keystream seed
 * from the SIV) is a critical security requirement for SIV constructions.
 *
 * @param profile_key Profile encryption key (32 bytes)
 * @param out_mac_key Output buffer for MAC key (32 bytes)
 * @param out_prf_key Output buffer for PRF key (32 bytes)
 * @return Error or NULL on success
 */
error_t *kdf_siv_subkeys(
    const uint8_t profile_key[KDF_KEY_SIZE],
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(profile_key);
    CHECK_NULL(out_mac_key);
    CHECK_NULL(out_prf_key);

    /* Derive MAC key (subkey_id=1). On failure, out_mac_key may have been
     * partially written; wipe it so callers see a clean error contract. */
    if (hydro_kdf_derive_from_key(
        out_mac_key, KDF_KEY_SIZE, /*subkey_id=*/ 1, CTX_SIV, profile_key
        ) != 0) {
        hydro_memzero(out_mac_key, KDF_KEY_SIZE);
        return ERROR(ERR_CRYPTO, "Failed to derive SIV MAC subkey");
    }

    /* Derive PRF key (subkey_id=2). On failure, out_mac_key holds a fully
     * valid subkey and out_prf_key may be partial — both must be wiped so
     * the error contract is uniform. */
    if (hydro_kdf_derive_from_key(
        out_prf_key, KDF_KEY_SIZE, /*subkey_id=*/ 2, CTX_SIV, profile_key
        ) != 0) {
        hydro_memzero(out_mac_key, KDF_KEY_SIZE);
        hydro_memzero(out_prf_key, KDF_KEY_SIZE);
        return ERROR(ERR_CRYPTO, "Failed to derive SIV PRF subkey");
    }

    return NULL;
}
