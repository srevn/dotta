/**
 * encryption.c - Cryptographic primitives implementation
 */

#include "crypto/encryption.h"

#include <hydrogen.h>
#include <string.h>

#include "base/error.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

/* File format constants */
static const unsigned char MAGIC_HEADER[8] = {
    'D', 'O', 'T', 'T', 'A',   /* Magic: "DOTTA" */
    ENCRYPTION_VERSION,        /* Version byte */
    0x00, 0x00                 /* Reserved (padding to 8 bytes) */
};

/**
 * Derive subkeys for SIV construction (internal helper)
 *
 * Derives two independent subkeys from the profile key using KDF:
 *   mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")
 *   ctr_key = KDF(profile_key, subkey_id=2, context="dottasiv")
 *
 * This ensures cryptographic independence between the MAC and stream cipher keys,
 * a critical security requirement for SIV constructions.
 *
 * @param profile_key Profile encryption key (32 bytes)
 * @param out_mac_key Output buffer for MAC key (32 bytes)
 * @param out_ctr_key Output buffer for CTR key (32 bytes)
 * @return Error or NULL on success
 */
static error_t *derive_siv_subkeys(
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    uint8_t out_mac_key[32],
    uint8_t out_ctr_key[32]
) {
    /* Derive MAC key (subkey_id=1) */
    if (hydro_kdf_derive_from_key(out_mac_key, 32, 1,
                                   ENCRYPTION_CTX_SIV_KDF, profile_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive MAC key");
    }

    /* Derive CTR key (subkey_id=2) */
    if (hydro_kdf_derive_from_key(out_ctr_key, 32, 2,
                                   ENCRYPTION_CTX_SIV_KDF, profile_key) != 0) {
        hydro_memzero(out_mac_key, 32);
        return ERROR(ERR_CRYPTO, "Failed to derive CTR key");
    }

    return NULL;
}

/**
 * Derive deterministic stream seed from path (internal helper)
 *
 * Derives a deterministic seed for the stream cipher from the CTR key and storage path:
 *   stream_seed = HMAC(ctr_key, storage_path, context="dottactr")
 *
 * This binds the keystream to the specific file path, ensuring different files
 * (even with identical content) use different keystreams.
 *
 * @param ctr_key CTR subkey (32 bytes)
 * @param storage_path File path in profile (e.g., "home/.bashrc")
 * @param out_seed Output buffer for stream seed (32 bytes)
 * @return Error or NULL on success
 */
static error_t *derive_stream_seed(
    const uint8_t ctr_key[32],
    const char *storage_path,
    uint8_t out_seed[32]
) {
    if (hydro_hash_hash(out_seed, 32,
                        (const uint8_t *)storage_path, strlen(storage_path),
                        ENCRYPTION_CTX_SIV_CTR, ctr_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive stream seed");
    }

    return NULL;
}

/**
 * Compute SIV/MAC over associated data and ciphertext (internal helper)
 *
 * Computes the SIV (Synthetic IV) as a MAC over:
 *   siv = HMAC(mac_key, storage_path || ciphertext, context="dottamac")
 *
 * The storage_path is authenticated as associated data, binding the ciphertext
 * to its intended location.
 *
 * @param mac_key MAC subkey (32 bytes)
 * @param storage_path File path in profile (authenticated associated data)
 * @param ciphertext Encrypted data
 * @param ciphertext_len Ciphertext length
 * @param out_siv Output buffer for SIV/MAC (32 bytes)
 * @return Error or NULL on success
 */
static error_t *compute_siv(
    const uint8_t mac_key[32],
    const char *storage_path,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    uint8_t out_siv[32]
) {
    hydro_hash_state mac_state;

    /* Initialize MAC with mac_key */
    if (hydro_hash_init(&mac_state, ENCRYPTION_CTX_SIV_MAC, mac_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to initialize MAC computation");
    }

    /* Authenticate storage_path (associated data) */
    hydro_hash_update(&mac_state, (const uint8_t *)storage_path, strlen(storage_path));

    /* Authenticate ciphertext */
    hydro_hash_update(&mac_state, ciphertext, ciphertext_len);

    /* Finalize to get SIV */
    hydro_hash_final(&mac_state, out_siv, 32);

    /* Clear MAC state */
    hydro_memzero(&mac_state, sizeof(mac_state));

    return NULL;
}

error_t *encryption_init(void) {
    if (hydro_init() != 0) {
        return ERROR(ERR_CRYPTO, "Failed to initialize libhydrogen");
    }
    return NULL;
}

error_t *encryption_derive_master_key(
    const char *passphrase,
    size_t passphrase_len,
    uint64_t opslimit,
    size_t memlimit,
    uint8_t threads,
    uint8_t out_master_key[ENCRYPTION_MASTER_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(out_master_key);

    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Use zero master key for hydro_pwhash (we derive everything from passphrase)
     *
     * Note: Zero master key is correct here because we're doing direct key
     * derivation, not password storage. The master key parameter is only
     * needed when creating encrypted password representatives for storage.
     * See libhydrogen Password-hashing.md for details. */
    static const uint8_t zero_master[hydro_pwhash_MASTERKEYBYTES] = {0};

    int result = hydro_pwhash_deterministic(
        out_master_key,
        ENCRYPTION_MASTER_KEY_SIZE,
        passphrase,
        passphrase_len,
        ENCRYPTION_CTX_PWHASH,
        zero_master,
        opslimit,
        memlimit,
        threads
    );

    if (result != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive master key from passphrase");
    }

    return NULL;
}

error_t *encryption_derive_profile_key(
    const uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE],
    const char *profile_name,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
) {
    CHECK_NULL(master_key);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_profile_key);

    if (profile_name[0] == '\0') {
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
    size_t name_len = strlen(profile_name);

    int result = hydro_hash_hash(
        out_profile_key,
        ENCRYPTION_PROFILE_KEY_SIZE,
        profile_name,
        name_len,
        ENCRYPTION_CTX_KDF,  /* Context: "profile " */
        master_key           /* Master key as keying material */
    );

    if (result != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive profile key for: %s", profile_name);
    }

    return NULL;
}

error_t *encryption_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t **out_ciphertext
) {
    CHECK_NULL(plaintext);
    CHECK_NULL(profile_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    error_t *err = NULL;
    uint8_t mac_key[32] = {0};
    uint8_t ctr_key[32] = {0};
    uint8_t stream_seed[32] = {0};
    uint8_t *keystream = NULL;
    unsigned char *ciphertext = NULL;
    buffer_t *output = NULL;

    /* Calculate output size with overflow detection */
    if (plaintext_len > SIZE_MAX - ENCRYPTION_OVERHEAD) {
        return ERROR(ERR_INVALID_ARG,
                    "Plaintext too large (size_t overflow): %zu bytes",
                    plaintext_len);
    }
    size_t total_len = ENCRYPTION_HEADER_SIZE + ENCRYPTION_SIV_SIZE + plaintext_len;

    /* Step 1: Derive MAC and CTR subkeys from profile key */
    err = derive_siv_subkeys(profile_key, mac_key, ctr_key);
    if (err) {
        goto cleanup;
    }

    /* Step 2: Derive deterministic stream seed from CTR key and path */
    err = derive_stream_seed(ctr_key, storage_path, stream_seed);
    if (err) {
        goto cleanup;
    }

    /* Step 3: Generate deterministic keystream */
    keystream = malloc(plaintext_len);
    if (!keystream && plaintext_len > 0) {
        err = ERROR(ERR_MEMORY, "Failed to allocate keystream buffer");
        goto cleanup;
    }

    if (plaintext_len > 0) {
        hydro_random_buf_deterministic(keystream, plaintext_len, stream_seed);
    }

    /* Step 4: Encrypt plaintext by XORing with keystream */
    ciphertext = malloc(plaintext_len);
    if (!ciphertext && plaintext_len > 0) {
        err = ERROR(ERR_MEMORY, "Failed to allocate ciphertext buffer");
        goto cleanup;
    }

    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }

    /* Step 5: Compute SIV/MAC over storage_path || ciphertext */
    uint8_t siv[ENCRYPTION_SIV_SIZE];
    err = compute_siv(mac_key, storage_path, ciphertext, plaintext_len, siv);
    if (err) {
        goto cleanup;
    }

    /* Step 6: Assemble output: [Magic Header][SIV][Ciphertext] */
    output = buffer_create_with_capacity(total_len);
    if (!output) {
        err = ERROR(ERR_MEMORY, "Failed to allocate encryption buffer");
        goto cleanup;
    }

    /* Write magic header */
    err = buffer_append(output, MAGIC_HEADER, sizeof(MAGIC_HEADER));
    if (err) {
        err = error_wrap(err, "Failed to write magic header");
        goto cleanup;
    }

    /* Write SIV */
    err = buffer_append(output, siv, sizeof(siv));
    if (err) {
        err = error_wrap(err, "Failed to write SIV");
        goto cleanup;
    }

    /* Write ciphertext */
    if (plaintext_len > 0) {
        err = buffer_append(output, ciphertext, plaintext_len);
        if (err) {
            err = error_wrap(err, "Failed to write ciphertext");
            goto cleanup;
        }
    }

    *out_ciphertext = output;
    output = NULL;  /* Transfer ownership, don't free */

cleanup:
    /* Securely clear sensitive data */
    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(ctr_key, sizeof(ctr_key));
    hydro_memzero(stream_seed, sizeof(stream_seed));
    hydro_memzero(siv, sizeof(siv));

    if (keystream) {
        hydro_memzero(keystream, plaintext_len);
        free(keystream);
    }

    if (ciphertext) {
        hydro_memzero(ciphertext, plaintext_len);
        free(ciphertext);
    }

    if (output) {
        buffer_free(output);
    }

    return err;
}

error_t *encryption_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t **out_plaintext
) {
    CHECK_NULL(ciphertext);
    CHECK_NULL(profile_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_plaintext);

    error_t *err = NULL;
    uint8_t mac_key[32] = {0};
    uint8_t ctr_key[32] = {0};
    uint8_t stream_seed[32] = {0};
    uint8_t *keystream = NULL;
    unsigned char *plaintext_data = NULL;
    buffer_t *output = NULL;

    /* Step 1: Validate minimum size */
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        return ERROR(ERR_CRYPTO,
                    "Invalid ciphertext: too small (expected >= %d, got %zu)",
                    ENCRYPTION_OVERHEAD, ciphertext_len);
    }

    /* Step 2: Verify magic header */
    if (memcmp(ciphertext, MAGIC_HEADER, sizeof(MAGIC_HEADER)) != 0) {
        return ERROR(ERR_CRYPTO, "Invalid magic header (not a dotta encrypted file)");
    }

    /* Check version */
    if (ciphertext[5] != ENCRYPTION_VERSION) {
        return ERROR(ERR_CRYPTO,
                    "Unsupported encryption version: %d (expected %d)",
                    ciphertext[5], ENCRYPTION_VERSION);
    }

    /* Step 3: Extract SIV and ciphertext body */
    const unsigned char *siv_received = ciphertext + ENCRYPTION_HEADER_SIZE;
    const unsigned char *ciphertext_body = ciphertext + ENCRYPTION_HEADER_SIZE + ENCRYPTION_SIV_SIZE;
    size_t plaintext_len = ciphertext_len - ENCRYPTION_OVERHEAD;

    /* Step 4: Derive MAC and CTR subkeys from profile key */
    err = derive_siv_subkeys(profile_key, mac_key, ctr_key);
    if (err) {
        goto cleanup;
    }

    /* Step 5: Re-compute SIV over storage_path || ciphertext */
    uint8_t siv_computed[ENCRYPTION_SIV_SIZE];
    err = compute_siv(mac_key, storage_path, ciphertext_body, plaintext_len, siv_computed);
    if (err) {
        goto cleanup;
    }

    /* Step 6: Verify SIV using constant-time comparison */
    if (!hydro_equal(siv_computed, siv_received, ENCRYPTION_SIV_SIZE)) {
        err = ERROR(ERR_CRYPTO,
                   "Authentication failed - wrong passphrase, corrupted file, or incorrect path");
        goto cleanup;
    }

    /* Step 7: Derive deterministic stream seed from CTR key and path */
    err = derive_stream_seed(ctr_key, storage_path, stream_seed);
    if (err) {
        goto cleanup;
    }

    /* Step 8: Generate deterministic keystream */
    keystream = malloc(plaintext_len);
    if (!keystream && plaintext_len > 0) {
        err = ERROR(ERR_MEMORY, "Failed to allocate keystream buffer");
        goto cleanup;
    }

    if (plaintext_len > 0) {
        hydro_random_buf_deterministic(keystream, plaintext_len, stream_seed);
    }

    /* Step 9: Decrypt ciphertext by XORing with keystream */
    plaintext_data = malloc(plaintext_len);
    if (!plaintext_data && plaintext_len > 0) {
        err = ERROR(ERR_MEMORY, "Failed to allocate plaintext buffer");
        goto cleanup;
    }

    for (size_t i = 0; i < plaintext_len; i++) {
        plaintext_data[i] = ciphertext_body[i] ^ keystream[i];
    }

    /* Step 10: Create output buffer */
    output = buffer_create_from_data(plaintext_data, plaintext_len);
    if (!output) {
        err = ERROR(ERR_MEMORY, "Failed to create output buffer");
        goto cleanup;
    }

    *out_plaintext = output;
    output = NULL;  /* Transfer ownership, don't free */

cleanup:
    /* Securely clear sensitive data */
    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(ctr_key, sizeof(ctr_key));
    hydro_memzero(stream_seed, sizeof(stream_seed));
    hydro_memzero(siv_computed, sizeof(siv_computed));

    if (keystream) {
        hydro_memzero(keystream, plaintext_len);
        free(keystream);
    }

    if (plaintext_data) {
        hydro_memzero(plaintext_data, plaintext_len);
        free(plaintext_data);
    }

    if (output) {
        buffer_free(output);
    }

    return err;
}

bool encryption_is_encrypted(const unsigned char *data, size_t data_len) {
    /* Check if data is large enough to contain magic bytes */
    if (!data || data_len < ENCRYPTION_MAGIC_BYTES) {
        return false;
    }

    /* Compare only the magic bytes (first 5 bytes of MAGIC_HEADER) */
    return memcmp(data, MAGIC_HEADER, ENCRYPTION_MAGIC_BYTES) == 0;
}
