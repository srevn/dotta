/**
 * encryption.c - Cryptographic primitives implementation
 */

#include "base/encryption.h"

#include <string.h>

#include "base/error.h"
#include "hydrogen.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

/* File format constants */
static const unsigned char MAGIC_HEADER[8] = {
    'D', 'O', 'T', 'T', 'A',   /* Magic: "DOTTA" */
    ENCRYPTION_VERSION,        /* Version byte */
    0x00, 0x00                 /* Reserved (padding to 8 bytes) */
};

/**
 * Derive deterministic nonce from content (internal helper)
 *
 * Uses keyed BLAKE2b hashing to derive a 64-bit nonce from:
 *   nonce = HMAC(profile_key, storage_path || plaintext)[0:8]
 *
 * This ensures:
 * - Same (key, path, content) → same nonce (idempotent)
 * - Different content → different nonce (collision-resistant)
 * - Including path prevents identical files from having identical ciphertexts
 *
 * Context string "dottanon" (8 bytes) = "dotta" + "non"ce
 *
 * @param profile_key Profile encryption key (32 bytes)
 * @param storage_path File path in profile (e.g., "home/.bashrc")
 * @param plaintext Content to encrypt
 * @param plaintext_len Content length
 * @param out_nonce Derived 64-bit nonce
 * @return Error or NULL on success
 */
static error_t *derive_nonce_from_content(
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint64_t *out_nonce
) {
    /* Initialize keyed hash with profile key */
    hydro_hash_state state;
    uint8_t hash[32];  /* BLAKE2b-256 output */

    if (hydro_hash_init(&state, "dottanon", profile_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to initialize hash for nonce derivation");
    }

    /* Hash: storage_path || plaintext */
    hydro_hash_update(&state, (const uint8_t *)storage_path, strlen(storage_path));
    hydro_hash_update(&state, plaintext, plaintext_len);
    hydro_hash_final(&state, hash, sizeof(hash));

    /* Extract first 64 bits as nonce (little-endian) */
    uint64_t nonce = 0;
    for (int i = 0; i < 8; i++) {
        nonce |= ((uint64_t)hash[i]) << (i * 8);
    }

    /* Securely clear sensitive data */
    hydro_memzero(hash, sizeof(hash));
    hydro_memzero(&state, sizeof(state));

    *out_nonce = nonce;
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

    /* Use zero master key for hydro_pwhash (we derive everything from passphrase) */
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

    /* Derive deterministic nonce from content */
    uint64_t nonce = 0;
    error_t *err = derive_nonce_from_content(
        profile_key,
        storage_path,
        plaintext,
        plaintext_len,
        &nonce
    );
    if (err) {
        return error_wrap(err, "Failed to derive nonce from content");
    }

    /* Calculate output size with overflow detection
     * We need to ensure that secretbox_len and total_len don't overflow.
     * This prevents allocating a small buffer when plaintext_len is huge. */

    /* Check: secretbox_len = HEADERBYTES + plaintext_len */
    if (plaintext_len > SIZE_MAX - hydro_secretbox_HEADERBYTES) {
        return ERROR(ERR_INVALID_ARG,
                    "Plaintext too large (size_t overflow): %zu bytes",
                    plaintext_len);
    }
    size_t secretbox_len = hydro_secretbox_HEADERBYTES + plaintext_len;

    /* Check: total_len = HEADER_SIZE + secretbox_len */
    if (secretbox_len > SIZE_MAX - ENCRYPTION_HEADER_SIZE) {
        return ERROR(ERR_INVALID_ARG,
                    "Ciphertext size overflow: %zu bytes",
                    secretbox_len);
    }
    size_t total_len = ENCRYPTION_HEADER_SIZE + secretbox_len;

    /* Create output buffer */
    buffer_t *output = buffer_create_with_capacity(total_len);
    if (!output) {
        return ERROR(ERR_MEMORY, "Failed to allocate encryption buffer");
    }

    /* Write magic header */
    err = buffer_append(output, MAGIC_HEADER, sizeof(MAGIC_HEADER));
    if (err) {
        buffer_free(output);
        return error_wrap(err, "Failed to write magic header");
    }

    /* Write nonce (little-endian uint64_t) */
    uint8_t nonce_bytes[8];
    for (int i = 0; i < 8; i++) {
        nonce_bytes[i] = (nonce >> (i * 8)) & 0xFF;
    }
    err = buffer_append(output, nonce_bytes, sizeof(nonce_bytes));
    if (err) {
        buffer_free(output);
        return error_wrap(err, "Failed to write nonce");
    }

    /* Allocate space for secretbox output */
    unsigned char *secretbox_output = malloc(secretbox_len);
    if (!secretbox_output) {
        buffer_free(output);
        return ERROR(ERR_MEMORY, "Failed to allocate secretbox buffer");
    }

    /* Encrypt with libhydrogen using derived nonce */
    int result = hydro_secretbox_encrypt(
        secretbox_output,
        plaintext,
        plaintext_len,
        nonce,
        ENCRYPTION_CTX_SECRETBOX,
        profile_key
    );

    if (result != 0) {
        free(secretbox_output);
        buffer_free(output);
        return ERROR(ERR_CRYPTO, "Failed to encrypt data");
    }

    /* Append secretbox output to buffer */
    err = buffer_append(output, secretbox_output, secretbox_len);
    free(secretbox_output);

    if (err) {
        buffer_free(output);
        return error_wrap(err, "Failed to append ciphertext");
    }

    *out_ciphertext = output;
    return NULL;
}

error_t *encryption_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    buffer_t **out_plaintext
) {
    CHECK_NULL(ciphertext);
    CHECK_NULL(profile_key);
    CHECK_NULL(out_plaintext);

    /* Validate minimum size */
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        return ERROR(ERR_CRYPTO,
                    "Invalid ciphertext: too small (expected >= %d, got %zu)",
                    ENCRYPTION_OVERHEAD, ciphertext_len);
    }

    /* Verify magic header */
    if (memcmp(ciphertext, MAGIC_HEADER, sizeof(MAGIC_HEADER)) != 0) {
        return ERROR(ERR_CRYPTO, "Invalid magic header (not a dotta encrypted file)");
    }

    /* Check version */
    if (ciphertext[5] != ENCRYPTION_VERSION) {
        return ERROR(ERR_CRYPTO,
                    "Unsupported encryption version: %d (expected %d)",
                    ciphertext[5], ENCRYPTION_VERSION);
    }

    /* Extract nonce (little-endian uint64_t) */
    uint64_t nonce = 0;
    for (int i = 0; i < 8; i++) {
        nonce |= ((uint64_t)ciphertext[8 + i]) << (i * 8);
    }

    /* Extract secretbox ciphertext */
    const unsigned char *secretbox_input = ciphertext + ENCRYPTION_HEADER_SIZE;
    size_t secretbox_len = ciphertext_len - ENCRYPTION_HEADER_SIZE;

    /* Calculate plaintext size */
    if (secretbox_len < hydro_secretbox_HEADERBYTES) {
        return ERROR(ERR_CRYPTO, "Invalid secretbox size");
    }
    size_t plaintext_len = secretbox_len - hydro_secretbox_HEADERBYTES;

    /* Allocate plaintext buffer */
    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        return ERROR(ERR_MEMORY, "Failed to allocate decryption buffer");
    }

    /* Decrypt with libhydrogen using extracted nonce */
    int result = hydro_secretbox_decrypt(
        plaintext,
        secretbox_input,
        secretbox_len,
        nonce,
        ENCRYPTION_CTX_SECRETBOX,
        profile_key
    );

    if (result != 0) {
        free(plaintext);
        return ERROR(ERR_CRYPTO,
                    "Authentication failed - wrong passphrase or corrupted file");
    }

    /* Create buffer from plaintext */
    buffer_t *output = buffer_create_from_data(plaintext, plaintext_len);
    free(plaintext);

    if (!output) {
        return ERROR(ERR_MEMORY, "Failed to create output buffer");
    }

    *out_plaintext = output;
    return NULL;
}

bool encryption_is_encrypted(const unsigned char *data, size_t data_len) {
    /* Check if data is large enough to contain magic bytes */
    if (!data || data_len < ENCRYPTION_MAGIC_BYTES) {
        return false;
    }

    /* Compare only the magic bytes (first 5 bytes of MAGIC_HEADER) */
    return memcmp(data, MAGIC_HEADER, ENCRYPTION_MAGIC_BYTES) == 0;
}
