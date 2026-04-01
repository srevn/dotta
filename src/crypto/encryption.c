/**
 * encryption.c - Cryptographic primitives implementation
 */

#include "crypto/encryption.h"

#include <hydrogen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

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
 * Store a uint64_t in little-endian byte order (portable)
 */
static void store_le64(uint8_t out[8], uint64_t val) {
    out[0] = (uint8_t)(val);
    out[1] = (uint8_t)(val >> 8);
    out[2] = (uint8_t)(val >> 16);
    out[3] = (uint8_t)(val >> 24);
    out[4] = (uint8_t)(val >> 32);
    out[5] = (uint8_t)(val >> 40);
    out[6] = (uint8_t)(val >> 48);
    out[7] = (uint8_t)(val >> 56);
}

/**
 * Load a uint64_t from little-endian byte order (portable)
 */
static uint64_t load_le64(const uint8_t in[8]) {
    return (uint64_t)in[0]
         | ((uint64_t)in[1] << 8)
         | ((uint64_t)in[2] << 16)
         | ((uint64_t)in[3] << 24)
         | ((uint64_t)in[4] << 32)
         | ((uint64_t)in[5] << 40)
         | ((uint64_t)in[6] << 48)
         | ((uint64_t)in[7] << 56);
}

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
    if (hydro_hash_hash(out_seed, 32, (const uint8_t *)storage_path, strlen(storage_path),
                        ENCRYPTION_CTX_SIV_CTR, ctr_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive stream seed");
    }

    return NULL;
}

/**
 * Compute SIV/MAC over associated data and ciphertext (internal helper)
 *
 * Computes the SIV (Synthetic IV) as a MAC over:
 *   siv = HMAC(mac_key, len(storage_path) || storage_path || ciphertext, context="dottamac")
 *
 * The path length prefix (8-byte LE) provides domain separation, preventing
 * an adversary from shifting the boundary between path and ciphertext to forge
 * a valid MAC for a different (path, ciphertext) pair.
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

    /* Length-prefix the path for domain separation */
    size_t path_len = strlen(storage_path);
    uint8_t path_len_le[8];
    store_le64(path_len_le, (uint64_t)path_len);
    hydro_hash_update(&mac_state, path_len_le, sizeof(path_len_le));

    /* Authenticate storage_path (associated data) */
    hydro_hash_update(&mac_state, (const uint8_t *)storage_path, path_len);

    /* Authenticate ciphertext (guard against NULL from malloc(0) on empty files) */
    if (ciphertext_len > 0) {
        hydro_hash_update(&mac_state, ciphertext, ciphertext_len);
    }

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

/**
 * Balloon hashing: memory-hard key derivation (internal helper)
 *
 * Implements the balloon hashing algorithm (Boneh, Corrigan-Gibbs, Schechter, 2016)
 * to add memory hardness to the key derivation pipeline. The algorithm has three
 * phases:
 *
 *   1. EXPANSION: Fill a large buffer with pseudorandom data derived from the
 *      CPU-hard key. Each block gets a unique seed (keyed hash of block index),
 *      then expanded to BLOCK_SIZE via deterministic PRNG.
 *
 *   2. MIXING: Perform data-dependent random access over the buffer. For each
 *      block, derive a pseudo-random index from the block's content, then mix
 *      the current block with the previous and randomly-indexed blocks. This is
 *      what provides memory hardness: computing any block requires having the
 *      full buffer in memory.
 *
 *   3. FINALIZATION: Hash the last block (which depends on the entire computation
 *      chain) to produce the 32-byte master key.
 *
 * The buffer is mlock'd (best-effort) to prevent swapping, securely zeroed
 * before freeing, and munlock'd after zeroing.
 *
 * @param cpu_key 32-byte output from hydro_pwhash_deterministic
 * @param memlimit Total memory in bytes (must be >= ENCRYPTION_BALLOON_MEMLIMIT_MIN)
 * @param out_master_key Output buffer for 32-byte master key
 * @return Error or NULL on success
 */
static error_t *balloon_harden(
    const uint8_t cpu_key[ENCRYPTION_MASTER_KEY_SIZE],
    size_t memlimit,
    uint8_t out_master_key[ENCRYPTION_MASTER_KEY_SIZE]
) {
    error_t *err = NULL;
    uint8_t *buf = NULL;
    bool buf_mlocked = false;

    const size_t n_blocks = memlimit / ENCRYPTION_BALLOON_BLOCK_SIZE;
    const size_t buf_size = n_blocks * ENCRYPTION_BALLOON_BLOCK_SIZE;

    /* Allocate balloon buffer */
    buf = malloc(buf_size);
    if (!buf) {
        return ERROR(ERR_MEMORY, "Failed to allocate %zu bytes for balloon hashing",
                     buf_size);
    }

    /* Best-effort mlock to prevent swapping sensitive key material to disk */
    buf_mlocked = (mlock(buf, buf_size) == 0);

    /* PHASE 1: EXPANSION
     *
     * Fill buffer deterministically. Each block gets a unique seed derived
     * from cpu_key and block index, then expanded via deterministic PRNG. */
    for (size_t i = 0; i < n_blocks; i++) {
        uint8_t seed[32];
        uint8_t i_le[8];
        store_le64(i_le, (uint64_t)i);

        if (hydro_hash_hash(seed, sizeof(seed), i_le, sizeof(i_le),
                            ENCRYPTION_CTX_BALLOON_EXPAND, cpu_key) != 0) {
            err = ERROR(ERR_CRYPTO, "Balloon expansion: hash failed at block %zu", i);
            goto cleanup;
        }

        hydro_random_buf_deterministic(
            buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE,
            ENCRYPTION_BALLOON_BLOCK_SIZE,
            seed
        );

        hydro_memzero(seed, sizeof(seed));
    }

    /* PHASE 2: MIXING
     *
     * Data-dependent random access over 3 rounds. For each block, derive a
     * pseudo-random index from the block's content, then re-expand the block
     * from a mix of (previous block, random block, current block). This forces
     * the full buffer to remain in memory. */
    for (int round = 0; round < ENCRYPTION_BALLOON_ROUNDS; round++) {
        for (size_t i = 0; i < n_blocks; i++) {
            size_t prev_idx = (i == 0) ? n_blocks - 1 : i - 1;

            /* Derive pseudo-random block index from current block content + position.
             * Key: first 32 bytes of current block (pseudorandom from expansion/prior mix).
             * Message: round || i as 16-byte little-endian encoding. */
            uint8_t idx_msg[16];
            store_le64(idx_msg, (uint64_t)round);
            store_le64(idx_msg + 8, (uint64_t)i);

            uint8_t idx_hash[32];
            if (hydro_hash_hash(idx_hash, sizeof(idx_hash), idx_msg, sizeof(idx_msg),
                                ENCRYPTION_CTX_BALLOON_INDEX,
                                buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE) != 0) {
                err = ERROR(ERR_CRYPTO, "Balloon mixing: index hash failed");
                goto cleanup;
            }

            size_t idx = (size_t)(load_le64(idx_hash) % (uint64_t)n_blocks);

            /* Mix previous, random, and current blocks via streaming keyed hash.
             * Key: first 32 bytes of previous block.
             * Data: first 32 bytes of random block || first 32 bytes of current block. */
            hydro_hash_state mix_state;
            uint8_t mix_hash[32];

            if (hydro_hash_init(&mix_state, ENCRYPTION_CTX_BALLOON_MIX,
                                buf + prev_idx * ENCRYPTION_BALLOON_BLOCK_SIZE) != 0) {
                err = ERROR(ERR_CRYPTO, "Balloon mixing: hash init failed");
                goto cleanup;
            }

            hydro_hash_update(&mix_state, buf + idx * ENCRYPTION_BALLOON_BLOCK_SIZE, 32);
            hydro_hash_update(&mix_state, buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE, 32);
            hydro_hash_final(&mix_state, mix_hash, sizeof(mix_hash));

            /* Re-expand current block from new seed */
            hydro_random_buf_deterministic(
                buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE,
                ENCRYPTION_BALLOON_BLOCK_SIZE,
                mix_hash
            );

            hydro_memzero(&mix_state, sizeof(mix_state));
            hydro_memzero(mix_hash, sizeof(mix_hash));
            hydro_memzero(idx_hash, sizeof(idx_hash));
        }
    }

    /* PHASE 3: FINALIZATION
     *
     * Hash the last block (which depends on the entire computation chain)
     * to produce the 32-byte master key. The cpu_key is used as the hash
     * key, binding the output to the original passphrase derivation. */
    if (hydro_hash_hash(out_master_key, ENCRYPTION_MASTER_KEY_SIZE,
                        buf + (n_blocks - 1) * ENCRYPTION_BALLOON_BLOCK_SIZE,
                        ENCRYPTION_BALLOON_BLOCK_SIZE,
                        ENCRYPTION_CTX_BALLOON_FINAL, cpu_key) != 0) {
        err = ERROR(ERR_CRYPTO, "Balloon finalization: hash failed");
        goto cleanup;
    }

cleanup:
    if (buf) {
        hydro_memzero(buf, buf_size);
        if (buf_mlocked) {
            munlock(buf, buf_size);
        }
        free(buf);
    }
    if (err) {
        hydro_memzero(out_master_key, ENCRYPTION_MASTER_KEY_SIZE);
    }

    return err;
}

error_t *encryption_derive_master_key(
    const char *passphrase,
    size_t passphrase_len,
    uint64_t opslimit,
    size_t memlimit,
    uint8_t out_master_key[ENCRYPTION_MASTER_KEY_SIZE]
) {
    CHECK_NULL(passphrase);
    CHECK_NULL(out_master_key);

    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Validate memlimit: 0 disables balloon hashing, otherwise must meet minimum */
    if (memlimit > 0 && memlimit < ENCRYPTION_BALLOON_MEMLIMIT_MIN) {
        return ERROR(ERR_INVALID_ARG,
                     "Balloon memlimit must be 0 (disabled) or >= %d bytes (1 MB)",
                     ENCRYPTION_BALLOON_MEMLIMIT_MIN);
    }

    /* Use zero master key for hydro_pwhash (we derive everything from passphrase)
     *
     * Note: Zero master key is correct here because we're doing direct key
     * derivation, not password storage. The master key parameter is only
     * needed when creating encrypted password representatives for storage.
     * See libhydrogen Password-hashing.md for details. */
    static const uint8_t zero_master[hydro_pwhash_MASTERKEYBYTES] = {0};

    /* Phase 1: CPU-hard derivation (Gimli permutation iterations)
     *
     * When balloon hashing is enabled (memlimit > 0), write to intermediate
     * buffer. When disabled, write directly to output (preserving pre-balloon
     * behavior exactly). */
    uint8_t cpu_key[ENCRYPTION_MASTER_KEY_SIZE] = {0};
    uint8_t *pwhash_target = (memlimit > 0) ? cpu_key : out_master_key;

    int result = hydro_pwhash_deterministic(
        pwhash_target,
        ENCRYPTION_MASTER_KEY_SIZE,
        passphrase,
        passphrase_len,
        ENCRYPTION_CTX_PWHASH,
        zero_master,
        opslimit,
        ENCRYPTION_PWHASH_MEMLIMIT,
        ENCRYPTION_PWHASH_THREADS
    );

    if (result != 0) {
        hydro_memzero(cpu_key, sizeof(cpu_key));
        return ERROR(ERR_CRYPTO, "Failed to derive master key from passphrase");
    }

    if (memlimit == 0) {
        return NULL;
    }

    /* Phase 2: Memory-hard derivation (balloon hashing) */
    error_t *err = balloon_harden(cpu_key, memlimit, out_master_key);
    hydro_memzero(cpu_key, sizeof(cpu_key));
    return err;
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
    uint8_t siv[ENCRYPTION_SIV_SIZE] = {0};
    uint8_t *keystream = NULL;
    unsigned char *ciphertext = NULL;
    buffer_t *output = NULL;

    /* Calculate output size with overflow detection */
    if (plaintext_len > SIZE_MAX - ENCRYPTION_OVERHEAD) {
        return ERROR(ERR_INVALID_ARG, "Plaintext too large (size_t overflow): %zu bytes",
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
    uint8_t siv_computed[ENCRYPTION_SIV_SIZE] = {0};
    uint8_t *keystream = NULL;
    unsigned char *plaintext_data = NULL;
    buffer_t *output = NULL;

    /* Step 1: Validate minimum size */
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        return ERROR(ERR_CRYPTO, "Invalid ciphertext: too small (expected >= %d, got %zu)",
                     ENCRYPTION_OVERHEAD, ciphertext_len);
    }

    /* Step 2: Verify magic header and version
     *
     * Check magic bytes and version separately to give precise diagnostics.
     * A version mismatch should report the actual version found, not just
     * "invalid magic header". */
    if (memcmp(ciphertext, MAGIC_HEADER, ENCRYPTION_MAGIC_BYTES) != 0) {
        return ERROR(ERR_CRYPTO, "Invalid magic header (not a dotta encrypted file)");
    }

    /* Check version */
    if (ciphertext[5] != ENCRYPTION_VERSION) {
        return ERROR(ERR_CRYPTO, "Unsupported encryption version: %d (expected %d)",
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
