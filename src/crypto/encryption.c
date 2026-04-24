/**
 * encryption.c - Cryptographic primitives implementation
 */

#include "crypto/encryption.h"

#include <hydrogen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"

/* File format constants */
static const unsigned char MAGIC_HEADER[8] = {
    'D',  'O', 'T', 'T', 'A', /* Magic: "DOTTA" */
    ENCRYPTION_VERSION,/* Version byte */
    0x00, 0x00         /* Reserved (padding to 8 bytes) */
};

/* Defensive upper bound on storage_path bytes (excluding NUL).
 *
 * Storage paths are profile-relative ("home/.bashrc", "root/etc/foo"), so
 * in practice they stay well under 1 KiB. The cap exists so the crypto
 * module defends itself at its own boundary rather than trusting upstream
 * validation, and so the same limit holds on every platform (PATH_MAX
 * varies — 1024 on macOS, 4096 on Linux). Trips only on pathological
 * input; normal callers never approach it. */
#define ENCRYPTION_STORAGE_PATH_MAX 4096

/* Maximum file size for encryption / decryption (100 MiB).
 *
 * Dotfiles are small configuration files; a 100 MiB cap prevents the
 * crypto layer from allocating huge keystream / ciphertext buffers on
 * behalf of runaway input. Enforced at both entry points so every
 * caller — regardless of how the bytes reached us — hits the same
 * limit with the same diagnostic. */
#define ENCRYPTION_MAX_CONTENT_SIZE ((size_t) 100 * 1024 * 1024)

/**
 * Store a uint64_t in little-endian byte order (portable)
 */
static void store_le64(uint8_t out[8], uint64_t val) {
    out[0] = (uint8_t) (val);
    out[1] = (uint8_t) (val >> 8);
    out[2] = (uint8_t) (val >> 16);
    out[3] = (uint8_t) (val >> 24);
    out[4] = (uint8_t) (val >> 32);
    out[5] = (uint8_t) (val >> 40);
    out[6] = (uint8_t) (val >> 48);
    out[7] = (uint8_t) (val >> 56);
}

/**
 * Load a uint64_t from little-endian byte order (portable)
 */
static uint64_t load_le64(const uint8_t in[8]) {
    return (uint64_t) in[0]
           | ((uint64_t) in[1] << 8)
           | ((uint64_t) in[2] << 16)
           | ((uint64_t) in[3] << 24)
           | ((uint64_t) in[4] << 32)
           | ((uint64_t) in[5] << 40)
           | ((uint64_t) in[6] << 48)
           | ((uint64_t) in[7] << 56);
}

/**
 * Derive subkeys for SIV construction (internal helper)
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
static error_t *derive_siv_subkeys(
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    uint8_t out_mac_key[32],
    uint8_t out_prf_key[32]
) {
    /* Derive MAC key (subkey_id=1) */
    if (hydro_kdf_derive_from_key(
        out_mac_key, 32, 1,
        ENCRYPTION_CTX_SIV_KDF, profile_key
        ) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive MAC key");
    }

    /* Derive PRF key (subkey_id=2) */
    if (hydro_kdf_derive_from_key(
        out_prf_key, 32, 2,
        ENCRYPTION_CTX_SIV_KDF, profile_key
        ) != 0) {
        hydro_memzero(out_mac_key, 32);
        return ERROR(ERR_CRYPTO, "Failed to derive PRF key");
    }

    return NULL;
}

/**
 * Compute synthetic IV over associated data and plaintext (internal helper)
 *
 * The synthetic IV doubles as both the MAC tag and the nonce that drives
 * the keystream. It is computed as:
 *
 *   siv = HMAC(mac_key,
 *              len(storage_path) as LE64 || storage_path || plaintext,
 *              context="dottamac")
 *
 * The path length prefix provides domain separation between path and
 * plaintext so an adversary cannot shift the boundary to forge a valid SIV
 * for a different (path, plaintext) pair. No length prefix is needed for
 * the plaintext: the path's length prefix already separates the two fields
 * unambiguously, and BLAKE2 is not vulnerable to length-extension.
 *
 * Because the SIV is a function of the plaintext, two different plaintexts
 * at the same (mac_key, path) produce different SIVs — and therefore
 * different keystreams — giving nonce-misuse resistance.
 *
 * @param mac_key MAC subkey (32 bytes)
 * @param storage_path File path in profile (authenticated associated data)
 * @param plaintext Plaintext to authenticate
 * @param plaintext_len Plaintext length
 * @param out_siv Output buffer for SIV (ENCRYPTION_SIV_SIZE bytes)
 * @return Error or NULL on success
 */
static error_t *compute_siv(
    const uint8_t mac_key[32],
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint8_t out_siv[ENCRYPTION_SIV_SIZE]
) {
    hydro_hash_state mac_state;

    /* Initialize MAC with mac_key */
    if (hydro_hash_init(&mac_state, ENCRYPTION_CTX_SIV_MAC, mac_key) != 0) {
        return ERROR(
            ERR_CRYPTO, "Failed to initialize SIV computation"
        );
    }

    /* Length-prefix the path for domain separation */
    size_t path_len = strlen(storage_path);
    uint8_t path_len_le[8];
    store_le64(path_len_le, (uint64_t) path_len);

    hydro_hash_update(
        &mac_state, path_len_le, sizeof(path_len_le)
    );

    /* Authenticate storage_path (associated data) */
    hydro_hash_update(
        &mac_state, (const uint8_t *) storage_path, path_len
    );

    /* Authenticate plaintext (guard against NULL when plaintext_len == 0) */
    if (plaintext_len > 0) {
        hydro_hash_update(&mac_state, plaintext, plaintext_len);
    }

    /* Finalize to get SIV */
    hydro_hash_final(&mac_state, out_siv, ENCRYPTION_SIV_SIZE);

    /* Clear MAC state */
    hydro_memzero(&mac_state, sizeof(mac_state));

    return NULL;
}

/**
 * Derive keystream seed from SIV (internal helper)
 *
 * Produces the seed that feeds the deterministic PRNG used for the XOR
 * keystream:
 *   keystream_seed = HMAC(prf_key, siv, context="dottactr")
 *
 * Binding the seed to a secret (prf_key) is essential: the SIV is written
 * to the output and is therefore public. If the PRNG were seeded directly
 * from the SIV, anyone who saw the ciphertext could reproduce the keystream
 * and recover the plaintext. Passing the SIV through a keyed hash puts the
 * keystream back behind the profile key.
 *
 * @param prf_key PRF subkey (32 bytes)
 * @param siv Synthetic IV (ENCRYPTION_SIV_SIZE bytes)
 * @param out_seed Output buffer for keystream seed (32 bytes)
 * @return Error or NULL on success
 */
static error_t *derive_keystream_seed(
    const uint8_t prf_key[32],
    const uint8_t siv[ENCRYPTION_SIV_SIZE],
    uint8_t out_seed[32]
) {
    if (hydro_hash_hash(
        out_seed, 32, siv, ENCRYPTION_SIV_SIZE,
        ENCRYPTION_CTX_SIV_CTR, prf_key
        ) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive keystream seed");
    }

    return NULL;
}

error_t *encryption_init(void) {
    if (hydro_init() != 0) {
        return ERROR(
            ERR_CRYPTO, "Failed to initialize libhydrogen"
        );
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

    const size_t n_blocks =
        memlimit / ENCRYPTION_BALLOON_BLOCK_SIZE;
    const size_t buf_size =
        n_blocks * ENCRYPTION_BALLOON_BLOCK_SIZE;

    /* Allocate balloon buffer */
    buf = malloc(buf_size);
    if (!buf) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate %zu bytes for balloon hashing",
            buf_size
        );
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
        store_le64(i_le, (uint64_t) i);

        if (hydro_hash_hash(
            seed, sizeof(seed), i_le, sizeof(i_le),
            ENCRYPTION_CTX_BALLOON_EXPAND, cpu_key
            ) != 0) {
            err = ERROR(
                ERR_CRYPTO, "Balloon expansion: hash failed at block %zu", i
            );
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
            store_le64(idx_msg, (uint64_t) round);
            store_le64(idx_msg + 8, (uint64_t) i);

            uint8_t idx_hash[32];
            if (hydro_hash_hash(
                idx_hash, sizeof(idx_hash), idx_msg, sizeof(idx_msg),
                ENCRYPTION_CTX_BALLOON_INDEX,
                buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE
                ) != 0) {
                err = ERROR(ERR_CRYPTO, "Balloon mixing: index hash failed");
                goto cleanup;
            }

            size_t idx = (size_t) (load_le64(idx_hash) % (uint64_t) n_blocks);

            /* Mix previous, random, and current blocks via streaming keyed hash.
             * Key: first 32 bytes of previous block.
             * Data: first 32 bytes of random block || first 32 bytes of current block. */
            hydro_hash_state mix_state;
            uint8_t mix_hash[32];

            if (hydro_hash_init(
                &mix_state, ENCRYPTION_CTX_BALLOON_MIX,
                buf + prev_idx * ENCRYPTION_BALLOON_BLOCK_SIZE
                ) != 0) {
                err = ERROR(
                    ERR_CRYPTO, "Balloon mixing: hash init failed"
                );
                goto cleanup;
            }

            hydro_hash_update(
                &mix_state, buf + idx * ENCRYPTION_BALLOON_BLOCK_SIZE, 32
            );
            hydro_hash_update(
                &mix_state, buf + i * ENCRYPTION_BALLOON_BLOCK_SIZE, 32
            );
            hydro_hash_final(
                &mix_state, mix_hash, sizeof(mix_hash)
            );

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
    if (hydro_hash_hash(
        out_master_key, ENCRYPTION_MASTER_KEY_SIZE,
        buf + (n_blocks - 1) * ENCRYPTION_BALLOON_BLOCK_SIZE,
        ENCRYPTION_BALLOON_BLOCK_SIZE,
        ENCRYPTION_CTX_BALLOON_FINAL, cpu_key
        ) != 0) {
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
        return ERROR(
            ERR_INVALID_ARG,
            "Balloon memlimit must be 0 (disabled) or >= %d bytes (1 MB)",
            ENCRYPTION_BALLOON_MEMLIMIT_MIN
        );
    }

    /* Use zero master key for hydro_pwhash (we derive everything from passphrase)
     *
     * Note: Zero master key is correct here because we're doing direct key
     * derivation, not password storage. The master key parameter is only
     * needed when creating encrypted password representatives for storage.
     * See libhydrogen Password-hashing.md for details. */
    static const uint8_t zero_master[hydro_pwhash_MASTERKEYBYTES] = { 0 };

    /* Phase 1: CPU-hard derivation (Gimli permutation iterations)
     *
     * When balloon hashing is enabled (memlimit > 0), write to intermediate
     * buffer. When disabled, write directly to output (preserving pre-balloon
     * behavior exactly). */
    uint8_t cpu_key[ENCRYPTION_MASTER_KEY_SIZE] = { 0 };
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
    const char *profile,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
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
    size_t name_len = strlen(profile);

    int result = hydro_hash_hash(
        out_profile_key,
        ENCRYPTION_PROFILE_KEY_SIZE,
        profile,
        name_len,
        ENCRYPTION_CTX_KDF,  /* Context: "profile " */
        master_key           /* Master key as keying material */
    );

    if (result != 0) {
        return ERROR(
            ERR_CRYPTO, "Failed to derive profile key for: %s",
            profile
        );
    }

    return NULL;
}

error_t *encryption_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(plaintext);
    CHECK_NULL(profile_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    error_t *err = NULL;
    uint8_t mac_key[32] = { 0 };
    uint8_t prf_key[32] = { 0 };
    uint8_t keystream_seed[32] = { 0 };
    buffer_t output = BUFFER_INIT;

    *out_ciphertext = (buffer_t){ 0 };

    /* Defensive: reject pathological storage paths at the boundary.
     * strnlen keeps the scan bounded even if the caller hands us a
     * non-NUL-terminated buffer. */
    if (strnlen(storage_path, ENCRYPTION_STORAGE_PATH_MAX + 1)
        > ENCRYPTION_STORAGE_PATH_MAX) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path too long (maximum %d bytes)",
            ENCRYPTION_STORAGE_PATH_MAX
        );
    }

    /* Policy cap: dotta manages small configuration files. A single cap
     * on the crypto entry point enforces the rule for every caller. */
    if (plaintext_len > ENCRYPTION_MAX_CONTENT_SIZE) {
        return ERROR(
            ERR_INVALID_ARG,
            "Content too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            plaintext_len, (size_t) ENCRYPTION_MAX_CONTENT_SIZE
        );
    }

    /* Calculate output size with overflow detection */
    if (plaintext_len > SIZE_MAX - ENCRYPTION_OVERHEAD) {
        return ERROR(
            ERR_INVALID_ARG, "Plaintext too large (size_t overflow): %zu bytes",
            plaintext_len
        );
    }
    size_t total_len =
        ENCRYPTION_HEADER_SIZE + ENCRYPTION_SIV_SIZE + plaintext_len;

    /* Step 1: Derive MAC and PRF subkeys from profile key */
    err = derive_siv_subkeys(profile_key, mac_key, prf_key);
    if (err) {
        goto cleanup;
    }

    /* Step 2: Allocate the output buffer at its final size and write directly.
     *
     * buffer_grow reserves total_len + 1 bytes (for the NUL terminator). We
     * own [0, total_len) and restore the invariant NUL at [total_len]. This
     * layout lets us compute the SIV and keystream straight into the output,
     * so peak memory is total_len bytes instead of the 3 * N of separate
     * keystream + ciphertext + output buffers. */
    err = buffer_grow(&output, total_len);
    if (err) {
        goto cleanup;
    }
    output.size = total_len;
    output.data[output.size] = '\0';

    /* Step 3: Write the fixed header */
    memcpy(output.data, MAGIC_HEADER, ENCRYPTION_HEADER_SIZE);

    unsigned char *siv_slot =
        (unsigned char *) output.data + ENCRYPTION_HEADER_SIZE;
    unsigned char *ct_slot = siv_slot + ENCRYPTION_SIV_SIZE;

    /* Step 4: Compute the synthetic IV over (path, plaintext) directly into
     * its output slot. Because the SIV depends on the plaintext, different
     * plaintexts at the same path yield different SIVs — and therefore
     * different keystreams — giving nonce-misuse resistance. This is the
     * defining step of SIV. */
    err = compute_siv(
        mac_key, storage_path, plaintext, plaintext_len, siv_slot
    );
    if (err) {
        goto cleanup;
    }

    /* Step 5: Derive the keystream seed from the SIV (keyed by prf_key so
     * the keystream is not reconstructable from the public SIV alone). */
    err = derive_keystream_seed(prf_key, siv_slot, keystream_seed);
    if (err) {
        goto cleanup;
    }

    /* Step 6: Write the keystream into the ciphertext slot, then XOR the
     * plaintext in place. One pass, one buffer. */
    if (plaintext_len > 0) {
        hydro_random_buf_deterministic(ct_slot, plaintext_len, keystream_seed);
        for (size_t i = 0; i < plaintext_len; i++) {
            ct_slot[i] ^= plaintext[i];
        }
    }

    /* Transfer to caller */
    *out_ciphertext = output;
    output = (buffer_t){ 0 };

cleanup:
    /* Securely clear sensitive data */
    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(prf_key, sizeof(prf_key));
    hydro_memzero(keystream_seed, sizeof(keystream_seed));

    /* On error, zero any bytes already written (including a freshly-written
     * keystream, which could otherwise disclose this plaintext's keystream
     * to an attacker who recovered the partial output). On success this is
     * a no-op — ownership was transferred to the caller above. */
    if (output.data) {
        hydro_memzero(output.data, output.size);
        buffer_free(&output);
    }

    return err;
}

error_t *encryption_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_plaintext
) {
    CHECK_NULL(ciphertext);
    CHECK_NULL(profile_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_plaintext);

    error_t *err = NULL;
    uint8_t mac_key[32] = { 0 };
    uint8_t prf_key[32] = { 0 };
    uint8_t keystream_seed[32] = { 0 };
    uint8_t siv_recomputed[ENCRYPTION_SIV_SIZE] = { 0 };
    unsigned char *plaintext_data = NULL;
    size_t plaintext_len = 0;
    buffer_t output = BUFFER_INIT;

    *out_plaintext = (buffer_t){ 0 };

    /* Defensive: reject pathological storage paths at the boundary.
     * strnlen keeps the scan bounded even if the caller hands us a
     * non-NUL-terminated buffer. */
    if (strnlen(storage_path, ENCRYPTION_STORAGE_PATH_MAX + 1)
        > ENCRYPTION_STORAGE_PATH_MAX) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path too long (maximum %d bytes)",
            ENCRYPTION_STORAGE_PATH_MAX
        );
    }

    /* Policy cap: mirror the encrypt-side limit. ciphertext_len includes
     * header + SIV, so the inner plaintext is ciphertext_len - OVERHEAD
     * bytes — cap the total with the overhead baked in. */
    if (ciphertext_len
        > ENCRYPTION_MAX_CONTENT_SIZE + (size_t) ENCRYPTION_OVERHEAD) {
        return ERROR(
            ERR_INVALID_ARG,
            "Ciphertext too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            ciphertext_len,
            (size_t) ENCRYPTION_MAX_CONTENT_SIZE + (size_t) ENCRYPTION_OVERHEAD
        );
    }

    /* Step 1: Validate minimum size */
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        return ERROR(
            ERR_CRYPTO, "Invalid ciphertext: (expected >= %d, got %zu)",
            ENCRYPTION_OVERHEAD, ciphertext_len
        );
    }

    /* Step 2: Verify magic header and version.
     *
     * Check magic bytes and version separately to give precise diagnostics.
     * A version mismatch should report the actual version found, not just
     * "invalid magic header". */
    if (memcmp(ciphertext, MAGIC_HEADER, ENCRYPTION_MAGIC_BYTES) != 0) {
        return ERROR(
            ERR_CRYPTO, "Invalid magic header (not a dotta encrypted file)"
        );
    }

    if (ciphertext[5] != ENCRYPTION_VERSION) {
        return ERROR(
            ERR_CRYPTO, "Unsupported encryption version: %d (expected %d)",
            ciphertext[5], ENCRYPTION_VERSION
        );
    }

    /* Step 3: Extract SIV and ciphertext body */
    const unsigned char *siv_received =
        ciphertext + ENCRYPTION_HEADER_SIZE;
    const unsigned char *ct_body =
        ciphertext + ENCRYPTION_HEADER_SIZE + ENCRYPTION_SIV_SIZE;
    plaintext_len = ciphertext_len - ENCRYPTION_OVERHEAD;

    /* Step 4: Derive MAC and PRF subkeys from profile key */
    err = derive_siv_subkeys(profile_key, mac_key, prf_key);
    if (err) {
        goto cleanup;
    }

    /* Step 5: Derive the keystream seed from the received SIV.
     *
     * In SIV, the IV authenticates the plaintext — it cannot be checked
     * without first recovering the plaintext. We therefore decrypt first,
     * compute siv' over the candidate plaintext, and compare against the
     * received SIV. The candidate is held in memory only until that
     * comparison; on mismatch it is wiped by the cleanup path and never
     * returned to the caller. */
    err = derive_keystream_seed(prf_key, siv_received, keystream_seed);
    if (err) {
        goto cleanup;
    }

    /* Step 6: Generate the keystream directly into the candidate plaintext
     * buffer, then XOR the ciphertext body into it. */
    if (plaintext_len > 0) {
        plaintext_data = malloc(plaintext_len);
        if (!plaintext_data) {
            err = ERROR(ERR_MEMORY, "Failed to allocate plaintext buffer");
            goto cleanup;
        }
        hydro_random_buf_deterministic(
            plaintext_data, plaintext_len, keystream_seed
        );
        for (size_t i = 0; i < plaintext_len; i++) {
            plaintext_data[i] ^= ct_body[i];
        }
    }

    /* Step 7: Re-compute the SIV over (path, candidate_plaintext). If the
     * ciphertext is authentic, this matches the received SIV exactly. */
    err = compute_siv(
        mac_key, storage_path, plaintext_data, plaintext_len, siv_recomputed
    );
    if (err) {
        goto cleanup;
    }

    /* Step 8: Constant-time compare. On mismatch, the cleanup path wipes
     * the candidate plaintext before returning. */
    if (!hydro_equal(siv_recomputed, siv_received, ENCRYPTION_SIV_SIZE)) {
        err = ERROR(
            ERR_CRYPTO, "Authentication failed "
            "- wrong passphrase, corrupted file, or incorrect path"
        );
        goto cleanup;
    }

    /* Step 9: Transfer plaintext to the output buffer */
    if (plaintext_len > 0) {
        err = buffer_append(&output, plaintext_data, plaintext_len);
        if (err) {
            goto cleanup;
        }
    }

    *out_plaintext = output;
    output = (buffer_t){ 0 };

cleanup:
    /* Securely clear sensitive data */
    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(prf_key, sizeof(prf_key));
    hydro_memzero(keystream_seed, sizeof(keystream_seed));
    hydro_memzero(siv_recomputed, sizeof(siv_recomputed));

    if (plaintext_data) {
        hydro_memzero(plaintext_data, plaintext_len);
        free(plaintext_data);
    }

    if (output.data) {
        hydro_memzero(output.data, output.size);
        buffer_free(&output);
    }

    return err;
}

bool encryption_is_encrypted(const unsigned char *data, size_t data_len) {
    /* Require magic + version so we only identify blobs we can actually
     * decrypt. A file whose first bytes happen to be "DOTTA" but encode
     * a different version byte is treated as plaintext here; the decrypt
     * path still surfaces a precise "unsupported version" error if a
     * caller does reach it (e.g. via explicit --no-encrypt override). */
    if (!data || data_len < ENCRYPTION_DETECT_BYTES) {
        return false;
    }

    return memcmp(data, MAGIC_HEADER, ENCRYPTION_DETECT_BYTES) == 0;
}
