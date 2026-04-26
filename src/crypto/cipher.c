/**
 * cipher.c - SIV encryption/decryption implementation
 */

#include "crypto/cipher.h"

#include <hydrogen.h>
#include <string.h>

#include "base/buffer.h"
#include "base/encoding.h"
#include "base/error.h"

/* Context strings (8 bytes, libhydrogen requirement). */
static const char CTX_SIV_MAC[8] = { 'd', 'o', 't', 't', 'a', 'm', 'a', 'c' };
static const char CTX_SIV_CTR[8] = { 'd', 'o', 't', 't', 'a', 'c', 't', 'r' };

/* File-format magic header: "DOTTA" + version byte + 2 reserved zero bytes. */
static const unsigned char MAGIC_HEADER[CIPHER_HEADER_SIZE] = {
    'D', 'O', 'T', 'T', 'A', /* Magic: "DOTTA" */
    CIPHER_VERSION, /* Version byte */
    0x00, 0x00      /* Reserved (padding to 8 bytes) */
};

/* Defensive upper bound on storage_path bytes (excluding NUL).
 *
 * Storage paths are profile-relative ("home/.bashrc", "root/etc/foo"), so
 * in practice they stay well under 1 KiB. The cap exists so the crypto
 * module defends itself at its own boundary rather than trusting upstream
 * validation, and so the same limit holds on every platform (PATH_MAX
 * varies — 1024 on macOS, 4096 on Linux). Trips only on pathological
 * input; normal callers never approach it. */
#define CIPHER_STORAGE_PATH_MAX 4096

/* Maximum file size for encryption / decryption (100 MiB).
 *
 * Dotfiles are small configuration files; a 100 MiB cap prevents the
 * crypto layer from allocating huge keystream / ciphertext buffers on
 * behalf of runaway input. Enforced at both entry points so every
 * caller — regardless of how the bytes reached us — hits the same
 * limit with the same diagnostic. */
#define CIPHER_MAX_CONTENT_SIZE ((size_t) 100 * 1024 * 1024)

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
 * @param out_siv Output buffer for SIV (CIPHER_SIV_SIZE bytes)
 * @return Error or NULL on success
 */
static error_t *compute_siv(
    const uint8_t mac_key[KDF_KEY_SIZE],
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint8_t out_siv[CIPHER_SIV_SIZE]
) {
    hydro_hash_state mac_state;

    /* Initialize MAC with mac_key */
    if (hydro_hash_init(&mac_state, CTX_SIV_MAC, mac_key) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to initialize SIV computation");
    }

    /* Length-prefix the path for domain separation */
    size_t path_len = strlen(storage_path);
    uint8_t path_len_le[8];
    store_le64(path_len_le, (uint64_t) path_len);

    /* Authenticate storage_path (associated data) */
    hydro_hash_update(&mac_state, path_len_le, sizeof(path_len_le));
    hydro_hash_update(&mac_state, (const uint8_t *) storage_path, path_len);

    /* Guard against NULL when plaintext_len == 0 (libhydrogen does not
     * promise NULL-safe pointer arithmetic on a zero-length update). */
    if (plaintext_len > 0) {
        hydro_hash_update(&mac_state, plaintext, plaintext_len);
    }

    /* Finalize to get SIV */
    hydro_hash_final(&mac_state, out_siv, CIPHER_SIV_SIZE);

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
 * @param siv Synthetic IV (CIPHER_SIV_SIZE bytes)
 * @param out_seed Output buffer for keystream seed (32 bytes)
 * @return Error or NULL on success
 */
static error_t *derive_keystream_seed(
    const uint8_t prf_key[KDF_KEY_SIZE],
    const uint8_t siv[CIPHER_SIV_SIZE],
    uint8_t out_seed[32]
) {
    if (hydro_hash_hash(
        out_seed, 32, siv, CIPHER_SIV_SIZE, CTX_SIV_CTR, prf_key
        ) != 0) {
        return ERROR(ERR_CRYPTO, "Failed to derive keystream seed");
    }

    return NULL;
}

/**
 * Defensive checks shared by encrypt and decrypt entry points.
 *
 * `strnlen` (rather than `strlen`) caps the scan even if the caller hands
 * us a non-NUL-terminated buffer. The crypto module defends itself at its
 * own boundary rather than trusting upstream validation, so a memory-
 * safety bug in a caller does not propagate into hash/MAC absorption.
 */
static error_t *validate_path(const char *storage_path) {
    if (strnlen(storage_path, CIPHER_STORAGE_PATH_MAX + 1)
        > CIPHER_STORAGE_PATH_MAX) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path too long (maximum %d bytes)",
            CIPHER_STORAGE_PATH_MAX
        );
    }
    return NULL;
}

error_t *cipher_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(plaintext);
    CHECK_NULL(mac_key);
    CHECK_NULL(prf_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    error_t *err = NULL;
    uint8_t keystream_seed[32] = { 0 };
    buffer_t output = BUFFER_INIT;

    *out_ciphertext = (buffer_t){ 0 };

    err = validate_path(storage_path);
    if (err) {
        return err;
    }

    /* Policy cap: dotta manages small configuration files. A single cap
     * on the crypto entry point enforces the rule for every caller. */
    if (plaintext_len > CIPHER_MAX_CONTENT_SIZE) {
        return ERROR(
            ERR_INVALID_ARG,
            "Content too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            plaintext_len, (size_t) CIPHER_MAX_CONTENT_SIZE
        );
    }

    /* Calculate output size with overflow detection */
    if (plaintext_len > SIZE_MAX - CIPHER_OVERHEAD) {
        return ERROR(
            ERR_INVALID_ARG, "Plaintext too large (size_t overflow): %zu bytes",
            plaintext_len
        );
    }
    size_t total_len = CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE + plaintext_len;

    /* Allocate the output buffer at its final size and write directly.
     *
     * buffer_grow reserves total_len + 1 bytes (for the NUL terminator). We
     * own [0, total_len) and restore the invariant NUL at [total_len]. This
     * layout lets us compute the SIV and keystream straight into the output,
     * so peak memory is total_len bytes instead of the 3 * N of separate
     * keystream + ciphertext + output buffers. */
    err = buffer_grow(&output, total_len);
    if (err) goto cleanup;

    output.size = total_len;
    output.data[output.size] = '\0';

    /* Write the fixed header */
    memcpy(output.data, MAGIC_HEADER, CIPHER_HEADER_SIZE);

    unsigned char *siv_slot =
        (unsigned char *) output.data + CIPHER_HEADER_SIZE;
    unsigned char *ct_slot = siv_slot + CIPHER_SIV_SIZE;

    /* Compute the synthetic IV over (path, plaintext) directly into its output slot.
     * Because the SIV depends on the plaintext, different plaintexts at the same
     * path yield different SIVs — and therefore different keystreams — giving
     * nonce-misuse resistance. This is the defining step of SIV. */
    err = compute_siv(mac_key, storage_path, plaintext, plaintext_len, siv_slot);
    if (err) goto cleanup;


    /* Derive the keystream seed from the SIV (keyed by prf_key so the
     * keystream is not reconstructable from the public SIV alone). */
    err = derive_keystream_seed(prf_key, siv_slot, keystream_seed);
    if (err) goto cleanup;

    /* Write keystream into the ciphertext slot, then XOR plaintext in
     * place. One pass, one buffer. */
    if (plaintext_len > 0) {
        hydro_random_buf_deterministic(ct_slot, plaintext_len, keystream_seed);
        for (size_t i = 0; i < plaintext_len; i++) {
            ct_slot[i] ^= plaintext[i];
        }
    }

    /* Transfer ownership to caller. */
    *out_ciphertext = output;
    output = (buffer_t){ 0 };

cleanup:
    /* Securely clear sensitive data */
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

error_t *cipher_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_plaintext
) {
    CHECK_NULL(ciphertext);
    CHECK_NULL(mac_key);
    CHECK_NULL(prf_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_plaintext);

    error_t *err = NULL;
    uint8_t keystream_seed[32] = { 0 };
    uint8_t siv_recomputed[CIPHER_SIV_SIZE] = { 0 };
    buffer_t output = BUFFER_INIT;

    *out_plaintext = (buffer_t){ 0 };

    /* Defensive: reject pathological storage paths at the boundary */
    err = validate_path(storage_path);
    if (err) return err;

    /* Policy cap: mirror the encrypt-side limit. ciphertext_len includes
     * header + SIV, so the inner plaintext is ciphertext_len - OVERHEAD
     * bytes — cap the total with the overhead baked in. */
    if (ciphertext_len > CIPHER_MAX_CONTENT_SIZE + (size_t) CIPHER_OVERHEAD) {
        return ERROR(
            ERR_INVALID_ARG,
            "Ciphertext too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            ciphertext_len,
            (size_t) CIPHER_MAX_CONTENT_SIZE + (size_t) CIPHER_OVERHEAD
        );
    }

    /* Validate minimum size */
    if (ciphertext_len < CIPHER_OVERHEAD) {
        return ERROR(
            ERR_CRYPTO, "Invalid ciphertext: (expected >= %d, got %zu)",
            CIPHER_OVERHEAD, ciphertext_len
        );
    }

    /* Verify magic header and version.
     *
     * Check magic bytes and version separately to give precise diagnostics.
     * A version mismatch should report the actual version found, not just
     * "invalid magic header". */
    if (memcmp(ciphertext, MAGIC_HEADER, CIPHER_MAGIC_BYTES) != 0) {
        return ERROR(
            ERR_CRYPTO, "Invalid magic header (not a dotta encrypted file)"
        );
    }
    if (ciphertext[5] != CIPHER_VERSION) {
        return ERROR(
            ERR_CRYPTO, "Unsupported encryption version: %d (expected %d)",
            ciphertext[5], CIPHER_VERSION
        );
    }

    /* Extract SIV and ciphertext body */
    const unsigned char *siv_received = ciphertext + CIPHER_HEADER_SIZE;
    const unsigned char *ct_body = ciphertext + CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE;
    size_t plaintext_len = ciphertext_len - CIPHER_OVERHEAD;

    /* Derive the keystream seed from the received SIV.
     *
     * In SIV, the IV authenticates the plaintext — it cannot be checked
     * without first recovering the plaintext. We therefore decrypt first,
     * compute siv' over the candidate plaintext, and compare against the
     * received SIV. The candidate is held in memory only until that
     * comparison; on mismatch it is wiped by the cleanup path and never
     * returned to the caller. */
    err = derive_keystream_seed(prf_key, siv_received, keystream_seed);
    if (err) goto cleanup;

    /* Allocate the output at its final size and decrypt straight into it,
     * mirroring the encrypt path. The previous implementation decrypted
     * into a separate heap buffer and then copied into the output, paying
     * one extra alloc and one extra full-buffer memcpy per file. */
    err = buffer_grow(&output, plaintext_len);
    if (err) goto cleanup;

    output.size = plaintext_len;
    output.data[output.size] = '\0';

    /* Generate the keystream directly into the candidate plaintext
     * buffer, then XOR the ciphertext body into it. */
    if (plaintext_len > 0) {
        hydro_random_buf_deterministic(
            (unsigned char *) output.data, plaintext_len, keystream_seed
        );
        unsigned char *pt = (unsigned char *) output.data;
        for (size_t i = 0; i < plaintext_len; i++) {
            pt[i] ^= ct_body[i];
        }
    }

    /* Re-compute SIV over (path, candidate plaintext) and compare to the
     * received SIV. SIV authenticates the plaintext — it cannot be checked
     * before decryption — so we hold the candidate just long enough to
     * verify, then either return it or wipe it via the cleanup path. */
    err = compute_siv(
        mac_key, storage_path,
        (const unsigned char *) output.data,
        plaintext_len,
        siv_recomputed
    );
    if (err) goto cleanup;

    /* Constant-time compare. On mismatch, the cleanup path wipes
     * the candidate plaintext before returning. */
    if (!hydro_equal(siv_recomputed, siv_received, CIPHER_SIV_SIZE)) {
        err = ERROR(
            ERR_CRYPTO, "Authentication failed "
            "- wrong passphrase, corrupted file, or incorrect path"
        );
        goto cleanup;
    }

    /* Transfer plaintext to the output buffer */
    *out_plaintext = output;
    output = (buffer_t){ 0 };

cleanup:
    /* Securely clear sensitive data */
    hydro_memzero(keystream_seed, sizeof(keystream_seed));
    hydro_memzero(siv_recomputed, sizeof(siv_recomputed));
    if (output.data) {
        hydro_memzero(output.data, output.size);
        buffer_free(&output);
    }

    return err;
}

bool cipher_is_encrypted(const unsigned char *data, size_t data_len) {
    /* Require magic + version so we only identify blobs we can actually
     * decrypt. A file whose first bytes happen to be "DOTTA" but encode
     * a different version byte is treated as plaintext here; the decrypt
     * path still surfaces a precise "unsupported version" error if a
     * caller does reach it (e.g. via explicit --no-encrypt override). */
    if (!data || data_len < CIPHER_DETECT_BYTES) {
        return false;
    }

    return memcmp(data, MAGIC_HEADER, CIPHER_DETECT_BYTES) == 0;
}
