/**
 * encryption.h - Cryptographic primitives for file encryption
 *
 * Provides deterministic authenticated encryption for sensitive dotfiles using
 * a SIV (Synthetic IV) construction built on libhydrogen primitives.
 * Files are encrypted at rest in Git and decrypted during deployment.
 *
 * Key hierarchy:
 *   User Passphrase
 *     → Master Key (via hydro_pwhash_deterministic)
 *     → Profile Key (via hydro_hash_hash with profile name)
 *     → Per-file MAC Key + CTR Key (via hydro_kdf_derive_from_key)
 *
 * SIV Construction (Version 2):
 *   This implements deterministic AEAD using the SIV (Synthetic IV) pattern:
 *
 *   1. Derive subkeys:
 *      mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")
 *      ctr_key = KDF(profile_key, subkey_id=2, context="dottasiv")
 *
 *   2. Derive deterministic stream seed:
 *      stream_seed = HMAC(ctr_key, storage_path, context="dottactr")
 *
 *   3. Encrypt using deterministic stream cipher:
 *      keystream = DeterministicPRNG(stream_seed, length=plaintext_len)
 *      ciphertext = plaintext XOR keystream
 *
 *   4. Compute SIV (MAC over associated data + ciphertext):
 *      siv = HMAC(mac_key, storage_path || ciphertext, context="dottamac")
 *
 *   File format: [Magic 8B][SIV 32B][Ciphertext N B]
 *
 * Security properties:
 * - Deterministic: Same (path, content, key) → same ciphertext (Git-friendly)
 * - Authenticated: Tamper detection via SIV verification
 * - Path-bound: Files tied to specific storage paths (AAD)
 * - Nonce-misuse resistant: No nonce management required
 * - Key isolation: Independent MAC and CTR keys via KDF
 * - Secure memory clearing after use
 */

#ifndef DOTTA_ENCRYPTION_H
#define DOTTA_ENCRYPTION_H

#include <stdbool.h>
#include <stdint.h>

#include "types.h"

/* Magic header for encrypted files */
#define ENCRYPTION_MAGIC "DOTTA"
#define ENCRYPTION_MAGIC_BYTES 5        /* "DOTTA" magic string length */
#define ENCRYPTION_VERSION 2            /* Version 2: SIV-based deterministic encryption */
#define ENCRYPTION_MAGIC_HEADER_SIZE 8  /* Magic (5 bytes) + version (1 byte) + padding (2 bytes) */
#define ENCRYPTION_HEADER_SIZE 8        /* Magic header (8 bytes) */
#define ENCRYPTION_SIV_SIZE 32          /* SIV/MAC tag (32 bytes) */
#define ENCRYPTION_OVERHEAD 40          /* Header (8) + SIV (32) */

/* Context strings (MUST be exactly 8 bytes) */
#define ENCRYPTION_CTX_PWHASH    "dotta/v1"
#define ENCRYPTION_CTX_KDF       "profile "  /* Note: 8 chars with trailing space */
#define ENCRYPTION_CTX_SIV_KDF   "dottasiv"  /* For deriving MAC/CTR subkeys */
#define ENCRYPTION_CTX_SIV_MAC   "dottamac"  /* For computing SIV/MAC */
#define ENCRYPTION_CTX_SIV_CTR   "dottactr"  /* For deriving stream seed */

/* Key sizes (from libhydrogen) */
#define ENCRYPTION_MASTER_KEY_SIZE 32       /* hydro_pwhash output */
#define ENCRYPTION_PROFILE_KEY_SIZE 32      /* hydro_kdf output */

/**
 * Initialize libhydrogen
 *
 * Must be called once at program startup before any encryption operations.
 * This initializes the random number generator and other internal state.
 *
 * @return Error or NULL on success
 */
error_t *encryption_init(void);

/**
 * Derive master key from passphrase
 *
 * Uses hydro_pwhash_deterministic to derive a 32-byte master key from
 * a user passphrase. The same passphrase always produces the same key
 * (deterministic derivation).
 *
 * This is a computationally expensive operation (controlled by opslimit
 * and memlimit). Higher values provide better protection against brute
 * force attacks but take longer.
 *
 * @param passphrase User passphrase (must not be NULL)
 * @param passphrase_len Length of passphrase in bytes
 * @param opslimit CPU cost parameter (recommended: 10000+)
 * @param memlimit Memory usage in bytes (recommended: 64MB+)
 * @param threads Number of threads for parallelization (1 = portable)
 * @param out_master_key Output buffer for 32-byte master key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *encryption_derive_master_key(
    const char *passphrase,
    size_t passphrase_len,
    uint64_t opslimit,
    size_t memlimit,
    uint8_t threads,
    uint8_t out_master_key[ENCRYPTION_MASTER_KEY_SIZE]
);

/**
 * Derive profile-specific key from master key
 *
 * Uses hydro_kdf_derive_from_key to derive a per-profile encryption key.
 * Each profile gets a unique key (derived from hash of profile name),
 * providing cryptographic isolation between profiles.
 *
 * This is a fast operation (no expensive hashing).
 *
 * @param master_key Master key (32 bytes, must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param out_profile_key Output buffer for 32-byte profile key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *encryption_derive_profile_key(
    const uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE],
    const char *profile_name,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
);

/**
 * Encrypt file content using SIV construction
 *
 * Encrypts plaintext using deterministic AEAD (SIV pattern). The encryption is
 * deterministic: same (storage_path, plaintext, profile_key) always produces
 * the same ciphertext, enabling Git deduplication and idempotency.
 *
 * Construction:
 *   1. Derive mac_key and ctr_key from profile_key via KDF
 *   2. Derive stream seed from ctr_key and storage_path
 *   3. Generate deterministic keystream and XOR with plaintext
 *   4. Compute SIV/MAC over storage_path || ciphertext
 *
 * Output format:
 *   [Magic: "DOTTA\x02\x00\x00" (8 bytes)]
 *   [SIV: MAC tag (32 bytes)]
 *   [Ciphertext: encrypted data (plaintext_len bytes)]
 *
 * The storage_path is used as authenticated associated data (AAD), binding
 * the ciphertext to its intended location. A file encrypted for one path
 * cannot be successfully decrypted for a different path.
 *
 * @param plaintext Input data (must not be NULL)
 * @param plaintext_len Input length in bytes
 * @param profile_key Profile-specific encryption key (32 bytes, must not be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc", must not be NULL)
 * @param out_ciphertext Output buffer (caller must free with buffer_free)
 * @return Error or NULL on success
 */
error_t *encryption_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t **out_ciphertext
);

/**
 * Decrypt file content using SIV construction
 *
 * Verifies dotta header, validates SIV/MAC, and decrypts ciphertext.
 *
 * Process:
 *   1. Parse header and extract SIV
 *   2. Derive mac_key and ctr_key from profile_key
 *   3. Re-compute SIV over storage_path || ciphertext
 *   4. Verify SIV matches (constant-time comparison)
 *   5. If valid, derive keystream and decrypt
 *
 * The storage_path must match the path used during encryption. This is
 * authenticated via the SIV - any mismatch will cause verification to fail.
 *
 * Returns ERR_CRYPTO if:
 * - Authentication fails (SIV mismatch - wrong key, tampered data, or wrong path)
 * - Invalid header format
 * - Unsupported version
 *
 * @param ciphertext Encrypted input (must not be NULL, must include dotta header)
 * @param ciphertext_len Input length in bytes (must be >= ENCRYPTION_OVERHEAD)
 * @param profile_key Profile-specific decryption key (32 bytes, must not be NULL)
 * @param storage_path File path in profile (must match encryption path, must not be NULL)
 * @param out_plaintext Output buffer (caller must free with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on authentication failure)
 */
error_t *encryption_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
    const char *storage_path,
    buffer_t **out_plaintext
);

/**
 * Check if data is encrypted
 *
 * Checks for dotta encryption magic header ("DOTTA").
 * Does not validate version or nonce.
 *
 * @param data File content (must not be NULL)
 * @param data_len Content length
 * @return true if data has valid dotta encryption magic header
 */
bool encryption_is_encrypted(const unsigned char *data, size_t data_len);

#endif /* DOTTA_ENCRYPTION_H */
