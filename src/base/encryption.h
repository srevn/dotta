/**
 * encryption.h - Cryptographic primitives for file encryption
 *
 * Provides authenticated encryption for sensitive dotfiles using libhydrogen.
 * Files are encrypted at rest in Git and decrypted during deployment.
 *
 * Key hierarchy:
 *   User Passphrase
 *     → Master Key (via hydro_pwhash_deterministic)
 *     → Profile Key (via hydro_kdf_derive_from_key)
 *     → Encrypted File (via hydro_secretbox_encrypt)
 *
 * Nonce derivation (Version 2):
 *   Nonces are derived deterministically from file content using keyed hashing:
 *     nonce = HMAC(profile_key, storage_path || plaintext)[0:8]
 *
 *   This ensures:
 *   - Same content → same nonce → same ciphertext (idempotent)
 *   - Different content → different nonce (collision-resistant)
 *   - No state tracking required (crash-safe)
 *   - Including path prevents identical files from having identical ciphertexts
 *
 * Security properties:
 * - Authenticated encryption (confidentiality + integrity)
 * - Per-profile key isolation
 * - Content-addressed nonce uniqueness (deterministic encryption)
 * - Secure memory clearing after use
 */

#ifndef DOTTA_ENCRYPTION_H
#define DOTTA_ENCRYPTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "types.h"

/* Magic header for encrypted files */
#define ENCRYPTION_MAGIC "DOTTA"
#define ENCRYPTION_MAGIC_BYTES 5        /* "DOTTA" magic string length */
#define ENCRYPTION_VERSION 2            /* Version 2: content-addressed nonces */
#define ENCRYPTION_MAGIC_HEADER_SIZE 8  /* Magic (5 bytes) + version (1 byte) + padding (2 bytes) */
#define ENCRYPTION_HEADER_SIZE 16       /* Magic header (8 bytes) + nonce (8 bytes) */
#define ENCRYPTION_OVERHEAD 52          /* Header (16) + secretbox (36) */

/* Context strings (MUST be exactly 8 bytes) */
#define ENCRYPTION_CTX_SECRETBOX "dottaenc"
#define ENCRYPTION_CTX_PWHASH    "dotta/v1"
#define ENCRYPTION_CTX_KDF       "profile "  /* Note: 8 chars with trailing space */

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
 * Encrypt file content
 *
 * Encrypts plaintext using hydro_secretbox_encrypt with deterministic nonce.
 * The nonce is derived from content using keyed hashing (see header comment).
 *
 * Output format:
 *   [Magic: "DOTTA\x02\x00\x00" (8 bytes)]
 *   [nonce: uint64_t little-endian (8 bytes)]
 *   [secretbox output: header + ciphertext (36 + plaintext_len bytes)]
 *
 * Encryption is deterministic: same (storage_path, plaintext) always produces
 * the same ciphertext. This provides idempotency for crash recovery.
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
 * Decrypt file content
 *
 * Verifies dotta header, extracts nonce, and decrypts using hydro_secretbox_decrypt.
 *
 * Returns ERR_CRYPTO if:
 * - Authentication fails (wrong key or tampered ciphertext)
 * - Invalid header format
 * - Unsupported version
 *
 * @param ciphertext Encrypted input (must not be NULL, must include dotta header)
 * @param ciphertext_len Input length in bytes (must be >= ENCRYPTION_OVERHEAD)
 * @param profile_key Profile-specific decryption key (32 bytes, must not be NULL)
 * @param out_plaintext Output buffer (caller must free with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on authentication failure)
 */
error_t *encryption_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE],
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
