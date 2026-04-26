/**
 * cipher.h - Deterministic authenticated encryption (SIV)
 *
 * Provides deterministic AEAD for sensitive dotfiles using a Synthetic IV
 * construction (in the spirit of RFC 5297) built on libhydrogen primitives.
 * Files are encrypted at rest in Git and decrypted during deployment.
 *
 * SIV Construction (Version 4):
 *   The synthetic IV is computed from the plaintext itself — the defining
 *   property of SIV — and doubles as the authentication tag.
 *
 *   1. Compute synthetic IV over path and plaintext:
 *      siv = HMAC(mac_key,
 *                 len(storage_path) as LE64 || storage_path || plaintext,
 *                 context="dottamac")
 *      (path length prefix provides domain separation; BLAKE2 is not
 *       length-extension vulnerable, so no trailing length is required)
 *
 *   2. Derive a secret keystream seed from the (public) SIV:
 *      keystream_seed = HMAC(prf_key, siv, context="dottactr")
 *      (prf_key keeps the keystream behind the profile key — if the seed
 *       were computed directly from the public SIV, anyone with the
 *       ciphertext could reproduce the keystream and recover the plaintext)
 *
 *   3. Encrypt using deterministic stream cipher:
 *      keystream = DeterministicPRNG(keystream_seed, length=plaintext_len)
 *      ciphertext = plaintext XOR keystream
 *
 *   File format: [Magic 5B][Version 1B][Reserved 2B][SIV 32B][Ciphertext N B]
 *
 * Security properties:
 *   - Deterministic: same (path, plaintext, keys) → same ciphertext
 *     (Git-friendly).
 *   - Authenticated: SIV is a MAC over (path, plaintext); any tampering
 *     of SIV or ciphertext produces an SIV mismatch after trial decryption.
 *   - Path-bound: ciphertext decrypted under a different path fails SIV
 *     verification.
 *   - Nonce-misuse resistant: different plaintexts at the same path yield
 *     different SIVs (and therefore different keystreams), avoiding the
 *     many-time-pad leak that would occur if the keystream were a pure
 *     function of the path.
 *   - Key isolation: independent MAC and PRF keys via crypto/kdf.
 *
 * Subkey provenance: the (mac_key, prf_key) pair is derived by crypto/kdf
 * from a profile key. This module never sees the master key or the profile
 * key; it operates only on the per-SIV subkey pair, which is the exact
 * scope cipher needs.
 */

#ifndef DOTTA_CRYPTO_CIPHER_H
#define DOTTA_CRYPTO_CIPHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"

/* File format constants */
#define CIPHER_MAGIC          "DOTTA"
#define CIPHER_MAGIC_BYTES    5             /* "DOTTA" magic string length */
#define CIPHER_VERSION        5             /* SIV with IV bound to plaintext */
#define CIPHER_DETECT_BYTES   6             /* Magic (5) + version (1) */
#define CIPHER_HEADER_SIZE    8             /* Magic (5) + version (1) + reserved (2) */
#define CIPHER_SIV_SIZE       32            /* SIV / MAC tag */
#define CIPHER_OVERHEAD       40            /* Header (8) + SIV (32) */

/**
 * Encrypt a plaintext buffer under (mac_key, prf_key) bound to storage_path.
 *
 * Output layout:
 *   [Magic: "DOTTA\x04\x00\x00" (8 bytes)]
 *   [SIV: synthetic IV / MAC tag (32 bytes)]
 *   [Ciphertext: encrypted data (plaintext_len bytes)]
 *
 * @param plaintext     Input data (must not be NULL)
 * @param plaintext_len Input length in bytes
 * @param mac_key       SIV MAC key (32 bytes)
 * @param prf_key       SIV PRF key (32 bytes)
 * @param storage_path  File path in profile (authenticated; must not be NULL)
 * @param out_ciphertext Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success
 */
error_t *cipher_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_ciphertext
);

/**
 * Decrypt a dotta-encrypted blob bound to storage_path.
 *
 * Process:
 *   1. Parse header and extract SIV + ciphertext body.
 *   2. Derive keystream_seed from (prf_key, stored SIV).
 *   3. Decrypt: candidate_plaintext = ciphertext XOR keystream.
 *   4. Re-compute siv' = MAC(mac_key, len(path) || path || candidate_plaintext).
 *   5. Constant-time compare siv' against the stored SIV; on mismatch the
 *      candidate is wiped and never returned.
 *
 * Returns ERR_CRYPTO if:
 *   - Authentication fails (SIV mismatch — wrong key, tampered data, or wrong path)
 *   - Invalid header format
 *   - Unsupported version
 *
 * @param ciphertext     Encrypted input (must include 8-byte header + 32-byte SIV)
 * @param ciphertext_len Input length (>= CIPHER_OVERHEAD)
 * @param mac_key        SIV MAC key (32 bytes)
 * @param prf_key        SIV PRF key (32 bytes)
 * @param storage_path   Same path used at encryption time; AAD mismatch fails SIV
 * @param out_plaintext  Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on auth failure)
 */
error_t *cipher_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_plaintext
);

/**
 * Test whether a byte buffer is a dotta-encrypted blob this build can decrypt.
 *
 * Verifies both the "DOTTA" magic and the version byte match the current
 * build. Blobs with a different version byte are reported as NOT encrypted,
 * so callers never try to decrypt something they cannot parse; any version
 * mismatch for a blob that does claim to be a dotta file surfaces later
 * from cipher_decrypt with an explicit "unsupported version" error.
 *
 * @param data     File content (may be NULL when len == 0)
 * @param data_len Content length
 * @return true if data begins with a recognised dotta magic + version
 */
bool cipher_is_encrypted(const unsigned char *data, size_t data_len);

#endif /* DOTTA_CRYPTO_CIPHER_H */
