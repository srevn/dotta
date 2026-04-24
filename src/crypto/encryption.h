/**
 * encryption.h - Cryptographic primitives for file encryption
 *
 * Provides deterministic authenticated encryption for sensitive dotfiles using
 * a SIV (Synthetic IV) construction built on libhydrogen primitives, in the
 * spirit of RFC 5297. Files are encrypted at rest in Git and decrypted during
 * deployment.
 *
 * Key hierarchy:
 *   User Passphrase
 *     → hydro_pwhash_deterministic (CPU-hard, Gimli iterations)
 *     → balloon_harden (memory-hard, when memlimit > 0)
 *     → Master Key (32 bytes)
 *       → Profile Key (via hydro_hash_hash with profile name)
 *         → Per-file MAC Key + PRF Key (via hydro_kdf_derive_from_key)
 *
 * SIV Construction (Version 4):
 *   Deterministic AEAD where the synthetic IV is computed from the plaintext
 *   itself — the defining property of SIV. The IV doubles as the
 *   authentication tag:
 *
 *   1. Derive subkeys from the profile key:
 *      mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")
 *      prf_key = KDF(profile_key, subkey_id=2, context="dottasiv")
 *
 *   2. Compute synthetic IV over path and plaintext:
 *      siv = HMAC(mac_key,
 *                 len(storage_path) as LE64 || storage_path || plaintext,
 *                 context="dottamac")
 *      (path length prefix provides domain separation; BLAKE2 is not
 *       length-extension vulnerable, so no trailing length is required)
 *
 *   3. Derive a secret keystream seed from the (public) SIV:
 *      keystream_seed = HMAC(prf_key, siv, context="dottactr")
 *      (prf_key keeps the keystream behind the profile key — if the seed
 *       were computed directly from the public SIV, anyone with the
 *       ciphertext could reproduce the keystream and recover the plaintext)
 *
 *   4. Encrypt using deterministic stream cipher:
 *      keystream = DeterministicPRNG(keystream_seed, length=plaintext_len)
 *      ciphertext = plaintext XOR keystream
 *
 *   File format: [Magic 5B][Version 1B][Reserved 2B][SIV 32B][Ciphertext N B]
 *
 * Security properties:
 * - Deterministic: Same (path, plaintext, key) → same ciphertext (Git-friendly)
 * - Authenticated: SIV is a MAC over (path, plaintext); any tampering of SIV
 *   or ciphertext produces an SIV mismatch after trial decryption.
 * - Path-bound: Ciphertext decrypted under a different path fails SIV
 *   verification.
 * - Nonce-misuse resistant: Different plaintexts at the same path yield
 *   different synthetic IVs (and therefore different keystreams), avoiding
 *   the many-time-pad leak that would occur if the keystream were a pure
 *   function of the path.
 * - Key isolation: Independent MAC and PRF keys via KDF.
 * - Secure memory clearing after use.
 */

#ifndef DOTTA_ENCRYPTION_H
#define DOTTA_ENCRYPTION_H

#include <stdbool.h>
#include <stdint.h>
#include <types.h>

/* Magic header for encrypted files */
#define ENCRYPTION_MAGIC "DOTTA"
#define ENCRYPTION_MAGIC_BYTES 5        /* "DOTTA" magic string length */
#define ENCRYPTION_VERSION 4            /* Version 4: SIV with IV bound to plaintext */
#define ENCRYPTION_DETECT_BYTES 6       /* Magic (5) + version (1): prefix length checking */
#define ENCRYPTION_HEADER_SIZE 8        /* Magic (5) + version (1) + reserved (2) */
#define ENCRYPTION_SIV_SIZE 32          /* SIV/MAC tag (32 bytes) */
#define ENCRYPTION_OVERHEAD 40          /* Header (8) + SIV (32) */

/* Context strings (MUST be exactly 8 bytes) */
#define ENCRYPTION_CTX_PWHASH    "dotta/v1"
#define ENCRYPTION_CTX_KDF       "profile "  /* Note: 8 chars with trailing space */
#define ENCRYPTION_CTX_SIV_KDF   "dottasiv"  /* For deriving MAC/PRF subkeys */
#define ENCRYPTION_CTX_SIV_MAC   "dottamac"  /* For computing SIV over (path, plaintext) */
#define ENCRYPTION_CTX_SIV_CTR   "dottactr"  /* For deriving keystream seed from SIV */

/* Key sizes (from libhydrogen) */
#define ENCRYPTION_MASTER_KEY_SIZE 32   /* hydro_pwhash output */
#define ENCRYPTION_PROFILE_KEY_SIZE 32  /* hydro_kdf output */

/* Password hashing parameters (passed to hydro_pwhash_deterministic) */
#define ENCRYPTION_PWHASH_MEMLIMIT 0    /* Unused by libhydrogen (memory hardness via balloon instead) */
#define ENCRYPTION_PWHASH_THREADS 1     /* Single-threaded (fixed) */

/* Balloon hashing parameters (memory-hard key derivation layer) */
#define ENCRYPTION_BALLOON_BLOCK_SIZE       1024                  /* Bytes per block */
#define ENCRYPTION_BALLOON_ROUNDS           3                     /* Mixing rounds */
#define ENCRYPTION_BALLOON_MEMLIMIT_DEFAULT (64 * 1024 * 1024)    /* 64 MB */
#define ENCRYPTION_BALLOON_MEMLIMIT_MIN     (1 * 1024 * 1024)     /* 1 MB minimum */

/* Balloon hashing context strings (must be exactly 8 bytes each) */
#define ENCRYPTION_CTX_BALLOON_EXPAND  "dottamem"  /* Expansion: per-block seed derivation */
#define ENCRYPTION_CTX_BALLOON_INDEX   "dottaidx"  /* Mixing: pseudo-random index derivation */
#define ENCRYPTION_CTX_BALLOON_MIX     "dottamix"  /* Mixing: block combination */
#define ENCRYPTION_CTX_BALLOON_FINAL   "dottafin"  /* Finalization: master key extraction */

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
 * Two-phase deterministic key derivation:
 *   1. CPU-hard: hydro_pwhash_deterministic (Gimli permutation iterations)
 *   2. Memory-hard: balloon hashing (large buffer with data-dependent access)
 *
 * The same (passphrase, opslimit, memlimit) always produces the same key
 * (deterministic derivation). Both phases are computationally expensive.
 *
 * When memlimit is 0, balloon hashing is skipped (CPU-hard only).
 * When memlimit is non-zero, it must be >= ENCRYPTION_BALLOON_MEMLIMIT_MIN.
 *
 * @param passphrase User passphrase (must not be NULL)
 * @param passphrase_len Length of passphrase in bytes
 * @param opslimit CPU cost parameter (recommended: 10000+, higher = more secure but slower)
 * @param memlimit Memory cost in bytes for balloon hashing (0 = disabled, default: 64 MB)
 * @param out_master_key Output buffer for 32-byte master key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *encryption_derive_master_key(
    const char *passphrase,
    size_t passphrase_len,
    uint64_t opslimit,
    size_t memlimit,
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
 * @param profile Profile name (must not be NULL)
 * @param out_profile_key Output buffer for 32-byte profile key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *encryption_derive_profile_key(
    const uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE],
    const char *profile,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
);

/**
 * Encrypt file content using SIV construction
 *
 * Encrypts plaintext using deterministic AEAD where the synthetic IV is
 * computed from the plaintext itself. Same (storage_path, plaintext,
 * profile_key) always produces the same ciphertext, enabling Git
 * deduplication and idempotency; different plaintexts at the same path
 * produce different IVs (and therefore different keystreams), giving
 * nonce-misuse resistance.
 *
 * Construction:
 *   1. Derive mac_key and prf_key from profile_key via KDF
 *   2. Compute siv = MAC(mac_key, len(path) || path || plaintext)
 *   3. Derive keystream_seed = MAC(prf_key, siv)
 *   4. ciphertext = plaintext XOR DeterministicPRNG(keystream_seed, N)
 *
 * Output format:
 *   [Magic: "DOTTA\x04\x00\x00" (8 bytes)]
 *   [SIV: synthetic IV / MAC tag (32 bytes)]
 *   [Ciphertext: encrypted data (plaintext_len bytes)]
 *
 * The storage_path is authenticated associated data, binding the ciphertext
 * to its intended location. A file encrypted for one path cannot be
 * successfully decrypted under another.
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
    buffer_t *out_ciphertext
);

/**
 * Decrypt file content using SIV construction
 *
 * Verifies dotta header, decrypts the ciphertext using the stored SIV as the
 * nonce, then re-computes the SIV over the candidate plaintext and verifies
 * that it matches the stored SIV.
 *
 * Process:
 *   1. Parse header and extract SIV + ciphertext body
 *   2. Derive mac_key and prf_key from profile_key
 *   3. Derive keystream_seed from (prf_key, stored SIV)
 *   4. Decrypt: candidate_plaintext = ciphertext XOR keystream
 *   5. Re-compute siv' = MAC(mac_key, len(path) || path || candidate_plaintext)
 *   6. Constant-time compare siv' against the stored SIV; on mismatch the
 *      candidate is wiped and never returned.
 *
 * The storage_path must match the path used during encryption. This is
 * authenticated via the SIV — any mismatch will cause verification to fail.
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
    buffer_t *out_plaintext
);

/**
 * Check if data is an encrypted dotta blob this build can decrypt
 *
 * Verifies both the "DOTTA" magic and the version byte match the current
 * build. Blobs with a different version byte are reported as NOT encrypted,
 * so callers never try to decrypt something they cannot parse; any version
 * mismatch for a blob that does claim to be a dotta file surfaces later
 * from encryption_decrypt with an explicit "unsupported version" error.
 *
 * @param data File content (must not be NULL)
 * @param data_len Content length
 * @return true if data begins with a recognised dotta magic + version
 */
bool encryption_is_encrypted(
    const unsigned char *data,
    size_t data_len
);

#endif /* DOTTA_ENCRYPTION_H */
