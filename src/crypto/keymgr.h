/**
 * keymgr.h - Encryption key management and session caching
 *
 * Manages the encryption master key lifecycle with session-based caching.
 * Prompts for passphrase when needed and caches the derived master key
 * both in memory and on disk for a configurable timeout period.
 *
 * Design principles:
 * - Single passphrase for all profiles (UX-friendly)
 * - Session-based caching (balance security vs UX)
 * - Persistent disk cache across command invocations (~/.cache/dotta/session)
 * - Configurable timeout (default: 1 hour)
 * - Secure memory clearing (hydro_memzero)
 * - Memory locking to prevent swap (mlock on POSIX systems)
 * - Monotonic clock for cache expiry (immune to clock manipulation)
 * - Environment variable fallback for automation
 *
 * Security considerations:
 * - Master key stored in process memory and on disk (vulnerable to dumps/theft)
 * - Disk cache obfuscated (XOR with host-bound keystream) and
 *   tamper-evident (keyed MAC) — not cryptographically encrypted; a
 *   reader with file access plus hostname/username can recover the key.
 *   See crypto/session.h for the full threat model.
 * - mlock() protection prevents swapping to disk (best-effort):
 *   * Master key in keymgr struct
 *   * Passphrase buffers during input/derivation
 * - Graceful degradation if mlock fails (logs warning)
 * - In-memory cache uses monotonic time (prevents lifetime manipulation)
 * - Cleared on timeout, explicit clear, or handle free; kernel reclaims
 *   locked pages on process death regardless
 */

#ifndef DOTTA_KEYMGR_H
#define DOTTA_KEYMGR_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <types.h>

/* Forward declarations */
typedef struct config config_t;

/**
 * Key manager (opaque)
 *
 * Maintains cached master key and session state.
 */
typedef struct keymgr keymgr;

/**
 * Create key manager
 *
 * Initializes session-based key management with configuration.
 * Does not prompt for passphrase immediately - passphrase is
 * requested on first key access (lazy initialization).
 *
 * @param config Configuration (for derivation memlimit and session_timeout)
 * @param out Key manager (caller must free with keymgr_free)
 * @return Error or NULL on success
 */
error_t *keymgr_create(
    const config_t *config,
    keymgr **out
);

/**
 * Encrypt plaintext under a profile-derived key
 *
 * Acquires the profile key internally, calls the encryption primitive,
 * and zeroes the derived key buffer before returning — callers never
 * see raw key bytes. On a cold keymgr this may prompt for the passphrase
 * and run the memory-hard derivation; once warm, each call only costs a
 * cheap keyed-BLAKE2 derivation plus the encryption itself.
 *
 * Error wrapping policy:
 *   - Subkey-derivation errors are wrapped with a uniform message that
 *     names the profile (the caller already knows the path; it rarely
 *     needs both).
 *   - `cipher_encrypt` errors are returned unwrapped so the caller can
 *     attach file-level context (path, operation) without duplicating a
 *     generic wrap that loses fidelity.
 *
 * @param keymgr       Key manager (must not be NULL)
 * @param profile      Profile name for key derivation (must not be NULL)
 * @param storage_path File path in profile (must not be NULL; AAD bound
 *                     into the ciphertext by `cipher_encrypt`)
 * @param plaintext    Plaintext bytes (must not be NULL unless len == 0)
 * @param plaintext_len Plaintext length in bytes
 * @param out_ciphertext Output buffer (caller owns; free with buffer_free)
 * @return Error or NULL on success
 */
error_t *keymgr_encrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    buffer_t *out_ciphertext
);

/**
 * Decrypt ciphertext under a profile-derived key
 *
 * Acquires the profile key internally, calls the decryption primitive,
 * and zeroes the derived key buffer before returning — callers never
 * see raw key bytes.
 *
 * Error wrapping policy matches `keymgr_encrypt` — subkey-derivation
 * failures are wrapped; `cipher_decrypt` errors pass through unwrapped so
 * callers can render file-level diagnostics (e.g. "wrong passphrase,
 * try: dotta key clear") without stacking duplicate wraps.
 *
 * @param keymgr       Key manager (must not be NULL)
 * @param profile      Profile name for key derivation (must not be NULL)
 * @param storage_path File path in profile (must not be NULL; must match
 *                     the path used at encryption time — AAD mismatch
 *                     fails SIV verification)
 * @param ciphertext   Dotta-encrypted bytes including header (must not
 *                     be NULL)
 * @param ciphertext_len Ciphertext length in bytes (>= CIPHER_OVERHEAD)
 * @param out_plaintext Output buffer (caller owns; free with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on authentication failure)
 */
error_t *keymgr_decrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    buffer_t *out_plaintext
);

/**
 * Explicitly set passphrase
 *
 * Derives key from passphrase and caches it. Used by `dotta key set`.
 * Does not prompt - passphrase must be provided by caller.
 *
 * @param keymgr Key manager (must not be NULL)
 * @param passphrase Passphrase (must not be NULL, will be copied and zeroed)
 * @param passphrase_len Passphrase length
 * @return Error or NULL on success
 */
error_t *keymgr_set_passphrase(
    keymgr *keymgr,
    const char *passphrase,
    size_t passphrase_len
);

/**
 * Clear cached key
 *
 * Securely zeros cached master key. Used by `dotta key clear` or
 * signal handlers (SIGINT/SIGTERM).
 *
 * Safe to call multiple times.
 *
 * @param keymgr Key manager (must not be NULL)
 */
void keymgr_clear(keymgr *keymgr);

/**
 * Probe for key availability without prompting
 *
 * Checks both in-memory cache and disk session cache. If a valid
 * disk cache exists, loads it into memory. Does NOT prompt for
 * passphrase or check environment variables.
 *
 * This is the non-interactive path: memory + disk (may load from disk),
 * never prompts. The operation-level functions keymgr_encrypt and
 * keymgr_decrypt do the full resolution (memory + disk + prompt).
 *
 * @param keymgr Key manager (must not be NULL)
 * @return true if key is available (either from memory or disk cache)
 */
bool keymgr_probe_key(keymgr *keymgr);

/**
 * Get time until cache expiration
 *
 * @param keymgr Key manager (must not be NULL)
 * @param out_expires_at Optional output for absolute expiration timestamp
 * @return Seconds until expiration (0 if not cached, -1 if no timeout)
 */
int64_t keymgr_time_until_expiry(
    const keymgr *keymgr,
    time_t *out_expires_at
);

/**
 * Free key manager
 *
 * Securely zeros cached key before freeing memory.
 * Safe to call with NULL.
 *
 * @param keymgr Key manager (can be NULL)
 */
void keymgr_free(keymgr *keymgr);

#endif /* DOTTA_KEYMGR_H */
