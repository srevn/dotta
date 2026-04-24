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
 * - Disk cache encrypted and machine-bound (verified via MAC)
 * - mlock() protection prevents swapping to disk (best-effort):
 *   * Master key in keymgr struct
 *   * Profile keys in hashmap cache
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
 * @param config Configuration (for opslimit and session_timeout)
 * @param out Key manager (caller must free with keymgr_free)
 * @return Error or NULL on success
 */
error_t *keymgr_create(
    const config_t *config,
    keymgr **out
);

/**
 * Get master key (prompts if not cached)
 *
 * Returns cached key if available and not expired, otherwise prompts
 * user for passphrase and derives key.
 *
 * Passphrase sources (priority order):
 * 1. Cached key (if not expired)
 * 2. DOTTA_ENCRYPTION_PASSPHRASE environment variable
 * 3. Interactive prompt (with terminal echo disabled)
 *
 * @param keymgr Key manager (must not be NULL)
 * @param out_master_key Output buffer for 32-byte key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *keymgr_get_key(
    keymgr *keymgr,
    uint8_t out_master_key[32]
);

/**
 * Get derived profile key (with caching)
 *
 * Returns cached profile key if available, otherwise derives it from
 * the master key and caches it for future use.
 *
 * This function provides transparent profile key caching, eliminating
 * the expensive key derivation overhead for batch operations. The cache
 * lifetime is tied to the master key cache.
 *
 * Process:
 * 1. Check profile_keys cache for cached key
 * 2. If cache miss: get master key and derive profile key
 * 3. Cache derived key for future use
 * 4. Copy key to output buffer
 *
 * Performance: O(1) for cache hit, O(expensive) for cache miss
 * Cache lifetime: Same as master key (cleared when master key expires/cleared)
 *
 * @param keymgr Key manager (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out_profile_key Output buffer for 32-byte profile key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *keymgr_get_profile_key(
    keymgr *keymgr,
    const char *profile,
    uint8_t out_profile_key[32]
);

/**
 * Encrypt plaintext under a profile-derived key
 *
 * Convenience wrapper combining `keymgr_get_profile_key`,
 * `encryption_encrypt`, and the mandatory `hydro_memzero` of the derived
 * key buffer into one call. Callers never materialize raw key bytes.
 *
 * The profile key is fetched from the keymgr's per-profile cache when
 * warm (no passphrase prompt, no KDF work), so this is cheap in a batch.
 * A cold call may prompt for the passphrase via `keymgr_get_key`.
 *
 * Error wrapping policy:
 *   - Profile-key fetch errors are wrapped with a uniform message that
 *     names the profile (the caller already knows the path; it rarely
 *     needs both).
 *   - `encryption_encrypt` errors are returned unwrapped so the caller
 *     can attach file-level context (path, operation) without
 *     duplicating a generic wrap that loses fidelity.
 *
 * @param keymgr       Key manager (must not be NULL)
 * @param profile      Profile name for key derivation (must not be NULL)
 * @param storage_path File path in profile (must not be NULL; AAD bound
 *                     into the ciphertext by `encryption_encrypt`)
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
 * Convenience wrapper combining `keymgr_get_profile_key`,
 * `encryption_decrypt`, and the mandatory `hydro_memzero` of the derived
 * key buffer into one call. Callers never materialize raw key bytes.
 *
 * Error wrapping policy matches `keymgr_encrypt` — profile-key failures
 * are wrapped; `encryption_decrypt` errors pass through unwrapped so
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
 * @param ciphertext_len Ciphertext length in bytes (>= ENCRYPTION_OVERHEAD)
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
 * This is the non-interactive counterpart to keymgr_get_key():
 *   - keymgr_probe_key(): memory + disk (may load from disk)
 *   - keymgr_get_key():   memory + disk + prompt (full resolution)
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
