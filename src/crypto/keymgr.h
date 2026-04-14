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
 * - Cleared on timeout, explicit clear, or process exit
 * - Signal handlers recommended for cleanup on SIGINT/SIGTERM
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
 * Check if key is cached in memory and not expired
 *
 * Only checks in-memory state. Does not probe the disk cache.
 * Use keymgr_probe_key() for a full availability check.
 *
 * @param keymgr Key manager (must not be NULL)
 * @return true if key is available in memory (cached and not expired)
 */
bool keymgr_has_key(const keymgr *keymgr);

/**
 * Probe for key availability without prompting
 *
 * Checks both in-memory cache and disk session cache. If a valid
 * disk cache exists, loads it into memory. Does NOT prompt for
 * passphrase or check environment variables.
 *
 * This is the non-interactive counterpart to keymgr_get_key():
 *   - keymgr_has_key():   memory only (const, no side effects)
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
int64_t keymgrime_until_expiry(
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

/**
 * Prompt for passphrase (with echo disabled)
 *
 * Reads passphrase from stdin with terminal echo disabled.
 * Supports interactive TTY and non-TTY input (for scripts).
 *
 * Implementation details:
 * - Uses tcgetattr/tcsetattr to disable echo (POSIX)
 * - Restores echo on completion or error
 * - Handles Ctrl+C gracefully (restores echo)
 * - Trims trailing newline
 *
 * @param prompt Prompt message to display (must not be NULL)
 * @param out_passphrase Passphrase buffer (caller must free and zero)
 * @param out_len Passphrase length (excluding null terminator)
 * @return Error or NULL on success
 */
error_t *keymgr_prompt_passphrase(
    const char *prompt,
    char **out_passphrase,
    size_t *out_len
);

/**
 * Get or create global keymgr
 *
 * Returns a process-wide keymgr instance, creating it on first access.
 * This avoids repeatedly prompting for passphrase across multiple operations.
 *
 * The global keymgr uses the provided config (or defaults if NULL).
 * Once created, it persists until keymgr_cleanup_global() is called.
 *
 * @param config Configuration (can be NULL for defaults)
 * @return Global keymgr instance or NULL on error
 */
keymgr *keymgr_get_global(const config_t *config);

/**
 * Cleanup global keymgr
 *
 * Securely clears and frees the global keymgr instance.
 * Should be called at program exit.
 *
 * Safe to call multiple times.
 */
void keymgr_cleanup_global(void);

#endif /* DOTTA_KEYMGR_H */
