/**
 * keymanager.h - Encryption key management and session caching
 *
 * Manages the encryption master key lifecycle with session-based caching.
 * Prompts for passphrase when needed and caches the derived master key
 * in memory for a configurable timeout period.
 *
 * Design principles:
 * - Single passphrase for all profiles (UX-friendly)
 * - Session-based caching (balance security vs UX)
 * - Configurable timeout (default: 1 hour)
 * - Secure memory clearing (hydro_memzero)
 * - Memory locking to prevent swap (mlock on POSIX systems)
 * - Environment variable fallback for automation
 *
 * Security considerations:
 * - Master key stored in process memory (vulnerable to dumps)
 * - mlock() protection prevents swapping to disk (best-effort)
 * - Graceful degradation if mlock fails (logs warning)
 * - Cleared on timeout, explicit clear, or process exit
 * - Signal handlers recommended for cleanup on SIGINT/SIGTERM
 */

#ifndef DOTTA_KEYMANAGER_H
#define DOTTA_KEYMANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "types.h"

/* Forward declarations */
typedef struct dotta_config dotta_config_t;

/**
 * Key manager (opaque)
 *
 * Maintains cached master key and session state.
 */
typedef struct keymanager keymanager_t;

/**
 * Create key manager
 *
 * Initializes session-based key management with configuration.
 * Does not prompt for passphrase immediately - passphrase is
 * requested on first key access (lazy initialization).
 *
 * @param config Configuration (for opslimit, memlimit, timeout, etc.)
 * @param out Key manager (caller must free with keymanager_free)
 * @return Error or NULL on success
 */
error_t *keymanager_create(
    const dotta_config_t *config,
    keymanager_t **out
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
 * @param mgr Key manager (must not be NULL)
 * @param out_master_key Output buffer for 32-byte key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *keymanager_get_key(
    keymanager_t *mgr,
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
 * @param mgr Key manager (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param out_profile_key Output buffer for 32-byte profile key (must be pre-allocated)
 * @return Error or NULL on success
 */
error_t *keymanager_get_profile_key(
    keymanager_t *mgr,
    const char *profile_name,
    uint8_t out_profile_key[32]
);

/**
 * Explicitly set passphrase
 *
 * Derives key from passphrase and caches it. Used by `dotta key set`.
 * Does not prompt - passphrase must be provided by caller.
 *
 * @param mgr Key manager (must not be NULL)
 * @param passphrase Passphrase (must not be NULL, will be copied and zeroed)
 * @param passphrase_len Passphrase length
 * @return Error or NULL on success
 */
error_t *keymanager_set_passphrase(
    keymanager_t *mgr,
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
 * @param mgr Key manager (must not be NULL)
 */
void keymanager_clear(keymanager_t *mgr);

/**
 * Check if key is cached and not expired
 *
 * @param mgr Key manager (must not be NULL)
 * @return true if key is available (cached and not expired)
 */
bool keymanager_has_key(const keymanager_t *mgr);

/**
 * Get time until cache expiration
 *
 * @param mgr Key manager (must not be NULL)
 * @param out_expires_at Optional output for absolute expiration timestamp
 * @return Seconds until expiration (0 if not cached, -1 if no timeout)
 */
int64_t keymanager_time_until_expiry(
    const keymanager_t *mgr,
    time_t *out_expires_at
);

/**
 * Free key manager
 *
 * Securely zeros cached key before freeing memory.
 * Safe to call with NULL.
 *
 * @param mgr Key manager (can be NULL)
 */
void keymanager_free(keymanager_t *mgr);

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
error_t *keymanager_prompt_passphrase(
    const char *prompt,
    char **out_passphrase,
    size_t *out_len
);

/**
 * Get or create global keymanager
 *
 * Returns a process-wide keymanager instance, creating it on first access.
 * This avoids repeatedly prompting for passphrase across multiple operations.
 *
 * The global keymanager uses the provided config (or defaults if NULL).
 * Once created, it persists until keymanager_cleanup_global() is called.
 *
 * @param config Configuration (can be NULL for defaults)
 * @return Global keymanager instance or NULL on error
 */
keymanager_t *keymanager_get_global(const dotta_config_t *config);

/**
 * Cleanup global keymanager
 *
 * Securely clears and frees the global keymanager instance.
 * Should be called at program exit.
 *
 * Safe to call multiple times.
 */
void keymanager_cleanup_global(void);

#endif /* DOTTA_KEYMANAGER_H */
