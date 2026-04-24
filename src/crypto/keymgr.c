/**
 * keymgr.c - Encryption key management implementation
 */

#include "crypto/keymgr.h"

#include <config.h>
#include <errno.h>
#include <hydrogen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "crypto/encryption.h"
#include "crypto/session.h"

/**
 * Key manager structure
 */
struct keymgr {
    /* Configuration */
    uint64_t opslimit;        /* CPU cost for password hashing */
    size_t memlimit;          /* Memory cost for balloon hashing (0 = disabled) */
    int32_t session_timeout;  /* Timeout in seconds (0 = always prompt, -1 = never expire) */

    /* Cached master key */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    bool has_key;             /* Is master key cached? */
    time_t cached_at;         /* When was key cached (monotonic time, 0 if not cached) */
    bool mlocked;             /* Is memory locked with mlock()? */

    /* Profile key cache (profile → uint8_t[32]) */
    hashmap_t *profile_keys;  /* Owned - each value is malloc'd ENCRYPTION_PROFILE_KEY_SIZE */
};

/**
 * Get monotonic timestamp in seconds
 *
 * Returns seconds since an arbitrary epoch (typically system boot time).
 * Unlike time(NULL), this is not affected by system clock changes, NTP
 * adjustments, or timezone modifications.
 *
 * This is used for in-memory cache expiry calculations to prevent cache
 * lifetime manipulation via clock changes. The file-based cache still uses
 * wall-clock time (as monotonic time resets on reboot).
 *
 * @return Monotonic timestamp in seconds, or wall-clock time if unavailable
 */
static time_t get_monotonic_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Fallback to wall-clock time if CLOCK_MONOTONIC unavailable
         * This should never happen on modern POSIX systems, but provides
         * graceful degradation if it does. */
        return time(NULL);
    }
    return ts.tv_sec;
}

error_t *keymgr_create(
    const config_t *config,
    keymgr **out
) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    keymgr *keymgr = calloc(1, sizeof(*keymgr));
    if (!keymgr) {
        return ERROR(ERR_MEMORY, "Failed to allocate key manager");
    }

    /* Copy configuration (memlimit: convert MB from config to bytes for crypto) */
    keymgr->opslimit = config->encryption_opslimit;
    keymgr->memlimit = config->encryption_memlimit * 1024 * 1024;
    keymgr->session_timeout = config->session_timeout;

    /* Initialize key state */
    keymgr->has_key = false;
    keymgr->cached_at = 0;
    keymgr->mlocked = false;
    keymgr->profile_keys = NULL;  /* Created lazily on first profile key request */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));

    /* Attempt to lock memory to prevent swapping to disk
     * This is a best-effort operation - if it fails, we log a warning
     * but continue operation (security enhancement, not requirement) */
    if (mlock(keymgr, sizeof(*keymgr)) == 0) {
        keymgr->mlocked = true;
    } else {
        /* mlock failed - log warning but don't fail initialization
         * Common reasons: insufficient permissions, RLIMIT_MEMLOCK exceeded */
        fprintf(stderr, "Warning: Failed to lock keymgr memory: %s\n", strerror(errno));
        fprintf(stderr, "         Master key may be swapped to disk.\n");
        fprintf(stderr, "         Consider running with elevated privileges\n");
        fprintf(stderr, "         or increasing RLIMIT_MEMLOCK for enhanced security.\n");
    }

    *out = keymgr;
    return NULL;
}

/**
 * Secure destructor trampoline for profile keys.
 *
 * `hashmap_free`/`hashmap_clear` take a `void(*)(void*)` callback, so
 * `buffer_secure_free` (which takes `(void*, size_t)`) needs a fixed
 * length bound at compile time. This one-liner supplies the length.
 */
static void secure_free_profile_key(void *key_ptr) {
    buffer_secure_free(key_ptr, ENCRYPTION_PROFILE_KEY_SIZE);
}

void keymgr_free(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }

    /* Securely zero master key before freeing */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;

    /* Securely clear and free profile key cache */
    if (keymgr->profile_keys) {
        hashmap_free(keymgr->profile_keys, secure_free_profile_key);
        keymgr->profile_keys = NULL;
    }

    /* Unlock memory if it was locked */
    if (keymgr->mlocked) {
        munlock(keymgr, sizeof(*keymgr));
        keymgr->mlocked = false;
    }

    free(keymgr);
}

/**
 * Check if cached key is expired
 *
 * Uses monotonic clock to prevent cache lifetime manipulation via
 * system clock changes.
 *
 * @param keymgr Key manager (must not be NULL)
 * @return true if key is cached and not expired
 */
static bool is_key_valid(const keymgr *keymgr) {
    if (!keymgr->has_key) {
        return false;
    }

    /* If timeout is 0, always prompt (no caching) */
    if (keymgr->session_timeout == 0) {
        return false;
    }

    /* If timeout is negative, key never expires */
    if (keymgr->session_timeout < 0) {
        return true;
    }

    /* Check if expired (positive timeout) using monotonic clock */
    time_t now = get_monotonic_time();
    time_t elapsed = now - keymgr->cached_at;

    return elapsed < keymgr->session_timeout;
}

bool keymgr_has_key(const keymgr *keymgr) {
    if (!keymgr) {
        return false;
    }

    return is_key_valid(keymgr);
}

bool keymgr_probe_key(keymgr *keymgr) {
    if (!keymgr) {
        return false;
    }

    /* Check in-memory cache first */
    if (is_key_valid(keymgr)) {
        return true;
    }

    /* Try disk session cache (skip if always-prompt mode) */
    if (keymgr->session_timeout == 0) {
        return false;
    }

    error_t *err = session_load(keymgr->master_key);
    if (err) {
        error_free(err);
        return false;
    }

    /* Disk cache loaded successfully - promote to in-memory */
    keymgr->has_key = true;
    keymgr->cached_at = get_monotonic_time();
    return true;
}

int64_t keymgr_time_until_expiry(
    const keymgr *keymgr,
    time_t *out_expires_at
) {
    if (!keymgr || !keymgr->has_key) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return 0;
    }

    /* Negative timeout = never expires */
    if (keymgr->session_timeout < 0) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return -1;
    }

    /* Timeout of 0 = always prompt (key never valid, always expired) */
    if (keymgr->session_timeout == 0) {
        if (out_expires_at) {
            *out_expires_at = time(NULL);  /* Already expired */
        }
        return 0;
    }

    /* Positive timeout = calculate remaining time using monotonic clock
     * This prevents cache lifetime manipulation via clock changes */
    time_t now_monotonic = get_monotonic_time();
    time_t elapsed = now_monotonic - keymgr->cached_at;
    int64_t remaining = (int64_t) (keymgr->session_timeout - elapsed);

    if (remaining < 0) {
        remaining = 0;
    }

    if (out_expires_at) {
        /* For display purposes, compute wall-clock expiry as current_time + remaining.
         * This is more accurate than using the original cached_at (which is monotonic)
         * and handles clock drift gracefully. */
        *out_expires_at = time(NULL) + remaining;
    }

    return remaining;
}

void keymgr_clear(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }

    /* Securely zero master key */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;

    /* Clear profile key cache (keys derived from master key, must be cleared too) */
    if (keymgr->profile_keys) {
        hashmap_clear(keymgr->profile_keys, secure_free_profile_key);
        /* Note: hashmap_clear clears entries but keeps the map structure.
         * This is intentional - we keep the map for future use. */
    }

    /* Clear file cache */
    session_clear();
}

error_t *keymgr_set_passphrase(
    keymgr *keymgr,
    const char *passphrase,
    size_t passphrase_len
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(passphrase);

    if (passphrase_len == 0) {
        return ERROR(
            ERR_INVALID_ARG, "Passphrase cannot be empty"
        );
    }

    /* Clear profile keys cache before deriving new master key
     *
     * CRITICAL: When the master key changes (e.g., session timeout + new passphrase),
     * all cached profile keys become invalid since they were derived from the OLD
     * master key. Failing to clear them causes decryption failures with confusing
     * "Authentication failed" errors.
     *
     * This is safe even if the same passphrase is entered - profile keys will simply
     * be re-derived on next use (negligible cost compared to master key derivation).
     */
    if (keymgr->profile_keys) {
        hashmap_clear(keymgr->profile_keys, secure_free_profile_key);
    }

    /* Derive master key from passphrase */
    error_t *err = encryption_derive_master_key(
        passphrase,
        passphrase_len,
        keymgr->opslimit,
        keymgr->memlimit,
        keymgr->master_key
    );

    if (err) {
        /* Clear key on error */
        hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
        keymgr->has_key = false;
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Mark key as cached (using monotonic time for expiry checks) */
    keymgr->has_key = true;
    keymgr->cached_at = get_monotonic_time();

    /* Save to file cache (non-fatal if fails) */
    if (keymgr->session_timeout != 0) {
        error_t *save_err = session_save(keymgr->master_key, keymgr->session_timeout);
        if (save_err) {
            /* Log warning but don't fail - in-memory cache still works */
            fprintf(
                stderr, "Warning: Failed to save session cache: %s\n",
                error_message(save_err)
            );
            error_free(save_err);
        }
    }

    return NULL;
}

/* Maximum passphrase length - reasonable limit to prevent DoS */
#define MAX_PASSPHRASE_LENGTH 4096

error_t *keymgr_prompt_passphrase(
    const char *prompt,
    char **out_passphrase,
    size_t *out_len
) {
    CHECK_NULL(prompt);
    CHECK_NULL(out_passphrase);
    CHECK_NULL(out_len);

    /* Check if stdin is a TTY */
    bool is_tty = isatty(STDIN_FILENO);

    struct termios old_term, new_term;
    bool echo_disabled = false;

    /* Disable echo if TTY */
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return ERROR(
                ERR_FS, "Failed to get terminal attributes"
            );
        }

        new_term = old_term;
        new_term.c_lflag &= ~ECHO;  /* Disable echo */

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            return ERROR(
                ERR_FS, "Failed to disable echo"
            );
        }

        echo_disabled = true;
    }

    /* Display prompt */
    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    /* Allocate fixed-size buffer to prevent unbounded memory allocation
     * This protects against DoS attacks where large data is piped to stdin */
    char *passphrase = malloc(MAX_PASSPHRASE_LENGTH + 1);
    if (!passphrase) {
        if (echo_disabled) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        }
        return ERROR(
            ERR_MEMORY, "Failed to allocate passphrase buffer"
        );
    }

    /* Lock memory to prevent passphrase from being swapped to disk */
    if (mlock(passphrase, MAX_PASSPHRASE_LENGTH + 1) != 0) {
        /* Best-effort: mlock failure is non-fatal but reduces security.
         * Common on systems with tight RLIMIT_MEMLOCK or without privileges. */
    }

    /* Read with size limit and EINTR retry
     * Signals (e.g., SIGWINCH on terminal resize) can interrupt fgets(),
     * so we retry on EINTR to avoid forcing the user to re-enter */
    char *result = NULL;
    do {
        errno = 0;
        result = fgets(passphrase, MAX_PASSPHRASE_LENGTH + 1, stdin);
    } while (result == NULL && errno == EINTR);

    /* Restore echo immediately */
    if (echo_disabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\n");  /* Echo newline that was hidden */
    }

    /* Check read result */
    if (result == NULL) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_FS, "Failed to read passphrase");
    }

    /* Calculate length */
    size_t len = strlen(passphrase);

    /* Check if input was truncated BEFORE trimming newline
     * fgets reads up to MAX_PASSPHRASE_LENGTH chars. If we got that many
     * chars WITHOUT a newline, the input was truncated. */
    bool has_newline = (len > 0 && passphrase[len - 1] == '\n');
    if (len == MAX_PASSPHRASE_LENGTH && !has_newline) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(
            ERR_INVALID_ARG, "Passphrase too long (maximum %d characters)",
            MAX_PASSPHRASE_LENGTH - 1
        );
    }

    /* Trim trailing newline */
    if (has_newline) {
        passphrase[len - 1] = '\0';
        len--;
    }

    /* Check for empty passphrase */
    if (len == 0) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Create a right-sized copy so callers can munlock/memzero with len+1.
     *
     * The read buffer is MAX_PASSPHRASE_LENGTH+1 bytes but the actual passphrase
     * is typically much shorter. Returning the oversized buffer means callers
     * can't know the true allocation size for proper munlock/memzero cleanup.
     * By returning a tight copy, len+1 is always the correct size. */
    char *tight = malloc(len + 1);
    if (!tight) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
    }

    if (mlock(tight, len + 1) != 0) {
        /* Best-effort: non-fatal */
    }

    memcpy(tight, passphrase, len + 1);

    /* Zero and free the oversized read buffer */
    buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);

    *out_passphrase = tight;
    *out_len = len;
    return NULL;
}

/**
 * Get passphrase from environment variable
 *
 * Reads from DOTTA_ENCRYPTION_PASSPHRASE if set.
 *
 * @param out_passphrase Passphrase (caller must free and zero)
 * @param out_len Passphrase length
 * @return Error or NULL on success (returns ERR_NOT_FOUND if not set)
 */
static error_t *get_passphrase_from_env(
    char **out_passphrase,
    size_t *out_len
) {
    CHECK_NULL(out_passphrase);
    CHECK_NULL(out_len);

    const char *env_passphrase = getenv("DOTTA_ENCRYPTION_PASSPHRASE");

    if (!env_passphrase || env_passphrase[0] == '\0') {
        return ERROR(ERR_NOT_FOUND, "DOTTA_ENCRYPTION_PASSPHRASE not set");
    }

    /* Duplicate passphrase */
    size_t len = strlen(env_passphrase);
    char *passphrase = malloc(len + 1);
    if (!passphrase) {
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
    }

    /* Lock memory to prevent swapping (best-effort) */
    if (mlock(passphrase, len + 1) != 0) {
        /* Non-fatal - passphrase still protected by process isolation */
    }

    memcpy(passphrase, env_passphrase, len + 1);

    *out_passphrase = passphrase;
    *out_len = len;
    return NULL;
}

error_t *keymgr_get_key(
    keymgr *keymgr,
    uint8_t out_master_key[32]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(out_master_key);

    /* Step 1: Check in-memory cache */
    if (is_key_valid(keymgr)) {
        memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
        return NULL;
    }

    /* Step 2: Try file cache (skip if session_timeout == 0) */
    if (keymgr->session_timeout != 0) {
        error_t *err = session_load(keymgr->master_key);
        if (!err) {
            /* Cache hit! Update in-memory state with current monotonic time.
             * File cache has its own wall-clock expiry check - once loaded,
             * we switch to monotonic time for in-memory expiry. */
            keymgr->has_key = true;
            keymgr->cached_at = get_monotonic_time();
            memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
            return NULL;
        }

        /* Cache miss/expired/corrupted - non-fatal, continue to prompt */
        if (err->code == ERR_NOT_FOUND || err->code == ERR_CRYPTO) {
            /* Expected failures (cache doesn't exist, expired, or corrupted) */
            error_free(err);
        } else {
            /* Unexpected error (file I/O) - warn but don't fail */
            fprintf(
                stderr, "Warning: Failed to load session cache: %s\n",
                error_message(err)
            );
            error_free(err);
        }
    }

    /* Step 3: Prompt for passphrase */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = NULL;

    /* Try environment variable first */
    err = get_passphrase_from_env(&passphrase, &passphrase_len);

    if (err && err->code == ERR_NOT_FOUND) {
        /* Env var not set - prompt interactively */
        error_free(err);
        err = NULL;

        err = keymgr_prompt_passphrase(
            "Enter encryption passphrase: ",
            &passphrase,
            &passphrase_len
        );
    } else if (err == NULL) {
        /* Warn user that env var is being used (security risk) */
        fprintf(
            stderr,
            "Warning: Using passphrase from DOTTA_ENCRYPTION_PASSPHRASE environment variable\n"
            "         This is insecure - environment variables can leak in process listings\n"
            "         and are inherited by child processes. Use interactive prompt instead.\n"
        );
    }

    if (err) {
        return error_wrap(err, "Failed to get passphrase");
    }

    /* Derive master key */
    err = keymgr_set_passphrase(keymgr, passphrase, passphrase_len);

    /* Securely zero and free passphrase.
     * Both keymgr_prompt_passphrase and get_passphrase_from_env
     * return a buffer of exactly passphrase_len+1 bytes with mlock. */
    buffer_secure_free(passphrase, passphrase_len + 1);

    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Copy to output */
    memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);

    return NULL;
}

/**
 * Get derived profile key (with caching)
 */
error_t *keymgr_get_profile_key(
    keymgr *keymgr,
    const char *profile,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(out_profile_key);

    /* Check cache first, but only if master key is still valid.
     *
     * If the master key has expired (session timeout), cached profile keys
     * must not be served — doing so would bypass re-authentication.
     * Clear the cache and fall through to trigger a passphrase prompt. */
    if (keymgr->profile_keys) {
        if (!is_key_valid(keymgr)) {
            /* Master key expired — invalidate all derived profile keys */
            hashmap_clear(keymgr->profile_keys, secure_free_profile_key);
        } else {
            uint8_t *cached_key = hashmap_get(keymgr->profile_keys, profile);
            if (cached_key) {
                /* Cache hit - copy and return */
                memcpy(out_profile_key, cached_key, ENCRYPTION_PROFILE_KEY_SIZE);
                return NULL;
            }
        }
    }

    /* Cache miss - need to derive profile key */

    /* Get master key (may prompt for passphrase) */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    error_t *err = keymgr_get_key(keymgr, master_key);
    if (err) {
        return error_wrap(err, "Failed to get master key");
    }

    /* Allocate memory for profile key (will be owned by cache) */
    uint8_t *profile_key = malloc(ENCRYPTION_PROFILE_KEY_SIZE);
    if (!profile_key) {
        hydro_memzero(master_key, sizeof(master_key));
        return ERROR(ERR_MEMORY, "Failed to allocate profile key");
    }

    /* Lock memory to prevent swapping to disk (best-effort, non-fatal if fails) */
    if (mlock(profile_key, ENCRYPTION_PROFILE_KEY_SIZE) != 0) {
        /* mlock failure is non-fatal - common reasons: insufficient privileges,
         * RLIMIT_MEMLOCK exceeded. Key still protected by file permissions. */
    }

    /* Derive profile key from master key */
    err = encryption_derive_profile_key(master_key, profile, profile_key);

    /* Clear master key immediately */
    hydro_memzero(master_key, sizeof(master_key));

    if (err) {
        buffer_secure_free(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        return error_wrap(err, "Failed to derive profile key for '%s'", profile);
    }

    /* Create cache hashmap if it doesn't exist yet (lazy initialization) */
    if (!keymgr->profile_keys) {
        keymgr->profile_keys = hashmap_create(8);  /* Initial capacity: 8 profiles */
        if (!keymgr->profile_keys) {
            /* Non-fatal: continue without caching */
            fprintf(stderr, "Warning: Failed to create profile key cache\n");
            fprintf(stderr, "         Performance may be degraded for batch operations\n");

            /* Copy key to output and return (no caching) */
            memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
            buffer_secure_free(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
            return NULL;
        }
    }

    /* Store in cache */
    err = hashmap_set(keymgr->profile_keys, profile, profile_key);
    if (err) {
        /* Non-fatal: continue without caching */
        fprintf(
            stderr, "Warning: Failed to cache profile key for '%s': %s\n",
            profile, error_message(err)
        );
        error_free(err);

        /* Copy key to output and return (no caching) */
        memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        buffer_secure_free(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        return NULL;
    }

    /* Successfully cached - copy to output */
    memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);

    return NULL;
}

error_t *keymgr_encrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    /* Fetch (or derive) profile key. The caller of this function never
     * sees the raw bytes — they live only in this local buffer and are
     * zeroed below before we return. */
    uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
    error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
    if (err) {
        return error_wrap(err, "Failed to get profile key for '%s'", profile);
    }

    err = encryption_encrypt(
        plaintext, plaintext_len, profile_key, storage_path, out_ciphertext
    );

    /* Clear the local key buffer on both success and failure. Missing
     * this zeroization on the error path would leave 32 bytes of key
     * material in stack memory until the frame is overwritten. */
    hydro_memzero(profile_key, sizeof(profile_key));

    return err;
}

error_t *keymgr_decrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    buffer_t *out_plaintext
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(ciphertext);
    CHECK_NULL(out_plaintext);

    uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
    error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
    if (err) {
        return error_wrap(err, "Failed to get profile key for '%s'", profile);
    }

    err = encryption_decrypt(
        ciphertext, ciphertext_len, profile_key, storage_path, out_plaintext
    );

    hydro_memzero(profile_key, sizeof(profile_key));

    return err;
}
