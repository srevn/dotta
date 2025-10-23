/**
 * keymanager.c - Encryption key management implementation
 */

#include "utils/keymanager.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#include "base/encryption.h"
#include "base/error.h"
#include "hydrogen.h"
#include "utils/config.h"
#include "utils/hashmap.h"

/**
 * Key manager structure
 */
struct keymanager {
    /* Configuration */
    uint64_t opslimit;
    size_t memlimit;
    uint8_t threads;
    int32_t session_timeout;  /* Timeout in seconds (0 = always prompt, -1 = never expire) */

    /* Cached master key */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    bool has_key;          /* Is master key cached? */
    time_t cached_at;      /* When was key cached? (0 if not cached) */
    bool mlocked;          /* Is memory locked with mlock()? */

    /* Profile key cache (profile_name → uint8_t[32]) */
    hashmap_t *profile_keys;  /* Owned - each value is malloc'd ENCRYPTION_PROFILE_KEY_SIZE */
};

error_t *keymanager_create(
    const dotta_config_t *config,
    keymanager_t **out
) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    keymanager_t *mgr = calloc(1, sizeof(keymanager_t));
    if (!mgr) {
        return ERROR(ERR_MEMORY, "Failed to allocate key manager");
    }

    /* Copy configuration */
    mgr->opslimit = config->encryption_opslimit;
    mgr->memlimit = config->encryption_memlimit;
    mgr->threads = config->encryption_threads;
    mgr->session_timeout = config->session_timeout;

    /* Initialize key state */
    mgr->has_key = false;
    mgr->cached_at = 0;
    mgr->mlocked = false;
    mgr->profile_keys = NULL;  /* Created lazily on first profile key request */
    hydro_memzero(mgr->master_key, sizeof(mgr->master_key));

    /* Attempt to lock memory to prevent swapping to disk
     * This is a best-effort operation - if it fails, we log a warning
     * but continue operation (security enhancement, not requirement) */
    if (mlock(mgr, sizeof(keymanager_t)) == 0) {
        mgr->mlocked = true;
    } else {
        /* mlock failed - log warning but don't fail initialization
         * Common reasons: insufficient permissions, RLIMIT_MEMLOCK exceeded */
        fprintf(stderr, "Warning: Failed to lock keymanager memory (mlock): %s\n", strerror(errno));
        fprintf(stderr, "         Master key may be swapped to disk.\n");
        fprintf(stderr, "         Consider running with elevated privileges\n");
        fprintf(stderr, "         or increasing RLIMIT_MEMLOCK for enhanced security.\n");
    }

    *out = mgr;
    return NULL;
}

/**
 * Secure destructor for profile keys
 *
 * Zeros memory before freeing to prevent key leakage.
 * Used as callback for hashmap_free() and hashmap_clear().
 *
 * @param key_ptr Pointer to malloc'd profile key (uint8_t[32])
 */
static void secure_free_profile_key(void *key_ptr) {
    if (key_ptr) {
        hydro_memzero(key_ptr, ENCRYPTION_PROFILE_KEY_SIZE);
        free(key_ptr);
    }
}

void keymanager_free(keymanager_t *mgr) {
    if (!mgr) {
        return;
    }

    /* Securely zero master key before freeing */
    hydro_memzero(mgr->master_key, sizeof(mgr->master_key));
    mgr->has_key = false;
    mgr->cached_at = 0;

    /* Securely clear and free profile key cache */
    if (mgr->profile_keys) {
        hashmap_free(mgr->profile_keys, secure_free_profile_key);
        mgr->profile_keys = NULL;
    }

    /* Unlock memory if it was locked */
    if (mgr->mlocked) {
        munlock(mgr, sizeof(keymanager_t));
        mgr->mlocked = false;
    }

    free(mgr);
}

/**
 * Check if cached key is expired
 *
 * @param mgr Key manager (must not be NULL)
 * @return true if key is cached and not expired
 */
static bool is_key_valid(const keymanager_t *mgr) {
    if (!mgr->has_key) {
        return false;
    }

    /* If timeout is 0, always prompt (no caching) */
    if (mgr->session_timeout == 0) {
        return false;
    }

    /* If timeout is negative, key never expires */
    if (mgr->session_timeout < 0) {
        return true;
    }

    /* Check if expired (positive timeout) */
    time_t now = time(NULL);
    time_t elapsed = now - mgr->cached_at;

    return elapsed < mgr->session_timeout;
}

bool keymanager_has_key(const keymanager_t *mgr) {
    if (!mgr) {
        return false;
    }

    return is_key_valid(mgr);
}

int64_t keymanager_time_until_expiry(
    const keymanager_t *mgr,
    time_t *out_expires_at
) {
    if (!mgr || !mgr->has_key) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return 0;
    }

    /* Negative timeout = never expires */
    if (mgr->session_timeout < 0) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return -1;
    }

    /* Timeout of 0 = always prompt (key never valid, always expired) */
    if (mgr->session_timeout == 0) {
        if (out_expires_at) {
            *out_expires_at = mgr->cached_at;  /* Expired immediately */
        }
        return 0;
    }

    /* Positive timeout = calculate remaining time */
    time_t now = time(NULL);
    time_t expires_at = mgr->cached_at + mgr->session_timeout;

    if (out_expires_at) {
        *out_expires_at = expires_at;
    }

    int64_t remaining = (int64_t)(expires_at - now);
    return remaining > 0 ? remaining : 0;
}

void keymanager_clear(keymanager_t *mgr) {
    if (!mgr) {
        return;
    }

    /* Securely zero master key */
    hydro_memzero(mgr->master_key, sizeof(mgr->master_key));
    mgr->has_key = false;
    mgr->cached_at = 0;

    /* Clear profile key cache (keys derived from master key, must be cleared too) */
    if (mgr->profile_keys) {
        hashmap_clear(mgr->profile_keys, secure_free_profile_key);
        /* Note: hashmap_clear clears entries but keeps the map structure.
         * This is intentional - we keep the map for future use. */
    }
}

error_t *keymanager_set_passphrase(
    keymanager_t *mgr,
    const char *passphrase,
    size_t passphrase_len
) {
    CHECK_NULL(mgr);
    CHECK_NULL(passphrase);

    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Derive master key from passphrase */
    error_t *err = encryption_derive_master_key(
        passphrase,
        passphrase_len,
        mgr->opslimit,
        mgr->memlimit,
        mgr->threads,
        mgr->master_key
    );

    if (err) {
        /* Clear key on error */
        hydro_memzero(mgr->master_key, sizeof(mgr->master_key));
        mgr->has_key = false;
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Mark key as cached */
    mgr->has_key = true;
    mgr->cached_at = time(NULL);

    return NULL;
}

/* Maximum passphrase length - reasonable limit to prevent DoS */
#define MAX_PASSPHRASE_LENGTH 4096

error_t *keymanager_prompt_passphrase(
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
            return ERROR(ERR_FS, "Failed to get terminal attributes");
        }

        new_term = old_term;
        new_term.c_lflag &= ~ECHO;  /* Disable echo */

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            return ERROR(ERR_FS, "Failed to disable echo");
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
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
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
        hydro_memzero(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        free(passphrase);
        return ERROR(ERR_FS, "Failed to read passphrase");
    }

    /* Calculate length */
    size_t len = strlen(passphrase);

    /* Check if input was truncated BEFORE trimming newline
     * fgets reads up to MAX_PASSPHRASE_LENGTH chars. If we got that many
     * chars WITHOUT a newline, the input was truncated. */
    bool has_newline = (len > 0 && passphrase[len - 1] == '\n');
    if (len == MAX_PASSPHRASE_LENGTH && !has_newline) {
        hydro_memzero(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        free(passphrase);
        return ERROR(ERR_INVALID_ARG,
                    "Passphrase too long (maximum %d characters)",
                    MAX_PASSPHRASE_LENGTH - 1);
    }

    /* Trim trailing newline */
    if (has_newline) {
        passphrase[len - 1] = '\0';
        len--;
    }

    /* Check for empty passphrase */
    if (len == 0) {
        hydro_memzero(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        free(passphrase);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    *out_passphrase = passphrase;
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

    memcpy(passphrase, env_passphrase, len + 1);

    *out_passphrase = passphrase;
    *out_len = len;
    return NULL;
}

error_t *keymanager_get_key(
    keymanager_t *mgr,
    uint8_t out_master_key[32]
) {
    CHECK_NULL(mgr);
    CHECK_NULL(out_master_key);

    /* Check if cached key is valid */
    if (is_key_valid(mgr)) {
        memcpy(out_master_key, mgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
        return NULL;
    }

    /* Key not cached or expired - need to derive from passphrase */

    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = NULL;

    /* Try environment variable first */
    err = get_passphrase_from_env(&passphrase, &passphrase_len);

    if (err && err->code == ERR_NOT_FOUND) {
        /* Env var not set - prompt interactively */
        error_free(err);
        err = NULL;

        err = keymanager_prompt_passphrase(
            "Enter encryption passphrase: ",
            &passphrase,
            &passphrase_len
        );
    } else if (err == NULL) {
        /* Warn user that env var is being used (security risk) */
        fprintf(stderr, "Warning: Using passphrase from DOTTA_ENCRYPTION_PASSPHRASE environment variable\n");
        fprintf(stderr, "         This is insecure - environment variables can leak in process listings\n");
        fprintf(stderr, "         and are inherited by child processes. Use interactive prompt instead.\n");
    }

    if (err) {
        return error_wrap(err, "Failed to get passphrase");
    }

    /* Derive master key */
    err = keymanager_set_passphrase(mgr, passphrase, passphrase_len);

    /* Securely zero passphrase */
    hydro_memzero(passphrase, passphrase_len);
    free(passphrase);

    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Copy to output */
    memcpy(out_master_key, mgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);

    return NULL;
}

error_t *keymanager_get_profile_key(
    keymanager_t *mgr,
    const char *profile_name,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
) {
    CHECK_NULL(mgr);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_profile_key);

    /* Check cache first */
    if (mgr->profile_keys) {
        uint8_t *cached_key = hashmap_get(mgr->profile_keys, profile_name);
        if (cached_key) {
            /* Cache hit - copy and return */
            memcpy(out_profile_key, cached_key, ENCRYPTION_PROFILE_KEY_SIZE);
            return NULL;
        }
    }

    /* Cache miss - need to derive profile key */

    /* Get master key (may prompt for passphrase) */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    error_t *err = keymanager_get_key(mgr, master_key);
    if (err) {
        return error_wrap(err, "Failed to get master key");
    }

    /* Allocate memory for profile key (will be owned by cache) */
    uint8_t *profile_key = malloc(ENCRYPTION_PROFILE_KEY_SIZE);
    if (!profile_key) {
        hydro_memzero(master_key, sizeof(master_key));
        return ERROR(ERR_MEMORY, "Failed to allocate profile key");
    }

    /* Derive profile key from master key */
    err = encryption_derive_profile_key(master_key, profile_name, profile_key);

    /* Clear master key immediately */
    hydro_memzero(master_key, sizeof(master_key));

    if (err) {
        hydro_memzero(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        free(profile_key);
        return error_wrap(err, "Failed to derive profile key for '%s'", profile_name);
    }

    /* Create cache hashmap if it doesn't exist yet (lazy initialization) */
    if (!mgr->profile_keys) {
        mgr->profile_keys = hashmap_create(8);  /* Initial capacity: 8 profiles */
        if (!mgr->profile_keys) {
            /* Non-fatal: continue without caching */
            fprintf(stderr, "Warning: Failed to create profile key cache\n");
            fprintf(stderr, "         Performance may be degraded for batch operations\n");

            /* Copy key to output and return (no caching) */
            memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
            hydro_memzero(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
            free(profile_key);
            return NULL;
        }
    }

    /* Store in cache */
    err = hashmap_set(mgr->profile_keys, profile_name, profile_key);
    if (err) {
        /* Non-fatal: continue without caching */
        fprintf(stderr, "Warning: Failed to cache profile key for '%s': %s\n",
                profile_name, error_message(err));
        error_free(err);

        /* Copy key to output and return (no caching) */
        memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        hydro_memzero(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
        free(profile_key);
        return NULL;
    }

    /* Successfully cached - copy to output */
    memcpy(out_profile_key, profile_key, ENCRYPTION_PROFILE_KEY_SIZE);

    return NULL;
}

/* Global Keymanager Singleton
 *
 * Provides a process-wide keymanager instance to avoid repeatedly prompting
 * for passphrase across multiple commands in the same execution.
 *
 * Thread safety: Not thread-safe (dotta is single-threaded)
 * Lifecycle: Created on first access, cleaned up at program exit
 */

static keymanager_t *global_keymanager = NULL;

/**
 * Get or create global keymanager
 *
 * Creates the global keymanager on first access. Returns the same instance
 * on subsequent calls. If config is NULL, uses default config values.
 *
 * @param config Configuration (can be NULL for defaults)
 * @return Global keymanager instance or NULL on error
 */
keymanager_t *keymanager_get_global(const dotta_config_t *config) {
    if (global_keymanager) {
        return global_keymanager;
    }

    /* Create new keymanager */
    dotta_config_t *cfg = (dotta_config_t *)config;
    bool allocated_config = false;

    if (!cfg) {
        cfg = config_create_default();
        if (!cfg) {
            return NULL;
        }
        allocated_config = true;
    }

    error_t *err = keymanager_create(cfg, &global_keymanager);

    if (allocated_config) {
        config_free(cfg);
    }

    if (err) {
        fprintf(stderr, "Failed to create global keymanager: %s\n", error_message(err));
        error_free(err);
        return NULL;
    }

    return global_keymanager;
}

/**
 * Cleanup global keymanager
 *
 * Securely clears and frees the global keymanager instance.
 * Safe to call multiple times or if global keymanager doesn't exist.
 *
 * Should be called at program exit (e.g., via atexit() or explicit cleanup).
 */
void keymanager_cleanup_global(void) {
    if (global_keymanager) {
        keymanager_free(global_keymanager);
        global_keymanager = NULL;
    }
}
