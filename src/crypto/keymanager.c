/**
 * keymanager.c - Encryption key management implementation
 */

#include "crypto/keymanager.h"

#include <errno.h>
#include <fcntl.h>
#include <hydrogen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "crypto/encryption.h"
#include "utils/config.h"
#include "utils/hashmap.h"

/**
 * Session Cache File Format
 *
 * Binary layout (116 bytes total):
 *   [magic: "DOTTASES" (8 bytes)]
 *   [version: 1 (1 byte)]
 *   [reserved: 0 (3 bytes)]
 *   [created_at: Unix timestamp (8 bytes)]
 *   [expires_at: Unix timestamp or 0 for never (8 bytes)]
 *   [machine_salt: Random salt (16 bytes)]
 *   [encrypted_key: Obfuscated master key (32 bytes)]
 *   [mac: HMAC for integrity (32 bytes)]
 *
 * Security properties:
 * - Obfuscated: Master key is XORed with deterministic stream
 * - Machine-bound: Derived from hostname + username
 * - Time-bound: Expires per session_timeout config
 * - Tamper-evident: MAC prevents modification
 * - Lightweight: Not military-grade, appropriate for threat model
 */
#define SESSION_CACHE_MAGIC "DOTTASES"
#define SESSION_CACHE_VERSION 1

struct session_cache_file {
    char magic[8];              /* "DOTTASES" */
    uint8_t version;            /* Format version (1) */
    uint8_t reserved[3];        /* Future use, must be 0 */
    uint64_t created_at;        /* Unix timestamp (seconds) */
    uint64_t expires_at;        /* Unix timestamp (0 = never) */
    uint8_t machine_salt[16];   /* Random salt for this cache entry */
    uint8_t encrypted_key[32];  /* Obfuscated master key */
    uint8_t mac[32];            /* HMAC for integrity */
} __attribute__((packed));

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
    time_t cached_at;      /* When was key cached (monotonic time, 0 if not cached) */
    bool mlocked;          /* Is memory locked with mlock()? */

    /* Profile key cache (profile_name → uint8_t[32]) */
    hashmap_t *profile_keys;  /* Owned - each value is malloc'd ENCRYPTION_PROFILE_KEY_SIZE */
};

/**
 * Get session cache file path
 *
 * Returns ~/.cache/dotta/session (XDG-style, works on all platforms).
 *
 * @param out_path Cache file path (caller must free)
 * @return Error or NULL on success
 */
static error_t *session_cache_get_path(char **out_path) {
    CHECK_NULL(out_path);

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        return ERROR(ERR_FS, "HOME environment variable not set");
    }

    char *path = NULL;
    if (asprintf(&path, "%s/.cache/dotta/session", home) < 0 || !path) {
        return ERROR(ERR_MEMORY, "Failed to allocate cache path");
    }

    *out_path = path;
    return NULL;
}

/**
 * Get machine identity for cache binding
 *
 * Returns "hostname\0username" string for deriving cache encryption key.
 *
 * @param out_identity Machine identity string (caller must free and zero)
 * @param out_len Length of identity string (including both null terminators)
 * @return Error or NULL on success
 */
static error_t *get_machine_identity(char **out_identity, size_t *out_len) {
    CHECK_NULL(out_identity);
    CHECK_NULL(out_len);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return ERROR(ERR_FS, "Failed to get hostname: %s", strerror(errno));
    }

    /* Ensure null termination in case hostname was truncated */
    hostname[sizeof(hostname) - 1] = '\0';

    const char *username = getlogin();
    if (!username) {
        username = getenv("USER");
        if (!username) {
            return ERROR(ERR_FS, "Failed to get username");
        }
    }

    /* Format: "hostname\0username\0" (two null-terminated strings) */
    size_t hostname_len = strlen(hostname);
    size_t username_len = strlen(username);
    size_t id_len = hostname_len + 1 + username_len + 1;

    char *identity = malloc(id_len);
    if (!identity) {
        return ERROR(ERR_MEMORY, "Failed to allocate identity buffer");
    }

    memcpy(identity, hostname, hostname_len + 1);
    memcpy(identity + hostname_len + 1, username, username_len + 1);

    *out_identity = identity;
    *out_len = id_len;
    return NULL;
}

/**
 * Save master key to session cache file
 *
 * Encrypts and saves the master key to ~/.cache/dotta/session with
 * machine binding and expiry time based on session_timeout.
 *
 * @param master_key Master key to save (32 bytes)
 * @param session_timeout Timeout in seconds (0 = always prompt, -1 = never expire)
 * @return Error or NULL on success
 */
static error_t *session_cache_save(
    const uint8_t master_key[32],
    int32_t session_timeout
) {
    CHECK_NULL(master_key);

    error_t *err = NULL;
    char *cache_path = NULL;
    char *cache_dir = NULL;
    char *machine_id = NULL;
    size_t machine_id_len = 0;
    FILE *fp = NULL;

    uint8_t cache_key[32] = {0};
    uint8_t stream[32] = {0};

    /* Get cache path */
    err = session_cache_get_path(&cache_path);
    if (err) return err;

    /* Create cache directory if needed (~/.cache/dotta) */
    cache_dir = strdup(cache_path);
    if (!cache_dir) {
        err = ERROR(ERR_MEMORY, "Failed to allocate cache dir path");
        goto cleanup;
    }

    char *last_slash = strrchr(cache_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    }

    if (!fs_exists(cache_dir)) {
        err = fs_create_dir_with_mode(cache_dir, 0700, true);
        if (err) {
            err = error_wrap(err, "Failed to create cache directory");
            goto cleanup;
        }
    }

    /* Build cache file */
    struct session_cache_file cache = {0};
    memcpy(cache.magic, SESSION_CACHE_MAGIC, 8);
    cache.version = SESSION_CACHE_VERSION;

    cache.created_at = (uint64_t)time(NULL);

    /* Calculate expiry */
    if (session_timeout < 0) {
        cache.expires_at = 0;  /* Never expire */
    } else {
        cache.expires_at = cache.created_at + (uint64_t)session_timeout;
    }

    /* Generate random salt */
    hydro_random_buf(cache.machine_salt, sizeof(cache.machine_salt));

    /* Get machine identity */
    err = get_machine_identity(&machine_id, &machine_id_len);
    if (err) goto cleanup;

    /* Derive cache key: hash(machine_id || machine_salt)
     * We concatenate machine_id and salt as the message, with NULL key */
    hydro_hash_state hash_state;
    if (hydro_hash_init(&hash_state, "dottacch", NULL) != 0) {
        err = ERROR(ERR_CRYPTO, "Failed to initialize hash for cache key");
        goto cleanup;
    }
    hydro_hash_update(&hash_state, (uint8_t *)machine_id, machine_id_len);
    hydro_hash_update(&hash_state, cache.machine_salt, sizeof(cache.machine_salt));
    hydro_hash_final(&hash_state, cache_key, 32);
    hydro_memzero(&hash_state, sizeof(hash_state));

    /* Encrypt master key using deterministic stream cipher */
    hydro_random_buf_deterministic(stream, 32, cache_key);
    for (int i = 0; i < 32; i++) {
        cache.encrypted_key[i] = master_key[i] ^ stream[i];
    }

    /* Compute MAC over: created_at || expires_at || machine_salt || encrypted_key
     * Use cache_key as the MAC key for authentication */
    hydro_hash_state mac_state;
    if (hydro_hash_init(&mac_state, "dottamac", cache_key) != 0) {
        err = ERROR(ERR_CRYPTO, "Failed to initialize MAC computation");
        goto cleanup;
    }

    hydro_hash_update(&mac_state, (uint8_t *)&cache.created_at, 8);
    hydro_hash_update(&mac_state, (uint8_t *)&cache.expires_at, 8);
    hydro_hash_update(&mac_state, cache.machine_salt, 16);
    hydro_hash_update(&mac_state, cache.encrypted_key, 32);

    hydro_hash_final(&mac_state, cache.mac, 32);
    hydro_memzero(&mac_state, sizeof(mac_state));

    /* Open file with secure permissions (atomic)
     *
     * SECURITY: Using open() with mode parameter sets permissions atomically during
     * file creation, eliminating the timing window where the file could exist with
     * default permissions (typically 0644 due to umask). This is critical for
     * protecting the encrypted master key.
     *
     * This pattern matches the secure file writing approach used throughout the
     * codebase (see fs_write_file_raw() in filesystem.c).
     */
    int fd = open(cache_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        err = ERROR(ERR_FS, "Failed to create cache file: %s", strerror(errno));
        goto cleanup;
    }

    /* Convert file descriptor to FILE* for buffered I/O
     * Note: If fdopen() succeeds, the FILE* takes ownership of the fd and will
     * close it when fclose() is called. If fdopen() fails, we must close fd manually. */
    fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);  /* fdopen failed - must close fd manually to prevent leak */
        err = ERROR(ERR_FS, "Failed to fdopen cache file: %s", strerror(errno));
        goto cleanup;
    }

    /* Defense-in-depth: Explicitly verify permissions using fchmod()
     * While open() already set 0600, this provides an additional security check
     * and guards against any umask interference. Using fchmod() (not chmod())
     * operates on the open file descriptor, which is safer than pathname-based chmod(). */
    if (fchmod(fileno(fp), 0600) != 0) {
        err = ERROR(ERR_FS, "Failed to set cache file permissions: %s", strerror(errno));
        goto cleanup;
    }

    /* Write cache data structure to file */
    if (fwrite(&cache, sizeof(cache), 1, fp) != 1) {
        err = ERROR(ERR_FS, "Failed to write cache file");
        goto cleanup;
    }

    /* Flush and sync to disk for durability
     * This ensures the cache survives system crashes and matches the paranoid-safe
     * file writing pattern used throughout the codebase (see fs_write_file_raw()).
     * fflush() writes buffered data to the kernel, fsync() commits to physical disk. */
    if (fflush(fp) != 0) {
        err = ERROR(ERR_FS, "Failed to flush cache file: %s", strerror(errno));
        goto cleanup;
    }

    if (fsync(fileno(fp)) != 0) {
        err = ERROR(ERR_FS, "Failed to sync cache file to disk: %s", strerror(errno));
        goto cleanup;
    }

cleanup:
    if (fp) fclose(fp);
    hydro_memzero(&cache, sizeof(cache));
    hydro_memzero(cache_key, sizeof(cache_key));
    hydro_memzero(stream, sizeof(stream));
    free(cache_path);
    free(cache_dir);
    if (machine_id) {
        hydro_memzero(machine_id, machine_id_len);
        free(machine_id);
    }

    return err;
}

/**
 * Load master key from session cache file
 *
 * Verifies MAC, checks expiry, and decrypts the master key.
 *
 * @param out_master_key Output buffer for 32-byte master key
 * @return Error or NULL on success (ERR_NOT_FOUND if cache doesn't exist/expired)
 */
static error_t *session_cache_load(
    uint8_t out_master_key[32]
) {
    CHECK_NULL(out_master_key);

    error_t *err = NULL;
    char *cache_path = NULL;
    char *machine_id = NULL;
    size_t machine_id_len = 0;
    FILE *fp = NULL;

    struct session_cache_file cache;
    uint8_t cache_key[32] = {0};
    uint8_t stream[32] = {0};
    uint8_t computed_mac[32] = {0};

    /* Get cache path */
    err = session_cache_get_path(&cache_path);
    if (err) return err;

    /* Check if cache exists */
    if (!fs_exists(cache_path)) {
        free(cache_path);
        return ERROR(ERR_NOT_FOUND, "Cache file does not exist");
    }

    /* Check permissions (must be 0600) */
    struct stat st;
    if (stat(cache_path, &st) != 0) {
        err = ERROR(ERR_FS, "Failed to stat cache file: %s", strerror(errno));
        free(cache_path);
        return err;
    }

    if ((st.st_mode & 0777) != 0600) {
        /* Wrong permissions - delete and fail */
        unlink(cache_path);
        free(cache_path);
        return ERROR(ERR_CRYPTO, "Cache file has wrong permissions (expected 0600)");
    }

    /* Read cache file */
    fp = fopen(cache_path, "rb");
    if (!fp) {
        err = ERROR(ERR_FS, "Failed to open cache file: %s", strerror(errno));
        free(cache_path);
        return err;
    }

    if (fread(&cache, sizeof(cache), 1, fp) != 1) {
        fclose(fp);
        unlink(cache_path);
        free(cache_path);
        return ERROR(ERR_CRYPTO, "Cache file corrupted (incomplete read)");
    }

    fclose(fp);
    fp = NULL;

    /* Validate magic header */
    if (memcmp(cache.magic, SESSION_CACHE_MAGIC, 8) != 0) {
        unlink(cache_path);
        free(cache_path);
        return ERROR(ERR_CRYPTO, "Cache file corrupted (bad magic)");
    }

    /* Check version */
    if (cache.version != SESSION_CACHE_VERSION) {
        unlink(cache_path);
        free(cache_path);
        return ERROR(ERR_CRYPTO, "Unsupported cache version: %d", cache.version);
    }

    /* Check expiry (if not 0 = never expire) */
    if (cache.expires_at != 0) {
        time_t now = time(NULL);
        if ((uint64_t)now >= cache.expires_at) {
            unlink(cache_path);
            free(cache_path);
            return ERROR(ERR_NOT_FOUND, "Cache expired");
        }
    }

    /* Get machine identity */
    err = get_machine_identity(&machine_id, &machine_id_len);
    if (err) {
        free(cache_path);
        return err;
    }

    /* Derive cache key: hash(machine_id || machine_salt)
     * Must match the derivation in session_cache_save() */
    hydro_hash_state hash_state;
    if (hydro_hash_init(&hash_state, "dottacch", NULL) != 0) {
        err = ERROR(ERR_CRYPTO, "Failed to initialize hash for cache key");
        goto cleanup;
    }
    hydro_hash_update(&hash_state, (uint8_t *)machine_id, machine_id_len);
    hydro_hash_update(&hash_state, cache.machine_salt, sizeof(cache.machine_salt));
    hydro_hash_final(&hash_state, cache_key, 32);
    hydro_memzero(&hash_state, sizeof(hash_state));

    /* Verify MAC using cache_key */
    hydro_hash_state mac_state;
    if (hydro_hash_init(&mac_state, "dottamac", cache_key) != 0) {
        err = ERROR(ERR_CRYPTO, "Failed to initialize MAC verification");
        goto cleanup;
    }

    hydro_hash_update(&mac_state, (uint8_t *)&cache.created_at, 8);
    hydro_hash_update(&mac_state, (uint8_t *)&cache.expires_at, 8);
    hydro_hash_update(&mac_state, cache.machine_salt, 16);
    hydro_hash_update(&mac_state, cache.encrypted_key, 32);

    hydro_hash_final(&mac_state, computed_mac, 32);
    hydro_memzero(&mac_state, sizeof(mac_state));

    if (!hydro_equal(computed_mac, cache.mac, 32)) {
        unlink(cache_path);
        err = ERROR(ERR_CRYPTO, "Cache MAC verification failed (tampered or wrong machine)");
        goto cleanup;
    }

    /* Decrypt master key */
    hydro_random_buf_deterministic(stream, 32, cache_key);
    for (int i = 0; i < 32; i++) {
        out_master_key[i] = cache.encrypted_key[i] ^ stream[i];
    }

cleanup:
    hydro_memzero(&cache, sizeof(cache));
    hydro_memzero(cache_key, sizeof(cache_key));
    hydro_memzero(stream, sizeof(stream));
    hydro_memzero(computed_mac, sizeof(computed_mac));
    free(cache_path);
    if (machine_id) {
        hydro_memzero(machine_id, machine_id_len);
        free(machine_id);
    }

    return err;
}

/**
 * Clear session cache file
 *
 * Securely zeros the cache file before deleting it.
 * Safe to call even if cache doesn't exist.
 */
static void session_cache_clear(void) {
    char *cache_path = NULL;

    if (session_cache_get_path(&cache_path) != NULL) {
        return;  /* Couldn't get path, nothing to clear */
    }

    if (!fs_exists(cache_path)) {
        free(cache_path);
        return;  /* Already cleared */
    }

    /* Secure deletion: zero file before unlinking (best-effort) */
    FILE *fp = fopen(cache_path, "r+b");
    if (fp) {
        struct session_cache_file zero = {0};
        fwrite(&zero, sizeof(zero), 1, fp);
        fclose(fp);
    }

    unlink(cache_path);
    free(cache_path);
}

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
 * Unlocks, zeros, and frees memory to prevent key leakage.
 * Used as callback for hashmap_free() and hashmap_clear().
 *
 * @param key_ptr Pointer to malloc'd profile key (uint8_t[32])
 */
static void secure_free_profile_key(void *key_ptr) {
    if (key_ptr) {
        /* Best-effort memory unlock (harmless if not locked) */
        munlock(key_ptr, ENCRYPTION_PROFILE_KEY_SIZE);
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
 * Uses monotonic clock to prevent cache lifetime manipulation via
 * system clock changes.
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

    /* Check if expired (positive timeout) using monotonic clock */
    time_t now = get_monotonic_time();
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
            *out_expires_at = time(NULL);  /* Already expired */
        }
        return 0;
    }

    /* Positive timeout = calculate remaining time using monotonic clock
     * This prevents cache lifetime manipulation via clock changes */
    time_t now_monotonic = get_monotonic_time();
    time_t elapsed = now_monotonic - mgr->cached_at;
    int64_t remaining = (int64_t)(mgr->session_timeout - elapsed);

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

    /* Clear file cache */
    session_cache_clear();
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
    if (mgr->profile_keys) {
        hashmap_clear(mgr->profile_keys, secure_free_profile_key);
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

    /* Mark key as cached (using monotonic time for expiry checks) */
    mgr->has_key = true;
    mgr->cached_at = get_monotonic_time();

    /* Save to file cache (non-fatal if fails) */
    if (mgr->session_timeout != 0) {
        error_t *save_err = session_cache_save(mgr->master_key, mgr->session_timeout);
        if (save_err) {
            /* Log warning but don't fail - in-memory cache still works */
            fprintf(stderr, "Warning: Failed to save session cache: %s\n",
                    error_message(save_err));
            error_free(save_err);
        }
    }

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
        munlock(passphrase, MAX_PASSPHRASE_LENGTH + 1);
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
        munlock(passphrase, MAX_PASSPHRASE_LENGTH + 1);
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
        munlock(passphrase, MAX_PASSPHRASE_LENGTH + 1);
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

    /* Lock memory to prevent swapping (best-effort) */
    if (mlock(passphrase, len + 1) != 0) {
        /* Non-fatal - passphrase still protected by process isolation */
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

    /* Step 1: Check in-memory cache */
    if (is_key_valid(mgr)) {
        memcpy(out_master_key, mgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
        return NULL;
    }

    /* Step 2: Try file cache (skip if session_timeout == 0) */
    if (mgr->session_timeout != 0) {
        error_t *err = session_cache_load(mgr->master_key);
        if (!err) {
            /* Cache hit! Update in-memory state with current monotonic time.
             * File cache has its own wall-clock expiry check - once loaded,
             * we switch to monotonic time for in-memory expiry. */
            mgr->has_key = true;
            mgr->cached_at = get_monotonic_time();
            memcpy(out_master_key, mgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
            return NULL;
        }

        /* Cache miss/expired/corrupted - non-fatal, continue to prompt */
        if (err->code == ERR_NOT_FOUND || err->code == ERR_CRYPTO) {
            /* Expected failures (cache doesn't exist, expired, or corrupted) */
            error_free(err);
        } else {
            /* Unexpected error (file I/O) - warn but don't fail */
            fprintf(stderr, "Warning: Failed to load session cache: %s\n",
                    error_message(err));
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

    /* Securely zero and free passphrase */
    munlock(passphrase, passphrase_len);
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

    /* Lock memory to prevent swapping to disk (best-effort, non-fatal if fails) */
    if (mlock(profile_key, ENCRYPTION_PROFILE_KEY_SIZE) != 0) {
        /* mlock failure is non-fatal - common reasons: insufficient privileges,
         * RLIMIT_MEMLOCK exceeded. Key still protected by file permissions. */
    }

    /* Derive profile key from master key */
    err = encryption_derive_profile_key(master_key, profile_name, profile_key);

    /* Clear master key immediately */
    hydro_memzero(master_key, sizeof(master_key));

    if (err) {
        munlock(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
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
            munlock(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
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
        munlock(profile_key, ENCRYPTION_PROFILE_KEY_SIZE);
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
 * NOTE: This does NOT clear the file cache - the cache persists across
 * invocations until it expires (per session_timeout) or is explicitly
 * cleared via `dotta key clear`. This is intentional for UX.
 *
 * Should be called at program exit (e.g., via atexit() or explicit cleanup).
 */
void keymanager_cleanup_global(void) {
    if (global_keymanager) {
        keymanager_free(global_keymanager);
        global_keymanager = NULL;
    }

    /* Note: We intentionally do NOT clear the file cache here.
     * The cache should persist across invocations until timeout/expiry. */
}
