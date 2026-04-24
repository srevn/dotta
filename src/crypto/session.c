/**
 * session.c — On-disk session cache implementation
 */

#include "crypto/session.h"

#include <errno.h>
#include <fcntl.h>
#include <hydrogen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "base/encoding.h"
#include "base/error.h"
#include "sys/filesystem.h"

/**
 * Session Cache File Format
 *
 * Binary layout (108 bytes total):
 *   [magic: "DOTTASES" (8 bytes)]
 *   [version: 1 (1 byte)]
 *   [reserved: 0 (3 bytes)]
 *   [created_at: Unix timestamp (8 bytes, native uint64)]
 *   [expires_at: Unix timestamp or 0 for never (8 bytes, native uint64)]
 *   [machine_salt: Random salt (16 bytes)]
 *   [encrypted_key: Obfuscated master key (32 bytes)]
 *   [mac: keyed-hash MAC for integrity (32 bytes)]
 *
 * The two timestamp fields are stored in native byte order because the
 * cache is machine-bound and never migrates between hosts. The MAC input,
 * however, canonicalizes both timestamps to little-endian (see below) so
 * the MAC computation is reproducible from the field values alone and
 * does not silently depend on host byte order.
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
    uint8_t mac[32];            /* MAC for integrity */
} __attribute__((packed));

/**
 * Compute the cache file path (~/.cache/dotta/session).
 *
 * Uses the XDG-style ~/.cache location, which works on all supported
 * platforms. Returns ERR_FS if HOME is unset.
 *
 * @param out_path Cache file path (caller must free).
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
 * Derive the machine identity used for cache binding.
 *
 * Returns "hostname\0username\0" so the two fields are unambiguously
 * separated at the byte level. The result is hashed with a per-cache
 * random salt to produce the obfuscation stream and MAC key; the
 * identity itself never touches disk.
 *
 * @param out_identity Machine identity string (caller must free and zero).
 * @param out_len Length of identity string (including both NULs).
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
 * Save key to session cache file
 *
 * Encrypts and saves the master key to ~/.cache/dotta/session with
 * machine binding and expiry time based on session_timeout.
 *
 * @param key Key to save (32 bytes)
 * @param session_timeout Timeout in seconds (0 = always prompt, -1 = never expire)
 */
error_t *session_save(const uint8_t key[32], int32_t timeout_seconds) {
    CHECK_NULL(key);

    error_t *err = NULL;
    char *cache_path = NULL;
    char *cache_dir = NULL;
    char *machine_id = NULL;
    size_t machine_id_len = 0;
    FILE *fp = NULL;

    uint8_t cache_key[32] = { 0 };
    uint8_t stream[32] = { 0 };

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
    struct session_cache_file cache = { 0 };
    memcpy(cache.magic, SESSION_CACHE_MAGIC, 8);
    cache.version = SESSION_CACHE_VERSION;

    cache.created_at = (uint64_t) time(NULL);

    /* Calculate expiry */
    if (timeout_seconds < 0) {
        cache.expires_at = 0;  /* Never expire */
    } else {
        cache.expires_at = cache.created_at + (uint64_t) timeout_seconds;
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
    hydro_hash_update(
        &hash_state, (uint8_t *) machine_id, machine_id_len
    );
    hydro_hash_update(
        &hash_state, cache.machine_salt, sizeof(cache.machine_salt)
    );
    hydro_hash_final(
        &hash_state, cache_key, 32
    );
    hydro_memzero(&hash_state, sizeof(hash_state));

    /* Encrypt master key using deterministic stream cipher */
    hydro_random_buf_deterministic(stream, 32, cache_key);
    for (int i = 0; i < 32; i++) {
        cache.encrypted_key[i] = key[i] ^ stream[i];
    }

    /* Compute MAC over: created_at || expires_at || machine_salt || encrypted_key
     * Use cache_key as the MAC key for authentication.
     *
     * The two timestamp fields are canonicalized to little-endian before
     * hashing so the MAC input is independent of host byte order. The
     * on-disk layout still stores them as native uint64_t — the cache
     * is machine-bound, so the layout never crosses endian boundaries —
     * but the MAC input itself is now reproducible from the field values
     * alone, matching the convention already used in encryption.c. */
    hydro_hash_state mac_state;
    if (hydro_hash_init(&mac_state, "dottamac", cache_key) != 0) {
        err = ERROR(ERR_CRYPTO, "Failed to initialize MAC computation");
        goto cleanup;
    }

    uint8_t ts_le[8];
    store_le64(ts_le, cache.created_at);
    hydro_hash_update(&mac_state, ts_le, sizeof(ts_le));
    store_le64(ts_le, cache.expires_at);
    hydro_hash_update(&mac_state, ts_le, sizeof(ts_le));
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
        err = ERROR(
            ERR_FS, "Failed to create cache file: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    /* Convert file descriptor to FILE* for buffered I/O
     * Note: If fdopen() succeeds, the FILE* takes ownership of the fd and will
     * close it when fclose() is called. If fdopen() fails, we must close fd manually. */
    fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);  /* fdopen failed - must close fd manually to prevent leak */
        err = ERROR(
            ERR_FS, "Failed to fdopen cache file: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    /* Defense-in-depth: Explicitly verify permissions using fchmod()
     * While open() already set 0600, this provides an additional security check
     * and guards against any umask interference. Using fchmod() (not chmod())
     * operates on the open file descriptor, which is safer than pathname-based chmod(). */
    if (fchmod(fileno(fp), 0600) != 0) {
        err = ERROR(
            ERR_FS, "Failed to set cache file permissions: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    /* Write cache data structure to file */
    if (fwrite(&cache, sizeof(cache), 1, fp) != 1) {
        err = ERROR(
            ERR_FS, "Failed to write cache file"
        );
        goto cleanup;
    }

    /* Flush and sync to disk for durability
     * This ensures the cache survives system crashes and matches the paranoid-safe
     * file writing pattern used throughout the codebase (see fs_write_file_raw()).
     * fflush() writes buffered data to the kernel, fsync() commits to physical disk. */
    if (fflush(fp) != 0) {
        err = ERROR(
            ERR_FS, "Failed to flush cache file: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    if (fsync(fileno(fp)) != 0) {
        err = ERROR(
            ERR_FS, "Failed to sync cache file to disk: %s",
            strerror(errno)
        );
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
 * Load key from session cache file
 *
 * Verifies MAC, checks expiry, and decrypts the master key.
 *
 * @param out_key Output buffer for 32-byte master key
 */
error_t *session_load(uint8_t out_key[32]) {
    CHECK_NULL(out_key);

    error_t *err = NULL;
    char *cache_path = NULL;
    char *machine_id = NULL;
    size_t machine_id_len = 0;
    FILE *fp = NULL;

    struct session_cache_file cache;
    uint8_t cache_key[32] = { 0 };
    uint8_t stream[32] = { 0 };
    uint8_t computed_mac[32] = { 0 };

    /* Get cache path */
    err = session_cache_get_path(&cache_path);
    if (err) return err;

    /* Check if cache exists */
    if (!fs_exists(cache_path)) {
        free(cache_path);
        return ERROR(
            ERR_NOT_FOUND, "Cache file does not exist"
        );
    }

    /* Check permissions (must be 0600) */
    struct stat st;
    if (stat(cache_path, &st) != 0) {
        err = ERROR(
            ERR_FS, "Failed to stat cache file: %s",
            strerror(errno)
        );
        free(cache_path);
        return err;
    }

    if ((st.st_mode & 0777) != 0600) {
        /* Wrong permissions - delete and fail */
        unlink(cache_path);
        free(cache_path);
        return ERROR(
            ERR_CRYPTO, "Cache file has wrong permissions (expected 0600)"
        );
    }

    /* Read cache file */
    fp = fopen(cache_path, "rb");
    if (!fp) {
        err = ERROR(
            ERR_FS, "Failed to open cache file: %s",
            strerror(errno)
        );
        free(cache_path);
        return err;
    }

    if (fread(&cache, sizeof(cache), 1, fp) != 1) {
        fclose(fp);
        hydro_memzero(&cache, sizeof(cache));
        unlink(cache_path);
        free(cache_path);
        return ERROR(
            ERR_CRYPTO, "Cache file corrupted (incomplete read)"
        );
    }

    fclose(fp);
    fp = NULL;

    /* Validate magic header */
    if (memcmp(cache.magic, SESSION_CACHE_MAGIC, 8) != 0) {
        hydro_memzero(&cache, sizeof(cache));
        unlink(cache_path);
        free(cache_path);
        return ERROR(
            ERR_CRYPTO, "Cache file corrupted (bad magic)"
        );
    }

    /* Check version */
    if (cache.version != SESSION_CACHE_VERSION) {
        hydro_memzero(&cache, sizeof(cache));
        unlink(cache_path);
        free(cache_path);
        return ERROR(
            ERR_CRYPTO, "Unsupported cache version: %d", cache.version
        );
    }

    /* Check expiry (if not 0 = never expire) */
    if (cache.expires_at != 0) {
        time_t now = time(NULL);
        if ((uint64_t) now >= cache.expires_at) {
            hydro_memzero(&cache, sizeof(cache));
            unlink(cache_path);
            free(cache_path);
            return ERROR(ERR_NOT_FOUND, "Cache expired");
        }
    }

    /* Get machine identity */
    err = get_machine_identity(&machine_id, &machine_id_len);
    if (err) {
        hydro_memzero(&cache, sizeof(cache));
        free(cache_path);
        return err;
    }

    /* Derive cache key: hash(machine_id || machine_salt)
     * Must match the derivation in session_save() */
    hydro_hash_state hash_state;
    if (hydro_hash_init(&hash_state, "dottacch", NULL) != 0) {
        err = ERROR(
            ERR_CRYPTO, "Failed to initialize hash for cache key"
        );
        goto cleanup;
    }
    hydro_hash_update(
        &hash_state, (uint8_t *) machine_id, machine_id_len
    );
    hydro_hash_update(
        &hash_state, cache.machine_salt, sizeof(cache.machine_salt)
    );

    hydro_hash_final(&hash_state, cache_key, 32);
    hydro_memzero(&hash_state, sizeof(hash_state));

    /* Verify MAC using cache_key.
     *
     * Canonicalize the timestamp fields the same way session_save does —
     * feeding raw field memory would match the save path on the same
     * machine today, but makes the MAC input host-byte-order dependent.
     * Using store_le64 here keeps the two paths in sync regardless of host. */
    hydro_hash_state mac_state;
    if (hydro_hash_init(&mac_state, "dottamac", cache_key) != 0) {
        err = ERROR(
            ERR_CRYPTO, "Failed to initialize MAC verification"
        );
        goto cleanup;
    }

    uint8_t ts_le[8];
    store_le64(ts_le, cache.created_at);
    hydro_hash_update(&mac_state, ts_le, sizeof(ts_le));
    store_le64(ts_le, cache.expires_at);
    hydro_hash_update(&mac_state, ts_le, sizeof(ts_le));
    hydro_hash_update(&mac_state, cache.machine_salt, 16);
    hydro_hash_update(&mac_state, cache.encrypted_key, 32);

    hydro_hash_final(&mac_state, computed_mac, 32);
    hydro_memzero(&mac_state, sizeof(mac_state));

    if (!hydro_equal(computed_mac, cache.mac, 32)) {
        unlink(cache_path);
        err = ERROR(
            ERR_CRYPTO, "Cache MAC verification failed (tampered or wrong machine)"
        );
        goto cleanup;
    }

    /* Decrypt master key */
    hydro_random_buf_deterministic(stream, 32, cache_key);
    for (int i = 0; i < 32; i++) {
        out_key[i] = cache.encrypted_key[i] ^ stream[i];
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
void session_clear(void) {
    char *cache_path = NULL;

    if (session_cache_get_path(&cache_path) != NULL) {
        return;  /* Couldn't get path, nothing to clear */
    }

    if (!fs_exists(cache_path)) {
        free(cache_path);
        return;  /* Already cleared */
    }

    /* Secure deletion: zero file before unlinking (best-effort).
     * Flush and sync to ensure zeros are committed to disk before the
     * file is unlinked, preventing kernel reordering from leaving
     * the original key data on disk. */
    FILE *fp = fopen(cache_path, "r+b");
    if (fp) {
        struct session_cache_file zero = { 0 };
        fwrite(&zero, sizeof(zero), 1, fp);
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
    }

    unlink(cache_path);
    free(cache_path);
}
