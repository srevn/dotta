/**
 * content.c - Transparent content provider implementation
 *
 * See content.h for API documentation.
 */

#include "content.h"

#include <errno.h>
#include <git2.h>
#include <hydrogen.h>
#include <string.h>
#include <sys/stat.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/bootstrap.h"
#include "core/metadata.h"
#include "crypto/encryption.h"
#include "crypto/keymanager.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"

/**
 * Maximum file size for encryption (100MB)
 *
 * This limit prevents:
 * - Memory exhaustion from huge files
 * - Disk exhaustion in worktrees
 * - DoS via resource consumption
 *
 * Rationale: Dotfiles should be small configuration files.
 * If you need to encrypt 100MB+ files, reconsider your approach.
 */
#define MAX_ENCRYPTED_FILE_SIZE (100 * 1024 * 1024)

/**
 * Content cache structure
 */
struct content_cache {
    git_repository *repo;     /* Borrowed reference */
    keymanager_t *km;         /* Borrowed reference (can be NULL) */
    hashmap_t *cache_map;     /* OID hex → buffer_t* (owned) */
};

/**
 * Securely free buffer (zero memory before release)
 *
 * SECURITY: This function zeros the buffer's memory before freeing it.
 * Critical for preventing memory disclosure of decrypted sensitive data
 * (SSH keys, API tokens, passwords, etc.) via:
 * - Swap files (if memory is paged to disk)
 * - Core dumps (crash analysis)
 * - Memory inspection tools
 * - Memory reuse by other processes
 *
 * Used by content cache to ensure plaintext doesn't linger in memory.
 *
 * @param buf_ptr Buffer to free (cast from void* for hashmap_free compatibility)
 */
static void buffer_free_secure(void *buf_ptr) {
    buffer_t *buf = (buffer_t *)buf_ptr;
    if (!buf) {
        return;
    }

    /* Zero sensitive plaintext data before freeing (defense in depth) */
    if (buffer_data(buf) && buffer_size(buf) > 0) {
        hydro_memzero((void *)buffer_data(buf), buffer_size(buf));
    }

    buffer_free(buf);
}

/**
 * Get plaintext from blob (internal workhorse)
 *
 * This function handles the core logic of loading a blob and
 * transparently decrypting it if needed.
 *
 * Process:
 * 1. Check magic header for encryption (source of truth)
 * 2. Validate consistency with metadata (defense in depth)
 * 3. Decrypt if needed
 * 4. Return plaintext buffer
 *
 * @param repo Git repository
 * @param blob Loaded git blob (must not be NULL)
 * @param storage_path File path in profile
 * @param profile_name Profile name
 * @param metadata Metadata for validation (must not be NULL)
 * @param km Key manager (can be NULL for plaintext files)
 * @param out_content Output buffer (caller owns)
 * @param out_was_encrypted Optional flag - set to true if file was encrypted (can be NULL)
 * @return Error or NULL on success
 */
static error_t *get_plaintext_from_blob(
    git_repository *repo,
    git_blob *blob,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    buffer_t **out_content,
    bool *out_was_encrypted
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_content);

    const unsigned char *blob_data = git_blob_rawcontent(blob);
    size_t blob_size = (size_t)git_blob_rawsize(blob);

    /* Step 1: Check magic header for encryption (source of truth) */
    bool is_encrypted = encryption_is_encrypted(blob_data, blob_size);

    /* Set output flag if caller wants it */
    if (out_was_encrypted) {
        *out_was_encrypted = is_encrypted;
    }

    /* Skip metadata validation for special system files that don't track themselves
     * These files are critical for dotta operations and live at profile root:
     * - .bootstrap (executable script for profile setup)
     * - .dottaignore (ignore patterns for the profile)
     * - .dotta/metadata.json (file permissions and encryption state)
     */
    bool is_special_file = (strcmp(storage_path, BOOTSTRAP_DEFAULT_SCRIPT_NAME) == 0 ||
                            strcmp(storage_path, METADATA_FILE_PATH) == 0 ||
                            strcmp(storage_path, ".dottaignore") == 0);

    if (!is_special_file) {
        /* Step 2: Validate consistency with metadata (defense in depth)
         * SECURITY: Metadata must contain entry for this file. Missing entries indicate:
         * - Metadata corruption (desync between git and metadata)
         * - File added to git without using dotta add/update (manual tampering)
         * - Serious bug in add/update/remove commands
         *
         * We require metadata entry to detect these error conditions.
         * Magic header alone is not sufficient for integrity verification.
         */
        const metadata_item_t *meta_entry = NULL;
        error_t *err = metadata_get_item(metadata, storage_path, &meta_entry);

        if (err) {
            /* Entry not found - this is now an error (metadata corruption) */
            error_free(err);
            return ERROR(ERR_STATE_INVALID,
                "File '%s' exists in git but not in metadata.\n"
                "This indicates metadata corruption or manual git manipulation.\n"
                "\n"
                "To fix:\n"
                "  1. If this is a legitimate file: dotta update -p %s '%s'\n"
                "  2. If this is corruption: inspect git history and restore metadata",
                storage_path, profile_name, storage_path);
        }

        if (!meta_entry) {
            /* Should never happen - metadata_get_item returns error if not found */
            return ERROR(ERR_INTERNAL,
                "metadata_get_item returned NULL without error for '%s'",
                storage_path);
        }

        /* Validate this is a file entry (union safety)
         * SECURITY: Accessing wrong union member is undefined behavior.
         * Storage paths should only map to files, but we validate defensively. */
        if (meta_entry->kind != METADATA_ITEM_FILE) {
            return ERROR(ERR_STATE_INVALID,
                "Metadata entry for '%s' is a directory, expected file.\n"
                "This indicates severe metadata corruption.",
                storage_path);
        }

        /* Cross-validate magic header against metadata encryption flag */
        if (is_encrypted && !meta_entry->file.encrypted) {
            return ERROR(ERR_STATE_INVALID,
                "File '%s' is encrypted in git but metadata says plaintext.\n"
                "This indicates metadata corruption.\n"
                "To fix, run: dotta update -p %s '%s'",
                storage_path, profile_name, storage_path);
        }
        if (!is_encrypted && meta_entry->file.encrypted) {
            return ERROR(ERR_STATE_INVALID,
                "File '%s' is marked as encrypted in metadata but stored as plaintext in git.\n"
                "This indicates metadata corruption.\n"
                "To fix, run: dotta update -p %s '%s'",
                storage_path, profile_name, storage_path);
        }
    }

    /* Step 3: Handle encrypted files */
    if (is_encrypted) {
        /* Check we have keymanager */
        if (!km) {
            return ERROR(ERR_CRYPTO,
                "File '%s' is encrypted but no key manager provided.\n"
                "\n"
                "To decrypt this file, ensure encryption is configured:\n"
                "  1. Set passphrase: dotta key set\n"
                "  2. Configure encryption in config.toml",
                storage_path);
        }

        /* Get profile key */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        error_t *err = keymanager_get_profile_key(km, profile_name, profile_key);
        if (err) {
            return error_wrap(err, "Failed to get profile key for '%s'", profile_name);
        }

        /* Decrypt */
        buffer_t *plaintext = NULL;
        err = encryption_decrypt(blob_data, blob_size, profile_key, storage_path, &plaintext);

        /* Clear profile key immediately (security) */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            return error_wrap(err,
                "Failed to decrypt '%s'.\n"
                "\n"
                "Possible causes:\n"
                "  - Wrong passphrase (try: dotta key clear)\n"
                "  - File corrupted in repository\n"
                "  - File encrypted with different passphrase",
                storage_path);
        }

        *out_content = plaintext;
        return NULL;
    }

    /* Step 4: Handle plaintext files */
    buffer_t *content = buffer_create();
    if (!content) {
        return ERROR(ERR_MEMORY, "Failed to allocate buffer");
    }

    if (blob_size > 0) {
        error_t *err = buffer_append(content, blob_data, blob_size);
        if (err) {
            buffer_free(content);
            return error_wrap(err, "Failed to copy blob content");
        }
    }

    *out_content = content;
    return NULL;
}

error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    buffer_t **out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_content);

    /* Load blob from repository */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, blob_oid);
    if (git_err != 0) {
        return ERROR(ERR_NOT_FOUND, "Failed to load blob: %s", git_error_last()->message);
    }

    /* Get plaintext content */
    error_t *err = get_plaintext_from_blob(
        repo, blob, storage_path, profile_name, metadata, km, out_content,
        NULL  /* Don't track encryption status in simple API */
    );

    git_blob_free(blob);
    return err;
}

error_t *content_get_from_tree_entry(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    buffer_t **out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_content);

    /* Get OID from tree entry */
    const git_oid *blob_oid = git_tree_entry_id(entry);
    if (!blob_oid) {
        return ERROR(ERR_INTERNAL, "Failed to get OID from tree entry");
    }

    /* Delegate to blob OID variant */
    return content_get_from_blob_oid(
        repo, blob_oid, storage_path, profile_name, metadata, km, out_content
    );
}

content_cache_t *content_cache_create(
    git_repository *repo,
    keymanager_t *km
) {
    if (!repo) {
        return NULL;
    }

    content_cache_t *cache = calloc(1, sizeof(content_cache_t));
    if (!cache) {
        return NULL;
    }

    cache->repo = repo;
    cache->km = km;
    cache->cache_map = hashmap_create(64);  /* Initial capacity: 64 entries */

    if (!cache->cache_map) {
        free(cache);
        return NULL;
    }

    return cache;
}

error_t *content_cache_get_from_blob_oid(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    const buffer_t **out_content
) {
    CHECK_NULL(cache);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_content);

    /* Convert OID to hex string (cache key) */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), blob_oid);

    /* Check cache */
    buffer_t *cached_content = hashmap_get(cache->cache_map, oid_str);
    if (cached_content) {
        /* Cache hit! */
        *out_content = cached_content;
        return NULL;
    }

    /* Cache miss - load blob and decrypt if needed */

    /* Load blob from repository */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, cache->repo, blob_oid);
    if (git_err != 0) {
        return ERROR(ERR_NOT_FOUND, "Failed to load blob: %s", git_error_last()->message);
    }

    /* Get plaintext content */
    buffer_t *content = NULL;
    error_t *err = get_plaintext_from_blob(
        cache->repo, blob, storage_path, profile_name, metadata, cache->km,
        &content, NULL  /* Don't track encryption status */
    );

    git_blob_free(blob);

    if (err) {
        return err;
    }

    /* Store in cache (cache takes ownership) */
    err = hashmap_set(cache->cache_map, oid_str, content);
    if (err) {
        /* Fatal - cannot return borrowed reference if caching fails */
        /* Ownership contract requires cache to own the buffer */
        buffer_free(content);
        return error_wrap(err, "Failed to cache content for blob");
    }

    *out_content = content;
    return NULL;
}

error_t *content_cache_get_from_tree_entry(
    content_cache_t *cache,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    const buffer_t **out_content
) {
    CHECK_NULL(cache);
    CHECK_NULL(entry);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_content);

    /* Get OID from tree entry */
    const git_oid *blob_oid = git_tree_entry_id(entry);
    if (!blob_oid) {
        return ERROR(ERR_INTERNAL, "Failed to get OID from tree entry");
    }

    /* Delegate to blob OID variant */
    return content_cache_get_from_blob_oid(
        cache, blob_oid, storage_path, profile_name, metadata, out_content
    );
}

void content_cache_free(content_cache_t *cache) {
    if (!cache) {
        return;
    }

    /* Free all cached buffers with secure cleanup
     * SECURITY: Use buffer_free_secure() to zero plaintext memory before freeing.
     * The cache contains decrypted sensitive data that must not linger in memory. */
    if (cache->cache_map) {
        hashmap_free(cache->cache_map, buffer_free_secure);
    }

    free(cache);
}

error_t *content_store_to_blob(
    git_repository *repo,
    const buffer_t *plaintext,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
    bool should_encrypt,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(plaintext);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_oid);

    const uint8_t *data = buffer_data(plaintext);
    size_t size = buffer_size(plaintext);

    /* Validate file size (security: prevent DoS via huge files) */
    if (size > MAX_ENCRYPTED_FILE_SIZE) {
        return ERROR(ERR_INVALID_ARG,
            "Content too large: %zu bytes (max %d bytes).\n"
            "\n"
            "Rationale: Dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            size, MAX_ENCRYPTED_FILE_SIZE);
    }

    buffer_t *ciphertext = NULL;

    /* Handle encryption if requested */
    if (should_encrypt) {
        if (!km) {
            return ERROR(ERR_CRYPTO,
                "Encryption requested but no keymanager provided");
        }

        /* Get profile key (cached in keymanager for performance) */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        error_t *err = keymanager_get_profile_key(km, profile_name, profile_key);
        if (err) {
            return error_wrap(err, "Failed to get profile key for '%s'", profile_name);
        }

        /* Encrypt */
        err = encryption_encrypt(data, size, profile_key, storage_path, &ciphertext);

        /* Clear profile key immediately (defense in depth) */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            return error_wrap(err, "Failed to encrypt '%s'", storage_path);
        }

        /* Use encrypted data */
        data = buffer_data(ciphertext);
        size = buffer_size(ciphertext);
    }

    /* Create git blob */
    int ret = git_blob_create_from_buffer(out_oid, repo, data, size);

    /* Free ciphertext if we allocated it */
    if (ciphertext) {
        buffer_free(ciphertext);
    }

    if (ret < 0) {
        const git_error *git_err = git_error_last();
        return ERROR(ERR_GIT, "Failed to create git blob: %s",
                    git_err ? git_err->message : "unknown error");
    }

    return NULL;
}

/**
 * Hash buffer content using Blake2b and return hex string
 *
 * Internal helper for content hashing.
 *
 * @param content Buffer to hash (must not be NULL)
 * @param out_hash Output hex string (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *hash_buffer_to_hex(const buffer_t *content, char **out_hash) {
    CHECK_NULL(content);
    CHECK_NULL(out_hash);

    /* Blake2b produces 32 bytes, which becomes 64 hex chars + null terminator */
    uint8_t hash_bytes[32];
    char *hex = NULL;

    /* Compute Blake2b hash
     * Context: "dottahsh" (8 bytes) for domain separation
     * Key: NULL (no keyed hashing needed for content addressing)
     */
    int result = hydro_hash_hash(
        hash_bytes,
        32,
        buffer_data(content),
        buffer_size(content),
        "dottahsh",
        NULL
    );

    if (result != 0) {
        return ERROR(ERR_CRYPTO, "Failed to compute Blake2b hash");
    }

    /* Convert to hex string */
    hex = malloc(65);  /* 64 hex chars + null terminator */
    if (!hex) {
        hydro_memzero(hash_bytes, sizeof(hash_bytes));
        return ERROR(ERR_MEMORY, "Failed to allocate hex string");
    }

    for (size_t i = 0; i < 32; i++) {
        snprintf(hex + (i * 2), 3, "%02x", hash_bytes[i]);
    }
    hex[64] = '\0';

    /* Clear sensitive hash bytes */
    hydro_memzero(hash_bytes, sizeof(hash_bytes));

    *out_hash = hex;
    return NULL;
}

error_t *content_hash_file(
    const char *filesystem_path,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    char **out_hash
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_hash);

    error_t *err = NULL;
    buffer_t *content = NULL;

    /* Read file from filesystem
     * We need to handle encryption transparently, so we:
     * 1. Read the raw file
     * 2. Check magic header for encryption
     * 3. Decrypt if needed
     * 4. Hash the plaintext
     *
     * For simplicity, we use the same pattern as content_get_from_tree_entry:
     * - Load file into buffer
     * - Detect encryption from magic
     * - Decrypt if needed
     */

    /* Read file into buffer */
    err = fs_read_file(filesystem_path, &content);
    if (err) {
        return error_wrap(err, "Failed to read file for hashing");
    }

    /* Check if encrypted */
    bool is_encrypted = encryption_is_encrypted(
        (const unsigned char *)buffer_data(content),
        buffer_size(content)
    );

    if (is_encrypted) {
        /* Encrypted - need to decrypt before hashing */
        if (!km) {
            buffer_free(content);
            return ERROR(ERR_CRYPTO,
                "File '%s' is encrypted but no key manager provided",
                filesystem_path);
        }

        /* Get profile key */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        err = keymanager_get_profile_key(km, profile_name, profile_key);
        if (err) {
            buffer_free(content);
            return error_wrap(err, "Failed to get profile key");
        }

        /* Decrypt */
        buffer_t *plaintext = NULL;
        err = encryption_decrypt(
            (const unsigned char *)buffer_data(content),
            buffer_size(content),
            profile_key,
            storage_path,
            &plaintext
        );

        /* Clear profile key immediately */
        hydro_memzero(profile_key, sizeof(profile_key));

        buffer_free(content);
        content = NULL;

        if (err) {
            return error_wrap(err, "Failed to decrypt file for hashing");
        }

        content = plaintext;
    }

    /* Hash the plaintext content */
    err = hash_buffer_to_hex(content, out_hash);
    buffer_free_secure(content);

    return err;
}

error_t *content_hash_from_tree_entry(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    char **out_hash
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);
    CHECK_NULL(out_hash);

    error_t *err = NULL;
    buffer_t *content = NULL;

    /* Get plaintext content (handles decryption transparently) */
    err = content_get_from_tree_entry(
        repo,
        entry,
        storage_path,
        profile_name,
        metadata,
        km,
        &content
    );
    if (err) {
        return error_wrap(err, "Failed to get content for hashing");
    }

    /* Hash the plaintext content */
    err = hash_buffer_to_hex(content, out_hash);
    buffer_free_secure(content);

    return err;
}

error_t *content_store_file_to_worktree(
    const char *filesystem_path,
    const char *worktree_path,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
    bool should_encrypt,
    struct stat *out_stat
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(worktree_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);

    /* Step 1: Validate file type (security: prevent symlink/special file confusion) */
    struct stat st;
    if (lstat(filesystem_path, &st) < 0) {
        return ERROR(ERR_FS, "Failed to stat '%s': %s",
                    filesystem_path, strerror(errno));
    }

    /* Return stat data to caller if requested (before error checks) */
    if (out_stat) {
        memcpy(out_stat, &st, sizeof(struct stat));
    }

    if (!S_ISREG(st.st_mode)) {
        const char *type = S_ISLNK(st.st_mode) ? "symlink" :
                           S_ISDIR(st.st_mode) ? "directory" :
                           S_ISFIFO(st.st_mode) ? "FIFO" :
                           S_ISSOCK(st.st_mode) ? "socket" :
                           S_ISCHR(st.st_mode) ? "character device" :
                           S_ISBLK(st.st_mode) ? "block device" : "special file";
        return ERROR(ERR_INVALID_ARG,
            "Cannot store '%s': it is a %s, not a regular file.\n"
            "\n"
            "Dotta only manages regular configuration files.\n"
            "Symlinks and special files are not supported.",
            filesystem_path, type);
    }

    /* Step 2: Read file from filesystem */
    buffer_t *content = NULL;
    error_t *err = fs_read_file(filesystem_path, &content);
    if (err) {
        return error_wrap(err, "Failed to read file '%s'", filesystem_path);
    }

    /* Step 3: Validate file size (security: prevent DoS via huge files) */
    size_t file_size = buffer_size(content);
    if (file_size > MAX_ENCRYPTED_FILE_SIZE) {
        buffer_free(content);
        return ERROR(ERR_INVALID_ARG,
            "File '%s' is too large: %zu bytes (max %d bytes).\n"
            "\n"
            "Rationale: Dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            filesystem_path, file_size, MAX_ENCRYPTED_FILE_SIZE);
    }

    /* Step 4: Get source file's mode (preserve permissions in worktree → git) */
    mode_t mode = st.st_mode;  /* Reuse mode from stat() above */

    /* Step 5: Encrypt if requested */
    buffer_t *data_to_write = content;  /* Default: write plaintext */
    buffer_t *ciphertext = NULL;

    if (should_encrypt) {
        if (!km) {
            buffer_free(content);
            return ERROR(ERR_CRYPTO,
                "Encryption requested but no keymanager provided");
        }

        /* Get profile key (cached in keymanager) */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        err = keymanager_get_profile_key(km, profile_name, profile_key);
        if (err) {
            buffer_free(content);
            return error_wrap(err, "Failed to get profile key for '%s'", profile_name);
        }

        /* Encrypt */
        err = encryption_encrypt(
            buffer_data(content),
            buffer_size(content),
            profile_key,
            storage_path,
            &ciphertext
        );

        /* Clear profile key immediately */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            buffer_free(content);
            return error_wrap(err, "Failed to encrypt '%s'", storage_path);
        }

        /* Use encrypted data for writing */
        data_to_write = ciphertext;
    }

    /* Step 6: Write to worktree with original mode
     * CRITICAL: Use source file's mode so git commits with correct permissions.
     * This ensures git mode matches metadata mode, preventing spurious MODE diffs. */
    err = fs_write_file_raw(
        worktree_path,
        buffer_data(data_to_write),
        buffer_size(data_to_write),
        mode,  /* Preserve source mode */
        -1,    /* Don't change ownership */
        -1     /* Don't change ownership */
    );

    /* Cleanup */
    buffer_free(content);
    if (ciphertext) {
        buffer_free(ciphertext);
    }

    if (err) {
        return error_wrap(err, "Failed to write to worktree '%s'", worktree_path);
    }

    return NULL;
}
