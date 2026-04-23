/**
 * content.c - Transparent content provider implementation
 *
 * See content.h for API documentation.
 */

#include "infra/content.h"

#include <errno.h>
#include <git2.h>
#include <hydrogen.h>
#include <string.h>
#include <sys/stat.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "crypto/encryption.h"
#include "crypto/keymgr.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/**
 * Content cache structure
 */
struct content_cache {
    git_repository *repo;     /* Borrowed reference */
    keymgr *keymgr;           /* Borrowed reference (can be NULL) */
    hashmap_t *cache_map;     /* OID hex -> buffer_t* (owned) */
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
static void buffer_destroy_secure(void *ptr) {
    buffer_t *buf = ptr;
    if (!buf) {
        return;
    }

    /* Zero sensitive plaintext data before freeing (defense in depth) */
    if (buf->data && buf->size > 0) {
        hydro_memzero(buf->data, buf->size);
    }

    buffer_destroy(buf);
}

/**
 * Get plaintext from blob (internal workhorse)
 *
 * This function handles the core logic of transparently decrypting
 * raw blob bytes if needed. Works on a zero-copy view, so callers
 * must keep the backing blob alive for the duration of the call.
 *
 * Architecture:
 * - VWD operations: expected_encrypted comes from entry->encrypted (state cache)
 * - Historical operations: expected_encrypted extracted from metadata by caller
 * - Defense-in-depth: Validates magic header matches expected state
 *
 * Process:
 * 1. Check magic header for encryption (source of truth)
 * 2. Validate encryption matches expectation (defense in depth)
 * 3. Decrypt if needed
 * 4. Return plaintext buffer
 *
 * @param blob_data Raw blob bytes (must not be NULL unless blob_size == 0)
 * @param blob_size Raw blob size in bytes
 * @param storage_path File path in profile
 * @param profile Profile name
 * @param expected_encrypted Expected encryption state (from VWD cache or metadata)
 * @param keymgr Key manager (can be NULL for plaintext files)
 * @param out_content Output buffer (caller owns)
 * @return Error or NULL on success
 */
static error_t *get_plaintext_from_blob(
    const unsigned char *blob_data,
    size_t blob_size,
    const char *storage_path,
    const char *profile,
    bool expected_encrypted,
    keymgr *keymgr,
    buffer_t *out_content
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    *out_content = (buffer_t){ 0 };

    /* Step 1: Check magic header for encryption (source of truth) */
    bool is_encrypted = encryption_is_encrypted(blob_data, blob_size);

    /* Step 2: Validate encryption state matches expectation (defense in depth)
     *
     * This cross-check detects:
     * - Manifest operations: State database out of sync with Git (corruption)
     * - Historical operations: Metadata corruption or manual tampering
     * - All operations: Magic header vs expected state mismatch
     *
     * The magic header is the source of truth, but we validate against the
     * expected state to catch inconsistencies early.
     */
    if (is_encrypted != expected_encrypted) {
        return ERROR(
            ERR_STATE_INVALID,
            "Encryption state mismatch for '%s':\n"
            "  Magic header indicates: %s\n"
            "  Expected state indicates: %s\n\n"
            "This means state corruption or manual git manipulation.\n"
            "To fix, run: dotta update -p %s '%s'",
            storage_path, is_encrypted ? "encrypted" : "plaintext",
            expected_encrypted ? "encrypted" : "plaintext",
            profile, storage_path
        );
    }

    /* Step 3: Handle encrypted files */
    if (is_encrypted) {
        /* Check we have keymgr */
        if (!keymgr) {
            return ERROR(
                ERR_CRYPTO,
                "File '%s' is encrypted but no key manager provided.\n\n"
                "To decrypt this file, ensure encryption is configured:\n"
                "  1. Set passphrase: dotta key set\n"
                "  2. Configure encryption in config.toml", storage_path
            );
        }

        /* Get profile key */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
        if (err) {
            return error_wrap(err, "Failed to get profile key for '%s'", profile);
        }

        /* Decrypt */
        err = encryption_decrypt(
            blob_data, blob_size, profile_key, storage_path, out_content
        );

        /* Clear profile key immediately (security) */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            return error_wrap(
                err,
                "Failed to decrypt '%s'.\n\nPossible causes:\n"
                "  - Wrong passphrase (try: dotta key clear)\n"
                "  - File corrupted in repository\n"
                "  - File encrypted with different passphrase", storage_path
            );
        }

        return NULL;
    }

    /* Step 4: Handle plaintext files */
    if (blob_size > 0) {
        error_t *err = buffer_append(out_content, blob_data, blob_size);
        if (err) {
            return error_wrap(err, "Failed to copy blob content");
        }
    }

    return NULL;
}

error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    bool expected_encrypted,
    keymgr *keymgr,
    buffer_t *out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    /* Open zero-copy view onto the blob */
    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(repo, blob_oid, &view);
    if (err) {
        return error_wrap(err, "Failed to load blob for '%s'", storage_path);
    }

    /* Get plaintext content (view bytes valid until close) */
    err = get_plaintext_from_blob(
        view.data, view.size, storage_path, profile,
        expected_encrypted, keymgr, out_content
    );

    gitops_blob_view_close(&view);
    return err;
}

content_cache_t *content_cache_create(
    git_repository *repo,
    keymgr *keymgr
) {
    if (!repo) {
        return NULL;
    }

    content_cache_t *cache = calloc(1, sizeof(content_cache_t));
    if (!cache) {
        return NULL;
    }

    cache->repo = repo;
    cache->keymgr = keymgr;

    /* Initial capacity: 64 entries */
    cache->cache_map = hashmap_create(64);

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
    const char *profile,
    bool expected_encrypted,
    const buffer_t **out_content
) {
    CHECK_NULL(cache);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
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

    /* Open zero-copy view onto the blob */
    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(cache->repo, blob_oid, &view);
    if (err) {
        return error_wrap(err, "Failed to load blob for '%s'", storage_path);
    }

    /* Heap-allocate buffer for cache storage */
    buffer_t *content = buffer_new(0);
    if (!content) {
        gitops_blob_view_close(&view);
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }

    /* Get plaintext content (view bytes valid until close) */
    err = get_plaintext_from_blob(
        view.data, view.size, storage_path, profile,
        expected_encrypted, cache->keymgr, content
    );

    gitops_blob_view_close(&view);

    if (err) {
        buffer_destroy(content);
        return err;
    }

    /* Store in cache (cache takes ownership) */
    err = hashmap_set(cache->cache_map, oid_str, content);
    if (err) {
        /* Fatal - cannot return borrowed reference if caching fails */
        /* Ownership contract requires cache to own the buffer */
        buffer_destroy(content);
        return error_wrap(err, "Failed to cache content for blob");
    }

    *out_content = content;
    return NULL;
}

void content_cache_free(content_cache_t *cache) {
    if (!cache) {
        return;
    }

    /* Free all cached buffers with secure cleanup
     * SECURITY: Use buffer_free_secure() to zero plaintext memory before freeing.
     * The cache contains decrypted sensitive data that must not linger in memory. */
    if (cache->cache_map) {
        hashmap_free(cache->cache_map, buffer_destroy_secure);
    }

    free(cache);
}

error_t *content_store_to_blob(
    git_repository *repo,
    const buffer_t *plaintext,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    git_oid *out_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(plaintext);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_oid);

    const unsigned char *data = (const unsigned char *) plaintext->data;
    size_t size = plaintext->size;

    buffer_t ciphertext = BUFFER_INIT;

    /* Handle encryption if requested */
    if (should_encrypt) {
        if (!keymgr) {
            return ERROR(
                ERR_CRYPTO, "Encryption requested but no keymgr provided"
            );
        }

        /* Get profile key (cached in keymgr for performance) */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
        if (err) {
            return error_wrap(
                err, "Failed to get profile key for '%s'", profile
            );
        }

        /* Encrypt */
        err = encryption_encrypt(
            data, size, profile_key, storage_path, &ciphertext
        );

        /* Clear profile key immediately (defense in depth) */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            return error_wrap(err, "Failed to encrypt '%s'", storage_path);
        }

        /* Use encrypted data */
        data = (const unsigned char *) ciphertext.data;
        size = ciphertext.size;
    }

    /* Create git blob */
    int ret = git_blob_create_from_buffer(out_oid, repo, data, size);

    /* Free ciphertext */
    buffer_free(&ciphertext);

    if (ret < 0) {
        const git_error *git_err = git_error_last();
        return ERROR(
            ERR_GIT, "Failed to create git blob: %s",
            git_err ? git_err->message : "unknown error"
        );
    }

    return NULL;
}

error_t *content_store_file_to_worktree(
    const char *filesystem_path,
    const char *worktree_path,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    struct stat *out_stat
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(worktree_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);

    /* Step 1: Validate file type (security: prevent symlink/special file confusion) */
    struct stat st;
    if (lstat(filesystem_path, &st) < 0) {
        return ERROR(
            ERR_FS, "Failed to stat '%s': %s",
            filesystem_path, strerror(errno)
        );
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

        return ERROR(
            ERR_INVALID_ARG,
            "Cannot store '%s': it is a %s, not a regular file.\n\n"
            "Dotta only manages regular configuration files.\n"
            "Symlinks and special files are not supported.", filesystem_path, type
        );
    }

    /* Step 2: Read file from filesystem
     *
     * The 100 MiB content cap lives in crypto/encryption.c as the single
     * enforcement point; the encrypt path rejects oversize input after
     * this read. For the plaintext path we rely on fs_read_file's own
     * bounds and libgit2's blob handling rather than duplicating the
     * policy here. */
    buffer_t content = BUFFER_INIT;
    error_t *err = fs_read_file(filesystem_path, &content);
    if (err) {
        return error_wrap(err, "Failed to read file '%s'", filesystem_path);
    }

    /* Step 3: Get source file's mode (preserve permissions in worktree -> git) */
    mode_t mode = st.st_mode;  /* Reuse mode from stat() above */

    /* Step 4: Encrypt if requested */
    buffer_t *data_to_write = &content;  /* Default: write plaintext */
    buffer_t ciphertext = BUFFER_INIT;

    if (should_encrypt) {
        if (!keymgr) {
            if (content.data) hydro_memzero(content.data, content.size);
            buffer_free(&content);
            return ERROR(
                ERR_CRYPTO, "Encryption requested but no keymgr provided"
            );
        }

        /* Get profile key (cached in keymgr) */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        err = keymgr_get_profile_key(keymgr, profile, profile_key);
        if (err) {
            if (content.data) hydro_memzero(content.data, content.size);
            buffer_free(&content);
            return error_wrap(
                err, "Failed to get profile key for '%s'", profile
            );
        }

        /* Encrypt */
        err = encryption_encrypt(
            (const unsigned char *) content.data,
            content.size,
            profile_key,
            storage_path,
            &ciphertext
        );

        /* Clear profile key immediately */
        hydro_memzero(profile_key, sizeof(profile_key));

        if (err) {
            if (content.data) hydro_memzero(content.data, content.size);
            buffer_free(&content);
            return error_wrap(
                err, "Failed to encrypt '%s'", storage_path
            );
        }

        /* Use encrypted data for writing */
        data_to_write = &ciphertext;
    }

    /* Step 5: Write to worktree with original mode
     * CRITICAL: Use source file's mode so git commits with correct permissions.
     * This ensures git mode matches metadata mode, preventing spurious MODE diffs. */
    err = fs_write_file_raw(
        worktree_path,
        (const unsigned char *) data_to_write->data,
        data_to_write->size,
        mode,  /* Preserve source mode */
        -1,    /* Don't change ownership */
        -1     /* Don't change ownership */
    );

    /* Cleanup (secure: plaintext may contain sensitive data) */
    if (content.data) hydro_memzero(content.data, content.size);
    buffer_free(&content);
    buffer_free(&ciphertext);

    if (err) {
        return error_wrap(
            err, "Failed to write to worktree '%s'", worktree_path
        );
    }

    return NULL;
}
