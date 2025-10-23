/**
 * content.c - Transparent content provider implementation
 *
 * See content.h for API documentation.
 */

#include "content.h"

#include <git2.h>
#include <string.h>

#include "base/encryption.h"
#include "base/error.h"
#include "core/metadata.h"
#include "hydrogen.h"
#include "utils/buffer.h"
#include "utils/hashmap.h"
#include "utils/keymanager.h"

/**
 * Content cache structure
 */
struct content_cache {
    git_repository *repo;     /* Borrowed reference */
    keymanager_t *km;         /* Borrowed reference (can be NULL) */
    hashmap_t *cache_map;     /* OID hex → buffer_t* (owned) */

    /* Statistics (for debugging and optimization) */
    size_t hits;              /* Cache hits */
    size_t misses;            /* Cache misses */
    size_t decryptions;       /* Number of decryptions performed */
};

/**
 * Get plaintext from blob (internal workhorse)
 *
 * This function handles the core logic of loading a blob and
 * transparently decrypting it if needed.
 *
 * Process:
 * 1. Check magic header for encryption
 * 2. Validate with metadata (if provided)
 * 3. Decrypt if needed
 * 4. Return plaintext buffer
 *
 * @param repo Git repository
 * @param blob Loaded git blob (must not be NULL)
 * @param storage_path File path in profile
 * @param profile_name Profile name
 * @param metadata Optional metadata for validation
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
    CHECK_NULL(out_content);

    const unsigned char *blob_data = git_blob_rawcontent(blob);
    size_t blob_size = (size_t)git_blob_rawsize(blob);

    /* Step 1: Check magic header for encryption (source of truth) */
    bool is_encrypted = encryption_is_encrypted(blob_data, blob_size);

    /* Set output flag if caller wants it */
    if (out_was_encrypted) {
        *out_was_encrypted = is_encrypted;
    }

    /* Step 2: Validate with metadata (if provided) */
    if (metadata) {
        const metadata_entry_t *meta_entry = NULL;
        error_t *err = metadata_get_entry(metadata, storage_path, &meta_entry);

        if (!err && meta_entry) {
            /* Metadata exists - cross-check with magic header */
            if (is_encrypted && !meta_entry->encrypted) {
                return ERROR(ERR_STATE_INVALID,
                    "File '%s' is encrypted in git but metadata says plaintext.\n"
                    "This indicates metadata corruption.\n"
                    "To fix, run: dotta update -p %s '%s'",
                    storage_path, profile_name, storage_path);
            }
            if (!is_encrypted && meta_entry->encrypted) {
                return ERROR(ERR_STATE_INVALID,
                    "File '%s' is marked as encrypted in metadata but stored as plaintext in git.\n"
                    "This indicates metadata corruption.\n"
                    "To fix, run: dotta update -p %s '%s'",
                    storage_path, profile_name, storage_path);
            }
        }

        if (err) {
            /* Entry not found in metadata is OK - magic header is source of truth */
            error_free(err);
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

        /* Get master key */
        uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
        error_t *err = keymanager_get_key(km, master_key);
        if (err) {
            return error_wrap(err, "Failed to get encryption key");
        }

        /* Derive profile key */
        uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
        err = encryption_derive_profile_key(master_key, profile_name, profile_key);

        /* Clear master key immediately (security) */
        hydro_memzero(master_key, sizeof(master_key));

        if (err) {
            return error_wrap(err, "Failed to derive profile key for '%s'", profile_name);
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

/* ========== Simple API Implementation ========== */

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

/* ========== Cached API Implementation ========== */

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

    cache->hits = 0;
    cache->misses = 0;
    cache->decryptions = 0;

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
    CHECK_NULL(out_content);

    /* Convert OID to hex string (cache key) */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), blob_oid);

    /* Check cache */
    buffer_t *cached_content = hashmap_get(cache->cache_map, oid_str);
    if (cached_content) {
        /* Cache hit! */
        cache->hits++;
        *out_content = cached_content;
        return NULL;
    }

    /* Cache miss - load blob and decrypt if needed */
    cache->misses++;

    /* Load blob from repository */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, cache->repo, blob_oid);
    if (git_err != 0) {
        return ERROR(ERR_NOT_FOUND, "Failed to load blob: %s", git_error_last()->message);
    }

    /* Get plaintext content with encryption tracking */
    buffer_t *content = NULL;
    bool was_encrypted = false;
    error_t *err = get_plaintext_from_blob(
        cache->repo, blob, storage_path, profile_name, metadata, cache->km,
        &content, &was_encrypted
    );

    git_blob_free(blob);

    if (err) {
        return err;
    }

    /* Update decryption stats if file was encrypted */
    if (was_encrypted) {
        cache->decryptions++;
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

void content_cache_get_stats(
    const content_cache_t *cache,
    size_t *out_hits,
    size_t *out_misses,
    size_t *out_decryptions
) {
    if (!cache) {
        return;
    }

    if (out_hits) {
        *out_hits = cache->hits;
    }
    if (out_misses) {
        *out_misses = cache->misses;
    }
    if (out_decryptions) {
        *out_decryptions = cache->decryptions;
    }
}

void content_cache_free(content_cache_t *cache) {
    if (!cache) {
        return;
    }

    /* Free all cached buffers */
    if (cache->cache_map) {
        hashmap_free(cache->cache_map, (void (*)(void *))buffer_free);
    }

    free(cache);
}
