/**
 * content.h - Transparent content provider with automatic decryption
 *
 * Provides unified access to git blob content with automatic decryption
 * for encrypted files. This layer abstracts away encryption complexity,
 * allowing higher-level code to work with plaintext content regardless
 * of whether files are encrypted in Git.
 *
 * Features:
 * - Transparent decryption (callers always get plaintext)
 * - Caching for batch operations (avoid redundant decryption)
 * - Type-safe ownership (const for borrowed references)
 * - Metadata validation (cross-check magic header for defense in depth)
 * - Magic header as source of truth for encryption detection
 *
 * Two-tier API:
 *
 * Simple API (single-file operations):
 *   buffer_t *content;
 *   content_get_from_blob_oid(repo, &oid, path, profile, encrypted, keymgr, &content);
 *   // ... use content ...
 *   buffer_free(content);  // Caller owns buffer
 *
 * Cached API (batch operations):
 *   content_cache_t *cache = content_cache_create(repo, keymgr);
 *   for (each file) {
 *       const buffer_t *content;  // Note: const
 *       content_cache_get_from_blob_oid(cache, &oid, path, profile, encrypted, &content);
 *       // ... use content (don't free - cache owns it) ...
 *   }
 *   content_cache_free(cache);  // Frees all cached buffers
 *
 * Architectural placement:
 * - Layer: Infrastructure (src/infra/)
 * - Depends on: base (encryption, gitops), utils (buffer, hashmap, keymgr)
 * - Used by: core (workspace), commands (show, diff)
 */

#ifndef DOTTA_CONTENT_H
#define DOTTA_CONTENT_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/* Forward declarations */
typedef struct keymgr keymgr;
typedef struct metadata metadata_t;

/**
 * Content cache (opaque)
 *
 * Caches decrypted content for the duration of an operation.
 * Provides O(1) lookup by blob OID.
 *
 * Ownership:
 * - Cache owns all buffers
 * - Callers receive borrowed references (const buffer_t*)
 * - Cache freed at end of operation (frees all buffers)
 *
 * Thread safety: Not thread-safe (dotta is single-threaded)
 */
typedef struct content_cache content_cache_t;

/**
 * Get plaintext content from blob OID
 *
 * Use for single-file operations (e.g., show command).
 * Caller owns the returned buffer and must free it.
 *
 * Process:
 * 1. Load blob from OID
 * 2. Check magic header for encryption
 * 3. Validate encryption matches expectation (defense in depth)
 * 4. If encrypted: decrypt using profile key from keymgr
 * 5. If plaintext: return blob content
 *
 * @param repo Git repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 *          SECURITY: Used as AAD in encryption. Must match Git tree path.
 * @param profile Profile name for key derivation (must not be NULL)
 * @param expected_encrypted Expected encryption state (for validation)
 * @param keymgr Key manager (can be NULL if file is known to be plaintext)
 * @param out_content Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_CRYPTO: File is encrypted but no keymgr provided
 * - ERR_CRYPTO: Decryption failed (wrong key, corruption, or path mismatch)
 * - ERR_STATE_INVALID: Magic header doesn't match expected encryption state
 * - ERR_NOT_FOUND: Blob not found
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    bool expected_encrypted,
    keymgr *keymgr,
    buffer_t *out_content
);

/**
 * Create content cache
 *
 * Creates a cache for batch content operations.
 * Cache should live for the duration of one logical operation
 * (e.g., one status command, one workspace analysis).
 *
 * @param repo Git repository (borrowed reference, must not be NULL)
 * @param keymgr Key manager (borrowed reference, can be NULL)
 * @return Content cache or NULL on allocation failure
 */
content_cache_t *content_cache_create(
    git_repository *repo,
    keymgr *keymgr
);

/**
 * Get plaintext content from blob OID (cached)
 *
 * Use for batch operations (e.g., status, workspace analysis).
 * Returns borrowed reference valid until cache is freed.
 *
 * On first access for a given blob OID:
 * - Loads and decrypts (if needed)
 * - Stores in cache
 *
 * On subsequent access for same OID:
 * - Returns cached buffer (O(1) lookup)
 *
 * @param cache Content cache (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL, used as AAD for encryption)
 * @param profile Profile name (must not be NULL)
 * @param expected_encrypted Expected encryption state (for validation)
 * @param out_content Output buffer (BORROWED - cache owns, don't free)
 * @return Error or NULL on success
 */
error_t *content_cache_get_from_blob_oid(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    bool expected_encrypted,
    const buffer_t **out_content
);

/**
 * Free content cache
 *
 * Frees cache and all cached buffers.
 * Invalidates all borrowed references returned by content_cache_get_*.
 * Safe to call with NULL.
 *
 * @param cache Content cache (can be NULL)
 */
void content_cache_free(content_cache_t *cache);

/**
 * Store buffer to git blob with optional encryption
 *
 * This is the WRITE counterpart to content_get_from_blob_oid().
 * Pure infrastructure function - caller decides policy (should_encrypt).
 *
 * Process:
 * 1. If should_encrypt=true:
 *    a. Get profile key from keymgr (uses cache for performance)
 *    b. Encrypt buffer using profile key
 *    c. Create git blob from encrypted data
 * 2. If should_encrypt=false:
 *    a. Create git blob from plaintext data directly
 * 3. Return blob OID
 *
 * This function is PURE MECHANISM - it doesn't make policy decisions.
 * The caller must use encryption_policy_should_encrypt() to determine
 * the should_encrypt parameter.
 *
 * @param repo Git repository (must not be NULL)
 * @param plaintext Plaintext buffer to store (must not be NULL)
 * @param storage_path Storage path (must not be NULL)
 *                     SECURITY: Used as AAD in encryption. Must match Git tree path.
 * @param profile Profile name (for key derivation, must not be NULL)
 * @param keymgr Key manager (for profile key derivation, can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false = plaintext)
 * @param out_oid Output OID of created blob (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_CRYPTO: Encryption requested but keymgr unavailable
 * - ERR_CRYPTO: Encryption failed
 * - ERR_GIT: Git blob creation failed
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_store_to_blob(
    git_repository *repo,
    const buffer_t *plaintext,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    git_oid *out_oid
);

/**
 * Store file to worktree with optional encryption
 *
 * High-level helper that combines: read file → encrypt (if needed) → write to worktree
 * This encapsulates the common pattern used in add/update commands.
 *
 * Process:
 * 1. Read file from filesystem and capture stat data
 * 2. If should_encrypt=true:
 *    a. Get profile key from keymgr
 *    b. Encrypt content
 *    c. Write encrypted content to worktree path
 * 3. If should_encrypt=false:
 *    a. Write plaintext content to worktree path
 *
 * This is a convenience wrapper - caller still decides policy via should_encrypt.
 * Use encryption_policy_should_encrypt() to determine the should_encrypt parameter.
 *
 * @param filesystem_path Path to source file on filesystem (must not be NULL)
 * @param worktree_path Destination path in worktree (must not be NULL)
 * @param storage_path Storage path in profile (must not be NULL, used as AAD for encryption)
 * @param profile Profile name (for key derivation, must not be NULL)
 * @param keymgr Key manager (can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false = plaintext)
 * @param out_stat Output stat data from source file (optional, can be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read source file
 * - ERR_CRYPTO: Encryption requested but keymgr unavailable
 * - ERR_CRYPTO: Encryption failed
 * - ERR_IO: Failed to write worktree file
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_store_file_to_worktree(
    const char *filesystem_path,
    const char *worktree_path,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    struct stat *out_stat
);

#endif /* DOTTA_CONTENT_H */
