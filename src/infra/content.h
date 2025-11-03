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
 *   content_get_from_tree_entry(repo, entry, path, profile, meta, km, &content);
 *   // ... use content ...
 *   buffer_free(content);  // Caller owns buffer
 *
 * Cached API (batch operations):
 *   content_cache_t *cache = content_cache_create(repo, km);
 *   for (each file) {
 *       const buffer_t *content;  // Note: const
 *       content_cache_get_from_tree_entry(cache, entry, path, profile, meta, &content);
 *       // ... use content (don't free - cache owns it) ...
 *   }
 *   content_cache_free(cache);  // Frees all cached buffers
 *
 * Architectural placement:
 * - Layer: Infrastructure (src/infra/)
 * - Depends on: base (encryption, gitops), utils (buffer, hashmap, keymanager)
 * - Used by: core (workspace), commands (show, diff)
 */

#ifndef DOTTA_INFRA_CONTENT_H
#define DOTTA_INFRA_CONTENT_H

#include <git2.h>
#include <sys/stat.h>

#include "types.h"

/* Forward declarations */
typedef struct keymanager keymanager_t;
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
 * Get plaintext content from tree entry
 *
 * Use for single-file operations (e.g., show command).
 * Caller owns the returned buffer and must free it.
 *
 * Process:
 * 1. Load blob from tree entry
 * 2. Check magic header for encryption
 * 3. Validate consistency with metadata
 * 4. If encrypted:
 *    a. Get master key from keymanager
 *    b. Derive profile key
 *    c. Decrypt blob
 * 5. If plaintext: return blob content
 *
 * @param repo Git repository (must not be NULL)
 * @param entry Tree entry to read (must not be NULL)
 * @param storage_path Path in profile (e.g., "home/.bashrc", must not be NULL)
 *                     SECURITY: Used as AAD in encryption. Must be actual Git tree path
 *                     (from tree traversal). Wrong path causes decrypt failure (by design).
 * @param profile_name Profile name for key derivation (must not be NULL)
 * @param metadata Metadata for validation (must not be NULL)
 * @param km Key manager (can be NULL if file is known to be plaintext)
 * @param out_content Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_CRYPTO: File is encrypted but no keymanager provided
 * - ERR_CRYPTO: Decryption failed (wrong key, corruption, or path mismatch)
 * - ERR_STATE_INVALID: Magic header and metadata disagree
 * - ERR_NOT_FOUND: Blob not found
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_get_from_tree_entry(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    buffer_t **out_content
);

/**
 * Get plaintext content from blob OID
 *
 * Lower-level variant when you have OID directly.
 * Same ownership and error semantics as content_get_from_tree_entry.
 *
 * @param repo Git repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 *                     SECURITY: Used as AAD in encryption. Must match Git tree path.
 * @param profile_name Profile name for key derivation (must not be NULL)
 * @param metadata Metadata for validation (must not be NULL)
 * @param km Key manager (can be NULL if file is known to be plaintext)
 * @param out_content Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 */
error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    buffer_t **out_content
);

/**
 * Create content cache
 *
 * Creates a cache for batch content operations.
 * Cache should live for the duration of one logical operation
 * (e.g., one status command, one workspace analysis).
 *
 * @param repo Git repository (borrowed reference, must not be NULL)
 * @param km Key manager (borrowed reference, can be NULL)
 * @return Content cache or NULL on allocation failure
 */
content_cache_t *content_cache_create(
    git_repository *repo,
    keymanager_t *km
);

/**
 * Get plaintext content from tree entry (cached)
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
 * @param entry Tree entry to read (must not be NULL)
 * @param storage_path Path in profile (must not be NULL, used as AAD for encryption)
 * @param profile_name Profile name (must not be NULL)
 * @param metadata Metadata for validation (must not be NULL)
 * @param out_content Output buffer (BORROWED - cache owns, don't free)
 * @return Error or NULL on success
 */
error_t *content_cache_get_from_tree_entry(
    content_cache_t *cache,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    const buffer_t **out_content
);

/**
 * Get plaintext content from blob OID (cached)
 *
 * Lower-level cached variant. Same semantics as content_cache_get_from_tree_entry.
 *
 * @param cache Content cache (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL, used as AAD for encryption)
 * @param profile_name Profile name (must not be NULL)
 * @param metadata Metadata for validation (must not be NULL)
 * @param out_content Output buffer (BORROWED - cache owns, don't free)
 * @return Error or NULL on success
 */
error_t *content_cache_get_from_blob_oid(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
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
 *    a. Get profile key from keymanager (uses cache for performance)
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
 * @param profile_name Profile name (for key derivation, must not be NULL)
 * @param km Key manager (for profile key derivation, can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false = plaintext)
 * @param out_oid Output OID of created blob (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_CRYPTO: Encryption requested but keymanager unavailable
 * - ERR_CRYPTO: Encryption failed
 * - ERR_GIT: Git blob creation failed
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_store_to_blob(
    git_repository *repo,
    const buffer_t *plaintext,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
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
 *    a. Get profile key from keymanager
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
 * @param profile_name Profile name (for key derivation, must not be NULL)
 * @param km Key manager (can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false = plaintext)
 * @param out_stat Output stat data from source file (optional, can be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read source file
 * - ERR_CRYPTO: Encryption requested but keymanager unavailable
 * - ERR_CRYPTO: Encryption failed
 * - ERR_IO: Failed to write worktree file
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_store_file_to_worktree(
    const char *filesystem_path,
    const char *worktree_path,
    const char *storage_path,
    const char *profile_name,
    keymanager_t *km,
    bool should_encrypt,
    struct stat *out_stat
);

/**
 * Compute content hash from filesystem file
 *
 * Computes Blake2b hash of file content with transparent decryption.
 * This is used by the virtual manifest system for divergence detection.
 *
 * Process:
 * 1. Read file from filesystem
 * 2. Detect encryption from magic header
 * 3. Decrypt if needed (transparent to caller)
 * 4. Hash plaintext content using Blake2b
 * 5. Return hex string (64 chars)
 *
 * The hash is computed over PLAINTEXT content, ensuring consistent
 * hashes regardless of encryption status. This allows the manifest
 * to detect content changes via hash comparison.
 *
 * @param filesystem_path Path to file on filesystem (must not be NULL)
 * @param storage_path Storage path in profile (must not be NULL, used for decryption AAD)
 * @param profile_name Profile name (must not be NULL, used for key derivation)
 * @param metadata Metadata for encryption detection (must not be NULL)
 * @param km Key manager for decryption (can be NULL if file is plaintext)
 * @param out_hash Output hash as hex string (must not be NULL, caller must free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read file
 * - ERR_CRYPTO: File is encrypted but no keymanager provided
 * - ERR_CRYPTO: Decryption failed
 * - ERR_MEMORY: Allocation failure
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_hash_file(
    const char *filesystem_path,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    char **out_hash
);

/**
 * Compute content hash from Git tree entry
 *
 * Computes Blake2b hash of Git blob content with transparent decryption.
 * This is the Git counterpart to content_hash_file().
 *
 * Process:
 * 1. Load blob from Git tree entry
 * 2. Detect encryption from magic header
 * 3. Decrypt if needed (transparent to caller)
 * 4. Hash plaintext content using Blake2b
 * 5. Return hex string (64 chars)
 *
 * Used by manifest operations when populating from Git (e.g., profile enable).
 *
 * @param repo Git repository (must not be NULL)
 * @param entry Tree entry to hash (must not be NULL)
 * @param storage_path Storage path in profile (must not be NULL, used for decryption AAD)
 * @param profile_name Profile name (must not be NULL, used for key derivation)
 * @param metadata Metadata for encryption detection (must not be NULL)
 * @param km Key manager for decryption (can be NULL if file is plaintext)
 * @param out_hash Output hash as hex string (must not be NULL, caller must free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_GIT: Failed to load blob
 * - ERR_CRYPTO: File is encrypted but no keymanager provided
 * - ERR_CRYPTO: Decryption failed
 * - ERR_MEMORY: Allocation failure
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_hash_from_tree_entry(
    git_repository *repo,
    const git_tree_entry *entry,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    char **out_hash
);

#endif /* DOTTA_INFRA_CONTENT_H */
