/**
 * content.h - Transparent content provider with automatic decryption
 *
 * Provides unified access to git blob content with automatic decryption for
 * encrypted files. This layer abstracts away encryption complexity, allowing
 * higher-level code to work with plaintext content regardless of whether files
 * are encrypted in Git.
 *
 * Features:
 * - Transparent decryption (callers always get plaintext)
 * - Caching for batch operations (avoid redundant decryption)
 * - Type-safe ownership (const for borrowed references)
 * - Magic header is the single source of truth for encryption state; callers do
 *   NOT pass an "expected encrypted" flag and the read path does NOT cross-check
 *   against any external claim. Bytes win.
 *
 * Two-tier API:
 *
 * Simple API (single-file operations):
 *   buffer_t *content;
 *   content_get_from_blob_oid(repo, &oid, path, profile, keymgr, &content);
 *   // ... use content ...
 *   buffer_free(content);  // Caller owns buffer
 *
 * Cached API (batch operations):
 *   content_cache_t *cache = content_cache_create(repo, keymgr);
 *   for (each file) {
 *       const buffer_t *content;  // Note: const
 *       content_cache_get_from_blob_oid(cache, &oid, path, profile, &content);
 *       // ... use content (don't free - cache owns it) ...
 *   }
 *   content_cache_free(cache);  // Frees all cached buffers
 *
 * Architectural placement:
 * - Layer: Infrastructure (src/infra/)
 * - Depends on: base (buffer, hashmap, secure), sys (filesystem, gitops), crypto
 *   (cipher for the format's constants and header, keymgr for every encrypt and
 *   decrypt)
 * - Used by: infra/salt (the census classifies), core (workspace's looks, deploy's
 *   reads, policy's byte truth), commands (show, diff, export, revert, list;
 *   add and update through the store)
 */

#ifndef DOTTA_CONTENT_H
#define DOTTA_CONTENT_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

#include "infra/compare.h"

/* Forward declarations */
typedef struct keymgr keymgr;
typedef struct metadata metadata_t;

/**
 * Classification of a Git blob's content kind.
 *
 * Determined by inspecting the blob's magic header. The cipher's MAC binds the
 * magic header into authentication, so blob bytes are the authoritative source
 * of truth for encryption state. Any external record (metadata.json, the view
 * row's flag) is by definition a cache that derives from byte sniffing.
 *
 * Three-way discrimination matches the cipher format's contract:
 *   - CONTENT_PLAINTEXT: blob does not begin with the cipher magic prefix, or
 *                        is too short to carry one.
 *   - CONTENT_ENCRYPTED: blob begins with `"DOTTA" || CIPHER_VERSION`; this build
 *                        can decrypt it given the key.
 *   - CONTENT_UNSUPPORTED_VERSION: blob begins with `"DOTTA"` but the version
 *                                  byte is not the current build's. Either an
 *                                  older format or an attacker-planted forgery
 *                                  (the SIV would fail under either key).
 */
typedef enum {
    CONTENT_PLAINTEXT           = 0,
    CONTENT_ENCRYPTED           = 1,
    CONTENT_UNSUPPORTED_VERSION = 2,
} content_kind_t;

/**
 * Classify raw bytes by inspecting the cipher detection window.
 *
 * Pure computation; no I/O. Use when callers already have the bytes in hand (a
 * file just read from the worktree, an in-memory buffer from another layer) and
 * want to avoid a Git ODB round-trip.
 *
 * NULL-safe: data == NULL OR size < CIPHER_DETECT_BYTES → PLAINTEXT.
 *
 * @param data Raw bytes (can be NULL when size == 0)
 * @param size Byte count
 * @return Classification verdict
 */
content_kind_t content_classify_bytes(const uint8_t *data, size_t size);

/**
 * Classify a Git blob by sniffing its magic header.
 *
 * Bytes are the authoritative source of truth for encryption state; this is the
 * canonical entry point for the question "is this blob encrypted?". Header-only
 * inspection — no keymgr required.
 *
 * When `out_salt_fp` is non-NULL and the blob classifies ENCRYPTED, the header's
 * salt fingerprint (KDF_SALT_FP_SIZE bytes — which repository salt keyed this
 * ciphertext) is copied out from the same parse; a truncated header then fails
 * the call rather than yielding an unattributable fingerprint. For PLAINTEXT
 * and UNSUPPORTED_VERSION the buffer is untouched — there is no fingerprint to
 * read. Callers that only want the kind pass NULL.
 *
 * @param repo Repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param out_kind Output kind on success (must not be NULL)
 * @param out_salt_fp Optional salt fingerprint out (KDF_SALT_FP_SIZE bytes;
 *          filled only for CONTENT_ENCRYPTED; can be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_GIT: Failed to load blob (corruption, missing object)
 * - ERR_CRYPTO: out_salt_fp requested but the encrypted header is truncated
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_classify(
    git_repository *repo,
    const git_oid *blob_oid,
    content_kind_t *out_kind,
    uint8_t *out_salt_fp
);

/**
 * Classify a filesystem path by sniffing its first bytes.
 *
 * Reads only the cipher detection window (6 bytes today). For large files this
 * is strictly cheaper than fs_read_file + content_classify_bytes — the former
 * materialises the whole content just to inspect a header.
 *
 * Symmetric with content_classify(repo, oid): same answer, different source.
 * Pick the form whose source is closest to the caller's data.
 *
 * @param fs_path Filesystem path (must not be NULL)
 * @param out_kind Output kind on success (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_NOT_FOUND: Path does not exist
 * - ERR_FS: I/O error opening or reading
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_classify_path(
    const char *fs_path,
    content_kind_t *out_kind
);

/**
 * Estimate plaintext size for display from a classified blob.
 *
 * Wire-format containment helper: the cipher's framing overhead is a crypto-layer
 * constant, but display code in cmds/list wants a sensible size to show users.
 * Centralising the subtraction here keeps crypto/cipher.h imports out of the
 * command layer.
 *
 * Returns:
 *   PLAINTEXT           → blob_size unchanged
 *   ENCRYPTED           → blob_size minus the cipher's fixed overhead
 *                         when the blob is at least that large; otherwise blob_size
 *                         (defensive — a too-small blob would have been
 *                         misclassified upstream)
 *   UNSUPPORTED_VERSION → blob_size unchanged. Cannot decrypt under this build,
 *                         so subtracting overhead would be a lie.
 *
 * Estimate, not exact size — header-only inspection cannot know the plaintext
 * length, only bound it. For exact sizes, decrypt via content_get_from_blob_oid
 * and read the buffer length.
 */
size_t content_estimated_plaintext_size(
    content_kind_t kind, size_t blob_size
);

/**
 * Content cache (opaque)
 *
 * Caches decrypted content for the duration of an operation. An entry is the
 * proof one decrypt made for one binding — the profile whose pair unsealed the
 * blob, the storage path the SIV absorbed, and the blob — and the key names the
 * whole binding (`profile:path@oid`, the refspec grammar with the blob's OID
 * where a commit would stand), so a row naming the same ciphertext under another
 * path or profile never reads an entry the cipher did not verify for it.
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
 * Use for single-file operations (e.g., show command). Caller owns the returned
 * buffer and must free it.
 *
 * Process:
 * 1. Load blob from OID
 * 2. Classify by magic header (the authoritative source of encryption state)
 * 3. PLAINTEXT      → copy bytes
 *    ENCRYPTED      → decrypt using profile key from keymgr
 *    UNSUPPORTED_VERSION → ERR_CRYPTO with version-skew diagnostic
 *
 * @param repo Git repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 *          SECURITY: Used as AAD in encryption. Must match Git tree path.
 * @param profile Profile name for key derivation (must not be NULL)
 * @param keymgr Key manager (can be NULL if file is known to be plaintext;
 *          required for ENCRYPTED blobs, returns ERR_CRYPTO otherwise)
 * @param out_content Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_CRYPTO: File is encrypted but no keymgr provided
 * - ERR_CRYPTO: Decryption failed (wrong key, corruption, or path mismatch)
 * - ERR_CRYPTO: Blob version unsupported by this build
 * - ERR_NOT_FOUND: Blob not found
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    buffer_t *out_content
);

/**
 * Compare a Git blob against a filesystem path (encryption-aware).
 *
 * The single seam for "is this blob equal to this disk file?". Internally
 * classifies the blob by magic header and routes:
 *   - PLAINTEXT           → fast path: stream-hash disk, compare to OID.
 *                           Avoids inflating the stored Git blob.
 *   - ENCRYPTED           → slow path: decrypt via cache, byte-compare to disk.
 *   - UNSUPPORTED_VERSION → slow path; surfaces ERR_CRYPTO with a clear
 *                           version-skew message via the content reader.
 *
 * Centralizing the routing decision here eliminates the bug class where callers
 * route on a stale or wrong-blob "encrypted" flag. The fact about the blob lives
 * with the blob, not with any external proxy.
 *
 * @param repo Git repository (must not be NULL)
 * @param blob_oid Blob OID to compare against (must not be NULL)
 * @param fs_path Filesystem path to compare to (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param initial_stat Pre-captured stat to skip an lstat (can be NULL)
 * @param storage_path Storage path; used as AAD when blob is encrypted (must
 *          not be NULL, must match Git tree path)
 * @param profile Profile name for key derivation when encrypted (must not be NULL)
 * @param cache Content cache (must not be NULL; used by the encrypted route so
 *          repeated callers do not redecrypt the same blob)
 * @param out_result Comparison result (must not be NULL)
 * @param out_stat Optional stat output (can be NULL)
 * @return Error or NULL on success. Errors propagate from classification,
 *          decryption, or the underlying compare primitives.
 */
error_t *content_compare_blob_to_disk(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *fs_path,
    git_filemode_t expected_mode,
    const struct stat *initial_stat,
    const char *storage_path,
    const char *profile,
    content_cache_t *cache,
    compare_result_t *out_result,
    struct stat *out_stat
);

/**
 * Create content cache
 *
 * Creates a cache for batch content operations. Cache should live for the duration
 * of one logical operation (e.g., one status command, one workspace analysis).
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
 * Use for batch operations (e.g., status, workspace analysis). Returns borrowed
 * reference valid until cache is freed.
 *
 * On first access for a given binding (profile, storage path, blob):
 * - Loads and classifies the blob (PLAINTEXT / ENCRYPTED / UNSUPPORTED_VERSION)
 * - Decrypts if needed; UNSUPPORTED_VERSION surfaces ERR_CRYPTO
 * - Stores plaintext in cache
 *
 * On subsequent access for the same binding:
 * - Returns cached buffer (O(1) lookup)
 *
 * @param cache Content cache (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param storage_path Path in profile (must not be NULL, used as AAD for
 *                     encryption)
 * @param profile Profile name (must not be NULL)
 * @param out_content Output buffer (BORROWED - cache owns, don't free)
 * @return Error or NULL on success
 */
error_t *content_cache_get_from_blob_oid(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile,
    const buffer_t **out_content
);

/**
 * Free content cache
 *
 * Frees cache and all cached buffers. Invalidates all borrowed references returned
 * by content_cache_get_*. Safe to call with NULL.
 *
 * @param cache Content cache (can be NULL)
 */
void content_cache_free(content_cache_t *cache);

/**
 * Store file to worktree with optional encryption
 *
 * High-level helper that combines: read file → encrypt (if needed) → write to
 * worktree. This encapsulates the common pattern used in add/update commands.
 *
 * Process:
 * 1. Open the file, fstat the descriptor, read it to EOF — the captured stat
 *    and the stored bytes are one inode by construction
 * 2. If should_encrypt=true: a. Get profile key from keymgr b. Encrypt content
 *    c. Write encrypted content to worktree path
 * 3. If should_encrypt=false: refuse a plaintext whose first bytes are the cipher
 *    magic, else write the plaintext to the worktree path
 *
 * This is a convenience wrapper — the caller still decides policy via
 * should_encrypt; use encryption_policy_should_encrypt() to compute it.
 *
 * Write-time invariant: the bytes stored classify (content_classify_bytes) as
 * `should_encrypt` says — ENCRYPTED iff true. An encrypt writes the magic, and
 * a plaintext that would read as ciphertext is refused, so the caller stamps
 * metadata.encrypted from `should_encrypt` and every reader, which classifies
 * the bytes, agrees with the stamp for any blob this store wrote. The one collision
 * the model has — a plaintext file whose first six bytes happen to be `"DOTTA"
 * || CIPHER_VERSION` — is therefore refused here with its way out (--encrypt,
 * or change the bytes), never stored under a claim every reader would contradict.
 *
 * @param filesystem_path Path to source file on filesystem (must not be NULL)
 * @param worktree_path Destination path in worktree (must not be NULL)
 * @param storage_path Storage path in profile (must not be NULL, used as AAD
 *                     for encryption)
 * @param profile Profile name (for key derivation, must not be NULL)
 * @param keymgr Key manager (can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false =
 *                       plaintext)
 * @param out_stat The capture's stat: the fstat of the descriptor whose bytes
 *                 were stored (optional, can be NULL; filled only when the look
 *                 reached a regular file's fd)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read source file
 * - ERR_VALIDATION: A plaintext store whose bytes would classify as ciphertext
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
