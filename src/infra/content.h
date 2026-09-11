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
 * - Magic header is the single source of truth for a content entry's encryption
 *   state; callers do NOT pass an "expected encrypted" flag and the read path
 *   does NOT cross-check against any external claim. Bytes win. What callers do
 *   pass is the entry's filemode, which says whether the bytes are judged at
 *   all: a link's are its target, never a seal, whatever they begin with.
 *
 * Two-tier API:
 *
 * Simple API (single-file operations):
 *   buffer_t content = BUFFER_INIT;
 *   content_get_from_blob_oid(repo, &oid, mode, path, profile, keymgr, &content);
 *   // ... use content ...
 *   buffer_free(&content);  // Caller owns buffer
 *
 * Cached API (batch operations):
 *   content_cache_t *cache = content_cache_create(repo, keymgr);
 *   for (each file) {
 *       const buffer_t *content;  // Note: const
 *       content_cache_get_from_blob_oid(cache, &oid, mode, path, profile, &content);
 *       // ... use content (don't free - cache owns it) ...
 *   }
 *   content_cache_free(cache);  // Frees all cached buffers
 *
 * Architectural placement:
 * - Layer: Infrastructure (src/infra/)
 * - Depends on: base (buffer, hashmap, secure), sys (filesystem, gitops, stage),
 *   crypto (cipher for the format's constants and header, keymgr for every encrypt
 *   and decrypt)
 * - Used by: infra/epoch (the census classifies), core (workspace's looks, deploy's
 *   reads, policy's byte truth), commands (show, diff, export, revert, list;
 *   add and update through the two captures)
 */

#ifndef DOTTA_CONTENT_H
#define DOTTA_CONTENT_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

#include "infra/compare.h"
#include "sys/stage.h"

/* Forward declarations */
typedef struct keymgr keymgr;
typedef struct metadata metadata_t;

/**
 * Classification of a Git blob's content kind.
 *
 * Determined by inspecting the blob's magic header, for a content entry. The
 * cipher's MAC binds the magic header into authentication, so a content entry's
 * bytes are the authoritative source of truth for its encryption state. A link's
 * bytes are its target — stored as read and never sealed (content_stage_link) —
 * so a link is PLAINTEXT whatever they begin with, and every function below that
 * answers for a blob takes the filemode of the entry it stands in. Any external
 * record (metadata.json, the view row's flag) is by definition a cache that derives
 * from byte sniffing.
 *
 * Three-way discrimination matches the cipher format's contract:
 *   - CONTENT_PLAINTEXT: blob does not begin with the cipher magic prefix, or
 *                        is too short to carry one — or the entry is a link.
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
 * file just read from disk, an in-memory buffer from another layer) and want to
 * avoid a Git ODB round-trip.
 *
 * NULL-safe: data == NULL OR size < CIPHER_DETECT_BYTES → PLAINTEXT.
 *
 * @param data Raw bytes (can be NULL when size == 0)
 * @param size Byte count
 * @return Classification verdict
 */
content_kind_t content_classify_bytes(const uint8_t *data, size_t size);

/**
 * Classify a Git blob by sniffing its magic header, as the entry it stands in.
 *
 * Bytes are the authoritative source of truth for a content entry's encryption
 * state; this is the canonical entry point for the question "is this entry
 * encrypted?". Header-only inspection — no keymgr required.
 *
 * The filemode says whether the header is read at all. A link's bytes are its
 * target, so a link is PLAINTEXT whatever they begin with; every other mode is
 * judged by its bytes — the regular kinds dotta writes and any other a foreign
 * tree carries — so an unfamiliar mode fails closed, and a sealed blob under it
 * still reads as sealed. The blob is loaded whatever the mode: the load is the
 * proof the repository holds the object, which cmds/revert reads as one for every
 * filemode.
 *
 * When `out_epoch_fp` is non-NULL and the blob classifies ENCRYPTED, the header's
 * epoch fingerprint (KDF_EPOCH_FP_SIZE bytes — which repository epoch keyed this
 * ciphertext) is copied out from the same parse; a truncated header then fails
 * the call rather than yielding an unattributable fingerprint. For PLAINTEXT
 * and UNSUPPORTED_VERSION the buffer is untouched — there is no fingerprint to
 * read. Callers that only want the kind pass NULL.
 *
 * @param repo Repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param mode The entry's filemode, as its tree or index records it
 * @param out_kind Output kind on success (must not be NULL)
 * @param out_epoch_fp Optional epoch fingerprint out (KDF_EPOCH_FP_SIZE bytes;
 *          filled only for CONTENT_ENCRYPTED; can be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_GIT: Failed to load blob (corruption, missing object)
 * - ERR_CRYPTO: out_epoch_fp requested but the encrypted header is truncated
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_classify(
    git_repository *repo,
    const git_oid *blob_oid,
    git_filemode_t mode,
    content_kind_t *out_kind,
    uint8_t *out_epoch_fp
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
 *   ENCRYPTED           → blob_size minus the cipher's fixed overhead when the
 *                         blob is at least that large (a blob of exactly the
 *                         overhead is an empty plaintext sealed); a shorter one
 *                         is truncated — the cipher refuses it — and keeps its
 *                         raw size
 *   UNSUPPORTED_VERSION → blob_size unchanged. Cannot decrypt under this build,
 *                         so subtracting overhead would be a lie.
 *
 * Exact for a well-formed blob — the stream cipher pads nothing, so the body is
 * the plaintext's length — and an estimate only in that nothing here verifies
 * the blob. For the bytes themselves, decrypt via content_get_from_blob_oid.
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
 * path or profile never reads an entry the cipher did not verify for it. The
 * entry's filemode closes the key (`:mode`): a link's bytes are copied where a
 * content entry's are judged, so one binding read both ways is two entries.
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
 * 2. Classify as the entry it stands in (content_classify): a link's bytes are
 *    its target
 * 3. PLAINTEXT      → copy bytes (a link's, whatever they begin with)
 *    ENCRYPTED      → decrypt using profile key from keymgr
 *    UNSUPPORTED_VERSION → ERR_CRYPTO with version-skew diagnostic
 *
 * @param repo Git repository (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param mode The entry's filemode, as its tree or index records it
 * @param storage_path Path in profile (must not be NULL)
 *          SECURITY: Used as AAD in encryption. Must match Git tree path.
 * @param profile Profile name for key derivation (must not be NULL)
 * @param keymgr Key manager (can be NULL if file is known to be plaintext;
 *          required for ENCRYPTED blobs, returns ERR_LOCKED otherwise)
 * @param out_content Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 *
 * Errors — a failed read is the ladder's shape (crypto/keymgr.h): the root names
 * the cause in one line, and "Cannot decrypt '<path>'" / "Cannot read '<path>'"
 * wraps it; the root's code is the chain's:
 * - ERR_LOCKED: encryption is disabled, or the keymgr holds no usable master
 * - ERR_CRYPTO: a held master does not open the blob (wrong key, corruption,
 *   path mismatch), a foreign epoch, or a version this build does not read
 * - ERR_NOT_FOUND / ERR_GIT: the blob could not be loaded
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    git_filemode_t mode,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    buffer_t *out_content
);

/**
 * The bytes this blob's content takes under another name
 *
 * Encrypted bytes carry their storage path in the seal (crypto/cipher.h "Path
 * binding"), so a claim that changes name cannot carry its blob's id: no read
 * under the new name could open it. This opens the content under `from` and seals
 * it under `to` — the same plaintext, the same encryption intent, a different
 * object — and the caller stores what it gets.
 *
 * Domain: bytes that carry a binding. A blob content_classify calls PLAINTEXT
 * is refused (ERR_INTERNAL) rather than copied — an unbound blob's id travels
 * unchanged, and the caller that reads the kind for its own claim already knows
 * which it holds, the way content_stage_file refuses everything but a regular
 * file and content_stage_link everything but a link. UNSUPPORTED_VERSION is refused
 * in get_plaintext_from_blob's own words: this build cannot open the bytes, so
 * it cannot seal them under another name, and entering them under one would leave
 * a claim no key will ever read.
 *
 * A link is not content and never reaches here: its bytes are a target path,
 * and Git's filemode is the authority on that at every boundary
 * (content_stage_link's capture, every read here — each takes the entry's filemode
 * — core/manifest.c's link row, cmds/revert.c's claim).
 *
 * The write-boundary invariant content_stage_file states holds here too: what
 * is answered classifies ENCRYPTED, as the source did, so a caller stamping
 * metadata.encrypted from the source blob describes what it stores.
 *
 * The epoch does not move either, and that is the seal's doing rather than this
 * function's: the open refuses a fingerprint that is not the handle's own before
 * any key work (crypto/keymgr.h), so bytes that open here were sealed under the
 * epoch this seals them back under. A blob from another epoch is refused, never
 * re-sealed into this one.
 *
 * The plaintext lives only inside this call and is wiped on every exit path.
 *
 * @param repo Repository the blob is read from (must not be NULL)
 * @param blob The blob's id (must not be NULL)
 * @param from_storage_path The name the bytes were sealed under (must not be
 *          NULL; the AAD they are opened with)
 * @param to_storage_path The name they are sealed under (must not be NULL)
 * @param profile Profile name, for key derivation (must not be NULL)
 * @param keymgr Key manager (ERR_LOCKED without one — every blob in the domain
 *          is sealed)
 * @param out_bytes Output buffer (CALLER OWNS - must free with buffer_free)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_LOCKED / ERR_CRYPTO: the read's own ladder, unwrapped (see
 *   content_get_from_blob_oid), and the encrypt's under "Cannot encrypt '<to>'"
 * - ERR_NOT_FOUND / ERR_GIT: the blob could not be loaded
 * - ERR_INTERNAL: the blob carries no binding, so nothing here had anything to
 *   move — the caller read the wrong fact
 *
 * Reader: a revert whose name changed between the commit and the branch's tip
 * (cmds/revert.c).
 */
error_t *content_rebind(
    git_repository *repo,
    const git_oid *blob,
    const char *from_storage_path,
    const char *to_storage_path,
    const char *profile,
    keymgr *keymgr,
    buffer_t *out_bytes
);

/**
 * Compare a Git blob against a filesystem path (encryption-aware).
 *
 * The single seam for "is this blob equal to this disk file?". Internally
 * classifies the blob as an entry of `expected_mode` (content_classify) and routes:
 *   - PLAINTEXT           → fast path: stream-hash disk, compare to OID.
 *                           Avoids inflating the stored Git blob. A link always.
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
 * On first access for a given binding (profile, storage path, blob) and filemode:
 * - Loads and classifies the blob as its entry (PLAINTEXT / ENCRYPTED /
 *   UNSUPPORTED_VERSION; a link's bytes are its target, content_classify)
 * - Decrypts if needed; UNSUPPORTED_VERSION surfaces ERR_CRYPTO
 * - Stores plaintext in cache
 *
 * On subsequent access for the same binding and filemode:
 * - Returns cached buffer (O(1) lookup)
 *
 * @param cache Content cache (must not be NULL)
 * @param blob_oid Blob OID (must not be NULL)
 * @param mode The entry's filemode, as its tree or index records it
 * @param storage_path Path in profile (must not be NULL, used as AAD for
 *                     encryption)
 * @param profile Profile name (must not be NULL)
 * @param out_content Output buffer (BORROWED - cache owns, don't free)
 * @return Error or NULL on success
 */
error_t *content_cache_get_from_blob_oid(
    content_cache_t *cache,
    const git_oid *blob_oid,
    git_filemode_t mode,
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
 * Refuse a seal on a run that can never make one
 *
 * Encryption turned off leaves the run with no key manager (include/runtime.h),
 * so a seal is refused under "Cannot encrypt '<path>'" over the line the read's
 * own locked root carries (ERR_LOCKED). The subject is the run, not the path:
 * with a key manager present this answers NULL, and whether it obtains a master
 * is its ladder's question, asked at the seal, where a prompt belongs.
 *
 * Readers: content_stage_file, before it opens anything; cmds/add's decision
 * pass, before any capture has begun — so a refusal there stores nothing.
 *
 * @param keymgr The run's key manager (NULL when encryption is turned off)
 * @param storage_path The path the seal was for (must not be NULL)
 * @return ERR_LOCKED under the path, or NULL when a seal can be attempted
 */
error_t *content_require_encryption(
    const keymgr *keymgr,
    const char *storage_path
);

/**
 * Capture a regular file onto a stage, encrypting it or not
 *
 * The capture add and update share: read the file → encrypt (if asked) → the
 * entry at `storage_path` on the stage, with the mode the file's own stat says.
 *
 * Process:
 * 1. Open the file, fstat the descriptor, read it to EOF — the captured stat
 *    and the stored bytes are one inode by construction
 * 2. If should_encrypt=true: a. Get profile key from keymgr b. Encrypt content
 *    c. Stage the ciphertext
 * 3. If should_encrypt=false: refuse a plaintext whose first bytes are the cipher
 *    magic, else stage the plaintext
 *
 * The entry's mode is Git's reading of the fstat: executable iff the owner's
 * execute bit is set (index.c's git_index__create_mode), regular otherwise. A
 * symlink is content_stage_link's; this capture refuses everything but a regular
 * file. The caller still decides policy via should_encrypt; use
 * encryption_policy_should_encrypt() to compute it. Encryption asked on a run
 * with no key manager is refused before anything is opened
 * (content_require_encryption).
 *
 * Write-time invariant: the bytes staged classify (content_classify_bytes) as
 * `should_encrypt` says — ENCRYPTED iff true. An encrypt writes the magic, and
 * a plaintext that would read as ciphertext is refused, so the caller stamps
 * metadata.encrypted from `should_encrypt` and every reader, which classifies
 * the bytes, agrees with the stamp for any blob this capture wrote. The one
 * collision the model has — a plaintext file whose first six bytes happen to be
 * `"DOTTA" || CIPHER_VERSION` — is therefore refused here with its way out
 * (--encrypt, or change the bytes), never staged under a claim every reader would
 * contradict.
 *
 * @param stage The stage the entry goes on (must not be NULL)
 * @param filesystem_path Path to source file on filesystem (must not be NULL)
 * @param storage_path Storage path in profile (must not be NULL; the entry's
 *                     path, and the AAD for encryption)
 * @param profile Profile name (for key derivation, must not be NULL)
 * @param keymgr Key manager (can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false =
 *                       plaintext)
 * @param out_stat The capture's stat: the fstat of the descriptor whose bytes
 *                 were staged (must not be NULL; set on every success)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read source file
 * - ERR_VALIDATION: A plaintext capture whose bytes would classify as ciphertext
 * - ERR_LOCKED: Encryption requested with the feature off (no keymgr), or the
 *   keymgr obtained no usable master — under "Cannot encrypt '<path>'"
 * - ERR_CRYPTO: Encryption failed
 * - ERR_CONFLICT: The stage refused the entry (a file/directory collision, or a
 *   name Git will not hold)
 * - ERR_INVALID_ARG: Required arguments are NULL, or the path is not a regular file
 */
error_t *content_stage_file(
    stage_t *stage,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    struct stat *out_stat
);

/**
 * Capture a symlink onto a stage
 *
 * The capture's other half: a link's bytes are its target, stored as read and
 * never sealed — deploy's symlink(2) and every readlink expose the target whatever
 * the branch holds, so a secret target belongs in an encrypted regular file
 * (core/policy.h) — under GIT_FILEMODE_LINK.
 *
 * One lstat names the occupant and is the stat the capture keeps; the target is
 * read after it. So the stat is the earlier look, which is the order the record
 * needs: a link that changes after it leaves a triple the next load cannot mistake
 * for the new one (core/state.h stat_cache_t). A second lstat then holds the
 * look and the read to one link — the same device and inode, and a ctime that
 * has not moved, since a new link at a freed inode carries its own — so the target,
 * the stat and the ownership a claim takes from it are one link's, as
 * content_stage_file's are one inode's by its descriptor. A link has no descriptor
 * to pin it, and this is the portable spelling of one. Residue, accepted: a link
 * made, read and replaced within one second, on a filesystem that hands a freed
 * inode straight back — the tree reads no sub-second field, and the record's
 * safety is the order's, not this check's.
 *
 * The capture's own refusals — not a link, or a link that changed — come before
 * anything is staged or stored.
 *
 * @param stage The stage the entry goes on (must not be NULL)
 * @param filesystem_path The link (must not be NULL; never followed)
 * @param storage_path Storage path in profile (must not be NULL; the entry's path)
 * @param out_stat The capture's stat: the lstat taken before the target was read
 *                 (must not be NULL; set on every success)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Required arguments are NULL, or the path is not a symlink
 * - ERR_CONFLICT: The link changed while it was read, or the stage refused the
 *   entry (a file/directory collision, or a name Git will not hold)
 * - ERR_NOT_FOUND / ERR_PERMISSION / ERR_FS: The look or the read, by its errno
 *   (a target too long to read whole is ENAMETOOLONG)
 */
error_t *content_stage_link(
    stage_t *stage,
    const char *filesystem_path,
    const char *storage_path,
    struct stat *out_stat
);

#endif /* DOTTA_CONTENT_H */
