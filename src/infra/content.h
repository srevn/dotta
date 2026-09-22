/**
 * content.h - The codec between an entry's bytes and a file's bytes
 *
 * One module for both directions of the seal, keyed by the claim the cipher binds
 * (the profile, the storage path). The read side answers a blob's plaintext,
 * classifies an entry by its bytes and compares one against disk; the write side
 * answers what a path on disk — or a sealed blob under another name — becomes
 * as an entry. Either way the encryption complexity stops here: higher layers
 * work in plaintext and name no cipher.
 *
 * Features:
 * - Transparent decryption (callers always get plaintext)
 * - Caching for batch operations (avoid redundant decryption)
 * - Type-safe ownership (const for borrowed references)
 * - Magic header is the single source of truth for a content entry's encryption
 *   state; callers do NOT pass an "expected encrypted" flag and the read path
 *   does NOT cross-check against any external claim. Bytes win. What callers do
 *   pass is the entry's filemode, which says whether the bytes are judged at
 *   all: a link's are its target, never a seal, whatever they begin with. The
 *   one function here that is handed the answer rather than reading it —
 *   content_estimated_plaintext_size, the framing taken off a size for a screen
 *   — opens nothing and routes nothing, and what it is handed is the branch's
 *   own stamp (core/metadata.h metadata_item_t), never a cross-check of these
 *   bytes.
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
 * The write side:
 *
 * Nothing here writes. Not to the object database, not to an index, not to disk:
 * every door reads — a blob, a file, a link — and answers with bytes, and the
 * caller places them. So a capture that is refused leaves the repository exactly
 * as it found it, there is no repository to place into by mistake, a dry run
 * that decides before it reads is neutral by construction, and sys/stage keeps
 * the tree's one blob writer (sys/stage.h stage_put).
 *
 * Three doors: content_capture_file and content_capture_link, a path on disk as
 * the entry it becomes; content_rebind, a sealed blob's content under a second
 * name. A link's capture holds no crypto at all and is here for content's own
 * rule — a link's bytes are its target and never a seal, whatever they begin
 * with — the same rule the classifier and the cache's key spell on the read side;
 * a capture's `encrypted` false for a link is that rule stated as a value.
 *
 * The plaintext a seal consumes never leaves this module: the encrypt runs inside
 * the capture and the plaintext is wiped there, whichever way the seal went.
 * What crosses is what the tree will hold.
 *
 * Architectural placement:
 * - Layer: Infrastructure (src/infra/)
 * - Depends on: base (buffer, hashmap, secure), sys (filesystem, gitops), crypto
 *   (cipher for the format's constants and header, keymgr for every encrypt and
 *   decrypt)
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

/* Forward declarations */
typedef struct keymgr keymgr;

/**
 * Classification of a Git blob's content kind.
 *
 * Determined by inspecting the blob's magic header, for a content entry. The
 * cipher's MAC binds the magic header into authentication, so a content entry's
 * bytes are the authoritative source of truth for its encryption state. A link's
 * bytes are its target — stored as read and never sealed (content_capture_link)
 * — so a link is PLAINTEXT whatever they begin with, and every function below
 * that answers for a blob takes the filemode of the entry it stands in. Any
 * external record (metadata.json, the view row's flag) is by definition a cache
 * that derives from byte sniffing.
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
 * Asked where the answer is a decision or a key, never where it is a screen or
 * a schedule: the store's refusal of a plaintext that reads as ciphertext makes
 * the branch's stamp true for every file dotta seals, and a screen reads that
 * stamp instead (core/metadata.h metadata_item_t). Readers: `cmds/add.c cmd_add`
 * and `cmds/update.c capture_file` (policy priority 3, where a wrong answer commits
 * a secret in the clear), `cmds/revert.c cmd_revert` (the stamp it writes, and
 * existence for every filemode), `infra/epoch.c epoch_walk_cb` (which blobs a
 * rotation must not orphan, where a false absence outlives the run). Every reader
 * is outside this module, and that is the shape rather than an accident: content's
 * own doors judge bytes they already hold (content_classify_bytes on a view,
 * classify_entry inside a read), so none of them pays a load to ask. A reader
 * not on this list is a bug.
 *
 * The price, measured rather than read off the docs: the blob is loaded whole
 * to reach six bytes, libgit2 offering no partial read of a packed object — and
 * after any `gc` or any `clone` every object is packed. So the cost is linear
 * in content bytes, and the remedy for a caller that finds it too dear is never
 * a cheaper read but a question it did not have to ask.
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
 * The bytes an entry stands for, as a screen names them.
 *
 * Wire-format containment helper: the cipher's framing overhead is a crypto-layer
 * constant, but the screens that size a branch's content want the file's number,
 * not the framing's. Centralising the subtraction here keeps crypto/cipher.h
 * imports out of the layers that ask — `cmds/list.c list_files` (the row) and
 * `core/profiles.c stats_walk_callback` (the fold the row's total must agree
 * with). A reader not on this list is a bug.
 *
 * Returns:
 *   plaintext → blob_size unchanged
 *   sealed    → blob_size minus the cipher's fixed overhead when the blob is at
 *               least that large (a blob of exactly the overhead is an empty
 *               plaintext sealed); a shorter one is truncated — the cipher refuses
 *               it — and keeps its raw size
 *
 * An estimate twice over. The stream cipher pads nothing, so for a well-formed
 * blob the body is exactly the plaintext's length; but `encrypted` is the branch's
 * own stamp rather than a reading of these bytes (core/metadata.h metadata_item_t),
 * and nothing here opens the blob to check. A hand-written sheet therefore moves
 * this number by the framing, which is a screen's worth of wrong and no more —
 * it decides no route and opens no file. A blob written under an encryption version
 * this build cannot read is stamped like any other and loses the framing here
 * too: it is a blob no reader can open at all, and its listed size is the least
 * of what is wrong with it.
 *
 * For the bytes themselves, decrypt via content_get_from_blob_oid.
 */
size_t content_estimated_plaintext_size(size_t blob_size, bool encrypted);

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
 * which it holds, the way content_capture_file refuses everything but a regular
 * file and content_capture_link everything but a link. UNSUPPORTED_VERSION is
 * refused in get_plaintext_from_blob's own words: this build cannot open the
 * bytes, so it cannot seal them under another name, and entering them under one
 * would leave a claim no key will ever read.
 *
 * A link is not content and never reaches here: its bytes are a target path,
 * and Git's filemode is the authority on that at every boundary
 * (content_capture_link, every read here — each takes the entry's filemode —
 * core/manifest.c's link row, cmds/revert.c's claim).
 *
 * The write-boundary invariant content_capture_file states holds here too: what
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
 * The single seam for "is this blob equal to this disk file?", asked of a blob
 * no stamp speaks for. One read answers the kind and the reference together:
 * the blob is read as an entry of `expected_mode` (content_get_from_blob_oid),
 * which judges its bytes and routes on them — a link's target as it stands, a
 * plaintext blob's bytes, a sealed blob's decrypt, a version this build cannot
 * read refused with the version pair — and what that read answers is the reference
 * the disk copy is judged against (infra/compare.h's pair).
 *
 * Why the bytes, and why no proxy: both callers compare against the *record's*
 * blob — core/state.h's anchor_t or released_copy_t — and neither carries an
 * encryption stamp. The view row's flag in scope is another blob's, and routing
 * the base question on it once miscategorised staleness across an encryption-policy
 * flip in both directions (the two are recorded at core/workspace.c
 * analyze_file_divergence). The row's own comparison keeps the id form and opens
 * nothing, and that asymmetry is principled rather than overlooked: the row's
 * flag is that blob's own, made byte-true at the write boundary
 * (content_capture_file), where the record's blob has no boundary at which it
 * could have been stamped.
 *
 * Why nothing is memoised: `cache` is handed in as the run's reader — its
 * repository and its key manager — and its memo is deliberately neither read
 * nor written here. An entry is keyed by the whole binding, so the key this read
 * would write is one nothing can ask for: the second question is put only when
 * the base differs from the row's blob, and an orphan's path has no row at all.
 * A base's plaintext therefore has the lifetime of one judgment and is wiped
 * and released at the end of it, the rule content_rebind keeps for the other
 * buffer this module owns. The price is one copy standing beside the disk copy
 * for the length of the comparison, where the id form held only the copy.
 *
 * The seam reads; it does not look. What the read answers is judged by
 * infra/compare.h's pair, whose one look is the caller's own, so the stat is
 * forwarded and required here for the same reason it is required there.
 *
 * Readers: `core/workspace.c analyze_file_divergence` (the second question, ours
 * against the base) and `core/workspace.c compute_orphan_divergence` (an orphan
 * against the record dotta keeps of it). A reader not on this list is a bug.
 *
 * @param cache The run's reader: its repository and its key manager (must not
 *          be NULL). The memo is neither read nor written here.
 * @param blob_oid Blob OID to compare against (must not be NULL)
 * @param filesystem_path Filesystem path to compare to (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param st The look the caller took at filesystem_path (must not be NULL)
 * @param storage_path Storage path; used as AAD when blob is encrypted (must
 *          not be NULL, must match Git tree path)
 * @param profile Profile name for key derivation when encrypted (must not be NULL)
 * @param out_result Comparison result (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors — the read's ladder, unwrapped (see content_get_from_blob_oid), or the
 * compare primitive's:
 * - ERR_LOCKED / ERR_CRYPTO: no key in reach, a blob a held key refuses, a foreign
 *   epoch, or a version this build does not read
 * - ERR_NOT_FOUND / ERR_GIT: the blob could not be loaded
 * - ERR_IO / ERR_PERMISSION: the disk copy could not be read
 * - ERR_INVALID_ARG: Required arguments are NULL
 */
error_t *content_compare_blob_to_disk(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *filesystem_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    const char *storage_path,
    const char *profile,
    compare_result_t *out_result
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
 * Returns a borrowed reference, valid until the cache is freed — the run's end
 * rather than a load's, one cache being made at dispatch and handed to every
 * reader (include/runtime.h).
 *
 * Readers, and every one of them names a view row's blob or a commit entry's,
 * never a record's: `core/workspace.c analyze_file_divergence` (the sealed arm
 * of the first question), `core/deploy.c deploy_file`, `cmds/diff.c
 * show_file_diff_from_workspace` and `cmds/diff.c
 * compare_tree_files_to_filesystem`. A reader not on this list is a bug.
 *
 * What the memo is for, named rather than assumed: one binding asked twice in
 * one run. A workspace load asks each managed path once, so a load never hits
 * itself; the hit is a second reader later in the same run — deploy taking back
 * what apply's load decrypted, the renderer taking back what its own load did.
 * A command with no second reader (status, update, sync) writes entries it will
 * not ask for, which is a memo's ordinary cost; it is the cost
 * content_compare_blob_to_disk declines for a base, whose key this list shows
 * no reader can name.
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
 * Readers: content_capture_file, before it opens anything; cmds/add.c cmd_add's
 * decision pass, before any capture has begun — so a refusal there names nothing
 * and reads nothing. Both are load-bearing and neither is the other's duplicate:
 * add asks early because its preview must refuse in the same words as its run,
 * and update has no decision pass at all, so the capture's own ask is the only
 * one on that route.
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
 * What a path on disk becomes: an entry's content, and the look it was taken at
 *
 * Everything a tree entry holds but its name, beside the stat its bytes were
 * read with. One act, because the bytes and the look are one inode: a file's
 * stat is the fstat of the descriptor its bytes came off, a link's the lstat
 * taken before its target was read and held to one link by a second.
 *
 * `mode` and `encrypted` are read off the other two — the entry's mode from the
 * look, the verdict from the bytes this module made. They are members because
 * the module that made the bytes is the one that answers for them, not to spare
 * a caller a line: update has no other producer for the verdict, and add's decision
 * pass is a policy where this is byte truth.
 *
 * The struct is the caller's — a stack local, cleared by either capture once
 * its arguments are accepted and filled once, on success — so a refused capture
 * leaves the cleared struct and freeing it is a no-op.
 *
 * One member is owned: `bytes`, which content_capture_free wipes and releases.
 * That free is the one in this tree that is not total, and the reason is that
 * the other three are values rather than resources, read by both callers past
 * it — the bytes go on the stage (bytes, mode), the claim is authored from the
 * look (core/metadata.h metadata_capture_from_file: st, encrypted) and the record
 * is bound to it (core/state.h stat_cache_from_stat: st). A free written to its
 * siblings' shape — `*capture = (content_capture_t){ 0 }`, as compare_free_diff
 * and gitops_blob_view_close are written — would leave both commands anchoring
 * a zero stat: a wrong record, with no crash.
 *
 * Readers: cmds/add.c add_file_to_stage, cmds/update.c update_profile.
 */
typedef struct {
    buffer_t bytes;        /* What the entry holds: the bytes as read, sealed as told, a link's target */
    git_filemode_t mode;   /* Git's reading of the look: BLOB, BLOB_EXECUTABLE or LINK */
    bool encrypted;        /* What `bytes` classify as, as the entry they stand in; false for a link */
    struct stat st;        /* The fstat beside a file's bytes; the lstat before a link's target */
} content_capture_t;

/**
 * Capture a regular file as the entry it becomes, encrypting it or not
 *
 * The capture add and update share: one look, read the file, seal it if asked —
 * and the bytes, the mode and the look answered to the caller, which puts the
 * entry at a name of its own.
 *
 * Process:
 * 1. Open the file, fstat the descriptor, read it to EOF — the captured stat
 *    and the captured bytes are one inode by construction
 * 2. If should_encrypt=true: a. Get profile key from keymgr b. Encrypt content
 *    c. Answer the ciphertext
 * 3. If should_encrypt=false: refuse a plaintext whose first bytes are the cipher
 *    magic, else answer the plaintext
 *
 * The entry's mode is Git's reading of the fstat: executable iff the owner's
 * execute bit is set (index.c's git_index__create_mode), regular otherwise. A
 * symlink is content_capture_link's; this capture refuses everything but a regular
 * file.
 *
 * `should_encrypt` and `keymgr` are two facts and do not collapse into one: the
 * first is the policy's verdict for this name (core/policy.h
 * encryption_policy_should_encrypt), the second is whether the run can seal at
 * all, and content_require_encryption is where they meet. Reading a NULL key
 * manager as "plaintext" would store in the clear exactly the file the policy
 * asked to seal.
 *
 * Write-time invariant: the bytes answered classify (content_classify) as
 * `encrypted` says — ENCRYPTED iff true. An encrypt writes the magic, and a
 * plaintext that would read as ciphertext is refused, so a claim stamped from
 * the answer and every reader of the bytes, which classifies them, agree for
 * any blob this capture made. The one collision the model has — a plaintext file
 * whose first six bytes happen to be `"DOTTA" || CIPHER_VERSION` — is therefore
 * refused here with its way out (--encrypt, or change the bytes), never answered
 * under a verdict every reader would contradict.
 *
 * The plaintext lives only inside this call: under a seal it is wiped before
 * the ciphertext is answered, whichever way the encrypt went. With no seal the
 * file's own bytes are the answer — headed for the object database in the clear
 * by the policy's own verdict — and content_capture_free wipes them all the same.
 *
 * @param filesystem_path Path to source file on filesystem (must not be NULL)
 * @param storage_path The name the seal binds (must not be NULL; the AAD). Under
 *          should_encrypt the caller's put MUST use this same name: the seal
 *          binds it, so bytes entered under another are a blob no key will ever
 *          open — silent at the commit, ERR_CRYPTO at every read after. That is
 *          the cost a name change has, and why content_rebind exists
 *          (crypto/cipher.h "Path binding"). Plaintext bytes carry no binding
 *          and stand at any name. The round trip is the `encrypt` suite's.
 * @param profile Profile name (for key derivation, must not be NULL)
 * @param keymgr Key manager (can be NULL if should_encrypt=false)
 * @param should_encrypt Policy decision from caller (true = encrypt, false =
 *                       plaintext)
 * @param out The capture (must not be NULL; cleared once the arguments are accepted
 *            and filled on success, so freeing it is correct either way)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_IO: Failed to read source file
 * - ERR_VALIDATION: A plaintext capture whose bytes would classify as ciphertext
 * - ERR_LOCKED: Encryption requested with the feature off (no keymgr), or the
 *   keymgr obtained no usable master — under "Cannot encrypt '<path>'"
 * - ERR_CRYPTO: Encryption failed
 * - ERR_INVALID_ARG: Required arguments are NULL, or the path is not a regular file
 */
error_t *content_capture_file(
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    content_capture_t *out
);

/**
 * Capture a symlink as the entry it becomes
 *
 * The capture's other half: a link's bytes are its target, taken as read and
 * never sealed — deploy's symlink(2) and every readlink expose the target whatever
 * the branch holds, so a secret target belongs in an encrypted regular file
 * (core/policy.h) — under GIT_FILEMODE_LINK, with `encrypted` false. It takes
 * no name, no profile and no key: everything a seal needs is a seal's, and a
 * link has no seal.
 *
 * One lstat names the occupant and is the stat the capture keeps; the target is
 * read after it. So the stat is the earlier look, which is the order the record
 * needs: a link that changes after it leaves a triple the next load cannot mistake
 * for the new one (core/state.h stat_cache_t). A second lstat then holds the
 * look and the read to one link — the same device and inode, and a ctime that
 * has not moved, since a new link at a freed inode carries its own — so the target,
 * the stat and the ownership a claim takes from it are one link's, as
 * content_capture_file's are one inode's by its descriptor. A link has no
 * descriptor to pin it, and this is the portable spelling of one. Residue,
 * accepted: a link made, read and replaced within one second, on a filesystem
 * that hands a freed inode straight back — the tree reads no sub-second field,
 * and the record's safety is the order's, not this check's.
 *
 * The capture's own refusals — not a link, or a link that changed — come before
 * anything is answered.
 *
 * @param filesystem_path The link (must not be NULL; never followed)
 * @param out The capture (must not be NULL; cleared once the arguments are accepted
 *            and filled on success, so freeing it is correct either way)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_INVALID_ARG: Required arguments are NULL, or the path is not a symlink
 * - ERR_CONFLICT: The link changed while it was read
 * - ERR_NOT_FOUND / ERR_PERMISSION / ERR_FS: The look or the read, by its errno
 *   (a target too long to read whole is ENAMETOOLONG)
 */
error_t *content_capture_link(
    const char *filesystem_path,
    content_capture_t *out
);

/**
 * Release a capture's bytes, and nothing else
 *
 * Wiped before they are released — content's rule for every buffer it hands back,
 * asked of nothing, so a reader never has to know which captures held a secret.
 * The look, the mode and the verdict are values and stay readable afterwards,
 * which is what both callers do with them (content_capture_t). Safe on a cleared
 * capture, and safe twice.
 *
 * @param capture The capture (can be NULL)
 */
void content_capture_free(content_capture_t *capture);

#endif /* DOTTA_CONTENT_H */
