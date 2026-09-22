/**
 * content.c - Transparent content provider implementation
 *
 * See content.h for API documentation.
 */

#include "infra/content.h"

#include <errno.h>
#include <fcntl.h>
#include <git2.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/secure.h"
#include "crypto/cipher.h"
#include "crypto/keymgr.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/**
 * Content cache structure
 */
struct content_cache {
    git_repository *repo;     /* Borrowed reference */
    keymgr *keymgr;           /* Borrowed reference (can be NULL) */
    hashmap_t *cache_map;     /* binding and mode (profile:path@oid:mode) -> buffer_t* (owned) */
};

/**
 * Securely free buffer (zero memory before release)
 *
 * SECURITY: This function zeros the buffer's memory before freeing it. Critical
 * for preventing memory disclosure of decrypted sensitive data (SSH keys, API
 * tokens, passwords, etc.) via:
 * - Swap files (if memory is paged to disk)
 * - Core dumps (crash analysis)
 * - Memory inspection tools
 * - Memory reuse by other processes
 *
 * Used by content cache to ensure plaintext doesn't linger in memory.
 *
 * The NULL-and-size test in front of the wipe is redundant — secure_wipe answers
 * a NULL pointer and a zero length itself (base/secure.h), so the wipe is total
 * without one — and is kept here and at this module's other wipes because one
 * module spells one thing one way. infra/compare states the same rule from the
 * other side and drops the test; the two are a style apart, not a disagreement
 * about what the primitive does.
 *
 * @param ptr Buffer to free (cast from void* for hashmap_free compatibility)
 */
static void buffer_destroy_secure(void *ptr) {
    buffer_t *buf = ptr;
    if (!buf) {
        return;
    }

    /* Zero sensitive plaintext data before freeing (defense in depth) */
    if (buf->data && buf->size > 0) {
        secure_wipe(buf->data, buf->size);
    }

    buffer_destroy(buf);
}

/**
 * Classify raw bytes by inspecting the cipher detection window.
 *
 * Pure computation; no I/O. Boundary handling:
 *
 * - Short blob (size < CIPHER_DETECT_BYTES) → PLAINTEXT. Real cipher blobs are
 *   at least CIPHER_OVERHEAD bytes; even a bare 5-byte "DOTTA" prefix lacks both
 *   the version byte and the SIV, so plaintext is the only safe interpretation.
 * - Magic prefix mismatch → PLAINTEXT.
 * - Magic match + current version → ENCRYPTED.
 * - Magic match + non-current version → UNSUPPORTED_VERSION.
 *
 * Indexing the version byte by `CIPHER_MAGIC_SIZE` keeps cipher's internal field
 * offsets (CIPHER_OFFSET_VERSION) opaque to this layer; the static_assert in
 * cipher.c guards their equivalence.
 */
content_kind_t content_classify_bytes(const uint8_t *data, size_t size) {
    if (!data || size < CIPHER_DETECT_BYTES) {
        return CONTENT_PLAINTEXT;
    }

    if (memcmp(data, CIPHER_MAGIC, CIPHER_MAGIC_SIZE) != 0) {
        return CONTENT_PLAINTEXT;
    }

    return data[CIPHER_MAGIC_SIZE] == CIPHER_VERSION
        ? CONTENT_ENCRYPTED
        : CONTENT_UNSUPPORTED_VERSION;
}

/**
 * The judgement every function here makes of an entry: its bytes, unless it is
 * a link — whose bytes are its target and never a seal, whatever they begin with
 * (the header). Every other mode is judged, so one dotta never writes fails closed.
 */
static content_kind_t classify_entry(
    const uint8_t *data, size_t size, git_filemode_t mode
) {
    return mode == GIT_FILEMODE_LINK
        ? CONTENT_PLAINTEXT
        : content_classify_bytes(data, size);
}

error_t *content_classify(
    git_repository *repo,
    const git_oid *blob_oid,
    git_filemode_t mode,
    content_kind_t *out_kind,
    uint8_t *out_epoch_fp
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out_kind);

    /* Loaded whatever the mode: the load is the proof the object is there. */
    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(repo, blob_oid, &view);
    if (err) {
        return error_wrap(err, "Failed to load blob for classification");
    }

    *out_kind = classify_entry((const uint8_t *) view.data, view.size, mode);

    /* Attribution rides the same parse: an ENCRYPTED verdict means the detect
     * window matched, and the fingerprint sits a few bytes further into the
     * authenticated header. cipher_read_header validates the full header, so a
     * blob long enough to classify but too short to carry the fingerprint (a
     * forged prefix) fails here instead of yielding garbage attribution. */
    if (out_epoch_fp != NULL && *out_kind == CONTENT_ENCRYPTED) {
        err = cipher_read_header(
            (const uint8_t *) view.data, view.size, out_epoch_fp
        );
    }

    gitops_blob_view_close(&view);
    return err;
}

size_t content_estimated_plaintext_size(size_t blob_size, bool encrypted) {
    /* Only a sealed blob carries the cipher's framing overhead; for anything
     * else blob_size is the only honest number. A blob of exactly the overhead
     * is an empty plaintext sealed; only a blob shorter than that — a truncated
     * one, which the cipher refuses — keeps its raw size. */
    if (!encrypted) {
        return blob_size;
    }

    return blob_size >= CIPHER_OVERHEAD ? blob_size - CIPHER_OVERHEAD
                                        : blob_size;
}

/**
 * The one line for a sealed blob met with the feature off — the read's and the
 * store's alike. ERR_LOCKED: no key is in reach at all, which is the run's fault
 * and not the blob's, and turning the feature on and setting the key is what
 * settles every such row at once. Names no path, and needs to name none: a report
 * that meets it already lists the path, and what it takes from the refusal is
 * the root's code alone — which classes the look LOCKED and puts the key in the
 * block's own closing line (core/workspace.h, workspace_fault_t).
 */
static const char ENCRYPTION_DISABLED[] =
    "Encryption is disabled (encryption.enabled = false); enable it in "
    "config.toml, then run 'dotta key set'";

/**
 * Get plaintext from blob (internal workhorse)
 *
 * Classifies the blob as its entry (classify_entry: the magic header, the single
 * source of truth for a content entry's encryption state; a link's bytes are
 * its target) and routes accordingly:
 *   - PLAINTEXT           → copy bytes
 *   - ENCRYPTED           → decrypt via keymgr
 *   - UNSUPPORTED_VERSION → ERR_CRYPTO naming the version pair
 *
 * Works on a zero-copy view, so callers must keep the backing blob alive for
 * the duration of the call.
 *
 * No external claim is consulted: the bytes carry the answer. This is the choke
 * point that makes the "metadata says encrypted but bytes say plaintext" drift
 * class structurally impossible.
 *
 * Every refusal is the ladder's shape (crypto/keymgr.h): the root names the cause
 * in one line — the keymgr's, the cipher's, or the two of this layer's own —
 * and the wrap adds the subject, "Cannot decrypt/read '<path>'". No list of
 * possible causes: the root already is the cause, and a list printed over a prompt
 * that yielded nothing or an epoch that can never match said what did not happen.
 *
 * @param blob_data Raw blob bytes (must not be NULL unless blob_size == 0)
 * @param blob_size Raw blob size in bytes
 * @param mode The entry's filemode
 * @param storage_path File path in profile (used as AAD when encrypted)
 * @param profile Profile name (used for key derivation when encrypted)
 * @param keymgr Key manager (can be NULL for plaintext files)
 * @param out_content Output buffer (caller owns)
 * @return Error or NULL on success
 */
static error_t *get_plaintext_from_blob(
    const uint8_t *blob_data, size_t blob_size, git_filemode_t mode,
    const char *storage_path, const char *profile, keymgr *keymgr,
    buffer_t *out_content
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    *out_content = (buffer_t){ 0 };

    /* Bytes are authoritative, as the entry they stand in: classify_entry is
     * total, so every blob lands in exactly one of three states regardless of
     * any external claim — a link's target in PLAINTEXT, whatever it begins
     * with. */
    content_kind_t kind = classify_entry(blob_data, blob_size, mode);

    switch (kind) {
        case CONTENT_PLAINTEXT: {
            if (blob_size > 0) {
                error_t *err = buffer_append(out_content, blob_data, blob_size);
                if (err) {
                    return error_wrap(err, "Failed to copy blob content");
                }
            }
            return NULL;
        }

        case CONTENT_ENCRYPTED: {
            if (!keymgr) {
                /* The feature off is the locked root. */
                error_t *err = ERROR(ERR_LOCKED, "%s", ENCRYPTION_DISABLED);
                return error_wrap(err, "Cannot decrypt '%s'", storage_path);
            }

            /* The keymgr's ladder decides (fetches the profile key, decrypts,
             * zeroes the key buffer; raw key material never leaves the crypto
             * layer), and its refusal is the root. */
            error_t *err = keymgr_decrypt(
                keymgr, profile, storage_path, blob_data, blob_size, out_content
            );
            if (err) {
                return error_wrap(err, "Cannot decrypt '%s'", storage_path);
            }
            return NULL;
        }

        case CONTENT_UNSUPPORTED_VERSION: {
            /* content_classify_bytes only returns this branch when blob_size is
             * large enough to carry the version byte at offset CIPHER_MAGIC_SIZE,
             * so reading it here is safe. The version pair is the root, in the
             * words the cipher's own header gate uses for the same fact. */
            error_t *err = ERROR(
                ERR_CRYPTO,
                "Unsupported encryption version 0x%02X (this build reads 0x%02X)",
                (unsigned) blob_data[CIPHER_MAGIC_SIZE], (unsigned) CIPHER_VERSION
            );
            return error_wrap(err, "Cannot read '%s'", storage_path);
        }
    }

    /* Unreachable: classify_entry returns one of three values. */
    return ERROR(
        ERR_INTERNAL,
        "Unknown content kind %d for '%s'", (int) kind, storage_path
    );
}

error_t *content_get_from_blob_oid(
    git_repository *repo,
    const git_oid *blob_oid,
    git_filemode_t mode,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    buffer_t *out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    /* get_plaintext_from_blob clears this too, but a blob that will not open
     * never reaches it. */
    *out_content = (buffer_t){ 0 };

    /* Open zero-copy view onto the blob */
    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(repo, blob_oid, &view);
    if (err) {
        return error_wrap(err, "Failed to load blob for '%s'", storage_path);
    }

    /* Get plaintext content (view bytes valid until close) */
    err = get_plaintext_from_blob(
        view.data, view.size, mode, storage_path, profile, keymgr, out_content
    );

    gitops_blob_view_close(&view);

    return err;
}

error_t *content_rebind(
    git_repository *repo,
    const git_oid *blob,
    const char *from_storage_path,
    const char *to_storage_path,
    const char *profile,
    keymgr *keymgr,
    buffer_t *out_bytes
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob);
    CHECK_NULL(from_storage_path);
    CHECK_NULL(to_storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_bytes);

    *out_bytes = (buffer_t){ 0 };

    gitops_blob_view_t view;
    error_t *err = gitops_blob_view_open(repo, blob, &view);
    if (err) {
        return error_wrap(err, "Failed to load blob for '%s'", from_storage_path);
    }

    /* Bytes are authoritative here as everywhere: only a sealed blob has a name
     * bound into it, and only it has anything to move. */
    if (content_classify_bytes((const uint8_t *) view.data, view.size)
        == CONTENT_PLAINTEXT) {
        gitops_blob_view_close(&view);
        return ERROR(
            ERR_INTERNAL, "content_rebind received unbound content at '%s'",
            from_storage_path
        );
    }

    /* A content entry by the domain (the header): a link never reaches here. */
    buffer_t plaintext = BUFFER_INIT;
    err = get_plaintext_from_blob(
        view.data, view.size, GIT_FILEMODE_BLOB, from_storage_path, profile,
        keymgr, &plaintext
    );
    gitops_blob_view_close(&view);
    if (err) {
        return err;              /* the read ladder's own words, unwrapped */
    }

    err = keymgr_encrypt(
        keymgr, profile, to_storage_path, (const uint8_t *) plaintext.data,
        plaintext.size, out_bytes
    );

    /* The plaintext ends here whichever way the seal went, as the file capture's
     * does: only the ciphertext goes on, and it is the caller's. */
    if (plaintext.data) {
        secure_wipe(plaintext.data, plaintext.size);
    }
    buffer_free(&plaintext);

    if (err) {
        return error_wrap(err, "Cannot encrypt '%s'", to_storage_path);
    }

    return NULL;
}

content_cache_t *content_cache_create(git_repository *repo, keymgr *keymgr) {
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
    git_filemode_t mode,
    const char *storage_path,
    const char *profile,
    const buffer_t **out_content
) {
    CHECK_NULL(cache);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    /* The key names the whole binding a decrypt proves — the profile whose pair
     * unseals the blob, the storage path the SIV absorbs, the blob itself — spelled
     * the way base/refspec spells a content name, the blob's OID where a commit
     * would stand. Injective: a profile name is a ref name and cannot contain
     * ':', and the OID is a fixed-width suffix. A hit is therefore an entry the
     * cipher verified for exactly this binding; a second row naming the same
     * ciphertext under another path or profile misses and runs its own decrypt,
     * which the cipher refuses. A plaintext blob shared by two rows is read twice
     * — one inflate of a dotfile; the cache exists for the decrypt.
     *
     * The entry's filemode closes the key: a link's bytes are copied where a
     * content entry's are judged, so one binding read both ways is two entries.
     * It is printed at a filemode's six octal digits, so the OID and the mode
     * are one fixed-width suffix. */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), blob_oid);

    char key[DOTTA_REFNAME_MAX + PATH_MAX + sizeof(oid_str) + sizeof(":@:000000")];
    int n = snprintf(
        key, sizeof(key), "%s:%s@%s:%06o", profile, storage_path, oid_str,
        (unsigned int) mode
    );
    if (n < 0 || (size_t) n >= sizeof(key)) {
        return ERROR(
            ERR_INVALID_ARG, "Content key too long for '%s'", storage_path
        );
    }

    buffer_t *cached_content = hashmap_get(cache->cache_map, key);
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
        view.data, view.size, mode, storage_path, profile, cache->keymgr, content
    );

    gitops_blob_view_close(&view);

    if (err) {
        buffer_destroy(content);
        return err;
    }

    /* Store in cache (cache takes ownership) */
    err = hashmap_set(cache->cache_map, key, content);
    if (err) {
        /* Fatal - cannot return borrowed reference if caching fails */
        /* Ownership contract requires cache to own the buffer */
        buffer_destroy(content);
        return error_wrap(err, "Failed to cache content for blob");
    }

    *out_content = content;

    return NULL;
}

error_t *content_compare_blob_to_disk(
    content_cache_t *cache,
    const git_oid *blob_oid,
    const char *filesystem_path,
    git_filemode_t expected_mode,
    const struct stat *st,
    const char *storage_path,
    const char *profile,
    compare_result_t *out_result
) {
    CHECK_NULL(cache);
    CHECK_NULL(blob_oid);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(st);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out_result);

    /* One read answers the kind and the bytes together: the blob is read as an
     * entry of `expected_mode` — a link's target, a plaintext blob's bytes, a
     * sealed blob's decrypt — and what this build cannot open is refused in that
     * read's own words. No proxy is consulted and none exists for this blob (the
     * header). The reader is the cache's, not its memo: a base is judged once,
     * and an entry for it would be written where nothing can ask for it. */
    buffer_t plaintext = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        cache->repo, blob_oid, expected_mode, storage_path, profile,
        cache->keymgr, &plaintext
    );

    if (!err) {
        err = compare_buffer_to_disk(
            &plaintext, filesystem_path, expected_mode, st, out_result
        );
    }

    /* The plaintext ends here whichever way the read and the verdict went — one
     * tail for every exit past the read, because a failure leaves the caller
     * whatever the callee built, a half-decrypt among them, and this module's
     * free is the wiping one (base/buffer.h's out-parameter rule; infra/compare
     * keeps the same tail over the disk copy it reads). The verdict is a value,
     * and the bytes were only ever the reference it was reached against. */
    if (plaintext.data) {
        secure_wipe(plaintext.data, plaintext.size);
    }
    buffer_free(&plaintext);

    return err;
}

void content_cache_free(content_cache_t *cache) {
    if (!cache) {
        return;
    }

    /* Free all cached buffers with secure cleanup
     * SECURITY: buffer_destroy_secure() zeroes plaintext memory before freeing.
     * The cache contains decrypted sensitive data that must not linger in
     * memory. */
    if (cache->cache_map) {
        hashmap_free(cache->cache_map, buffer_destroy_secure);
    }

    free(cache);
}

error_t *content_require_encryption(const keymgr *keymgr, const char *storage_path) {
    CHECK_NULL(storage_path);

    if (keymgr) {
        return NULL;
    }

    return error_wrap(
        ERROR(ERR_LOCKED, "%s", ENCRYPTION_DISABLED),
        "Cannot encrypt '%s'", storage_path
    );
}

error_t *content_capture_file(
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    keymgr *keymgr,
    bool should_encrypt,
    content_capture_t *out
) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* Filled once, at the end: a refusal past here leaves the cleared capture,
     * so no caller can read a look the bytes it names were never taken with. */
    *out = (content_capture_t){ 0 };

    /* The capture's twin of the read's locked root, asked before anything is
     * opened: a seal on a run with no key in reach at all. */
    if (should_encrypt) {
        RETURN_IF_ERROR(content_require_encryption(keymgr, storage_path));
    }

    /* Step 1: One look — open the descriptor whose bytes are answered
     *
     * The answered stat is the fstat of that fd, so the stat and the bytes are
     * one inode by construction; the old shape (lstat, then a path re-open inside
     * the read) let a swap between the two looks bind one file's triple to another
     * file's blob. O_NOFOLLOW refuses a symlink (a link is content_capture_link's),
     * O_NONBLOCK keeps a FIFO with no writer from wedging the open (harmless
     * for a regular file), O_CLOEXEC is hygiene. */
    int fd = fs_open(
        filesystem_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0
    );
    struct stat st;
    if (fd < 0) {
        /* A symlink refuses at the open (ELOOP), a socket refuses open outright
         * — neither leaves an fd to fstat. One diagnostic lstat lets the refusal
         * below name the type as before; it binds nothing. */
        int open_errno = errno;
        if (fs_lstat(filesystem_path, &st) != 0 || S_ISREG(st.st_mode)) {
            return error_from_errno(open_errno, "Failed to open '%s'", filesystem_path);
        }
    } else if (fstat(fd, &st) < 0) {
        int stat_errno = errno;
        close(fd);
        return error_from_errno(stat_errno, "Failed to stat '%s'", filesystem_path);
    }

    if (!S_ISREG(st.st_mode)) {
        if (fd >= 0) close(fd);

        /* This capture's own requirement, not a product rule: a symlink is
         * content_capture_link's (the header), and the walk lists one as a leaf;
         * what cannot be captured at all is a special file. */
        return ERROR(
            ERR_INVALID_ARG, "Cannot capture '%s': it is a %s, not a regular file.",
            filesystem_path, fs_stat_noun(&st)
        );
    }

    /* The entry's mode is Git's reading of the look: executable iff the owner's
     * execute bit is set (libgit2's git_index__create_mode), regular otherwise. */
    git_filemode_t mode = (st.st_mode & S_IXUSR) ? GIT_FILEMODE_BLOB_EXECUTABLE
                                                 : GIT_FILEMODE_BLOB;

    /* Step 2: Read the descriptor to EOF
     *
     * The 100 MiB content cap lives in crypto/cipher.c as the single enforcement
     * point; the encrypt path rejects oversize input after this read. For the
     * plaintext path we rely on fs_read_fd's own bounds and libgit2's blob handling
     * rather than duplicating the policy here. */
    buffer_t bytes = BUFFER_INIT;
    error_t *err = fs_read_fd(fd, &bytes);
    close(fd);
    if (err) {
        return error_wrap(err, "Failed to read file '%s'", filesystem_path);
    }

    /* Step 3: The entry's bytes — the ciphertext when encryption was asked, else
     * the file's own, unless they would read as ciphertext.
     *
     * Every reader classifies the stored bytes by their magic (content_classify:
     * bytes win over any external claim), so this is the one boundary where the
     * claim and the bytes are made to agree: an encrypt writes the magic, and a
     * plaintext whose first bytes already are the magic is refused — entered,
     * it would be stamped plaintext by the caller and read as ciphertext by every
     * reader after, and no key would open it. With the refusal, `should_encrypt`
     * is the byte truth. The plaintext a seal consumes ends in this frame; what
     * leaves under no seal is the file's own bytes, which the caller releases
     * through content_capture_free. */
    if (should_encrypt) {
        buffer_t sealed = BUFFER_INIT;
        err = keymgr_encrypt(
            keymgr, profile, storage_path, (const uint8_t *) bytes.data,
            bytes.size, &sealed
        );

        /* Unconditional, as content_rebind's is: the plaintext ends here whichever
         * way the seal went, and only the ciphertext goes on. */
        if (bytes.data) {
            secure_wipe(bytes.data, bytes.size);
        }
        buffer_free(&bytes);

        if (err) {
            buffer_free(&sealed);
            return error_wrap(err, "Cannot encrypt '%s'", storage_path);
        }

        bytes = sealed;
    } else if (content_classify_bytes((const uint8_t *) bytes.data, bytes.size)
        != CONTENT_PLAINTEXT) {
        if (bytes.data) {
            secure_wipe(bytes.data, bytes.size);
        }
        buffer_free(&bytes);
        return ERROR(
            ERR_VALIDATION,
            "Cannot capture '%s' as plaintext: its first bytes are dotta's "
            "cipher magic, so every reader would take it for ciphertext; add it "
            "with --encrypt, or change them", filesystem_path
        );
    }

    *out = (content_capture_t){
        .bytes = bytes, .mode = mode, .encrypted = should_encrypt, .st = st
    };

    return NULL;
}

error_t *content_capture_link(const char *filesystem_path, content_capture_t *out) {
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);

    /* Filled once, at the end, as the file capture is. */
    *out = (content_capture_t){ 0 };

    /* The look: what stands here, and the stat the capture keeps */
    struct stat st;
    if (fs_lstat(filesystem_path, &st) != 0) {
        return error_from_errno(errno, "Failed to stat '%s'", filesystem_path);
    }
    if (!S_ISLNK(st.st_mode)) {
        /* This capture's own requirement, as content_capture_file's is: a regular
         * file is that capture's, and what cannot be captured at all is a special
         * file. */
        return ERROR(
            ERR_INVALID_ARG, "Cannot capture '%s': it is a %s, not a symlink.",
            filesystem_path, fs_stat_noun(&st)
        );
    }

    /* The read, after the look */
    char *target = NULL;
    RETURN_IF_ERROR(fs_read_symlink(filesystem_path, &target));

    /* The same link, looked at again: another renamed over it is another inode,
     * and a new one at a freed inode carries a ctime of its own (the header). */
    struct stat again;
    if (fs_lstat(filesystem_path, &again) != 0 || again.st_dev != st.st_dev ||
        again.st_ino != st.st_ino || again.st_ctime != st.st_ctime) {
        free(target);
        return ERROR(
            ERR_CONFLICT, "Cannot capture '%s': it changed while it was read",
            filesystem_path
        );
    }

    /* The entry's bytes are the target, as read: never judged, never sealed. */
    buffer_t bytes = BUFFER_INIT;
    error_t *err = buffer_append_string(&bytes, target);
    free(target);
    if (err) {
        buffer_free(&bytes);
        return err;
    }

    *out = (content_capture_t){
        .bytes = bytes, .mode = GIT_FILEMODE_LINK, .encrypted = false, .st = st
    };

    return NULL;
}

void content_capture_free(content_capture_t *capture) {
    if (!capture) {
        return;
    }

    /* Content's rule for every buffer it releases, and nothing else: the look,
     * the mode and the verdict are values, and both callers read them past this
     * (the header). */
    if (capture->bytes.data) {
        secure_wipe(capture->bytes.data, capture->bytes.size);
    }
    buffer_free(&capture->bytes);
}
