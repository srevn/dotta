/**
 * session.c - On-disk session cache implementation
 *
 * Symmetric save/load pipeline:
 *
 *   save:  build the struct (magic, version, timestamps)
 *                       → entropy_fill(nonce) → derive_cache_key(epoch) → XChaCha20
 *                       obfuscate (master XOR keystream) → MAC over [0..81) →
 *                       mode-0600 open + write + fsync
 *
 *   load:  open(O_NOFOLLOW) + fstat (mode/uid/size) → read 113 bytes
 *                       → magic + version → derive_cache_key(epoch) → MAC verify
 *                       (constant-time) → expiry (on trusted bytes) → XChaCha20
 *                       deobfuscate into out_master_key
 *
 * Both halves derive cache_key from the epoch alone, so a file is readable exactly
 * under the epoch that wrote it: the file is named by the epoch's fingerprint
 * and keyed by its bytes, and a file renamed under another epoch's name fails
 * the MAC.
 *
 * Wiping: the 113-byte struct, `cache_key` and `computed_mac` are scrubbed on
 * every exit path. `out_master_key` is scrubbed on every error path; on success
 * it carries the deobfuscated master and ownership transfers. Wipe primitive:
 * `crypto_wipe` directly (this layer already includes <monocypher.h>).
 *
 * Why unkeyed BLAKE2b for cache_key derivation: the no-keyed-BLAKE2b-outside-mac.c
 * rule governs only *keyed* BLAKE2b. cache_key is the OUTPUT of a derivation,
 * not a key into a keyed primitive; the keyed primitive is reserved for the MAC
 * step that follows.
 *
 * Why XChaCha20: the same primitive cipher.c uses, so reusing it keeps the stack's
 * primitive surface small. The nonce is drawn per file, which is what XChaCha20's
 * 24-byte nonce is for: one cache_key per epoch, and no two files under it share
 * a (key, nonce) pair.
 */

#include "crypto/session.h"

#include <errno.h>
#include <fcntl.h>
#include <monocypher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "base/encoding.h"
#include "base/error.h"
#include "crypto/kdf.h"
#include "crypto/mac.h"
#include "sys/entropy.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

/* Magic prefix: "DOTTASES" — Dotta SESsion. 8 bytes; the file is fixed-size and
 * never sniffed, so no length-byte header. */
#define SESSION_CACHE_MAGIC      "DOTTASES"
#define SESSION_CACHE_MAGIC_SIZE 8

/* Format version. Bumps invalidate prior files without migration — an unsupported
 * version surfaces as ERR_CRYPTO and is unlinked. */
#define SESSION_CACHE_VERSION    0x04

/* The directory under the invoker's home, spelled once for both paths. */
#define SESSION_CACHE_DIR        ".cache/dotta"

/* Field offsets within the on-disk layout. Named so parser and builder share
 * one source of truth.
 *
 *   bytes [0..8)     magic
 *   byte   [8]       version
 *   bytes [9..17)    created_at (LE64)
 *   bytes [17..25)   expires_at (LE64)
 *   bytes [25..49)   nonce
 *   bytes [49..81)   obfuscated_key
 *   bytes [81..113)  mac
 */
#define SESSION_OFF_MAGIC        0
#define SESSION_OFF_VERSION      8
#define SESSION_OFF_CREATED_AT   9
#define SESSION_OFF_EXPIRES_AT   17
#define SESSION_OFF_NONCE        25
#define SESSION_OFF_OBFUSCATED   49
#define SESSION_OFF_MAC          81
#define SESSION_FILE_SIZE        113

/* The XChaCha20 nonce: 24 bytes, per file. */
#define SESSION_NONCE_SIZE       24

/* Bytes covered by the MAC: the prefix before the MAC field (magic..obfuscated_key
 * inclusive). Bound to a named constant so save and load cannot accidentally
 * MAC a different range. */
#define SESSION_MAC_INPUT_SIZE   81

_Static_assert(
    SESSION_OFF_MAC == SESSION_MAC_INPUT_SIZE,
    "MAC input is the bytes [0..MAC_offset)"
);
_Static_assert(
    SESSION_OFF_MAC + CRYPTO_MAC_SIZE == SESSION_FILE_SIZE,
    "session cache file size must include the MAC"
);
_Static_assert(
    SESSION_OFF_OBFUSCATED + KDF_KEY_SIZE == SESSION_OFF_MAC,
    "obfuscated_key must butt up against the MAC"
);

/* On-disk struct mirroring the layout above. Multi-byte numerics are raw byte
 * arrays (LE-encoded via store_le64) so the on-disk bytes never depend on host
 * byte order. */
struct session_cache_file {
    uint8_t magic[8];                       /* "DOTTASES" */
    uint8_t version;                        /* SESSION_CACHE_VERSION */
    uint8_t created_at_le[8];               /* LE64 — Unix seconds, informational */
    uint8_t expires_at_le[8];               /* LE64 — Unix seconds; 0 = never */
    uint8_t nonce[SESSION_NONCE_SIZE];      /* entropy_fill; the XChaCha20 nonce */
    uint8_t obfuscated_key[KDF_KEY_SIZE];   /* master XOR keystream */
    uint8_t mac[CRYPTO_MAC_SIZE];           /* keyed BLAKE2b over [0..81) */
} __attribute__((packed));

_Static_assert(
    sizeof(struct session_cache_file) == SESSION_FILE_SIZE,
    "session_cache_file layout drift"
);
_Static_assert(
    offsetof(struct session_cache_file, mac) == SESSION_OFF_MAC,
    "MAC field offset must match SESSION_OFF_MAC"
);
_Static_assert(
    offsetof(struct session_cache_file, nonce) == SESSION_OFF_NONCE,
    "nonce offset must match SESSION_OFF_NONCE"
);

/**
 * Resolve the epoch's session file path (~/.cache/dotta/session-<fingerprint>).
 * Caller frees.
 *
 * Under the invoker's home (sys/identity) whatever the run's identity: a master
 * set without sudo lands under /home/user, and a later `sudo dotta apply` finds
 * it there rather than under /root.
 *
 * @param epoch    The epoch whose file to name
 * @param out_file File path (caller frees)
 * @return ERR_MEMORY on allocation failure
 */
static error_t *resolve_cache_path(const kdf_epoch_t *epoch, char **out_file) {
    *out_file = NULL;

    uint8_t fp[KDF_EPOCH_FP_SIZE];
    kdf_epoch_fingerprint(epoch, fp);

    char fp_hex[KDF_EPOCH_FP_SIZE * 2 + 1];
    for (size_t i = 0; i < KDF_EPOCH_FP_SIZE; i++) {
        snprintf(fp_hex + i * 2, 3, "%02x", fp[i]);
    }

    char *file = NULL;
    if (asprintf(
        &file, "%s/" SESSION_CACHE_DIR "/session-%s", identity()->home, fp_hex
        ) < 0 || !file) {
        return ERROR(ERR_MEMORY, "Failed to allocate session cache file path");
    }

    *out_file = file;
    return NULL;
}

/**
 * Derive the 32-byte cache_key from the epoch's bytes.
 *
 *     cache_key = BLAKE2b-32(salt ‖ params)
 *
 * The same 35 bytes the fingerprint hashes at length 8 (kdf_epoch_fingerprint);
 * the 32-byte output length keeps this derivation distinct from it. Both inputs
 * are fixed-width, so nothing is length-framed. Cannot fail.
 *
 * @param epoch   The epoch
 * @param out_key 32-byte output buffer (cache_key)
 */
static void derive_cache_key(
    const kdf_epoch_t *epoch,
    uint8_t out_key[CRYPTO_KEY_SIZE]
) {
    uint8_t params[KDF_PARAMS_SIZE];
    kdf_params_store(params, epoch->memory_mib, epoch->passes);

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, CRYPTO_KEY_SIZE);
    crypto_blake2b_update(&ctx, epoch->salt, KDF_SALT_SIZE);
    crypto_blake2b_update(&ctx, params, KDF_PARAMS_SIZE);
    crypto_blake2b_final(&ctx, out_key);

    /* The inputs are public; the state is scrubbed for the audit's sake, so every
     * BLAKE2b context in the crypto layer ends the same way. */
    crypto_wipe(&ctx, sizeof(ctx));
}

error_t *session_save(
    const uint8_t master_key[KDF_KEY_SIZE],
    const kdf_epoch_t *epoch,
    time_t expires_at
) {
    CHECK_NULL(master_key);
    CHECK_NULL(epoch);

    char *cache_path = NULL;
    char *cache_dir = NULL;
    int fd = -1;
    struct session_cache_file cache = { 0 };
    uint8_t cache_key[CRYPTO_KEY_SIZE] = { 0 };

    error_t *err = resolve_cache_path(epoch, &cache_path);
    if (err) {
        goto cleanup;
    }

    /* The one caller that makes the directory. Always-call form: tightens a
     * pre-existing dir with a weaker mode to 0700 instead of leaving it alone.
     * The parent ~/.cache gets the default 0755. */
    if (asprintf(&cache_dir, "%s/" SESSION_CACHE_DIR, identity()->home) < 0
        || !cache_dir) {
        err = ERROR(ERR_MEMORY, "Failed to allocate session cache dir path");
        goto cleanup;
    }
    err = fs_create_dir_with_mode(cache_dir, 0700, true);
    if (err) {
        err = error_wrap(err, "Failed to ensure session cache directory");
        goto cleanup;
    }

    /* Build the on-disk struct field by field. */
    memcpy(cache.magic, SESSION_CACHE_MAGIC, SESSION_CACHE_MAGIC_SIZE);
    cache.version = SESSION_CACHE_VERSION;
    store_le64(cache.created_at_le, (uint64_t) time(NULL));
    store_le64(cache.expires_at_le, (uint64_t) expires_at);

    /* entropy_fill scrubs the buffer to zeros on failure, so a failed draw cannot
     * leak partial random state. */
    err = entropy_fill(cache.nonce, sizeof(cache.nonce));
    if (err) {
        err = error_wrap(err, "Failed to read random bytes for session nonce");
        goto cleanup;
    }

    /* cache_key doubles as obfuscation key and MAC key; CRYPTO_DOMAIN_SESSION_MAC
     * at the MAC step keeps this MAC distinct from every other call site. */
    derive_cache_key(epoch, cache_key);

    /* Obfuscate: master XOR XChaCha20(cache_key, nonce). crypto_chacha20_x XORs
     * in one pass without a separate keystream allocation. */
    crypto_chacha20_x(
        cache.obfuscated_key, master_key, KDF_KEY_SIZE,
        cache_key, cache.nonce, /*ctr=*/ 0
    );

    /* MAC over the 81-byte struct prefix. */
    crypto_mac_oneshot(
        cache.mac, cache_key, CRYPTO_DOMAIN_SESSION_MAC,
        (const uint8_t *) &cache, SESSION_MAC_INPUT_SIZE,
        NULL, 0
    );

    /* Open with secure permissions atomically. O_NOFOLLOW guards against a symlink
     * swapping our path for a sensitive file; O_CLOEXEC matches the secure-file
     * pattern used elsewhere (see fs_write_file_raw). */
    fd = open(
        cache_path,
        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
        0600
    );
    if (fd < 0) {
        err = error_from_errno(
            errno, "Failed to create session cache file '%s'", cache_path
        );
        goto cleanup;
    }

    /* O_CREAT honors umask, which under unusual values (e.g. 0277) clears write
     * bits and produces a 0400 file the load path cannot accept. fchmod forces
     * 0600 regardless of umask. */
    if (fchmod(fd, 0600) != 0) {
        err = error_from_errno(
            errno, "Failed to set session cache file permissions"
        );
        goto cleanup;
    }

    /* Write the struct in a loop that handles EINTR and partial writes. For 113
     * bytes on a regular file the loop is in practice one iteration. */
    const uint8_t *bytes = (const uint8_t *) &cache;
    size_t off = 0;
    while (off < sizeof(cache)) {
        ssize_t n = write(fd, bytes + off, sizeof(cache) - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = error_from_errno(errno, "Failed to write session cache");
            goto cleanup;
        }
        off += (size_t) n;
    }

    /* fsync the file but not the parent dir: a half-written file cannot survive
     * a crash, and the parent-dir fsync's extra cost does not pay for itself
     * under the "save re-typing a passphrase" threat model. */
    if (fsync(fd) != 0) {
        err = error_from_errno(errno, "Failed to fsync session cache");
        goto cleanup;
    }

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    crypto_wipe(&cache, sizeof(cache));
    crypto_wipe(cache_key, sizeof(cache_key));
    free(cache_path);
    free(cache_dir);

    return err;
}

error_t *session_load(
    uint8_t out_master_key[KDF_KEY_SIZE],
    const kdf_epoch_t *epoch,
    time_t *out_expires_at
) {
    CHECK_NULL(out_master_key);
    CHECK_NULL(epoch);
    CHECK_NULL(out_expires_at);

    char *cache_path = NULL;
    int fd = -1;
    struct session_cache_file cache;
    uint8_t cache_key[CRYPTO_KEY_SIZE] = { 0 };
    uint8_t computed_mac[CRYPTO_MAC_SIZE] = { 0 };
    /* `unlink_on_fail` distinguishes ERR_FS (transient I/O — leave the file in
     * place) from ERR_CRYPTO / expired ERR_NOT_FOUND (the file is unrecoverable
     * from this build's perspective — delete it so the next call starts fresh). */
    bool unlink_on_fail = false;

    error_t *err = resolve_cache_path(epoch, &cache_path);
    if (err) {
        goto cleanup;
    }

    /* Open with O_NOFOLLOW so a symlink-swapped path returns ELOOP rather than
     * reading the unintended file. ENOENT is the "no cache yet" path — distinct
     * from ERR_FS so the caller can proceed silently. */
    fd = open(cache_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            err = ERROR(ERR_NOT_FOUND, "Session cache does not exist");
        } else {
            err = error_from_errno(
                errno, "Failed to open session cache '%s'", cache_path
            );
        }
        goto cleanup;
    }

    /* fstat against the OPENED fd (not stat against the path) closes the TOCTOU
     * window between the checks and the read: what is checked is the inode that
     * will be read. */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        err = error_from_errno(errno, "Failed to stat session cache");
        goto cleanup;
    }

    if (!S_ISREG(st.st_mode)) {
        err = ERROR(ERR_CRYPTO, "Session cache is not a regular file");
        unlink_on_fail = true;
        goto cleanup;
    }
    if ((st.st_mode & 0777) != 0600) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache has wrong permissions (got 0%o, expected 0600)",
            (unsigned) (st.st_mode & 0777)
        );
        unlink_on_fail = true;
        goto cleanup;
    }
    if (st.st_uid != identity()->uid) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache has wrong ownership (uid %u, expected %u)",
            (unsigned) st.st_uid, (unsigned) identity()->uid
        );
        unlink_on_fail = true;
        goto cleanup;
    }
    if ((uint64_t) st.st_size != (uint64_t) sizeof(cache)) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache size mismatch (got %lld, expected %zu)",
            (long long) st.st_size, sizeof(cache)
        );
        unlink_on_fail = true;
        goto cleanup;
    }

    /* Read exactly sizeof(cache) bytes, retrying on EINTR. A genuine I/O failure
     * surfaces as ERR_FS without unlink so a flaky disk does not kill the cache;
     * a short read on a file just verified to be sizeof(cache) bytes is corruption
     * (or a truncation raced between fstat and read) and unlinks. */
    uint8_t *bytes = (uint8_t *) &cache;
    size_t off = 0;
    while (off < sizeof(cache)) {
        ssize_t n = read(fd, bytes + off, sizeof(cache) - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = error_from_errno(errno, "Failed to read session cache");
            goto cleanup;
        }
        if (n == 0) {
            err = ERROR(
                ERR_CRYPTO,
                "Session cache truncated (got %zu of %zu bytes)",
                off, sizeof(cache)
            );
            unlink_on_fail = true;
            goto cleanup;
        }
        off += (size_t) n;
    }

    /* Magic + version. A version mismatch is an unloadable file (alpha policy:
     * no migration). */
    if (memcmp(
        cache.magic, SESSION_CACHE_MAGIC, SESSION_CACHE_MAGIC_SIZE
        ) != 0) {
        err = ERROR(ERR_CRYPTO, "Session cache magic mismatch");
        unlink_on_fail = true;
        goto cleanup;
    }
    if (cache.version != SESSION_CACHE_VERSION) {
        err = ERROR(
            ERR_CRYPTO,
            "Unsupported session cache version: %u "
            "(this build understands version %u)",
            (unsigned) cache.version, (unsigned) SESSION_CACHE_VERSION
        );
        unlink_on_fail = true;
        goto cleanup;
    }

    /* Recompute the MAC over the 81-byte prefix under the epoch's cache_key.
     * crypto_verify32 is constant-time. No field beyond magic and version is
     * trusted until the tag verifies. */
    derive_cache_key(epoch, cache_key);
    crypto_mac_oneshot(
        computed_mac,
        cache_key, CRYPTO_DOMAIN_SESSION_MAC,
        (const uint8_t *) &cache, SESSION_MAC_INPUT_SIZE,
        NULL, 0
    );
    if (crypto_verify32(computed_mac, cache.mac) != 0) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache MAC verification failed "
            "(tampered, or written for another repository epoch)"
        );
        unlink_on_fail = true;
        goto cleanup;
    }

    /* From here on the fields are authenticated — expires_at included. Expiry
     * after the MAC, so a flipped expiry bit surfaces as tampering, not as a
     * misleading "expired". */
    const uint64_t expires_at = load_le64(cache.expires_at_le);
    if (expires_at != 0 && (uint64_t) time(NULL) >= expires_at) {
        err = ERROR(ERR_NOT_FOUND, "Session cache expired");
        unlink_on_fail = true;
        goto cleanup;
    }

    /* Deobfuscate directly into the caller's buffer: the FINAL step, so every
     * error path above returns before out_master_key is touched. */
    crypto_chacha20_x(
        out_master_key, cache.obfuscated_key, KDF_KEY_SIZE,
        cache_key, cache.nonce, /*ctr=*/ 0
    );
    *out_expires_at = (time_t) expires_at;

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    if (err != NULL && unlink_on_fail && cache_path != NULL) {
        (void) unlink(cache_path);
    }
    crypto_wipe(&cache, sizeof(cache));
    crypto_wipe(cache_key, sizeof(cache_key));
    crypto_wipe(computed_mac, sizeof(computed_mac));
    if (err != NULL) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
    }
    free(cache_path);

    return err;
}

bool session_clear(const kdf_epoch_t *epoch) {
    char *cache_path = NULL;
    if (resolve_cache_path(epoch, &cache_path) != NULL) {
        return false;
    }

    /* Open without O_TRUNC so the existing bytes can be overwritten with zeros
     * before the unlink; O_NOFOLLOW so a symlink swap cannot make this truncate
     * an unrelated file. Best-effort throughout: any failure here falls through
     * to the unlink, which is what guarantees the file is gone. */
    int fd = open(cache_path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        const uint8_t zero_block[SESSION_FILE_SIZE] = { 0 };
        size_t off = 0;
        while (off < sizeof(zero_block)) {
            ssize_t n = write(fd, zero_block + off, sizeof(zero_block) - off);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;  /* best-effort: stop and let the unlink finish the job */
            }
            off += (size_t) n;
        }
        (void) fsync(fd);
        (void) close(fd);
    }

    const bool removed = unlink(cache_path) == 0;
    free(cache_path);
    return removed;
}
