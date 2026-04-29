/**
 * session.c - On-disk session cache implementation
 *
 * Symmetric save/load pipeline:
 *
 *   save:  build struct → fill (magic, version, params, timestamps)
 *                       → entropy_fill(salt)
 *                       → derive_cache_key(salt)
 *                       → XChaCha20 obfuscate (master XOR keystream)
 *                       → MAC over [0..76) || repo_salt
 *                       → atomic-mode 0600 open + write + fsync
 *
 *   load:  open(O_NOFOLLOW) + fstat (size/mode/uid)
 *                       → read 108 bytes
 *                       → magic + version
 *                       → derive_cache_key(loaded_salt)
 *                       → MAC verify (constant-time) over [0..76) || repo_salt
 *                       → expiry check (after MAC, on trusted bytes)
 *                       → params range check
 *                       → XChaCha20 deobfuscate into out_master_key
 *
 * Both halves share `derive_cache_key`, so the absorbed byte stream
 * is identical on the same machine; a copy to another host produces
 * a different cache_key and fails MAC. The MAC also absorbs the
 * caller-supplied `repo_salt` as additional input — a cache produced
 * under repo A's salt fails MAC verification when loaded against
 * repo B's salt, defending against cross-repo cache confusion when
 * two dotta repositories share a passphrase.
 *
 * Wiping: the 108-byte struct, `cache_key`, and `computed_mac` are
 * scrubbed on every exit path. `out_master_key` is scrubbed on every
 * error path; on success it carries the deobfuscated master and
 * ownership transfers. Wipe primitive: `crypto_wipe` directly (this
 * layer already includes `<monocypher.h>`).
 *
 * Why unkeyed BLAKE2b for cache_key derivation: the no-keyed-BLAKE2b-
 * outside-mac.c rule governs only *keyed* BLAKE2b. cache_key is the
 * OUTPUT of derivation, not a key into a keyed primitive, so we use
 * monocypher's unkeyed BLAKE2b directly here; the keyed primitive is
 * reserved for the MAC step that follows.
 *
 * Why XChaCha20 (not ChaCha20): XChaCha20 is the same primitive
 * cipher.c uses, so reusing it minimises the stack's primitive
 * surface. The constant-zero 24-byte nonce is safe because cache_key
 * carries entropy via the per-file machine_salt — no two cache files
 * share a (key, nonce) pair under any non-pathological flow.
 */

#include "crypto/session.h"

#include <errno.h>
#include <fcntl.h>
#include <monocypher.h>
#include <pwd.h>
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

/* Magic prefix: "DOTTASES" — Dotta SESsion. 8 bytes; the cache is
 * fixed-size and never sniffed, so no length-byte header. */
#define SESSION_CACHE_MAGIC      "DOTTASES"
#define SESSION_CACHE_MAGIC_SIZE 8

/* Format version. Bumps invalidate prior caches without migration —
 * unsupported versions surface as ERR_CRYPTO and are unlinked.
 *
 *   0x02 → 0x03: MAC input grew to absorb the caller-supplied
 *                `repo_salt`. Old caches fail MAC under the new
 *                input shape; bumping the version surfaces the
 *                rejection as a clean format diagnostic instead. */
#define SESSION_CACHE_VERSION    0x03

/* Field offsets within the on-disk layout. Named so parser and
 * builder share one source of truth.
 *
 *   bytes [0..8)    magic
 *   byte   [8]      version
 *   bytes [9..11)   memory_mib (LE16)
 *   byte   [11]     passes
 *   bytes [12..20)  created_at (LE64)
 *   bytes [20..28)  expires_at (LE64)
 *   bytes [28..44)  machine_salt
 *   bytes [44..76)  obfuscated_key
 *   bytes [76..108) mac
 */
#define SESSION_OFF_MAGIC        0
#define SESSION_OFF_VERSION      8
#define SESSION_OFF_MEMORY_MIB   9
#define SESSION_OFF_PASSES       11
#define SESSION_OFF_CREATED_AT   12
#define SESSION_OFF_EXPIRES_AT   20
#define SESSION_OFF_MACHINE_SALT 28
#define SESSION_OFF_OBFUSCATED   44
#define SESSION_OFF_MAC          76
#define SESSION_FILE_SIZE        108

/* Bytes covered by the MAC: the prefix before the MAC field
 * (magic..obfuscated_key inclusive). Bound to a named constant so
 * save and load cannot accidentally MAC a different range. */
#define SESSION_MAC_INPUT_SIZE   76

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

/* On-disk struct mirroring the layout above. Multi-byte numerics
 * are raw byte arrays (LE-encoded via store_le16/store_le64) so the
 * on-disk bytes never depend on host byte order. */
struct session_cache_file {
    uint8_t magic[8];                       /* "DOTTASES" */
    uint8_t version;                        /* SESSION_CACHE_VERSION */
    uint8_t memory_mib_le[2];               /* LE16 — Argon2 memory params */
    uint8_t passes;                         /* Argon2 pass count */
    uint8_t created_at_le[8];               /* LE64 — Unix seconds, informational */
    uint8_t expires_at_le[8];               /* LE64 — Unix seconds; 0 = never */
    uint8_t machine_salt[16];               /* entropy_fill */
    uint8_t obfuscated_key[KDF_KEY_SIZE];   /* master XOR keystream */
    uint8_t mac[CRYPTO_MAC_SIZE];           /* keyed BLAKE2b over [0..76) */
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
    offsetof(struct session_cache_file, machine_salt)
    == SESSION_OFF_MACHINE_SALT,
    "machine_salt offset must match SESSION_OFF_MACHINE_SALT"
);

/* Hostname/username buffers for cache_key derivation. 256 is the
 * safe upper bound across platforms (HOST_NAME_MAX is 64 on Linux,
 * 255 on macOS). Username is bounded defensively.
 *
 * Truncation: `derive_cache_key` calls `strnlen(name, MAX)`, so two
 * host/user pairs whose first MAX bytes coincide produce the same
 * cache_key — pathological, and outside the local-machine threat
 * model. The lower-bound assertion catches an accidentally-tiny cap
 * that would degrade machine-binding on real systems. */
#define SESSION_HOSTNAME_BUF 256
#define SESSION_USERNAME_MAX 256

_Static_assert(
    SESSION_HOSTNAME_BUF >= 64,
    "hostname buffer must hold typical host names without truncation"
);
_Static_assert(
    SESSION_USERNAME_MAX >= 32,
    "username cap must hold typical user names without truncation"
);

/**
 * Resolve the cache file path (~/.cache/dotta/session) and its
 * parent directory. Caller frees both pointers.
 *
 * @param out_file Cache file path (caller frees)
 * @param out_dir  Parent directory path (caller frees)
 * @return ERR_FS if HOME is unset; ERR_MEMORY on allocation failure
 */
static error_t *resolve_cache_paths(char **out_file, char **out_dir) {
    *out_file = NULL;
    *out_dir = NULL;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        return ERROR(ERR_FS, "HOME environment variable not set");
    }

    char *file = NULL;
    char *dir = NULL;
    if (asprintf(&dir, "%s/.cache/dotta", home) < 0 || !dir) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate session cache dir path"
        );
    }
    if (asprintf(&file, "%s/session", dir) < 0 || !file) {
        free(dir);
        return ERROR(
            ERR_MEMORY, "Failed to allocate session cache file path"
        );
    }

    *out_file = file;
    *out_dir = dir;

    return NULL;
}

/**
 * Derive the 32-byte cache_key from the per-file salt plus the
 * host's stable identity (hostname + username).
 *
 *     cache_key = BLAKE2b(LE64(host_len) || host
 *                      || LE64(user_len) || user
 *                      || salt[16])
 *
 * Identical inputs on the same machine produce the same cache_key;
 * a copy to another host produces a different cache_key and fails
 * MAC verification.
 *
 * The salt is absorbed UNFRAMED (16 bytes verbatim, fixed-width by
 * construction); the variable-length inputs (host, user) ARE
 * LE64-prefixed so an attacker cannot construct two distinct
 * (host, user) tuples whose absorbed bytes coincide. Same fixed-
 * width carve-out that `crypto_mac_init` uses for its 8-byte tag.
 *
 * Why `getpwuid(getuid())` over `getlogin` / `getenv("USER")`:
 *   getlogin reads utmp (unreliable in containers, under sudo, with
 *   no controlling TTY); getenv is user-spoofable. getpwuid is a
 *   kernel-anchored lookup. Single-threaded, so the `_r` variant
 *   is unnecessary.
 *
 * @param salt    Per-file random salt (16 bytes)
 * @param out_key 32-byte output buffer (cache_key)
 * @return ERR_FS if hostname or username cannot be read
 */
static error_t *derive_cache_key(
    const uint8_t salt[16],
    uint8_t out_key[CRYPTO_KEY_SIZE]
) {
    error_t *err = NULL;
    char hostname[SESSION_HOSTNAME_BUF];
    crypto_blake2b_ctx ctx;

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return ERROR(ERR_FS, "Failed to read hostname: %s", strerror(errno));
    }
    /* gethostname does not guarantee NUL-termination on truncation. */
    hostname[sizeof(hostname) - 1] = '\0';
    const size_t host_len = strnlen(hostname, sizeof(hostname));

    /* getpwuid returns a pointer into static libc memory — never free
     * or wipe. errno=0 before the call distinguishes "no entry" from
     * "transient lookup failure". */
    errno = 0;
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !pw->pw_name) {
        err = ERROR(
            ERR_FS, "Failed to read username for uid %u: %s", (unsigned) getuid(),
            errno != 0 ? strerror(errno) : "no entry in password database"
        );
        goto cleanup;
    }
    const size_t user_len = strnlen(pw->pw_name, SESSION_USERNAME_MAX);

    /* LE64-prefixed BLAKE2b absorb mirroring crypto/mac.c's framing,
     * run on the unkeyed primitive (cache_key is the OUTPUT of
     * derivation, not a key into a keyed hash). */
    crypto_blake2b_init(&ctx, CRYPTO_KEY_SIZE);

    uint8_t len_le[8];
    store_le64(len_le, (uint64_t) host_len);
    crypto_blake2b_update(&ctx, len_le, sizeof(len_le));
    crypto_blake2b_update(&ctx, (const uint8_t *) hostname, host_len);

    store_le64(len_le, (uint64_t) user_len);
    crypto_blake2b_update(&ctx, len_le, sizeof(len_le));
    crypto_blake2b_update(&ctx, (const uint8_t *) pw->pw_name, user_len);

    crypto_blake2b_update(&ctx, salt, 16);
    crypto_blake2b_final(&ctx, out_key);

cleanup:
    /* Wipe the BLAKE2b state. The internal accumulator carries
     * intermediate state derived from the inputs; the inputs themselves
     * (hostname, username) are non-secret per threat model, but
     * scrubbing the state keeps the audit chokepoint legible.
     *
     * `hostname` is wiped as defense in depth — non-secret content,
     * but stack hygiene matches the rest of the crypto stack. We do
     * not touch `pw->pw_name` (libc-owned memory, untouchable). */
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(hostname, sizeof(hostname));
    return err;
}

error_t *session_save(
    const uint8_t master_key[KDF_KEY_SIZE],
    uint16_t memory_mib,
    uint8_t passes,
    const uint8_t repo_salt[KDF_SALT_SIZE],
    int32_t timeout_seconds
) {
    CHECK_NULL(master_key);
    CHECK_NULL(repo_salt);

    if (timeout_seconds == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "session_save invoked with timeout=0 (always-prompt policy "
            "must be gated by the caller before reaching session.c)"
        );
    }

    /* Defense-in-depth params validation; otherwise malformed params
     * would surface as a corrupt cache file rather than a clear error. */
    error_t *err = kdf_validate_params(memory_mib, passes);
    if (err) {
        return err;
    }

    char *cache_path = NULL;
    char *cache_dir = NULL;
    int fd = -1;
    struct session_cache_file cache = { 0 };
    uint8_t cache_key[CRYPTO_KEY_SIZE] = { 0 };

    err = resolve_cache_paths(&cache_path, &cache_dir);
    if (err) {
        goto cleanup;
    }

    /* Always-call form: tightens a pre-existing dir with weaker mode
     * to 0700 instead of leaving it alone. Parent ~/.cache gets the
     * default 0755. */
    err = fs_create_dir_with_mode(cache_dir, 0700, true);
    if (err) {
        err = error_wrap(err, "Failed to ensure session cache directory");
        goto cleanup;
    }

    /* Build the on-disk struct field by field. */
    memcpy(cache.magic, SESSION_CACHE_MAGIC, SESSION_CACHE_MAGIC_SIZE);
    cache.version = SESSION_CACHE_VERSION;
    store_le16(cache.memory_mib_le, memory_mib);
    cache.passes = passes;

    const uint64_t now_seconds = (uint64_t) time(NULL);
    store_le64(cache.created_at_le, now_seconds);
    /* timeout < 0 ("never expire") encodes as expires_at == 0; load
     * treats 0 as the never-expire sentinel. */
    const uint64_t expires_at = (timeout_seconds < 0)
        ? 0U
        : now_seconds + (uint64_t) timeout_seconds;
    store_le64(cache.expires_at_le, expires_at);

    /* entropy_fill scrubs the buffer to zeros on failure, so a
     * failed salt cannot leak partial random state. */
    err = entropy_fill(cache.machine_salt, sizeof(cache.machine_salt));
    if (err) {
        err = error_wrap(err, "Failed to read random bytes for session salt");
        goto cleanup;
    }

    /* Derive cache_key from salt + machine identity. cache_key doubles
     * as obfuscation key and MAC key; CRYPTO_DOMAIN_SESSION_MAC at
     * the MAC step keeps this MAC distinct from other call sites. */
    err = derive_cache_key(cache.machine_salt, cache_key);
    if (err) {
        goto cleanup;
    }

    /* Obfuscate: master XOR XChaCha20(cache_key, zero_nonce). The
     * constant-zero nonce is safe because cache_key already carries
     * entropy via the per-file machine_salt. crypto_chacha20_x XORs
     * in one pass without a separate keystream allocation. */
    static const uint8_t zero_nonce[24] = { 0 };
    crypto_chacha20_x(
        cache.obfuscated_key, master_key, KDF_KEY_SIZE,
        cache_key, zero_nonce, /*ctr=*/ 0
    );

    /* MAC over the 76-byte struct prefix AND the caller-supplied
     * repo_salt. Domain-tagged with CRYPTO_DOMAIN_SESSION_MAC so it
     * cannot be confused with a cipher-blob SIV under another key.
     *
     * Repo-salt binding: the salt is NOT stored in the cache file;
     * load callers re-supply it from the current repo's
     * refs/dotta/salt. A cache produced under one repo's salt fails
     * MAC verification under another repo's salt — same uniform
     * "tampered or wrong target" path the rest of the cache uses. */
    crypto_mac_oneshot(
        cache.mac, cache_key, CRYPTO_DOMAIN_SESSION_MAC,
        (const uint8_t *) &cache, SESSION_MAC_INPUT_SIZE,
        repo_salt, KDF_SALT_SIZE
    );

    /* Open with secure permissions atomically. O_NOFOLLOW guards
     * against a symlink-attack swapping our cache path with a
     * sensitive file; O_CLOEXEC matches the secure-file pattern used
     * elsewhere in the codebase (see fs_write_file_raw). */
    fd = open(
        cache_path,
        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
        0600
    );
    if (fd < 0) {
        err = ERROR(
            ERR_FS, "Failed to create session cache file '%s': %s",
            cache_path, strerror(errno)
        );
        goto cleanup;
    }

    /* O_CREAT honors umask, which under unusual values (e.g. 0277)
     * clears write bits and produces a 0400 file the load path
     * cannot accept. fchmod forces 0600 regardless of umask. */
    if (fchmod(fd, 0600) != 0) {
        err = ERROR(
            ERR_FS, "Failed to set session cache file permissions: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    /* Write the 108-byte struct in a loop that handles EINTR and
     * partial writes. For a 108-byte buffer on a regular file, the
     * loop is in practice one iteration — the loop guards against
     * pathological kernels and is cheap insurance. */
    const uint8_t *bytes = (const uint8_t *) &cache;
    size_t off = 0;
    while (off < sizeof(cache)) {
        ssize_t n = write(fd, bytes + off, sizeof(cache) - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = ERROR(
                ERR_FS, "Failed to write session cache: %s",
                strerror(errno)
            );
            goto cleanup;
        }
        off += (size_t) n;
    }

    /* fsync the file but not the parent dir: a half-written cache
     * cannot survive a crash, and the parent-dir fsync's extra cost
     * doesn't pay for itself under the "ergonomic cache, not
     * credential storage" threat model. */
    if (fsync(fd) != 0) {
        err = ERROR(
            ERR_FS, "Failed to fsync session cache: %s",
            strerror(errno)
        );
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
    uint16_t *out_memory_mib,
    uint8_t *out_passes,
    const uint8_t repo_salt[KDF_SALT_SIZE]
) {
    CHECK_NULL(out_master_key);
    CHECK_NULL(out_memory_mib);
    CHECK_NULL(out_passes);
    CHECK_NULL(repo_salt);

    char *cache_path = NULL;
    char *cache_dir = NULL;
    int fd = -1;
    struct session_cache_file cache;
    uint8_t cache_key[CRYPTO_KEY_SIZE] = { 0 };
    uint8_t computed_mac[CRYPTO_MAC_SIZE] = { 0 };
    /* `unlink_on_fail` distinguishes ERR_FS (transient I/O — leave
     * file in place) from ERR_CRYPTO / expired ERR_NOT_FOUND (the
     * file is unrecoverable from this build's perspective — delete
     * it so the next invocation starts fresh). */
    bool unlink_on_fail = false;

    error_t *err = resolve_cache_paths(&cache_path, &cache_dir);
    if (err) {
        goto cleanup;
    }

    /* Open with O_NOFOLLOW so a symlink-swapped cache path returns
     * ELOOP rather than reading the unintended file. ENOENT is the
     * "no cache yet" path — distinct from ERR_FS so the caller can
     * silently proceed to prompt without a warning. */
    fd = open(cache_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            err = ERROR(ERR_NOT_FOUND, "Session cache does not exist");
        } else {
            err = ERROR(
                ERR_FS, "Failed to open session cache '%s': %s",
                cache_path, strerror(errno)
            );
        }
        goto cleanup;
    }

    /* fstat against the OPENED fd (not stat against path) closes the
     * TOCTOU window between the permission check and the read.
     * Successful open + fstat means we're checking the inode we'll
     * read from, not whatever the path resolves to a moment later. */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        err = ERROR(
            ERR_FS, "Failed to stat session cache: %s", strerror(errno)
        );
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
    if (st.st_uid != getuid()) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache has wrong ownership (uid %u, expected %u)",
            (unsigned) st.st_uid, (unsigned) getuid()
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

    /* Read exactly sizeof(cache) bytes, retrying on EINTR. A genuine
     * I/O failure (kernel error) surfaces as ERR_FS without unlink so
     * a flaky disk doesn't kill the cache; a short read on a file we
     * just verified to be sizeof(cache) bytes indicates corruption
     * (or a race where someone truncated the file between fstat and
     * read) and unlinks. */
    uint8_t *bytes = (uint8_t *) &cache;
    size_t off = 0;
    while (off < sizeof(cache)) {
        ssize_t n = read(fd, bytes + off, sizeof(cache) - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = ERROR(
                ERR_FS, "Failed to read session cache: %s",
                strerror(errno)
            );
            /* Transient I/O — leave file in place. */
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

    /* Magic + version checks. A version mismatch is treated as an
     * unloadable file (alpha policy: no migration). */
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

    /* Derive cache_key with the (still-unauthenticated) salt. If the
     * salt has been altered, the MAC verify below fails. We do not
     * trust ANY field beyond magic/version until MAC has verified. */
    err = derive_cache_key(cache.machine_salt, cache_key);
    if (err) {
        goto cleanup;
    }

    /* Recompute MAC over the 76-byte prefix AND caller-supplied
     * repo_salt under cache_key + SESSION_MAC tag. crypto_verify32 is
     * constant-time; the comparison runs in the same number of cycles
     * regardless of how many bytes match.
     *
     * A cache from a different repo (different repo_salt) reaches
     * here with a MAC that won't verify under the current salt — the
     * unlink path handles it as any other tampered cache, and the
     * caller (keymgr) prompts fresh under the correct repo. */
    crypto_mac_oneshot(
        computed_mac,
        cache_key, CRYPTO_DOMAIN_SESSION_MAC,
        (const uint8_t *) &cache, SESSION_MAC_INPUT_SIZE,
        repo_salt, KDF_SALT_SIZE
    );
    if (crypto_verify32(computed_mac, cache.mac) != 0) {
        err = ERROR(
            ERR_CRYPTO,
            "Session cache MAC verification failed "
            "(tampered, copied from another machine, wrong user, "
            "or cache belongs to a different dotta repository)"
        );
        unlink_on_fail = true;
        goto cleanup;
    }

    /* From here on, the on-disk fields are authenticated and we can
     * trust them — including expires_at. Apply expiry AFTER MAC so an
     * attacker who flipped expiry bits surfaces as MAC failure, not
     * as a misleading "expired" diagnostic. */
    const uint64_t expires_at = load_le64(cache.expires_at_le);
    if (expires_at != 0) {
        const uint64_t now_seconds = (uint64_t) time(NULL);
        if (now_seconds >= expires_at) {
            err = ERROR(ERR_NOT_FOUND, "Session cache expired");
            unlink_on_fail = true;
            goto cleanup;
        }
    }

    /* Validate cached params: a corrupted (memory_mib, passes) pair
     * would have failed MAC, but defense in depth keeps the boundary
     * uniform with cipher_peek_params (sketch §10/I-20). */
    const uint16_t memory_mib = load_le16(cache.memory_mib_le);
    err = kdf_validate_params(memory_mib, cache.passes);
    if (err) {
        unlink_on_fail = true;
        goto cleanup;
    }

    /* Deobfuscate master_key directly into the caller's output buffer.
     * crypto_chacha20_x XORs cache.obfuscated_key with the keystream
     * and writes to out_master_key in one pass — no temporary buffer.
     * This is the FINAL step before success: any error path above
     * returns before we touch out_master_key, and the cleanup below
     * scrubs it on every error path regardless. */
    static const uint8_t zero_nonce[24] = { 0 };
    crypto_chacha20_x(
        out_master_key, cache.obfuscated_key, KDF_KEY_SIZE,
        cache_key, zero_nonce, /*ctr=*/ 0
    );

    *out_memory_mib = memory_mib;
    *out_passes = cache.passes;

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
    /* Scrub the output on every error path. See header for why this
     * loosens the sketch's "left untouched" wording. */
    if (err != NULL) {
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
    }
    free(cache_path);
    free(cache_dir);

    return err;
}

void session_clear(void) {
    char *cache_path = NULL;
    char *cache_dir = NULL;
    if (resolve_cache_paths(&cache_path, &cache_dir) != NULL) {
        free(cache_path);
        free(cache_dir);
        return;
    }

    /* Fast path: file doesn't exist, nothing to do. fs_exists guards
     * against transient ENOENT; the open below would also surface
     * ENOENT, but checking once up front lets us skip the open call
     * entirely in the common no-cache case. */
    if (!fs_exists(cache_path)) {
        free(cache_path);
        free(cache_dir);
        return;
    }

    /* Open without O_TRUNC so we can overwrite the existing bytes
     * with zeros before unlinking. O_NOFOLLOW so we cannot be tricked
     * into truncating an unrelated file via a symlink swap. Best-
     * effort throughout: any failure here falls through to unlink,
     * which is what guarantees the cache entry is gone. */
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
                break;  /* best-effort: stop and let unlink finish the job */
            }
            off += (size_t) n;
        }
        (void) fsync(fd);
        (void) close(fd);
    }

    (void) unlink(cache_path);
    free(cache_path);
    free(cache_dir);
}
