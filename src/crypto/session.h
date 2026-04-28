/**
 * session.h - On-disk session cache for the master encryption key
 *
 * Persists a 32-byte secret to ~/.cache/dotta/session between dotta
 * invocations so the user is not re-prompted within the configured
 * timeout window. Owned entirely by this module; keymgr orchestrates
 * save/load/clear but never touches the file format.
 *
 * File format (108 bytes; little-endian; fully specified in session.c):
 *
 *     magic[8]            "DOTTASES"
 *     version             SESSION_CACHE_VERSION (= 0x03)
 *     memory_mib_le[2]    LE16 — Argon2 memory params for this key
 *     passes              uint8 — Argon2 pass count
 *     created_at_le[8]    LE64 — Unix seconds, informational
 *     expires_at_le[8]    LE64 — Unix seconds; 0 = never expire
 *     machine_salt[16]    entropy_fill
 *     obfuscated_key[32]  master XOR XChaCha20(cache_key, zero_nonce)
 *     mac[32]             keyed BLAKE2b over bytes [0..76) AND repo_salt
 *
 * The cached key is bound to the Argon2 params it was derived under.
 * keymgr consults those params before installing the cached key —
 * different params yield no install, just a fresh prompt under the
 * target params.
 *
 * The cached key is ALSO bound to the per-repo Argon2id salt via the
 * MAC input: a cache produced under repo A's salt fails MAC verification
 * when loaded against repo B's salt. The salt itself is not stored in
 * the file (the caller supplies it on every save/load); binding via the
 * MAC means the consequences of a mismatch are uniform with every other
 * "wrong cache" failure (unlink + ERR_CRYPTO + fresh prompt). Without
 * this binding, two repos sharing a passphrase would silently swap
 * masters via the cache, and the failure would surface confusingly as
 * a downstream SIV "authentication failed".
 *
 * Security properties:
 *   - Obfuscated, not encrypted. The stored key is XORed with a
 *     deterministic XChaCha20 keystream keyed by
 *         BLAKE2b(LE64(host_len) || host
 *              || LE64(user_len) || user
 *              || salt[16]).
 *     A reader with file access plus hostname/username can recover
 *     the key. File mode 0600 at create time, re-verified at load.
 *   - Machine-bound. Cache_key derivation incorporates hostname and
 *     username; a copy to another host fails MAC verification.
 *   - Tamper-evident. Keyed BLAKE2b MAC over the 76-byte prefix,
 *     constant-time verified on load. Domain-separated via
 *     CRYPTO_DOMAIN_SESSION_MAC.
 *   - Time-bound. Wall-clock expiry; monotonic time would reset on
 *     reboot and defeat the persistence this module provides.
 *     keymgr's in-memory cache uses monotonic time for the
 *     anti-tamper job within a process lifetime.
 *   - Secure deletion. clear() overwrites with zeros and fsyncs
 *     before unlinking. Best-effort: raw-block recovery from the
 *     freed inode remains an attacker option on COW filesystems.
 *
 * Threat model: ergonomic caching against a passive attacker or
 * another user not targeting this machine. A determined attacker
 * with cache + machine-identity access recovers the master key —
 * this is "save re-typing a passphrase", not "credential at rest".
 *
 * Crypto-internal header. keymgr.c is the sole consumer.
 */

#ifndef DOTTA_CRYPTO_SESSION_H
#define DOTTA_CRYPTO_SESSION_H

#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"

/**
 * Persist a 32-byte secret plus its Argon2 params to the on-disk
 * session cache.
 *
 * Creates ~/.cache/dotta (mode 0700) if missing and writes the cache
 * file with mode 0600 (set at open + reasserted via fchmod against
 * umask). Content is obfuscated, MAC-tagged, and fsynced before
 * return so a crash cannot leave a half-written cache.
 *
 * The (memory_mib, passes) parameters live alongside the key so the
 * loader can decide whether the cached master matches the params the
 * caller is asking about. The 32-byte `repo_salt` is bound into the
 * MAC input — see header file overview for the cross-repo confusion
 * threat this defends against — and is NOT persisted in the file.
 *
 * @param master_key      Secret to persist (32 bytes; non-NULL)
 * @param memory_mib      Argon2 memory params (validated)
 * @param passes          Argon2 pass count (validated)
 * @param repo_salt       Per-repo Argon2id salt (32 bytes; non-NULL;
 *                        bound into MAC, not stored in the cache file)
 * @param timeout_seconds > 0: cache expires this many seconds from now;
 *                        < 0: cache never expires;
 *                        0:  caller must not invoke — always-prompt
 *                            policy is gated upstream.
 * @return NULL on success; ERR_INVALID_ARG on timeout==0 contract
 *         violation; ERR_CRYPTO on out-of-range params; ERR_FS on
 *         I/O failure; ERR_MEMORY on allocation failure.
 */
error_t *session_save(
    const uint8_t master_key[KDF_KEY_SIZE],
    uint16_t memory_mib,
    uint8_t passes,
    const uint8_t repo_salt[KDF_SALT_SIZE],
    int32_t timeout_seconds
);

/**
 * Load and decode the on-disk session cache.
 *
 * Validation order:
 *   1. regular file, mode 0600, owned by the current uid
 *   2. exactly SESSION_FILE_SIZE bytes
 *   3. magic + version
 *   4. MAC (constant-time) under cache_key derived from machine identity,
 *      with `repo_salt` absorbed as additional MAC input
 *   5. expiry (wall-clock)
 *   6. recorded Argon2 params within KDF_ARGON2_*_MIN/MAX
 *
 * MAC verification fires before expiry so trusted bytes drive the
 * comparison. File-caused failures (corruption, mismatch, expiry,
 * wrong perms) unlink the file so the next call starts fresh;
 * transient I/O failure leaves the file in place. A cache produced
 * under a different `repo_salt` fails MAC verification — same
 * unlink-and-reprompt path as any other tampered cache.
 *
 * @param out_master_key Buffer for the 32-byte secret (caller wipes
 *                       after use via crypto_wipe)
 * @param out_memory_mib Argon2 memory params (set on success only)
 * @param out_passes     Argon2 pass count (set on success only)
 * @param repo_salt      Per-repo Argon2id salt (32 bytes; non-NULL;
 *                       bound into MAC; cross-repo mismatch surfaces
 *                       as ERR_CRYPTO)
 * @return NULL on success;
 *         ERR_NOT_FOUND if missing or expired;
 *         ERR_CRYPTO for corruption / bad perms / version mismatch /
 *             MAC failure (including cross-repo cache);
 *         ERR_FS for unexpected I/O errors.
 *
 * Every error path scrubs `out_master_key` via crypto_wipe before
 * return — matches the kdf_master_key / entropy_fill contract
 * and prevents reuse of stale stack content.
 */
error_t *session_load(
    uint8_t out_master_key[KDF_KEY_SIZE],
    uint16_t *out_memory_mib,
    uint8_t *out_passes,
    const uint8_t repo_salt[KDF_SALT_SIZE]
);

/**
 * Delete the session cache.
 *
 * Best-effort secure overwrite: writes zeros across the file,
 * fflush + fsync, then unlinks. Any failure in the zero-overwrite
 * path is silent; the subsequent unlink is what guarantees the cache
 * is no longer loadable. No-op if the cache doesn't exist.
 */
void session_clear(void);

#endif /* DOTTA_CRYPTO_SESSION_H */
