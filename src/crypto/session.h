/**
 * session.h — On-disk session cache for the master encryption key
 *
 * Persists a 32-byte secret to ~/.cache/dotta/session between dotta
 * invocations so the user is not re-prompted for every command within
 * a configured timeout window. The cache is owned entirely by this
 * module; the keymgr orchestrates save/load/clear but never touches
 * the file format or its derivation inputs.
 *
 * File format (108 bytes total, fully specified in session.c):
 *     magic | version | created_at | expires_at | salt | xor(key,stream) | mac
 *
 * Security properties:
 *   - Obfuscated, not encrypted. The stored key is XORed with a
 *     deterministic stream derived from hash(hostname || username ||
 *     salt). An attacker with file read access plus knowledge of the
 *     host's hostname and username can recover the key. File
 *     permissions are set to 0600 (owner-only) at create time and
 *     re-verified at load time; mismatched modes trigger forced
 *     unlink + re-prompt.
 *   - Machine-bound. The derivation above yields a different stream
 *     on any other machine; a cache copied to another host fails MAC
 *     verification and is discarded.
 *   - Tamper-evident. BLAKE2-keyed MAC over (timestamps, salt, XORed
 *     key), verified with constant-time compare on load.
 *   - Time-bound. The cache records wall-clock expiry. Monotonic time
 *     would reset on reboot and defeat the persistence this module
 *     provides; the in-memory cache (in keymgr.c) uses monotonic time
 *     for anti-tamper within a process lifetime.
 *   - Secure deletion. clear() overwrites the file with zeros and
 *     fsyncs before unlinking, so the original bytes leave disk
 *     before the directory entry goes away.
 *
 * Threat model: this module defends ergonomic session caching against
 * a passive attacker or another user on the system who is not
 * actively targeting this machine. A determined attacker with read
 * access to ~/.cache/dotta/session plus hostname/username knowledge
 * can recover the master key. This is appropriate for "save the user
 * from re-typing a passphrase every invocation", not for storing a
 * credential at rest.
 *
 * This header lives in src/crypto/ and is crypto-internal. No module
 * outside src/crypto/ should include it; keymgr.c is the sole
 * consumer.
 */

#ifndef DOTTA_SESSION_H
#define DOTTA_SESSION_H

#include <stdint.h>
#include <types.h>

/**
 * Persist a 32-byte secret to the on-disk session cache.
 *
 * Creates ~/.cache/dotta (mode 0700) if missing and writes the cache
 * file with mode 0600. The content is obfuscated with a machine-bound
 * stream, tagged with a keyed MAC, and fsynced to disk before return
 * so a subsequent crash cannot leave a half-written cache.
 *
 * @param key              Secret to persist (32 bytes)
 * @param timeout_seconds  > 0: cache expires this many seconds from
 *                              now (wall-clock).
 *                         < 0: cache never expires.
 *                           0: caller must not invoke — the "always
 *                              prompt" policy is gated by the caller
 *                              before reaching this function.
 * @return NULL on success; ERR_FS for I/O failures; ERR_MEMORY for
 *         allocation failures; ERR_CRYPTO for primitive failures.
 */
error_t *session_save(
    const uint8_t key[32],
    int32_t timeout_seconds
);

/**
 * Load and decode the on-disk session cache.
 *
 * Reads ~/.cache/dotta/session, verifies mode (0600), magic, version,
 * expiry (wall-clock), and MAC. On any failure the file is unlinked
 * so the next call starts fresh.
 *
 * @param out_key Buffer for the 32-byte secret (pre-allocated).
 * @return NULL on successful load;
 *         ERR_NOT_FOUND if the file is missing or expired (caller
 *             treats as "no cache" and proceeds to prompt);
 *         ERR_CRYPTO for corruption / bad permissions / version
 *             mismatch / MAC failure (also fall-through to prompt,
 *             but distinct so logs can explain why);
 *         ERR_FS for unexpected I/O errors (caller warns, proceeds
 *             to prompt; in-memory cache remains authoritative).
 */
error_t *session_load(uint8_t out_key[32]);

/**
 * Delete the session cache.
 *
 * Best-effort secure overwrite: writes zeros across the file,
 * fflush + fsync, then unlinks. Any failure in the zero-overwrite
 * path is silent; the subsequent unlink is what guarantees the
 * cache is no longer loadable. No-op if the cache doesn't exist.
 */
void session_clear(void);

#endif /* DOTTA_SESSION_H */
