/**
 * session.h - On-disk session cache for the master encryption key
 *
 * Persists a 32-byte master between dotta invocations so the user is not
 * re-prompted within the configured window. One file per repository epoch:
 *
 *     ~/.cache/dotta/session-<epoch fingerprint, 16 hex>
 *
 * under the invoker's home (sys/identity), so a master set without sudo is found
 * by a later `sudo dotta apply`. The file is the EPOCH's, not the repository's:
 * two repositories that each minted their own never contest one, and two checkouts
 * of one repository share one — deliberately, since a master is a function of
 * (passphrase, epoch) and there is only one of it to cache. So a file outlives
 * any single keymgr's interest in it: a repository that adopts another epoch
 * leaves its old file to whoever is still on that epoch (crypto/keymgr.h,
 * `keymgr_rekey`). A file is only ever read under the epoch that named it. Owned
 * entirely by this module; keymgr orchestrates save/load/clear and never touches
 * the format.
 *
 * File format (113 bytes; little-endian; the offsets are session.c's):
 *
 *     magic[8]            "DOTTASES"
 *     version             SESSION_CACHE_VERSION (= 0x04)
 *     created_at_le[8]    LE64 — Unix seconds, informational
 *     expires_at_le[8]    LE64 — Unix seconds; 0 = never expires
 *     nonce[24]           entropy_fill — the XChaCha20 nonce of the obfuscation
 *     obfuscated_key[32]  master XOR XChaCha20(cache_key, nonce)
 *     mac[32]             keyed BLAKE2b(cache_key, CRYPTO_DOMAIN_SESSION_MAC)
 *                         over bytes [0..81)
 *
 *     cache_key = BLAKE2b-32(salt ‖ params) — the epoch's own bytes
 *
 * What the file is, said once: **obfuscated, not encrypted**. The key that masks
 * the master and keys the MAC is derived from the epoch, which is public (it is
 * the ref every clone fetches), so the MAC is a keyed checksum — it detects
 * corruption and a file that belongs to another epoch — and the XOR keeps the
 * master out of plain sight and does nothing more. The file's protection is its
 * mode (0600, asserted at create and checked at load) and its owner (the invoker's
 * uid, checked on the opened descriptor). A copy to another machine of the same
 * uid loads; nothing here defends against a reader who has the file and the
 * repository. This is "save re-typing a passphrase", not "credential at rest".
 *
 * Expiry is wall-clock, because the file must outlive a reboot; the caller decides
 * the moment (keymgr computes `now + timeout`, or 0 for never) and this module
 * refuses a file past it. A clock set back extends a window, a clock set forward
 * closes one: stated, not defended.
 *
 * Crypto-internal header. keymgr.c is the sole consumer; tests/test-session.c
 * reads it at its own boundary to pin the format.
 */

#ifndef DOTTA_CRYPTO_SESSION_H
#define DOTTA_CRYPTO_SESSION_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <types.h>

#include "crypto/kdf.h"

/**
 * Persist a master key to the epoch's session file.
 *
 * Creates ~/.cache/dotta (mode 0700) if missing and writes the file with mode
 * 0600 (set at open, reasserted via fchmod against umask), obfuscated, MAC-tagged
 * and fsynced before return. The write is in place with O_TRUNC: a crash leaves
 * a short file the loader's size check rejects.
 *
 * @param master_key Secret to persist (32 bytes; non-NULL)
 * @param epoch      The epoch the master derives under: names the file and keys
 *                   the obfuscation (non-NULL)
 * @param expires_at Unix seconds after which the file refuses to load; 0 = never
 * @return NULL on success; ERR_FS on I/O failure; ERR_MEMORY on allocation failure;
 *         ERR_CRYPTO if the nonce cannot be drawn
 */
error_t *session_save(
    const uint8_t master_key[KDF_KEY_SIZE],
    const kdf_epoch_t *epoch,
    time_t expires_at
);

/**
 * Load the master key from the epoch's session file.
 *
 * Validation order:
 *   1. regular file, mode 0600, owned by the invoker's uid
 *   2. exactly SESSION_FILE_SIZE bytes
 *   3. magic + version
 *   4. MAC (constant-time) under the epoch's cache_key
 *   5. expiry (wall-clock)
 *
 * The MAC is verified before the expiry is read, so the decision is made on
 * authenticated bytes. A file that fails for a reason of its own — corruption,
 * wrong mode or owner, another epoch's bytes under this name, expired — is unlinked
 * so the next call starts fresh; a transient I/O failure leaves it in place.
 *
 * @param out_master_key Buffer for the 32-byte secret (the caller wipes after
 *                       use; scrubbed here on every error path)
 * @param epoch          The epoch whose file to read (non-NULL)
 * @param out_expires_at The file's expiry, 0 = never (non-NULL; set on success)
 * @return NULL on success; ERR_NOT_FOUND if there is no file or it has expired;
 *         ERR_CRYPTO for corruption, wrong mode or owner, version mismatch or
 *         MAC failure; ERR_FS for an unexpected I/O error
 */
error_t *session_load(
    uint8_t out_master_key[KDF_KEY_SIZE],
    const kdf_epoch_t *epoch,
    time_t *out_expires_at
);

/**
 * Delete the epoch's session file.
 *
 * Best-effort secure overwrite — zeros across the file, fsync — then unlink;
 * the unlink is what guarantees the file is no longer loadable, and any failure
 * of the overwrite is silent. Nothing to do when there is no file.
 *
 * `false` is "this removed nothing", not "nothing was there": the file may have
 * been absent, or the path — the one allocation on the way in — may not have
 * been buildable. Telling those apart would cost the caller a signature it has
 * no use for on a run already out of memory.
 *
 * @param epoch The epoch whose file to remove (non-NULL)
 * @return true iff a file was there and is gone
 */
bool session_clear(const kdf_epoch_t *epoch);

#endif /* DOTTA_CRYPTO_SESSION_H */
