/**
 * keymgr.h — Master-key lifecycle and per-operation subkey acquisition
 *
 * The single chokepoint between dotta's command/content layers and
 * the cipher / kdf / session primitives. Two responsibilities:
 *
 *   1. Per-operation subkey acquisition — given a profile name and
 *      target Argon2id params, derives the (mac_key, prf_key) pair
 *      and hands them to `cipher_encrypt` / `cipher_decrypt`. The
 *      master key never escapes this module.
 *   2. Master-key cache lifecycle — hides the "is the user still
 *      authenticated" question behind a single resolve step.
 *
 * Two-tier cache:
 *   - In-memory slot. Single (master_key, memory_mib, passes,
 *     cached_at) record inside the keymgr struct. Tracks whatever
 *     (mib, passes) was last requested; evicts on any cross-parameter
 *     request.
 *   - On-disk session cache (~/.cache/dotta/session, owned by
 *     crypto/session). The canonical current-config slot. Only
 *     updated when the request's params equal the snapshot taken at
 *     keymgr_create; a non-current request reads the file (to learn
 *     its params) but never promotes or overwrites it.
 *
 * Param routing:
 *   - `keymgr_encrypt` uses the current-config params (snapshot at
 *     create time) so fresh blobs always carry the latest strength.
 *   - `keymgr_decrypt` uses the params from the blob header so old
 *     blobs decrypt under the params they were sealed with regardless
 *     of later config edits.
 *   - `keymgr_set_passphrase` and `keymgr_probe_key` use current-
 *     config (no blob context to draw a different target from).
 *
 * Security:
 *   - The master lives in process memory and on disk. The disk cache
 *     is obfuscated and machine-bound, NOT encrypted at rest — see
 *     crypto/session.h for the full threat model.
 *   - mlock on the keymgr struct is best-effort; under tight
 *     RLIMIT_MEMLOCK the constructor logs a one-time advisory and
 *     continues. The kernel reclaims the page on process death.
 *   - In-memory expiry uses CLOCK_MONOTONIC so cache lifetime cannot
 *     be extended by skewing the system clock. The on-disk cache uses
 *     wall-clock so it can survive reboots.
 *   - Every key buffer (master, mac_key, prf_key, intermediates) is
 *     scrubbed via `crypto_wipe` on every exit path. Callers never
 *     see raw key bytes.
 *   - Cross-parameter eviction is intentional. Workflows that
 *     interleave blobs at different params re-prompt on each
 *     transition; the remediation is operational (re-encrypt under
 *     one consistent params set), not algorithmic.
 *   - Always-prompt mode (`session_timeout == 0`) bypasses both cache
 *     tiers entirely: derivations succeed but the master is never
 *     installed in the slot or persisted, so no master-key bytes
 *     outlive a single operation. The `is_slot_valid_for` predicate
 *     would already treat the slot as cold under timeout==0, but the
 *     stronger invariant — bytes never land there — is enforced at
 *     every install site.
 */

#ifndef DOTTA_KEYMGR_H
#define DOTTA_KEYMGR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <types.h>

#include "crypto/kdf.h"

/* Forward declarations */
typedef struct config config_t;

/**
 * Key manager (opaque).
 *
 * Holds the config snapshot (Argon2 params, session timeout) plus
 * the in-memory cache slot. Best-effort mlock'd at create time.
 * Treat as opaque; access via the functions below.
 */
typedef struct keymgr keymgr;

/**
 * Create a key manager.
 *
 * Snapshots the current-config Argon2 params, session timeout, AND
 * the per-repository salt into the struct. Later config edits in the
 * same process do not affect this snapshot, so a single command
 * produces blobs under one consistent (memory_mib, passes) even if
 * the file changes mid-run; the salt is immutable post-init regardless.
 *
 * No derivation, prompt, or I/O at create time. The first call to
 * encrypt / decrypt / set_passphrase / probe_key triggers the lazy
 * resolution chain.
 *
 * The 32-byte `salt` parameter is the per-repo random tag from
 * `refs/dotta/salt:salt`; loading it is the caller's responsibility
 * (typically `infra/salt::salt_load` at the
 * dispatcher boundary). The salt is public; treat as ordinary input.
 *
 * @param config Configuration (non-NULL; encryption fields read)
 * @param salt   Per-repo Argon2id salt (32 bytes; non-NULL; copied)
 * @param out    Key manager (caller frees with keymgr_free)
 * @return Error or NULL on success
 */
error_t *keymgr_create(
    const config_t *config,
    const uint8_t salt[KDF_SALT_SIZE],
    keymgr **out
);

/**
 * Encrypt plaintext under a profile-derived key.
 *
 * Acquires the master key under the current-config (memory_mib,
 * passes) snapshot, derives the SIV subkey pair, calls
 * `cipher_encrypt`, and wipes every intermediate buffer on every
 * exit path.
 *
 * Cold cache: prompts and runs memory-hard Argon2id. Warm cache:
 * two BLAKE2b derivations plus SIV+keystream bandwidth.
 *
 * Error wrapping: subkey-derivation errors are wrapped with a
 * profile-naming message; `cipher_encrypt` errors pass through
 * unwrapped so the caller can attach file-level context.
 *
 * @param km             Key manager (non-NULL)
 * @param profile        Profile name (non-NULL, non-empty)
 * @param storage_path   File path (non-NULL; bound into SIV)
 * @param plaintext      Plaintext bytes (non-NULL when len > 0)
 * @param plaintext_len  Plaintext length (≤ CIPHER_MAX_CONTENT)
 * @param out_ciphertext Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success
 */
error_t *keymgr_encrypt(
    keymgr *km,
    const char *profile,
    const char *storage_path,
    const uint8_t *plaintext,
    size_t plaintext_len,
    buffer_t *out_ciphertext
);

/**
 * Decrypt ciphertext under a profile-derived key.
 *
 * Reads (memory_mib, passes) from the blob header via
 * `cipher_peek_params`, then acquires the master key under those
 * blob-recorded params. Decryption thus survives config edits.
 *
 * If the cached slot holds different params it is evicted and
 * re-derived under the blob's params. The on-disk session cache
 * (canonical current-config slot) is consulted but never overwritten
 * by an old-params derivation.
 *
 * Error wrapping mirrors `keymgr_encrypt`: subkey-derivation errors
 * are wrapped; `cipher_decrypt` errors pass through unwrapped so
 * callers can render file-level diagnostics (e.g. "wrong passphrase,
 * try: dotta key clear") without stacking wraps.
 *
 * @param km             Key manager (non-NULL)
 * @param profile        Profile name (non-NULL, non-empty)
 * @param storage_path   File path (non-NULL; must match the path used
 *                       at encryption — mismatch fails SIV verify)
 * @param ciphertext     Dotta-encrypted bytes including header (non-NULL)
 * @param ciphertext_len Ciphertext length (≥ CIPHER_OVERHEAD)
 * @param out_plaintext  Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on auth/parse failure)
 */
error_t *keymgr_decrypt(
    keymgr *km,
    const char *profile,
    const char *storage_path,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    buffer_t *out_plaintext
);

/**
 * Explicitly set the passphrase (`dotta key set`).
 *
 * Derives the master key under the current-config params. Behavior
 * branches on `session_timeout`:
 *   - `session_timeout != 0`: install the master in the in-memory slot
 *     (replacing any prior contents) AND write to the on-disk session
 *     cache.
 *   - `session_timeout == 0` (always-prompt): derive — which validates
 *     the passphrase — but neither install nor persist; the master is
 *     scrubbed before return. Subsequent operations re-prompt as
 *     expected under the always-prompt contract.
 *
 * Rotation UX: if a master derived from a different passphrase was
 * cached, this call silently invalidates every blob encrypted under
 * the prior passphrase. `cmd_key_set` is responsible for surfacing
 * the rotation warning before invoking this function.
 *
 * The passphrase buffer is read-only; the caller owns its lifetime
 * and must scrub it after the call returns (`buffer_secure_free` is
 * canonical for `passphrase_prompt` buffers).
 *
 * @param km             Key manager (non-NULL)
 * @param passphrase     Passphrase bytes (non-NULL, len > 0)
 * @param passphrase_len Passphrase length (excluding NUL)
 * @return Error or NULL on success
 */
error_t *keymgr_set_passphrase(
    keymgr *km,
    const uint8_t *passphrase,
    size_t passphrase_len
);

/**
 * Clear the cached master key.
 *
 * Securely zeros the in-memory slot (master_key, params, timestamp)
 * and unlinks the on-disk session cache. Used by `dotta key clear` and
 * at process shutdown via the cleanup chain. Safe to call multiple
 * times and on a never-warmed keymgr.
 *
 * @param km Key manager (NULL-safe)
 */
void keymgr_clear(keymgr *km);

/**
 * Probe whether the current-config master key is available without
 * prompting.
 *
 * Checks the in-memory slot first; on miss, consults the on-disk
 * session cache. A disk cache recording non-current params is left
 * in place but treated as a miss — this function answers "is the
 * current-config key cached?".
 *
 * Side effect: a successful disk-cache match installs the key into
 * the in-memory slot so the subsequent operation reuses it.
 *
 * Never prompts and never reads `DOTTA_ENCRYPTION_PASSPHRASE`. For
 * the full resolution chain use `keymgr_encrypt` / `keymgr_decrypt`.
 *
 * @param km Key manager (NULL-safe; returns false)
 * @return true iff the current-config key is cached
 */
bool keymgr_probe_key(keymgr *km);

/**
 * Get time until the cached slot expires.
 *
 * Reports against whatever (master_key, params) pair currently
 * occupies the in-memory slot — a per-process freshness estimate,
 * not a per-params query. For "is the current-config key warm?"
 * use `keymgr_probe_key` first, then this for the time component.
 *
 * @param km             Key manager (NULL-safe; returns 0)
 * @param out_expires_at Optional output for the wall-clock expiry
 *                       time; 0 when cache is cold or never expires
 * @return Seconds until expiration; 0 if not cached or expired;
 *         -1 if the slot never expires
 */
int64_t keymgr_time_until_expiry(
    const keymgr *km,
    time_t *out_expires_at
);

/**
 * Free the key manager.
 *
 * Securely zeros the cached key, releases the mlock pin (if held), and
 * frees the struct. NULL-safe.
 *
 * @param km Key manager (NULL-safe)
 */
void keymgr_free(keymgr *km);

#endif /* DOTTA_KEYMGR_H */
