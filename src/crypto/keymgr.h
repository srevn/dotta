/**
 * keymgr.h — Master-key lifecycle and per-operation subkey acquisition
 *
 * The single chokepoint between dotta's command/content layers and the cipher /
 * kdf / session primitives. Two responsibilities:
 *
 *   1. Per-operation subkey acquisition — given a profile name, derives the
 *      (mac_key, prf_key) pair from the master and hands them to `cipher_encrypt`
 *      / `cipher_decrypt`. The master key never escapes this module.
 *   2. Master-key cache lifecycle — hides the "is the user still authenticated"
 *      question behind a single resolve step.
 *
 * One master, one slot. The master is a function of (passphrase, epoch), and
 * the epoch — the salt and the Argon2id pair — is the repository's, minted once
 * and immutable under ciphertext (crypto/kdf.h, infra/epoch.h). A keymgr is bound
 * to one epoch at create time and holds at most one master: the in-memory slot
 * is the process memo of it, the on-disk session cache (crypto/session) the memo
 * across processes. Nothing routes by parameters: every blob names its epoch by
 * fingerprint, and either it is this repository's or no master here can open it
 * — `keymgr_decrypt` refuses the foreign one before asking for anything.
 *
 * Two-tier cache:
 *   - In-memory slot. One (master_key, cached_at) record inside the keymgr struct.
 *   - On-disk session cache (~/.cache/dotta/session, owned by crypto/session),
 *     written by every fresh derivation and read by the first resolve of a process.
 *
 * Security:
 *   - The master lives in process memory and on disk. The disk cache is obfuscated
 *     and machine-bound, NOT encrypted at rest — see crypto/session.h for the
 *     full threat model.
 *   - mlock on the keymgr struct is best-effort; under tight RLIMIT_MEMLOCK the
 *     constructor logs a one-time advisory and continues. The kernel reclaims
 *     the page on process death.
 *   - In-memory expiry uses CLOCK_MONOTONIC so cache lifetime cannot be extended
 *     by skewing the system clock. The on-disk cache uses wall-clock so it can
 *     survive reboots.
 *   - Every key buffer (master, mac_key, prf_key, intermediates) is scrubbed
 *     via `crypto_wipe` on every exit path. Callers never see raw key bytes.
 *   - Always-prompt mode (`session_timeout == 0`) bypasses both cache tiers
 *     entirely: derivations succeed but the master is never installed in the
 *     slot or persisted, so no master-key bytes outlive a single operation.
 */

#ifndef DOTTA_KEYMGR_H
#define DOTTA_KEYMGR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <types.h>

#include "crypto/kdf.h"

/**
 * Key manager (opaque).
 *
 * Holds the epoch, the session timeout and the in-memory cache slot. Best-effort
 * mlock'd at create time. Treat as opaque; access via the functions below.
 */
typedef struct keymgr keymgr;

/**
 * Create a key manager bound to an epoch.
 *
 * Copies the epoch and computes its fingerprint (`kdf_epoch_fingerprint`), which
 * is stamped into every blob this keymgr encrypts and checked against every blob
 * it is asked to decrypt. The epoch follows `refs/dotta/epoch`; the one command
 * that moves that ref mid-run (sync's adopt) re-binds via `keymgr_rekey`.
 *
 * No derivation, prompt, or I/O at create time. The first call to encrypt / decrypt
 * / set_passphrase / probe_key triggers the lazy resolution chain.
 *
 * Loading the epoch is the caller's responsibility (`infra/epoch::epoch_load`
 * at the dispatcher boundary). The epoch is public; treat as ordinary input.
 *
 * @param session_timeout Seconds the on-disk cache lives (config); 0 = always
 *                        prompt, -1 = never expire
 * @param epoch           The repository's epoch (non-NULL; copied)
 * @param out             Key manager (caller frees with keymgr_free)
 * @return Error or NULL on success
 */
error_t *keymgr_create(
    int32_t session_timeout,
    const kdf_epoch_t *epoch,
    keymgr **out
);

/**
 * Encrypt plaintext under a profile-derived key.
 *
 * Acquires the master key, derives the SIV subkey pair, calls `cipher_encrypt`
 * with the epoch's fingerprint, and wipes every intermediate buffer on every
 * exit path.
 *
 * Cold cache: prompts and runs memory-hard Argon2id. Warm cache: two BLAKE2b
 * derivations plus SIV+keystream bandwidth.
 *
 * Errors pass through unwrapped: a resolve names its own cause, and a
 * `cipher_encrypt` refusal is the caller's to attach file-level context to.
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
 * First checks the blob's epoch fingerprint against this keymgr's: a foreign
 * fingerprint can never decrypt here (the master would derive under a different
 * epoch), so it is refused up front — before any passphrase prompt — with a precise
 * ERR_CRYPTO instead of a misleading authentication failure. Then acquires the
 * master key and decrypts.
 *
 * Errors pass through unwrapped, as in `keymgr_encrypt`, so callers can render
 * file-level diagnostics without stacking wraps.
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
 * Derives the master key under the epoch. Behavior branches on `session_timeout`:
 *   - `session_timeout != 0`: install the master in the in-memory slot (replacing
 *     any prior contents) AND write to the on-disk session cache.
 *   - `session_timeout == 0` (always-prompt): derive — which validates the
 *     passphrase — but neither install nor persist; the master is scrubbed before
 *     return. Subsequent operations re-prompt as expected under the always-prompt
 *     contract.
 *
 * Rotation UX: if a master derived from a different passphrase was cached, this
 * call silently invalidates every blob encrypted under the prior passphrase.
 * `cmd_key_set` is responsible for surfacing the rotation warning before invoking
 * this function.
 *
 * The passphrase buffer is read-only; the caller owns its lifetime and must scrub
 * it after the call returns (`buffer_secure_free` is canonical for
 * `passphrase_prompt` buffers).
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
 * Securely zeros the in-memory slot and unlinks the on-disk session cache. Used
 * by `dotta key clear` and at process shutdown via the cleanup chain. Safe to
 * call multiple times and on a never-warmed keymgr.
 *
 * @param km Key manager (NULL-safe)
 */
void keymgr_clear(keymgr *km);

/**
 * Re-bind the key manager to a new epoch.
 *
 * For the one code path that moves `refs/dotta/epoch` mid-command — sync's adopt.
 * The create-time copy goes stale the moment the ref moves, so the command that
 * moved it re-establishes the binding, the same duty sync discharges for Git by
 * rebuilding the manifest after its pulls. Evicts the in-memory master (it derives
 * from the old epoch), recomputes the fingerprint, and unlinks the on-disk session
 * cache eagerly (its MAC binds the salt, so a stale file would fail-and-unlink
 * lazily regardless).
 *
 * @param km    Key manager (NULL-safe — encryption-disabled runs have none)
 * @param epoch The newly adopted epoch (non-NULL; copied)
 */
void keymgr_rekey(keymgr *km, const kdf_epoch_t *epoch);

/**
 * The epoch this key manager is bound to.
 *
 * `dotta key status` prints its pair. Borrowed; valid for the keymgr's lifetime
 * and until the next `keymgr_rekey`.
 *
 * @param km Key manager (non-NULL)
 * @return The epoch
 */
const kdf_epoch_t *keymgr_epoch(const keymgr *km);

/**
 * Probe whether the master key is available without prompting.
 *
 * Checks the in-memory slot first; on miss, consults the on-disk session cache.
 *
 * Side effect: a successful disk-cache hit installs the key into the in-memory
 * slot so the subsequent operation reuses it.
 *
 * Never prompts and never reads `DOTTA_ENCRYPTION_PASSPHRASE`. For the full
 * resolution chain use `keymgr_encrypt` / `keymgr_decrypt`.
 *
 * @param km Key manager (NULL-safe; returns false)
 * @return true iff the key is cached
 */
bool keymgr_probe_key(keymgr *km);

/**
 * Get time until the cached slot expires.
 *
 * Reports against the master occupying the in-memory slot — a per-process freshness
 * estimate. For "is the key warm?" use `keymgr_probe_key` first, then this for
 * the time component.
 *
 * @param km             Key manager (NULL-safe; returns 0)
 * @param out_expires_at Optional output for the wall-clock expiry time; 0 when
 *                       cache is cold or never expires
 * @return Seconds until expiration; 0 if not cached or expired; -1 if the slot
 *         never expires
 */
int64_t keymgr_time_until_expiry(
    const keymgr *km,
    time_t *out_expires_at
);

/**
 * Free the key manager.
 *
 * Securely zeros the cached key, releases the mlock pin (if held), and frees
 * the struct. NULL-safe.
 *
 * @param km Key manager (NULL-safe)
 */
void keymgr_free(keymgr *km);

#endif /* DOTTA_KEYMGR_H */
