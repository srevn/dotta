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
 * to one epoch at create time and holds at most one master. Nothing routes by
 * parameters: every blob names its epoch by fingerprint, and either it is this
 * repository's or no master here can open it — `keymgr_decrypt` refuses the foreign
 * one before asking for anything.
 *
 * The slot and the file. The in-memory slot is the process memo of the master:
 * once resolved, every later operation of the run reads it, under every
 * `session_timeout` — a two-file `add` derives once. The on-disk session file
 * (crypto/session; one per epoch, under the invoker's home) is the memo across
 * processes: written by every fresh derivation when the file tier is on, read
 * by the first resolve of a process. `session_timeout` governs the file alone:
 * 0 turns the tier off (nothing is written, so the next process asks again), -1
 * writes a file that never expires, a positive value one that expires that many
 * seconds after it was written. The slot carries the file's expiry —
 * `keymgr_cached` reports it — and nothing else keeps time: a master that came
 * from a file the loader accepted is good for the run.
 *
 * Security:
 *   - The master lives in process memory and, when the file tier is on, on disk.
 *     The file is obfuscated, NOT encrypted at rest — see crypto/session.h for
 *     what it is and what protects it.
 *   - mlock on the keymgr struct is best-effort; under tight RLIMIT_MEMLOCK the
 *     constructor logs a one-time advisory and continues. The kernel reclaims
 *     the page on process death.
 *   - Every key buffer (master, mac_key, prf_key, intermediates) is scrubbed
 *     via `crypto_wipe` on every exit path. Callers never see raw key bytes.
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
 * Holds the epoch, the session timeout and the in-memory slot. Best-effort mlock'd
 * at create time. Treat as opaque; access via the functions below.
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
 * / set_passphrase / cached triggers the lazy resolution chain.
 *
 * Loading the epoch is the caller's responsibility (`infra/epoch::epoch_load`
 * at the dispatcher boundary). The epoch is public; treat as ordinary input.
 *
 * @param session_timeout Seconds the on-disk file lives (config); 0 = no file,
 *                        -1 = never expires
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
 * Derives the master key under the epoch, installs it in the slot (replacing
 * any prior occupant) and, when the file tier is on (`session_timeout != 0`),
 * writes the session file. Under `session_timeout == 0` the derivation — which
 * is what validates the passphrase — runs and the slot is installed for this
 * process; no file is written, so the next process asks again.
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
 * Securely zeros the in-memory slot and unlinks the epoch's session file. Used
 * by `dotta key clear`. Safe to call multiple times and on a never-warmed keymgr.
 *
 * @param km Key manager (NULL-safe)
 * @return true iff a session file was there and is gone
 */
bool keymgr_clear(keymgr *km);

/**
 * Re-bind the key manager to a new epoch.
 *
 * For the one code path that moves `refs/dotta/epoch` mid-command — sync's adopt.
 * The create-time copy goes stale the moment the ref moves, so the command that
 * moved it re-establishes the binding, the same duty sync discharges for Git by
 * rebuilding the manifest after its pulls. Evicts the in-memory master (it derives
 * from the old epoch), unlinks the old epoch's session file (the file is the
 * epoch's by name; nothing would read it again), and recomputes the fingerprint.
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
 * Is the master key available without asking?
 *
 * The slot, else — when the file tier is on — the epoch's session file, which a
 * hit installs into the slot so the operation that follows reuses it. Never prompts
 * and never reads `DOTTA_ENCRYPTION_PASSPHRASE`; for the full resolution chain
 * use `keymgr_encrypt` / `keymgr_decrypt`.
 *
 * @param km             Key manager (NULL-safe; returns false)
 * @param out_expires_at Optional: the file's expiry, Unix seconds; 0 when the
 *                       key is not cached or the file never expires
 * @return true iff the key is cached
 */
bool keymgr_cached(keymgr *km, time_t *out_expires_at);

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
