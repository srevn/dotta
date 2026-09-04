/**
 * keymgr.h - The repository's unlock proof, and per-operation subkey acquisition
 *
 * The single chokepoint between dotta's command/content layers and the cipher /
 * kdf / session primitives. Two responsibilities:
 *
 *   1. Per-operation subkey acquisition — given a profile name, derives the
 *      (mac_key, prf_key) pair from the master and hands them to `cipher_encrypt`
 *      / `cipher_decrypt`. The master key never escapes this module.
 *   2. The proof — a master that provably opens this repository's ciphertext,
 *      obtained once and remembered: the "is the user authenticated" question
 *      hidden behind a single resolve step.
 *
 * One master, one slot. The master is a function of (passphrase, epoch), and
 * the epoch — the salt and the Argon2id pair — is the repository's, minted once
 * and immutable under ciphertext (crypto/kdf.h, infra/epoch.h). A keymgr is bound
 * to one epoch at create time and holds at most one master. Nothing routes by
 * parameters: every blob names its epoch by fingerprint, and either it is this
 * repository's or no master here can open it — `keymgr_decrypt` refuses the foreign
 * one before asking for anything.
 *
 * Nothing enters the slot or the file unverified. A fresh master — derived from
 * a passphrase the environment or the prompt gave — is kept only after it has
 * opened a witness: the blob the decrypt in hand was asked for, or, when that
 * refuses it or the operation holds no blob (an encrypt, `key set`), a ciphertext
 * of this epoch the repository holds. The keymgr finds the latter through the
 * witness source it was created with: the source presents every ciphertext of
 * the epoch, tips first, to a predicate of the keymgr's until one opens, so a
 * tampered or relocated blob costs nothing but its own row. A master that opens
 * nothing is wiped and never kept, and the row that asked reads the refusal.
 * With no ciphertext in the repository there is nothing to open: a typed passphrase
 * is confirmed by typing it twice, one from the environment is taken as given
 * (an explicit source is the automation's own assertion). The binding of the
 * witness a kept master opened is the proof's (`keymgr_witness`). A master a
 * cache handed back is not re-verified: a blob it does not open is that blob's
 * fault, and the slot stays.
 *
 * The ladder asks once per run. Its refusal — no source in reach, nothing read
 * at the prompt, a passphrase that opened nothing — stands for the process: every
 * later resolve re-issues the same line without asking again, so a workspace of
 * N encrypted rows costs one prompt and one file probe, not N. Retries only
 * at a terminal (KEYMGR_ATTEMPTS, misses of any kind); over a pipe, one line;
 * from the environment, none. `key set` is the one ask that clears a standing
 * refusal; a rekey clears it too (the sources are now about another epoch);
 * `key clear` does not (it is about the caches).
 *
 * The slot and the file. The in-memory slot is the process memo of the master:
 * once resolved, every later operation of the run reads it, under every
 * `session_timeout` — a two-file `add` derives once. The on-disk session file
 * (crypto/session; one per epoch, under the invoker's home) is the memo across
 * processes: written by every kept master when the file tier is on, read by the
 * first resolve of a process. `session_timeout` governs the file alone: 0 turns
 * the tier off (nothing is written, so the next process asks again), -1 writes
 * a file that never expires, a positive value one that expires that many seconds
 * after it was written. The slot carries the file's expiry — `keymgr_cached`
 * reports it — and nothing else keeps time: a master that came from a file the
 * loader accepted is good for the run. A save that fails is silent inside an
 * operation (the slot is the run's; the operation must not fail for want of a
 * cache) and unlinks the file so it never lies; `keymgr_set`, whose job the file
 * is, returns it.
 *
 * The reach. A command declares how far the keymgr may go for a passphrase
 * (`keymgr_reach_t`): the caches alone, or the environment and the prompt beyond
 * them. Under CACHED a cold resolve is ERR_LOCKED — no passphrase in reach —
 * and the row that asked reads as unverifiable; nothing is asked and nothing is
 * written. `status` and `sync` report; `apply` and `add` obtain.
 *
 * The codes. ERR_LOCKED means this run holds no usable master: none in reach,
 * none read at the prompt, none that opens the repository's ciphertext — one
 * fact for every row of the run, and a key is what settles it. ERR_CRYPTO is
 * the cipher's word under a held master — a blob it does not open is that blob's
 * fault — and the refusals no master can ever lift here: a foreign epoch, a version
 * this build does not read, a malformed header. A witness walk or a derivation
 * that fails on its own keeps its own code. The workspace reads the code to name
 * a failed look's fault (core/workspace.h), so the boundary is a contract, not
 * a habit.
 *
 * The layer computes, the verbs report: nothing here writes to a stream but the
 * prompt's own text, and that only at a terminal (sys/passphrase). Every refusal
 * is one `error_t` naming its cause and the way out.
 *
 * Security:
 *   - The master lives in process memory and, when the file tier is on, on disk.
 *     The file is obfuscated, NOT encrypted at rest — see crypto/session.h for
 *     what it is and what protects it.
 *   - The struct is a `secure_alloc` mapping of its own (base/secure.h): locked
 *     against swap best-effort — under tight RLIMIT_MEMLOCK the process prints
 *     one advisory and continues — and wiped and unmapped by `keymgr_free`. The
 *     kernel reclaims the pages on process death.
 *   - Every key buffer (master, mac_key, prf_key, intermediates, a fresh master
 *     on trial) is scrubbed via `crypto_wipe` on every exit path. The ladder
 *     carries no plaintext: a witness's decrypt is wiped and freed where it ran.
 *     Callers never see raw key bytes.
 */

#ifndef DOTTA_KEYMGR_H
#define DOTTA_KEYMGR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <types.h>

#include "crypto/kdf.h"

/* libgit2's opaque repository type: the witness source's argument, which the
 * crypto layer carries as a token and never dereferences — runtime.h's own trick,
 * so the source has a typed signature and the dispatcher needs no adapter. */
struct git_repository;

/**
 * Key manager (opaque).
 *
 * Holds the epoch, the session timeout, the reach, the in-memory slot, the standing
 * refusal and the witness source, in a mapping of its own. Treat as opaque; access
 * via the functions below.
 */
typedef struct keymgr keymgr;

/**
 * How far the keymgr may reach for a passphrase.
 *
 * CACHED: the slot and the session file — what earlier runs left — and nothing
 * else: no environment variable, no prompt, no file written. A resolve that finds
 * nothing there is ERR_LOCKED. OBTAIN: then the environment, then the prompt.
 * The command declares it (include/runtime.h's crypto need) and the dispatcher
 * maps it here.
 */
typedef enum keymgr_reach {
    KEYMGR_REACH_CACHED,
    KEYMGR_REACH_OBTAIN
} keymgr_reach_t;

/**
 * Attempts at a terminal before the ladder refuses — misses of any kind: a wrong
 * passphrase, an empty line, a confirm that did not match. Over a pipe there is
 * one attempt; from the environment none.
 */
#define KEYMGR_ATTEMPTS 3

/**
 * A witness: one ciphertext with the binding it was sealed under.
 *
 * What a fresh master is tried against. A borrowed view — the bytes and the strings
 * are the presenter's and live for the call that presents them: the decrypt's
 * own arguments for the blob in hand, the source's walk for one the repository
 * holds.
 */
typedef struct keymgr_witness {
    const uint8_t *ciphertext;    /* the blob, whole (header, SIV, body) */
    size_t len;                   /* its length, the header included */
    const char *profile;          /* the branch it is sealed under */
    const char *storage_path;     /* the tree path bound into its SIV */
} keymgr_witness_t;

/**
 * The keymgr's answer to a witness a source presents: does the master on trial
 * open it? An accepted witness ends the walk. `*out_accepted` is written on every
 * return that has an answer, the refusals included.
 *
 * A predicate that cannot answer — a decrypt that failed for a reason other than
 * the cipher's "no" — returns its error instead, and that error becomes the walk's:
 * the source stops, reports it, and the attempt is refused with it. A question
 * nobody could answer is never an absence.
 *
 * `self` is what the keymgr handed the source beside the predicate; the source
 * passes it back untouched and never reads it.
 */
typedef error_t *(*keymgr_opens_fn)(
    void *self,
    const keymgr_witness_t *witness,
    bool *out_accepted
);

/**
 * Where the keymgr finds witnesses: whoever holds the repository.
 *
 * Presents every ciphertext of `epoch` the repository holds — tips first, so
 * the first presented is usually a live file; one object at two paths, or at
 * one path under two branches, is presented under each binding, since only one
 * of them can be the one it was sealed under — to `accept` until one is accepted,
 * and reports whether one was. A ciphertext of another epoch or of a version
 * this build does not read is never presented. The walk's own failure (an object
 * that will not load) is returned, and so is a refusal `accept` itself raises;
 * either stands as that attempt's refusal, and `*out_accepted` is false. The
 * one implementation is `infra/epoch::epoch_find_ciphertext`, over the ciphertext
 * census's walk of every local branch and its history; the unit suites bring
 * their own.
 */
typedef error_t *(*keymgr_witness_source_fn)(
    struct git_repository *repo,
    const kdf_epoch_t *epoch,
    keymgr_opens_fn accept,
    void *self,
    bool *out_accepted
);

/**
 * Create a key manager bound to an epoch, with its witness source.
 *
 * Copies the epoch and computes its fingerprint (`kdf_epoch_fingerprint`), which
 * is stamped into every blob this keymgr encrypts and checked against every blob
 * it is asked to decrypt. The epoch follows `refs/dotta/epoch`; the one command
 * that moves that ref mid-run (sync's adopt) re-binds via `keymgr_rekey`.
 *
 * The source is where a fresh master finds ciphertext to open — the dispatcher
 * passes `epoch_find_ciphertext` with the run's repository. The keymgr calls it
 * only when it has a fresh master to verify and the blob in hand (if any) refused
 * it, and once more on the prompt path with no blob in hand to learn whether
 * the prompt verifies or confirms; a warm run never calls it. A keymgr created
 * with no source (NULL) verifies a fresh master against the blob in hand alone
 * and, with none, takes it as given — the unit suites' shape; every command's
 * keymgr has one.
 *
 * No derivation, prompt, or I/O at create time. The first call to encrypt / decrypt
 * / set / cached triggers the lazy resolution chain.
 *
 * Loading the epoch is the caller's responsibility (`infra/epoch::epoch_load`
 * at the dispatcher boundary). The epoch is public; treat as ordinary input.
 *
 * @param session_timeout Seconds the on-disk file lives (config); 0 = no file,
 *                        -1 = never expires
 * @param epoch           The repository's epoch (non-NULL; copied)
 * @param reach           How far a resolve may go for a passphrase
 * @param source          The witness source (NULL: none)
 * @param repo            The source's repository, passed through untouched
 *                        (NULL when the source needs none)
 * @param out             Key manager (caller frees with keymgr_free)
 * @return Error or NULL on success
 */
error_t *keymgr_create(
    int32_t session_timeout,
    const kdf_epoch_t *epoch,
    keymgr_reach_t reach,
    keymgr_witness_source_fn source,
    struct git_repository *repo,
    keymgr **out
);

/**
 * Encrypt plaintext under a profile-derived key.
 *
 * Acquires the master key, derives the SIV subkey pair, calls `cipher_encrypt`
 * with the epoch's fingerprint, and wipes every intermediate buffer on every
 * exit path.
 *
 * Cold cache: the ladder — the environment, then the prompt, under OBTAIN; a
 * fresh master is verified against a ciphertext the repository holds (or confirmed
 * / taken as given when it holds none) before anything is sealed under it. Under
 * CACHED a cold cache is ERR_LOCKED. Warm cache: two BLAKE2b derivations plus
 * SIV+keystream bandwidth.
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
 * master key — the blob in hand is the witness a fresh master must open first,
 * so a cold decrypt verifies on the very blob it was asked for — and decrypts.
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
 * @return Error or NULL on success: ERR_LOCKED when the run holds no usable master,
 *         ERR_CRYPTO when a held master does not open this blob or no master
 *         here ever could (the codes paragraph above)
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
 * Obtain and keep the passphrase outright (`dotta key set`).
 *
 * The ladder's user half — the environment, then the prompt — with the caches
 * skipped and any standing refusal cleared: the verb's job is to verify against
 * the repository, not against what an earlier run left. The fresh master is
 * verified against a ciphertext the repository holds, or confirmed by typing it
 * twice / taken as given from the environment when it holds none; then it enters
 * the slot, replacing any occupant, and the file when the tier is on.
 *
 * A passphrase that opens none of the repository's ciphertext is refused, so a
 * `key set` can no longer install a master that silently invalidates every sealed
 * file; there is no rotation to warn about. Under `session_timeout == 0` the
 * verification runs and the slot takes the master for this process; no file is
 * written, so the next process asks again.
 *
 * Caching is this verb's job, so the session file's save error is returned —
 * the slot is installed either way, and the file was unlinked so it never lies.
 *
 * @param km Key manager (non-NULL)
 * @return Error or NULL on success: the ladder's refusal (ERR_LOCKED — nothing
 *         usable was obtained, or the passphrase opened nothing; a walk or a
 *         derivation that failed keeps its own code), or the save's
 */
error_t *keymgr_set(keymgr *km);

/**
 * The witness the kept master opened, if any.
 *
 * The binding — profile and storage path — of the ciphertext a fresh master was
 * verified against before it entered the slot: the blob a decrypt was asked for,
 * or the one the witness source presented. False when the slot is empty, when
 * the master came from a cache (verified by an earlier run), or when there was
 * nothing to open and it was confirmed or taken as given. `dotta key set -v`
 * prints it. Borrowed; valid until the slot changes.
 *
 * @param km               Key manager (NULL-safe; returns false)
 * @param out_profile      The profile (set on true)
 * @param out_storage_path The storage path (set on true)
 * @return true iff the kept master opened a witness
 */
bool keymgr_witness(
    const keymgr *km,
    const char **out_profile,
    const char **out_storage_path
);

/**
 * Clear the cached master key.
 *
 * Securely zeros the in-memory slot and unlinks the epoch's session file. Used
 * by `dotta key clear`. A standing refusal stays: the clear is about the caches,
 * not about what the user would answer. Safe to call multiple times and on a
 * never-warmed keymgr.
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
 * epoch's by name; nothing would read it again), clears a standing refusal (the
 * sources are now about another epoch), and recomputes the fingerprint.
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
 * The one entry point that dereferences `km` without a `CHECK_NULL`: it returns
 * a borrowed pointer, so it has nowhere to put a refusal, and the non-NULL is
 * the caller's to honour.
 *
 * @param km Key manager (non-NULL)
 * @return The epoch
 */
const kdf_epoch_t *keymgr_epoch(const keymgr *km);

/**
 * Is the master key available without asking?
 *
 * The slot, else — when the file tier is on and no refusal stands — the epoch's
 * session file, which a hit installs into the slot so the operation that follows
 * reuses it. Never prompts and never reads `DOTTA_ENCRYPTION_PASSPHRASE`; for
 * the full resolution chain use `keymgr_encrypt` / `keymgr_decrypt`.
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
 * Securely zeros the cached key and ends the struct's mapping (wiped, unlocked,
 * unmapped). NULL-safe.
 *
 * @param km Key manager (NULL-safe)
 */
void keymgr_free(keymgr *km);

#endif /* DOTTA_KEYMGR_H */
