/**
 * epoch.h - The repository's epoch: its Argon2id salt and parameters
 *
 * Owns the `refs/dotta/epoch` ref, a synced piece of repo-wide infrastructure
 * that sits alongside the local-only `dotta-worktree` branch and the user-data
 * profile branches.
 *
 * The ref doubles as the repository identity marker: `dotta init` creates it
 * unconditionally and `dotta sync` establishes it on every remote, so a remote
 * that does not advertise it is not a dotta repository. `dotta clone` gates on
 * exactly this; `repo_open` is the local-side counterpart (dotta-worktree branch
 * presence).
 *
 *     refs/dotta/epoch
 *       └── commit
 *             └── tree
 *                   ├── salt     (KDF_SALT_SIZE bytes — the Argon2id salt)
 *                   └── params   (KDF_PARAMS_SIZE bytes — LE16 memory_mib ‖ passes)
 *
 * The epoch is everything the master-key derivation takes but the passphrase
 * (`kdf_epoch_t`), and the repository is its one owner: a master is a function
 * of (passphrase, epoch), so every machine on a repository derives one master
 * from one passphrase, and a change of strength is a new epoch — every blob
 * re-sealed, never a second master beside the first. The salt makes each repository
 * a distinct attack target (a precomputation table built against one repo's
 * passphrase guesses cannot be reused against any other); the parameters are
 * the cost of a guess. It is minted once at `dotta init`, fetched at `dotta clone`,
 * and reconciled at `dotta sync` (establish it on the remote, take the remote's,
 * or refuse and say why — see `epoch_resolve`), so cross-machine sync of encrypted
 * dotfiles works while still defeating cross-installation precomputation.
 *
 * The commit→tree→blob structure (rather than a ref pointing at a blob directly)
 * is standard Git citizenship: it lets `dotta git show refs/dotta/epoch` render
 * a meaningful object header and keeps tree-walk and history tools working; two
 * blobs name the two facts under `git ls-tree`.
 *
 * The epoch is PUBLIC. Argon2 requires uniqueness across attack targets, not
 * secrecy. Treat as ordinary input bytes; do not mlock or wipe.
 *
 * The repository's ciphertext is also where a passphrase is proved. The same
 * key-free walk that the reconcile's census runs — every local branch, its full
 * history — is the keymgr's witness source (`epoch_find_ciphertext`): a fresh
 * master is kept only after it opened a ciphertext of this epoch the repository
 * holds, and this module is what presents them (crypto/keymgr.h).
 *
 * Every asker of that walk acts on an ABSENCE of ciphertext — the licence to
 * mint, to adopt, or to take a passphrase as given — and a branch listing is
 * not a proof of one: Git skips a ref it cannot read rather than reporting it
 * (sys/gitops.h), so an unlistable `refs/heads` reads as a repository with no
 * branches. So the walk proves the listing is this repository's before walking
 * it, by the one branch every repository that reaches it holds — `dotta-worktree`
 * — and refuses a listing without it. That catches a listing that lost everything;
 * one that lost a single unreadable ref it cannot, and that limit stays Git's.
 *
 * Layering — `infra/` depends on sys/gitops + sys/entropy + sys/transfer +
 * crypto/kdf (the epoch type, its encoding and its fingerprint) + crypto/keymgr
 * (the witness vocabulary). Consumed by main.c (the load at dispatch, and the
 * witness source the keymgr is created with), cmd_init, cmd_clone, cmd_sync.
 * libgit2 is called directly from this module's push/fetch primitives because
 * there is exactly one consumer of "push/fetch a non-branch ref" today and
 * `sys/gitops` does not yet need to abstract that.
 */

#ifndef DOTTA_EPOCH_H
#define DOTTA_EPOCH_H

#include <git2.h>
#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"
#include "crypto/keymgr.h"
#include "sys/transfer.h"

/* Custom-namespace ref. Branch-listing filters target refs/heads/... so this
 * ref does not require additional filtering at branch sites. */
#define EPOCH_REF          "refs/dotta/epoch"

/** Tree-entry names for the two blobs. */
#define EPOCH_SALT_BLOB    "salt"
#define EPOCH_PARAMS_BLOB  "params"

/**
 * Initialize the repository's epoch ref.
 *
 * If `refs/dotta/epoch` exists with a valid salt and params, no-op (idempotent
 * on repeat `dotta init`, and across partial-init repair paths): the pair given
 * is ignored, and the epoch that stands is what `*out` carries — the caller
 * compares it against what it asked for. Otherwise generates KDF_SALT_SIZE random
 * bytes via `entropy_fill`, writes a commit→tree→{`salt`, `params`} with the
 * pair given, and points the ref at the new commit.
 *
 * Every fresh mint is gated on the ciphertext census, on both ways the ref can
 * fail to yield an epoch — it stands and yields none (a wrong-size blob, a missing
 * blob, a pair out of range, a broken shape, an object libgit2 will not load)
 * or it is absent. The danger is one danger: with the epoch's bytes unavailable
 * no blob's fingerprint can be matched against anything, so any reachable
 * ciphertext (any fingerprint, any version) may be keyed by what the ref held,
 * and a fresh epoch would orphan it permanently. With any reachable ciphertext,
 * ERR_CRYPTO propagates naming the state of the ref and the restore that repairs
 * it, and the evidence stays in place (a remote holding the true epoch heals a
 * divergence via sync's fetch paths instead). A census that cannot finish proves
 * no absence and reaches the same verdict, but not for the same reason, so it
 * carries its own cause rather than borrowing that sentence. With a clean census
 * the ref binds nothing: an unreadable one is deleted and re-minted
 * (`*out_repaired` set — the caller renders the repair), an absent one is simply
 * a repository that has no epoch yet.
 *
 * Called by `cmd_init` after the dotta-worktree branch is established.
 * Encryption-disabled installations still produce the ref so a future `dotta
 * key set` (or a clone fetching this remote) finds it ready.
 *
 * @param repo         Repository (must not be NULL)
 * @param memory_mib   Argon2 memory in MiB to mint with (a preset's; in range)
 * @param passes       Argon2 pass count to mint with (a preset's; in range)
 * @param out          The epoch that stands after the call: the existing one,
 *                     or the one minted (must not be NULL)
 * @param out_repaired Optional: set true iff an unreadable ref was deleted and
 *                     re-minted (can be NULL)
 * @return Error or NULL on success
 */
error_t *epoch_init(
    git_repository *repo,
    uint16_t memory_mib,
    uint8_t passes,
    kdf_epoch_t *out,
    bool *out_repaired
);

/**
 * Load the repository's epoch.
 *
 * Walks `refs/dotta/epoch` → commit → tree → the `salt` and `params` blobs and
 * fills `*out`: exactly KDF_SALT_SIZE salt bytes, and a pair validated with
 * `kdf_validate_params` — this is the boundary the pair enters the process at,
 * and nothing downstream re-checks it.
 *
 * Returns ERR_NOT_FOUND when — and only when — the ref itself is missing, the
 * canonical diagnostic for "this dotta repo has not been initialized" or "this
 * clone fetched from a remote that does not host the epoch ref". The dispatcher
 * wraps it with an actionable hint; `epoch_init` reads it as "there is no ref
 * to delete before minting", which is why the code stops at the ref and never
 * speaks for the payload.
 *
 * Returns ERR_CRYPTO when the ref exists but yields no epoch — the tree lacks a
 * blob, an entry is not a blob, a blob is the wrong size, or the pair is out of
 * range — each indicating tampering or a partial / format-broken commit.
 *
 * A third code reaches callers and needs no type to tell it apart: ERR_GIT, from
 * an object libgit2 will not load, says exactly what ERR_CRYPTO says — the ref
 * stands and yields no epoch — differing only in the mechanism that got there.
 * ERR_NOT_FOUND is the statement about the ref, made deliberately at one site;
 * everything else is that one fact, and every consumer may treat them as one.
 * All three do: `epoch_init` asks whether there is a ref to delete before it
 * mints, the reconcile's divergent branch asks whether it got an epoch, and the
 * dispatcher picks between two first lines. What none of them may read into
 * ERR_CRYPTO is that the bytes are certainly malformed rather than merely
 * unavailable.
 *
 * @param repo Repository (must not be NULL)
 * @param out  The epoch (must not be NULL; zeroed on failure)
 * @return Error or NULL on success
 */
error_t *epoch_load(git_repository *repo, kdf_epoch_t *out);

/**
 * Push `refs/dotta/epoch` to the named remote.
 *
 * No-op when the local ref does not exist (e.g. during sync before any `dotta
 * init` has populated it locally). Idempotent: an already-up-to-date push completes
 * cleanly. Surfaces network and auth failures as regular Git errors.
 *
 * Called once per `dotta sync` after profile pushes complete, so the `dotta init`
 * → `dotta remote add` → `dotta sync` workflow ships the epoch to the remote
 * without requiring manual `git push refs/dotta/...`.
 *
 * @param repo        Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL, e.g. "origin")
 * @param xfer        Transfer context for credentials / progress
 * @return Error or NULL on success
 */
error_t *epoch_push(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
);

/**
 * Fetch `refs/dotta/epoch` from the named remote, validating the result.
 *
 * Called by `cmd_clone` after the main clone completes and by `cmd_sync` on the
 * adopt path, so the canonical epoch is present before any encrypt/decrypt
 * operation runs.
 *
 * This is the epoch *acquisition boundary*, so it owns the "is this a well-formed
 * epoch?" check — and it is transactional about it: obtain, prove, install. The
 * remote's advertisement names a commit; its objects are downloaded under a refspec
 * with no destination, so nothing local points at them; both blobs are validated
 * at that commit; and only a proven epoch is written to `refs/dotta/epoch`, the
 * one mutation this call makes and its last step. A malformed epoch (a wrong-size
 * or missing blob, a pair out of range) returns ERR_CRYPTO with the local ref
 * untouched — there is nothing to roll back, because a corrupt remote epoch never
 * stood in `refs/dotta/epoch` for a later `epoch_resolve` or `epoch_load` to
 * read as canonical.
 *
 * The install is a force: whatever the local ref held is replaced wholesale.
 * Whether that is safe is the caller's to decide, not this boundary's —
 * `cmd_sync`'s adopt path gates it on the ciphertext census, `cmd_clone` reaches
 * a repository that has no epoch at all.
 *
 * On success the validated epoch is copied to `*out` when requested — the boundary
 * hands over exactly what it proved, so the adopting caller (`cmd_sync`, which
 * feeds it to `keymgr_rekey`) never re-reads the ref it just watched move. Clone
 * has no crypto handles yet and passes NULL.
 *
 * @param repo        Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL, e.g. "origin")
 * @param xfer        Transfer context for credentials / progress
 * @param out         Optional: the validated epoch (can be NULL)
 * @return Error or NULL on success; ERR_NOT_FOUND if the remote lacks the ref;
 *         ERR_CRYPTO if the fetched epoch is malformed (the local ref untouched)
 */
error_t *epoch_fetch(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    kdf_epoch_t *out
);

/**
 * Decision of `epoch_resolve`: how the local epoch relates to the remote's, and
 * what (if anything) the caller should do about it.
 *
 * The fact-finding is exact despite the epoch commit carrying a non-deterministic
 * timestamp. Status comes from a commit-OID comparison, not a blob-byte compare:
 * the epoch only ever propagates by force-fetch (clone / adopt), which copies
 * the *exact* remote commit object, so a converged local ref shares the remote's
 * OID byte-for-byte (EQUAL is then a trivial match with zero object transfer).
 * Two machines that independently minted an epoch hold different random bytes
 * in different commits → different OID → genuinely divergent. The only
 * equal-bytes-different-OID path (two commit-wraps of the same 32 random bytes)
 * has probability 2^-256 and fails *safe*: it misclassifies as divergent, routing
 * through the census to a refusal rather than a silent overwrite.
 *
 * EQUAL is that OID comparison and nothing more — not a claim that the epoch
 * can be read. A repository whose epoch objects are gone still names the remote's
 * commit, so there is genuinely nothing to reconcile and sync says so, while
 * every command that must *read* the epoch fails at dispatch. The two are
 * consistent because the reconcile's subject is the ref, not the bytes under it.
 *
 * The decision is the fact; the CLI gating (--no-push / --no-pull / --dry-run)
 * and all user-facing rendering are the caller's policy.
 *
 * ADOPT is one arm over three findings — an absent ref, one that yields no epoch
 * with nothing sealed here, and a readable epoch that keys nothing here — because
 * the caller does the same thing with all three and has the same thing to say
 * about it. They differ in the census that established them, not in the act, so
 * the split lives in `epoch_resolve`'s reasoning and not in this vocabulary.
 * What the adopt must NOT do is describe the census it was reached by: only one
 * of the three ran an attributed one, and a line claiming otherwise is a claim
 * about work that did not happen.
 */
typedef enum {
    /* Nothing to do. */
    EPOCH_RECONCILE_EQUAL,          /* remote OID == local ref target */
    EPOCH_RECONCILE_UNREACHABLE,    /* inspect transport failure → caller skips best-effort */

    /* Push. */
    EPOCH_RECONCILE_ESTABLISH,      /* remote absent, the local ref yields an epoch */
    EPOCH_RECONCILE_NO_LOCAL_EPOCH, /* remote absent, the local ref yields none */

    /* Fetch — three findings, one act. */
    EPOCH_RECONCILE_ADOPT,          /* divergent, and nothing here depends on the bytes
                                     * at the local ref → caller takes the remote's */

    /* Refuse — two findings, two remedies. */
    EPOCH_RECONCILE_CONFLICT,       /* divergent, the local epoch keys reachable ciphertext
                                     * → caller warns, no git op */
    EPOCH_RECONCILE_DAMAGED,        /* divergent, the local ref yields no epoch over
                                     * ciphertext it may key → restore, never replace */
} epoch_reconcile_t;

/**
 * Decide how to reconcile the local epoch with the remote's — a pure fact-finder.
 * No I/O beyond git, no rendering, no CLI flags.
 *
 * Connects and lists the remote (commit-OID compare, zero object transfer). A
 * divergence is then decided from two things and nothing else — what the local
 * ref yields, and what a key-free census over the *full history* of every local
 * branch finds. The history and not the tips: `dotta show`/`revert` decrypt blobs
 * at any `@commit`, so history-reachable ciphertext pins the epoch exactly as
 * tip ciphertext does.
 *
 *   ref absent             nothing to lose, nothing to attribute   ADOPT
 *   ref yields no epoch    + any ciphertext at all                 DAMAGED
 *   ref yields no epoch    + none                                  ADOPT
 *   an epoch               + ciphertext its fingerprint keys       CONFLICT
 *   an epoch               + none it keys                          ADOPT
 *
 * The question is about the BYTES at the ref, not about the epoch derived from
 * them, and the two come apart on exactly one input: a ref that stands and yields
 * no epoch may hold the only copy of the salt that keys this repository, one
 * blob away from a restore. With the pair unreadable no blob's fingerprint can
 * be matched against anything, so the census there must ask for ANY ciphertext
 * — any fingerprint, any version. That is the census `epoch_init` runs over the
 * identical state, for the same reason, reaching the same verdict: leave the
 * evidence in place for a restore. With a readable epoch only the ciphertext IT
 * keys counts; foreign-keyed blobs (pulled from a remote under its own epoch)
 * argue FOR converging, not against, and a version this build cannot attribute
 * counts either way.
 *
 * An absent ref is the one row that runs no census, because `epoch_init`'s reason
 * for running one there does not hold here: a mint would introduce a *new* root
 * that orphans whatever the ref used to key, while a fetch installs the remote's,
 * which may be exactly that root. The bytes are already gone; nothing this decision
 * licenses can make it worse.
 *
 * Fails closed by returning: a census that cannot finish is an error, never a
 * verdict, and it is the only error this call produces beyond a NULL argument.
 * Transport failure (connect / ls) still folds to EPOCH_RECONCILE_UNREACHABLE
 * so the caller can skip epoch reconciliation best-effort — the authoritative
 * "remote unreachable" diagnostic comes from the subsequent fetch phase — but a
 * census failure has no second reporter anywhere in sync, so its cause is returned
 * rather than freed. It is returned bare: this boundary knows the mechanism,
 * and the caller that renders it is the one that can name the subject.
 *
 * This module owns only the *mechanism* of looking and classifying; the acts,
 * the CLI gating, and the rendering are policy and live in `cmd_sync`.
 *
 * @param repo         Repository (must not be NULL)
 * @param remote_name  Remote name (must not be NULL, e.g. "origin")
 * @param xfer         Transfer context for credentials / progress (must not be NULL)
 * @param out_decision Output decision (must not be NULL)
 * @return Error on a NULL argument or on a census that could not finish; otherwise
 *         NULL with *out_decision set
 */
error_t *epoch_resolve(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    epoch_reconcile_t *out_decision
);

/**
 * The keymgr's witness source (`keymgr_witness_source_fn`): find a ciphertext
 * of `epoch` the master on trial opens.
 *
 * Presents every ciphertext of `epoch` the repository holds — the census's walk
 * over every local branch and its full history, tips first, so the first presented
 * is usually a live file — to `accept` with the binding it stands under (the
 * branch, and the tree path), until one is accepted. One object at two paths,
 * or at one path under two branches, is presented under each: only one of them
 * can be the binding it was sealed under, and the walk cannot know which. A blob
 * of another epoch or of a version this build does not read is never presented:
 * no master here can open either, so it says nothing about a passphrase. The
 * keymgr asks two questions through this one function: whether any ciphertext
 * exists (an `accept` that takes the first) and whether a fresh master opens
 * one (an `accept` that decrypts).
 *
 * The full history and not the tips, for the reason at the head of this file:
 * an absence here is a licence, and a walk that stopped at the tips would report
 * one over ciphertext the repository still holds — which for this asker means
 * taking a wrong passphrase as given (crypto/keymgr.h).
 *
 * The walk's own failure — a branch that will not list, an object that will not
 * load — is returned and stands as that attempt's refusal in the keymgr, and so
 * is a refusal `accept` itself raises; either leaves `*out_accepted` false. A
 * ciphertext reachable from no local branch is never presented, and a decrypt
 * of one reads its refusal on its own row.
 *
 * Given to the keymgr at its creation by the dispatcher (`keymgr_create`); the
 * keymgr calls it only for a fresh master with no blob in hand or whose blob in
 * hand refused it, and once on the prompt path to choose verify over confirm.
 *
 * @param repo         Repository (must not be NULL)
 * @param epoch        The epoch whose ciphertext is presented (must not be NULL)
 * @param accept       The keymgr's predicate (must not be NULL)
 * @param self         Its payload, passed through untouched (can be NULL)
 * @param out_accepted True iff `accept` accepted a witness; false on any error
 *                     (must not be NULL)
 * @return Error or NULL on success
 */
error_t *epoch_find_ciphertext(
    git_repository *repo,
    const kdf_epoch_t *epoch,
    keymgr_opens_fn accept,
    void *self,
    bool *out_accepted
);

#endif /* DOTTA_EPOCH_H */
