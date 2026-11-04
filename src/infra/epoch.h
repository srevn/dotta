/**
 * epoch.h - The repository's epoch: its Argon2id salt and parameters
 *
 * Owns the `refs/dotta/epoch` ref, a synced piece of repo-wide infrastructure
 * that sits alongside this machine's baseline (`refs/dotta/baseline`, never synced)
 * and the user-data profile branches.
 *
 * The ref doubles as the remote's identity marker: `dotta init` creates it
 * unconditionally and `dotta sync` establishes it on every remote, so a remote
 * that does not advertise it is not a dotta repository. `dotta clone` gates on
 * exactly this. The local store's identity is a different fact — the declaration
 * a create-style command wrote into its config (utils/repo.h) — because an absent
 * epoch is a state the store must survive: `sync` adopts the remote's over it,
 * and `init` mints over it once the census clears.
 *
 *     refs/dotta/epoch
 *       └── commit
 *             └── tree
 *                   ├── salt     (KDF_SALT_SIZE bytes — the Argon2id salt)
 *                   └── params   (KDF_PARAMS_SIZE bytes — LE16 memory ‖ passes ‖ lanes)
 *
 * The epoch is everything the master-key derivation takes but the passphrase
 * (`kdf_epoch_t`), and the repository is its one owner: a master is a function
 * of (passphrase, epoch), so every machine on a repository derives one master
 * from one passphrase, and a change of strength is a new epoch — every blob
 * re-sealed, never a second master beside the first. The salt makes each repository
 * a distinct attack target (a precomputation table built against one repo's
 * passphrase guesses cannot be reused against any other); the parameters are
 * the cost of a guess. It is minted once at `dotta init`, adopted at `dotta clone`,
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
 * mint, to adopt, or to take a passphrase as given — so the walk needs a branch
 * listing that is complete or an error, and sys/gitops's is one (its header:
 * libgit2 skips a loose ref it cannot read, and the listing reads the loose store
 * itself to catch it). The walk holds no proof of its own, and one rule serves
 * both answers: a ciphertext found — a witness opened, one the census counts —
 * stands whatever the walk could not read on the way, and a walk that ends without
 * one fails on the first thing it could not read, a listing's error among them,
 * so the census fails closed.
 *
 * Layering — `infra/` depends on sys/gitops + sys/stage + sys/entropy + sys/remote
 * + infra/content (a blob's kind, key-free) + infra/commit (an act's word) +
 * crypto/kdf (the epoch type, its encoding and its fingerprint) + crypto/keymgr
 * (the witness vocabulary). Consumed by main.c (the load at dispatch, and the
 * witness source the keymgr is created with), cmd_init, cmd_clone, cmd_sync.
 * The epoch meets the remote only through its caller's session (sys/remote.h):
 * its verdict reads the session's advertisement, its objects ride the caller's
 * one fetch, and its establish is the caller's push.
 */

#ifndef DOTTA_EPOCH_H
#define DOTTA_EPOCH_H

#include <git2.h>
#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"
#include "crypto/keymgr.h"
#include "infra/commit.h"
#include "sys/remote.h"

/* Custom-namespace ref. Branch-listing filters target refs/heads/... so this
 * ref does not require additional filtering at branch sites. */
#define EPOCH_REF          "refs/dotta/epoch"

/* The refspec that restores the epoch from a remote holding this repository's.
 * Forced, because an epoch commit is a root: over a ref that is present but
 * unreadable a plain fetch is rejected as non-fast-forward and restores nothing.
 * Naming the one ref and not its namespace: a restore is of the epoch, and
 * refs/dotta holds this machine's baseline beside it (core/ignore.h), which a
 * glob would replace with a remote's. A restore only from a remote that holds
 * this repository's own epoch: from a foreign one it installs that remote's,
 * and the local salt is gone for good — which no reader of a missing or unreadable
 * ref can tell apart, so each that names the restore names that condition with
 * it. The three refusals (main.c's dispatch, epoch_init's two arms) name the
 * refspec and no remote, which they cannot know; cmds/sync.c
 * sync_print_epoch_damaged has its remote in hand and names the whole command. */
#define EPOCH_RESTORE_REFSPEC "+" EPOCH_REF ":" EPOCH_REF

/** Tree-entry names for the two blobs. */
#define EPOCH_SALT_BLOB    "salt"
#define EPOCH_PARAMS_BLOB  "params"

/**
 * Initialize the repository's epoch ref.
 *
 * The ref is read once, its id (sys/gitops.h gitops_reference_oid), and every
 * finding below judges the commit at that id, as the reconcile's own reading
 * does (epoch_resolve). If the commit yields a valid salt and params, no-op
 * (idempotent on repeat `dotta init`, and across partial-init repair paths):
 * the parameters given are ignored, and the epoch that stands is what `*out`
 * carries — the caller compares it against what it asked for. Otherwise generates
 * KDF_SALT_SIZE random bytes via `entropy_fill`, writes a commit→tree→{`salt`,
 * `params`} with the parameters given, naming its caller's action (infra/commit.h
 * commit_action_word), and points the ref at the new commit.
 *
 * Every fresh mint is gated on the ciphertext census, on both ways the ref can
 * fail to yield an epoch — it names a commit that yields none (a wrong-size blob,
 * a missing blob, parameters out of range, a broken shape, an object libgit2
 * will not load) or it is absent. The danger is one danger: with the epoch's
 * bytes unavailable no blob's fingerprint can be matched against anything, so
 * any reachable ciphertext (any fingerprint, any version) may be keyed by what
 * the ref held, and a fresh epoch would orphan it permanently. With any reachable
 * ciphertext, the refusal names the state of the ref and the restore that repairs
 * it, and the evidence stays in place (a remote holding the true epoch heals a
 * divergence via sync's fetch paths instead). A census that found none and could
 * not read everything proves no absence and reaches the same verdict, but not
 * for the same reason, so it carries its own cause rather than borrowing that
 * sentence. With a clean census the ref binds nothing: one that yields no epoch
 * is deleted from the id it was read at, so a ref another writer moved since is
 * refused, and re-minted (`*out_repaired` set — the caller renders the repair);
 * an absent one is simply a repository that has no epoch yet.
 *
 * A ref no read reaches — one at the null id, a symbolic ref to nothing, a file
 * Git cannot parse, each a hand's or a disk's, never git's or libgit2's — has
 * no id to judge or to delete from, and is refused before any census, the read's
 * cause naming the ref: git's own fetch dies over it ("bad object"), so no restore
 * is named, and the evidence stays in place.
 *
 * Every refusal names the epoch or its act — the read, the census, the ref and
 * its restore, the removal, the mint (the salt's draw its first step) — and keeps
 * its cause's code: ERR_CRYPTO where the ref is missing, the read's, the judgment's
 * or the census's where they stand (ERR_CRYPTO for bytes refused, ERR_GIT for a
 * reference or an object that would not read). No caller reads it.
 *
 * Called by `cmd_init` once the store is declared its own (utils/repo.h), which
 * returns each refusal as it is said (cmds/init.c cmd_init). Encryption-disabled
 * installations still produce the ref so a future `dotta key set` (or a clone
 * fetching this remote) finds it ready.
 *
 * @param repo         Repository (must not be NULL)
 * @param params       The Argon2id parameters to mint with (a preset's; in range)
 * @param action       The command a mint's commit names: the caller's
 * @param out          The epoch that stands after the call: the existing one,
 *                     or the one minted (must not be NULL)
 * @param out_repaired Optional: set true iff an unreadable ref was deleted and
 *                     re-minted (can be NULL)
 * @return Error or NULL on success
 */
error_t epoch_init(
    git_repository *repo,
    kdf_params_t params,
    commit_action_t action,
    kdf_epoch_t *out,
    bool *out_repaired
);

/**
 * Load the repository's epoch.
 *
 * Walks `refs/dotta/epoch` → commit → tree → the `salt` and `params` blobs and
 * fills `*out`: exactly KDF_SALT_SIZE salt bytes, and parameters validated with
 * `kdf_validate_params` — this is the boundary they enter the process at, and
 * nothing downstream re-checks them.
 *
 * Returns ERR_NOT_FOUND when — and only when — the ref itself is missing, the
 * canonical diagnostic for "this dotta repo has not been initialized" or "this
 * clone could not adopt its remote's epoch". The dispatcher wraps it with the
 * restore (main.c open_run), its one reader, which is why the code stops at the
 * ref and never speaks for the payload.
 *
 * Returns ERR_CRYPTO when the ref exists but yields no epoch — the tree lacks a
 * blob, an entry is not a blob, a blob is the wrong size, or the parameters are
 * out of range — each indicating tampering or a partial / format-broken commit.
 *
 * A third code reaches callers and needs no type to tell it apart: ERR_GIT, from
 * an object libgit2 will not load, says exactly what ERR_CRYPTO says — the ref
 * stands and yields no epoch — differing only in the mechanism that got there.
 * ERR_NOT_FOUND is the statement about the ref, made deliberately at one site;
 * everything else is that one fact, and every consumer may treat them as one.
 * The dispatcher, the code's one reader, does: it asks which of two first lines
 * it prints, and may not read into ERR_CRYPTO that the bytes are certainly
 * malformed rather than merely unavailable. The reconcile and the mint read the
 * ref's id instead, and judge the bytes at it (`epoch_resolve`, `epoch_init`).
 *
 * @param repo Repository (must not be NULL)
 * @param out  The epoch (must not be NULL; zeroed on failure)
 * @return Error or NULL on success
 */
error_t epoch_load(git_repository *repo, kdf_epoch_t *out);

/**
 * The verdict of `epoch_resolve`: how the local epoch relates to the remote's,
 * and what (if anything) the caller should do about it.
 *
 * The fact-finding is exact despite the epoch commit carrying a non-deterministic
 * timestamp. Status comes from a commit-OID comparison, not a blob-byte compare:
 * the epoch only ever propagates by an adopt (clone's, sync's), which installs
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
 * The verdict is the fact; the CLI gating (--no-push / --dry-run) and all
 * user-facing rendering are the caller's policy.
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

    /* Push. */
    EPOCH_RECONCILE_ESTABLISH,      /* remote absent, the local ref yields an epoch */
    EPOCH_RECONCILE_NO_LOCAL_EPOCH, /* remote absent, the local ref yields none */

    /* Adopt — three findings, one act. */
    EPOCH_RECONCILE_ADOPT,          /* divergent, and nothing here depends on the bytes
                                     * at the local ref → caller takes the remote's */

    /* Refuse — two findings, two remedies. */
    EPOCH_RECONCILE_CONFLICT,       /* divergent, the local epoch keys reachable ciphertext
                                     * → caller warns, no git op */
    EPOCH_RECONCILE_DAMAGED,        /* divergent, the local ref yields no epoch over
                                     * ciphertext it may key → restore, never replace */
} epoch_reconcile_t;

/**
 * What `epoch_resolve` decided, and the two ids it judged
 *
 * The verdict, and the ids it was reached over: the local ref's as its one read
 * named it — the census's subject — and the remote's as the session's advertisement
 * named it, Git's null id for either absent. The act the verdict calls for is
 * made from them, never from a second read of either: the establish pushes `local`
 * expecting `advertised`, the remote holding none (sys/remote.h remote_push),
 * and the adopt proves `advertised`'s commit and installs it over `local`
 * (epoch_adopt).
 */
typedef struct {
    epoch_reconcile_t verdict;      /* How the two ids relate, and the act it calls for */
    git_oid local;                  /* refs/dotta/epoch here, as its one read named it; the null id: none */
    git_oid advertised;             /* The remote's, off the session's advertisement; the null id: none */
} epoch_decision_t;

/**
 * Decide how to reconcile the local epoch with the remote's — a pure fact-finder.
 * No network, no rendering, no CLI flags.
 *
 * The remote's epoch is read off the caller's session (sys/remote.h
 * remote_advertised), a commit-OID compare with zero object transfer: a session
 * that opened has reached its remote, so no verdict stands for one that could
 * not be reached. A divergence is then decided from two things and nothing else
 * — what the local ref yields, and what a key-free census over the *full history*
 * of every local branch finds. The history and not the heads: `dotta show`/`revert`
 * decrypt blobs at any `@commit`, so history-reachable ciphertext pins the epoch
 * exactly as head ciphertext does.
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
 * blob away from a restore. With the parameters unreadable no blob's fingerprint
 * can be matched against anything, so the census there must ask for ANY ciphertext
 * — any fingerprint, any version. That is the census `epoch_init` runs over the
 * identical state, for the same reason, reaching the same verdict: leave the
 * evidence in place for a restore. With a readable epoch only the ciphertext IT
 * keys counts; foreign-keyed blobs (pulled from a remote under its own epoch)
 * argue FOR converging, not against, and a version this build cannot attribute
 * counts either way.
 *
 * An absent ref is the one row that runs no census, because `epoch_init`'s reason
 * for running one there does not hold here: a mint would introduce a *new* root
 * that orphans whatever the ref used to key, while an adopt installs the remote's,
 * which may be exactly that root. The bytes are already gone; nothing this verdict
 * licenses can make it worse.
 *
 * Two errors, each in its own words, since neither has a second reporter anywhere
 * in sync: the local ref that would not read — read once, first, and named in
 * its failure (sys/gitops.h gitops_reference_find) — and a census that found
 * nothing and could not read everything, which fails closed: an error and never
 * a verdict, wrapped as the question it could not answer, whose cause names the
 * first thing it could not read and where it stands.
 *
 * This module owns only the *mechanism* of looking and classifying; the acts,
 * the CLI gating, and the rendering are policy and live in `cmd_sync`.
 *
 * Readers: cmds/sync.c sync_reconcile_epoch; cmds/clone.c cmd_clone, whose gate
 * is the advertised id and whose adopt the decision licenses.
 *
 * @param repo   Repository (must not be NULL)
 * @param remote The caller's session, its advertisement read (must not be NULL)
 * @param out    The decision (must not be NULL)
 * @return Error where the local ref would not read or the census could not finish;
 *         otherwise NULL with *out set
 */
error_t epoch_resolve(
    git_repository *repo,
    const remote_t *remote,
    epoch_decision_t *out
);

/**
 * Install the epoch the remote advertised, once its commit is proved
 *
 * The acquisition's last two steps, transactional: the caller's fetch brought
 * the objects (sys/remote.h remote_fetch, asked for EPOCH_REF) and stored no
 * ref for them; both blobs are validated at the advertised commit; and only a
 * proven epoch is written to `refs/dotta/epoch`, the one mutation this call makes
 * and its last step. Every failure of that proof returns one ERR_CRYPTO, worded
 * as an epoch that could not be adopted and caused by the mechanism's own sentence
 * — a wrong-size or missing blob, parameters out of range, an advertised object
 * that is no commit, one the read could not load — blaming neither side, since
 * the code cannot tell the remote's bytes from this store's read; and leaves
 * the local ref untouched: there is nothing to roll back, because an epoch that
 * was not proven never stood in `refs/dotta/epoch` for a later `epoch_resolve`
 * or `epoch_load` to read as canonical.
 *
 * ERR_CRYPTO is read by cmds/clone.c cmd_clone, which warns past it; cmds/sync.c
 * sync_reconcile_epoch prints every failure whole and reads no code. Every failure
 * names the act and the remote.
 *
 * The install is written from the census's read: the local ref is replaced by
 * the remote's only where it still names what the decision judged — `local`,
 * Git's null id where none stood — so one another writer moved, deleted or made
 * since is refused and stands as that writer left it (sys/gitops.h
 * gitops_write_reference). Whether replacing what the census read is safe is
 * the verdict's: `cmd_sync` reaches ADOPT only where nothing reachable here depends
 * on the bytes being replaced, `cmd_clone` with no epoch at all.
 *
 * @param repo        Repository (must not be NULL)
 * @param decision    The verdict, ADOPT, and the ids it judged (must not be NULL)
 * @param remote_name The remote the epoch is adopted from, named in the line
 *                    and in every failure (must not be NULL)
 * @param action      The command the install's reflog line names: the caller's
 * @return Error or NULL on success; ERR_CRYPTO where the advertised epoch could
 *         not be proved (the local ref untouched); ERR_CONFLICT where another
 *         writer moved the local ref since the census read it
 */
error_t epoch_adopt(
    git_repository *repo,
    const epoch_decision_t *decision,
    const char *remote_name,
    commit_action_t action
);

/**
 * The keymgr's witness source (`keymgr_witness_source_fn`): find a ciphertext
 * of `epoch` the master on trial opens.
 *
 * Presents every ciphertext of `epoch` the repository holds — the census's walk
 * over every local branch and its full history, heads first, so the first presented
 * is usually a live file — to `accept` with the binding it stands under (the
 * branch, and the tree path), until one is accepted. One object at two paths,
 * or at one path under two branches, is presented under each: only one of them
 * can be the binding it was sealed under, and the walk cannot know which. A blob
 * of another epoch or of a version this build does not read is never presented:
 * no master here can open either, so it says nothing about a passphrase. The
 * keymgr asks two questions through this one function: whether any ciphertext
 * exists (an `accept` that takes the first) and whether a fresh master opens
 * one (an `accept` that asks the cipher, crypto/cipher.h cipher_opens).
 *
 * The full history and not the heads, for the reason at the head of this file:
 * an absence here is a licence, and a walk that stopped at the heads would report
 * one over ciphertext the repository still holds — which for this asker means
 * taking a wrong passphrase as given (crypto/keymgr.h).
 *
 * What the walk cannot read — a branch that will not list, a head, a history or
 * a tree that will not load, a blob it cannot judge — it passes over, so a witness
 * accepted beyond it stands. Where none is accepted, the first of them is returned,
 * named by where it stands, with `*out_accepted` false: an absence the walk could
 * not prove (crypto/keymgr.c derive_and_check reads it so). `accept` is a predicate
 * and raises none. A ciphertext reachable from no local branch is never presented,
 * and a decrypt of one reads its refusal on its own row.
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
error_t epoch_find_ciphertext(
    git_repository *repo,
    const kdf_epoch_t *epoch,
    keymgr_opens_fn accept,
    void *self,
    bool *out_accepted
);

#endif /* DOTTA_EPOCH_H */
