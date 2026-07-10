/**
 * salt.h - Per-repository Argon2id salt
 *
 * Owns the `refs/dotta/salt` ref, a synced piece of repo-wide
 * infrastructure that sits alongside the local-only `dotta-worktree`
 * branch and the user-data profile branches.
 *
 * The ref doubles as the repository identity marker: `dotta init`
 * creates it unconditionally and `dotta sync` establishes it on every
 * remote, so a remote that does not advertise it is not a dotta
 * repository. `dotta clone` gates on exactly this; `repo_open` is the
 * local-side counterpart (dotta-worktree branch presence).
 *
 *     refs/dotta/salt
 *       └── commit
 *             └── tree
 *                   └── salt   (KDF_SALT_SIZE bytes — Argon2id salt)
 *
 * The salt makes each repository a distinct attack target: a
 * precomputation table built against one repo's passphrase guesses
 * cannot be reused against any other. It is generated once at
 * `dotta init`, fetched at `dotta clone`, and reconciled at
 * `dotta sync` (establish on the remote, adopt from it, or surface a
 * conflict — see `salt_resolve`), so cross-machine sync of
 * encrypted dotfiles works while still defeating cross-installation
 * precomputation.
 *
 * The commit→tree→blob structure (rather than a ref pointing at a
 * blob directly) is standard Git citizenship: it lets `dotta git
 * show refs/dotta/salt` render a meaningful object header and keeps
 * tree-walk and history tools working.
 *
 * Salt is PUBLIC. Argon2 requires uniqueness across attack targets,
 * not secrecy. Treat as ordinary input bytes; do not mlock or wipe.
 *
 * Layering — `infra/` depends on sys/gitops + sys/entropy +
 * sys/transfer + crypto/kdf (for the salt-size constant). Consumed
 * by main.c, cmd_init, cmd_clone, cmd_sync. libgit2 is called
 * directly from this module's push/fetch primitives because there is
 * exactly one consumer of "push/fetch a non-branch ref" today and
 * `sys/gitops` does not yet need to abstract that.
 */

#ifndef DOTTA_SALT_H
#define DOTTA_SALT_H

#include <git2.h>
#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"
#include "sys/transfer.h"

/* Custom-namespace ref. Branch-listing filters target refs/heads/...
 * so this ref does not require additional filtering at branch sites. */
#define SALT_REF        "refs/dotta/salt"

/** Tree-entry name for the salt blob. */
#define SALT_BLOB_NAME  "salt"

/**
 * Initialize the per-repository salt ref.
 *
 * If `refs/dotta/salt` exists with a valid salt blob, no-op
 * (idempotent on repeat `dotta init`, and across partial-init repair
 * paths). Otherwise generates KDF_SALT_SIZE random bytes via
 * `entropy_fill`, writes a commit→tree→`salt` blob, and points the
 * ref at the new commit.
 *
 * Called by `cmd_init` after the dotta-worktree branch is established.
 * Encryption-disabled installations still produce the ref so a future
 * `dotta key set` (or a clone fetching this remote) finds it ready.
 *
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t *salt_init(git_repository *repo);

/**
 * Load the per-repo Argon2id salt.
 *
 * Walks `refs/dotta/salt` → commit → tree → `salt` blob and copies
 * exactly KDF_SALT_SIZE bytes into `out_salt`.
 *
 * Returns ERR_NOT_FOUND when the ref is missing — the canonical
 * diagnostic for "this dotta repo has not been initialized" or "this
 * clone fetched from a remote that does not host the salt ref".
 * Caller (typically `main.c::open_crypto_for_mode`) wraps with an
 * actionable hint pointing to `dotta init` or sync.
 *
 * Returns ERR_CRYPTO when the ref exists but the blob is the wrong
 * size, indicating tampering or a partial / format-broken commit.
 *
 * @param repo     Repository (must not be NULL)
 * @param out_salt Output buffer for KDF_SALT_SIZE bytes
 * @return Error or NULL on success
 */
error_t *salt_load(
    git_repository *repo,
    uint8_t out_salt[KDF_SALT_SIZE]
);

/**
 * Push `refs/dotta/salt` to the named remote.
 *
 * No-op when the local ref does not exist (e.g. during sync before any
 * `dotta init` has populated it locally). Idempotent: an already-up-to-
 * date push completes cleanly. Surfaces network and auth failures as
 * regular Git errors.
 *
 * Called once per `dotta sync` after profile pushes complete, so the
 * `dotta init` → `dotta remote add` → `dotta sync` workflow ships the
 * salt to the remote without requiring manual `git push refs/dotta/...`.
 *
 * @param repo        Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL, e.g. "origin")
 * @param xfer        Transfer context for credentials / progress
 * @return Error or NULL on success
 */
error_t *salt_push(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
);

/**
 * Fetch `refs/dotta/salt` from the named remote, validating the result.
 *
 * Called by `cmd_clone` after the main clone completes and by `cmd_sync`
 * on the adopt path, so the canonical salt is present before any
 * encrypt/decrypt operation runs.
 *
 * This is the salt *acquisition boundary*, so it owns the "is this a
 * well-formed salt?" check. After the force-fetch lands the remote
 * commit in `refs/dotta/salt`, the blob is size-validated via
 * `salt_load`. A malformed salt (wrong size or otherwise unreadable)
 * is rolled back — the local ref is restored to its prior target, or
 * removed if there was none — and ERR_CRYPTO is returned. A corrupt
 * remote salt therefore never lands locally to be mistaken for
 * canonical by a later `salt_resolve` or `salt_load`.
 *
 * @param repo        Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL, e.g. "origin")
 * @param xfer        Transfer context for credentials / progress
 * @return Error or NULL on success;
 *         ERR_NOT_FOUND if the remote lacks the ref;
 *         ERR_CRYPTO if the fetched salt is malformed (already rolled back)
 */
error_t *salt_fetch(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
);

/**
 * Decision of `salt_resolve`: how the local salt relates to the
 * remote's, and what (if anything) the caller should do about it.
 *
 * The fact-finding is exact despite the salt commit carrying a
 * non-deterministic timestamp. Status comes from a commit-OID comparison,
 * not a blob-byte compare: the salt only ever propagates by force-fetch
 * (clone / adopt), which copies the *exact* remote commit object, so a
 * converged local ref shares the remote's OID byte-for-byte (EQUAL is then
 * a trivial match with zero object transfer). Two machines that
 * independently minted a salt hold different random bytes in different
 * commits → different OID → genuinely divergent. The only
 * equal-bytes-different-OID path (two commit-wraps of the same 32 random
 * bytes) has probability 2^-256 and fails *safe*: it misclassifies as
 * divergent, routing through the in-use census to a conflict rather than a
 * silent overwrite.
 *
 * The decision is the fact; the CLI gating (--no-push / --no-pull /
 * --dry-run) and all user-facing rendering are the caller's policy.
 */
typedef enum {
    SALT_RECONCILE_EQUAL,          /* remote OID == local; no-op */
    SALT_RECONCILE_ESTABLISH,      /* remote absent, local salt valid → caller pushes */
    SALT_RECONCILE_NO_LOCAL_SALT,  /* remote absent, local salt missing/malformed → nothing to publish */
    SALT_RECONCILE_ADOPT,          /* divergent, local salt unused → caller force-fetches */
    SALT_RECONCILE_CONFLICT,       /* divergent, local salt in use → caller warns, no git op */
    SALT_RECONCILE_UNREACHABLE,    /* inspect transport failure → caller skips best-effort */
} salt_reconcile_t;

/**
 * Decide how to reconcile the local salt with the remote's — a pure
 * fact-finder. No I/O beyond git, no rendering, no CLI flags.
 *
 * Connects and lists the remote (commit-OID compare, zero object
 * transfer); on a divergent salt, also validates the local salt and runs a
 * key-free census of every local profile branch to learn whether any local
 * ciphertext depends on the salt that an adopt would replace. The census
 * fails *closed*: any uncertainty — local salt unreadable for a reason
 * other than absent/malformed, or any census error — lands on CONFLICT,
 * never on a data-destroying ADOPT.
 *
 * This module owns only the *mechanism* of looking and classifying; the
 * establish/adopt/conflict actions, CLI gating, and rendering are policy
 * and live in `cmd_sync`.
 *
 * Transport failure (connect / ls) folds to SALT_RECONCILE_UNREACHABLE so
 * the caller can skip salt reconciliation best-effort — the authoritative
 * "remote unreachable" diagnostic comes from the subsequent fetch phase.
 * The only error returned is programmer misuse (a NULL argument).
 *
 * @param repo         Repository (must not be NULL)
 * @param remote_name  Remote name (must not be NULL, e.g. "origin")
 * @param xfer         Transfer context for credentials / progress (must not be NULL)
 * @param out_decision Output decision (must not be NULL)
 * @return Error only on a NULL argument; otherwise NULL with *out_decision set
 */
error_t *salt_resolve(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    salt_reconcile_t *out_decision
);

#endif /* DOTTA_SALT_H */
