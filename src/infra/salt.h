/**
 * salt.h - Per-repository Argon2id salt
 *
 * Owns the `refs/dotta/salt` ref, a synced piece of repo-wide
 * infrastructure that sits alongside the local-only `dotta-worktree`
 * branch and the user-data profile branches.
 *
 *     refs/dotta/salt
 *       └── commit
 *             └── tree
 *                   └── salt   (KDF_SALT_SIZE bytes — Argon2id salt)
 *
 * The salt makes each repository a distinct attack target: a
 * precomputation table built against one repo's passphrase guesses
 * cannot be reused against any other. It is generated once at
 * `dotta init`, fetched at `dotta clone`, and pushed at `dotta sync`,
 * so cross-machine sync of encrypted dotfiles works while still
 * defeating cross-installation precomputation.
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
 * Fetch `refs/dotta/salt` from the named remote.
 *
 * Called by `cmd_clone` after the main clone completes, so the salt is
 * present before any encrypt/decrypt operation runs. Returns
 * ERR_NOT_FOUND when the remote does not advertise the ref — the clone
 * caller treats this as a soft warning (the remote may not be a dotta
 * repository, or it predates per-repo salts).
 *
 * @param repo        Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL, e.g. "origin")
 * @param xfer        Transfer context for credentials / progress
 * @return Error or NULL on success;
 *         ERR_NOT_FOUND if the remote lacks the ref
 */
error_t *salt_fetch(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
);

#endif /* DOTTA_SALT_H */
