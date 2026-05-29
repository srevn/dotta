/**
 * salt.c - Per-repository Argon2id salt implementation
 *
 * Five entry points:
 *   - salt_init      — generate salt + write commit/tree/blob (idempotent)
 *   - salt_load      — walk ref → commit → tree → blob, copy bytes
 *   - salt_push      — push refs/dotta/salt to a remote
 *   - salt_fetch     — fetch + validate refs/dotta/salt from a remote
 *   - salt_resolve   — pure fact-finder for cmd_sync's salt policy
 *
 * Every entry point validates inputs, manages libgit2 object lifetimes
 * via local cleanup blocks, and translates libgit2 error codes through
 * `error_from_git`. The module never holds resources across return.
 *
 * The push/fetch primitives speak libgit2 directly rather than going
 * through `sys/gitops::gitops_*_branches` — those build branch-specific
 * `refs/heads/...` refspecs internally, and "abstract over arbitrary
 * refspec sync" is not yet a recurring need (this is the only consumer).
 * If a second non-branch consumer arrives, that's the moment to extract
 * a `gitops_fetch_refspec` helper.
 *
 * Salt-blob mode: stored as a regular file blob (mode 0100644). The
 * mode is irrelevant to dotta — nothing checks it out — but using the
 * standard file mode keeps the tree inspectable via `dotta git show`.
 */

#include "infra/salt.h"

#include <git2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "infra/content.h"
#include "sys/entropy.h"
#include "sys/gitops.h"
#include "sys/transfer.h"

/* Standard regular-file mode for the salt blob. Nothing checks out the
 * tree; the choice keeps `git show` / `git ls-tree` output readable. */
#define SALT_BLOB_MODE 0100644

/**
 * Resolve refs/dotta/salt to a tree.
 *
 * Returns ERR_NOT_FOUND when the ref is missing, the canonical
 * "uninitialized" diagnostic. Caller is responsible for freeing
 * `*out_tree` via `git_tree_free` on success.
 */
static error_t *resolve_salt_tree(
    git_repository *repo,
    git_tree **out_tree
) {
    *out_tree = NULL;

    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, SALT_REF);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(
            ERR_NOT_FOUND,
            "Salt ref '%s' not found",
            SALT_REF
        );
    }
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Peel through any annotated-tag layers down to the commit. The
     * ref is created as a direct commit by salt_init, but peeling
     * defends against future shapes (signed-tag wrappers, symbolic
     * refs) without changing the load semantics. */
    git_object *commit_obj = NULL;
    git_err = git_reference_peel(&commit_obj, ref, GIT_OBJECT_COMMIT);
    git_reference_free(ref);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to peel '%s' to a commit", SALT_REF
        );
    }

    git_commit *commit = (git_commit *) commit_obj;
    git_err = git_commit_tree(out_tree, commit);
    git_commit_free(commit);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to load tree from '%s'", SALT_REF
        );
    }

    return NULL;
}

/**
 * Read the salt blob from a tree, validating size.
 *
 * Wipes `out_salt` via memset on every error path so a caller cannot
 * accidentally proceed with stale stack content under a swallowed
 * error code.
 */
static error_t *read_salt_blob(
    git_repository *repo,
    git_tree *tree,
    uint8_t out_salt[KDF_SALT_SIZE]
) {
    const git_tree_entry *entry = git_tree_entry_byname(
        tree, SALT_BLOB_NAME
    );
    if (entry == NULL) {
        memset(out_salt, 0, KDF_SALT_SIZE);
        return ERROR(
            ERR_NOT_FOUND,
            "Salt blob '%s' missing from %s tree",
            SALT_BLOB_NAME, SALT_REF
        );
    }

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        memset(out_salt, 0, KDF_SALT_SIZE);
        return ERROR(
            ERR_CRYPTO,
            "Tree entry '%s' in %s is not a blob",
            SALT_BLOB_NAME, SALT_REF
        );
    }

    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, git_tree_entry_id(entry));
    if (git_err < 0) {
        memset(out_salt, 0, KDF_SALT_SIZE);
        return error_from_git(git_err);
    }

    git_object_size_t size = git_blob_rawsize(blob);
    if (size != KDF_SALT_SIZE) {
        git_blob_free(blob);
        memset(out_salt, 0, KDF_SALT_SIZE);
        return ERROR(
            ERR_CRYPTO,
            "Salt blob in %s has wrong size: %lld bytes (expected %u)",
            SALT_REF, (long long) size, (unsigned) KDF_SALT_SIZE
        );
    }

    memcpy(out_salt, git_blob_rawcontent(blob), KDF_SALT_SIZE);
    git_blob_free(blob);

    return NULL;
}

error_t *salt_load(
    git_repository *repo,
    uint8_t out_salt[KDF_SALT_SIZE]
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_salt);

    git_tree *tree = NULL;
    error_t *err = resolve_salt_tree(repo, &tree);
    if (err) {
        memset(out_salt, 0, KDF_SALT_SIZE);
        return err;
    }

    err = read_salt_blob(repo, tree, out_salt);
    git_tree_free(tree);
    return err;
}

error_t *salt_init(git_repository *repo) {
    CHECK_NULL(repo);

    /* Idempotency: if the ref already resolves and the salt blob is
     * the right size, treat as success. A user re-running `dotta init`
     * on an existing repo must not regenerate the salt — that would
     * silently invalidate every encrypted blob in the repo. */
    uint8_t existing_salt[KDF_SALT_SIZE];
    error_t *probe_err = salt_load(repo, existing_salt);
    if (probe_err == NULL) {
        return NULL;  /* already initialized */
    }
    /* Any error other than ERR_NOT_FOUND propagates: a partially
     * formed ref (e.g. wrong-size salt blob) needs human attention,
     * not silent overwrite. */
    if (probe_err->code != ERR_NOT_FOUND) {
        return error_wrap(
            probe_err,
            "Repository salt exists but is malformed"
        );
    }
    error_free(probe_err);

    /* Generate the salt. entropy_fill scrubs the buffer to zeros on
     * any failure, so a half-populated salt cannot leak out. */
    uint8_t salt[KDF_SALT_SIZE];
    error_t *err = entropy_fill(salt, sizeof(salt));
    if (err) {
        return error_wrap(err, "Failed to generate repository salt");
    }

    /* Write the salt as a blob. */
    git_oid blob_oid;
    int git_err = git_blob_create_from_buffer(
        &blob_oid, repo, salt, sizeof(salt)
    );
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to write salt blob"
        );
    }

    /* Build a tree containing only the salt blob. */
    git_treebuilder *tb = NULL;
    git_err = git_treebuilder_new(&tb, repo, NULL);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to create salt tree builder"
        );
    }

    git_err = git_treebuilder_insert(
        NULL, tb, SALT_BLOB_NAME, &blob_oid,
        SALT_BLOB_MODE
    );
    if (git_err < 0) {
        git_treebuilder_free(tb);
        return error_wrap(
            error_from_git(git_err),
            "Failed to insert salt blob into tree"
        );
    }

    git_oid tree_oid;
    git_err = git_treebuilder_write(&tree_oid, tb);
    git_treebuilder_free(tb);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to write salt tree"
        );
    }

    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, repo, &tree_oid);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to look up newly-written salt tree"
        );
    }

    /* Build a signature with the same fallback policy as orphan-branch
     * creation, so a fresh machine without git config can still init. */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) {
        git_tree_free(tree);
        return error_wrap(
            sig_err, "Failed to get signature for salt commit"
        );
    }

    /* Orphan commit (no parents) writing directly to refs/dotta/salt.
     * The message is purely diagnostic; nothing in dotta parses it. */
    git_oid commit_oid;
    git_err = git_commit_create(
        &commit_oid,
        repo,
        SALT_REF,
        sig, sig,
        NULL,                      /* encoding: default */
        "Initialize repository salt",
        tree,
        0, NULL                    /* no parents = orphan */
    );

    git_signature_free(sig);
    git_tree_free(tree);

    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to commit salt to '%s'", SALT_REF
        );
    }

    return NULL;
}

error_t *salt_push(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    /* Skip the network round-trip when the local ref does not exist —
     * `dotta init` populates it but a `dotta sync` on a freshly-cloned
     * encryption-disabled repo may not have one yet. */
    git_reference *local_ref = NULL;
    int git_err = git_reference_lookup(&local_ref, repo, SALT_REF);
    if (git_err == GIT_ENOTFOUND) {
        return NULL;
    }
    if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_reference_free(local_ref);

    git_remote *remote = NULL;
    git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_push_options push_opts;
    git_push_options_init(&push_opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &push_opts.callbacks, xfer, GIT_DIRECTION_PUSH
    );

    /* Non-force refspec: a salt push must be fast-forward. Two
     * machines that independently `dotta init`ed and now race their
     * salts to the same remote will see the second one fail here —
     * surfaced as a regular non-fast-forward Git error so the user
     * understands they need to reconcile. */
    char refspec[DOTTA_REFSPEC_MAX];
    int n = snprintf(
        refspec, sizeof(refspec), "%s:%s", SALT_REF, SALT_REF
    );
    if (n < 0 || (size_t) n >= sizeof(refspec)) {
        git_remote_free(remote);
        return ERROR(
            ERR_INTERNAL, "Salt refspec buffer too small"
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_PUSH);
    git_err = git_remote_push(remote, &refs, &push_opts);
    transfer_op_end(xfer, git_err);
    git_remote_free(remote);

    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to push '%s' to '%s'", SALT_REF, remote_name
        );
    }

    return NULL;
}

/**
 * Probe the remote's advertised `refs/dotta/salt`.
 *
 * Uses `git_remote_connect` + `git_remote_ls` so the absence diagnostic
 * is "remote does not advertise this ref" — distinct from "fetch
 * failed for transport reasons". `git_remote_ls` transfers no byte
 * payload, so the connect uses FETCH direction purely to align the
 * credential path with the subsequent fetch.
 *
 * When the ref is advertised and `out_oid` is non-NULL, the advertised
 * commit OID is copied out — the hook `salt_inspect_remote` uses to
 * compare against the local ref without transferring the blob. Pass NULL
 * for `out_oid` when only presence matters (the `salt_fetch` case).
 *
 * Returns NULL with `*out_present` set; never surfaces "ref missing"
 * as an error code (that is the load-bearing return value of this
 * predicate).
 */
static error_t *probe_remote_salt(
    git_remote *remote,
    transfer_context_t *xfer,
    bool *out_present,
    git_oid *out_oid
) {
    *out_present = false;

    git_remote_callbacks callbacks;
    git_remote_init_callbacks(&callbacks, GIT_REMOTE_CALLBACKS_VERSION);
    transfer_configure_callbacks(&callbacks, xfer, GIT_DIRECTION_FETCH);

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    int git_err = git_remote_connect(
        remote, GIT_DIRECTION_FETCH, &callbacks, NULL, NULL
    );
    transfer_op_end(xfer, git_err);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const git_remote_head **heads = NULL;
    size_t heads_len = 0;
    git_err = git_remote_ls(&heads, &heads_len, remote);
    if (git_err < 0) {
        git_remote_disconnect(remote);
        return error_from_git(git_err);
    }

    for (size_t i = 0; i < heads_len; i++) {
        if (heads[i] != NULL && heads[i]->name != NULL
            && strcmp(heads[i]->name, SALT_REF) == 0) {
            *out_present = true;
            if (out_oid != NULL) {
                git_oid_cpy(out_oid, &heads[i]->oid);
            }
            break;
        }
    }

    git_remote_disconnect(remote);
    return NULL;
}

error_t *salt_fetch(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Two-step probe-then-fetch: check the remote's advertised refs
     * before constructing a refspec that targets a possibly-absent ref.
     * `git_remote_fetch` on a missing ref surfaces a generic Git error
     * indistinguishable from real transport failures by error code
     * alone — the probe gives us a clean ERR_NOT_FOUND surface for the
     * "remote isn't a dotta v7 repo" case. Presence is all we need here;
     * the OID-comparison consumer is salt_inspect_remote. */
    bool present = false;
    error_t *err = probe_remote_salt(remote, xfer, &present, NULL);
    if (err) {
        git_remote_free(remote);
        return err;
    }
    if (!present) {
        git_remote_free(remote);
        return ERROR(
            ERR_NOT_FOUND,
            "Remote '%s' does not advertise '%s'",
            remote_name, SALT_REF
        );
    }

    /* Capture the current local salt target before the force-fetch
     * overwrites it, so a malformed fetched salt can be rolled back to
     * exactly the prior state: a failed adopt never leaves garbage,
     * and never bricks a valid local salt. */
    git_oid prior_oid;
    bool prior_exists =
        (git_reference_name_to_id(&prior_oid, repo, SALT_REF) == 0);

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    /* Force update (`+` prefix): the local ref is replaced wholesale by
     * the remote's. This is safe because the only caller that reaches a
     * *divergent* local salt — `cmd_sync`'s adopt path — gates the fetch
     * on a key-free census proving no local ciphertext depends on the
     * salt being replaced. Clone reaches a missing (not divergent)
     * local salt, so there is nothing to overwrite. The force prefix also
     * lets a deliberate re-init on the canonical machine propagate to
     * other clones without manual git surgery. */
    char refspec[DOTTA_REFSPEC_MAX];
    int n = snprintf(
        refspec, sizeof(refspec), "+%s:%s",
        SALT_REF, SALT_REF
    );
    if (n < 0 || (size_t) n >= sizeof(refspec)) {
        git_remote_free(remote);
        return ERROR(
            ERR_INTERNAL, "Salt refspec buffer too small"
        );
    }

    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    git_err = git_remote_fetch(remote, &refs, &fetch_opts, NULL);
    transfer_op_end(xfer, git_err);
    git_remote_free(remote);

    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to fetch '%s' from '%s'", SALT_REF, remote_name
        );
    }

    /* Validate the bytes we just landed. This is the salt acquisition
     * boundary: a malformed salt must never persist in refs/dotta/salt
     * where a later inspect would read it as canonical or salt_load
     * would surface a deferred, cryptic decrypt failure. */
    uint8_t scratch[KDF_SALT_SIZE];
    err = salt_load(repo, scratch);
    /* Salt is public — no wipe. */
    if (err) {
        /* Roll the local ref back to its prior state so the failed adopt
         * leaves nothing behind. Best-effort: a local ref write failing
         * here is extraordinarily rare and does not change the diagnostic
         * the caller acts on. */
        if (prior_exists) {
            git_reference *restored = NULL;
            int rc = git_reference_create(
                &restored, repo, SALT_REF, &prior_oid, 1, NULL
            );
            if (rc == 0) {
                git_reference_free(restored);
            }
        } else {
            git_reference_remove(repo, SALT_REF);
        }

        /* Normalize every validation failure (wrong size, missing blob,
         * non-commit object) to a single ERR_CRYPTO surface so callers
         * route uniformly — fold salt_load's specific cause into the
         * message rather than chaining, since error_wrap would inherit
         * salt_load's varied codes (ERR_CRYPTO / ERR_NOT_FOUND / ERR_GIT)
         * and split the callers' handling. */
        error_t *malformed = ERROR(
            ERR_CRYPTO,
            "Remote salt is malformed; remote repo may be corrupt (%s)",
            error_message(err)
        );
        error_free(err);
        return malformed;
    }

    return NULL;
}

/*
 * Local-ciphertext census: "is any blob in any local profile branch
 * encrypted?", answered key-free (content_classify is header-only) so it
 * runs before any passphrase is available. Gates the divergent-salt
 * decision — replacing a salt that keys live ciphertext bricks it
 * (deterministic SIV), so an adopt is safe only when this comes back empty.
 */

/* Payload for the census tree-walk. */
typedef struct {
    git_repository *repo;   /* borrowed; for content_classify blob loads */
    bool found;             /* set on the first ciphertext blob */
    error_t *error;         /* set if content_classify fails (owned) */
} salt_census_t;

/*
 * Tree-walk callback. Returns 0 to continue, -1 to stop; the stop reason is
 * disambiguated by the payload — `found` set means ciphertext located,
 * `error` set means classification failed. gitops_tree_walk maps the -1 to
 * a non-NULL error_t that the driver discards in favour of the payload.
 */
static int salt_census_cb(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    (void) root;
    salt_census_t *data = (salt_census_t *) payload;

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    content_kind_t kind;
    error_t *err = content_classify(
        data->repo, git_tree_entry_id(entry), &kind
    );
    if (err) {
        data->error = err;
        return -1;
    }

    if (kind != CONTENT_PLAINTEXT) {
        data->found = true;
        return -1;  /* ENCRYPTED or UNSUPPORTED_VERSION */
    }

    return 0;
}

/*
 * Walk every local profile branch — including disabled ones, whose
 * ciphertext a salt swap bricks just the same — and report whether any blob
 * classifies as ciphertext. Short-circuits on the first hit. Lists branches
 * via sys/gitops directly and skips the local-only dotta-worktree anchor
 * inline, so infra/salt takes no core/ dependency. Propagates any error so
 * the caller can fail closed.
 */
static error_t *local_has_ciphertext(
    git_repository *repo,
    bool *out_in_use
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_in_use);

    *out_in_use = false;

    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return error_wrap(err, "Failed to list local branches for salt census");
    }

    for (size_t i = 0; i < branches->count; i++) {
        const char *branch = branches->items[i];

        /* dotta-worktree is the local-only empty HEAD anchor, never a
         * profile branch — skip it (the salt ref lives outside refs/heads
         * and is never walked here either). */
        if (strcmp(branch, "dotta-worktree") == 0) {
            continue;
        }

        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, branch, &tree, NULL);
        if (err) {
            err = error_wrap(err, "Failed to load tree for branch '%s'", branch);
            goto cleanup;
        }

        salt_census_t data = { .repo = repo, .found = false, .error = NULL };
        error_t *walk_err = gitops_tree_walk(tree, salt_census_cb, &data);
        git_tree_free(tree);

        if (data.error) {
            error_free(walk_err);  /* benign stop wrapper */
            err = data.error;
            goto cleanup;
        }
        if (data.found) {
            error_free(walk_err); /* benign stop wrapper */
            *out_in_use = true;
            goto cleanup;            /* short-circuit remaining branches */
        }
        if (walk_err) {
            err = walk_err;  /* genuine walk-machinery failure */
            goto cleanup;
        }
    }

    err = NULL;  /* walked every branch; no ciphertext */

cleanup:
    string_array_free(branches);
    return err;
}

/*
 * Would replacing the local salt brick local data? True iff a valid local
 * salt exists AND some local ciphertext depends on it. Fails CLOSED: any
 * uncertainty returns true, because a false "not in use" green-lights an
 * adopt that destroys data while a false "in use" only costs a manual
 * reconcile.
 *
 *   local salt absent / malformed → derives nothing → not in use
 *   local salt unreadable for any other reason → can't prove safe → in use
 *   local salt valid → run the census; a census error → in use
 */
static bool salt_local_in_use(git_repository *repo) {
    uint8_t scratch[KDF_SALT_SIZE];
    error_t *lerr = salt_load(repo, scratch);
    /* Salt is public — no wipe. */
    if (lerr) {
        error_code_t code = lerr->code;
        error_free(lerr);
        return !(code == ERR_NOT_FOUND || code == ERR_CRYPTO);
    }

    bool in_use = false;
    error_t *cerr = local_has_ciphertext(repo, &in_use);
    if (cerr) {
        error_free(cerr);
        return true;  /* census error → fail closed */
    }
    return in_use;
}

/*
 * Remote salt status relative to the local ref, by commit-OID compare (the
 * OID-vs-byte exactness rationale lives on the public salt_reconcile_t).
 * DIVERGENT subsumes the local-absent case: a joiner with no salt must
 * converge to the remote's.
 */
typedef enum {
    SALT_REMOTE_ABSENT,     /* remote does not advertise refs/dotta/salt */
    SALT_REMOTE_EQUAL,      /* advertised OID == local ref target */
    SALT_REMOTE_DIVERGENT,  /* advertised OID != local target (incl. local-absent) */
} salt_remote_status_t;

/*
 * Inspect the remote salt without transferring objects: connect + ls, then
 * compare the advertised refs/dotta/salt OID against the local ref target.
 * Read-only and dry-run-safe. Transport failure surfaces as an error (which
 * salt_resolve folds to UNREACHABLE); a remote that simply lacks
 * the ref is ABSENT, never an error.
 */
static error_t *salt_inspect_remote(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    salt_remote_status_t *out_status
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(out_status);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    bool present = false;
    git_oid remote_oid;
    error_t *err = probe_remote_salt(remote, xfer, &present, &remote_oid);
    git_remote_free(remote);
    if (err) {
        /* Transport failure — propagate so the caller can skip salt
         * reconciliation best-effort. */
        return err;
    }

    if (!present) {
        *out_status = SALT_REMOTE_ABSENT;
        return NULL;
    }

    /* Remote advertises the ref. Compare its commit OID against the
     * local ref target. A missing local ref is DIVERGENT (a joiner that
     * has no salt yet must converge to the remote's). */
    git_oid local_oid;
    git_err = git_reference_name_to_id(&local_oid, repo, SALT_REF);
    if (git_err == GIT_ENOTFOUND) {
        *out_status = SALT_REMOTE_DIVERGENT;
        return NULL;
    }
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    *out_status = git_oid_equal(&local_oid, &remote_oid)
        ? SALT_REMOTE_EQUAL
        : SALT_REMOTE_DIVERGENT;
    return NULL;
}

error_t *salt_resolve(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    salt_reconcile_t *out_decision
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(out_decision);

    salt_remote_status_t status;
    error_t *err = salt_inspect_remote(repo, remote_name, xfer, &status);
    if (err) {
        /* Transport / lookup failure folds to UNREACHABLE: the caller skips
         * salt reconciliation best-effort, and the fetch phase carries the
         * authoritative "remote unreachable" diagnostic. */
        error_free(err);
        *out_decision = SALT_RECONCILE_UNREACHABLE;
        return NULL;
    }

    switch (status) {
        case SALT_REMOTE_EQUAL:
            *out_decision = SALT_RECONCILE_EQUAL;
            return NULL;

        case SALT_REMOTE_ABSENT: {
            /* Establish publishes THIS machine's salt, so a valid local one
             * must exist. A repo with no local salt (or a malformed one) has
             * nothing to publish — distinguish the two so the caller never
             * claims an establish it cannot perform (the establish guard). */
            uint8_t scratch[KDF_SALT_SIZE];
            error_t *lerr = salt_load(repo, scratch);  /* public — no wipe */
            if (lerr) {
                error_free(lerr);
                *out_decision = SALT_RECONCILE_NO_LOCAL_SALT;
            } else {
                *out_decision = SALT_RECONCILE_ESTABLISH;
            }
            return NULL;
        }

        case SALT_REMOTE_DIVERGENT:
            /* Fail closed: salt_local_in_use returns true on any
             * uncertainty, so ADOPT (which overwrites the local salt) is
             * reached only when no local ciphertext can be bricked. */
            *out_decision = salt_local_in_use(repo)
                ? SALT_RECONCILE_CONFLICT
                : SALT_RECONCILE_ADOPT;
            return NULL;
    }

    /* salt_inspect_remote yields exactly one of three statuses; fold any
     * hypothetical out-of-range value to the best-effort skip. */
    *out_decision = SALT_RECONCILE_UNREACHABLE;
    return NULL;
}
