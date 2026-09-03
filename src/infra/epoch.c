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
 * Every entry point validates inputs, manages libgit2 object lifetimes via local
 * cleanup blocks, and translates libgit2 error codes through `error_from_git`.
 * The module never holds resources across return.
 *
 * The push/fetch primitives speak libgit2 directly rather than going through
 * `sys/gitops::gitops_*_branches` — those build branch-specific `refs/heads/...`
 * refspecs internally, and "abstract over arbitrary refspec sync" is not yet a
 * recurring need (this is the only consumer). If a second non-branch consumer
 * arrives, that's the moment to extract a `gitops_fetch_refspec` helper.
 *
 * Salt-blob mode: stored as a regular file blob (mode 0100644). The mode is
 * irrelevant to dotta — nothing checks it out — but using the standard file mode
 * keeps the tree inspectable via `dotta git show`.
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
#include "base/hashmap.h"
#include "infra/content.h"
#include "sys/entropy.h"
#include "sys/gitops.h"
#include "sys/transfer.h"

/* Standard regular-file mode for the salt blob. Nothing checks out the tree;
 * the choice keeps `git show` / `git ls-tree` output readable. */
#define SALT_BLOB_MODE 0100644

/* The local-ciphertext census (defined with the reconcile machinery below);
 * salt_init gates every fresh mint on it. */
static error_t *local_has_ciphertext(
    git_repository *repo,
    const uint8_t *local_fp,
    bool *out_in_use
);

/**
 * Resolve refs/dotta/salt to a tree.
 *
 * Returns ERR_NOT_FOUND when the ref is missing, the canonical "uninitialized"
 * diagnostic. Caller is responsible for freeing `*out_tree` via `git_tree_free`
 * on success.
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

    /* Peel through any annotated-tag layers down to the commit. The ref is created
     * as a direct commit by salt_init, but peeling defends against future shapes
     * (signed-tag wrappers, symbolic refs) without changing the load semantics. */
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
 * Wipes `out_salt` via memset on every error path so a caller cannot accidentally
 * proceed with stale stack content under a swallowed error code.
 *
 * ERR_NOT_FOUND belongs to the ref alone (`resolve_salt_tree`), so nothing here
 * returns it: a ref that resolves to a commit whose tree carries no salt blob
 * is a broken shape, not an uninitialized repository. `salt_init` reads exactly
 * that distinction to decide whether there is a ref to delete before it mints.
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
            ERR_CRYPTO,
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

error_t *salt_init(git_repository *repo, bool *out_repaired) {
    CHECK_NULL(repo);

    if (out_repaired) {
        *out_repaired = false;
    }

    /* Idempotency: if the ref already resolves and the salt blob is the right
     * size, treat as success. A user re-running `dotta init` on an existing repo
     * must not regenerate the salt — that would silently invalidate every encrypted
     * blob in the repo. */
    uint8_t existing_salt[KDF_SALT_SIZE];
    error_t *probe_err = salt_load(repo, existing_salt);
    if (probe_err == NULL) {
        return NULL;  /* already initialized */
    }

    /* The ref yielded no salt. Damaged or gone, its bytes are unavailable either
     * way, so no blob's fingerprint can be matched against anything: any ciphertext
     * in this repository (any fingerprint, any version) may be keyed by what
     * the ref held, and minting over it would orphan that ciphertext permanently.
     * One census answers both because it is one danger, and a census that cannot
     * prove absence is the same verdict (fail closed). */
    bool any_ciphertext = true;
    error_t *cerr = local_has_ciphertext(repo, NULL, &any_ciphertext);
    if (cerr) {
        error_free(cerr);
        any_ciphertext = true;
    }

    if (probe_err->code != ERR_NOT_FOUND) {
        /* The ref is there and damaged. Over reachable ciphertext it may be the
         * damaged form of the salt that keys it, so the refusal keeps the probe
         * as its cause — salt_load names what is wrong with the blob — and the
         * evidence stays in place for a restore. A clean census makes the ref
         * pure noise: delete it, mint fresh, and tell the caller a repair
         * happened. */
        if (any_ciphertext) {
            return error_wrap(
                probe_err,
                "Repository salt '%s' is malformed and encrypted files depend "
                "on it\n\n"
                "Minting a new one would seal every encrypted file in this "
                "repository away permanently. Restore the ref instead:\n"
                "  dotta git fetch origin 'refs/dotta/*:refs/dotta/*'\n"
                "or copy it from a machine that still has this repository.",
                SALT_REF
            );
        }
        error_free(probe_err);

        int rc = git_reference_remove(repo, SALT_REF);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc),
                "Failed to remove malformed salt ref '%s'", SALT_REF
            );
        }
        if (out_repaired) {
            *out_repaired = true;
        }
    } else {
        /* The ref is gone: nothing to repair, nothing to delete, and nothing
         * for the probe to add — "not found" is what the refusal's own first
         * line already says. Only the census stands between the mint and whatever
         * the ref used to key. */
        error_free(probe_err);

        if (any_ciphertext) {
            return ERROR(
                ERR_CRYPTO,
                "Repository salt '%s' is missing and encrypted files depend "
                "on it\n\n"
                "Minting a new one would seal every encrypted file in this "
                "repository away permanently. Restore the ref instead:\n"
                "  dotta git fetch origin 'refs/dotta/*:refs/dotta/*'\n"
                "or copy it from a machine that still has this repository.",
                SALT_REF
            );
        }
    }

    /* Generate the salt. entropy_fill scrubs the buffer to zeros on any failure,
     * so a half-populated salt cannot leak out. */
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

    /* Build a signature with the same fallback policy as orphan-branch creation,
     * so a fresh machine without git config can still init. */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) {
        git_tree_free(tree);
        return error_wrap(
            sig_err, "Failed to get signature for salt commit"
        );
    }

    /* Orphan commit (no parents) writing directly to refs/dotta/salt. The message
     * is purely diagnostic; nothing in dotta parses it. */
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

    /* Skip the network round-trip when the local ref does not exist — `dotta
     * init` populates it but a `dotta sync` on a freshly-cloned encryption-disabled
     * repo may not have one yet. */
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

    /* Non-force refspec: a salt push must be fast-forward. Two machines that
     * independently `dotta init`ed and now race their salts to the same remote
     * will see the second one fail here — surfaced as a regular non-fast-forward
     * Git error so the user understands they need to reconcile. */
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
        /* Bare: the boundary (cmd_sync's establish arm) prefixes exactly one
         * layer of context, and its warning renders error_message — outermost
         * only — so a wrap here would displace the actual libgit2 reason
         * (non-fast-forward, rejected namespace, auth) with a restatement of
         * what the caller already says. */
        return error_from_git(git_err);
    }

    return NULL;
}

/**
 * Probe the remote's advertised `refs/dotta/salt`.
 *
 * Uses `git_remote_connect` + `git_remote_ls` so the absence diagnostic is "remote
 * does not advertise this ref" — distinct from "fetch failed for transport
 * reasons". `git_remote_ls` transfers no byte payload, so the connect uses FETCH
 * direction purely to align the credential path with the subsequent fetch.
 *
 * When the ref is advertised and `out_oid` is non-NULL, the advertised commit
 * OID is copied out — the hook `salt_inspect_remote` uses to compare against
 * the local ref without transferring the blob. Pass NULL for `out_oid` when only
 * presence matters (the `salt_fetch` case).
 *
 * Returns NULL with `*out_present` set; never surfaces "ref missing" as an error
 * code (that is the load-bearing return value of this predicate).
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
    transfer_context_t *xfer,
    uint8_t *out_salt
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

    /* Two-step probe-then-fetch: check the remote's advertised refs before
     * constructing a refspec that targets a possibly-absent ref. `git_remote_fetch`
     * on a missing ref surfaces a generic Git error indistinguishable from real
     * transport failures by error code alone — the probe gives us a clean
     * ERR_NOT_FOUND surface for the "remote isn't a dotta v7 repo" case. Presence
     * is all we need here; the OID-comparison consumer is salt_inspect_remote. */
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

    /* Capture the current local salt target before the force-fetch overwrites
     * it, so a malformed fetched salt can be rolled back to exactly the prior
     * state: a failed adopt never leaves garbage, and never bricks a valid local
     * salt. */
    git_oid prior_oid;
    bool prior_exists =
        (git_reference_name_to_id(&prior_oid, repo, SALT_REF) == 0);

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);
    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    /* Force update (`+` prefix): the local ref is replaced wholesale by the
     * remote's. This is safe because the only caller that reaches a *divergent*
     * local salt — `cmd_sync`'s adopt path — gates the fetch on the key-free
     * census proving no reachable ciphertext (any commit, any branch) is keyed
     * by the salt being replaced. Clone reaches a missing (not divergent) local
     * salt, so there is nothing to overwrite. Deliberate salt rotation remains
     * unsupported end-to-end: a re-minted salt cannot even be published (the
     * push is non-force), and a clone whose ciphertext the old salt keys lands
     * on CONFLICT, not adopt. */
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
        /* Bare, matching salt_push: the boundaries (sync's adopt arm, clone's
         * acquisition gate) each attach their own single layer of context. */
        return error_from_git(git_err);
    }

    /* Validate the bytes we just landed. This is the salt acquisition boundary:
     * a malformed salt must never persist in refs/dotta/salt where a later inspect
     * would read it as canonical or salt_load would surface a deferred, cryptic
     * decrypt failure. */
    uint8_t scratch[KDF_SALT_SIZE];
    err = salt_load(repo, scratch);
    /* Salt is public — no wipe. */
    if (err) {
        /* Roll the local ref back to its prior state so the failed adopt leaves
         * nothing behind. Best-effort: a local ref write failing here is
         * extraordinarily rare and does not change the diagnostic the caller
         * acts on. */
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

        /* Normalize every validation failure (wrong size, missing blob, non-commit
         * object) to a single ERR_CRYPTO surface so callers route uniformly —
         * fold salt_load's specific cause into the message rather than chaining,
         * since error_wrap would inherit salt_load's varied codes (ERR_CRYPTO /
         * ERR_NOT_FOUND / ERR_GIT) and split the callers' handling. */
        error_t *malformed = ERROR(
            ERR_CRYPTO,
            "Remote salt is malformed; remote repo may be corrupt (%s)",
            error_message(err)
        );
        error_free(err);
        return malformed;
    }

    /* Hand over exactly the bytes the validation proved — the caller never re-reads
     * the ref it just watched move. */
    if (out_salt != NULL) {
        memcpy(out_salt, scratch, KDF_SALT_SIZE);
    }

    return NULL;
}

/*
 * Local-ciphertext census: "does any commit reachable from any local branch carry
 * ciphertext keyed by a given salt?", answered key-free (content_classify is
 * header-only, the salt fingerprint is public) so it runs before any passphrase
 * is available. Gates the divergent-salt decision — replacing a salt that keys
 * reachable ciphertext bricks it (deterministic SIV), and *reachable* means the
 * full history, not the tips: `dotta show`/`revert`/`diff` decrypt blobs at any
 * `@commit`, every one of them under the current salt.
 *
 * Attribution is by the blob header's salt fingerprint. With a fingerprint to
 * match (`local_fp` non-NULL), only ciphertext this salt keys counts — foreign
 * ciphertext (pulled from a remote under its own salt) neither pins the local
 * salt nor blocks converging to the salt that CAN decrypt it. With no fingerprint
 * (`local_fp` NULL), any ciphertext counts — the caller has no salt to attribute
 * against, so presence alone must fail closed.
 */

/* Payload for the census walks, shared across every branch so an object visited
 * under one branch is never re-classified under another. */
typedef struct {
    git_repository *repo;   /* borrowed; for content_classify blob loads */
    const uint8_t *local_fp;/* fingerprint to attribute against; NULL = any */
    hashmap_t *seen;        /* borrowed; visited tree/blob OIDs (hex keys) */
    bool found;             /* set on the first blob that counts */
    error_t *error;         /* set if classification/bookkeeping fails (owned) */
} salt_census_t;

/*
 * Tree-walk callback (pre-order). Returns 0 to continue, 1 to skip an
 * already-visited subtree, -1 to stop; the stop reason is disambiguated by the
 * payload — `found` set means decisive ciphertext located, `error` set means
 * the walk could not prove anything. gitops_tree_walk maps the -1 to a non-NULL
 * error_t that the driver discards in favour of the payload.
 */
static int salt_census_cb(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    (void) root;
    salt_census_t *data = (salt_census_t *) payload;

    /* Only trees descend and only blobs carry content; anything else (a submodule
     * commit) has no bytes under this salt. */
    git_object_t type = git_tree_entry_type(entry);
    if (type != GIT_OBJECT_BLOB && type != GIT_OBJECT_TREE) {
        return 0;
    }

    char oid_hex[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oid_hex, sizeof(oid_hex), git_tree_entry_id(entry));
    if (hashmap_has(data->seen, oid_hex)) {
        /* History shares objects heavily between commits: pruning a visited subtree
         * is what keeps the full-history walk at O(unique objects). */
        return (type == GIT_OBJECT_TREE) ? 1 : 0;
    }
    error_t *err = hashmap_set(data->seen, oid_hex, NULL);
    if (err) {
        data->error = err;
        return -1;
    }

    if (type == GIT_OBJECT_TREE) {
        return 0;  /* first visit: descend */
    }

    content_kind_t kind;
    uint8_t fp[KDF_SALT_FP_SIZE];
    err = content_classify(
        data->repo, git_tree_entry_id(entry), &kind,
        data->local_fp ? fp : NULL
    );
    if (err) {
        data->error = err;
        return -1;
    }

    if (kind == CONTENT_PLAINTEXT) {
        return 0;
    }
    if (data->local_fp == NULL) {
        data->found = true;  /* any ciphertext counts */
        return -1;
    }
    if (kind == CONTENT_UNSUPPORTED_VERSION) {
        data->found = true;  /* unattributable format → fail closed */
        return -1;
    }
    if (memcmp(fp, data->local_fp, KDF_SALT_FP_SIZE) == 0) {
        data->found = true;  /* keyed by exactly the salt in question */
        return -1;
    }
    return 0;  /* foreign-keyed; some other salt's concern */
}

/*
 * Walk the full history of every local branch — disabled profiles included, whose
 * ciphertext a salt swap bricks just the same — and report whether any reachable
 * blob counts under the census rules above. Short-circuits on the first decisive
 * hit. Lists branches via sys/gitops and skips the local-only dotta-worktree
 * anchor inline, so infra/salt takes no core/ dependency; the revwalk speaks
 * libgit2 directly the way sys/stats does. Propagates any error so the caller
 * can fail closed.
 */
static error_t *local_has_ciphertext(
    git_repository *repo,
    const uint8_t *local_fp,
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

    hashmap_t *seen = hashmap_create(0);
    if (!seen) {
        string_array_free(branches);
        return ERROR(ERR_MEMORY, "Failed to allocate salt census visited set");
    }

    salt_census_t data = {
        .repo  = repo,  .local_fp = local_fp, .seen = seen,
        .found = false, .error    = NULL,
    };
    git_revwalk *walker = NULL;

    for (size_t i = 0; i < branches->count && !data.found; i++) {
        const char *branch = branches->items[i];

        /* dotta-worktree is the local-only empty HEAD anchor, never a profile
         * branch — skip it (the salt ref lives outside refs/heads and is never
         * walked here either). */
        if (strcmp(branch, "dotta-worktree") == 0) {
            continue;
        }

        char refname[DOTTA_REFNAME_MAX];
        err = gitops_build_refname(
            refname, sizeof(refname), "refs/heads/%s", branch
        );
        if (err) {
            err = error_wrap(err, "Invalid branch name '%s'", branch);
            goto cleanup;
        }

        int git_err = git_revwalk_new(&walker, repo);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }
        git_revwalk_sorting(walker, GIT_SORT_NONE);
        git_err = git_revwalk_push_ref(walker, refname);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }

        git_oid commit_oid;
        while (git_revwalk_next(&commit_oid, walker) == 0) {
            git_commit *commit = NULL;
            git_err = git_commit_lookup(&commit, repo, &commit_oid);
            if (git_err < 0) {
                err = error_from_git(git_err);
                goto cleanup;
            }

            /* A commit whose root tree was already walked (identical content in
             * an earlier commit or another branch) contributes nothing new —
             * skip it before loading the tree. */
            char tree_hex[GIT_OID_HEXSZ + 1];
            git_oid_tostr(
                tree_hex, sizeof(tree_hex), git_commit_tree_id(commit)
            );
            if (hashmap_has(seen, tree_hex)) {
                git_commit_free(commit);
                continue;
            }
            err = hashmap_set(seen, tree_hex, NULL);
            if (err) {
                git_commit_free(commit);
                goto cleanup;
            }

            git_tree *tree = NULL;
            git_err = git_commit_tree(&tree, commit);
            git_commit_free(commit);
            if (git_err < 0) {
                err = error_from_git(git_err);
                goto cleanup;
            }

            error_t *walk_err = gitops_tree_walk(tree, salt_census_cb, &data);
            git_tree_free(tree);

            if (data.error) {
                error_free(walk_err);  /* benign stop wrapper */
                err = data.error;
                data.error = NULL;
                goto cleanup;
            }
            if (data.found) {
                error_free(walk_err);  /* benign stop wrapper */
                break;                 /* short-circuit; outer loop exits too */
            }
            if (walk_err) {
                err = walk_err;  /* genuine walk-machinery failure */
                goto cleanup;
            }
        }

        git_revwalk_free(walker);
        walker = NULL;
    }

    *out_in_use = data.found;
    err = NULL;

cleanup:
    if (walker) {
        git_revwalk_free(walker);
    }
    hashmap_free(seen, NULL);
    string_array_free(branches);
    return err;
}

/*
 * Would replacing the local salt brick local data? True iff a valid local salt
 * exists AND ciphertext it keys is reachable from some local branch. Fails CLOSED:
 * any uncertainty returns true, because a false "not in use" green-lights an
 * adopt that destroys data while a false "in use" only costs a manual reconcile.
 *
 *   local salt absent / malformed → derives nothing → not in use local salt
 *   unreadable for any other reason → can't prove safe → in use local salt valid
 *   → census against its fingerprint; a census error → in use
 */
static bool salt_local_in_use(git_repository *repo) {
    uint8_t salt[KDF_SALT_SIZE];
    error_t *lerr = salt_load(repo, salt);
    /* Salt is public — no wipe. */
    if (lerr) {
        error_code_t code = lerr->code;
        error_free(lerr);
        return !(code == ERR_NOT_FOUND || code == ERR_CRYPTO);
    }

    uint8_t fp[KDF_SALT_FP_SIZE];
    kdf_salt_fingerprint(salt, fp);

    bool in_use = false;
    error_t *cerr = local_has_ciphertext(repo, fp, &in_use);
    if (cerr) {
        error_free(cerr);
        return true;  /* census error → fail closed */
    }
    return in_use;
}

/*
 * Remote salt status relative to the local ref, by commit-OID compare (the
 * OID-vs-byte exactness rationale lives on the public salt_reconcile_t). DIVERGENT
 * subsumes the local-absent case: a joiner with no salt must converge to the
 * remote's.
 */
typedef enum {
    SALT_REMOTE_ABSENT,     /* remote does not advertise refs/dotta/salt */
    SALT_REMOTE_EQUAL,      /* advertised OID == local ref target */
    SALT_REMOTE_DIVERGENT,  /* advertised OID != local target (incl. local-absent) */
} salt_remote_status_t;

/*
 * Inspect the remote salt without transferring objects: connect + ls, then compare
 * the advertised refs/dotta/salt OID against the local ref target. Read-only
 * and dry-run-safe. Transport failure surfaces as an error (which salt_resolve
 * folds to UNREACHABLE); a remote that simply lacks the ref is ABSENT, never an
 * error.
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
        /* Transport failure — propagate so the caller can skip salt reconciliation
         * best-effort. */
        return err;
    }

    if (!present) {
        *out_status = SALT_REMOTE_ABSENT;
        return NULL;
    }

    /* Remote advertises the ref. Compare its commit OID against the local ref
     * target. A missing local ref is DIVERGENT (a joiner that has no salt yet
     * must converge to the remote's). */
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
        /* Transport / lookup failure folds to UNREACHABLE: the caller skips salt
         * reconciliation best-effort, and the fetch phase carries the authoritative
         * "remote unreachable" diagnostic. */
        error_free(err);
        *out_decision = SALT_RECONCILE_UNREACHABLE;
        return NULL;
    }

    switch (status) {
        case SALT_REMOTE_EQUAL:
            *out_decision = SALT_RECONCILE_EQUAL;
            return NULL;

        case SALT_REMOTE_ABSENT: {
            /* Establish publishes THIS machine's salt, so a valid local one must
             * exist. A repo with no local salt (or a malformed one) has nothing
             * to publish — distinguish the two so the caller never claims an
             * establish it cannot perform (the establish guard). */
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
            /* Fail closed: salt_local_in_use returns true on any uncertainty,
             * so ADOPT (which overwrites the local salt) is reached only when
             * no local ciphertext can be bricked. */
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
