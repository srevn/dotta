/**
 * epoch.c - The repository's epoch: implementation
 *
 * Six entry points:
 *   - epoch_init            — mint the salt beside the pair given + write
 *                             commit/tree/blobs (idempotent)
 *   - epoch_load            — walk ref → commit → tree → blobs, validate, copy
 *   - epoch_push            — push refs/dotta/epoch to a remote
 *   - epoch_fetch           — obtain, validate, then install refs/dotta/epoch
 *                             from a remote
 *   - epoch_resolve         — pure fact-finder for cmd_sync's epoch policy
 *   - epoch_find_ciphertext — the keymgr's witness source, over the census's walk
 *
 * Every entry point validates inputs, manages libgit2 object lifetimes via local
 * cleanup blocks, and translates libgit2 error codes through `error_from_git`.
 * The module never holds resources across return.
 *
 * The push/fetch primitives speak libgit2 directly rather than going through
 * `sys/gitops::gitops_*_branches` — those build branch-specific `refs/heads/...`
 * refspecs internally, and "abstract over arbitrary refspec sync" is not yet a
 * recurring need (this is the only consumer). The acquisition side differs in
 * kind and not only in refspec: gitops fetches with `git_remote_fetch`, which
 * updates the tips a branch fetch is *for*, while `epoch_fetch` downloads the
 * objects and stores no ref, because it installs one only after judging them. A
 * second non-branch consumer would be the moment to extract a helper — of whichever
 * of the two shapes it turns out to want.
 *
 * Blob mode: both blobs are stored as regular files (GIT_FILEMODE_BLOB). The
 * mode is irrelevant to dotta — nothing checks out the tree — but using the
 * standard file mode keeps the tree inspectable via `dotta git show`.
 */

#include "infra/epoch.h"

#include <git2.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "crypto/keymgr.h"
#include "infra/content.h"
#include "sys/entropy.h"
#include "sys/gitops.h"
#include "sys/transfer.h"

/* The local-ciphertext census (defined with the reconcile machinery below);
 * epoch_init gates every fresh mint on it. */
static error_t *local_has_ciphertext(
    git_repository *repo, const uint8_t *local_fp, bool *out_found
);

/**
 * Resolve refs/dotta/epoch to a tree.
 *
 * Returns ERR_NOT_FOUND when the ref is missing, the canonical "uninitialized"
 * diagnostic. Caller is responsible for freeing `*out_tree` via `git_tree_free`
 * on success.
 */
static error_t *resolve_epoch_tree(
    git_repository *repo, git_tree **out_tree
) {
    *out_tree = NULL;

    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, EPOCH_REF);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(
            ERR_NOT_FOUND,
            "Epoch ref '%s' not found",
            EPOCH_REF
        );
    }
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Peel through any annotated-tag layers down to the commit. The ref is created
     * as a direct commit by epoch_init, but peeling defends against future shapes
     * (signed-tag wrappers, symbolic refs) without changing the load semantics. */
    git_object *commit_obj = NULL;
    git_err = git_reference_peel(&commit_obj, ref, GIT_OBJECT_COMMIT);
    git_reference_free(ref);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to peel '%s' to a commit", EPOCH_REF
        );
    }

    git_commit *commit = (git_commit *) commit_obj;
    git_err = git_commit_tree(out_tree, commit);
    git_commit_free(commit);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to load tree from '%s'", EPOCH_REF
        );
    }

    return NULL;
}

/**
 * Read one fixed-size blob from the epoch tree by name.
 *
 * ERR_NOT_FOUND belongs to the ref alone (`resolve_epoch_tree`), so nothing here
 * returns it: a ref that resolves to a commit whose tree lacks a blob is a broken
 * shape, not an uninitialized repository. `epoch_init` reads exactly that
 * distinction to decide whether there is a ref to delete before it mints.
 */
static error_t *read_epoch_blob(
    git_repository *repo, git_tree *tree, const char *name,
    size_t size, uint8_t *out
) {
    const git_tree_entry *entry = git_tree_entry_byname(tree, name);
    if (entry == NULL) {
        return ERROR(
            ERR_CRYPTO,
            "Blob '%s' missing from %s tree",
            name, EPOCH_REF
        );
    }

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return ERROR(
            ERR_CRYPTO,
            "Tree entry '%s' in %s is not a blob",
            name, EPOCH_REF
        );
    }

    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, git_tree_entry_id(entry));
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_object_size_t got = git_blob_rawsize(blob);
    if (got != size) {
        git_blob_free(blob);
        return ERROR(
            ERR_CRYPTO,
            "Blob '%s' in %s has wrong size: %lld bytes (expected %zu)",
            name, EPOCH_REF, (long long) got, size
        );
    }

    memcpy(out, git_blob_rawcontent(blob), size);
    git_blob_free(blob);

    return NULL;
}

/**
 * Read the epoch from a tree, validating both blobs.
 *
 * A failure can leave `*out` half-filled — the salt read before the params blob
 * refused. `epoch_load` zeroes it at its one exit, which is where its header
 * states the promise, so no caller proceeds with stale stack content under a
 * swallowed error code; `read_epoch_commit` makes no such promise and its caller
 * discards a failed read whole. The pair is validated here — the boundary it
 * enters at — with `kdf_validate_params`.
 */
static error_t *read_epoch_tree(
    git_repository *repo, git_tree *tree, kdf_epoch_t *out
) {
    error_t *err = read_epoch_blob(
        repo, tree, EPOCH_SALT_BLOB, KDF_SALT_SIZE, out->salt
    );
    if (err) {
        return err;
    }

    uint8_t params[KDF_PARAMS_SIZE];
    err = read_epoch_blob(
        repo, tree, EPOCH_PARAMS_BLOB, KDF_PARAMS_SIZE, params
    );
    if (err) {
        return err;
    }

    kdf_params_load(params, &out->memory_mib, &out->passes);
    err = kdf_validate_params(out->memory_mib, out->passes);
    if (err) {
        return error_wrap(
            err, "Params blob in %s is out of range", EPOCH_REF
        );
    }

    return NULL;
}

/**
 * Read the epoch from the commit at `oid`, validating both blobs.
 *
 * The ref is never consulted, which is exactly what the acquisition boundary
 * needs: bytes sitting in the object database while `refs/dotta/epoch` still
 * holds whatever it held. An object that is not a commit, or a commit whose tree
 * or blobs the transfer did not carry, refuses here — before anything points at it.
 */
static error_t *read_epoch_commit(
    git_repository *repo, const git_oid *oid, kdf_epoch_t *out
) {
    git_commit *commit = NULL;
    int git_err = git_commit_lookup(&commit, repo, oid);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err), "Failed to load the epoch commit"
        );
    }

    git_tree *tree = NULL;
    git_err = git_commit_tree(&tree, commit);
    git_commit_free(commit);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err), "Failed to load the epoch commit's tree"
        );
    }

    error_t *err = read_epoch_tree(repo, tree, out);
    git_tree_free(tree);

    return err;
}

error_t *epoch_load(git_repository *repo, kdf_epoch_t *out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t *err = resolve_epoch_tree(repo, &tree);
    if (!err) {
        err = read_epoch_tree(repo, tree, out);
        git_tree_free(tree);
    }
    if (err) {
        memset(out, 0, sizeof(*out));  /* the header's promise, made once */
    }

    return err;
}

error_t *epoch_init(
    git_repository *repo, uint16_t memory_mib, uint8_t passes,
    kdf_epoch_t *out, bool *out_repaired
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    if (out_repaired) {
        *out_repaired = false;
    }

    /* Idempotency: if the ref already resolves to a valid epoch, treat as success
     * and hand that epoch back. A user re-running `dotta init` on an existing
     * repo must not regenerate the epoch — that would silently invalidate every
     * encrypted blob in the repo. */
    error_t *probe_err = epoch_load(repo, out);
    if (probe_err == NULL) {
        return NULL;  /* already initialized */
    }

    /* The ref yielded no epoch. Unreadable or gone, its bytes are unavailable
     * either way, so no blob's fingerprint can be matched against anything: any
     * ciphertext in this repository (any fingerprint, any version) may be keyed
     * by what the ref held, and minting over it would orphan that ciphertext
     * permanently. One census answers both because it is one danger. */
    bool any_ciphertext = false;
    error_t *cerr = local_has_ciphertext(repo, NULL, &any_ciphertext);
    if (cerr) {
        /* No absence was proved, so the verdict is the found-ciphertext verdict
         * — do not mint — but the reason is not that reason, and the census's
         * own message names the listing or the object that stopped it. Carry
         * it. The probe goes: what is wrong with the ref is not actionable until
         * the thing that broke the census is, and this refusal is the one blocking
         * it. */
        error_free(probe_err);
        return error_wrap(
            cerr,
            "Cannot tell whether this repository holds encrypted files sealed "
            "under the epoch at '%s', so minting a new one is refused\n\n"
            "Repair the repository and run 'dotta init' again.",
            EPOCH_REF
        );
    }

    if (probe_err->code != ERR_NOT_FOUND) {
        /* The ref is there and yields no epoch. Over reachable ciphertext it
         * may be the unreadable form of the epoch that keys it, so the refusal
         * keeps the probe as its cause — epoch_load names what is wrong with
         * the blob — and the evidence stays in place for a restore. A clean census
         * makes the ref pure noise: delete it, mint fresh, and tell the caller
         * a repair happened. */
        if (any_ciphertext) {
            return error_wrap(
                probe_err,
                "Repository epoch '%s' cannot be read and encrypted files may "
                "be sealed under it\n\n"
                "Minting a new one would seal them away permanently. Restore "
                "the ref instead:\n"
                "  dotta git fetch origin '+refs/dotta/*:refs/dotta/*'\n"
                "or copy it from a machine that still has this repository.",
                EPOCH_REF
            );
        }
        error_free(probe_err);

        int rc = git_reference_remove(repo, EPOCH_REF);
        if (rc < 0) {
            return error_wrap(
                error_from_git(rc),
                "Failed to remove unreadable epoch ref '%s'", EPOCH_REF
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
                "Repository epoch '%s' is missing and encrypted files may be "
                "sealed under it\n\n"
                "Minting a new one would seal them away permanently. Restore "
                "the ref instead:\n"
                "  dotta git fetch origin '+refs/dotta/*:refs/dotta/*'\n"
                "or copy it from a machine that still has this repository.",
                EPOCH_REF
            );
        }
    }

    /* Mint: a fresh salt beside the pair given. entropy_fill scrubs the buffer
     * to zeros on any failure, so a half-populated salt cannot leak out. */
    error_t *err = entropy_fill(out->salt, KDF_SALT_SIZE);
    if (err) {
        memset(out, 0, sizeof(*out));
        return error_wrap(err, "Failed to generate repository salt");
    }
    out->memory_mib = memory_mib;
    out->passes = passes;

    uint8_t params[KDF_PARAMS_SIZE];
    kdf_params_store(params, memory_mib, passes);

    /* Write the two blobs. */
    git_oid salt_oid;
    int git_err = git_blob_create_from_buffer(
        &salt_oid, repo, out->salt, KDF_SALT_SIZE
    );
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to write salt blob"
        );
    }
    git_oid params_oid;
    git_err = git_blob_create_from_buffer(
        &params_oid, repo, params, KDF_PARAMS_SIZE
    );
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to write params blob"
        );
    }

    /* Build a tree holding the two. */
    git_treebuilder *tb = NULL;
    git_err = git_treebuilder_new(&tb, repo, NULL);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to create epoch tree builder"
        );
    }

    git_err = git_treebuilder_insert(
        NULL, tb, EPOCH_SALT_BLOB, &salt_oid, GIT_FILEMODE_BLOB
    );
    if (git_err == 0) {
        git_err = git_treebuilder_insert(
            NULL, tb, EPOCH_PARAMS_BLOB, &params_oid, GIT_FILEMODE_BLOB
        );
    }
    if (git_err < 0) {
        git_treebuilder_free(tb);
        return error_wrap(
            error_from_git(git_err),
            "Failed to insert epoch blobs into tree"
        );
    }

    git_oid tree_oid;
    git_err = git_treebuilder_write(&tree_oid, tb);
    git_treebuilder_free(tb);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to write epoch tree"
        );
    }

    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, repo, &tree_oid);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to look up newly-written epoch tree"
        );
    }

    /* Build a signature with the same fallback policy as orphan-branch creation,
     * so a fresh machine without git config can still init. */
    git_signature *sig = NULL;
    error_t *sig_err = gitops_get_signature(&sig, repo);
    if (sig_err) {
        git_tree_free(tree);
        return error_wrap(
            sig_err, "Failed to get signature for epoch commit"
        );
    }

    /* Orphan commit (no parents) writing directly to refs/dotta/epoch. The message
     * is purely diagnostic; nothing in dotta parses it. */
    git_oid commit_oid;
    git_err = git_commit_create(
        &commit_oid,
        repo,
        EPOCH_REF,
        sig, sig,
        NULL,                      /* encoding: default */
        "Initialize repository epoch",
        tree,
        0, NULL                    /* no parents = orphan */
    );

    git_signature_free(sig);
    git_tree_free(tree);

    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to commit epoch to '%s'", EPOCH_REF
        );
    }

    return NULL;
}

error_t *epoch_push(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_ARG(remote_name[0] != '\0', "Remote name cannot be empty");

    /* Skip the network round-trip when the local ref does not exist — `dotta
     * init` populates it but a `dotta sync` on a freshly-cloned encryption-disabled
     * repo may not have one yet. */
    git_reference *local_ref = NULL;
    int git_err = git_reference_lookup(&local_ref, repo, EPOCH_REF);
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

    /* Non-force refspec: an epoch push must be fast-forward. Two machines that
     * independently `dotta init`ed and now race their epochs to the same remote
     * will see the second one fail here — surfaced as a regular non-fast-forward
     * Git error so the user understands they need to reconcile. */
    char *refspecs[] = { EPOCH_REF ":" EPOCH_REF };
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
 * Probe the remote's advertised `refs/dotta/epoch`.
 *
 * Uses `git_remote_connect` + `git_remote_ls` so the absence diagnostic is "remote
 * does not advertise this ref" — distinct from "fetch failed for transport
 * reasons". `git_remote_ls` transfers no byte payload, so the connect uses FETCH
 * direction purely to align the credential path with whatever the caller does next.
 *
 * The advertised commit OID is the fact both callers came for, and it is copied
 * to `*out_oid` when — and only when — the ref is advertised, `*out_present`
 * being what says whether to read it. `inspect_remote_epoch` compares it against
 * the local ref without transferring a blob; `epoch_fetch` downloads it and,
 * once proved, installs it.
 *
 * The prober never owns the connection: it leaves the remote connected and the
 * caller's `git_remote_free` closes the transport. That is what lets `epoch_fetch`
 * download over the very connection that made the advertisement, so the OID it
 * validates is the one that connection named rather than whatever the remote's
 * ref has moved to since.
 *
 * Returns NULL with `*out_present` set; never surfaces "ref missing" as an error
 * code (that is the load-bearing return value of this predicate).
 */
static error_t *probe_remote_epoch(
    git_remote *remote, transfer_context_t *xfer, bool *out_present,
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
        return error_from_git(git_err);
    }

    for (size_t i = 0; i < heads_len; i++) {
        if (heads[i] == NULL || heads[i]->name == NULL
            || strcmp(heads[i]->name, EPOCH_REF) != 0) {
            continue;
        }
        *out_present = true;
        git_oid_cpy(out_oid, &heads[i]->oid);
        break;
    }

    return NULL;
}

error_t *epoch_fetch(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    kdf_epoch_t *out
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

    /* Look before taking. The advertisement gives a clean ERR_NOT_FOUND surface
     * for "this remote is not a dotta repository", where asking for a ref the
     * remote lacks surfaces a generic Git error indistinguishable from real
     * transport failure by code alone. The commit it names is the one this call
     * acquires: the probe leaves the connection open and the download below runs
     * on it, so nothing the remote does meanwhile can substitute another commit
     * for the one that was judged. */
    bool present = false;
    git_oid advertised;
    error_t *err = probe_remote_epoch(remote, xfer, &present, &advertised);
    if (err) {
        git_remote_free(remote);
        return err;
    }
    if (!present) {
        git_remote_free(remote);
        return ERROR(
            ERR_NOT_FOUND, "Remote '%s' does not advertise '%s'",
            remote_name, EPOCH_REF
        );
    }

    git_fetch_options fetch_opts;
    git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);

    transfer_configure_callbacks(
        &fetch_opts.callbacks, xfer, GIT_DIRECTION_FETCH
    );

    /* A refspec with no destination means "want these objects, store no ref for
     * them", and `git_remote_download` — unlike `git_remote_fetch` — never updates
     * tips, so it writes no FETCH_HEAD either. The remote epoch's bytes become
     * readable at `advertised` while refs/dotta/epoch still holds whatever it
     * held. */
    char *refspecs[] = { EPOCH_REF };
    git_strarray refs = { refspecs, 1 };

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    git_err = git_remote_download(remote, &refs, &fetch_opts);
    transfer_op_end(xfer, git_err);
    git_remote_free(remote);  /* freeing the remote closes the transport */

    if (git_err < 0) {
        /* Bare, matching epoch_push: the boundaries (sync's adopt arm, clone's
         * acquisition gate) each attach their own single layer of context. */
        return error_from_git(git_err);
    }

    /* Judge the bytes while no ref names them. This is the epoch acquisition
     * boundary, so it owns the "is this a well-formed epoch?" check — and there
     * is nothing to undo when the answer is no, because a malformed remote epoch
     * never stood in refs/dotta/epoch for a later inspect to read as canonical
     * or a later load to surface as a deferred, cryptic decrypt failure. */
    kdf_epoch_t fetched;
    err = read_epoch_commit(repo, &advertised, &fetched);
    /* The epoch is public — no wipe. */
    if (err) {
        /* Normalize every validation failure (wrong size, missing blob, a pair
         * out of range, a non-commit object) to a single ERR_CRYPTO surface so
         * callers route uniformly — fold the read's specific cause into the message
         * rather than chaining, since error_wrap would inherit its varied codes
         * (ERR_CRYPTO / ERR_GIT) and split the callers' handling. */
        error_t *malformed = ERROR(
            ERR_CRYPTO,
            "Remote epoch is malformed; remote repo may be corrupt (%s)",
            error_message(err)
        );
        error_free(err);
        return malformed;
    }

    /* Install, and only now: the one mutation this function makes, and its last
     * step. The write is forced — the local ref is replaced wholesale by the
     * remote's — which is safe because the only caller that reaches a *divergent*
     * local epoch, `cmd_sync`'s adopt path, gates the fetch on the key-free census
     * proving no reachable ciphertext (any commit, any branch) is keyed by the
     * epoch being replaced. Clone reaches a missing (not divergent) local epoch,
     * so there is nothing to overwrite. Deliberate epoch rotation remains
     * unsupported end-to-end: a re-minted epoch cannot even be published (the
     * push is non-force), and a clone whose ciphertext the old epoch keys lands
     * on CONFLICT, not adopt. NULL ref_out: libgit2 frees the handle it makes. */
    git_err = git_reference_create(NULL, repo, EPOCH_REF, &advertised, 1, NULL);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err),
            "Failed to point '%s' at the epoch fetched from '%s'",
            EPOCH_REF, remote_name
        );
    }

    /* Hand over exactly what the validation proved, and only once the ref carries
     * it — the caller never re-reads the ref it just watched move. */
    if (out != NULL) {
        *out = fetched;
    }

    return NULL;
}

/*
 * The ciphertext walk: every blob reachable from any local branch's full history
 * — disabled profiles included — classified key-free by its header
 * (content_classify is header-only, the epoch fingerprint is public), with every
 * ciphertext presented to a callback until it stops the walk. Two askers: the
 * census — "does the repository hold ciphertext keyed by a given epoch?", which
 * gates the divergent-epoch decision, because replacing an epoch that keys
 * reachable ciphertext bricks it (deterministic SIV), and *reachable* means the
 * full history, not the tips: `dotta show`/`revert`/`diff` decrypt blobs at any
 * `@commit`, every one of them under the current epoch — and the keymgr's witness
 * source, "is there a ciphertext of this epoch a fresh master opens?" Two sites
 * answering one question — what ciphertext of this epoch does the repository
 * hold — get one walker, so neither can skip a branch or forget an object the
 * other remembers.
 */

/* One ciphertext the walk met: the binding it stands under, what its header says,
 * and its bytes for as long as the callback runs. Plaintext blobs never reach a
 * callback. */
typedef struct {
    const char *branch;         /* the profile */
    const char *storage_path;   /* the tree path, root ‖ name */
    const git_oid *oid;         /* the blob object, borrowed from the tree entry */
    content_kind_t kind;        /* ENCRYPTED or UNSUPPORTED_VERSION */
    const uint8_t *epoch_fp;    /* set iff ENCRYPTED: the header's; else NULL */
    const uint8_t *data;        /* the blob, borrowed while the callback runs */
    size_t size;                /* its length, the header included */
} epoch_ciphertext_t;

/* The asker's callback: continue, or stop with its answer in its payload. */
typedef error_t *(*epoch_ciphertext_fn)(
    const epoch_ciphertext_t *ct,
    void *payload,
    bool *stop
);

/* The walk's own payload, shared across every branch. */
typedef struct {
    git_repository *repo;       /* borrowed; for blob loads */
    hashmap_t *seen;            /* borrowed; visited (object, branch, path) */
    epoch_ciphertext_fn fn;     /* the asker */
    void *payload;              /* the asker's, carried untouched */
    const char *branch;         /* the branch under walk */
    bool stopped;               /* the asker stopped the walk */
    error_t *error;             /* the walk could not prove anything (owned) */
} epoch_walk_t;

/*
 * Tree-walk callback (pre-order). Returns 0 to continue, 1 to skip an
 * already-visited subtree, -1 to stop; the stop reason is disambiguated by the
 * payload — `stopped` means the asker answered, `error` means the walk could
 * not prove anything. gitops_tree_walk maps the -1 to a non-NULL error_t that
 * the driver discards in favour of the payload.
 */
static int epoch_walk_cb(
    const char *root, const git_tree_entry *entry, void *payload
) {
    epoch_walk_t *walk = payload;

    /* Only trees descend and only blobs carry content; anything else (a submodule
     * commit) has no bytes under this epoch. */
    git_object_t type = git_tree_entry_type(entry);
    if (type != GIT_OBJECT_BLOB && type != GIT_OBJECT_TREE) {
        return 0;
    }

    /* The unit of the walk is the binding, not the object: one blob standing at
     * two paths, or at one path under two branches, is two witnesses (the SIV
     * binds the path, the pair the profile), and each must be presented. So the
     * visited set keys by object, branch and path, and prunes a subtree only
     * where the same tree stands at the same path of the same branch — where
     * every binding beneath it recurs. History shares objects heavily between
     * commits, and orphan profile branches share none, so this is still one visit
     * per object in practice. The key's parts are bounded: the branch by its
     * refname (gitops_build_refname), the path by PATH_MAX (checked here). */
    const git_oid *oid = git_tree_entry_id(entry);
    char path[PATH_MAX];
    int n = snprintf(
        path, sizeof(path), "%s%s", root, git_tree_entry_name(entry)
    );
    if (n < 0 || (size_t) n >= sizeof(path)) {
        walk->error = ERROR(
            ERR_INVALID_ARG, "Tree path too long in '%s': %s%s",
            walk->branch, root, git_tree_entry_name(entry)
        );
        return -1;
    }

    char oid_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_hex, sizeof(oid_hex), oid);

    char key[GIT_OID_SHA1_HEXSIZE + DOTTA_REFNAME_MAX + PATH_MAX + 3];
    (void) snprintf(key, sizeof(key), "%s:%s:%s", oid_hex, walk->branch, path);
    if (hashmap_has(walk->seen, key)) {
        return (type == GIT_OBJECT_TREE) ? 1 : 0;
    }
    error_t *err = hashmap_set(walk->seen, key, NULL);
    if (err) {
        walk->error = err;
        return -1;
    }

    if (type == GIT_OBJECT_TREE) {
        return 0;  /* first visit: descend */
    }

    content_kind_t kind;
    uint8_t fp[KDF_EPOCH_FP_SIZE];
    err = content_classify(walk->repo, oid, &kind, fp);
    if (err) {
        walk->error = err;
        return -1;
    }
    if (kind == CONTENT_PLAINTEXT) {
        return 0;
    }

    /* A ciphertext: present it with its bytes. The second open is a cached object
     * lookup, paid for the few blobs that are ciphertext. */
    gitops_blob_view_t view;
    err = gitops_blob_view_open(walk->repo, oid, &view);
    if (err) {
        walk->error = err;
        return -1;
    }

    const epoch_ciphertext_t ct = {
        .branch       = walk->branch,
        .storage_path = path,
        .oid          = oid,
        .kind         = kind,
        .epoch_fp     = kind == CONTENT_ENCRYPTED ? fp : NULL,
        .data         = view.data,
        .size         = view.size,
    };
    bool stop = false;
    err = walk->fn(&ct, walk->payload, &stop);
    gitops_blob_view_close(&view);
    if (err) {
        walk->error = err;
        return -1;
    }
    if (stop) {
        walk->stopped = true;
        return -1;
    }
    return 0;
}

/*
 * Walk the full history of every local branch and present every ciphertext to
 * `fn` until it stops the walk. Lists branches via sys/gitops and skips the
 * local-only dotta-worktree anchor inline, so infra/epoch takes no core/
 * dependency; the revwalk speaks libgit2 directly the way sys/stats does.
 * Propagates any error so the caller can fail closed.
 *
 * Including the listing's own. Every asker here acts on an ABSENCE of ciphertext
 * — the licence to mint, to adopt, or to take a passphrase as given — and a branch
 * listing is not a proof of one: libgit2 skips a ref it cannot open or parse
 * rather than reporting it (sys/gitops.h), so a `refs/heads` it may traverse
 * but not read yields an EMPTY array and no error at all. The anchor is the proof
 * this module holds: dotta-worktree stands in every repository that reaches here
 * — `repo_open` refuses one without it, and `cmd_init` makes it before the first
 * census — and the walk already names it, to skip it. A listing without it did
 * not list this repository.
 *
 * That catches a listing that lost everything. One that lost a single unreadable
 * ref while the anchor still reads it cannot, and that limit stays libgit2's,
 * stated where the listing is made.
 */
static error_t *walk_ciphertext(
    git_repository *repo, epoch_ciphertext_fn fn, void *payload
) {
    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) {
        return error_wrap(
            err, "Failed to list local branches for the ciphertext walk"
        );
    }
    if (!string_array_contains(branches, "dotta-worktree")) {
        string_array_free(branches);
        return ERROR(
            ERR_GIT,
            "This repository's branch listing came back without "
            "'dotta-worktree', so it did not list this repository and nothing "
            "can be concluded about the encrypted files it holds\n\n"
            "Git skips a ref it cannot read instead of reporting it — check "
            "that the refs under '%s' are readable.",
            git_repository_path(repo)
        );
    }

    hashmap_t *seen = hashmap_create(0);
    if (!seen) {
        string_array_free(branches);
        return ERROR(
            ERR_MEMORY, "Failed to allocate the ciphertext walk's visited set"
        );
    }

    epoch_walk_t walk = {
        .repo = repo, .seen = seen, .fn = fn, .payload = payload,
    };
    git_revwalk *walker = NULL;

    for (size_t i = 0; i < branches->count && !walk.stopped; i++) {
        const char *branch = branches->items[i];

        /* The anchor, whose presence in the listing was the proof above: an empty
         * HEAD, never a profile branch, and nothing to walk. (The epoch ref lives
         * outside refs/heads and is never walked here either.) */
        if (strcmp(branch, "dotta-worktree") == 0) {
            continue;
        }
        walk.branch = branch;

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

        for (;;) {
            /* Classified, not compared: GIT_ITEROVER is the branch walked out,
             * and a negative code is a walk that ended early — which has proved
             * no absence, and an absence is what both callers act on. */
            git_oid commit_oid;
            git_err = git_revwalk_next(&commit_oid, walker);
            if (git_err == GIT_ITEROVER) {
                break;
            }
            if (git_err < 0) {
                err = error_from_git(git_err);
                goto cleanup;
            }

            git_commit *commit = NULL;
            git_err = git_commit_lookup(&commit, repo, &commit_oid);
            if (git_err < 0) {
                err = error_from_git(git_err);
                goto cleanup;
            }

            /* A commit whose root tree was already walked under this branch
             * (identical content in an earlier commit) contributes nothing new
             * — skip it before loading the tree. The key is the walk's: object,
             * branch, path — the root's path being empty. */
            char oid_hex[GIT_OID_SHA1_HEXSIZE + 1];
            git_oid_tostr(oid_hex, sizeof(oid_hex), git_commit_tree_id(commit));

            char key[GIT_OID_SHA1_HEXSIZE + DOTTA_REFNAME_MAX + 3];
            (void) snprintf(key, sizeof(key), "%s:%s:", oid_hex, branch);
            if (hashmap_has(seen, key)) {
                git_commit_free(commit);
                continue;
            }
            err = hashmap_set(seen, key, NULL);
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

            error_t *walk_err = gitops_tree_walk(tree, epoch_walk_cb, &walk);
            git_tree_free(tree);

            if (walk.error) {
                error_free(walk_err);  /* benign stop wrapper */
                err = walk.error;
                goto cleanup;
            }
            if (walk.stopped) {
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

    /* Falling out of the loop is the walk finished: every assignment to `err`
     * inside it goes straight to the label, so `err` is still the listing's NULL.
     * A reader of a fail-closed walk should not have to re-derive that. */

cleanup:
    if (walker) {
        git_revwalk_free(walker);
    }
    hashmap_free(seen, NULL);
    string_array_free(branches);
    return err;
}

/*
 * The census. Attribution is by the blob header's epoch fingerprint. With a
 * fingerprint to match (`local_fp` non-NULL), only ciphertext this epoch keys
 * counts — foreign ciphertext (pulled from a remote under its own epoch) neither
 * pins the local epoch nor blocks converging to the epoch that CAN decrypt it —
 * and a version this build cannot attribute fails closed. With no fingerprint
 * (`local_fp` NULL), any ciphertext counts — the caller has no epoch to attribute
 * against, so presence alone must fail closed.
 */
typedef struct {
    const uint8_t *local_fp;    /* the fingerprint to attribute to; NULL: any */
    bool found;                 /* set on the first blob that counts */
} epoch_census_t;

static error_t *epoch_census_cb(
    const epoch_ciphertext_t *ct, void *payload, bool *stop
) {
    epoch_census_t *census = payload;

    /* Any ciphertext counts with no fingerprint to attribute to; an unattributable
     * format fails closed; otherwise only a blob keyed by exactly the epoch in
     * question. A foreign-keyed blob is some other epoch's concern. */
    if (census->local_fp == NULL
        || ct->kind == CONTENT_UNSUPPORTED_VERSION
        || memcmp(ct->epoch_fp, census->local_fp, KDF_EPOCH_FP_SIZE) == 0) {
        census->found = true;
        *stop = true;
    }
    return NULL;
}

/*
 * Three states in two values, and the error is one of them: an unfinished census
 * proved no absence, and an absence is the whole of what both callers act on.
 * So neither reads `*out_found` past an error — each returns the cause to whoever
 * can name the subject — and the `false` written on that path is a courtesy,
 * not an answer. Failing closed is their policy, not the walk's.
 */
static error_t *local_has_ciphertext(
    git_repository *repo, const uint8_t *local_fp, bool *out_found
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_found);

    epoch_census_t census = { .local_fp = local_fp };
    error_t *err = walk_ciphertext(repo, epoch_census_cb, &census);
    *out_found = !err && census.found;
    return err;
}

/*
 * The witness source. A ciphertext of this epoch is presented with the binding
 * it stands under — the branch, and the tree path — and the keymgr's predicate
 * says whether the master on trial opens it; one object under two bindings is
 * presented under each, since only one of them can be the one it was sealed under.
 * A version this build does not read is never a witness, nor is another epoch's
 * ciphertext: no master here can open either, so they say nothing about a
 * passphrase.
 */
typedef struct {
    uint8_t fp[KDF_EPOCH_FP_SIZE];  /* the epoch's; only its ciphertext shows */
    keymgr_opens_fn accept;         /* the keymgr's predicate */
    void *self;                     /* the predicate's, carried untouched */
    bool accepted;                  /* set when the predicate accepted one */
} epoch_find_t;

static error_t *epoch_find_cb(
    const epoch_ciphertext_t *ct, void *payload, bool *stop
) {
    epoch_find_t *find = payload;

    if (ct->kind != CONTENT_ENCRYPTED
        || memcmp(ct->epoch_fp, find->fp, KDF_EPOCH_FP_SIZE) != 0) {
        return NULL;
    }

    const keymgr_witness_t witness = {
        .ciphertext   = ct->data,
        .len          = ct->size,
        .profile      = ct->branch,
        .storage_path = ct->storage_path,
    };
    bool accepted = false;
    error_t *err = find->accept(find->self, &witness, &accepted);
    if (err) {
        return err;
    }
    if (accepted) {
        find->accepted = true;
        *stop = true;
    }
    return NULL;
}

error_t *epoch_find_ciphertext(
    git_repository *repo, const kdf_epoch_t *epoch, keymgr_opens_fn accept,
    void *self, bool *out_accepted
) {
    CHECK_NULL(repo);
    CHECK_NULL(epoch);
    CHECK_NULL(accept);
    CHECK_NULL(out_accepted);

    epoch_find_t find = { .accept = accept, .self = self };
    kdf_epoch_fingerprint(epoch, find.fp);

    error_t *err = walk_ciphertext(repo, epoch_find_cb, &find);
    *out_accepted = !err && find.accepted;
    return err;
}

/*
 * The divergent branch's one question — not "is the local epoch in use" but "does
 * anything this repository holds depend on the BYTES at refs/dotta/epoch?" The
 * two come apart on a ref that stands and yields no epoch, which is precisely
 * where the salt blob may still be one restore away, and that is the whole of
 * the difference. Five findings out of one load and at most one census:
 *
 *   ref absent             nothing to lose, nothing to attribute   ADOPT
 *   ref yields no epoch    + any ciphertext at all                 DAMAGED
 *   ref yields no epoch    + none                                  ADOPT
 *   an epoch               + ciphertext its fingerprint keys       CONFLICT
 *   an epoch               + none it keys                          ADOPT
 *
 * Three routes to one act, two refusals. The censuses differ where the verdict
 * does not: only a readable epoch has a fingerprint to attribute against, so
 * the top row asks nothing and the two middle rows ask for any ciphertext at
 * all. That is why the caller's adopt line may name the act and never the census.
 *
 * Fails CLOSED by returning: a census that could not finish is an error the caller
 * refuses on, never a verdict. Nothing here writes a value to stand in for a
 * refusal it could not phrase, which is what the bool this replaced had to do —
 * and what it wrote for a ref that yields no epoch was the permissive one.
 *
 * The rationale for each row, and for the row that runs no census, is at
 * `epoch_resolve` in the header; it is the caller's contract, not an internal.
 */
static error_t *decide_divergence(
    git_repository *repo, epoch_reconcile_t *out_decision
) {
    kdf_epoch_t local;
    error_t *lerr = epoch_load(repo, &local);
    /* The epoch is public — no wipe. */

    if (lerr && lerr->code == ERR_NOT_FOUND) {
        /* No bytes at the ref: nothing to make unreachable, and whatever this
         * repository holds was orphaned by whatever removed them. A census here
         * would attribute against a value that does not exist. */
        error_free(lerr);
        *out_decision = EPOCH_RECONCILE_ADOPT;
        return NULL;
    }

    if (lerr) {
        /* The ref stands and yields no epoch, whichever mechanism got there
         * (epoch.h). Its salt blob may be intact and may be the only copy of
         * what keys this repository — but with the pair unreadable no fingerprint
         * can be matched against anything, so the census asks for any ciphertext
         * at all. Its own cause has nothing to add to either verdict: what the
         * blob is wrong about does not change whether something is sealed. */
        error_free(lerr);

        bool any = false;
        error_t *cerr = local_has_ciphertext(repo, NULL, &any);
        if (cerr) {
            return cerr;
        }
        *out_decision = any ? EPOCH_RECONCILE_DAMAGED : EPOCH_RECONCILE_ADOPT;
        return NULL;
    }

    /* A readable epoch: only the ciphertext IT keys pins it. */
    uint8_t fp[KDF_EPOCH_FP_SIZE];
    kdf_epoch_fingerprint(&local, fp);

    bool keyed = false;
    error_t *cerr = local_has_ciphertext(repo, fp, &keyed);
    if (cerr) {
        return cerr;
    }
    *out_decision = keyed ? EPOCH_RECONCILE_CONFLICT : EPOCH_RECONCILE_ADOPT;
    return NULL;
}

/*
 * Remote epoch status relative to the local ref, by commit-OID compare (the
 * OID-vs-byte exactness rationale lives on the public epoch_reconcile_t). DIVERGENT
 * subsumes the local-absent case: a joiner with no epoch must converge to the
 * remote's.
 */
typedef enum {
    EPOCH_REMOTE_ABSENT,     /* remote does not advertise refs/dotta/epoch */
    EPOCH_REMOTE_EQUAL,      /* advertised OID == local ref target */
    EPOCH_REMOTE_DIVERGENT,  /* advertised OID != local target (incl. local-absent) */
} epoch_remote_status_t;

/*
 * Inspect the remote epoch without transferring objects: connect + ls, then compare
 * the advertised refs/dotta/epoch OID against the local ref target. Read-only
 * and dry-run-safe. Transport failure surfaces as an error (which epoch_resolve
 * folds to UNREACHABLE); a remote that simply lacks the ref is ABSENT, never an
 * error.
 */
static error_t *inspect_remote_epoch(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    epoch_remote_status_t *out_status
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
    error_t *err = probe_remote_epoch(remote, xfer, &present, &remote_oid);
    git_remote_free(remote);
    if (err) {
        /* Transport failure — propagate so the caller can skip epoch reconciliation
         * best-effort. */
        return err;
    }

    if (!present) {
        *out_status = EPOCH_REMOTE_ABSENT;
        return NULL;
    }

    /* Remote advertises the ref. Compare its commit OID against the local ref
     * target. A missing local ref is DIVERGENT (a joiner that has no epoch yet
     * must converge to the remote's). */
    git_oid local_oid;
    git_err = git_reference_name_to_id(&local_oid, repo, EPOCH_REF);
    if (git_err == GIT_ENOTFOUND) {
        *out_status = EPOCH_REMOTE_DIVERGENT;
        return NULL;
    }
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    *out_status = git_oid_equal(&local_oid, &remote_oid)
        ? EPOCH_REMOTE_EQUAL
        : EPOCH_REMOTE_DIVERGENT;

    return NULL;
}

error_t *epoch_resolve(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    epoch_reconcile_t *out_decision
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(out_decision);

    epoch_remote_status_t status;
    error_t *err = inspect_remote_epoch(repo, remote_name, xfer, &status);
    if (err) {
        /* Transport / lookup failure folds to UNREACHABLE: the caller skips epoch
         * reconciliation best-effort, and the fetch phase carries the authoritative
         * "remote unreachable" diagnostic. */
        error_free(err);
        *out_decision = EPOCH_RECONCILE_UNREACHABLE;
        return NULL;
    }

    switch (status) {
        case EPOCH_REMOTE_EQUAL:
            *out_decision = EPOCH_RECONCILE_EQUAL;
            return NULL;

        case EPOCH_REMOTE_ABSENT: {
            /* Establish publishes THIS machine's epoch, so a valid local one
             * must exist. A repo whose ref is absent, or stands and yields no
             * epoch, has nothing to publish — distinguish the two so the caller
             * never claims an establish it cannot perform (the establish guard). */
            kdf_epoch_t scratch;
            error_t *lerr = epoch_load(repo, &scratch);
            *out_decision = lerr ? EPOCH_RECONCILE_NO_LOCAL_EPOCH
                                 : EPOCH_RECONCILE_ESTABLISH;

            error_free(lerr);
            return NULL;
        }

        case EPOCH_REMOTE_DIVERGENT:
            /* Five findings, and the fail-closed one is the return: a fetch arm
             * is reached only over bytes nothing here can depend on. */
            return decide_divergence(repo, out_decision);
    }

    /* inspect_remote_epoch yields exactly one of three statuses; fold any
     * hypothetical out-of-range value to the best-effort skip. */
    *out_decision = EPOCH_RECONCILE_UNREACHABLE;
    return NULL;
}
