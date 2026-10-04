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
 * cleanup blocks, and words each libgit2 failure itself, libgit2's sentence after
 * its own (`error_git`); a static trusts the entry point that called it and checks
 * nothing again. The module never holds resources across return.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "crypto/keymgr.h"
#include "infra/content.h"
#include "sys/entropy.h"
#include "sys/gitops.h"
#include "sys/stage.h"
#include "sys/transfer.h"

/* The local-ciphertext census (defined with the reconcile machinery below);
 * epoch_init gates every fresh mint on it. */
static error_t epoch_census(
    git_repository *repo, const uint8_t *local_fp, bool *out_found
);

/**
 * Read one fixed-size blob from the epoch tree by name.
 *
 * ERR_NOT_FOUND belongs to the ref alone (`epoch_load`), so nothing here returns
 * it: a ref that resolves to a commit whose tree lacks a blob is a broken shape,
 * not an uninitialized repository. `epoch_init` reads exactly that distinction
 * to decide whether there is a ref to delete before it mints.
 *
 * Every refusal names the blob and never a ref: the tree is the ref's at a load
 * and an advertisement's at a fetch, which no ref names until it is proven, so
 * the caller says where (base/error.h "Messages").
 */
static error_t epoch_read_blob(
    git_repository *repo, git_tree *tree, const char *name,
    size_t size, uint8_t *out
) {
    const git_tree_entry *entry = git_tree_entry_byname(tree, name);
    if (entry == NULL) {
        return error_create(ERR_CRYPTO, "Blob '%s' missing from the tree", name);
    }

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return error_create(ERR_CRYPTO, "Tree entry '%s' is not a blob", name);
    }

    git_blob *blob = NULL;
    int rc = git_blob_lookup(&blob, repo, git_tree_entry_id(entry));
    if (rc < 0) return error_git(rc, "Cannot read '%s'", name);

    git_object_size_t got = git_blob_rawsize(blob);
    if (got != size) {
        git_blob_free(blob);
        return error_create(
            ERR_CRYPTO, "Blob '%s' has wrong size: %lld bytes (expected %zu)",
            name, (long long) got, size
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
 * swallowed error code; `epoch_read_commit` makes no such promise and its callers
 * discard a failed read whole. The pair is validated here — the boundary it enters
 * at — with `kdf_validate_params`.
 */
static error_t epoch_read_tree(
    git_repository *repo, git_tree *tree, kdf_epoch_t *out
) {
    error_t err = epoch_read_blob(
        repo, tree, EPOCH_SALT_BLOB, KDF_SALT_SIZE, out->salt
    );
    if (err) return err;

    uint8_t params[KDF_PARAMS_SIZE];
    err = epoch_read_blob(
        repo, tree, EPOCH_PARAMS_BLOB, KDF_PARAMS_SIZE, params
    );
    if (err) return err;

    kdf_params_load(params, &out->memory_mib, &out->passes);
    err = kdf_validate_params(out->memory_mib, out->passes);
    if (err) return error_wrap(err, "Params blob is out of range");

    return NULL;
}

/**
 * Read the epoch from the commit at `oid`, validating both blobs.
 *
 * The ref is never consulted, which is exactly what its two readers need: the
 * acquisition boundary (epoch_fetch), judging bytes that sit in the object database
 * while `refs/dotta/epoch` still holds whatever it held — an object that is not
 * a commit, or a commit whose tree or blobs the transfer did not carry, refuses
 * here, before anything points at it — and the reconcile (epoch_resolve,
 * epoch_decide), judging the commit its one read of the ref named.
 */
static error_t epoch_read_commit(
    git_repository *repo, const git_oid *oid, kdf_epoch_t *out
) {
    git_commit *commit = NULL;
    int rc = git_commit_lookup(&commit, repo, oid);
    if (rc < 0) {
        return error_git(rc, "Failed to load the epoch commit");
    }

    git_tree *tree = NULL;
    rc = git_commit_tree(&tree, commit);
    git_commit_free(commit);
    if (rc < 0) {
        return error_git(rc, "Failed to load the epoch commit's tree");
    }

    error_t err = epoch_read_tree(repo, tree, out);
    git_tree_free(tree);

    return err;
}

error_t epoch_load(git_repository *repo, kdf_epoch_t *out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* The ref's tree, or its absence proven (sys/gitops.h gitops_reference_find):
     * a packed-refs that will not parse is a failure, and never the "no epoch"
     * whose readers adopt without a census or mint over sealed files. The absence
     * is the one ERR_NOT_FOUND this module says, the canonical "uninitialized"
     * (the header). */
    git_tree *tree = NULL;
    error_t err = gitops_reference_tree(repo, EPOCH_REF, &tree);
    if (!err) {
        err = tree ? epoch_read_tree(repo, tree, out)
                   : error_create(ERR_NOT_FOUND, "Epoch ref '%s' not found", EPOCH_REF);
        git_tree_free(tree);
    }
    if (err) {
        memset(out, 0, sizeof(*out));  /* the header's promise, made once */
    }

    return err;
}

error_t epoch_init(
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
    error_t probe_err = epoch_load(repo, out);
    if (probe_err == NULL) {
        return NULL;  /* already initialized */
    }

    /* The ref yielded no epoch. Unreadable or gone, its bytes are unavailable
     * either way, so no blob's fingerprint can be matched against anything: any
     * ciphertext in this repository (any fingerprint, any version) may be keyed
     * by what the ref held, and minting over it would orphan that ciphertext
     * permanently. One census answers both because it is one danger. */
    bool any_ciphertext = false;
    error_t err = epoch_census(repo, NULL, &any_ciphertext);
    if (err) {
        /* No absence was proved, so the verdict is the found-ciphertext verdict
         * — do not mint — but the reason is not that reason, and the census's
         * own message names the first thing it could not read, and where. Carry
         * it. The probe goes: what is wrong with the ref is not actionable until
         * the thing that broke the census is, and this refusal is the one blocking
         * it. */
        return error_wrap(
            err, "Cannot tell whether this repository holds encrypted files sealed "
            "under the epoch at '%s', so minting a new one is refused", EPOCH_REF
        );
    }

    if (error_code(probe_err) != ERR_NOT_FOUND) {
        /* The ref is there and yields no epoch. Over reachable ciphertext it
         * may be the unreadable form of the epoch that keys it, so the refusal
         * keeps the probe as its cause — epoch_load names what is wrong with
         * the blob — and the evidence stays in place for a restore. A clean census
         * makes the ref pure noise: delete it, mint fresh, and tell the caller
         * a repair happened. */
        if (any_ciphertext) {
            return error_wrap(
                probe_err, "Repository epoch '%s' cannot be read and encrypted files "
                "may be sealed under it; a fetch of '" EPOCH_RESTORE_REFSPEC "' from "
                "a remote that holds this repository's epoch restores it", EPOCH_REF
            );
        }

        int rc = git_reference_remove(repo, EPOCH_REF);
        if (rc < 0) {
            return error_git(rc, "Failed to remove unreadable epoch ref '%s'", EPOCH_REF);
        }
        if (out_repaired) {
            *out_repaired = true;
        }
    } else {
        /* The ref is gone: nothing to repair, nothing to delete, and nothing
         * for the probe to add — "not found" is what the refusal's own first
         * line already says. Only the census stands between the mint and whatever
         * the ref used to key. */
        if (any_ciphertext) {
            return error_create(
                ERR_CRYPTO, "Repository epoch '%s' is missing and encrypted files may be "
                "sealed under it; a fetch of '" EPOCH_RESTORE_REFSPEC "' from a remote "
                "that holds this repository's epoch restores it", EPOCH_REF
            );
        }
    }

    /* Mint: a fresh salt beside the pair given. entropy_fill scrubs the buffer
     * to zeros on any failure, so a half-populated salt cannot leak out; its
     * failure is the mint's first, said with the rest below. */
    out->memory_mib = memory_mib;
    out->passes = passes;

    uint8_t params[KDF_PARAMS_SIZE];
    kdf_params_store(params, memory_mib, passes);

    err = entropy_fill(out->salt, KDF_SALT_SIZE);

    /* The mint is a root commit on a ref nothing names: the two blobs on an
     * orphan's stage, committed. The census and the delete above ran on an absent
     * ref, and the stage refuses a ref that appeared since — at its open, and
     * again at the commit — which is the immutability the epoch wants: a second
     * commit on this ref would seal every blob away. The message is purely
     * diagnostic; nothing in dotta parses it. */
    stage_t *stage = NULL;
    if (!err) err = stage_orphan(repo, EPOCH_REF, &stage);
    if (!err) {
        err = stage_put(
            stage, EPOCH_SALT_BLOB, out->salt, KDF_SALT_SIZE, GIT_FILEMODE_BLOB, NULL
        );
    }
    if (!err) {
        err = stage_put(
            stage, EPOCH_PARAMS_BLOB, params, KDF_PARAMS_SIZE, GIT_FILEMODE_BLOB,
            NULL
        );
    }
    if (!err) {
        err = stage_commit(stage, "Initialize repository epoch", NULL);
    }
    stage_free(stage);

    /* The stage names the ref where its refusal is the ref's, and the blob where
     * it is a blob's — the salt's or the params' — and the salt's draw names
     * its bytes alone, so the mint is said over every step, the ref never twice */
    if (err) {
        memset(out, 0, sizeof(*out));
        return error_wrap(err, "Cannot mint the repository epoch");
    }

    return NULL;
}

error_t epoch_push(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);

    /* Skip the network round-trip when the local ref does not exist — `dotta
     * init` populates it but a `dotta sync` on a freshly-cloned encryption-disabled
     * repo may not have one yet. */
    bool exists = false;
    error_t err = gitops_reference_exists(repo, EPOCH_REF, &exists);
    if (err) return err;
    if (!exists) return NULL;

    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc < 0) return error_git(rc, "Cannot push '%s' to remote '%s'", EPOCH_REF, remote_name);

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
    rc = git_remote_push(remote, &refs, &push_opts);
    transfer_op_end(xfer, rc);

    /* The act and the remote in its words, then libgit2's reason — a
     * non-fast-forward, a rejected namespace, the credentials — read before the
     * free as every transfer's is (sys/gitops.c gitops_fetch_remote): the whole
     * of what cmd_sync's establish arm prints */
    err = rc < 0
        ? error_git(rc, "Cannot push '%s' to remote '%s'", EPOCH_REF, remote_name)
        : NULL;
    git_remote_free(remote);
    return err;
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
 * being what says whether to read it. `epoch_inspect_remote` compares it against
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
static error_t epoch_probe_remote(
    git_remote *remote, transfer_context_t *xfer, bool *out_present,
    git_oid *out_oid
) {
    *out_present = false;

    git_remote_callbacks callbacks;
    git_remote_init_callbacks(&callbacks, GIT_REMOTE_CALLBACKS_VERSION);
    transfer_configure_callbacks(&callbacks, xfer, GIT_DIRECTION_FETCH);

    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    int rc = git_remote_connect(
        remote, GIT_DIRECTION_FETCH, &callbacks, NULL, NULL
    );
    transfer_op_end(xfer, rc);
    if (rc < 0) {
        return error_git(rc, "Cannot list the references of remote '%s'", git_remote_name(remote));
    }

    const git_remote_head **heads = NULL;
    size_t heads_len = 0;
    rc = git_remote_ls(&heads, &heads_len, remote);
    if (rc < 0) {
        return error_git(rc, "Cannot list the references of remote '%s'", git_remote_name(remote));
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

error_t epoch_fetch(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    kdf_epoch_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);

    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc < 0) return error_git(rc, "Cannot fetch '%s' from remote '%s'", EPOCH_REF, remote_name);

    /* Look before taking. The advertisement gives a clean ERR_NOT_FOUND surface
     * for "this remote is not a dotta repository", where asking for a ref the
     * remote lacks surfaces a generic Git error indistinguishable from real
     * transport failure by code alone. The commit it names is the one this call
     * acquires: the probe leaves the connection open and the download below runs
     * on it, so nothing the remote does meanwhile can substitute another commit
     * for the one that was judged. */
    bool present = false;
    git_oid advertised;
    error_t err = epoch_probe_remote(remote, xfer, &present, &advertised);
    if (err) {
        git_remote_free(remote);
        return err;
    }
    if (!present) {
        git_remote_free(remote);
        return error_create(
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

    /* The download's sentence is read before the close: the download leaves the
     * transport connected (remote.c git_remote_download disconnects nothing,
     * where git_remote_push does before it returns), and freeing the remote writes
     * a flush to a connection the remote may have reset (transports/smart.c
     * git_smart__close), whose failure would be the sentence read. The act and
     * the remote in its words, as epoch_push's: what the boundaries print whole
     * (sync's adopt arm, clone's acquisition gate). */
    transfer_op_begin(xfer, GIT_DIRECTION_FETCH);
    rc = git_remote_download(remote, &refs, &fetch_opts);
    transfer_op_end(xfer, rc);
    err = rc < 0
        ? error_git(rc, "Cannot fetch '%s' from remote '%s'", EPOCH_REF, remote_name)
        : NULL;
    git_remote_free(remote);
    if (err) return err;

    /* Judge the bytes while no ref names them. This is the epoch acquisition
     * boundary, so it owns the "is this a well-formed epoch?" check — and there
     * is nothing to undo when the answer is no, because a malformed remote epoch
     * never stood in refs/dotta/epoch for a later inspect to read as canonical
     * or a later load to surface as a deferred, cryptic decrypt failure. */
    kdf_epoch_t fetched;
    err = epoch_read_commit(repo, &advertised, &fetched);
    /* The epoch is public — no wipe. */
    if (err) {
        /* One ERR_CRYPTO surface for every way the read can fail, so clone and
         * sync route it alike — a wrap would keep the cause's code (ERR_CRYPTO
         * or ERR_GIT) and split them. The ways are two kinds, and the code cannot
         * tell them apart: bytes the read refused (a wrong size, a missing blob,
         * a pair out of range, an object that is no commit), the remote's; and
         * an object that would not load after a download that completed, this
         * store's. So the words blame neither: the act that failed, and the root's
         * — the blob the read refused, which object it was loading and the
         * mechanism's sentence for it, one node as every libgit2 failure is
         * (base/error.h error_git), or the bound the pair broke beneath the wrap
         * naming the params blob. The act names the advertisement, where the
         * reader names no ref (epoch_read_blob). A re-mint keeps one fact's words
         * (base/error.h "Messages"). */
        return error_create(
            ERR_CRYPTO, "Cannot adopt the epoch remote '%s' advertises: %s",
            remote_name, error_message(error_root(err))
        );
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
    rc = git_reference_create(NULL, repo, EPOCH_REF, &advertised, 1, NULL);
    if (rc < 0) {
        return error_git(
            rc, "Failed to point '%s' at the epoch fetched from '%s'", EPOCH_REF, remote_name
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
 *
 * One rule serves both, since a yes needs one look and a no needs every look:
 * an answer the asker stops on stands, whatever the walk could not read on the
 * way; a walk that ends without one fails on the first thing it could not read.
 * So the walk passes over what will not read — a branch's tip, a history, a tree,
 * a blob — keeps the first of them, and goes on: the census still fails closed,
 * its absence unproven, and a witness beyond a broken object still opens.
 */

/* One ciphertext the walk met: the binding it stands under, what its header says,
 * and its bytes for as long as the callback runs. Plaintext blobs never reach a
 * callback. */
typedef struct {
    const char *branch;         /* the profile */
    const char *storage_path;   /* the tree path the walk joined, lent for the call */
    const git_oid *oid;         /* the blob object, borrowed from the tree entry */
    content_kind_t kind;        /* ENCRYPTED or UNSUPPORTED_VERSION */
    const uint8_t *epoch_fp;    /* set iff ENCRYPTED: the header's; else NULL */
    const uint8_t *data;        /* the blob, borrowed while the callback runs */
    size_t size;                /* its length, the header included */
} epoch_ciphertext_t;

/* The asker's callback: true stops the walk, the answer in its payload. */
typedef bool (*epoch_ciphertext_fn)(const epoch_ciphertext_t *ct, void *payload);

/* The walk's own payload, shared across every branch. */
typedef struct {
    git_repository *repo;      /* borrowed; for blob loads */
    hashmap_t *seen;           /* borrowed; visited (object, mode, branch, path) */
    buffer_t key;              /* a binding's key, spelled per entry */
    epoch_ciphertext_fn fn;    /* the asker */
    void *payload;             /* the asker's, carried untouched */
    const char *branch;        /* the branch under walk */
    bool stopped;              /* the asker answered: every loop of the walk ends */
    error_t failure;           /* the first thing passed over, unread; the answer
                                * where the asker never stops the walk */
} epoch_walk_t;

/*
 * Walk visitor (pre-order): a binding met before is skipped, a tree with every
 * binding beneath it; a subtree is loaded before libgit2 descends into it, a
 * blob is judged by its header, and a ciphertext presented to the asker, whose
 * answer stops the walk and is kept for the driver, whose history and branch
 * loops end with it. It never fails: what it cannot read — a subtree that will
 * not load, a blob it cannot judge or open — it keeps on the walk where the walk
 * holds none yet, named by its binding, and passes over (the rule above).
 */
static error_t epoch_present_blob(
    const char *path, const git_tree_entry *entry, void *payload,
    gitops_next_t *next
) {
    epoch_walk_t *walk = payload;

    /* Only trees descend and only blobs carry content; anything else (a submodule
     * commit) has no bytes under this epoch. */
    git_object_t type = git_tree_entry_type(entry);
    if (type != GIT_OBJECT_BLOB && type != GIT_OBJECT_TREE) {
        return NULL;
    }

    /* The unit of the walk is a binding as it is judged, not the object. One
     * blob at two paths, or at one path under two branches, is two witnesses —
     * the SIV binds the path, the pair the profile — and each must be presented;
     * one blob at one path under two modes is two judgments, a link's bytes being
     * its target and never a ciphertext (infra/content.h content_classify). So
     * the visited set keys by object, mode, branch and path — every input of
     * the judgment — and a binding met before is skipped: a tree only where the
     * same tree stands at the same path of the same branch, where every binding
     * beneath it recurs, modes and all, a tree's id fixing its entries'. History
     * shares objects heavily between commits, and orphan profile branches share
     * none, so this is still one visit per object in practice; a root tree two
     * commits share costs one visit of each entry it holds. The key is spelled
     * here and nowhere else, and no two bindings spell one: ':' stands in none
     * of the id's hex, the mode's octal or a branch name (a refname refuses it),
     * so the last field is the whole path, whatever it holds. */
    const git_oid *oid = git_tree_entry_id(entry);
    char oid_hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_hex, sizeof(oid_hex), oid);

    buffer_clear(&walk->key);
    buffer_appendf(
        &walk->key, "%s:%06o:%s:%s", oid_hex,
        (unsigned) git_tree_entry_filemode(entry), walk->branch, path
    );
    if (!hashmap_add(walk->seen, walk->key.data, NULL)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }

    /* A first visit to a tree descends, and the tree is loaded here first: libgit2
     * loads a subtree after its visitor has seen it and ends the whole walk where
     * one will not load (tree.c tree_walk), every binding after it unmet. One
     * that will not load is kept and skipped, so libgit2 never tries it; one
     * that loads is libgit2's to load again, from its object cache for a tree
     * under 4 KiB (cache.c), read twice where larger. */
    if (type == GIT_OBJECT_TREE) {
        git_tree *subtree = NULL;
        int rc = git_tree_lookup(&subtree, walk->repo, oid);
        if (rc < 0) {
            if (!walk->failure) {
                walk->failure = error_git(rc, "Cannot read '%s:%s'", walk->branch, path);
            }
            *next = GITOPS_NEXT_SKIP;
            return NULL;
        }
        git_tree_free(subtree);
        return NULL;
    }

    /* Judged as the entry it stands in: a link's bytes are its target, never a
     * ciphertext, whatever they begin with (infra/content.h); and a ciphertext
     * opened to be presented with its bytes — the second open a cached object
     * lookup, paid for the few blobs that are ciphertext. */
    content_kind_t kind;
    uint8_t fp[KDF_EPOCH_FP_SIZE];
    gitops_blob_view_t view;
    error_t err = content_classify(
        walk->repo, oid, git_tree_entry_filemode(entry), &kind, fp
    );
    if (!err && kind == CONTENT_PLAINTEXT) return NULL;
    if (!err) err = gitops_blob_view_open(walk->repo, oid, &view);

    /* A blob it cannot judge or open may be a ciphertext, so it is kept and passed
     * over, said as the question it left open. The cause is the classifier's
     * own, one per such blob; the binding is wrapped onto the one kept alone. */
    if (err) {
        if (!walk->failure) {
            walk->failure = error_wrap(
                err, "Cannot tell whether '%s:%s' is encrypted", walk->branch, path
            );
        }
        return NULL;
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
    walk->stopped = walk->fn(&ct, walk->payload);
    gitops_blob_view_close(&view);
    if (walk->stopped) {
        *next = GITOPS_NEXT_STOP;
    }
    return NULL;
}

/*
 * One commit of a branch's history: its tree walked, every binding in it presented
 * (epoch_present_blob). A commit whose tree will not load is kept on the walk
 * where the walk holds no failure yet, named by its branch, and the history goes
 * on past it: an older commit may hold the witness.
 */
static void epoch_walk_commit(epoch_walk_t *walk, const git_oid *commit_oid) {
    git_commit *commit = NULL;
    git_tree *tree = NULL;
    int rc = git_commit_lookup(&commit, walk->repo, commit_oid);
    if (rc == 0) {
        rc = git_commit_tree(&tree, commit);
        git_commit_free(commit);
    }
    if (rc < 0) {
        if (!walk->failure) {
            walk->failure = error_git(
                rc, "Cannot read the history of 'refs/heads/%s'", walk->branch
            );
        }
        return;
    }

    /* Every commit's tree is walked: what an earlier commit already held is skipped
     * at its first entry (epoch_present_blob), so a tree two commits share costs
     * a visit of each entry it holds and nothing beneath them. The visitor passes
     * over what it cannot read, so what the tree walk can fail on is libgit2's
     * own load of a subtree the visitor loaded a moment before. */
    error_t err = gitops_tree_walk(tree, epoch_present_blob, walk);
    git_tree_free(tree);
    if (!walk->failure) walk->failure = err;
}

/*
 * Walk the full history of every local branch and present every ciphertext to
 * `fn` until it stops the walk. Every asker here acts on an ABSENCE of ciphertext
 * — the licence to mint, to adopt, or to take a passphrase as given — so the
 * listing must be complete or an error, and sys/gitops's is (its header; listed
 * there rather than through core/profiles, so infra/epoch takes no core/
 * dependency). The walk holds no proof of its own: it answers by the rule at
 * the head of the walk, an asker's answer whatever was passed over, else the
 * first thing it could not read, which names where it stands — sync prints the
 * census's cause whole beneath its own question (`epoch_reconcile`). The revwalk
 * speaks libgit2 directly the way sys/stats does. The epoch ref lives outside
 * refs/heads and is never walked.
 */
static error_t epoch_walk(
    git_repository *repo, epoch_ciphertext_fn fn, void *payload
) {
    /* The branches, their names and the bindings already seen, in a frame of
     * the walk's own: each read inside the loop and dropped with it. The set
     * owns its keys, so one spelled in the walk's buffer is copied into the frame
     * only as it takes a slot. What the walk keeps is the error module's, never
     * the frame's (base/error.h "Lifetime"). */
    arena_t *frame = arena_create(0);
    epoch_walk_t walk = {
        .repo = repo, .seen = hashmap_create(frame, 0), .fn = fn, .payload = payload,
    };

    /* The branches, complete or an error (sys/gitops.h): a listing that refused
     * leaves none to walk and proves no absence, and its failure is the first
     * the walk keeps. */
    string_array_t branches = { 0 };
    walk.failure = gitops_list_branches(repo, frame, &branches);

    for (size_t i = 0; i < branches.count && !walk.stopped; i++) {
        walk.branch = branches.entries[i];

        /* Read back by the name the listing gave it, under the rule the listing
         * read it by — the reference rule, never the branch rule, which refuses
         * two shapes a reference can hold (HEAD, a leading '-'): the census walks
         * what Git holds, and a ref it refused would refuse every unlock and
         * every mint beside it. The name is spelled as long as Git made it, and
         * its tip is read as every tip is (sys/gitops.h gitops_reference_commit),
         * its failure naming the reference: a branch gone since the listing holds
         * nothing now, and one whose tip will not read is kept and passed over. */
        const char *refname = arena_str_format(frame, "refs/heads/%s", walk.branch);
        git_commit *tip = NULL;
        error_t err = gitops_reference_commit(repo, refname, &tip);
        if (!walk.failure) walk.failure = err;
        if (!tip) continue;

        /* The history from that tip, in no order of its own: the push copies
         * the tip's id, so the tip is freed once it is taken */
        git_revwalk *walker = NULL;
        int rc = git_revwalk_new(&walker, repo);
        if (rc == 0) {
            git_revwalk_sorting(walker, GIT_SORT_NONE);
            rc = git_revwalk_push(walker, git_commit_id(tip));
        }
        git_commit_free(tip);

        /* Each commit until the history ends, the asker answers or the history
         * will not go on. Classified, not compared: GIT_ITEROVER is the branch
         * walked out, and a negative code a history that ended early, which has
         * proved no absence — kept, and the branches after it walked. */
        for (git_oid commit_oid; rc == 0 && !walk.stopped;) {
            rc = git_revwalk_next(&commit_oid, walker);
            if (rc == 0) epoch_walk_commit(&walk, &commit_oid);
        }
        if (rc < 0 && rc != GIT_ITEROVER && !walk.failure) {
            walk.failure = error_git(rc, "Cannot read the history of '%s'", refname);
        }
        git_revwalk_free(walker);    /* NULL-safe: revwalk.c git_revwalk_free */
    }

    buffer_deinit(&walk.key);
    arena_free(frame);

    return walk.stopped ? NULL : walk.failure;
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

static bool epoch_census_cb(const epoch_ciphertext_t *ct, void *payload) {
    epoch_census_t *census = payload;

    /* Any ciphertext counts with no fingerprint to attribute to; an unattributable
     * format fails closed; otherwise only a blob keyed by exactly the epoch in
     * question. A foreign-keyed blob is some other epoch's concern. */
    if (census->local_fp == NULL
        || ct->kind == CONTENT_UNSUPPORTED_VERSION
        || memcmp(ct->epoch_fp, census->local_fp, KDF_EPOCH_FP_SIZE) == 0) {
        census->found = true;
    }
    return census->found;
}

/*
 * Three states in two values, and the error is one of them: a census that found
 * nothing and could not read everything proved no absence, and an absence is
 * the whole of what both callers act on — where one that found a ciphertext answers
 * whatever it passed over (the walk's rule). So neither reads `*out_found` past
 * an error — each returns the cause to whoever can name the subject — and the
 * `false` written on that path is a courtesy, not an answer. Failing closed is
 * their policy, not the walk's.
 */
static error_t epoch_census(
    git_repository *repo, const uint8_t *local_fp, bool *out_found
) {
    epoch_census_t census = { .local_fp = local_fp };
    error_t err = epoch_walk(repo, epoch_census_cb, &census);
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

static bool epoch_find_cb(const epoch_ciphertext_t *ct, void *payload) {
    epoch_find_t *find = payload;

    if (ct->kind != CONTENT_ENCRYPTED
        || memcmp(ct->epoch_fp, find->fp, KDF_EPOCH_FP_SIZE) != 0) {
        return false;
    }

    const keymgr_witness_t witness = {
        .ciphertext   = ct->data,
        .len          = ct->size,
        .profile      = ct->branch,
        .storage_path = ct->storage_path,
    };
    find->accepted = find->accept(find->self, &witness);
    return find->accepted;
}

error_t epoch_find_ciphertext(
    git_repository *repo, const kdf_epoch_t *epoch, keymgr_opens_fn accept,
    void *self, bool *out_accepted
) {
    CHECK_NULL(repo);
    CHECK_NULL(epoch);
    CHECK_NULL(accept);
    CHECK_NULL(out_accepted);

    epoch_find_t find = { .accept = accept, .self = self };
    kdf_epoch_fingerprint(epoch, find.fp);

    error_t err = epoch_walk(repo, epoch_find_cb, &find);
    *out_accepted = !err && find.accepted;
    return err;
}

/*
 * The divergent branch's one question — not "is the local epoch in use" but "does
 * anything this repository holds depend on the BYTES at refs/dotta/epoch?" The
 * two come apart on a ref that stands and yields no epoch, which is precisely
 * where the salt blob may still be one restore away, and that is the whole of
 * the difference. Five findings out of the one read of the ref epoch_resolve
 * made — `local`, the zero id where none stood — the bytes at that commit, and
 * at most one census:
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
static error_t epoch_decide(
    git_repository *repo, const git_oid *local, epoch_reconcile_t *out_decision
) {
    if (git_oid_is_zero(local)) {
        /* No bytes at the ref: nothing to make unreachable, and whatever this
         * repository holds was orphaned by whatever removed them. A census here
         * would attribute against a value that does not exist. */
        *out_decision = EPOCH_RECONCILE_ADOPT;
        return NULL;
    }

    /* The bytes at the commit the remote's was compared against, never a second
     * read of the ref, which could judge a commit the compare never saw. The
     * epoch is public — no wipe. */
    kdf_epoch_t epoch;
    error_t err = epoch_read_commit(repo, local, &epoch);

    if (err) {
        /* The ref stands and yields no epoch, whichever mechanism got there
         * (epoch.h). Its salt blob may be intact and may be the only copy of
         * what keys this repository — but with the pair unreadable no fingerprint
         * can be matched against anything, so the census asks for any ciphertext
         * at all. Its own cause has nothing to add to either verdict: what the
         * blob is wrong about does not change whether something is sealed. */
        bool any = false;
        err = epoch_census(repo, NULL, &any);
        if (err) return err;
        *out_decision = any ? EPOCH_RECONCILE_DAMAGED : EPOCH_RECONCILE_ADOPT;
        return NULL;
    }

    /* A readable epoch: only the ciphertext IT keys pins it. */
    uint8_t fp[KDF_EPOCH_FP_SIZE];
    kdf_epoch_fingerprint(&epoch, fp);

    bool keyed = false;
    err = epoch_census(repo, fp, &keyed);
    if (err) return err;
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
} epoch_remote_t;

/*
 * Inspect the remote epoch without transferring objects: connect + ls, then compare
 * the advertised refs/dotta/epoch OID against the local one the caller read —
 * the zero id where no local ref stands. Read-only and dry-run-safe. Its failure
 * is the remote's alone, the lookup or the transport (which epoch_resolve folds
 * to UNREACHABLE); a remote that simply lacks the ref is ABSENT, never an error.
 */
static error_t epoch_inspect_remote(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    const git_oid *local, epoch_remote_t *out_status
) {
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc < 0) {
        return error_git(
            rc, "Cannot list the references of remote '%s'", remote_name
        );
    }

    /* The advertisement, its sentence read before the free closes the transport
     * (epoch_probe_remote reads it at the failing call) */
    bool present = false;
    git_oid remote_oid;
    error_t err = epoch_probe_remote(remote, xfer, &present, &remote_oid);
    git_remote_free(remote);
    if (err) return err;

    if (!present) {
        *out_status = EPOCH_REMOTE_ABSENT;
        return NULL;
    }

    /* Remote advertises the ref: its commit OID against the local one. No
     * advertised id is the zero id, so a missing local ref compares DIVERGENT —
     * a joiner that has no epoch yet must converge to the remote's. */
    *out_status = git_oid_equal(local, &remote_oid)
        ? EPOCH_REMOTE_EQUAL
        : EPOCH_REMOTE_DIVERGENT;

    return NULL;
}

error_t epoch_resolve(
    git_repository *repo, const char *remote_name, transfer_context_t *xfer,
    epoch_reconcile_t *out_decision
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(xfer);
    CHECK_NULL(out_decision);

    /* This store's own ref, read before the remote is asked: two questions, and
     * a failure here is the run's and never the remote's. It names the ref
     * (sys/gitops.h gitops_reference_find), which the caller's line does not.
     * The one read: every finding below judges the commit it names. */
    git_oid local;
    error_t err = gitops_reference_oid(repo, EPOCH_REF, &local);
    if (err) return err;

    /* The remote's half alone now: a lookup or transport failure folds to
     * UNREACHABLE — the caller skips epoch reconciliation best-effort, and the
     * fetch phase carries the authoritative "remote unreachable" diagnostic. */
    epoch_remote_t status;
    err = epoch_inspect_remote(repo, remote_name, xfer, &local, &status);
    if (err) {
        *out_decision = EPOCH_RECONCILE_UNREACHABLE;
        return NULL;
    }

    switch (status) {
        case EPOCH_REMOTE_EQUAL:
            *out_decision = EPOCH_RECONCILE_EQUAL;
            return NULL;

        case EPOCH_REMOTE_ABSENT: {
            /* Establish publishes THIS machine's epoch, so a valid local one
             * must exist, judged at the commit read above. A repo whose ref is
             * absent, or stands and yields no epoch, has nothing to publish —
             * distinguish the two so the caller never claims an establish it
             * cannot perform (the establish guard). */
            kdf_epoch_t scratch;
            *out_decision = git_oid_is_zero(&local)
                || epoch_read_commit(repo, &local, &scratch)
                ? EPOCH_RECONCILE_NO_LOCAL_EPOCH : EPOCH_RECONCILE_ESTABLISH;

            return NULL;
        }

        case EPOCH_REMOTE_DIVERGENT:
            /* Five findings, and the fail-closed one is the return: a fetch arm
             * is reached only over bytes nothing here can depend on. A census
             * that could not finish is said as the question it could not answer,
             * here where it was asked, as epoch_init says its own */
            err = epoch_decide(repo, &local, out_decision);
            if (err) {
                return error_wrap(
                    err, "Whether any encrypted file here is sealed under the local "
                    "epoch could not be determined"
                );
            }
            return NULL;
    }

    /* epoch_inspect_remote yields exactly one of three statuses */
    CHECK_ARG(false, "a remote epoch status no enumerator names");
}
