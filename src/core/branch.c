/**
 * branch.c - A profile's branch, over one tree
 *
 * The handle is a tree and the sheet read from it once, at the first question,
 * its failure kept beside it. The walk is the decode core/branch.h states, in
 * two halves: one walk of the tree for the blobs (branch_step), then the sheet's
 * directory items, with the names the first half found a blob standing at carried
 * to the second.
 */

#include "core/branch.h"

#include <stdlib.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/heap.h"
#include "core/metadata.h"
#include "infra/label.h"
#include "sys/gitops.h"

struct branch {
    git_repository *repo;   /* Borrowed: the sheet's blob is read through it */
    char *profile;          /* The handle's copy, named over every failure */
    const git_tree *tree;   /* The caller's, or `own` */
    git_tree *own;          /* The tip branch_load read; NULL over a caller's tree */
    metadata_t *sheet;      /* NULL until a question loads it, and beside a failure */
    error_t sheet_failure;  /* Why it would not load; NULL where it did or is not asked yet */
};

/* One walk: what the tree's half carries to the directory half, and the visitor's
 * failure past the tree walk it stopped */
typedef struct {
    const metadata_t *sheet;    /* NULL: a tolerant walk past a sheet that will not load */
    branch_visit_fn visit;      /* The visitor */
    void *payload;              /* The caller's, untouched */
    hashmap_t *contradicted;    /* The sheet's DIRECTORY keys a blob stands at; the walk's frame */
    error_t failure;            /* The visitor's: the one that stopped the tree walk */
} branch_walk_t;

branch_t *branch_open(git_repository *repo, const char *profile, const git_tree *tree) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(tree);

    /* The name copied and the tree borrowed, and nothing read: the sheet waits
     * for the first question that needs it (branch_sheet_failure) */
    branch_t *branch = heap_calloc(1, sizeof(*branch));
    branch->repo = repo;
    branch->profile = heap_strdup(profile);
    branch->tree = tree;

    return branch;
}

error_t branch_load(git_repository *repo, const char *profile, branch_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    *out = NULL;

    /* The tip, its absence refused in gitops' words, which name the reference:
     * nothing to say over them */
    git_tree *tip = NULL;
    error_t err = gitops_load_branch_tree(repo, profile, &tip);
    if (err) return err;

    /* The branch over it, and the tip the handle's own, released with it */
    branch_t *branch = branch_open(repo, profile, tip);
    branch->own = tip;

    *out = branch;
    return NULL;
}

void branch_free(branch_t *branch) {
    if (!branch) return;

    metadata_free(branch->sheet);
    git_tree_free(branch->own);
    free(branch->profile);
    free(branch);
}

const char *branch_profile(const branch_t *branch) {
    CHECK_NULL(branch);
    return branch->profile;
}

const git_tree *branch_tree(const branch_t *branch) {
    CHECK_NULL(branch);
    return branch->tree;
}

error_t branch_sheet_failure(branch_t *branch) {
    CHECK_NULL(branch);

    /* Asked once. The loader answers a sheet or a failure — an absent sheet is
     * an empty one, never NULL — so a handle holding neither has not asked yet;
     * and a failure leaves the sheet as it was, NULL beside it (core/metadata.h
     * metadata_load_from_tree, untouched on failure) */
    if (!branch->sheet && !branch->sheet_failure) {
        branch->sheet_failure = metadata_load_from_tree(
            branch->repo, branch->tree, branch->profile, &branch->sheet
        );
    }

    return branch->sheet_failure;
}

/**
 * Walk visitor: one entry of the branch's tree, shown to branch_walk's visitor
 * where it is a claim
 *
 * The tree's half of the decode, in order: the content gate on the name the walk
 * joined (a name in the grammar, and nothing else), the kind, the shape, the
 * sheet's item at the name — and, in the same answer, the content authority —
 * the claim, and the visitor's turn.
 *
 * Identity — the blob's id and the type its filemode says — is read off the
 * borrowed entry here, at the one boundary where the entry is valid, so no claim
 * carries an opaque handle and nothing is duplicated to outlive the walk.
 *
 * @param path The entry's path within the tree, joined by the walk (borrowed —
 *             valid for the call only)
 * @param entry Git tree entry (borrowed — valid for the call only)
 * @param payload The walk (branch_walk_t)
 * @param next Set to SKIP past machinery, and to STOP where the visitor failed
 * @return NULL, or the tree's failure that ends the walk: a name outside the
 *         grammar
 */
static error_t branch_step(
    const char *path, const git_tree_entry *entry, void *payload,
    gitops_next_t *next
) {
    branch_walk_t *walk = payload;

    /* The content gate, asked of the name the entry stands at (infra/label.h
     * label_prefixes): a managed path is a name in the grammar — beneath a label,
     * or the label's word alone, the namespace's own directory, which holds what
     * a directory holds. Everything else the branch carries is machinery: dotta's
     * own files (.dottaignore, .bootstrap, .dotta/) and whatever else a hand or
     * a tool left beside them — a README, a LICENSE, a docs/ tree — and no walk
     * of content sees it. Asked of every entry's whole name, a tree's included,
     * so a tree of machinery is skipped with everything beneath it; beneath a
     * label it is always passed. Skipped in silence, and before the shape rule,
     * so machinery is never read as corruption. */
    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }

    /* Only blobs are claims: a tree beneath a label is walked into — and, in
     * the same line, a gitlink, which is neither, is passed. dotta never writes
     * one (sys/stage refuses the mode), but `dotta git` and a foreign push can,
     * and the branch's answer is that it claims nothing: no claim, no path, nothing
     * beneath it composed through it. Stated rather than incidental, because a
     * selection of the view's rows is what export copies (cmds/export.c
     * collect_filesystem) and it copies around such an entry in silence. */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return NULL;
    }

    /* The entry name is Git's, not this machine's. mount_resolve joins a label's
     * tail verbatim on the strength of the path having been validated at its
     * write boundary, and for a branch this machine authored it was — but a branch
     * that arrived by clone or sync was validated by whoever wrote it, which is
     * to say not at all. A tree can name a subtree "..", so the shape has to be
     * checked where the tree is read, the same reason the sheet's key loop checks
     * its own (core/metadata.c). Malformed here is corruption, not a lifecycle
     * stage: it ends the walk as the branch's failure, never a claim. */
    error_t err = label_validate_storage(path);
    if (err) return err;

    /* This blob's claim, by the name the tree gave it — and, in the same answer,
     * the content authority. A path is a tree or a blob and the tree is the content
     * authority, so a DIRECTORY item standing at a blob's name is stale metadata:
     * it claims nothing here, not even its owner or group, and nothing as a
     * directory either, which the second half reads back from this set rather
     * than asking the tree a second time — keyed by the sheet's own key, which
     * outlives the walk. Asked by name, and a name needs no path, so the one
     * rule covers the blob this machine can place and the blob it cannot alike.
     *
     * The blob a contradicted item leaves is claimed at its floors and with no
     * stamp, which reads a ciphertext blob through the plaintext comparison and
     * prints [modified] on every load (core/workspace.c). The contradiction is
     * the branch's and that is where it gets fixed; the decode states it rather
     * than repairs it. */
    const metadata_item_t *item = metadata_lookup(walk->sheet, path);
    if (item && item->kind == PATH_KIND_DIRECTORY) {
        hashmap_set(walk->contradicted, item->key, NULL);
        item = NULL;
    }

    /* The blob's identity: its id, and the type its filemode says — libgit2
     * normalizes the mode it hands back (lib/libgit2/src/libgit2/tree.c
     * normalize_filemode), so a blob's is one of three. No mode is claimed until
     * the item says one. */
    branch_claim_t claim = {
        .storage_path = path,
        .mode         = MODE_UNCLAIMED,
    };
    git_oid_cpy(&claim.blob_oid, git_tree_entry_id(entry));
    switch (git_tree_entry_filemode(entry)) {
        case GIT_FILEMODE_BLOB_EXECUTABLE:
            claim.type = PATH_TYPE_EXECUTABLE;
            break;
        case GIT_FILEMODE_LINK:
            claim.type = PATH_TYPE_SYMLINK;
            break;
        default:
            /* A blob (filtered to blobs above) */
            claim.type = PATH_TYPE_FILE;
            break;
    }

    /* The item's claim over the blob, where the sheet makes one. Owner and group
     * ride every blob, links included: the ownership claim is true regardless
     * of what the path became, and a name the item does not make stays NULL. */
    if (item) {
        claim.owner = item->owner;
        claim.group = item->group;

        /* Mode and stamp only where a mode can stand — the tree's word (the type),
         * never the item's kind: symlink(2) takes no mode, and a link's bytes
         * are its target rather than content anything could seal. A mode the
         * item does not claim stays unclaimed, for the reader to floor
         * (branch_claim_mode). */
        if (claim.type != PATH_TYPE_SYMLINK) {
            claim.mode = item->mode;
            claim.encrypted = item->encrypted;
        }
    }

    /* The visitor's turn. Its failure ends the walk and is kept, so every failure
     * the tree walk answers is the tree's (branch_walk), and the visitor's comes
     * back as it made it. */
    walk->failure = walk->visit(&claim, walk->payload);
    if (walk->failure) *next = GITOPS_NEXT_STOP;

    return NULL;
}

error_t branch_walk(
    branch_t *branch,
    branch_read_t read,
    branch_visit_fn visit,
    void *payload
) {
    CHECK_NULL(branch);
    CHECK_NULL(visit);

    /* The sheet first, so a strict walk the sheet refuses shows no claim, and a
     * tolerant one goes on without it, the sheet's half alone lost. The failure
     * is the loader's, which names the profile, and comes back as it is. */
    error_t err = branch_sheet_failure(branch);
    if (err && read == BRANCH_READ_STRICT) return err;

    /* A frame of the walk's own for the one thing its two halves share, the names
     * a blob stands at: built by the first, read by the second, and nothing after
     * the walk (include/runtime.h "Memory": no arena in reach). Keyed by the
     * sheet's own keys, which the handle keeps. */
    arena_t *frame = arena_create(0);
    hashmap_t *contradicted = hashmap_borrow(frame, 8);
    branch_walk_t walk = {
        .sheet        = branch->sheet,
        .visit        = visit,
        .payload      = payload,
        .contradicted = contradicted,
    };

    /* The blobs, in the tree's pre-order (branch_step). What the tree walk answers
     * is the tree's — a name its grammar refused, a subtree that would not load
     * — and each names a path in the tree, so the profile is the where neither
     * says. The visitor's own failure stopped the walk and comes back as it was
     * made. */
    err = gitops_tree_walk(branch->tree, branch_step, &walk);
    if (err) {
        err = error_wrap(err, "Cannot read profile '%s'", branch->profile);
    } else {
        err = walk.failure;
    }

    /* The directory claims: every DIRECTORY item the sheet carries, in its own
     * order. A tree holds no empty directory, so the item is the claim's whole
     * footprint; one a blob stands at the name of claims nothing, and the first
     * half recorded it. The class rides the claim, and a directory takes no
     * stamp. */
    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(walk.sheet, &count);
    for (size_t i = 0; !err && i < count; i++) {
        const metadata_item_t *item = items[i];
        if (item->kind != PATH_KIND_DIRECTORY) continue;
        if (hashmap_has(walk.contradicted, item->key)) continue;

        const branch_claim_t claim = {
            .storage_path = item->key,
            .type         = PATH_TYPE_DIRECTORY,
            .mode         = item->mode,
            .owner        = item->owner,
            .group        = item->group,
            .tracked      = item->tracked,
        };
        err = visit(&claim, payload);
    }

    arena_free(frame);
    return err;
}

mode_t branch_claim_mode(const branch_claim_t *claim) {
    CHECK_NULL(claim);

    /* The claim's own, where it makes one: a 0000 claim is a claim */
    if (claim->mode != MODE_UNCLAIMED) return claim->mode;

    /* Else the floor its type stands at */
    switch (claim->type) {
        case PATH_TYPE_FILE:
            return 0644;
        case PATH_TYPE_EXECUTABLE:
            return 0755;
        case PATH_TYPE_SYMLINK:
            return 0;   /* the row's don't-care: no mode stands on a link */
        case PATH_TYPE_DIRECTORY:
            return DIR_MODE_DEFAULT;
    }

    CHECK_ARG(false, "a path type no enumerator names");
}
