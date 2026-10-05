/**
 * branch.c - A profile's branch, over one tree
 *
 * The handle is a tree and the sheet read from it once, at the first question,
 * its failure kept beside it. The walk is the decode core/branch.h states, in
 * two halves: one walk of the tree for the blobs (branch_step), then the sheet's
 * directory items, each asked the one question that classifies it, the directory
 * claim standing at its name (branch_directory_item) — the items it answers none
 * for are branch_contradicted's. The point questions ask the decode of one name:
 * a blob's claim through the walk's own decode (branch_decode_blob), and the
 * directory claim standing at a name through the question the walk asks of each
 * item, decoded as the walk decodes it (branch_decode_directory). The count is
 * the walk, tallied (branch_count).
 */

#include "core/branch.h"

#include <stdlib.h>

#include "base/arena.h"
#include "base/error.h"
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
    arena_t *arena;         /* The claims the handle lends (branch_find) */
};

/* The walk's tree half: the sheet each blob's item is read from, the visitor,
 * and the visitor's failure past the tree walk it stopped */
typedef struct {
    const metadata_t *sheet;    /* NULL: a tolerant walk past a sheet that will not load */
    branch_visit_fn visit;      /* The visitor */
    void *payload;              /* The caller's, untouched */
    error_t failure;            /* The visitor's: the one that stopped the tree walk */
} branch_walk_t;

branch_t *branch_open(git_repository *repo, const char *profile, const git_tree *tree) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(tree);

    /* The name copied and the tree borrowed, and nothing read: the sheet waits
     * for the first question that needs it (branch_sheet_failure). The arena is
     * the handle's own, made here and freed with it, for the claims it lends */
    branch_t *branch = heap_calloc(1, sizeof(*branch));
    branch->repo = repo;
    branch->profile = heap_strdup(profile);
    branch->tree = tree;
    branch->arena = arena_create(0);

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

    arena_free(branch->arena);
    metadata_free(branch->sheet);
    git_tree_free(branch->own);
    free(branch->profile);
    free(branch);
}

const char *branch_profile(const branch_t *branch) {
    CHECK_NULL(branch);
    return branch->profile;
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
 * The claim a blob makes at its name: its identity, and the item's claim over it
 *
 * Identity — the blob's id and the type its filemode says — is read off the entry
 * here, at the one boundary where the entry is valid (borrowed for the walk's
 * visit, or a point question's own copy), so no claim carries an opaque handle
 * and nothing is duplicated to outlive the walk.
 *
 * Readers: branch_step, at every blob the walk meets, and branch_find, at the
 * one it is asked — so the file claim a point question answers is the walk's.
 *
 * @param path The claim's name, which the claim keeps (must not be NULL)
 * @param entry The blob's tree entry (must not be NULL)
 * @param item The FILE item at the name, or NULL: none, or one the caller voided
 * @return The claim, by value: a function of its three inputs, which cannot fail
 */
static branch_claim_t branch_decode_blob(
    const char *path,
    const git_tree_entry *entry,
    const metadata_item_t *item
) {
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
            /* A blob (the callers pass blobs alone) */
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

    return claim;
}

/**
 * The claim a directory item makes at its name
 *
 * The sheet's alone: a tree holds no empty directory, so the item is the claim's
 * whole footprint, and the claim's strings are the sheet's, which the handle keeps.
 *
 * Readers: branch_walk, at each directory claim that stands; branch_contradicted,
 * at each one a blob contradicts; and branch_find, at the one it is asked — so
 * the directory claim a point question answers is the walk's.
 *
 * @param item A DIRECTORY item (must not be NULL)
 * @return The claim, by value: a function of its item, which cannot fail
 */
static branch_claim_t branch_decode_directory(const metadata_item_t *item) {
    /* The item's every field but the stamp: the class rides the claim, and a
     * directory takes no stamp */
    return (branch_claim_t){
        .storage_path = item->key,
        .type = PATH_TYPE_DIRECTORY,
        .mode = item->mode,
        .owner = item->owner,
        .group = item->group,
        .tracked = item->tracked,
    };
}

/**
 * The sheet's directory claim standing at `name`, or NULL: the DIRECTORY item
 * there, where no blob stands at the name
 *
 * The classification, at one name: the walk's directory half asks it of each
 * item and shows the claim it answers, branch_contradicted shows each item it
 * answers none for, and the point questions ask it of the one name they are asked
 * — one question, so no two of them can part. The tree first, so a name a blob
 * stands at answers without the sheet; then the sheet, under `read`. The raw
 * item, which is this module's own: each reader makes of it what it asks.
 *
 * Readers: branch_walk and branch_contradicted, at each DIRECTORY item;
 * branch_holds, where the tree is silent at the name; and branch_find, for a
 * directory claim.
 *
 * @param branch Handle
 * @param read The sheet's policy for this question
 * @param name A validated storage path
 * @param out The item, or NULL where none stands (NULL after an error)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's (STRICT), in the loader's words
 */
static error_t branch_directory_item(
    branch_t *branch,
    branch_read_t read,
    const char *name,
    const metadata_item_t **out
) {
    *out = NULL;

    /* A blob at the name contradicts the claim there and is the tree's answer,
     * the sheet unread: the whole of what the classification asks the tree. The
     * look reads its three answers as three — a subtree that will not load on
     * the way is a failure to read, never an absence
     * (lib/libgit2/src/libgit2/tree.c git_tree_entry_bypath: -1 where a subtree
     * will not load, GIT_ENOTFOUND for a name absent or reached through a
     * non-tree) */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, branch->tree, name);
    if (rc < 0 && rc != GIT_ENOTFOUND) {
        return error_git(rc, "Cannot read '%s' in profile '%s'", name, branch->profile);
    }
    git_object_t type = rc == 0 ? git_tree_entry_type(entry) : GIT_OBJECT_INVALID;
    git_tree_entry_free(entry);   /* NULL-safe, and NULL unless rc == 0 */
    if (type == GIT_OBJECT_BLOB) return NULL;

    /* An open question: the sheet, under the reader's policy. A tolerant read
     * past a sheet that will not load holds no item, since metadata_lookup takes
     * the NULL sheet the failure leaves (branch_sheet_failure) */
    error_t err = branch_sheet_failure(branch);
    if (err && read == BRANCH_READ_STRICT) return err;

    /* The item at the name, where it claims a directory: a FILE item with no
     * blob claims nothing here, as in the walk */
    const metadata_item_t *item = metadata_lookup(branch->sheet, name);
    if (item && item->kind == PATH_KIND_DIRECTORY) *out = item;

    return NULL;
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
     * beneath it composed through it. Stated rather than incidental, because
     * what this walk shows is what export copies — its claims, or the view's
     * rows placed from them (cmds/export.c) — so every copy goes around such an
     * entry in silence. */
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
     * it claims nothing here, not even its owner or group — and nothing as a
     * directory either, which the directory half finds for itself, asking the
     * tree at the item's own name as a point question does (branch_directory_item).
     * Asked by name, and a name needs no path, so the one rule covers the blob
     * this machine can place and the blob it cannot alike.
     *
     * The blob a contradicted item leaves is claimed at its floors and with no
     * stamp, which reads a ciphertext blob through the plaintext comparison and
     * prints [modified] on every load (core/workspace.c). The contradiction is
     * the branch's and that is where it gets fixed; the decode states it rather
     * than repairs it. */
    const metadata_item_t *item = metadata_lookup(walk->sheet, path);
    if (item && item->kind == PATH_KIND_DIRECTORY) item = NULL;

    /* The claim the blob makes, its identity and the item's claim over it, by
     * the one decode a point question at this name reads too
     * (branch_decode_blob) */
    const branch_claim_t claim = branch_decode_blob(path, entry, item);

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

    /* The blobs, in the tree's pre-order (branch_step). What the tree walk answers
     * is the tree's — a name its grammar refused, a subtree that would not load
     * — and each names a path in the tree, so the profile is the where neither
     * says. The visitor's own failure stopped the walk and comes back as it was
     * made. */
    branch_walk_t walk = {
        .sheet   = branch->sheet,
        .visit   = visit,
        .payload = payload,
    };
    err = gitops_tree_walk(branch->tree, branch_step, &walk);
    if (err) return error_wrap(err, "Cannot read profile '%s'", branch->profile);
    if (walk.failure) return walk.failure;

    /* The directory claims the tree leaves standing: every DIRECTORY item the
     * sheet carries, in its own order — none past a sheet a tolerant walk went
     * on without, which holds no item — each asked the question that classifies
     * it, the directory claim standing at its name, the one a point question
     * asks there (branch_directory_item). One a blob stands at the name of claims
     * nothing, and is branch_contradicted's to show. The question reads no tree
     * the blobs' half did not, so its failure needs a store that changed beneath
     * the walk. */
    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(branch->sheet, &count);
    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        const metadata_item_t *standing = NULL;
        err = branch_directory_item(branch, read, items[i]->key, &standing);
        if (err) return err;
        if (!standing) continue;

        /* The claim the point question answers at that name, by its decode */
        const branch_claim_t claim = branch_decode_directory(standing);
        err = visit(&claim, payload);
        if (err) return err;
    }

    return NULL;
}

error_t branch_contradicted(
    branch_t *branch,
    branch_read_t read,
    branch_visit_fn visit,
    void *payload
) {
    CHECK_NULL(branch);
    CHECK_NULL(visit);

    /* The sheet first, as the walk reads it: a strict question the sheet refuses
     * shows no claim, and a tolerant one shows none past it, the failure kept
     * for the reader to say. The failure is the loader's, which names the profile,
     * and comes back as it is. */
    error_t err = branch_sheet_failure(branch);
    if (err && read == BRANCH_READ_STRICT) return err;

    /* The walk's directory half, answered the other way: every DIRECTORY item,
     * in the sheet's own order, asked the same question (branch_directory_item),
     * and shown where it answers none — a blob stands at the name. Asked before
     * any walk read the tree, the question can meet a subtree that will not load
     * on its way, and says so in its own words, naming the claim's name. */
    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(branch->sheet, &count);
    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        const metadata_item_t *standing = NULL;
        err = branch_directory_item(branch, read, items[i]->key, &standing);
        if (err) return err;
        if (standing) continue;

        /* The item, decoded as the walk would have shown it had no blob stood
         * at its name */
        const branch_claim_t claim = branch_decode_directory(items[i]);
        err = visit(&claim, payload);
        if (err) return err;
    }

    return NULL;
}

/**
 * Walk visitor: one claim, tallied by its kind
 *
 * A blob is a file, whatever its type; a directory claim counts where the profile
 * tracks it, and an ancestor claim not at all (branch_count_t).
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The count so far (branch_count_t)
 * @return NULL: a tally fails nowhere
 */
static error_t branch_count_claim(const branch_claim_t *claim, void *payload) {
    branch_count_t *count = payload;

    if (claim->type != PATH_TYPE_DIRECTORY) {
        count->file_count++;
    } else if (claim->tracked) {
        count->directory_count++;
    }

    return NULL;
}

error_t branch_count(branch_t *branch, branch_count_t *out) {
    CHECK_NULL(branch);
    CHECK_NULL(out);

    /* The claims the walk shows, read strictly, tallied in a value of the call's
     * own and handed out whole: a walk that stopped short leaves the caller's
     * as it was. The walk's failures name the profile already — the loader's
     * words for the sheet, "Cannot read profile" over the tree's — so nothing
     * is said over them. */
    branch_count_t count = { 0 };
    error_t err = branch_walk(branch, BRANCH_READ_STRICT, branch_count_claim, &count);
    if (err) return err;

    *out = count;
    return NULL;
}

error_t branch_holds(branch_t *branch, const char *name, branch_held_t *out) {
    CHECK_NULL(branch);
    CHECK_NULL(name);
    CHECK_NULL(out);

    /* The tree first: a name is Git's key, and the tree is the content authority
     * (core/metadata.h), so an entry here is the whole answer whatever the sheet
     * says at the name. Three answers read as three: an intermediate object that
     * will not load is a failure to read, never an absence. */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, branch->tree, name);
    if (rc == 0) {
        /* Three kinds and no fourth: git_tree_entry_type reads the entry's mode
         * word, which is a gitlink, a directory, or a blob — so the last arm is
         * the gitlink and not a shrug. */
        branch_held_kind_t kind;
        switch (git_tree_entry_type(entry)) {
            case GIT_OBJECT_BLOB: kind = BRANCH_HELD_FILE; break;
            case GIT_OBJECT_TREE: kind = BRANCH_HELD_DIRECTORY; break;
            default:              kind = BRANCH_HELD_SUBMODULE; break;
        }

        *out = (branch_held_t){
            .kind = kind,
            .oid = *git_tree_entry_id(entry),
            .filemode = git_tree_entry_filemode(entry),
        };
        git_tree_entry_free(entry);

        return NULL;
    }
    if (rc != GIT_ENOTFOUND) {
        return error_git(rc, "Cannot read '%s' in profile '%s'", name, branch->profile);
    }

    /* The tree's silence: the one claim a tree cannot hold, a directory claim
     * with nothing beneath it, standing here and nowhere else. Read strictly —
     * whether the sheet alone holds one is the sheet's question, so a sheet that
     * will not load is the answer — and by the question the walk and the directory
     * question ask too, so none of them can part */
    const metadata_item_t *item = NULL;
    error_t err = branch_directory_item(branch, BRANCH_READ_STRICT, name, &item);
    if (err) return err;

    *out = (branch_held_t){
        .kind = item ? BRANCH_HELD_DIRECTORY : BRANCH_HELD_NOTHING,
    };

    return NULL;
}

error_t branch_find(
    branch_t *branch,
    branch_read_t read,
    path_kind_t kind,
    const char *name,
    const branch_claim_t **out
) {
    CHECK_NULL(branch);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The blob at the name, or no file claim: the tree's answer, the
             * sheet unread where it gives one. The look reads three answers as
             * three, as every look here does (branch_directory_item) */
            git_tree_entry *entry = NULL;
            int rc = git_tree_entry_bypath(&entry, branch->tree, name);
            if (rc < 0 && rc != GIT_ENOTFOUND) {
                return error_git(
                    rc, "Cannot read '%s' in profile '%s'", name, branch->profile
                );
            }
            if (rc != 0 || git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
                git_tree_entry_free(entry);   /* NULL-safe */
                return NULL;
            }

            /* Its FILE item, under the reader's policy: a DIRECTORY item at a
             * blob's name claims nothing at the blob — the walk's at-name rule
             * (branch_step) */
            error_t err = branch_sheet_failure(branch);
            if (err && read == BRANCH_READ_STRICT) {
                git_tree_entry_free(entry);
                return err;
            }
            const metadata_item_t *item = metadata_lookup(branch->sheet, name);
            if (item && item->kind == PATH_KIND_DIRECTORY) item = NULL;

            /* Decoded as the walk decodes the blob, and kept for the handle's
             * life, its name copied beside it: an answer outlives the caller's
             * argument */
            branch_claim_t *kept = arena_alloc(branch->arena, sizeof(*kept));
            *kept = branch_decode_blob(arena_strdup(branch->arena, name), entry, item);
            git_tree_entry_free(entry);

            *out = kept;
            return NULL;
        }

        case PATH_KIND_DIRECTORY: {
            /* The directory claim standing at the name, by the question the walk
             * asks of each item and holds asks where the tree is silent */
            const metadata_item_t *item = NULL;
            error_t err = branch_directory_item(branch, read, name, &item);
            if (err || !item) return err;

            /* Decoded as the walk decodes the claim, and kept for the handle's
             * life: its strings are the sheet's, which the handle keeps too */
            branch_claim_t *kept = arena_alloc(branch->arena, sizeof(*kept));
            *kept = branch_decode_directory(item);

            *out = kept;
            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
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
