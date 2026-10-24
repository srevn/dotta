/**
 * stage.c - One ref's next tree, staged in memory: implementation
 *
 * See stage.h. The stage composes five primitives: the ref read once to its head,
 * its absence proven (sys/gitops.h gitops_load_reference_commit,
 * gitops_reference_exists), an ownerless index seeded from the head's tree
 * (git_index_new + git_index_read_tree — never git_repository_index, the
 * checked-out branch's staging area), the tree written straight to the ODB
 * (git_index_write_tree_to — never git_index_write, which wants a backing file),
 * gitops' one writer of a commit object, which moves no ref (gitops_create_commit),
 * and gitops' one writer of a ref, from the head the open read — from nothing
 * for an orphan's stage (gitops_write_reference). That write's compare, under
 * the ref's own lock, is the last inch of the atomicity, and it is still libgit2's:
 * the stage owns no lock, and says every refusal of the write as the writer's
 * one fact with its own clause.
 */

#include "sys/stage.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"
#include "sys/gitops.h"

struct stage {
    git_repository *repo;   /* borrowed */
    char *refname;          /* owned */
    git_commit *parent;     /* the head at open; NULL for an orphan's stage */
    git_tree *tree;         /* the parent's tree, or the empty tree */
    git_index *index;       /* ownerless, seeded from tree */
};

struct stage_admission {
    git_index *index;       /* ownerless: the opened tree, and every blob admitted since */
};

/**
 * The stage on `refname`, seeded: the tree of `parent` in a private index with
 * it as the parent-to-be, or — when `parent` is NULL, the orphan's stage — the
 * empty tree and no parent
 *
 * The stage owns everything it makes from its first allocation on, and the parent
 * from the call, so every failure frees through stage_free and nothing is handed
 * across this call half-built. Its readers are the two openers: each resolves
 * the ref, refuses the state it did not expect, and seeds here.
 */
static error_t stage_seed(
    git_repository *repo, const char *refname, git_commit *parent, stage_t **out
) {
    stage_t *st = heap_calloc(1, sizeof(*st));
    st->repo = repo;
    st->refname = heap_strdup(refname);
    st->parent = parent;

    int rc;
    if (parent) {
        rc = git_commit_tree(&st->tree, parent);
        if (rc < 0) {
            stage_free(st);
            return error_git(rc, "Failed to read the head of '%s'", refname);
        }
    } else {
        /* The empty tree: Git's own "nothing", the tree every orphan's stage
         * opens on. Read, never written: its id is the hash of a tree with no
         * entries, and libgit2 — like git — serves that one object whether or
         * not the database holds it (odb.c odb_read_hardcoded). The index seeded
         * from it answers for its tree from its own cache until a verb touches
         * it (tree.c git_tree__write_index), so an orphan's stage committed
         * untouched meets the rule every stage keeps — a tree equal to the opened
         * one — and writes nothing there either. */
        git_oid empty;
        rc = git_odb_hash(&empty, "", 0, GIT_OBJECT_TREE);
        if (rc == 0) {
            rc = git_tree_lookup(&st->tree, repo, &empty);
        }
        if (rc < 0) {
            stage_free(st);
            return error_git(rc, "Failed to read the empty tree for '%s'", refname);
        }
    }

    rc = git_index_new(&st->index);
    if (rc == 0) {
        rc = git_index_read_tree(st->index, st->tree);
    }
    if (rc < 0) {
        stage_free(st);
        return error_git(rc, "Failed to read the tree of '%s'", refname);
    }

    *out = st;
    return NULL;
}

error_t stage_open(git_repository *repo, const char *refname, stage_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out);
    *out = NULL;

    /* The head, the parent-to-be: the commit the ref names, read as every head
     * is (sys/gitops.h gitops_reference_commit) — the ref's absence proven and
     * refused, a packed-refs that will not parse its own failure, and a ref at
     * anything but a commit refused, a tag never peeled: the commit writes the
     * ref only from the id the open read there (gitops_write_reference), so the
     * parent must be that id. */
    git_commit *parent = NULL;
    error_t err = gitops_load_reference_commit(repo, refname, &parent);
    if (err) return err;

    return stage_seed(repo, refname, parent, out);
}

error_t stage_orphan(git_repository *repo, const char *refname, stage_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out);
    *out = NULL;

    /* Absent, and proven so (sys/gitops.h gitops_reference_find): a name that
     * stands, and a packed-refs that will not parse, are refused before any put.
     * The root commit's write decides the name free again, under the ref's lock
     * (gitops_write_reference). */
    bool exists = false;
    error_t err = gitops_reference_exists(repo, refname, &exists);
    if (err) return err;
    if (exists) {
        return error_create(ERR_EXISTS, "Reference '%s' already exists", refname);
    }

    return stage_seed(repo, refname, NULL, out);
}

const git_tree *stage_tree(const stage_t *st) {
    CHECK_NULL(st);

    return st->tree;
}

git_index *stage_index(stage_t *st) {
    CHECK_NULL(st);

    return st->index;
}

/**
 * Git's type for what a mode word says stands at a name: a gitlink's is a commit,
 * a directory's a tree, and every other mode's a blob
 *
 * libgit2's own reading of a tree entry, whole (lib/libgit2/src/libgit2/tree.c
 * git_tree_entry_type: S_ISGITLINK, then S_ISDIR), asked of a mode the stage
 * meets as a tree spelled it — an index entry's, where the index was seeded from
 * one (index.c read_tree_cb), and a delta's side, which the comparison hands on
 * from either (iterator.c tree_iterator_set_current) — so a blob of whatever
 * permission bits a hand's tree spells is the blob the profile's walk reads there
 * (core/profiles.c profile_step).
 *
 * Readers: the noun a refusal names an entry in a name's way by (stage_mode_noun),
 * and what stood on a delta's side (stage_side_type).
 */
static git_object_t stage_mode_type(uint32_t mode) {
    switch (mode & S_IFMT) {
        case GIT_FILEMODE_COMMIT: return GIT_OBJECT_COMMIT;
        case GIT_FILEMODE_TREE:   return GIT_OBJECT_TREE;
        default:                  return GIT_OBJECT_BLOB;
    }
}

/**
 * What a refusal calls an entry in a name's way: a gitlink a submodule, as Git's
 * own add names one with a path inside it (lib/git/submodule.c
 * die_path_inside_submodule) and revert one at its name (cmds/revert.c cmd_revert),
 * and every blob a file
 *
 * Readers: stage_admit_path, an entry above the name; stage_admit_subtree, one
 * at it.
 */
static const char *stage_mode_noun(uint32_t mode) {
    return stage_mode_type(mode) == GIT_OBJECT_COMMIT ? "submodule" : "file";
}

/**
 * Can anything at all be named at this path — the shape, and no entry above it?
 *
 * The identical beginning of both sides of the rule, a blob's and a subtree's:
 * what libgit2 would refuse later with a worse message, and then a proper prefix
 * that names an entry, which puts the path inside a file or a submodule. Neither
 * answer depends on what is being put there.
 *
 * The scratch is this function's, NUL-terminated at each slash in turn; the
 * sentence prints from `path`, which is whole throughout.
 */
static error_t stage_admit_path(git_index *index, const char *path) {
    size_t len = strlen(path);
    if (len == 0 || path[0] == '/' || path[len - 1] == '/' || strstr(path, "//")) {
        return error_create(
            ERR_INVALID_ARG,
            "Cannot stage '%s': a tree path has no leading or trailing slash "
            "and no empty component", path
        );
    }

    char *scratch = heap_alloc(len + 1);
    memcpy(scratch, path, len + 1);

    /* A file or a submodule where a directory is needed: a proper prefix naming
     * an entry, by its own noun */
    for (char *slash = strchr(scratch, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        const git_index_entry *above = git_index_get_bypath(index, scratch, 0);
        if (above) {
            int prefix_len = (int) (slash - scratch);
            free(scratch);
            return error_create(
                ERR_CONFLICT, "Cannot stage '%s': '%.*s' is a %s in this tree",
                path, prefix_len, path, stage_mode_noun(above->mode)
            );
        }
        *slash = '/';
    }

    free(scratch);

    return NULL;
}

/**
 * Put an entry into `index`: the mode, the shape, the two collisions, then
 * libgit2's add
 *
 * Every entry enters an index here — the stage's, and an admission's — and the
 * order is the header's first rule: git_index_add REPLACES on a file/directory
 * collision (index.c check_file_directory_collision with ok_to_replace), so an
 * entry added past a refusal would take another away. Both collisions are refused
 * first, in this module's own sentences.
 *
 * What git_index_add can refuse after that is libgit2's own path rule — `.git`
 * as a component in every spelling libgit2 protects, `.` and `..` — validated
 * with mode 0 whatever the entry carries (index_entry_dup passes no stat), and
 * an allocation. Nothing else remains on an ownerless index: the object check
 * is the owner's, and the collision check replaces (index_insert). A name the
 * rule refuses is a verdict about the name, as a collision is, and is spelled
 * as one — here, because nothing later can: error_wrap keeps its cause's code,
 * and error_git is always ERR_GIT.
 */
static error_t stage_put_entry(git_index *index, const git_index_entry *entry) {
    const char *path = entry->path;

    if (entry->mode != GIT_FILEMODE_BLOB &&
        entry->mode != GIT_FILEMODE_BLOB_EXECUTABLE &&
        entry->mode != GIT_FILEMODE_LINK) {
        return error_create(
            ERR_INVALID_ARG,
            "Cannot stage '%s' with mode 0%o: not a blob or link mode",
            path, (unsigned int) entry->mode
        );
    }

    error_t err = stage_admit_path(index, path);
    if (err) return err;

    /* A directory where the file goes: any entry beneath the path. The index is
     * sorted, so one prefix probe answers. */
    size_t len = strlen(path);
    char *beneath = heap_alloc(len + 2);
    memcpy(beneath, path, len);
    beneath[len] = '/';
    beneath[len + 1] = '\0';

    int rc = git_index_find_prefix(NULL, index, beneath);
    free(beneath);

    if (rc == 0) {
        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': it is a directory in this tree",
            path
        );
    }
    if (rc != GIT_ENOTFOUND) {
        /* Not tidiness: reading "no conflict" out of a failure to look admits a
         * blob the index would then make room for by dropping an entry. The linked
         * libgit2 is whichever one pkg-config found at or above 1.9, and its
         * contract here is "0 or an error code". */
        return error_git(rc, "Failed to search the tree beneath '%s'", path);
    }

    /* The same path already an entry: replaced — the upsert every writer wants. */
    rc = git_index_add(index, entry);
    if (rc == 0) return NULL;

    /* The index class is exact here: the mode is checked above and both collisions
     * refused, so on this path it is raised by the path rule alone. */
    const git_error *cause = git_error_last();
    if (cause->klass == GIT_ERROR_INDEX) {
        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': Git refuses the name (%s)", path,
            cause->message
        );
    }

    return error_git(rc, "Failed to stage '%s'", path);
}

error_t stage_admission_create(const stage_t *st, stage_admission_t **out) {
    CHECK_NULL(st);
    CHECK_NULL(out);
    *out = NULL;

    stage_admission_t *adm = heap_calloc(1, sizeof(*adm));

    /* Ownerless, for the reason the stage's own index is: the path rule runs at
     * every add, and the object check waits for a tree write that never comes.
     * The index holds its own copies of the entries, so the stage is not borrowed
     * past this call. */
    int rc = git_index_new(&adm->index);
    if (rc == 0) {
        rc = git_index_read_tree(adm->index, st->tree);
    }
    if (rc < 0) {
        stage_admission_free(adm);
        return error_git(rc, "Failed to read the tree of '%s'", st->refname);
    }

    *out = adm;
    return NULL;
}

error_t stage_admit_blob(stage_admission_t *adm, const char *path) {
    CHECK_NULL(adm);
    CHECK_NULL(path);

    /* Recorded as a blob under the null id. The mode is the put's caller's word,
     * and a caller asking about a path it has not read yet has no mode to offer
     * — nor needs one: libgit2 validates a path with mode 0 (stage_put_entry). */
    git_index_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.mode = GIT_FILEMODE_BLOB;
    entry.path = path;

    return stage_put_entry(adm->index, &entry);
}

error_t stage_admit_subtree(const stage_admission_t *adm, const char *path) {
    CHECK_NULL(adm);
    CHECK_NULL(path);
    error_t err = stage_admit_path(adm->index, path);
    if (err) return err;

    /* An entry at the path itself, a blob or a gitlink: it and a subtree cannot
     * both stand there, and nothing beneath it could be committed either. Entries
     * beneath the path are the subtree already standing, and need no asking. */
    const git_index_entry *entry = git_index_get_bypath(adm->index, path, 0);
    if (entry) {
        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': it is a %s in this tree", path,
            stage_mode_noun(entry->mode)
        );
    }

    return NULL;
}

void stage_admission_free(stage_admission_t *adm) {
    if (!adm) return;

    git_index_free(adm->index);
    free(adm);
}

error_t stage_put(
    stage_t *st, const char *path, const void *data, size_t size,
    git_filemode_t mode, git_oid *out_blob
) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_ARG(data != NULL || size == 0, "data cannot be NULL with a size");

    /* The entry first, under the null id: every refusal the put has — the mode,
     * the shape, both collisions, Git's own name rule — is met before a byte is
     * written (stage_put_entry). The index is ownerless, so libgit2 asks for no
     * object behind it (index.c index_insert), as it asks for none behind an
     * admission's. */
    git_index_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.mode = (uint32_t) mode;
    entry.path = path;
    error_t err = stage_put_entry(st->index, &entry);
    if (err) return err;

    /* Then the blob, written once — the one hash of the bytes — and the entry
     * pointed at it through the same add (stage_put_entry), which meets the answers
     * it met. A write that fails leaves the entry at the null id (the header). */
    git_oid blob;
    int rc = git_blob_create_from_buffer(
        &blob, st->repo, size > 0 ? data : "", size
    );
    if (rc < 0) {
        return error_git(rc, "Failed to write the blob for '%s'", path);
    }

    /* The id is answered once the entry stands: a refused put names no blob the
     * tree holds */
    err = stage_put_blob(st, path, &blob, mode);
    if (err) return err;
    if (out_blob) {
        git_oid_cpy(out_blob, &blob);
    }

    return NULL;
}

error_t stage_put_blob(
    stage_t *st, const char *path, const git_oid *blob, git_filemode_t mode
) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_NULL(blob);

    git_index_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.mode = (uint32_t) mode;
    entry.path = path;
    git_oid_cpy(&entry.id, blob);

    return stage_put_entry(st->index, &entry);
}

error_t stage_remove(stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);

    /* git_index_remove at stage 0 reports a missing entry, where
     * git_index_remove_bypath would swallow it ("ensure gone"). */
    int rc = git_index_remove(st->index, path, 0);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "'%s' is not in this tree", path);
    }
    if (rc < 0) {
        return error_git(rc, "Failed to remove '%s'", path);
    }

    return NULL;
}

/**
 * The index against the tree the open read, a type change one delta
 *
 * Readers: stage_changed, whether any entry moved; stage_changes, each one —
 * one comparison for both questions, so the bool and the list cannot part.
 */
static error_t stage_diff(const stage_t *st, git_diff **out) {
    /* A type change — a blob become a link, a gitlink a blob — one delta at its
     * name, where libgit2 would split it into a removal and an addition
     * (lib/libgit2/src/libgit2/diff_generate.c maybe_modified) */
    git_diff_options opts;
    git_diff_options_init(&opts, GIT_DIFF_OPTIONS_VERSION);
    opts.flags |= GIT_DIFF_INCLUDE_TYPECHANGE;

    /* libgit2 diffs the two through iterators, an entry unmodified where its id
     * and its mode agree, and writes no object — an id whose object is not written
     * yet is compared by the id alone */
    int rc = git_diff_tree_to_index(out, st->repo, st->tree, st->index, &opts);
    if (rc < 0) {
        return error_git(rc, "Failed to compare the tree of '%s'", st->refname);
    }

    return NULL;
}

error_t stage_changed(const stage_t *st, bool *out) {
    CHECK_NULL(st);
    CHECK_NULL(out);

    /* The index against the tree the open read, stage_commit's question asked
     * without its write (stage_diff) */
    git_diff *diff = NULL;
    error_t err = stage_diff(st, &diff);
    if (err) return err;

    /* An unmodified entry is no delta, so any delta is a move */
    *out = git_diff_num_deltas(diff) > 0;
    git_diff_free(diff);

    return NULL;
}

/**
 * What stood on one side of a delta: Git's type for its mode (stage_mode_type),
 * or GIT_OBJECT_INVALID where nothing stands — an addition's first side, a
 * removal's second
 *
 * Absence is read off libgit2's own word for it, the flag that a file exists on
 * the side (include/git2/diff.h GIT_DIFF_FLAG_EXISTS), never off the mode 0 a
 * zeroed delta leaves such a side at (lib/libgit2/src/libgit2/diff_generate.c
 * diff_delta__alloc): a hand's tree can spell 0 (tree.c parse_mode), which the
 * walk reads as a blob.
 *
 * Reader: stage_changes, each delta's two sides.
 */
static git_object_t stage_side_type(const git_diff_file *side) {
    return side->flags & GIT_DIFF_FLAG_EXISTS
        ? stage_mode_type(side->mode) : GIT_OBJECT_INVALID;
}

error_t stage_changes(const stage_t *st, arena_t *arena, stage_changes_t *out) {
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The comparison stage_changed asks, its deltas read rather than counted
     * (stage_diff) */
    git_diff *diff = NULL;
    error_t err = stage_diff(st, &diff);
    if (err) return err;

    /* Each delta kept, in the order the comparison made them: its name, one string
     * for both sides since no rename is asked (diff_generate.c diff_delta__alloc),
     * copied out of the diff that goes, and what stood on each side. The room
     * is made at once, and an arena's answer is never NULL, for no delta either */
    const size_t count = git_diff_num_deltas(diff);
    stage_change_t *entries = arena_calloc(arena, count, sizeof(*entries));
    for (size_t i = 0; i < count; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        entries[i] = (stage_change_t){
            .path = arena_strdup(arena, delta->new_file.path),
            .before = stage_side_type(&delta->old_file),
            .after = stage_side_type(&delta->new_file),
        };
    }
    git_diff_free(diff);

    *out = (stage_changes_t){ .entries = entries, .count = count };
    return NULL;
}

error_t stage_commit(
    stage_t *st, const char *message, const char *action, bool *out_committed
) {
    CHECK_NULL(st);
    CHECK_NULL(message);
    CHECK_NULL(action);

    if (out_committed) {
        *out_committed = false;
    }

    git_oid tree_oid;
    int rc = git_index_write_tree_to(&tree_oid, st->index, st->repo);
    if (rc < 0) {
        return error_git(rc, "Failed to write the tree for '%s'", st->refname);
    }

    /* The tree the open read: nothing to commit, nothing moves. */
    if (git_oid_equal(&tree_oid, git_tree_id(st->tree))) {
        return NULL;
    }

    git_tree *tree = NULL;
    rc = git_tree_lookup(&tree, st->repo, &tree_oid);
    if (rc < 0) {
        return error_git(rc, "Failed to read the tree written for '%s'", st->refname);
    }

    git_signature *sig = NULL;
    error_t err = gitops_get_signature(&sig, st->repo);
    if (err) {
        git_tree_free(tree);
        return err;
    }

    /* The object: the tree, the head the open read as its one parent — none for
     * an orphan's stage — and the writer's action in its header, written apart
     * from the ref, which is written below */
    const git_commit *parents[] = { st->parent };
    git_oid commit_oid;
    err = gitops_create_commit(
        st->repo, sig, sig, NULL, message, tree, st->parent ? 1 : 0, parents, action,
        &commit_oid
    );
    git_signature_free(sig);
    git_tree_free(tree);
    if (err) return error_wrap(err, "Failed to commit to '%s'", st->refname);

    /* The line git writes for a commit, off the commit just written: libgit2's
     * summary rule, never a second spelling of it (refs.c
     * git_reference__update_for_commit), and a summary it cannot allocate its
     * failure */
    git_commit *commit = NULL;
    rc = git_commit_lookup(&commit, st->repo, &commit_oid);
    const char *summary = rc == 0 ? git_commit_summary(commit) : NULL;
    if (rc == 0 && !summary) rc = -1;
    if (rc < 0) {
        git_commit_free(commit);
        return error_git(rc, "Failed to read the commit written for '%s'", st->refname);
    }
    char *reflog_msg = heap_str_format(
        "commit%s: %s", st->parent ? "" : " (initial)", summary
    );
    git_commit_free(commit);

    /* The ref, from the head the open read — from nothing for an orphan's stage:
     * a head another writer moved or deleted since, or a ref one made, refuses
     * under the ref's lock (sys/gitops.h gitops_write_reference) */
    const git_oid none = GIT_OID_SHA1_ZERO;
    err = gitops_write_reference(
        st->repo, st->refname, &commit_oid,
        st->parent ? git_commit_id(st->parent) : &none, reflog_msg
    );
    free(reflog_msg);

    /* Refused, the object stays loose (the header) and nothing was committed:
     * the clause every refusal of the write carries, re-minted over the writer's
     * one fact (base/error.h "Messages") */
    if (err) {
        return error_create(
            error_code(err), "%s; nothing was committed", error_message(err)
        );
    }

    if (out_committed) {
        *out_committed = true;
    }
    return NULL;
}

void stage_free(stage_t *st) {
    if (!st) {
        return;
    }

    git_index_free(st->index);
    git_tree_free(st->tree);
    git_commit_free(st->parent);
    free(st->refname);
    free(st);
}
