/**
 * stage.c - One ref's next tree, staged in memory: implementation
 *
 * See stage.h. The stage composes four libgit2 primitives: the ref resolved once
 * (git_reference_name_to_id), an ownerless index seeded from the tip's tree
 * (git_index_new + git_index_read_tree — never git_repository_index, the
 * checked-out branch's staging area), the tree written straight to the ODB
 * (git_index_write_tree_to — never git_index_write, which wants a backing file),
 * and git_commit_create with `update_ref`, which reads the ref's current tip
 * and refuses unless it is the first parent handed in — for a root commit, unless
 * the ref is still absent (commit.c) — then moves the ref under its lock against
 * the value it just read (refdb_fs.c). That check is the last inch of the
 * atomicity, and libgit2 is the right owner of it: the stage classifies its two
 * refusals (GIT_EMODIFIED for a tip that moved or a ref that appeared before
 * the commit looked, GIT_EEXISTS for one that appeared between the look and the
 * lock) and states the rest.
 */

#include "sys/stage.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "sys/gitops.h"

struct stage {
    git_repository *repo;   /* borrowed */
    char *refname;          /* owned */
    git_commit *parent;     /* the tip at open; NULL for an orphan's stage */
    git_tree *tree;         /* the parent's tree, or the empty tree */
    git_index *index;       /* ownerless, seeded from tree */
};

/**
 * The stage on `refname`, seeded: the tree at `tip` in a private index with the
 * tip as the parent-to-be, or — when `tip` is NULL, the orphan's stage — the
 * empty tree and no parent
 *
 * The stage owns everything it makes from its first allocation on, so every failure
 * frees through stage_free and nothing is handed across this call half-built.
 * The two openers are its doors: each resolves the ref, refuses the state it
 * did not expect, and seeds here.
 */
static error_t *stage_seed(
    git_repository *repo, const char *refname, const git_oid *tip, stage_t **out
) {
    stage_t *st = calloc(1, sizeof(*st));
    if (!st) {
        return ERROR(ERR_MEMORY, "Failed to allocate stage");
    }
    st->repo = repo;
    st->refname = strdup(refname);
    if (!st->refname) {
        stage_free(st);
        return ERROR(ERR_MEMORY, "Failed to copy reference name");
    }

    int rc;
    if (tip) {
        /* The tip is the parent-to-be, so it must be a commit: a ref to any other
         * object refuses at the lookup, in Git's words. */
        rc = git_commit_lookup(&st->parent, repo, tip);
        if (rc == 0) {
            rc = git_commit_tree(&st->tree, st->parent);
        }
        if (rc < 0) {
            stage_free(st);
            return error_wrap(
                error_from_git(rc), "Failed to read the tip of '%s'", refname
            );
        }
    } else {
        /* The empty tree: Git's own "nothing", the tree every orphan's stage
         * opens on. Read, never written: its id is the hash of a tree with no
         * entries, and libgit2 — like git — serves that one object whether or
         * not the database holds it (odb.c odb_read_hardcoded, present at the
         * 1.5 floor). The index seeded from it answers for its tree from its
         * own cache until a verb touches it (tree.c git_tree__write_index), so
         * an orphan's stage committed untouched meets the rule every stage keeps
         * — a tree equal to the opened one — and writes nothing there either. */
        git_oid empty;
        rc = git_odb_hash(&empty, "", 0, GIT_OBJECT_TREE);
        if (rc == 0) {
            rc = git_tree_lookup(&st->tree, repo, &empty);
        }
        if (rc < 0) {
            stage_free(st);
            return error_wrap(
                error_from_git(rc), "Failed to read the empty tree for '%s'",
                refname
            );
        }
    }

    rc = git_index_new(&st->index);
    if (rc == 0) {
        rc = git_index_read_tree(st->index, st->tree);
    }
    if (rc < 0) {
        stage_free(st);
        return error_wrap(
            error_from_git(rc), "Failed to read the tree of '%s'", refname
        );
    }

    *out = st;
    return NULL;
}

error_t *stage_open(git_repository *repo, const char *refname, stage_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out);
    *out = NULL;

    git_oid tip;
    int rc = git_reference_name_to_id(&tip, repo, refname);
    if (rc == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "Reference '%s' does not exist", refname);
    }
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Failed to resolve reference '%s'", refname
        );
    }

    return stage_seed(repo, refname, &tip, out);
}

error_t *stage_orphan(git_repository *repo, const char *refname, stage_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out);
    *out = NULL;

    git_oid tip;
    int rc = git_reference_name_to_id(&tip, repo, refname);
    if (rc == 0) {
        return ERROR(ERR_EXISTS, "Reference '%s' already exists", refname);
    }
    if (rc != GIT_ENOTFOUND) {
        return error_wrap(
            error_from_git(rc), "Failed to resolve reference '%s'", refname
        );
    }

    return stage_seed(repo, refname, NULL, out);
}

const git_tree *stage_tree(const stage_t *st) {
    return st ? st->tree : NULL;
}

git_index *stage_index(stage_t *st) {
    return st ? st->index : NULL;
}

error_t *stage_put(
    stage_t *st, const char *path, const void *data, size_t size,
    git_filemode_t mode
) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_ARG(data != NULL || size == 0, "data cannot be NULL with a size");

    git_oid blob;
    int rc = git_blob_create_from_buffer(
        &blob, st->repo, size > 0 ? data : "", size
    );
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Failed to write the blob for '%s'", path
        );
    }

    return stage_put_blob(st, path, &blob, mode);
}

/**
 * Can anything at all be named at this path — the shape, and no blob above it?
 *
 * The identical beginning of both admissions: what libgit2 would refuse later
 * with a worse message, and then a proper prefix that names an entry, which puts
 * the path inside a file. Neither answer depends on what is being put there.
 *
 * The scratch is this function's, NUL-terminated at each slash in turn; the
 * sentence prints from `path`, which is whole throughout.
 */
static error_t *admit_tree_path(const stage_t *st, const char *path) {
    size_t len = strlen(path);
    if (len == 0 || path[0] == '/' || path[len - 1] == '/' || strstr(path, "//")) {
        return ERROR(
            ERR_INVALID_ARG,
            "Cannot stage '%s': a tree path has no leading or trailing slash "
            "and no empty component", path
        );
    }

    char *scratch = malloc(len + 1);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to allocate path scratch");
    }
    memcpy(scratch, path, len + 1);

    /* A file where a directory is needed: a proper prefix naming an entry. */
    for (char *slash = strchr(scratch, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        if (git_index_get_bypath(st->index, scratch, 0)) {
            int prefix_len = (int) (slash - scratch);
            free(scratch);
            return ERROR(
                ERR_CONFLICT, "Cannot stage '%s': '%.*s' is a file in this tree",
                path, prefix_len, path
            );
        }
        *slash = '/';
    }

    free(scratch);

    return NULL;
}

error_t *stage_admit_blob(const stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    RETURN_IF_ERROR(admit_tree_path(st, path));

    /* A directory where the file goes: any entry beneath the path. The index is
     * sorted, so one prefix probe answers. */
    size_t len = strlen(path);
    char *beneath = malloc(len + 2);
    if (!beneath) {
        return ERROR(ERR_MEMORY, "Failed to allocate path scratch");
    }
    memcpy(beneath, path, len);
    beneath[len] = '/';
    beneath[len + 1] = '\0';

    int rc = git_index_find_prefix(NULL, st->index, beneath);
    free(beneath);

    if (rc == 0) {
        return ERROR(
            ERR_CONFLICT, "Cannot stage '%s': it is a directory in this tree",
            path
        );
    }
    if (rc != GIT_ENOTFOUND) {
        /* Not tidiness: reading "no conflict" out of a failure to look admits a
         * blob the index would then make room for by dropping an entry. The linked
         * libgit2 is whichever one pkg-config found at or above 1.5, and its
         * contract here is "0 or an error code". */
        return error_wrap(
            error_from_git(rc), "Failed to search the tree beneath '%s'", path
        );
    }

    return NULL;
}

error_t *stage_admit_subtree(const stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    RETURN_IF_ERROR(admit_tree_path(st, path));

    /* A file at the path itself: a blob and a subtree cannot both stand there,
     * and nothing beneath it could be committed either. Entries beneath the path
     * are the subtree already standing, and need no asking. */
    if (git_index_get_bypath(st->index, path, 0)) {
        return ERROR(
            ERR_CONFLICT, "Cannot stage '%s': it is a file in this tree", path
        );
    }

    return NULL;
}

error_t *stage_put_blob(
    stage_t *st, const char *path, const git_oid *blob, git_filemode_t mode
) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_NULL(blob);

    if (mode != GIT_FILEMODE_BLOB &&
        mode != GIT_FILEMODE_BLOB_EXECUTABLE &&
        mode != GIT_FILEMODE_LINK) {
        return ERROR(
            ERR_INVALID_ARG,
            "Cannot stage '%s' with mode 0%o: not a blob or link mode",
            path, (unsigned int) mode
        );
    }

    /* The shape and the two collisions, before anything is added (see the header):
     * the mode above is the put's own, since a caller asking about a path it
     * has not read yet has no mode to offer. */
    RETURN_IF_ERROR(stage_admit_blob(st, path));

    /* The same path already an entry: replaced — the upsert every writer wants. */
    git_index_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.mode = (uint32_t) mode;
    entry.path = path;
    git_oid_cpy(&entry.id, blob);

    int rc = git_index_add(st->index, &entry);
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Failed to stage '%s'", path);
    }

    return NULL;
}

error_t *stage_remove(stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);

    /* git_index_remove at stage 0 reports a missing entry, where
     * git_index_remove_bypath would swallow it ("ensure gone"). */
    int rc = git_index_remove(st->index, path, 0);
    if (rc == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "'%s' is not in this tree", path);
    }
    if (rc < 0) {
        return error_wrap(error_from_git(rc), "Failed to remove '%s'", path);
    }

    return NULL;
}

error_t *stage_commit(stage_t *st, const char *message, bool *out_committed) {
    CHECK_NULL(st);
    CHECK_NULL(message);

    if (out_committed) {
        *out_committed = false;
    }

    git_oid tree_oid;
    int rc = git_index_write_tree_to(&tree_oid, st->index, st->repo);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Failed to write the tree for '%s'", st->refname
        );
    }

    /* The tree the open read: nothing to commit, nothing moves. */
    if (git_oid_equal(&tree_oid, git_tree_id(st->tree))) {
        return NULL;
    }

    git_tree *tree = NULL;
    rc = git_tree_lookup(&tree, st->repo, &tree_oid);
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Failed to read the tree written for '%s'",
            st->refname
        );
    }

    git_signature *sig = NULL;
    error_t *err = gitops_get_signature(&sig, st->repo);
    if (err) {
        git_tree_free(tree);
        return err;
    }

    /* The parent is the tip the open read, and libgit2 moves the ref only if
     * that is still its tip — for a root commit, only if the ref is still
     * absent. */
    const git_commit *parents[] = { st->parent };
    git_oid commit_oid;
    rc = git_commit_create(
        &commit_oid, st->repo, st->refname, sig, sig, NULL, message, tree,
        st->parent ? 1 : 0, parents
    );
    git_signature_free(sig);
    git_tree_free(tree);

    if (rc == GIT_EMODIFIED || rc == GIT_EEXISTS) {
        return ERROR(
            ERR_CONFLICT,
            "Reference '%s' was changed by another writer since this command "
            "read it; nothing was committed\n"
            "Run the command again", st->refname
        );
    }
    if (rc < 0) {
        return error_wrap(
            error_from_git(rc), "Failed to commit to '%s'", st->refname
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
