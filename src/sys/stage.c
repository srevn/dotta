/**
 * stage.c - One ref's next commit, staged in memory: implementation
 *
 * See stage.h. The stage composes five primitives: the ref read once to its head,
 * its absence proven (sys/gitops.h gitops_load_reference_commit,
 * gitops_reference_exists), an ownerless index seeded from the head's tree
 * (git_index_new + git_index_read_tree — never git_repository_index, the
 * checked-out branch's staging area) or from Git's merge of it with another
 * commit's (git_merge_trees, whose index is ownerless too), the tree written
 * straight to the ODB (git_index_write_tree_to — never git_index_write, which
 * wants a backing file), gitops' one writer of a commit object, which moves no
 * ref (gitops_create_commit), and gitops' one writer of a ref, from the head
 * the open read — from nothing for an orphan's stage (gitops_write_reference).
 * That write's compare, under the ref's own lock, is the last inch of the
 * atomicity, and it is still libgit2's: the stage owns no lock, and says every
 * refusal of the write as the writer's one fact with its own clause.
 */

#include "sys/stage.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "sys/gitops.h"

struct stage {
    git_repository *repo;   /* borrowed */
    char *refname;          /* owned */
    git_commit *parent;     /* the head at open, the first parent; NULL for an orphan's stage */
    git_commit *theirs;     /* a merge's second parent; NULL over no merge */
    git_tree *tree;         /* the parent's tree, or the empty tree */
    git_tree *theirs_tree;  /* the second parent's tree; NULL over no merge */
    git_tree *merge_base;   /* the merge base's tree, or the empty tree; NULL over no merge */
    git_index *index;       /* ownerless: the tree read into it, or Git's merge of the three */
};

struct stage_admission {
    git_index *index;       /* ownerless: the opened tree, and every blob admitted since */
};

/**
 * Git's empty tree: its own "nothing", read and never written
 *
 * Its id is the hash of a tree with no entries, and libgit2 — like git — serves
 * that one object whether or not the database holds it (odb.c odb_read_hardcoded).
 *
 * Readers: stage_seed, the tree an orphan's stage opens on; stage_merge_trees,
 * the merge base of two histories that share no commit.
 */
static error_t stage_empty_tree(const stage_t *st, git_tree **out) {
    git_oid empty;
    int rc = git_odb_hash(&empty, "", 0, GIT_OBJECT_TREE);
    if (rc == 0) {
        rc = git_tree_lookup(out, st->repo, &empty);
    }
    if (rc < 0) {
        return error_git(rc, "Failed to read the empty tree for '%s'", st->refname);
    }

    return NULL;
}

/**
 * An ownerless index holding the tree the stage opened at
 *
 * Ownerless — never git_repository_index, the checked-out branch's staging area
 * — so libgit2's path rule runs at every add, and the object check waits for a
 * tree write (index.c index_insert). The index holds its own copies of the entries:
 * the stage is not borrowed past the call.
 *
 * Readers: stage_seed, the index of a stage over one parent or none;
 * stage_admission_create, an admission's.
 */
static error_t stage_read_tree(const stage_t *st, git_index **out) {
    int rc = git_index_new(out);
    if (rc == 0) {
        rc = git_index_read_tree(*out, st->tree);
    }
    if (rc < 0) {
        return error_git(rc, "Failed to read the tree of '%s'", st->refname);
    }

    return NULL;
}

/**
 * A merge's index: Git's three-way merge of the opened tree and theirs over the
 * tree the two histories last shared, under the stage's own options
 *
 * A failure is said as the merge's, theirs' read among them — a commit the store
 * lacks named by libgit2 — save the empty tree's, said as each reader of it says
 * it (stage_empty_tree).
 *
 * Reader: stage_seed, a merge's seed.
 */
static error_t stage_merge_trees(stage_t *st, const git_oid *theirs) {
    /* Theirs, the second parent — any commit the store holds — and its tree */
    int rc = git_commit_lookup(&st->theirs, st->repo, theirs);
    if (rc == 0) {
        rc = git_commit_tree(&st->theirs_tree, st->theirs);
    }
    if (rc < 0) {
        return error_git(rc, "Failed to merge into '%s'", st->refname);
    }

    /* The tree the two histories last shared: their merge base's, the first of
     * their best common ancestors (sys/gitops.h gitops_find_merge_base) — or,
     * where they share no commit, Git's empty tree, as git merges unrelated
     * histories: an empty ancestor merges as none does
     * (lib/libgit2/src/libgit2/merge.c git_merge__iterators) */
    git_oid base;
    error_t err = gitops_find_merge_base(
        st->repo, git_commit_id(st->parent), git_commit_id(st->theirs), &base
    );
    if (!err && git_oid_is_zero(&base)) {
        err = stage_empty_tree(st, &st->merge_base);
        if (err) return err;
    } else {
        if (!err) err = gitops_get_tree_from_commit(st->repo, &base, &st->merge_base);
        if (err) return error_wrap(err, "Failed to merge into '%s'", st->refname);
    }

    /* Git's merge, under the stage's own options (the header): no rename paired
     * — the options' one default flag is GIT_MERGE_FIND_RENAMES
     * (include/git2/merge.h GIT_MERGE_OPTIONS_INIT), and with it clear the pairing
     * returns at once (merge.c git_merge_diff_list__find_renames) — Git's text
     * driver named, so merge.default is never read (merge.c merge_normalize_opts),
     * and no favor, the options' own GIT_MERGE_FILE_FAVOR_NORMAL. The index it
     * answers is a new one, ownerless as the stage's every index is (merge.c
     * index_from_diff_list), so the puts keep their contract on it. */
    git_merge_options opts;
    git_merge_options_init(&opts, GIT_MERGE_OPTIONS_VERSION);
    opts.flags &= ~GIT_MERGE_FIND_RENAMES;
    opts.default_driver = "text";
    rc = git_merge_trees(
        &st->index, st->repo, st->merge_base, st->tree, st->theirs_tree, &opts
    );
    if (rc < 0) {
        return error_git(rc, "Failed to merge into '%s'", st->refname);
    }

    return NULL;
}

/**
 * The stage on `refname`, seeded: the tree of `parent` with it as the first parent
 * — or, where `parent` is NULL, the orphan's stage, the empty tree and no parent
 * — and the index the commit's tree is written from: that tree read into it,
 * or, where `theirs` names a commit, Git's merge of the two
 *
 * The stage owns everything it makes from its first allocation on, and the parent
 * from the call, so every failure frees through stage_free and nothing is handed
 * across this call half-built. Its readers are the three openers: each resolves
 * the ref, refuses the state it did not expect, and seeds here — two seeds of
 * one model, a merge's the second.
 */
static error_t stage_seed(
    git_repository *repo, const char *refname, git_commit *parent, const git_oid *theirs,
    stage_t **out
) {
    stage_t *st = heap_calloc(1, sizeof(*st));
    st->repo = repo;
    st->refname = heap_strdup(refname);
    st->parent = parent;

    /* The tree every move is measured from: the head's, a merge's among them,
     * or Git's empty tree, every orphan's stage's. The index seeded from the
     * empty tree answers for its tree from its own cache until a verb touches
     * it (tree.c git_tree__write_index), so an orphan's stage committed untouched
     * meets the rule every stage keeps — a tree equal to the opened one — and
     * writes nothing there either. */
    error_t err = NULL;
    if (parent) {
        int rc = git_commit_tree(&st->tree, parent);
        if (rc < 0) err = error_git(rc, "Failed to read the head of '%s'", refname);
    } else {
        err = stage_empty_tree(st, &st->tree);
    }

    /* The index: the opened tree read into it, or Git's merge of it and theirs */
    if (!err) {
        err = theirs ? stage_merge_trees(st, theirs) : stage_read_tree(st, &st->index);
    }
    if (err) {
        stage_free(st);
        return err;
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

    return stage_seed(repo, refname, parent, NULL, out);
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

    return stage_seed(repo, refname, NULL, NULL, out);
}

error_t stage_merge(
    git_repository *repo, const char *refname, const git_oid *theirs, stage_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(theirs);
    CHECK_NULL(out);
    *out = NULL;

    /* The head, the first parent, read and refused as stage_open reads it; theirs
     * is the seed's, which merges it in (stage_merge_trees) */
    git_commit *parent = NULL;
    error_t err = gitops_load_reference_commit(repo, refname, &parent);
    if (err) return err;

    return stage_seed(repo, refname, parent, theirs, out);
}

const git_tree *stage_tree(const stage_t *st) {
    CHECK_NULL(st);

    return st->tree;
}

const git_tree *stage_theirs(const stage_t *st) {
    CHECK_NULL(st);

    return st->theirs_tree;
}

const git_tree *stage_merge_base(const stage_t *st) {
    CHECK_NULL(st);

    return st->merge_base;
}

/**
 * Git's type for what a mode word says stands at a name: a gitlink's is a commit,
 * a directory's a tree, and every other mode's a blob
 *
 * libgit2's own reading of a tree entry, whole (lib/libgit2/src/libgit2/tree.c
 * git_tree_entry_type: S_ISGITLINK, then S_ISDIR), asked of a mode the stage
 * meets as a tree spelled it — an index entry's, where the index was seeded from
 * one (index.c read_tree_cb), and a delta's file, before or after, which the
 * comparison hands on from either (iterator.c tree_iterator_set_current) — so a
 * blob of whatever permission bits a hand's tree spells is the blob the profile's
 * walk reads there (core/profiles.c profile_step).
 *
 * Readers: the noun a refusal names an entry in a name's way by (stage_mode_noun),
 * what a delta says stood at its name (stage_delta_type), and what the tree holds
 * at one (stage_holds).
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
 * The identical beginning of both halves of the rule, a blob's and a subtree's:
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
 * Whether `index` holds an entry beneath `path`: one the name and a separator
 * begin, at any depth
 *
 * The separator is the boundary: an entry at the name itself is not beneath it,
 * nor one at a sibling the name merely prefixes ("x.bak" and "x0" beside "x").
 * The index is sorted, so one prefix probe answers (lib/libgit2/src/libgit2/index.c
 * git_index_find_prefix), and it asks every stage: a conflict's entries are entries
 * here.
 *
 * Readers: stage_put_entry, a directory where the file goes; stage_holds_beneath,
 * the stage's question of its own index, so the put's refusal and the prune's
 * answer cannot part.
 */
static error_t stage_beneath(git_index *index, const char *path, bool *out) {
    size_t len = strlen(path);
    char *prefix = heap_alloc(len + 2);
    memcpy(prefix, path, len);
    prefix[len] = '/';
    prefix[len + 1] = '\0';

    int rc = git_index_find_prefix(NULL, index, prefix);
    free(prefix);

    /* Not tidiness: a failure read as nothing beneath would admit a blob the
     * index then makes room for by dropping an entry, and let the prune take a
     * derivation something stands beneath. The linked libgit2 is whichever one
     * pkg-config found at or above 1.9, and its contract here is "0 or an error
     * code", GIT_ENOTFOUND where no entry begins with the prefix. */
    if (rc != 0 && rc != GIT_ENOTFOUND) {
        return error_git(rc, "Failed to search the tree beneath '%s'", path);
    }

    *out = rc == 0;
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

    /* A directory where the file goes: any entry beneath the path */
    bool beneath = false;
    err = stage_beneath(index, path, &beneath);
    if (err) return err;
    if (beneath) {
        return error_create(
            ERR_CONFLICT,
            "Cannot stage '%s': it is a directory in this tree", path
        );
    }

    /* The same path already an entry: replaced — the upsert every writer wants. */
    int rc = git_index_add(index, entry);
    if (rc == 0) return NULL;

    /* The index class is exact here: the mode is checked above and both collisions
     * refused, so on this path it is raised by the path rule alone. */
    const git_error *cause = git_error_last();
    if (cause->klass == GIT_ERROR_INDEX) {
        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': Git refuses the name (%s)",
            path, cause->message
        );
    }

    return error_git(rc, "Failed to stage '%s'", path);
}

error_t stage_admission_create(const stage_t *st, stage_admission_t **out) {
    CHECK_NULL(st);
    CHECK_NULL(out);
    *out = NULL;

    stage_admission_t *adm = heap_calloc(1, sizeof(*adm));

    /* Ownerless, as the stage's own index is (stage_read_tree): the path rule
     * runs at every add, and the object check waits for a tree write that never
     * comes. The opened tree, a merge's head's included, and never the stage's
     * index. */
    error_t err = stage_read_tree(st, &adm->index);
    if (err) {
        stage_admission_free(adm);
        return err;
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

error_t stage_conflicts(const stage_t *st, arena_t *arena, string_array_t *out) {
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    git_index_conflict_iterator *conflicts = NULL;
    int rc = git_index_conflict_iterator_new(&conflicts, st->index);
    if (rc < 0) {
        return error_git(rc, "Failed to read the conflicts of '%s'", st->refname);
    }

    /* Each name once, in the index's order: the iterator steps past a name's
     * stages together, and any side it holds names it — the three share the name.
     * The iteration classifies its three answers, as every one dotta makes does:
     * an entry, the end, or a failure. */
    string_array_t names;
    string_array_init(&names, arena, 0);
    const git_index_entry *ancestor = NULL;
    const git_index_entry *ours = NULL;
    const git_index_entry *theirs = NULL;
    while ((rc = git_index_conflict_next(&ancestor, &ours, &theirs, conflicts)) == 0) {
        string_array_push(&names, (ancestor ? ancestor : ours ? ours : theirs)->path);
    }
    git_index_conflict_iterator_free(conflicts);
    if (rc != GIT_ITEROVER) {
        return error_git(rc, "Failed to read the conflicts of '%s'", st->refname);
    }

    *out = names;
    return NULL;
}

/* One walk of the tree a name is settled from: the index the tree's entries go
 * into, and the name */
typedef struct {
    git_index *index;           /* The stage's */
    const char *path;           /* The name settled */
    size_t path_len;            /* Its length, asked once */
} stage_walk_t;

/*
 * The settle's visitor, once per entry of the tree it reads: an entry at the
 * name or beneath it put where it stands — a blob, and a gitlink its mode refuses
 * — and a tree there passed into; an entry above the name, on the way down to
 * it, passed into; every other entry passed by, a tree with everything beneath
 * it, so the walk reads the way to the name and what stands there, and no more.
 */
static error_t stage_step(
    const char *path, const git_tree_entry *entry, void *payload, gitops_next_t *next
) {
    const stage_walk_t *walk = payload;

    if (str_path_under(path, walk->path, walk->path_len)) {
        if (git_tree_entry_type(entry) == GIT_OBJECT_TREE) return NULL;

        git_index_entry put;
        memset(&put, 0, sizeof(put));
        put.mode = git_tree_entry_filemode(entry);
        put.path = path;
        git_oid_cpy(&put.id, git_tree_entry_id(entry));

        return stage_put_entry(walk->index, &put);
    }

    if (!str_path_beneath(walk->path, path, strlen(path))) {
        *next = GITOPS_NEXT_SKIP;
    }
    return NULL;
}

error_t stage_settle(stage_t *st, const char *path, const git_tree *tree) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_NULL(tree);

    /* What the index holds at the name and beneath it goes, the staged entry
     * and a conflict's alike. libgit2 takes an entry at a name, and every entry
     * beneath it ("<path>/"), one stage at a time (index.c git_index_remove,
     * which answers GIT_ENOTFOUND where none stands, and
     * git_index_remove_directory), so each of the four is asked in turn: the
     * staged one, then the merge base's, ours' and theirs'. */
    for (int i = GIT_INDEX_STAGE_NORMAL; i <= GIT_INDEX_STAGE_THEIRS; i++) {
        int rc = git_index_remove(st->index, path, i);
        if (rc == 0 || rc == GIT_ENOTFOUND) {
            rc = git_index_remove_directory(st->index, path, i);
        }
        if (rc < 0) {
            return error_git(rc, "Failed to settle '%s'", path);
        }
    }

    /* Then what the tree holds there, each entry put as every entry is
     * (stage_put_entry), its mode the tree's, read as libgit2 reads one (tree.c
     * git_tree_entry_filemode) — nothing at or beneath the name stands in its
     * way any more — and its blob the tree's, held already (stage_step) */
    stage_walk_t walk = { .index = st->index, .path = path, .path_len = strlen(path) };
    return gitops_tree_walk(tree, stage_step, &walk);
}

error_t stage_unite(stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);

    /* The conflict at the name: the merge base's entry there, ours' and theirs',
     * each where that side holds a blob */
    const git_index_entry *ancestor = NULL;
    const git_index_entry *ours = NULL;
    const git_index_entry *theirs = NULL;
    int rc = git_index_conflict_get(&ancestor, &ours, &theirs, st->index, path);
    if (rc == GIT_ENOTFOUND) {
        return error_create(
            ERR_NOT_FOUND, "Cannot unite '%s': no conflict stands there", path
        );
    }
    if (rc < 0) {
        return error_git(rc, "Failed to unite '%s'", path);
    }

    /* A removal has no lines to unite with the other side's: the conflict stands */
    if (!ours || !theirs) {
        return error_create(
            ERR_CONFLICT, "Cannot unite '%s': a side holds nothing there", path
        );
    }

    /* The union, made in memory over the three blobs: a version Git reads as
     * binary — a NUL in its first 8,000 bytes — composes under no favor but ours'
     * or theirs', and comes back not automergeable, nothing written (merge_file.c
     * merge_file__from_inputs, merge_file__binary) */
    git_merge_file_options opts;
    git_merge_file_options_init(&opts, GIT_MERGE_FILE_OPTIONS_VERSION);
    opts.favor = GIT_MERGE_FILE_FAVOR_UNION;
    git_merge_file_result united;
    rc = git_merge_file_from_index(&united, st->repo, ancestor, ours, theirs, &opts);
    if (rc < 0) {
        return error_git(rc, "Failed to unite '%s'", path);
    }
    if (!united.automergeable) {
        git_merge_file_result_free(&united);
        return error_create(
            ERR_CONFLICT, "Cannot unite '%s': Git reads a version of it as binary", path
        );
    }

    /* Its blob, written once, under Git's mode for the three (merge.h
     * git_merge_file__best_mode) */
    git_index_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.mode = united.mode;
    entry.path = path;
    rc = git_blob_create_from_buffer(
        &entry.id, st->repo, united.len > 0 ? united.ptr : "", united.len
    );
    git_merge_file_result_free(&united);
    if (rc < 0) {
        return error_git(rc, "Failed to write the blob for '%s'", path);
    }

    /* Staged beside the conflict, and then the conflict taken: the add replaces
     * only the entry of its own stage (the header), so a put refused would leave
     * the conflict standing — and none is, both sides holding a blob at the name */
    error_t err = stage_put_entry(st->index, &entry);
    if (err) return err;

    rc = git_index_conflict_remove(st->index, path);
    if (rc < 0) {
        return error_git(rc, "Failed to unite '%s'", path);
    }

    return NULL;
}

stage_held_t stage_holds(const stage_t *st, const char *path) {
    CHECK_NULL(st);
    CHECK_NULL(path);

    /* The staged entry, at stage 0 — a conflict's entries stand at the other
     * three, and no tree holds them — by one lookup in the index's own map, which
     * finds an entry or none (index.c git_index_get_bypath) */
    const git_index_entry *entry = git_index_get_bypath(st->index, path, 0);
    if (!entry) {
        return (stage_held_t){ .type = GIT_OBJECT_INVALID };
    }

    /* Its type as libgit2 reads the mode word (stage_mode_type), and the entry's
     * two facts copied out by value: the index's entry moves with its next edit */
    return (stage_held_t){
        .type = stage_mode_type(entry->mode),
        .oid = entry->id,
        .filemode = (git_filemode_t) entry->mode,
    };
}

error_t stage_holds_beneath(const stage_t *st, const char *path, bool *out) {
    CHECK_NULL(st);
    CHECK_NULL(path);
    CHECK_NULL(out);

    /* The put's own search, of the index every edit so far has left (stage_beneath) */
    return stage_beneath(st->index, path, out);
}

/**
 * The index against the tree the open read, a type change one delta
 *
 * Readers: stage_changed, whether any entry moved over one parent or none;
 * stage_changes, each one — one comparison for both questions, so the bool and
 * the list cannot part where the bool asks it.
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

    /* A merge's second parent records the integration whatever the tree, so its
     * commit moves the ref (stage_commit) */
    if (st->theirs) {
        *out = true;
        return NULL;
    }

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
 * What a delta says stood at its name, before or after: Git's type for the file's
 * mode (stage_mode_type), or GIT_OBJECT_INVALID where nothing stands — an
 * addition's before, a removal's after
 *
 * Absence is read off libgit2's own word for it, the flag that the file exists
 * (include/git2/diff.h GIT_DIFF_FLAG_EXISTS), never off the mode 0 a zeroed delta
 * leaves an absent file at (lib/libgit2/src/libgit2/diff_generate.c
 * diff_delta__alloc): a hand's tree can spell 0 (tree.c parse_mode), which the
 * walk reads as a blob.
 *
 * Reader: stage_changes, each delta's two files.
 */
static git_object_t stage_delta_type(const git_diff_file *file) {
    return file->flags & GIT_DIFF_FLAG_EXISTS
        ? stage_mode_type(file->mode) : GIT_OBJECT_INVALID;
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
     * for its two files since no rename is asked (diff_generate.c
     * diff_delta__alloc), copied out of the diff that goes, and what stood there
     * before and after. The room is made at once, and an arena's answer is never
     * NULL, for no delta either */
    const size_t count = git_diff_num_deltas(diff);
    stage_change_t *entries = arena_calloc(arena, count, sizeof(*entries));
    for (size_t i = 0; i < count; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        entries[i] = (stage_change_t){
            .path = arena_strdup(arena, delta->new_file.path),
            .before = stage_delta_type(&delta->old_file),
            .after = stage_delta_type(&delta->new_file),
        };
    }
    git_diff_free(diff);

    *out = (stage_changes_t){ .entries = entries, .count = count };
    return NULL;
}

error_t stage_commit(
    stage_t *st, const char *message, const char *action, git_oid *out_commit
) {
    CHECK_NULL(st);
    CHECK_NULL(message);
    CHECK_NULL(action);

    if (out_commit) {
        *out_commit = (git_oid) GIT_OID_SHA1_ZERO;
    }

    /* The tree, which a conflict a merge left standing refuses in Git's words
     * (tree.c git_tree__write_index) */
    git_oid tree_oid;
    int rc = git_index_write_tree_to(&tree_oid, st->index, st->repo);
    if (rc < 0) {
        return error_git(rc, "Failed to write the tree for '%s'", st->refname);
    }

    /* The tree the open read: nothing to commit, nothing moves — save over a
     * merge, whose second parent records the integration whatever the tree */
    if (!st->theirs && git_oid_equal(&tree_oid, git_tree_id(st->tree))) {
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

    /* The object: the tree, the head the open read as its first parent — none
     * for an orphan's stage — and a merge's other commit as its second, in git's
     * order, the first the line the merge continues (cmds/show.c show_commit
     * diffs a merge against it); and the writer's action in its header, written
     * apart from the ref, which is written below */
    const git_commit *parents[] = { st->parent, st->theirs };
    git_oid commit_oid;
    err = gitops_create_commit(
        st->repo, sig, sig, NULL, message, tree, st->theirs ? 2 : st->parent ? 1 : 0,
        parents, action, &commit_oid
    );
    git_signature_free(sig);
    git_tree_free(tree);
    if (err) return error_wrap(err, "Failed to commit to '%s'", st->refname);

    /* The summary its line says, off the commit just written: libgit2's rule
     * for a commit's line, never a second spelling of it (refs.c
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

    /* The ref, from the head the open read — from nothing for an orphan's stage:
     * a head another writer moved or deleted since, or a ref one made, refuses
     * under the ref's lock — its line the writer's action, then the summary, a
     * root's alike (sys/gitops.h gitops_write_reference) */
    const git_oid none = GIT_OID_SHA1_ZERO;
    err = gitops_write_reference(
        st->repo, st->refname, &commit_oid,
        st->parent ? git_commit_id(st->parent) : &none, action, "%s", summary
    );
    git_commit_free(commit);

    /* Refused, the object stays loose (the header) and nothing was committed:
     * the clause every refusal of the write carries, re-minted over the writer's
     * one fact (base/error.h "Messages") */
    if (err) {
        return error_create(
            error_code(err), "%s; nothing was committed", error_message(err)
        );
    }

    /* The commit the ref now names, by the id it was written under: the ref read
     * again could answer another writer's commit, made once the lock was let go */
    if (out_commit) {
        git_oid_cpy(out_commit, &commit_oid);
    }
    return NULL;
}

void stage_free(stage_t *st) {
    if (!st) {
        return;
    }

    git_index_free(st->index);
    git_tree_free(st->merge_base);
    git_tree_free(st->theirs_tree);
    git_tree_free(st->tree);
    git_commit_free(st->theirs);
    git_commit_free(st->parent);
    free(st->refname);
    free(st);
}
