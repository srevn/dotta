/**
 * stats.c - Git object and history statistics implementation
 *
 * A blob's size is its object header's (git_odb_read_header): nothing inflated.
 * A path's history is two walks of its lines (sys/stats.h), sharing the rule
 * and nothing else: what a tree holds at a path (stats_entry), and a parent read
 * with its tree (stats_parent). Each keeps lines (stats_line_t), the newest commit
 * a line has reached read next: the last changes' walk one line a path, in the
 * call's one transient; the history's its one path's lines, queued in a frame
 * of its own with every commit they reached.
 */

#include "sys/stats.h"

#include <ctype.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/heap.h"

/**
 * A path's entry in a tree, as its history reads it: a blob, by its id and its
 * filemode, or none
 */
typedef struct {
    git_oid blob;               /* Git's null id: none */
    git_filemode_t mode;        /* Its filemode; none's is 0 */
} stats_entry_t;

/**
 * A line of a path's history: the entry it carries, and the commit it has reached
 */
typedef struct {
    stats_entry_t entry;        /* What every commit on it holds at the path */
    git_oid reached;            /* Git's null id once the line ended */
    git_time_t time;            /* Its commit time: the newest a line has reached is read next */
} stats_line_t;

/**
 * One file's lines not yet read, each commit queued once
 */
typedef struct {
    arena_t *frame;             /* The walk's own: the lines and the set */
    hashmap_t *seen;            /* Hex id: every commit a line has reached */
    stats_line_t *lines;        /* Oldest first: the newest is read next */
    size_t count;
    size_t capacity;
} stats_queue_t;

/**
 * A commit's info, its summary copied into `arena`
 */
commit_info_t stats_commit_info(arena_t *arena, const git_commit *commit) {
    const char *message = git_commit_message(commit);
    if (!message) message = "";

    size_t len = strcspn(message, "\n");
    while (len > 0 && isspace((unsigned char) message[len - 1])) len--;

    return (commit_info_t){
        .oid = *git_commit_id(commit),
        .summary = arena_strndup(arena, message, len),
        .time = git_commit_author(commit)->when.time,
    };
}

/**
 * A blob's size
 */
error_t stats_blob_size(git_repository *repo, const git_oid *blob_oid, size_t *out) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    /* Get object database */
    git_odb *odb = NULL;
    int rc = git_repository_odb(&odb, repo);
    if (rc < 0) return error_git(rc, "Cannot open the object database");

    error_t err = stats_blob_size_with_odb(odb, blob_oid, out);
    git_odb_free(odb);
    return err;
}

/**
 * A blob's size, through a caller-held ODB handle
 */
error_t stats_blob_size_with_odb(git_odb *odb, const git_oid *blob_oid, size_t *out) {
    CHECK_NULL(odb);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    size_t size;
    git_object_t type;
    int rc = git_odb_read_header(&size, &type, odb, blob_oid);
    if (rc < 0) return error_git(rc, "Cannot read a blob's size");

    if (type != GIT_OBJECT_BLOB) {
        return error_create(ERR_INVALID_ARG, "Object is not a blob");
    }

    *out = size;
    return NULL;
}

/**
 * The entry `tree` holds at `path`
 *
 * A blob of any filemode; none where a component is missing, or the name or one
 * above it is no tree's (git_tree_entry_bypath answers GIT_ENOTFOUND for both).
 *
 * @param tree The tree (must not be NULL)
 * @param path A storage path (must not be NULL)
 * @param out The entry (must not be NULL)
 * @return Error or NULL: a subtree on the way that will not read is the failure,
 *         never none
 */
static error_t stats_entry(const git_tree *tree, const char *path, stats_entry_t *out) {
    *out = (stats_entry_t){ 0 };

    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, tree, path);
    if (rc == GIT_ENOTFOUND) return NULL;
    if (rc < 0) return error_git(rc, "Cannot read '%s' in the history", path);

    if (git_tree_entry_type(entry) == GIT_OBJECT_BLOB) {
        *out = (stats_entry_t){
            .blob = *git_tree_entry_id(entry),
            .mode = git_tree_entry_filemode(entry),
        };
    }
    git_tree_entry_free(entry);

    return NULL;
}

/**
 * Parent `i` of `commit`, and its tree
 *
 * @param commit The commit (must not be NULL)
 * @param i Which parent, below the commit's count
 * @param parent The parent, the caller's to free; NULL on a failure (must not
 *               be NULL)
 * @param tree Its tree, the caller's to free; NULL on a failure (must not be NULL)
 * @return Error or NULL
 */
static error_t stats_parent(
    const git_commit *commit, unsigned int i, git_commit **parent, git_tree **tree
) {
    *parent = NULL;
    *tree = NULL;

    /* A parent the commit names and that will not load is the walk's failure,
     * as its tree is: read as none, the commit would be a root, credited with
     * every path it holds */
    int rc = git_commit_parent(parent, commit, i);
    if (rc == 0) rc = git_commit_tree(tree, *parent);
    if (rc < 0) {
        git_commit_free(*parent);
        *parent = NULL;
        return error_git(rc, "Cannot read a commit's parent in the history");
    }

    return NULL;
}

/**
 * Each of a set of paths' last change
 */
error_t stats_last_changes(
    git_repository *repo, const git_oid *head_oid, const char *const *paths,
    size_t count, arena_t *arena, commit_info_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(head_oid);
    if (count > 0) CHECK_NULL(paths);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* A line a path, each at the head and carrying the entry the head holds there:
     * a line goes on only through a parent holding it, so it carries it to its
     * end. The lines are the call's one transient, the heap's (include/runtime.h
     * "Memory"); the answers are the caller's arena's, a none zeroed. */
    stats_line_t *lines = heap_calloc(count, sizeof(*lines));
    commit_info_t *changes = arena_calloc(arena, count, sizeof(*changes));
    error_t err = NULL;

    git_commit *head = NULL;
    git_tree *head_tree = NULL;
    int rc = git_commit_lookup(&head, repo, head_oid);
    if (rc == 0) rc = git_commit_tree(&head_tree, head);
    if (rc < 0) err = error_git(rc, "Cannot read a commit in the history");
    for (size_t p = 0; !err && p < count; p++) {
        err = stats_entry(head_tree, paths[p], &lines[p].entry);
        lines[p].reached = *head_oid;
        lines[p].time = git_commit_time(head);
    }
    git_tree_free(head_tree);
    git_commit_free(head);

    while (!err) {
        /* The newest commit a line has reached is read next, once for every line
         * waiting there */
        size_t newest = count;
        for (size_t p = 0; p < count; p++) {
            if (git_oid_is_zero(&lines[p].reached)) continue;
            if (newest == count || lines[p].time > lines[newest].time) newest = p;
        }
        if (newest == count) break;

        const git_oid reached = lines[newest].reached;
        size_t waiting = 0;
        for (size_t p = 0; p < count; p++) {
            waiting += git_oid_equal(&lines[p].reached, &reached);
        }

        git_commit *commit = NULL;
        rc = git_commit_lookup(&commit, repo, &reached);
        if (rc < 0) {
            err = error_git(rc, "Cannot read a commit in the history");
            break;
        }

        /* Each parent in order takes the lines waiting here whose entry it holds,
         * and a parent is read only while one is left for it: a line goes on
         * through the first parent holding its entry, and that one alone
         * (lib/git/revision.c try_to_simplify_commit) */
        const unsigned int parent_count = git_commit_parentcount(commit);
        for (unsigned int i = 0; !err && waiting > 0 && i < parent_count; i++) {
            git_commit *parent = NULL;
            git_tree *tree = NULL;
            err = stats_parent(commit, i, &parent, &tree);

            for (size_t p = 0; !err && p < count; p++) {
                if (!git_oid_equal(&lines[p].reached, &reached)) continue;

                stats_entry_t held;
                err = stats_entry(tree, paths[p], &held);
                if (!err && git_oid_equal(&held.blob, &lines[p].entry.blob) &&
                    held.mode == lines[p].entry.mode) {
                    lines[p].reached = *git_commit_id(parent);
                    lines[p].time = git_commit_time(parent);
                    waiting--;
                }
            }

            git_tree_free(tree);
            git_commit_free(parent);
        }

        /* The lines no parent took end here: the commit changed their paths — a
         * root what it holds, its parent Git's empty tree, so a line carrying
         * none to a root ends with none */
        if (!err && waiting > 0) {
            const commit_info_t info = stats_commit_info(arena, commit);
            for (size_t p = 0; p < count; p++) {
                if (!git_oid_equal(&lines[p].reached, &reached)) continue;

                if (parent_count > 0 || !git_oid_is_zero(&lines[p].entry.blob)) {
                    changes[p] = info;
                }
                lines[p].reached = (git_oid){ 0 };
            }
        }

        git_commit_free(commit);
    }

    free(lines);
    if (err) return err;

    *out = changes;
    return NULL;
}

/**
 * A line of one file's history reaches a commit
 *
 * Queued by the commit's time where no line reached it before — past every line
 * older, before every line as new, so of two of one age the one queued first is
 * read first — and never again: git's own queue (lib/git/revision.c
 * process_parents, its SEEN).
 *
 * @param queue The file's lines (must not be NULL)
 * @param commit The commit (must not be NULL)
 * @param entry What the commit holds at the path (must not be NULL)
 */
static void stats_arrive(
    stats_queue_t *queue, const git_commit *commit, const stats_entry_t *entry
) {
    char hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(hex, sizeof(hex), git_commit_id(commit));
    if (!hashmap_add(queue->seen, hex, NULL)) return;

    queue->lines = arena_grow(
        queue->frame, queue->lines, &queue->capacity, queue->count + 1,
        sizeof(*queue->lines)
    );

    const git_time_t time = git_commit_time(commit);
    size_t slot = queue->count++;
    for (; slot > 0 && queue->lines[slot - 1].time >= time; slot--) {
        queue->lines[slot] = queue->lines[slot - 1];
    }
    queue->lines[slot] = (stats_line_t){
        .entry = *entry, .reached = *git_commit_id(commit), .time = time,
    };
}

/**
 * One file's every change
 */
error_t stats_file_history(
    git_repository *repo, const git_oid *head_oid, const char *file_path,
    arena_t *arena, file_history_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(head_oid);
    CHECK_NULL(file_path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The lines and every commit they reached are the walk's frame's; the history
     * grows in the caller's arena, abandoning each spine it outgrows */
    stats_queue_t queue = { .frame = arena_create(0) };
    queue.seen = hashmap_create(queue.frame, 0);
    file_history_t history = { 0 };
    size_t capacity = 0;
    error_t err = NULL;

    /* The head's line, carrying the entry the head holds there */
    git_commit *head = NULL;
    git_tree *head_tree = NULL;
    stats_entry_t entry;
    int rc = git_commit_lookup(&head, repo, head_oid);
    if (rc == 0) rc = git_commit_tree(&head_tree, head);
    if (rc < 0) err = error_git(rc, "Cannot read a commit in the history");
    if (!err) err = stats_entry(head_tree, file_path, &entry);
    if (!err) stats_arrive(&queue, head, &entry);
    git_tree_free(head_tree);
    git_commit_free(head);

    while (!err && queue.count > 0) {
        const stats_line_t line = queue.lines[--queue.count];

        git_commit *commit = NULL;
        rc = git_commit_lookup(&commit, repo, &line.reached);
        if (rc < 0) {
            err = error_git(rc, "Cannot read a commit in the history");
            break;
        }

        /* Each parent in order takes the line where it holds its entry, and a
         * parent is read only while the line is left for it: the first holding
         * the entry takes it alone (lib/git/revision.c try_to_simplify_commit) */
        const unsigned int parent_count = git_commit_parentcount(commit);
        size_t waiting = 1;
        for (unsigned int i = 0; !err && waiting > 0 && i < parent_count; i++) {
            git_commit *parent = NULL;
            git_tree *tree = NULL;
            err = stats_parent(commit, i, &parent, &tree);

            stats_entry_t held;
            if (!err) err = stats_entry(tree, file_path, &held);
            if (!err && git_oid_equal(&held.blob, &line.entry.blob) &&
                held.mode == line.entry.mode) {
                stats_arrive(&queue, parent, &held);
                waiting--;
            }

            git_tree_free(tree);
            git_commit_free(parent);
        }

        /* A line no parent took: the commit changed the path — a root where it
         * holds it, its parent Git's empty tree — and the line goes on through
         * every parent, each carrying what it holds there */
        if (!err && waiting > 0) {
            if (parent_count > 0 || !git_oid_is_zero(&line.entry.blob)) {
                history.commits = arena_grow(
                    arena, history.commits, &capacity, history.count + 1,
                    sizeof(*history.commits)
                );
                history.commits[history.count++] = stats_commit_info(arena, commit);
            }

            for (unsigned int i = 0; !err && i < parent_count; i++) {
                git_commit *parent = NULL;
                git_tree *tree = NULL;
                err = stats_parent(commit, i, &parent, &tree);

                stats_entry_t held;
                if (!err) err = stats_entry(tree, file_path, &held);
                if (!err) stats_arrive(&queue, parent, &held);

                git_tree_free(tree);
                git_commit_free(parent);
            }
        }

        git_commit_free(commit);
    }

    arena_free(queue.frame);
    if (err) return err;

    *out = history;
    return NULL;
}
