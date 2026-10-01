/**
 * stats.c - Git object and history statistics implementation
 *
 * Implementation notes:
 * - Uses git_odb_read_header for size queries (10-50x faster than git_blob_lookup)
 * - Unified commit walker eliminates code duplication
 * - Early termination when all files found (major speedup)
 */

#include "sys/stats.h"

#include <ctype.h>
#include <git2.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"

/**
 * File -> commit map (opaque type)
 */
struct file_commit_map {
    hashmap_t *map;  /* path (string) -> commit_info_t*, both the arena's */
};

/**
 * Walk mode for unified commit walker
 */
typedef enum {
    WALK_MODE_MAP,      /* Build file -> commit map (early termination enabled) */
    WALK_MODE_HISTORY   /* Collect all commits for single file */
} walk_mode_t;

/**
 * The unified commit walker's state
 */
typedef struct {
    /* Input configuration */
    walk_mode_t mode;
    const char *target_path;      /* File path (for HISTORY mode), NULL for MAP mode */
    arena_t *arena;               /* Where every commit info, its summary and the history live */

    /* Output destinations (one will be populated based on mode) */
    hashmap_t *map;               /* For MAP mode: path -> commit_info_t* */
    commit_info_t *commits;       /* For HISTORY mode: array of commits */
    size_t commits_count;
    size_t commits_capacity;

    /* State tracking (for early termination in MAP mode) */
    size_t files_found;           /* Number of files found so far */
    size_t files_needed;          /* Total files in current tree */
} walk_t;

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
 * Unified commit walker
 *
 * Walks commit history and processes diffs based on mode:
 * - MAP mode: Populates pre-seeded hashmap entries with commit info. The map
 *   must be pre-populated with the names to map (NULL values) to ensure only
 *   they are mapped and early termination is correct.
 * - HISTORY mode: Collects all commits that modified a specific file.
 *
 * Every info it makes is the walk's arena's, so a walk that fails partway leaves
 * nothing to release but the revwalk.
 */
static error_t stats_walk(
    git_repository *repo,
    const git_oid *tip_oid,
    walk_t *walk
) {
    CHECK_NULL(repo);
    CHECK_NULL(tip_oid);
    CHECK_NULL(walk);

    git_revwalk *walker = NULL;
    error_t err = NULL;

    /* The history from the caller's commit, and no reference read here: the caller
     * read its tip once, beside everything else it read off that commit.
     * git_revwalk_push copies the id it is given. */
    int rc = git_revwalk_new(&walker, repo);
    if (rc < 0) return error_from_git(rc);

    rc = git_revwalk_push(walker, tip_oid);
    if (rc < 0) {
        err = error_from_git(rc);
        goto cleanup;
    }

    /* Sort by time (newest first) */
    git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    /* Walk commits. GIT_ITEROVER ends the history; a negative code is a walk
     * that failed, and a history it could not finish must not read as a whole
     * one — the callers report an absence in it as fact. */
    for (;;) {
        git_oid oid;
        rc = git_revwalk_next(&oid, walker);
        if (rc == GIT_ITEROVER) {
            break;
        }
        if (rc < 0) {
            err = error_from_git(rc);
            goto cleanup;
        }

        /* Early termination for MAP mode */
        if (walk->mode == WALK_MODE_MAP && walk->files_found >= walk->files_needed) {
            break;  /* All files found! */
        }

        git_commit *commit = NULL;
        rc = git_commit_lookup(&commit, repo, &oid);
        if (rc < 0) {
            err = error_from_git(rc);
            goto cleanup;
        }

        /* Get commit tree */
        git_tree *tree = NULL;
        rc = git_commit_tree(&tree, commit);
        if (rc < 0) {
            git_commit_free(commit);
            err = error_from_git(rc);
            goto cleanup;
        }

        /* Get parent tree (if exists). A parent the commit names and that will
         * not load is the walk's failure, as its tree's is: read as no parent,
         * the commit would be diffed against the empty tree and credited with
         * every file it holds. The revwalk above parses a parent more lightly
         * than a load does (commit_list.c commit_quick_parse reads no tree id
         * and no author), so reaching the commit proves nothing about its
         * parent. */
        git_tree *parent_tree = NULL;
        if (git_commit_parentcount(commit) > 0) {
            git_commit *parent = NULL;
            rc = git_commit_parent(&parent, commit, 0);
            if (rc == 0) {
                rc = git_commit_tree(&parent_tree, parent);
                git_commit_free(parent);
            }
            if (rc < 0) {
                git_tree_free(tree);
                git_commit_free(commit);
                err = error_from_git(rc);
                goto cleanup;
            }
        }

        /* Create diff */
        git_diff *diff = NULL;
        rc = git_diff_tree_to_tree(&diff, repo, parent_tree, tree, NULL);

        if (parent_tree) {
            git_tree_free(parent_tree);
        }
        git_tree_free(tree);

        if (rc < 0) {
            git_commit_free(commit);
            err = error_from_git(rc);
            goto cleanup;
        }

        /* Process diff based on mode */
        if (walk->mode == WALK_MODE_MAP) {
            /* MAP mode: Add file -> commit mappings. The commit's info is made
             * at the first file it maps and shared by the rest: nothing frees
             * an info, so one copy serves every file of the commit. */
            commit_info_t *info = NULL;
            size_t num_deltas = git_diff_num_deltas(diff);
            for (size_t i = 0; i < num_deltas; i++) {
                const git_diff_delta *delta = git_diff_get_delta(diff, i);
                const char *path = delta->new_file.path ? delta->new_file.path
                                                        : delta->old_file.path;

                if (!path) continue;

                /* Only map files that exist in the current tree. The map is
                 * pre-populated with current-tree paths (NULL values). Skip paths
                 * not in the tree (deleted files, old renames) and paths already
                 * mapped (non-NULL value): one probe tells the two apart. */
                void *mapped = NULL;
                if (!hashmap_find(walk->map, path, &mapped) || mapped) continue;

                if (!info) {
                    info = arena_calloc(walk->arena, 1, sizeof(*info));
                    *info = stats_commit_info(walk->arena, commit);
                }
                hashmap_set(walk->map, path, info);

                walk->files_found++;
            }

        } else { /* WALK_MODE_HISTORY */
            /* HISTORY mode: Check if diff contains target file */
            size_t num_deltas = git_diff_num_deltas(diff);
            bool found = false;

            for (size_t i = 0; i < num_deltas; i++) {
                const git_diff_delta *delta = git_diff_get_delta(diff, i);
                const char *path = delta->new_file.path ? delta->new_file.path
                                                        : delta->old_file.path;

                if (path && strcmp(path, walk->target_path) == 0) {
                    found = true;
                    break;
                }
            }

            /* The history grows in the arena, abandoning each spine it outgrows */
            if (found) {
                walk->commits = arena_grow(
                    walk->arena, walk->commits, &walk->commits_capacity,
                    walk->commits_count + 1, sizeof(*walk->commits)
                );
                walk->commits[walk->commits_count++] = stats_commit_info(
                    walk->arena, commit
                );
            }
        }

        git_diff_free(diff);
        git_commit_free(commit);
    }

cleanup:
    git_revwalk_free(walker);
    return err;
}

/**
 * A blob's size
 */
error_t stats_blob_size(
    git_repository *repo,
    const git_oid *blob_oid,
    size_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    /* Get object database */
    git_odb *odb = NULL;
    int rc = git_repository_odb(&odb, repo);
    if (rc < 0) return error_from_git(rc);

    error_t err = stats_blob_size_with_odb(odb, blob_oid, out);
    git_odb_free(odb);
    return err;
}

/**
 * A blob's size, through a caller-held ODB handle
 */
error_t stats_blob_size_with_odb(
    git_odb *odb,
    const git_oid *blob_oid,
    size_t *out
) {
    CHECK_NULL(odb);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    size_t size;
    git_object_t type;
    int rc = git_odb_read_header(&size, &type, odb, blob_oid);
    if (rc < 0) return error_from_git(rc);

    if (type != GIT_OBJECT_BLOB) {
        return ERROR(ERR_INVALID_ARG, "Object is not a blob");
    }

    *out = size;
    return NULL;
}

/**
 * Build file -> commit map
 */
error_t stats_build_file_commit_map(
    git_repository *repo,
    const git_oid *tip_oid,
    const string_array_t *paths,
    arena_t *arena,
    file_commit_map_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tip_oid);
    CHECK_NULL(paths);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Pre-populate the map with the caller's names (NULL values), and only them.
     * The commit walker maps a name the map holds and no other, so a file deleted
     * or renamed along the history is never credited, and the walk stops once
     * every name is mapped — a name nobody reads, left in, would hold it to the
     * root commit. The map owns its keys, copied into the arena as each takes
     * its slot. */
    hashmap_t *map = hashmap_create(arena, paths->count);
    for (size_t i = 0; i < paths->count; i++) {
        hashmap_set(map, paths->entries[i], NULL);
    }

    /* Initialize walk context */
    walk_t walk = {
        .mode             = WALK_MODE_MAP,
        .target_path      = NULL,
        .arena            = arena,
        .map              = map,
        .commits          = NULL,
        .commits_count    = 0,
        .commits_capacity = 0,
        .files_found      = 0,
        .files_needed     = hashmap_size(map)
    };

    /* Walk commits to build map */
    error_t err = stats_walk(repo, tip_oid, &walk);
    if (err) return err;

    file_commit_map_t *commit_map = arena_calloc(arena, 1, sizeof(*commit_map));
    commit_map->map = map;

    *out = commit_map;
    return NULL;
}

/**
 * The commits that touched one file
 */
error_t stats_file_history(
    git_repository *repo,
    const git_oid *tip_oid,
    const char *file_path,
    arena_t *arena,
    file_history_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tip_oid);
    CHECK_NULL(file_path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Initialize walk context */
    walk_t walk = {
        .mode             = WALK_MODE_HISTORY,
        .target_path      = file_path,
        .arena            = arena,
        .map              = NULL,
        .commits          = NULL,
        .commits_count    = 0,
        .commits_capacity = 0,
        .files_found      = 0,
        .files_needed     = 0
    };

    /* Walk commits to collect history: what a failed walk collected is the arena's
     * bytes, and a walk that found none answers so — its words are the caller's */
    error_t err = stats_walk(repo, tip_oid, &walk);
    if (err) return err;

    *out = (file_history_t){ walk.commits, walk.commits_count };
    return NULL;
}

/**
 * Lookup commit info for file
 */
const commit_info_t *stats_file_commit_map_get(
    const file_commit_map_t *map,
    const char *file_path
) {
    if (!map || !file_path) return NULL;

    return (const commit_info_t *) hashmap_get(map->map, file_path);
}
