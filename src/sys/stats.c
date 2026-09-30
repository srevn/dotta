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
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/heap.h"
#include "sys/gitops.h"

/* Configuration constants */
#define PATH_BUFFER_SIZE 1024
#define HASHMAP_INITIAL_SIZE 256

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
 *
 * The summary is the message's first line with its trailing whitespace trimmed,
 * and empty for a commit with no message.
 */
static commit_info_t stats_commit_info(arena_t *arena, const git_commit *commit) {
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
 * Tree walk callback data (for populating file paths into hashmap)
 */
struct tree_populate_data {
    hashmap_t *map;
    size_t file_count;
};

/**
 * Tree walk callback: add each blob path to hashmap with NULL value
 *
 * Pre-populates the map with all file paths from the current tree. NULL values
 * serve as sentinels for "not yet mapped to a commit". This ensures the commit
 * walker only processes files that actually exist in the current tree, preventing
 * premature early termination.
 */
static int populate_tree_paths_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    struct tree_populate_data *data = payload;

    const char *name = git_tree_entry_name(entry);
    size_t root_len = root ? strlen(root) : 0;
    size_t name_len = strlen(name);
    size_t path_len = root_len + name_len;

    /* Build full path (root is directory prefix, e.g. "home/") */
    char stack_buf[PATH_BUFFER_SIZE];
    char *path = stack_buf;

    if (path_len >= sizeof(stack_buf)) {
        path = heap_alloc(path_len + 1);
    }

    memcpy(path, root, root_len);
    memcpy(path + root_len, name, name_len);
    path[path_len] = '\0';

    hashmap_set(data->map, path, NULL);

    if (path != stack_buf) {
        free(path);
    }

    data->file_count++;
    return 0;
}

/**
 * Populate hashmap with all file paths from tree
 *
 * Walks the tree once, adding all blob paths as keys with NULL values. Returns
 * the total file count for early termination tracking.
 */
static error_t populate_tree_paths(
    git_tree *tree,
    hashmap_t *map,
    size_t *out_count
) {
    CHECK_NULL(tree);
    CHECK_NULL(map);
    CHECK_NULL(out_count);

    struct tree_populate_data data = {
        .map        = map,
        .file_count = 0
    };

    error_t err = gitops_tree_walk(tree, populate_tree_paths_callback, &data);
    if (err) return err;

    *out_count = data.file_count;
    return NULL;
}

/**
 * Unified commit walker
 *
 * Walks commit history and processes diffs based on mode:
 * - MAP mode: Populates pre-seeded hashmap entries with commit info. The map
 *   must be pre-populated with current-tree paths (NULL values) to ensure only
 *   valid files are mapped and early termination is correct.
 * - HISTORY mode: Collects all commits that modified a specific file.
 *
 * Every info it makes is the walk's arena's, so a walk that fails partway leaves
 * nothing to release but the revwalk.
 */
static error_t stats_walk(
    git_repository *repo,
    const char *branch_name,
    walk_t *walk
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(walk);

    git_revwalk *walker = NULL;

    /* Resolve the branch head. The walk needs the OID, not the reference that
     * carries it — git_revwalk_push copies what it is given. */
    git_oid head_oid;
    error_t err = gitops_resolve_branch_head_oid(repo, branch_name, &head_oid);
    if (err) return err;

    /* Create revwalker */
    int rc = git_revwalk_new(&walker, repo);
    if (rc < 0) return error_from_git(rc);

    rc = git_revwalk_push(walker, &head_oid);
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

        /* Get parent tree (if exists) */
        git_tree *parent_tree = NULL;
        if (git_commit_parentcount(commit) > 0) {
            git_commit *parent = NULL;
            rc = git_commit_parent(&parent, commit, 0);
            if (rc == 0) {
                rc = git_commit_tree(&parent_tree, parent);
                git_commit_free(parent);
                if (rc < 0) {
                    git_tree_free(tree);
                    git_commit_free(commit);
                    err = error_from_git(rc);
                    goto cleanup;
                }
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
    const char *branch_name,
    git_tree *tree,
    arena_t *arena,
    file_commit_map_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(tree);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Pre-populate map with all current-tree file paths (NULL values). This ensures
     * the commit walker only maps files that actually exist in the current tree,
     * preventing spurious entries from deleted/renamed files and fixing premature
     * early termination. The map owns its keys, so a path built on the walk's
     * stack is copied into the arena as it takes its slot. */
    hashmap_t *paths = hashmap_create(arena, HASHMAP_INITIAL_SIZE);
    size_t files_needed;
    error_t err = populate_tree_paths(tree, paths, &files_needed);
    if (err) return err;

    /* Initialize walk context */
    walk_t walk = {
        .mode             = WALK_MODE_MAP,
        .target_path      = NULL,
        .arena            = arena,
        .map              = paths,
        .commits          = NULL,
        .commits_count    = 0,
        .commits_capacity = 0,
        .files_found      = 0,
        .files_needed     = files_needed
    };

    /* Walk commits to build map */
    err = stats_walk(repo, branch_name, &walk);
    if (err) return err;

    file_commit_map_t *map = arena_calloc(arena, 1, sizeof(*map));
    map->map = paths;

    *out = map;
    return NULL;
}

/**
 * The commits that touched one file
 */
error_t stats_file_history(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    arena_t *arena,
    file_history_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
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
     * bytes */
    error_t err = stats_walk(repo, branch_name, &walk);
    if (err) return err;

    /* Check if we found any commits */
    if (walk.commits_count == 0) {
        return ERROR(
            ERR_NOT_FOUND, "No history found for file '%s' in branch '%s'",
            file_path, branch_name
        );
    }

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
