/**
 * stats.c - Profile and file statistics implementation
 *
 * Implementation notes:
 * - Uses git_odb_read_header for size queries (10-50x faster than git_blob_lookup)
 * - Unified commit walker eliminates code duplication
 * - Early termination when all files found (major speedup)
 * - Overflow protection on size accumulation
 */

#include "stats.h"

#include <ctype.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "utils/hashmap.h"

/* Configuration constants */
#define PATH_BUFFER_SIZE 1024
#define REFNAME_BUFFER_SIZE 256
#define HASHMAP_INITIAL_SIZE 256
#define COMMITS_INITIAL_CAPACITY 16
#define COMMITS_MAX_CAPACITY (SIZE_MAX / sizeof(commit_info_t) / 2)

/**
 * File -> commit map (opaque type)
 */
struct file_commit_map {
    hashmap_t *map;  /* path (string) -> commit_info_t* */
};

/**
 * Walk mode for unified commit walker
 */
typedef enum {
    WALK_MODE_MAP,      /* Build file -> commit map (early termination enabled) */
    WALK_MODE_HISTORY   /* Collect all commits for single file */
} walk_mode_t;

/**
 * Context for unified commit walker
 */
typedef struct {
    /* Input configuration */
    walk_mode_t mode;
    const char *target_path;      /* File path (for HISTORY mode), NULL for MAP mode */

    /* Output destinations (one will be populated based on mode) */
    hashmap_t *map;               /* For MAP mode: path -> commit_info_t* */
    commit_info_t *commits;       /* For HISTORY mode: array of commits */
    size_t commits_count;
    size_t commits_capacity;

    /* State tracking (for early termination in MAP mode) */
    size_t files_found;           /* Number of files found so far */
    size_t files_needed;          /* Total files in current tree */
} walk_ctx_t;

/**
 * Tree walk callback data (for profile stats)
 */
struct tree_walk_data {
    git_odb *odb;        /* Cached ODB handle (avoids repeated git_repository_odb calls) */
    size_t file_count;
    size_t total_size;
    error_t *error;
};

/**
 * Get blob size from a pre-acquired ODB handle (metadata only, no decompression)
 */
static error_t *get_blob_size_with_odb(
    git_odb *odb,
    const git_oid *blob_oid,
    size_t *out_size
) {
    size_t size;
    git_object_t type;
    int git_err = git_odb_read_header(&size, &type, odb, blob_oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (type != GIT_OBJECT_BLOB) {
        return ERROR(ERR_INVALID_ARG, "Object is not a blob");
    }

    *out_size = size;
    return NULL;
}

/**
 * Get blob size efficiently (metadata only, no decompression)
 *
 * Acquires ODB handle per call. For batch operations, prefer
 * get_blob_size_with_odb() with a cached ODB handle.
 */
static error_t *get_blob_size(
    git_repository *repo,
    const git_oid *blob_oid,
    size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out_size);

    /* Get object database */
    git_odb *odb = NULL;
    int git_err = git_repository_odb(&odb, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    error_t *err = get_blob_size_with_odb(odb, blob_oid, out_size);
    git_odb_free(odb);
    return err;
}

/**
 * Extract first line of commit message
 *
 * Trims trailing whitespace and returns empty string for empty commits.
 */
static char *extract_commit_summary(const char *message) {
    if (!message) {
        return strdup("");
    }

    /* Find first newline */
    const char *newline = strchr(message, '\n');
    size_t len = newline ? (size_t) (newline - message) : strlen(message);

    /* Trim trailing whitespace */
    while (len > 0 && isspace((unsigned char) message[len - 1])) {
        len--;
    }

    /* Allocate and return (NULL on allocation failure) */
    return strndup(message, len);
}

/**
 * Create commit info from git commit
 */
static error_t *create_commit_info(
    git_commit *commit,
    commit_info_t **out
) {
    CHECK_NULL(commit);
    CHECK_NULL(out);

    commit_info_t *info = calloc(1, sizeof(commit_info_t));
    if (!info) {
        return ERROR(ERR_MEMORY, "Failed to allocate commit info");
    }

    /* Copy OID */
    git_oid_cpy(&info->oid, git_commit_id(commit));

    /* Extract summary */
    const char *message = git_commit_message(commit);
    info->summary = extract_commit_summary(message);
    if (!info->summary) {
        free(info);
        return ERROR(ERR_MEMORY, "Failed to allocate commit summary");
    }

    /* Get timestamp (use libgit2 native type) */
    const git_signature *author = git_commit_author(commit);
    info->time = author->when.time;

    *out = info;
    return NULL;
}

/**
 * Tree walk callback data (for populating file paths into hashmap)
 */
struct tree_populate_data {
    hashmap_t *map;
    size_t file_count;
    error_t *error;
};

/**
 * Tree walk callback: add each blob path to hashmap with NULL value
 *
 * Pre-populates the map with all file paths from the current tree.
 * NULL values serve as sentinels for "not yet mapped to a commit".
 * This ensures the commit walker only processes files that actually
 * exist in the current tree, preventing premature early termination.
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
        path = malloc(path_len + 1);
        if (!path) {
            data->error = ERROR(ERR_MEMORY, "Failed to allocate path buffer");
            return -1;
        }
    }

    memcpy(path, root, root_len);
    memcpy(path + root_len, name, name_len);
    path[path_len] = '\0';

    error_t *err = hashmap_set(data->map, path, NULL);

    if (path != stack_buf) {
        free(path);
    }

    if (err) {
        data->error = err;
        return -1;
    }

    data->file_count++;
    return 0;
}

/**
 * Populate hashmap with all file paths from tree
 *
 * Walks the tree once, adding all blob paths as keys with NULL values.
 * Returns the total file count for early termination tracking.
 */
static error_t *populate_tree_paths(
    git_tree *tree,
    hashmap_t *map,
    size_t *out_count
) {
    CHECK_NULL(tree);
    CHECK_NULL(map);
    CHECK_NULL(out_count);

    struct tree_populate_data data = {
        .map        = map,
        .file_count = 0,
        .error      = NULL
    };

    error_t *err = gitops_tree_walk(
        tree, populate_tree_paths_callback, &data
    );
    if (err || data.error) {
        /* Prefer callback error */
        if (data.error) {
            error_free(err);
            return data.error;
        }
        return err;
    }

    *out_count = data.file_count;
    return NULL;
}

/**
 * Tree walk callback for profile statistics
 */
static int tree_walk_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    (void) root;  /* Unused */
    struct tree_walk_data *data = (struct tree_walk_data *) payload;

    /* Defensive check */
    if (!data) {
        return -1;
    }

    /* Only process blobs (files) */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Get blob size efficiently (metadata only, using cached ODB) */
    const git_oid *oid = git_tree_entry_id(entry);
    size_t size;
    error_t *err = get_blob_size_with_odb(data->odb, oid, &size);
    if (err) {
        data->error = err;
        return -1;
    }

    /* Overflow protection */
    if (data->total_size > SIZE_MAX - size) {
        data->error = ERROR(
            ERR_INTERNAL, "Profile size exceeds maximum representable value"
        );
        return -1;
    }

    /* Accumulate statistics */
    data->file_count++;
    data->total_size += size;

    return 0;
}

/**
 * Unified commit walker
 *
 * Walks commit history and processes diffs based on mode:
 * - MAP mode: Populates pre-seeded hashmap entries with commit info.
 *   The map must be pre-populated with current-tree paths (NULL values)
 *   to ensure only valid files are mapped and early termination is correct.
 * - HISTORY mode: Collects all commits that modified a specific file.
 */
static error_t *walk_commits(
    git_repository *repo,
    const char *branch_name,
    walk_ctx_t *ctx
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(ctx);

    error_t *err = NULL;
    git_reference *ref = NULL;
    git_revwalk *walker = NULL;
    commit_info_t *current_commit_info = NULL;

    /* Build refname */
    char refname[REFNAME_BUFFER_SIZE];
    err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", branch_name
    );
    if (err) {
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    /* Lookup branch reference */
    err = gitops_lookup_reference(repo, refname, &ref);
    if (err) {
        return error_wrap(err, "Failed to lookup branch '%s'", branch_name);
    }

    const git_oid *target_oid = git_reference_target(ref);
    if (!target_oid) {
        git_reference_free(ref);
        return ERROR(ERR_INTERNAL, "Branch '%s' has no commits", branch_name);
    }

    /* Create revwalker */
    int git_err = git_revwalk_new(&walker, repo);
    if (git_err < 0) {
        git_reference_free(ref);
        return error_from_git(git_err);
    }

    git_err = git_revwalk_push(walker, target_oid);
    if (git_err < 0) {
        git_revwalk_free(walker);
        git_reference_free(ref);
        return error_from_git(git_err);
    }

    /* Sort by time (newest first) */
    git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    /* Walk commits */
    git_oid oid;
    while (git_revwalk_next(&oid, walker) == 0) {
        /* Early termination for MAP mode */
        if (ctx->mode == WALK_MODE_MAP && ctx->files_found >= ctx->files_needed) {
            break;  /* All files found! */
        }

        git_commit *commit = NULL;
        git_err = git_commit_lookup(&commit, repo, &oid);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Create commit info for this commit */
        current_commit_info = NULL;
        err = create_commit_info(commit, &current_commit_info);
        if (err) {
            git_commit_free(commit);
            goto cleanup;
        }

        /* Get commit tree */
        git_tree *tree = NULL;
        git_err = git_commit_tree(&tree, commit);
        if (git_err < 0) {
            stats_free_commit_info(current_commit_info);
            git_commit_free(commit);
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Get parent tree (if exists) */
        git_tree *parent_tree = NULL;
        if (git_commit_parentcount(commit) > 0) {
            git_commit *parent = NULL;
            git_err = git_commit_parent(&parent, commit, 0);
            if (git_err == 0) {
                git_err = git_commit_tree(&parent_tree, parent);
                git_commit_free(parent);
                if (git_err < 0) {
                    stats_free_commit_info(current_commit_info);
                    git_tree_free(tree);
                    git_commit_free(commit);
                    err = error_from_git(git_err);
                    goto cleanup;
                }
            }
        }

        /* Create diff */
        git_diff *diff = NULL;
        git_err = git_diff_tree_to_tree(&diff, repo, parent_tree, tree, NULL);

        if (parent_tree) {
            git_tree_free(parent_tree);
        }
        git_tree_free(tree);

        if (git_err < 0) {
            stats_free_commit_info(current_commit_info);
            git_commit_free(commit);
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Process diff based on mode */
        if (ctx->mode == WALK_MODE_MAP) {
            /* MAP mode: Add file -> commit mappings */
            size_t num_deltas = git_diff_num_deltas(diff);
            for (size_t i = 0; i < num_deltas; i++) {
                const git_diff_delta *delta = git_diff_get_delta(diff, i);
                const char *path = delta->new_file.path ? delta->new_file.path
                                                        : delta->old_file.path;

                if (!path) continue;

                /* Only map files that exist in the current tree.
                 * The map is pre-populated with current-tree paths (NULL values).
                 * Skip paths not in the tree (deleted files, old renames) and
                 * paths already mapped (non-NULL value). */
                if (!hashmap_has(ctx->map, path) || hashmap_get(ctx->map, path)) {
                    continue;
                }

                /* Duplicate commit info for this file */
                commit_info_t *info = calloc(1, sizeof(commit_info_t));
                if (!info) {
                    git_diff_free(diff);
                    stats_free_commit_info(current_commit_info);
                    git_commit_free(commit);
                    err = ERROR(ERR_MEMORY, "Failed to allocate commit info");
                    goto cleanup;
                }

                git_oid_cpy(&info->oid, &current_commit_info->oid);
                info->summary = strdup(current_commit_info->summary);
                if (!info->summary) {
                    free(info);
                    git_diff_free(diff);
                    stats_free_commit_info(current_commit_info);
                    git_commit_free(commit);
                    err = ERROR(ERR_MEMORY, "Failed to duplicate commit summary");
                    goto cleanup;
                }
                info->time = current_commit_info->time;

                /* Add to map */
                err = hashmap_set(ctx->map, path, info);
                if (err) {
                    stats_free_commit_info(info);
                    git_diff_free(diff);
                    stats_free_commit_info(current_commit_info);
                    git_commit_free(commit);
                    goto cleanup;
                }

                ctx->files_found++;
            }

        } else { /* WALK_MODE_HISTORY */
            /* HISTORY mode: Check if diff contains target file */
            size_t num_deltas = git_diff_num_deltas(diff);
            bool found = false;

            for (size_t i = 0; i < num_deltas; i++) {
                const git_diff_delta *delta = git_diff_get_delta(diff, i);
                const char *path = delta->new_file.path ?
                    delta->new_file.path : delta->old_file.path;

                if (path && strcmp(path, ctx->target_path) == 0) {
                    found = true;
                    break;
                }
            }

            if (found) {
                /* Grow array if needed */
                if (ctx->commits_count >= ctx->commits_capacity) {
                    size_t new_capacity;

                    if (ctx->commits_capacity == 0) {
                        new_capacity = COMMITS_INITIAL_CAPACITY;
                    } else if (ctx->commits_capacity >= COMMITS_MAX_CAPACITY) {
                        git_diff_free(diff);
                        stats_free_commit_info(current_commit_info);
                        git_commit_free(commit);
                        err = ERROR(ERR_INTERNAL, "File history too large");
                        goto cleanup;
                    } else {
                        new_capacity = ctx->commits_capacity * 2;
                        if (new_capacity > COMMITS_MAX_CAPACITY) {
                            new_capacity = COMMITS_MAX_CAPACITY;
                        }
                    }

                    commit_info_t *new_commits =
                        realloc(ctx->commits, new_capacity * sizeof(commit_info_t));
                    if (!new_commits) {
                        git_diff_free(diff);
                        stats_free_commit_info(current_commit_info);
                        current_commit_info = NULL;  /* Prevent double-free in cleanup */
                        git_commit_free(commit);
                        err = ERROR(ERR_MEMORY, "Failed to grow commits array");
                        goto cleanup;
                    }
                    ctx->commits = new_commits;
                    ctx->commits_capacity = new_capacity;
                }

                /* Copy commit info to array */
                commit_info_t *info = &ctx->commits[ctx->commits_count];
                git_oid_cpy(&info->oid, &current_commit_info->oid);
                info->summary = strdup(current_commit_info->summary);
                if (!info->summary) {
                    git_diff_free(diff);
                    stats_free_commit_info(current_commit_info);
                    current_commit_info = NULL;  /* Prevent double-free in cleanup */
                    git_commit_free(commit);
                    err = ERROR(ERR_MEMORY, "Failed to duplicate commit summary");
                    goto cleanup;
                }
                info->time = current_commit_info->time;
                ctx->commits_count++;
            }
        }

        git_diff_free(diff);
        stats_free_commit_info(current_commit_info);
        current_commit_info = NULL;
        git_commit_free(commit);
    }

    /* Success */
    git_revwalk_free(walker);
    git_reference_free(ref);
    return NULL;

cleanup:
    if (current_commit_info) {
        stats_free_commit_info(current_commit_info);
    }
    if (walker) {
        git_revwalk_free(walker);
    }
    if (ref) {
        git_reference_free(ref);
    }
    return err;
}

/**
 * Get profile statistics
 */
error_t *stats_get_profile_stats(
    git_repository *repo,
    git_tree *tree,
    profile_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(out);

    /* Acquire ODB once for all blob size reads */
    git_odb *odb = NULL;
    int git_err = git_repository_odb(&odb, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Initialize walk data */
    struct tree_walk_data data = {
        .odb        = odb,
        .file_count = 0,
        .total_size = 0,
        .error      = NULL
    };

    /* Walk tree */
    error_t *err = gitops_tree_walk(tree, tree_walk_callback, &data);
    git_odb_free(odb);

    if (err || data.error) {
        /* Prefer callback error */
        if (data.error) {
            error_free(err);
            return data.error;
        }
        return err;
    }

    /* Fill output */
    out->file_count = data.file_count;
    out->total_size = data.total_size;

    return NULL;
}

/**
 * Get blob size
 */
error_t *stats_get_blob_size(
    git_repository *repo,
    const git_oid *blob_oid,
    size_t *out
) {
    return get_blob_size(repo, blob_oid, out);
}

/**
 * Build file -> commit map
 */
error_t *stats_build_file_commit_map(
    git_repository *repo,
    const char *branch_name,
    git_tree *tree,
    file_commit_map_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(tree);
    CHECK_NULL(out);

    /* Allocate map structure */
    file_commit_map_t *map = calloc(1, sizeof(file_commit_map_t));
    if (!map) {
        return ERROR(ERR_MEMORY, "Failed to allocate file commit map");
    }

    /* Create hashmap */
    map->map = hashmap_create(HASHMAP_INITIAL_SIZE);
    if (!map->map) {
        free(map);
        return ERROR(ERR_MEMORY, "Failed to create hashmap");
    }

    /* Pre-populate map with all current-tree file paths (NULL values).
     * This ensures the commit walker only maps files that actually exist
     * in the current tree, preventing spurious entries from deleted/renamed
     * files and fixing premature early termination. */
    size_t files_needed;
    error_t *err = populate_tree_paths(tree, map->map, &files_needed);
    if (err) {
        hashmap_free(map->map, NULL);
        free(map);
        return err;
    }

    /* Initialize walk context */
    walk_ctx_t ctx = {
        .mode             = WALK_MODE_MAP,
        .target_path      = NULL,
        .map              = map->map,
        .commits          = NULL,
        .commits_count    = 0,
        .commits_capacity = 0,
        .files_found      = 0,
        .files_needed     = files_needed
    };

    /* Walk commits to build map */
    err = walk_commits(repo, branch_name, &ctx);
    if (err) {
        hashmap_free(map->map, stats_free_commit_info);
        free(map);
        return err;
    }

    *out = map;
    return NULL;
}

/**
 * Get file history
 */
error_t *stats_get_file_history(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    file_history_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(file_path);
    CHECK_NULL(out);

    /* Allocate history */
    file_history_t *history = calloc(1, sizeof(file_history_t));
    if (!history) {
        return ERROR(ERR_MEMORY, "Failed to allocate file history");
    }

    /* Initialize walk context */
    walk_ctx_t ctx = {
        .mode             = WALK_MODE_HISTORY,
        .target_path      = file_path,
        .map              = NULL,
        .commits          = NULL,
        .commits_count    = 0,
        .commits_capacity = 0,
        .files_found      = 0,
        .files_needed     = 0
    };

    /* Walk commits to collect history */
    error_t *err = walk_commits(repo, branch_name, &ctx);
    if (err) {
        /* Free any partially collected commits */
        for (size_t i = 0; i < ctx.commits_count; i++) {
            free(ctx.commits[i].summary);
        }
        free(ctx.commits);
        free(history);
        return err;
    }

    /* Check if we found any commits */
    if (ctx.commits_count == 0) {
        free(history);
        return ERROR(
            ERR_NOT_FOUND, "No history found for file '%s' in branch '%s'",
            file_path, branch_name
        );
    }

    /* Fill history */
    history->commits = ctx.commits;
    history->count = ctx.commits_count;

    *out = history;
    return NULL;
}

/**
 * Lookup commit info for file
 */
const commit_info_t *stats_file_commit_map_get(
    const file_commit_map_t *map,
    const char *file_path
) {
    if (!map || !file_path) {
        return NULL;
    }

    return (const commit_info_t *) hashmap_get(map->map, file_path);
}

/**
 * Free commit info
 *
 * Generic callback signature for use with containers (e.g., hashmap_free).
 * Accepts void* to match standard C cleanup callback pattern.
 */
void stats_free_commit_info(void *ptr) {
    commit_info_t *info = ptr;
    if (!info) {
        return;
    }
    free(info->summary);
    free(info);
}

/**
 * Free file -> commit map
 */
void stats_free_file_commit_map(file_commit_map_t *map) {
    if (!map) {
        return;
    }
    if (map->map) {
        hashmap_free(map->map, stats_free_commit_info);
    }
    free(map);
}

/**
 * Free file history
 */
void stats_free_file_history(file_history_t *history) {
    if (!history) {
        return;
    }
    for (size_t i = 0; i < history->count; i++) {
        free(history->commits[i].summary);
    }
    free(history->commits);
    free(history);
}
