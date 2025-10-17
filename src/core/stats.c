/**
 * stats.c - Profile and file statistics implementation
 */

#include "stats.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "utils/hashmap.h"

/* Configuration constants */
#define STATS_REFNAME_BUFFER_SIZE 256
#define STATS_HASHMAP_INITIAL_SIZE 256
#define STATS_COMMITS_INITIAL_CAPACITY 16
#define STATS_COMMITS_MAX_CAPACITY (SIZE_MAX / sizeof(commit_info_t) / 2)

/**
 * Tree walk callback data for profile statistics
 */
struct stats_walk_data {
    git_repository *repo;
    size_t file_count;
    size_t total_size;
    error_t *error;
};

/**
 * Tree walk callback for collecting profile statistics
 */
static int stats_tree_walk_callback(const char *root, const git_tree_entry *entry, void *payload) {
    (void)root;  /* Unused - but required by libgit2 callback signature */
    struct stats_walk_data *data = (struct stats_walk_data *)payload;

    /* Defensive: libgit2 should never pass NULL, but check anyway */
    if (!data) {
        return -1;
    }

    /* Only process blobs (files) */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Get blob to read size */
    const git_oid *oid = git_tree_entry_id(entry);
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, data->repo, oid);
    if (git_err < 0) {
        data->error = error_from_git(git_err);
        return -1;
    }

    /* Accumulate statistics */
    data->file_count++;
    data->total_size += git_blob_rawsize(blob);

    git_blob_free(blob);
    return 0;
}

/**
 * Get profile statistics
 */
error_t *stats_get_profile_stats(
    git_repository *repo,
    profile_t *profile,
    profile_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* Load tree if not loaded (lazy loading mutates profile) */
    error_t *err = profile_load_tree(repo, profile);
    if (err) {
        return err;
    }

    /* Initialize walk data */
    struct stats_walk_data data = {
        .repo = repo,
        .file_count = 0,
        .total_size = 0,
        .error = NULL
    };

    /* Walk tree */
    err = gitops_tree_walk(profile->tree, stats_tree_walk_callback, &data);
    if (err || data.error) {
        return err ? err : data.error;
    }

    /* Fill output */
    out->file_count = data.file_count;
    out->total_size = data.total_size;

    return NULL;
}

/**
 * Get file statistics
 */
error_t *stats_get_file_stats(
    git_repository *repo,
    git_tree_entry *entry,
    file_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(entry);
    CHECK_NULL(out);

    /* Verify it's a blob */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return ERROR(ERR_INVALID_ARG, "Entry is not a file");
    }

    /* Get blob */
    const git_oid *oid = git_tree_entry_id(entry);
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Get size */
    out->size = git_blob_rawsize(blob);

    git_blob_free(blob);
    return NULL;
}

/**
 * Extract first line of commit message
 *
 * Returns NULL on allocation failure (caller must handle).
 * Empty commits get an empty string (valid case).
 */
static char *extract_commit_summary(const char *message) {
    if (!message) {
        return strdup("");
    }

    const char *newline = strchr(message, '\n');
    size_t len = newline ? (size_t)(newline - message) : strlen(message);

    /* Trim trailing whitespace */
    while (len > 0 && (message[len - 1] == ' ' || message[len - 1] == '\t')) {
        len--;
    }

    /* Let NULL propagate on allocation failure */
    return strndup(message, len);
}

/**
 * Create commit info from git commit
 */
static error_t *create_commit_info(git_commit *commit, commit_info_t **out) {
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
    info->message_summary = extract_commit_summary(message);
    if (!info->message_summary) {
        free(info);
        return ERROR(ERR_MEMORY, "Failed to allocate commit summary");
    }

    /* Get timestamp */
    const git_signature *author = git_commit_author(commit);
    info->timestamp = author->when.time;

    *out = info;
    return NULL;
}

/**
 * Diff callback data for building file→commit index
 */
struct index_diff_data {
    hashmap_t *index;
    commit_info_t *current_commit_info;
    error_t *error;
};

/**
 * Diff callback for building file→commit index
 */
static int index_diff_callback(
    const git_diff_delta *delta,
    float progress,
    void *payload
) {
    (void)progress;
    struct index_diff_data *data = (struct index_diff_data *)payload;

    /* Defensive: libgit2 should never pass NULL, but check anyway */
    if (!data) {
        return -1;
    }

    /* Get file path (new_file for adds/modifies, old_file for deletes) */
    const char *path = delta->new_file.path ? delta->new_file.path : delta->old_file.path;
    if (!path) {
        return 0;
    }

    /* Skip if file already has a commit (we want the most recent) */
    if (hashmap_get(data->index, path)) {
        return 0;
    }

    /* Duplicate commit info for this file */
    commit_info_t *info = calloc(1, sizeof(commit_info_t));
    if (!info) {
        data->error = ERROR(ERR_MEMORY, "Failed to allocate commit info");
        return -1;
    }

    git_oid_cpy(&info->oid, &data->current_commit_info->oid);
    info->message_summary = strdup(data->current_commit_info->message_summary);
    if (!info->message_summary) {
        free(info);
        data->error = ERROR(ERR_MEMORY, "Failed to duplicate commit summary");
        return -1;
    }
    info->timestamp = data->current_commit_info->timestamp;

    /* Add to index */
    error_t *err = hashmap_set(data->index, path, info);
    if (err) {
        stats_free_commit_info(info);
        data->error = err;
        return -1;
    }

    return 0;
}

/**
 * Build file→commit index for profile
 */
error_t *stats_build_file_commit_index(
    git_repository *repo,
    const char *profile_name,
    hashmap_t **out_index
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_index);

    error_t *err = NULL;
    hashmap_t *index = NULL;
    git_reference *ref = NULL;
    git_revwalk *walker = NULL;
    commit_info_t *commit_info = NULL;

    /* Create index hashmap */
    index = hashmap_create(STATS_HASHMAP_INITIAL_SIZE);
    if (!index) {
        return ERROR(ERR_MEMORY, "Failed to create file→commit index");
    }

    /* Get profile branch reference */
    char refname[STATS_REFNAME_BUFFER_SIZE];
    err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", profile_name);
    if (err) {
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
        return error_wrap(err, "Invalid profile name '%s'", profile_name);
    }

    err = gitops_lookup_reference(repo, refname, &ref);
    if (err) {
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
        return error_wrap(err, "Failed to lookup profile '%s'", profile_name);
    }

    const git_oid *target_oid = git_reference_target(ref);
    if (!target_oid) {
        git_reference_free(ref);
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
        return ERROR(ERR_INTERNAL, "Profile '%s' has no commits", profile_name);
    }

    /* Create revwalk */
    int git_err = git_revwalk_new(&walker, repo);
    if (git_err < 0) {
        git_reference_free(ref);
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
        return error_from_git(git_err);
    }

    git_err = git_revwalk_push(walker, target_oid);
    if (git_err < 0) {
        git_revwalk_free(walker);
        git_reference_free(ref);
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
        return error_from_git(git_err);
    }

    /* Sort by time (newest first) */
    git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    /* Walk commits */
    git_oid oid;
    while (git_revwalk_next(&oid, walker) == 0) {
        git_commit *commit = NULL;
        git_err = git_commit_lookup(&commit, repo, &oid);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Create commit info for this commit */
        commit_info = NULL;
        err = create_commit_info(commit, &commit_info);
        if (err) {
            git_commit_free(commit);
            goto cleanup;
        }

        /* Get commit tree */
        git_tree *tree = NULL;
        git_err = git_commit_tree(&tree, commit);
        if (git_err < 0) {
            stats_free_commit_info(commit_info);
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
            stats_free_commit_info(commit_info);
            git_commit_free(commit);
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Process diff to find changed files */
        struct index_diff_data diff_data = {
            .index = index,
            .current_commit_info = commit_info,
            .error = NULL
        };

        git_err = git_diff_foreach(diff, index_diff_callback, NULL, NULL, NULL, &diff_data);
        git_diff_free(diff);
        stats_free_commit_info(commit_info);
        commit_info = NULL;
        git_commit_free(commit);

        if (git_err < 0 || diff_data.error) {
            err = diff_data.error ? diff_data.error : error_from_git(git_err);
            goto cleanup;
        }
    }

    /* Success */
    git_revwalk_free(walker);
    git_reference_free(ref);
    *out_index = index;
    return NULL;

cleanup:
    if (commit_info) {
        stats_free_commit_info(commit_info);
    }
    if (walker) {
        git_revwalk_free(walker);
    }
    if (ref) {
        git_reference_free(ref);
    }
    if (index) {
        hashmap_free(index, (void (*)(void *))stats_free_commit_info);
    }
    return err;
}

/**
 * Diff callback data for file history
 */
struct history_diff_data {
    const char *target_path;
    commit_info_t *current_commit_info;
    commit_info_t *commits;
    size_t count;
    size_t capacity;
    error_t *error;
};

/**
 * Diff callback for file history
 */
static int history_diff_callback(
    const git_diff_delta *delta,
    float progress,
    void *payload
) {
    (void)progress;
    struct history_diff_data *data = (struct history_diff_data *)payload;

    /* Defensive: libgit2 should never pass NULL, but check anyway */
    if (!data) {
        return -1;
    }

    /* Get file path */
    const char *path = delta->new_file.path ? delta->new_file.path : delta->old_file.path;
    if (!path) {
        return 0;
    }

    /* Check if this is the file we're tracking */
    if (strcmp(path, data->target_path) != 0) {
        return 0;
    }

    /* Grow array if needed */
    if (data->count >= data->capacity) {
        size_t new_capacity;

        /* Calculate new capacity with overflow protection */
        if (data->capacity == 0) {
            new_capacity = STATS_COMMITS_INITIAL_CAPACITY;
        } else if (data->capacity >= STATS_COMMITS_MAX_CAPACITY) {
            /* Already at maximum safe capacity */
            data->error = ERROR(ERR_MEMORY, "Commit history too large");
            return -1;
        } else {
            new_capacity = data->capacity * 2;
            /* Cap at maximum safe capacity */
            if (new_capacity > STATS_COMMITS_MAX_CAPACITY) {
                new_capacity = STATS_COMMITS_MAX_CAPACITY;
            }
        }

        commit_info_t *new_commits = realloc(data->commits, new_capacity * sizeof(commit_info_t));
        if (!new_commits) {
            data->error = ERROR(ERR_MEMORY, "Failed to grow commits array");
            return -1;
        }
        data->commits = new_commits;
        data->capacity = new_capacity;
    }

    /* Copy commit info */
    commit_info_t *info = &data->commits[data->count];
    git_oid_cpy(&info->oid, &data->current_commit_info->oid);
    info->message_summary = strdup(data->current_commit_info->message_summary);
    if (!info->message_summary) {
        data->error = ERROR(ERR_MEMORY, "Failed to duplicate commit summary");
        return -1;
    }
    info->timestamp = data->current_commit_info->timestamp;
    data->count++;

    return 0;
}

/**
 * Get file history
 */
error_t *stats_get_file_history(
    git_repository *repo,
    const char *profile_name,
    const char *file_path,
    file_history_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(file_path);
    CHECK_NULL(out);

    error_t *err = NULL;
    file_history_t *history = NULL;
    git_reference *ref = NULL;
    git_revwalk *walker = NULL;
    commit_info_t *commit_info = NULL;

    /* Allocate history */
    history = calloc(1, sizeof(file_history_t));
    if (!history) {
        return ERROR(ERR_MEMORY, "Failed to allocate file history");
    }

    /* Get profile branch reference */
    char refname[STATS_REFNAME_BUFFER_SIZE];
    err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", profile_name);
    if (err) {
        free(history);
        return error_wrap(err, "Invalid profile name '%s'", profile_name);
    }

    err = gitops_lookup_reference(repo, refname, &ref);
    if (err) {
        free(history);
        return error_wrap(err, "Failed to lookup profile '%s'", profile_name);
    }

    const git_oid *target_oid = git_reference_target(ref);
    if (!target_oid) {
        git_reference_free(ref);
        free(history);
        return ERROR(ERR_INTERNAL, "Profile '%s' has no commits", profile_name);
    }

    /* Create revwalk */
    int git_err = git_revwalk_new(&walker, repo);
    if (git_err < 0) {
        git_reference_free(ref);
        free(history);
        return error_from_git(git_err);
    }

    git_err = git_revwalk_push(walker, target_oid);
    if (git_err < 0) {
        git_revwalk_free(walker);
        git_reference_free(ref);
        free(history);
        return error_from_git(git_err);
    }

    /* Sort by time (newest first) */
    git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    /* Initialize history tracking */
    struct history_diff_data diff_data = {
        .target_path = file_path,
        .current_commit_info = NULL,
        .commits = NULL,
        .count = 0,
        .capacity = 0,
        .error = NULL
    };

    /* Walk commits */
    git_oid oid;
    while (git_revwalk_next(&oid, walker) == 0) {
        git_commit *commit = NULL;
        git_err = git_commit_lookup(&commit, repo, &oid);
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Create commit info */
        commit_info = NULL;
        err = create_commit_info(commit, &commit_info);
        if (err) {
            git_commit_free(commit);
            goto cleanup;
        }

        /* Get commit tree */
        git_tree *tree = NULL;
        git_err = git_commit_tree(&tree, commit);
        if (git_err < 0) {
            stats_free_commit_info(commit_info);
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
            stats_free_commit_info(commit_info);
            git_commit_free(commit);
            err = error_from_git(git_err);
            goto cleanup;
        }

        /* Check if diff contains our target file */
        diff_data.current_commit_info = commit_info;
        git_err = git_diff_foreach(diff, history_diff_callback, NULL, NULL, NULL, &diff_data);
        git_diff_free(diff);
        stats_free_commit_info(commit_info);
        commit_info = NULL;
        git_commit_free(commit);

        if (git_err < 0 || diff_data.error) {
            err = diff_data.error ? diff_data.error : error_from_git(git_err);
            goto cleanup;
        }
    }

    /* Check if we found any commits for this file */
    if (diff_data.count == 0) {
        git_revwalk_free(walker);
        git_reference_free(ref);
        free(history);
        return ERROR(ERR_NOT_FOUND, "No history found for file '%s' in profile '%s'",
                    file_path, profile_name);
    }

    /* Success */
    history->commits = diff_data.commits;
    history->count = diff_data.count;
    git_revwalk_free(walker);
    git_reference_free(ref);
    *out = history;
    return NULL;

cleanup:
    if (commit_info) {
        stats_free_commit_info(commit_info);
    }
    /* Free accumulated commits */
    for (size_t i = 0; i < diff_data.count; i++) {
        free(diff_data.commits[i].message_summary);
    }
    free(diff_data.commits);
    if (walker) {
        git_revwalk_free(walker);
    }
    if (ref) {
        git_reference_free(ref);
    }
    free(history);
    return err;
}

/**
 * Free commit info
 */
void stats_free_commit_info(commit_info_t *info) {
    if (!info) {
        return;
    }
    free(info->message_summary);
    free(info);
}

/**
 * Free file history
 */
void stats_free_file_history(file_history_t *history) {
    if (!history) {
        return;
    }
    for (size_t i = 0; i < history->count; i++) {
        free(history->commits[i].message_summary);
    }
    free(history->commits);
    free(history);
}
