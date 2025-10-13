/**
 * upstream.c - Remote profile tracking and metadata implementation
 */

#include "upstream.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "utils/array.h"

/**
 * Analyze upstream state for a single profile
 */
error_t *upstream_analyze_profile(
    git_repository *repo,
    const char *remote_name,
    const char *profile_name,
    upstream_info_t **out_info
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_info);

    /* Allocate info structure */
    upstream_info_t *info = calloc(1, sizeof(upstream_info_t));
    if (!info) {
        return ERROR(ERR_MEMORY, "Failed to allocate upstream info");
    }

    info->profile_name = strdup(profile_name);
    if (!info->profile_name) {
        free(info);
        return ERROR(ERR_MEMORY, "Failed to allocate profile name");
    }

    /* Build reference names */
    char local_refname[256];
    char remote_refname[256];
    error_t *err;

    err = gitops_build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", profile_name);
    if (err) {
        upstream_info_free(info);
        return error_wrap(err, "Invalid profile name '%s'", profile_name);
    }

    err = gitops_build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
                       remote_name, profile_name);
    if (err) {
        upstream_info_free(info);
        return error_wrap(err, "Invalid remote/profile name '%s/%s'", remote_name, profile_name);
    }

    /* Check local branch exists */
    git_reference *local_ref = NULL;
    int git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err == GIT_ENOTFOUND) {
        info->exists_locally = false;
        info->state = UPSTREAM_UNKNOWN;
        *out_info = info;
        return NULL;
    } else if (git_err < 0) {
        upstream_info_free(info);
        return error_from_git(git_err);
    }
    info->exists_locally = true;

    /* Check remote branch exists */
    git_reference *remote_ref = NULL;
    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err == GIT_ENOTFOUND) {
        /* No remote tracking branch */
        git_reference_free(local_ref);
        info->exists_remotely = false;
        info->state = UPSTREAM_NO_REMOTE;
        *out_info = info;
        return NULL;
    } else if (git_err < 0) {
        git_reference_free(local_ref);
        upstream_info_free(info);
        return error_from_git(git_err);
    }
    info->exists_remotely = true;

    /* Get OIDs */
    const git_oid *local_oid = git_reference_target(local_ref);
    const git_oid *remote_oid = git_reference_target(remote_ref);

    /* Check if identical */
    if (git_oid_equal(local_oid, remote_oid)) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        info->state = UPSTREAM_UP_TO_DATE;
        info->ahead = 0;
        info->behind = 0;
        *out_info = info;
        return NULL;
    }

    /* Calculate ahead/behind */
    size_t ahead = 0, behind = 0;
    git_err = git_graph_ahead_behind(&ahead, &behind, repo, local_oid, remote_oid);
    git_reference_free(local_ref);
    git_reference_free(remote_ref);

    if (git_err < 0) {
        upstream_info_free(info);
        return error_from_git(git_err);
    }

    info->ahead = ahead;
    info->behind = behind;

    /* Determine state */
    if (ahead > 0 && behind == 0) {
        info->state = UPSTREAM_LOCAL_AHEAD;
    } else if (ahead == 0 && behind > 0) {
        info->state = UPSTREAM_REMOTE_AHEAD;
    } else if (ahead > 0 && behind > 0) {
        info->state = UPSTREAM_DIVERGED;
    } else {
        info->state = UPSTREAM_UP_TO_DATE;
    }

    *out_info = info;
    return NULL;
}

/**
 * Free upstream info
 */
void upstream_info_free(upstream_info_t *info) {
    if (!info) {
        return;
    }
    free(info->profile_name);
    free(info);
}

/**
 * Free upstream info list
 */
void upstream_info_list_free(upstream_info_list_t *list) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].profile_name);
    }
    free(list->entries);
    free(list);
}

/**
 * Get string representation of upstream state
 */
const char *upstream_state_string(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return "up-to-date";
        case UPSTREAM_LOCAL_AHEAD:  return "ahead";
        case UPSTREAM_REMOTE_AHEAD: return "behind";
        case UPSTREAM_DIVERGED:     return "diverged";
        case UPSTREAM_NO_REMOTE:    return "no remote";
        case UPSTREAM_UNKNOWN:      return "unknown";
        default:                    return "unknown";
    }
}

/**
 * Get compact symbol for upstream state
 */
const char *upstream_state_symbol(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return "=";
        case UPSTREAM_LOCAL_AHEAD:  return "↑";
        case UPSTREAM_REMOTE_AHEAD: return "↓";
        case UPSTREAM_DIVERGED:     return "↕";
        case UPSTREAM_NO_REMOTE:    return "•";
        case UPSTREAM_UNKNOWN:      return "?";
        default:                    return "?";
    }
}

/**
 * Detect default remote name for tracking
 */
error_t *upstream_detect_remote(git_repository *repo, char **out_remote) {
    CHECK_NULL(repo);
    CHECK_NULL(out_remote);

    *out_remote = NULL;

    /* Get list of remotes */
    git_strarray remotes = {0};
    int git_err = git_remote_list(&remotes, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (remotes.count == 0) {
        git_strarray_dispose(&remotes);
        return ERROR(ERR_NOT_FOUND,
                    "No remotes configured\n"
                    "Hint: Add a remote with 'dotta remote add <name> <url>'");
    }

    /* Check if "origin" exists */
    bool has_origin = false;
    for (size_t i = 0; i < remotes.count; i++) {
        if (strcmp(remotes.strings[i], "origin") == 0) {
            has_origin = true;
            break;
        }
    }

    if (has_origin) {
        *out_remote = strdup("origin");
        git_strarray_dispose(&remotes);
        return *out_remote ? NULL : ERROR(ERR_MEMORY, "Failed to allocate remote name");
    }

    /* If exactly one remote, use it */
    if (remotes.count == 1) {
        *out_remote = strdup(remotes.strings[0]);
        git_strarray_dispose(&remotes);
        return *out_remote ? NULL : ERROR(ERR_MEMORY, "Failed to allocate remote name");
    }

    /* Multiple remotes, no origin - need explicit remote name */
    git_strarray_dispose(&remotes);
    return ERROR(ERR_INVALID_ARG,
                "Multiple remotes configured, but no 'origin' found\n"
                "Hint: Specify remote explicitly or rename preferred remote to 'origin'");
}

/**
 * Discover remote branches that don't exist locally
 */
error_t *upstream_discover_branches(
    git_repository *repo,
    const char *remote_name,
    string_array_t **out_branches
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out_branches);

    string_array_t *branches = string_array_create();
    if (!branches) {
        return ERROR(ERR_MEMORY, "Failed to create branch array");
    }

    /* Iterate remote refs */
    git_reference_iterator *iter = NULL;
    int git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        string_array_free(branches);
        return error_from_git(git_err);
    }

    char remote_prefix[256];
    error_t *err = gitops_build_refname(remote_prefix, sizeof(remote_prefix), "refs/remotes/%s/", remote_name);
    if (err) {
        git_reference_iterator_free(iter);
        string_array_free(branches);
        return error_wrap(err, "Invalid remote name '%s'", remote_name);
    }
    size_t prefix_len = strlen(remote_prefix);

    git_reference *ref = NULL;
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);

        /* Only process remote tracking branches */
        if (strncmp(refname, remote_prefix, prefix_len) != 0) {
            git_reference_free(ref);
            continue;
        }

        /* Extract branch name */
        const char *branch_name = refname + prefix_len;

        /* Skip dotta-worktree and HEAD */
        if (strcmp(branch_name, "dotta-worktree") == 0 || strcmp(branch_name, "HEAD") == 0) {
            git_reference_free(ref);
            continue;
        }

        /* Check if local branch exists */
        bool exists = false;
        error_t *err = gitops_branch_exists(repo, branch_name, &exists);
        if (err) {
            error_free(err);
            git_reference_free(ref);
            continue;
        }

        if (!exists) {
            /* This is a new remote branch - add to list */
            err = string_array_push(branches, branch_name);
            if (err) {
                string_array_free(branches);
                git_reference_free(ref);
                git_reference_iterator_free(iter);
                return err;
            }
        }

        git_reference_free(ref);
    }

    git_reference_iterator_free(iter);
    *out_branches = branches;
    return NULL;
}

/**
 * Create local tracking branch from remote
 */
error_t *upstream_create_tracking_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    /* Get remote ref */
    char remote_refname[256];
    error_t *err = gitops_build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (err) {
        return error_wrap(err, "Invalid remote/branch name '%s/%s'", remote_name, branch_name);
    }

    git_reference *remote_ref = NULL;
    int git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const git_oid *target_oid = git_reference_target(remote_ref);
    if (!target_oid) {
        git_reference_free(remote_ref);
        return ERROR(ERR_GIT, "Remote ref '%s' has no target", remote_refname);
    }

    /* Create local branch */
    char local_refname[256];
    err = gitops_build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (err) {
        git_reference_free(remote_ref);
        return error_wrap(err, "Invalid branch name '%s'", branch_name);
    }

    git_reference *local_ref = NULL;
    git_err = git_reference_create(&local_ref, repo, local_refname, target_oid, 0, NULL);
    git_reference_free(remote_ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(local_ref);
    return NULL;
}
