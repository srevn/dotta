/**
 * upstream.c - Remote profile tracking and metadata implementation
 */

#include "sys/upstream.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/credentials.h"
#include "sys/gitops.h"

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
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err;

    err = gitops_build_refname(
        local_refname, sizeof(local_refname), "refs/heads/%s",
        profile_name
    );
    if (err) {
        upstream_info_free(info);
        return error_wrap(
            err, "Invalid profile name '%s'",
            profile_name
        );
    }

    err = gitops_build_refname(
        remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
        remote_name, profile_name
    );
    if (err) {
        upstream_info_free(info);
        return error_wrap(
            err, "Invalid remote/profile name '%s/%s'",
            remote_name, profile_name
        );
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

    if (!local_oid || !remote_oid) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        upstream_info_free(info);
        return ERROR(ERR_GIT, "Branch reference has no target OID");
    }

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
    git_err = git_graph_ahead_behind(
        &ahead, &behind, repo, local_oid, remote_oid
    );
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
    git_strarray remotes = { 0 };
    int git_err = git_remote_list(&remotes, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (remotes.count == 0) {
        git_strarray_dispose(&remotes);
        return ERROR(
            ERR_NOT_FOUND, "No remotes configured\n"
            "Hint: Add a remote with 'dotta remote add <name> <url>'"
        );
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
        return *out_remote ? NULL : ERROR(
            ERR_MEMORY, "Failed to allocate remote name"
        );
    }

    /* If exactly one remote, use it */
    if (remotes.count == 1) {
        *out_remote = strdup(remotes.strings[0]);
        git_strarray_dispose(&remotes);
        return *out_remote ? NULL : ERROR(
            ERR_MEMORY, "Failed to allocate remote name"
        );
    }

    /* Multiple remotes, no origin - need explicit remote name */
    git_strarray_dispose(&remotes);
    return ERROR(
        ERR_INVALID_ARG, "Multiple remotes configured, but no 'origin' found\n"
        "Hint: Specify remote explicitly or rename preferred remote to 'origin'"
    );
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

    /* Get all remote tracking branches */
    string_array_t *remote_branches = NULL;
    error_t *err = gitops_list_remote_branches(repo, remote_name, &remote_branches);
    if (err) {
        return err;
    }

    /* Get all local branches */
    string_array_t *local_branches = NULL;
    err = gitops_list_branches(repo, &local_branches);
    if (err) {
        string_array_free(remote_branches);
        return err;
    }

    /* Set difference: remote branches not yet present locally */
    string_array_t *new_branches = string_array_new(remote_branches->count);
    if (!new_branches) {
        string_array_free(remote_branches);
        string_array_free(local_branches);
        return ERROR(ERR_MEMORY, "Failed to allocate branch list");
    }

    for (size_t i = 0; i < remote_branches->count; i++) {
        if (!string_array_contains(local_branches, remote_branches->items[i])) {
            err = string_array_push(new_branches, remote_branches->items[i]);
            if (err) {
                string_array_free(new_branches);
                string_array_free(remote_branches);
                string_array_free(local_branches);
                return err;
            }
        }
    }

    string_array_free(remote_branches);
    string_array_free(local_branches);

    *out_branches = new_branches;
    return NULL;
}

/**
 * Query remote server for available branches
 */
error_t *upstream_query_remote_branches(
    git_repository *repo,
    const char *remote_name,
    void *cred_ctx,
    string_array_t **out_branches
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out_branches);

    /* Resource tracking */
    git_remote *remote = NULL;
    string_array_t *branches = NULL;
    error_t *err = NULL;

    /* Create branch array */
    branches = string_array_new(0);
    if (!branches) {
        return ERROR(ERR_MEMORY, "Failed to create branch array");
    }

    /* Lookup remote */
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        string_array_free(branches);
        return error_from_git(git_err);
    }

    /* Setup callbacks for authentication */
    git_remote_callbacks callbacks;
    git_remote_init_callbacks(&callbacks, GIT_REMOTE_CALLBACKS_VERSION);
    if (cred_ctx) {
        callbacks.credentials = credentials_callback;
        callbacks.payload = cred_ctx;
    }

    /* Connect to remote (network operation) */
    git_err = git_remote_connect(
        remote, GIT_DIRECTION_FETCH, &callbacks, NULL, NULL
    );
    if (git_err < 0) {
        if (cred_ctx) {
            credential_context_reject(cred_ctx);
        }
        git_remote_free(remote);
        string_array_free(branches);
        return error_from_git(git_err);
    }

    /* Approve credentials on successful connection */
    if (cred_ctx) {
        credential_context_approve(cred_ctx);
    }

    /* Get list of refs from remote */
    const git_remote_head **refs = NULL;
    size_t refs_len = 0;
    git_err = git_remote_ls(&refs, &refs_len, remote);
    if (git_err < 0) {
        git_remote_disconnect(remote);
        git_remote_free(remote);
        string_array_free(branches);
        return error_from_git(git_err);
    }

    /* Extract branch names from refs/heads/ prefix */
    const char *heads_prefix = "refs/heads/";
    size_t prefix_len = strlen(heads_prefix);

    for (size_t i = 0; i < refs_len; i++) {
        const char *refname = refs[i]->name;

        /* Only process branch refs */
        if (!str_starts_with(refname, heads_prefix)) {
            continue;
        }

        /* Extract branch name */
        const char *branch_name = refname + prefix_len;

        /* Skip dotta-worktree and any empty names */
        if (strcmp(branch_name, "dotta-worktree") == 0 ||
            strlen(branch_name) == 0) {
            continue;
        }

        /* Add to list */
        err = string_array_push(branches, branch_name);
        if (err) {
            git_remote_disconnect(remote);
            git_remote_free(remote);
            string_array_free(branches);
            return err;
        }
    }

    /* Cleanup */
    git_remote_disconnect(remote);
    git_remote_free(remote);

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
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
        remote_name, branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid remote/branch name '%s/%s'",
            remote_name, branch_name
        );
    }

    git_oid target_oid;
    err = gitops_resolve_reference_oid(repo, remote_refname, &target_oid);
    if (err) {
        return error_wrap(
            err, "Failed to resolve remote ref '%s'",
            remote_refname
        );
    }

    /* Create local branch pointing to the same commit */
    char local_refname[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(
        local_refname, sizeof(local_refname), "refs/heads/%s",
        branch_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid branch name '%s'",
            branch_name
        );
    }

    return gitops_create_reference(repo, local_refname, &target_oid, false);
}
