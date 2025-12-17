/**
 * completion.c - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts.
 * All functions follow the silent failure model - errors result in
 * no output rather than error messages to stderr.
 */

#include "completion.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/state.h"
#include "core/upstream.h"
#include "utils/array.h"

/* Constants */
#define COMPLETE_COMMIT_SHORT_OID_LEN 8
#define COMPLETE_COMMIT_DEFAULT_LIMIT 20
#define COMPLETE_COMMIT_MAX_LIMIT 100
#define COMPLETE_COMMIT_SUMMARY_MAX 60

/**
 * Output enabled profiles from state database
 *
 * Queries the enabled_profiles table and outputs profile names.
 */
static void complete_enabled_profiles(git_repository *repo) {
    state_t *state = NULL;
    error_t *err = state_load(repo, &state);
    if (err) {
        error_free(err);
        return;
    }

    string_array_t *profiles = NULL;
    err = state_get_profiles(state, &profiles);
    if (err) {
        error_free(err);
        state_free(state);
        return;
    }

    /* Sort enabled profiles alphabetically for easier completion */
    string_array_sort(profiles);

    for (size_t i = 0; i < string_array_size(profiles); i++) {
        printf("%s\tEnabled Profile\n", string_array_get(profiles, i));
    }

    string_array_free(profiles);
    state_free(state);
}

/**
 * Output all available profiles
 *
 * Lists all local branches and remote-tracking branches,
 * excluding the internal dotta-worktree branch.
 */
static void complete_all_profiles(git_repository *repo) {
    /* 1. Local branches */
    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (!err) {
        string_array_sort(branches);
        for (size_t i = 0; i < string_array_size(branches); i++) {
            const char *name = string_array_get(branches, i);
            /* Skip internal worktree branch */
            if (strcmp(name, "dotta-worktree") != 0) {
                printf("%s\tProfile\n", name);
            }
        }
    } else {
        error_free(err);
    }

    /* 2. Remote tracking branches */
    char *remote_name = NULL;
    if (upstream_detect_remote(repo, &remote_name) == NULL) {
        string_array_t *remote_branches = NULL;
        if (upstream_discover_branches(repo, remote_name, &remote_branches) == NULL) {
            string_array_sort(remote_branches);
            for (size_t i = 0; i < string_array_size(remote_branches); i++) {
                printf("%s\tRemote Profile\n", string_array_get(remote_branches, i));
            }
            string_array_free(remote_branches);
        }
        free(remote_name);
    }

    if (branches) {
        string_array_free(branches);
    }
}

/**
 * Output configured git remotes
 */
static void complete_remotes(git_repository *repo) {
    git_strarray remotes = {0};
    int git_err = git_remote_list(&remotes, repo);
    if (git_err == 0) {
        for (size_t i = 0; i < remotes.count; i++) {
            git_remote *remote = NULL;
            const char *name = remotes.strings[i];
            if (git_remote_lookup(&remote, repo, name) == 0) {
                const char *url = git_remote_url(remote);
                printf("%s\t%s\n", name, url ? url : "Remote");
                git_remote_free(remote);
            } else {
                printf("%s\tRemote\n", name);
            }
        }
        git_strarray_dispose(&remotes);
    }
}

/**
 * Output managed files from state database
 *
 * @param repo Repository
 * @param profile Optional profile filter (NULL for all files)
 * @param storage_paths If true, output storage_path; if false, filesystem_path
 */
static void complete_files(
    git_repository *repo,
    const char *profile,
    bool storage_paths
) {
    state_t *state = NULL;
    error_t *err = state_load(repo, &state);
    if (err) {
        error_free(err);
        return;
    }

    state_file_entry_t *entries = NULL;
    size_t count = 0;

    if (profile) {
        err = state_get_entries_by_profile(state, profile, &entries, &count);
    } else {
        err = state_get_all_files(state, &entries, &count);
    }

    if (err) {
        error_free(err);
        state_free(state);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        const char *path = storage_paths
            ? entries[i].storage_path
            : entries[i].filesystem_path;
        if (path) {
            printf("%s\t%s\n", path, entries[i].profile);
        }
    }

    state_free_all_files(entries, count);
    state_free(state);
}

/**
 * Output recent commits for completion
 *
 * Outputs commits in tab-separated format: <short_oid>\t<summary>
 * This allows fish to display the summary as a description.
 *
 * @param repo Repository
 * @param profile Profile to get commits from (NULL uses first enabled profile)
 * @param limit Maximum number of commits to output
 */
static void complete_commits(
    git_repository *repo,
    const char *profile,
    int limit
) {
    /* Clamp limit to reasonable bounds */
    if (limit <= 0) {
        limit = COMPLETE_COMMIT_DEFAULT_LIMIT;
    }
    if (limit > COMPLETE_COMMIT_MAX_LIMIT) {
        limit = COMPLETE_COMMIT_MAX_LIMIT;
    }

    /* Determine target profile */
    const char *target_profile = profile;
    string_array_t *profiles STRING_ARRAY_CLEANUP = NULL;

    /* If no profile specified, use first enabled profile */
    if (!profile) {
        state_t *state = NULL;
        error_t *err = state_load(repo, &state);
        if (err) {
            error_free(err);
            return;
        }

        err = state_get_profiles(state, &profiles);
        state_free(state);
        if (err) {
            error_free(err);
            return;
        }

        if (string_array_size(profiles) > 0) {
            target_profile = string_array_get(profiles, 0);
        }
    }

    if (!target_profile) {
        return;
    }

    /* Resolve reference using DWIM (handles branches, tags, remotes) */
    git_reference *ref = NULL;
    int git_err = git_reference_dwim(&ref, repo, target_profile);
    if (git_err != 0) {
        return;
    }

    /* Peel to commit (handles symbolic refs and tags automatically) */
    git_object *obj = NULL;
    git_err = git_reference_peel(&obj, ref, GIT_OBJECT_COMMIT);
    git_reference_free(ref);
    if (git_err != 0) {
        return;
    }

    const git_oid *head_oid = git_object_id(obj);

    /* Create revision walker */
    git_revwalk *walker = NULL;
    git_err = git_revwalk_new(&walker, repo);
    if (git_err != 0) {
        git_object_free(obj);
        return;
    }

    git_revwalk_push(walker, head_oid);
    git_revwalk_sorting(walker, GIT_SORT_TIME);

    /* Walk commits and output */
    git_oid oid;
    int count = 0;
    while (git_revwalk_next(&oid, walker) == 0 && count < limit) {
        git_commit *commit = NULL;
        if (git_commit_lookup(&commit, repo, &oid) != 0) {
            continue;
        }

        /* Format short OID */
        char oid_str[COMPLETE_COMMIT_SHORT_OID_LEN + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &oid);

        /* Extract first line of commit message */
        const char *message = git_commit_message(commit);
        const char *newline = strchr(message, '\n');
        size_t msg_len = newline ? (size_t)(newline - message) : strlen(message);
        if (msg_len > COMPLETE_COMMIT_SUMMARY_MAX) {
            msg_len = COMPLETE_COMMIT_SUMMARY_MAX;
        }

        /* Output: <oid>\t<summary> */
        printf("%s\t%.*s\n", oid_str, (int)msg_len, message);

        git_commit_free(commit);
        count++;
    }

    git_revwalk_free(walker);
    git_object_free(obj);
}

/**
 * Run completion command
 *
 * Dispatches to appropriate completion function based on mode.
 * Always returns NULL (success) - errors result in no output.
 */
error_t *cmd_completion(
    git_repository *repo,
    const cmd_completion_options_t *opts
) {
    if (!opts) {
        return NULL;  /* Silent failure */
    }

    switch (opts->mode) {
        case COMPLETE_CHECK:
            /* Check mode handled in cmd_completion_main before we're called */
            break;

        case COMPLETE_PROFILES:
            if (!repo) {
                return NULL;
            }
            if (opts->all) {
                complete_all_profiles(repo);
            } else {
                complete_enabled_profiles(repo);
            }
            break;

        case COMPLETE_FILES:
            if (!repo) {
                return NULL;
            }
            complete_files(repo, opts->profile, opts->storage_paths);
            break;

        case COMPLETE_COMMITS:
            if (!repo) {
                return NULL;
            }
            complete_commits(repo, opts->profile, opts->limit);
            break;

        case COMPLETE_REMOTES:
            if (!repo) {
                return NULL;
            }
            complete_remotes(repo);
            break;

        default:
            /* Unknown mode - silent failure */
            break;
    }

    return NULL;
}
