/**
 * show.c - Show file content from profile
 */

#include "show.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "infra/path.h"
#include "utils/config.h"

/**
 * Get basename from path
 */
static const char *get_basename(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/**
 * Convert filesystem-style path to storage path without requiring file to exist
 * This is a simplified version of path_to_storage for querying purposes
 */
static error_t *convert_to_storage_path_query(const char *path, char **out) {
    CHECK_NULL(path);
    CHECK_NULL(out);

    char *expanded_path = NULL;
    const char *working_path = path;

    /* Expand ~ if present */
    if (path[0] == '~') {
        error_t *err = path_expand_home(path, &expanded_path);
        if (err) {
            return err;
        }
        working_path = expanded_path;
    }

    /* Must be absolute path at this point */
    if (working_path[0] != '/') {
        free(expanded_path);
        return ERROR(ERR_INVALID_ARG, "Path must be absolute or start with ~");
    }

    /* Get HOME directory */
    char *home = NULL;
    error_t *err = path_get_home(&home);
    if (err) {
        free(expanded_path);
        return err;
    }

    size_t home_len = strlen(home);
    char *result = NULL;

    /* Check if path is under $HOME */
    if (strncmp(working_path, home, home_len) == 0 &&
        (working_path[home_len] == '/' || working_path[home_len] == '\0')) {
        /* Under home directory */
        const char *rel = working_path + home_len;
        if (rel[0] == '/') rel++;

        if (rel[0] == '\0') {
            free(home);
            free(expanded_path);
            return ERROR(ERR_INVALID_ARG, "Cannot query HOME directory itself");
        }

        result = malloc(strlen("home/") + strlen(rel) + 1);
        if (!result) {
            free(home);
            free(expanded_path);
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        sprintf(result, "home/%s", rel);
    } else {
        /* Outside home - use root/ prefix */
        result = malloc(strlen("root") + strlen(working_path) + 1);
        if (!result) {
            free(home);
            free(expanded_path);
            return ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        sprintf(result, "root%s", working_path);
    }

    free(home);
    free(expanded_path);
    *out = result;
    return NULL;
}

/**
 * Load tree from commit OID
 */
static error_t *load_tree_from_commit(
    git_repository *repo,
    const git_oid *commit_oid,
    git_tree **out_tree
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_oid);
    CHECK_NULL(out_tree);

    /* Lookup commit */
    git_commit *commit = NULL;
    int ret = git_commit_lookup(&commit, repo, commit_oid);
    if (ret < 0) {
        return error_from_git(ret);
    }

    /* Get tree from commit */
    git_tree *tree = NULL;
    ret = git_commit_tree(&tree, commit);
    git_commit_free(commit);

    if (ret < 0) {
        return error_from_git(ret);
    }

    *out_tree = tree;
    return NULL;
}

/**
 * Print blob content
 */
static error_t *print_blob_content(
    git_repository *repo,
    const git_oid *blob_oid,
    bool raw
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);

    git_blob *blob = NULL;
    int ret = git_blob_lookup(&blob, repo, blob_oid);
    if (ret < 0) {
        return error_from_git(ret);
    }

    const void *content = git_blob_rawcontent(blob);
    git_object_size_t size = git_blob_rawsize(blob);

    if (!raw) {
        /* Add header showing size */
        printf("Content-Length: %lld bytes\n", (long long)size);
        printf("---\n");
    }

    /* Write content to stdout */
    if (content && size > 0) {
        fwrite(content, 1, (size_t)size, stdout);

        /* Ensure newline at end if not present */
        const char *last_char = (const char *)content + size - 1;
        if (*last_char != '\n') {
            printf("\n");
        }
    }

    git_blob_free(blob);
    return NULL;
}

/**
 * Show file from a specific profile (optionally at specific commit)
 */
static error_t *show_from_profile(
    git_repository *repo,
    const char *profile_name,
    const char *file_path,
    const char *commit_ref,
    bool raw
) {
    error_t *err = NULL;
    git_tree *tree = NULL;
    git_tree_entry *entry = NULL;
    git_commit *commit = NULL;
    git_oid commit_oid;

    /* Load tree from profile */
    if (commit_ref) {
        /* Resolve commit and load its tree */
        err = gitops_resolve_commit_in_branch(repo, profile_name, commit_ref, &commit_oid, &commit);
        if (err) {
            return err;
        }

        err = load_tree_from_commit(repo, &commit_oid, &tree);
        if (err) {
            if (commit) git_commit_free(commit);
            return error_wrap(err, "Failed to load tree from commit '%s'", commit_ref);
        }

        /* Print commit metadata if not raw */
        if (!raw && commit) {
            char oid_str[8];
            git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

            const git_signature *author = git_commit_author(commit);
            time_t commit_time = (time_t)author->when.time;
            struct tm *tm_info = localtime(&commit_time);
            char time_buf[64];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

            printf("# Commit: %s\n", oid_str);
            printf("# Date: %s\n", time_buf);
            printf("# Author: %s <%s>\n", author->name, author->email);

            /* Show first line of commit message */
            const char *msg = git_commit_message(commit);
            const char *newline = strchr(msg, '\n');
            if (newline) {
                printf("# Message: %.*s\n", (int)(newline - msg), msg);
            } else {
                printf("# Message: %s\n", msg);
            }
        }

        if (commit) git_commit_free(commit);
    } else {
        /* Load from branch HEAD */
        size_t ref_name_size = strlen("refs/heads/") + strlen(profile_name) + 1;
        char *ref_name = malloc(ref_name_size);
        if (!ref_name) {
            return ERROR(ERR_MEMORY, "Failed to allocate reference name");
        }
        snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_name);

        err = gitops_load_tree(repo, ref_name, &tree);
        free(ref_name);

        if (err) {
            return error_wrap(err, "Failed to load tree for profile '%s'", profile_name);
        }
    }

    /* Find file in tree */
    err = gitops_find_file_in_tree(repo, tree, file_path, &entry);
    if (err) {
        git_tree_free(tree);
        return err;
    }

    /* Get entry type and OID */
    git_object_t entry_type = git_tree_entry_type(entry);
    const git_oid *entry_oid = git_tree_entry_id(entry);

    if (entry_type == GIT_OBJECT_BLOB) {
        err = print_blob_content(repo, entry_oid, raw);
    } else if (entry_type == GIT_OBJECT_TREE) {
        err = ERROR(ERR_INVALID_ARG, "'%s' is a directory", file_path);
    } else {
        err = ERROR(ERR_INTERNAL, "Unexpected object type for '%s'", file_path);
    }

    git_tree_entry_free(entry);
    git_tree_free(tree);
    return err;
}

/**
 * Show command implementation
 */
error_t *cmd_show(git_repository *repo, const cmd_show_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    char *storage_path_converted = NULL;

    if (opts->profile) {
        /* Profile specified - show from that profile */
        bool exists = false;
        err = gitops_branch_exists(repo, opts->profile, &exists);
        if (err) {
            return err;
        }
        if (!exists) {
            return ERROR(ERR_NOT_FOUND, "Profile '%s' not found", opts->profile);
        }

        /* Try to convert filesystem path to storage path */
        const char *search_path = opts->file_path;
        if (opts->file_path[0] == '/' || opts->file_path[0] == '~') {
            /* Looks like a filesystem path - try to convert */
            err = convert_to_storage_path_query(opts->file_path, &storage_path_converted);
            if (err) {
                error_free(err);
                /* Fall back to original path */
                search_path = opts->file_path;
            } else {
                search_path = storage_path_converted;
            }
        }

        err = show_from_profile(repo, opts->profile, search_path, opts->commit, opts->raw);
        free(storage_path_converted);
        return err;
    }

    /* No profile specified - search across all configured profiles */

    /* If commit is specified without profile, require profile to be specified */
    if (opts->commit) {
        return ERROR(ERR_INVALID_ARG,
                    "When using --commit, you must also specify --profile\n"
                    "Hint: Use 'dotta log' to see which profiles have commits");
    }

    err = config_load(NULL, &config);
    if (err) {
        return error_wrap(err, "Failed to load config");
    }

    err = profile_load_with_fallback(
        repo,
        NULL, 0,
        (const char **)config->profile_order,
        config->profile_order_count,
        config->auto_detect,
        config->strict_mode,
        &profiles
    );

    if (err) {
        config_free(config);
        return error_wrap(err, "Failed to load profiles");
    }

    if (profiles->count == 0) {
        config_free(config);
        profile_list_free(profiles);
        return ERROR(ERR_NOT_FOUND, "No profiles found");
    }

    /* Try to convert filesystem path to storage path for better matching */
    const char *search_path = opts->file_path;
    if (opts->file_path[0] == '/' || opts->file_path[0] == '~') {
        /* Looks like a filesystem path - try to convert */
        err = convert_to_storage_path_query(opts->file_path, &storage_path_converted);
        if (err) {
            error_free(err);
            /* Fall back to original path */
            search_path = opts->file_path;
        } else {
            search_path = storage_path_converted;
        }
    }

    /* Try to find file: first by exact path, then by basename */
    const char *basename = get_basename(search_path);
    bool use_basename_search = (strcmp(basename, search_path) == 0);

    typedef struct {
        char *profile_name;
        char *file_path;
    } match_t;

    match_t *matches = NULL;
    size_t match_count = 0;

    /* Search all profiles */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;
        git_tree *tree = NULL;

        size_t ref_name_size = strlen("refs/heads/") + strlen(profile_name) + 1;
        char *ref_name = malloc(ref_name_size);
        if (!ref_name) continue;
        snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_name);

        if (gitops_load_tree(repo, ref_name, &tree) == NULL) {
            if (use_basename_search) {
                /* Search by basename */
                char **paths = NULL;
                size_t path_count = 0;

                if (gitops_find_files_by_basename_in_tree(repo, tree, basename, &paths, &path_count) == NULL) {
                    for (size_t j = 0; j < path_count; j++) {
                        matches = realloc(matches, (match_count + 1) * sizeof(match_t));
                        if (matches) {
                            matches[match_count].profile_name = strdup(profile_name);
                            matches[match_count].file_path = paths[j];
                            match_count++;
                        } else {
                            free(paths[j]);
                        }
                    }
                    free(paths);
                }
            } else {
                /* Try exact path */
                git_tree_entry *entry = NULL;
                if (gitops_find_file_in_tree(repo, tree, search_path, &entry) == NULL) {
                    matches = realloc(matches, (match_count + 1) * sizeof(match_t));
                    if (matches) {
                        matches[match_count].profile_name = strdup(profile_name);
                        matches[match_count].file_path = strdup(search_path);
                        match_count++;
                    }
                    git_tree_entry_free(entry);
                }
            }
            git_tree_free(tree);
        }
        free(ref_name);
    }

    config_free(config);
    profile_list_free(profiles);
    free(storage_path_converted);

    if (match_count == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in any profile", opts->file_path);
    }

    if (match_count == 1) {
        /* Found in one profile - show it */
        if (!opts->raw) {
            printf("# From profile: %s\n", matches[0].profile_name);
            printf("# Path: %s\n", matches[0].file_path);
            printf("\n");
        }
        err = show_from_profile(repo, matches[0].profile_name, matches[0].file_path, NULL, opts->raw);
        free(matches[0].profile_name);
        free(matches[0].file_path);
        free(matches);
        return err;
    }

    /* Found in multiple profiles - show options */
    fprintf(stderr, "File '%s' found in multiple profiles:\n", opts->file_path);
    for (size_t i = 0; i < match_count; i++) {
        fprintf(stderr, "  %s: %s\n", matches[i].profile_name, matches[i].file_path);
        free(matches[i].profile_name);
        free(matches[i].file_path);
    }
    free(matches);
    fprintf(stderr, "\nPlease specify --profile to disambiguate\n");
    fprintf(stderr, "\n");

    return ERROR(ERR_INVALID_ARG, "Ambiguous file reference");
}
