/**
 * show.c - Show file content or commit details
 */

#include "show.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "infra/path.h"
#include "utils/buffer.h"
#include "utils/config.h"
#include "utils/timeutil.h"

/**
 * Print blob content
 *
 * Uses content layer for transparent decryption. Password prompt only
 * happens if file is encrypted and key is not cached.
 */
static error_t *print_blob_content(
    git_repository *repo,
    const git_oid *blob_oid,
    const char *storage_path,
    const char *profile_name,
    const metadata_t *metadata,
    keymanager_t *km,
    bool raw
) {
    CHECK_NULL(repo);
    CHECK_NULL(blob_oid);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(metadata);

    /* Get plaintext content (handles encryption transparently) */
    bool encrypted = metadata_get_file_encrypted(metadata, storage_path);

    buffer_t *content = NULL;
    error_t *err = content_get_from_blob_oid(
        repo,
        blob_oid,
        storage_path,
        profile_name,
        encrypted,
        km,    /* Prompt for password only if file is encrypted */
        &content
    );
    if (err) {
        return error_wrap(err, "Failed to get file content");
    }

    if (!raw) {
        /* Add header showing size */
        printf("Content-Length: %zu bytes\n", buffer_size(content));
        printf("---\n");
    }

    /* Write content to stdout */
    if (buffer_size(content) > 0) {
        fwrite(buffer_data(content), 1, buffer_size(content), stdout);

        /* Ensure newline at end if not present */
        const char *data = (const char *)buffer_data(content);
        if (data[buffer_size(content) - 1] != '\n') {
            printf("\n");
        }
    }

    buffer_free(content);
    return NULL;
}

/**
 * Show file from a specific profile (optionally at specific commit)
 */
static error_t *show_file(
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
    char *ref_name = NULL;
    git_oid commit_oid;
    metadata_t *metadata = NULL;

    /*
     * Get global keymanager for decryption (if needed)
     *
     * This does NOT prompt for password yet. Password prompt only happens
     * if file is encrypted and key is not cached, when content layer calls
     * keymanager_get_key().
     */
    keymanager_t *km = keymanager_get_global(NULL);

    /* Load metadata for encryption state validation */
    err = metadata_load_from_branch(repo, profile_name, &metadata);
    if (err) {
        /* Non-fatal: metadata file might not exist yet (new profile) */
        /* Create empty metadata for validation (won't have file entries) */
        error_t *create_err = metadata_create_empty(&metadata);
        if (create_err) {
            error_free(create_err);
            err = ERROR(ERR_MEMORY, "Failed to create metadata");
            goto cleanup;
        }
        error_free(err);
        err = NULL;
    }

    /* Load tree from profile */
    if (commit_ref) {
        /* Resolve commit and load its tree */
        err = gitops_resolve_commit_in_branch(repo, profile_name, commit_ref, &commit_oid, &commit);
        if (err) {
            goto cleanup;
        }

        err = gitops_get_tree_from_commit(repo, &commit_oid, &tree);
        if (err) {
            err = error_wrap(err, "Failed to load tree from commit '%s'", commit_ref);
            goto cleanup;
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
    } else {
        /* Load from branch HEAD */
        char ref_name_buf[DOTTA_REFNAME_MAX];
        err = gitops_build_refname(ref_name_buf, sizeof(ref_name_buf), "refs/heads/%s", profile_name);
        if (err) {
            err = error_wrap(err, "Invalid profile name '%s'", profile_name);
            goto cleanup;
        }

        err = gitops_load_tree(repo, ref_name_buf, &tree);
        if (err) {
            err = error_wrap(err, "Failed to load tree for profile '%s'", profile_name);
            goto cleanup;
        }
    }

    /* Find file in tree */
    err = gitops_find_file_in_tree(repo, tree, file_path, &entry);
    if (err) {
        goto cleanup;
    }

    /* Get entry type and OID */
    git_object_t entry_type = git_tree_entry_type(entry);
    const git_oid *entry_oid = git_tree_entry_id(entry);

    if (entry_type == GIT_OBJECT_BLOB) {
        /*
         * Print file content with transparent decryption
         *
         * file_path is the storage_path (e.g., "home/.bashrc")
         * profile_name is used for key derivation
         * metadata is used for encryption state validation
         * km will prompt for password only if file is encrypted
         */
        err = print_blob_content(repo, entry_oid, file_path, profile_name, metadata, km, raw);
    } else if (entry_type == GIT_OBJECT_TREE) {
        err = ERROR(ERR_INVALID_ARG, "'%s' is a directory", file_path);
    } else {
        err = ERROR(ERR_INTERNAL, "Unexpected object type for '%s'", file_path);
    }

cleanup:
    if (metadata) {
        metadata_free(metadata);
    }
    if (entry) {
        git_tree_entry_free(entry);
    }
    if (tree) {
        git_tree_free(tree);
    }
    if (commit) {
        git_commit_free(commit);
    }
    free(ref_name);
    return err;
}

/**
 * Callback for printing diff lines to stdout
 */
static int print_diff_line(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    (void)delta;
    (void)hunk;
    (void)payload;

    /* Write the line content to stdout */
    fwrite(line->content, 1, line->content_len, stdout);
    return 0;
}

/**
 * Show commit with diff
 */
static error_t *show_commit(
    git_repository *repo,
    const char *commit_ref,
    const char *profile_name,
    bool raw
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit_ref);
    CHECK_NULL(profile_name);

    error_t *err = NULL;
    git_oid commit_oid;
    git_commit *commit = NULL;
    git_tree *commit_tree = NULL;
    git_tree *parent_tree = NULL;
    git_diff *diff = NULL;
    git_diff_stats *stats = NULL;

    /* Resolve commit in profile */
    err = gitops_resolve_commit_in_branch(repo, profile_name, commit_ref, &commit_oid, &commit);
    if (err) {
        err = error_wrap(err, "Commit '%s' not found in profile '%s'", commit_ref, profile_name);
        goto cleanup;
    }

    /* Get commit tree */
    err = gitops_get_tree_from_commit(repo, &commit_oid, &commit_tree);
    if (err) {
        goto cleanup;
    }

    /* Get parent tree (NULL if first commit) */
    unsigned int parent_count = git_commit_parentcount(commit);
    if (parent_count > 0) {
        const git_oid *parent_oid = git_commit_parent_id(commit, 0);
        err = gitops_get_tree_from_commit(repo, parent_oid, &parent_tree);
        if (err) {
            goto cleanup;
        }
    }

    /* Generate diff between parent and commit */
    err = gitops_diff_trees(repo, parent_tree, commit_tree, &diff);
    if (err) {
        goto cleanup;
    }

    /* Get diff stats */
    err = gitops_diff_get_stats(diff, &stats);
    if (err) {
        goto cleanup;
    }

    if (!raw) {
        /* Print commit header */
        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);

        printf("commit %s (%s)\n", oid_str, profile_name);

        const git_signature *author = git_commit_author(commit);
        time_t commit_time = (time_t)author->when.time;

        char time_str[64];
        format_relative_time(commit_time, time_str, sizeof(time_str));

        printf("Date:   %s\n", time_str);
        printf("\n");

        /* Print commit message (indented) */
        const char *msg = git_commit_message(commit);
        const char *line = msg;
        while (line && *line) {
            const char *next = strchr(line, '\n');
            if (next) {
                printf("    %.*s\n", (int)(next - line), line);
                line = next + 1;
            } else {
                printf("    %s\n", line);
                break;
            }
        }
        printf("\n");

        /* Print stats summary */
        size_t files_changed = git_diff_stats_files_changed(stats);
        size_t insertions = git_diff_stats_insertions(stats);
        size_t deletions = git_diff_stats_deletions(stats);

        printf(" %zu file%s changed", files_changed, files_changed == 1 ? "" : "s");
        if (insertions > 0) {
            printf(", %zu insertion%s(+)", insertions, insertions == 1 ? "" : "s");
        }
        if (deletions > 0) {
            printf(", %zu deletion%s(-)", deletions, deletions == 1 ? "" : "s");
        }
        printf("\n\n");
    }

    if (stats) {
        git_diff_stats_free(stats);
        stats = NULL;
    }

    /* Print the diff itself */
    int ret = git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, print_diff_line, NULL);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

cleanup:
    if (stats) {
        git_diff_stats_free(stats);
    }
    if (diff) {
        git_diff_free(diff);
    }
    if (parent_tree) {
        git_tree_free(parent_tree);
    }
    if (commit_tree) {
        git_tree_free(commit_tree);
    }
    if (commit) {
        git_commit_free(commit);
    }
    return err;
}

/**
 * Show command implementation
 */
error_t *cmd_show(git_repository *repo, const cmd_show_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    char *storage_path_converted = NULL;
    const char *found_profile = NULL;

    /* Handle SHOW_COMMIT mode */
    if (opts->mode == SHOW_COMMIT) {
        CHECK_NULL(opts->commit);

        /* Determine which profile to search */
        const char *profile_name = opts->profile;

        if (!profile_name) {
            /* No profile specified - use enabled profiles */
            err = config_load(NULL, &config);
            if (err) {
                err = error_wrap(err, "Failed to load config");
                goto cleanup;
            }

            err = profile_resolve(repo, NULL, 0, config->strict_mode, &profiles, NULL);
            if (err) {
                err = error_wrap(err, "Failed to load profiles");
                goto cleanup;
            }

            if (profiles->count == 0) {
                err = ERROR(ERR_NOT_FOUND, "No enabled profiles found");
                goto cleanup;
            }

            /* Try to find commit in enabled profiles (in order) */
            for (size_t i = 0; i < profiles->count; i++) {
                profile_name = profiles->profiles[i].name;
                error_t *try_err = show_commit(repo, opts->commit, profile_name, opts->raw);

                /* If found, we're done */
                if (!try_err) {
                    goto cleanup;
                }

                /* If error is not "commit not found", save and bail out */
                if (try_err->code != ERR_NOT_FOUND) {
                    err = try_err;
                    goto cleanup;
                }

                error_free(try_err);
            }

            err = ERROR(ERR_NOT_FOUND, "Commit '%s' not found in enabled profiles", opts->commit);
            goto cleanup;
        }

        /* Profile specified - show commit from that profile */
        bool exists = false;
        err = gitops_branch_exists(repo, profile_name, &exists);
        if (err) {
            goto cleanup;
        }
        if (!exists) {
            err = ERROR(ERR_NOT_FOUND, "Profile '%s' not found", profile_name);
            goto cleanup;
        }

        err = show_commit(repo, opts->commit, profile_name, opts->raw);
        goto cleanup;
    }

    /* Handle SHOW_FILE mode */
    CHECK_NULL(opts->file_path);

    if (opts->profile) {
        /* Profile specified - show from that profile */
        bool exists = false;
        err = gitops_branch_exists(repo, opts->profile, &exists);
        if (err) {
            goto cleanup;
        }
        if (!exists) {
            err = ERROR(ERR_NOT_FOUND, "Profile '%s' not found", opts->profile);
            goto cleanup;
        }

        /* Try to convert filesystem path to storage path */
        const char *search_path = opts->file_path;
        if (opts->file_path[0] == '/' || opts->file_path[0] == '~') {
            /* Looks like a filesystem path - try to convert */
            error_t *convert_err = path_resolve_input(opts->file_path, false, &storage_path_converted);
            if (convert_err) {
                error_free(convert_err);
                /* Fall back to original path */
                search_path = opts->file_path;
            } else {
                search_path = storage_path_converted;
            }
        }

        err = show_file(repo, opts->profile, search_path, opts->commit, opts->raw);
        goto cleanup;
    }

    /* No profile specified - search across enabled profiles (exact path only) */

    /* If commit is specified without profile, require profile to be specified */
    if (opts->commit) {
        err = ERROR(ERR_INVALID_ARG,
                    "When using --commit with a file, you must also specify --profile\n"
                    "Hint: Use 'dotta list' to see which profiles contain files");
        goto cleanup;
    }

    err = config_load(NULL, &config);
    if (err) {
        err = error_wrap(err, "Failed to load config");
        goto cleanup;
    }

    err = profile_resolve(repo, NULL, 0, config->strict_mode, &profiles, NULL);
    if (err) {
        err = error_wrap(err, "Failed to load profiles");
        goto cleanup;
    }

    if (profiles->count == 0) {
        err = ERROR(ERR_NOT_FOUND, "No profiles found");
        goto cleanup;
    }

    /* Try to convert filesystem path to storage path for better matching */
    const char *search_path = opts->file_path;
    if (opts->file_path[0] == '/' || opts->file_path[0] == '~') {
        /* Looks like a filesystem path - try to convert */
        error_t *convert_err = path_resolve_input(opts->file_path, false, &storage_path_converted);
        if (convert_err) {
            error_free(convert_err);
            /* Fall back to original path */
            search_path = opts->file_path;
        } else {
            search_path = storage_path_converted;
        }
    }

    /* Search all profiles for exact path match */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;
        git_tree *tree = NULL;
        git_tree_entry *entry = NULL;

        char ref_name[DOTTA_REFNAME_MAX];
        error_t *refname_err = gitops_build_refname(ref_name, sizeof(ref_name),
                                                     "refs/heads/%s", profile_name);
        if (refname_err) {
            error_free(refname_err);
            continue;
        }

        error_t *load_err = gitops_load_tree(repo, ref_name, &tree);
        if (load_err == NULL) {
            error_t *find_err = gitops_find_file_in_tree(repo, tree, search_path, &entry);
            if (find_err == NULL) {
                /* Found it! */
                found_profile = profile_name;
                git_tree_entry_free(entry);
                git_tree_free(tree);
                break;
            }
            error_free(find_err);
            git_tree_free(tree);
        } else {
            error_free(load_err);
        }
    }

    if (!found_profile) {
        err = ERROR(ERR_NOT_FOUND, "File '%s' not found in enabled profiles", opts->file_path);
        goto cleanup;
    }

    /* Show the file */
    if (!opts->raw) {
        printf("# From profile: %s\n", found_profile);
        printf("# Path: %s\n", search_path);
        printf("\n");
    }
    err = show_file(repo, found_profile, search_path, NULL, opts->raw);

cleanup:
    if (config) {
        config_free(config);
    }
    if (profiles) {
        profile_list_free(profiles);
    }
    free(storage_path_converted);
    return err;
}
