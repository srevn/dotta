/**
 * revert.c - Revert file to previous commit state
 */

#include "revert.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/deploy.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/compare.h"
#include "infra/path.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Get basename from path
 */
static const char *get_basename(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/**
 * File match result
 */
typedef struct {
    char *profile_name;
    char *file_path;
} file_match_t;

/**
 * Discover file in profiles
 *
 * Returns profile name and resolved file path.
 * Handles both exact path and basename matching.
 */
static error_t *discover_file(
    git_repository *repo,
    const char *file_path,
    const char *profile_hint,
    char **out_profile,
    char **out_resolved_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(file_path);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_resolved_path);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;

    /* If profile specified, check only that profile */
    if (profile_hint) {
        bool exists = false;
        err = gitops_branch_exists(repo, profile_hint, &exists);
        if (err) {
            return err;
        }
        if (!exists) {
            return ERROR(ERR_NOT_FOUND, "Profile '%s' not found", profile_hint);
        }

        /* Load tree for this profile */
        size_t ref_name_size = strlen("refs/heads/") + strlen(profile_hint) + 1;
        char *ref_name = malloc(ref_name_size);
        if (!ref_name) {
            return ERROR(ERR_MEMORY, "Failed to allocate reference name");
        }
        snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_hint);

        git_tree *tree = NULL;
        err = gitops_load_tree(repo, ref_name, &tree);
        free(ref_name);

        if (err) {
            return error_wrap(err, "Failed to load tree for profile '%s'", profile_hint);
        }

        /* Try to find file by exact path */
        git_tree_entry *entry = NULL;
        err = gitops_find_file_in_tree(repo, tree, file_path, &entry);
        if (err) {
            git_tree_free(tree);
            return error_wrap(err, "File '%s' not found in profile '%s'",
                            file_path, profile_hint);
        }

        git_tree_entry_free(entry);
        git_tree_free(tree);

        *out_profile = strdup(profile_hint);
        *out_resolved_path = strdup(file_path);

        if (!*out_profile || !*out_resolved_path) {
            free(*out_profile);
            free(*out_resolved_path);
            return ERROR(ERR_MEMORY, "Failed to allocate output strings");
        }

        return NULL;
    }

    /* No profile specified - search across all configured profiles */
    err = config_load(NULL, &config);
    if (err) {
        return error_wrap(err, "Failed to load config");
    }

    err = profile_resolve(
        repo,
        NULL, 0,
        config->strict_mode,
        &profiles,
        NULL);

    if (err) {
        config_free(config);
        return error_wrap(err, "Failed to load profiles");
    }

    if (profiles->count == 0) {
        config_free(config);
        profile_list_free(profiles);
        return ERROR(ERR_NOT_FOUND, "No profiles found");
    }

    /* Try to find file: first by exact path, then by basename */
    const char *basename = get_basename(file_path);
    bool use_basename_search = (strcmp(basename, file_path) == 0);

    file_match_t *matches = NULL;
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
                        matches = realloc(matches, (match_count + 1) * sizeof(file_match_t));
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
                if (gitops_find_file_in_tree(repo, tree, file_path, &entry) == NULL) {
                    matches = realloc(matches, (match_count + 1) * sizeof(file_match_t));
                    if (matches) {
                        matches[match_count].profile_name = strdup(profile_name);
                        matches[match_count].file_path = strdup(file_path);
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

    if (match_count == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in any profile", file_path);
    }

    if (match_count == 1) {
        /* Found in one profile - use it */
        *out_profile = matches[0].profile_name;
        *out_resolved_path = matches[0].file_path;
        free(matches);
        return NULL;
    }

    /* Found in multiple profiles - show options and error */
    fprintf(stderr, "File '%s' found in multiple profiles:\n", file_path);
    for (size_t i = 0; i < match_count; i++) {
        fprintf(stderr, "  %s: %s\n", matches[i].profile_name, matches[i].file_path);
        free(matches[i].profile_name);
        free(matches[i].file_path);
    }
    free(matches);
    fprintf(stderr, "\nPlease specify --profile to disambiguate\n");

    return ERROR(ERR_INVALID_ARG, "Ambiguous file reference");
}

/**
 * Show diff preview between two blobs
 */
static error_t *show_diff_preview(
    git_repository *repo,
    const char *file_path,
    const git_oid *current_oid,
    const git_oid *target_oid,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(file_path);
    CHECK_NULL(current_oid);
    CHECK_NULL(target_oid);
    CHECK_NULL(out);

    /* Check if blobs are identical */
    if (git_oid_equal(current_oid, target_oid)) {
        output_info(out, "File is already at target state (no changes)");
        return NULL;
    }

    /* Lookup blobs */
    git_blob *current_blob = NULL;
    git_blob *target_blob = NULL;
    int ret = git_blob_lookup(&current_blob, repo, current_oid);
    if (ret < 0) {
        return error_from_git(ret);
    }

    ret = git_blob_lookup(&target_blob, repo, target_oid);
    if (ret < 0) {
        git_blob_free(current_blob);
        return error_from_git(ret);
    }

    /* Create patch between blobs */
    git_patch *patch = NULL;
    ret = git_patch_from_blobs(
        &patch,
        current_blob, file_path,  /* old */
        target_blob, file_path,   /* new */
        NULL  /* options */
    );

    git_blob_free(current_blob);
    git_blob_free(target_blob);

    if (ret < 0) {
        return error_from_git(ret);
    }

    /* Get patch stats */
    size_t additions = 0;
    size_t deletions = 0;
    size_t num_hunks = git_patch_num_hunks(patch);

    for (size_t i = 0; i < num_hunks; i++) {
        const git_diff_hunk *hunk;
        ret = git_patch_get_hunk(&hunk, NULL, patch, i);
        if (ret == 0) {
            additions += hunk->new_lines;
            deletions += hunk->old_lines;
        }
    }

    /* Show header */
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "\n%s--- Changes preview ---%s\n",
                output_color_code(out, OUTPUT_COLOR_BOLD),
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "\n--- Changes preview ---\n");
    }

    /* Show stats */
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "File: %s%s%s\n",
                output_color_code(out, OUTPUT_COLOR_CYAN),
                file_path,
                output_color_code(out, OUTPUT_COLOR_RESET));
        output_printf(out, OUTPUT_NORMAL, "Changes: %s+%zu%s / %s-%zu%s\n",
                output_color_code(out, OUTPUT_COLOR_GREEN), additions,
                output_color_code(out, OUTPUT_COLOR_RESET),
                output_color_code(out, OUTPUT_COLOR_RED), deletions,
                output_color_code(out, OUTPUT_COLOR_RESET));
    } else {
        output_printf(out, OUTPUT_NORMAL, "File: %s\n", file_path);
        output_printf(out, OUTPUT_NORMAL, "Changes: +%zu / -%zu\n", additions, deletions);
    }
    output_newline(out);

    /* Print patch */
    git_buf buf = {0};
    ret = git_patch_to_buf(&buf, patch);
    if (ret == 0 && buf.ptr) {
        /* Colorize diff output if colors enabled */
        if (output_colors_enabled(out)) {
            char *line = buf.ptr;
            char *next_line;

            while (line && *line) {
                next_line = strchr(line, '\n');
                size_t line_len = next_line ? (size_t)(next_line - line) : strlen(line);

                /* Determine color based on first character */
                const char *color = NULL;
                if (line[0] == '+' && line_len > 0 && line[1] != '+') {
                    color = output_color_code(out, OUTPUT_COLOR_GREEN);
                } else if (line[0] == '-' && line_len > 0 && line[1] != '-') {
                    color = output_color_code(out, OUTPUT_COLOR_RED);
                } else if (line[0] == '@' && line[1] == '@') {
                    color = output_color_code(out, OUTPUT_COLOR_CYAN);
                }

                if (color) {
                    output_printf(out, OUTPUT_NORMAL, "%s%.*s%s\n",
                            color, (int)line_len, line,
                            output_color_code(out, OUTPUT_COLOR_RESET));
                } else {
                    output_printf(out, OUTPUT_NORMAL, "%.*s\n", (int)line_len, line);
                }

                line = next_line ? next_line + 1 : NULL;
            }
        } else {
            output_printf(out, OUTPUT_NORMAL, "%s", buf.ptr);
        }
    }

    git_buf_dispose(&buf);
    git_patch_free(patch);

    return NULL;
}

/**
 * Check for uncommitted changes in profile branch
 *
 * Uses git_status_file to check for BOTH staged and unstaged modifications.
 * This is more robust than manually comparing index to HEAD.
 */
static error_t *check_working_tree_status(
    git_repository *repo,
    const char *profile_name,
    const char *file_path,
    bool *has_changes
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(file_path);
    CHECK_NULL(has_changes);

    /* Use git_status_file to get the full status of the file */
    unsigned int status_flags = 0;
    int ret = git_status_file(&status_flags, repo, file_path);

    if (ret < 0) {
        /* GIT_ENOTFOUND means the file is not tracked, which is not an error here */
        if (ret == GIT_ENOTFOUND) {
            *has_changes = false;
            return NULL;
        }
        return error_from_git(ret);
    }

    /* Check for any modification in the index or working directory */
    *has_changes = (status_flags != GIT_STATUS_CURRENT);

    return NULL;
}

/**
 * Revert file in profile branch to target commit
 *
 * This creates a new commit with the file reverted to its target state.
 */
static error_t *revert_file_in_branch(
    git_repository *repo,
    const dotta_config_t *config,
    const char *profile_name,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *commit_message,
    bool create_commit
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(file_path);
    CHECK_NULL(target_commit_oid);

    error_t *err = NULL;
    git_commit *target_commit = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *target_entry = NULL;
    git_reference *branch_ref = NULL;
    git_commit *head_commit = NULL;
    git_tree *head_tree = NULL;
    git_index *index = NULL;
    git_blob *target_blob = NULL;
    git_tree *new_tree = NULL;
    git_signature *sig = NULL;
    char *msg = NULL;
    git_oid target_blob_oid_copy;
    git_filemode_t target_mode = 0;

    /* Get target commit's tree */
    int ret = git_commit_lookup(&target_commit, repo, target_commit_oid);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_commit_tree(&target_tree, target_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Find file in target tree */
    ret = git_tree_entry_bypath(&target_entry, target_tree, file_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            err = ERROR(ERR_NOT_FOUND,
                       "File '%s' not found at target commit", file_path);
        } else {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    /* Get the target blob OID and copy it before freeing the entry */
    git_oid_cpy(&target_blob_oid_copy, git_tree_entry_id(target_entry));
    target_mode = git_tree_entry_filemode(target_entry);

    /* Load current HEAD for the profile */
    size_t ref_name_size = strlen("refs/heads/") + strlen(profile_name) + 1;
    char *ref_name = malloc(ref_name_size);
    if (!ref_name) {
        err = ERROR(ERR_MEMORY, "Failed to allocate reference name");
        goto cleanup;
    }
    snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_name);

    ret = git_reference_lookup(&branch_ref, repo, ref_name);
    free(ref_name);

    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    const git_oid *head_oid = git_reference_target(branch_ref);
    if (!head_oid) {
        err = ERROR(ERR_GIT, "Branch '%s' has no target", profile_name);
        goto cleanup;
    }

    ret = git_commit_lookup(&head_commit, repo, head_oid);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_commit_tree(&head_tree, head_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Use index approach to handle nested paths correctly */
    ret = git_repository_index(&index, repo);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Read HEAD tree into index */
    ret = git_index_read_tree(index, head_tree);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Update the file entry in index */
    /* Lookup blob to get content - we'll recreate it via git_index_add_frombuffer */
    ret = git_blob_lookup(&target_blob, repo, &target_blob_oid_copy);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    const void *blob_content = git_blob_rawcontent(target_blob);
    git_object_size_t blob_size = git_blob_rawsize(target_blob);

    /* Remove old entry */
    git_index_remove_bypath(index, file_path);

    /* Create new entry using git_index_add_frombuffer which handles nested paths */
    git_index_entry source_entry;
    memset(&source_entry, 0, sizeof(source_entry));
    source_entry.mode = target_mode;
    source_entry.path = file_path;

    ret = git_index_add_from_buffer(index, &source_entry, blob_content, blob_size);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* If not creating commit, write index and return */
    if (!create_commit) {
        ret = git_index_write(index);
        if (ret < 0) {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    /* Write index to tree - use _to variant to specify repository */
    git_oid new_tree_oid;
    ret = git_index_write_tree_to(&new_tree_oid, index, repo);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Create commit with reverted file */
    ret = git_tree_lookup(&new_tree, repo, &new_tree_oid);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Get default signature */
    ret = git_signature_default(&sig, repo);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Create commit message if not provided */
    if (commit_message && commit_message[0]) {
        msg = strdup(commit_message);
    } else {
        /* Generate message using template system */
        char oid_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), target_commit_oid);

        /* Build context for commit message */
        const char *files[] = {file_path};
        commit_message_context_t ctx = {
            .action = COMMIT_ACTION_REVERT,
            .profile = profile_name,
            .files = files,
            .file_count = 1,
            .custom_msg = NULL,
            .target_commit = oid_str
        };

        msg = build_commit_message(config, &ctx);
    }

    if (!msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    /* Create commit */
    git_oid new_commit_oid;
    const git_commit *parents[] = {head_commit};
    ret = git_commit_create(
        &new_commit_oid,
        repo,
        git_reference_name(branch_ref),  /* Update the branch */
        sig,     /* author */
        sig,     /* committer */
        NULL,    /* encoding (NULL = UTF-8) */
        msg,     /* message */
        new_tree,
        1,       /* parent count */
        parents
    );

    if (ret < 0) {
        err = error_from_git(ret);
    }

cleanup:
    if (target_commit) git_commit_free(target_commit);
    if (target_tree) git_tree_free(target_tree);
    if (target_entry) git_tree_entry_free(target_entry);
    if (branch_ref) git_reference_free(branch_ref);
    if (head_commit) git_commit_free(head_commit);
    if (head_tree) git_tree_free(head_tree);
    if (index) git_index_free(index);
    if (target_blob) git_blob_free(target_blob);
    if (new_tree) git_tree_free(new_tree);
    if (sig) git_signature_free(sig);
    if (msg) free(msg);

    return err;
}

/**
 * Deploy a single reverted file to filesystem
 *
 * Creates necessary structures and calls deploy_file from deploy.c
 */
static error_t *deploy_reverted_file(
    git_repository *repo,
    const char *profile_name,
    const char *storage_path,
    bool force,
    bool verbose,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    error_t *err = NULL;
    profile_t *profile = NULL;
    char *filesystem_path = NULL;
    git_tree_entry *entry = NULL;
    state_t *state = NULL;
    state_file_entry_t *state_entry = NULL;
    metadata_t *metadata = NULL;

    /* Load the profile */
    err = profile_load(repo, profile_name, &profile);
    if (err) {
        err = error_wrap(err, "Failed to load profile '%s'", profile_name);
        goto cleanup;
    }

    /* Resolve filesystem path from storage path */
    err = path_from_storage(storage_path, &filesystem_path);
    if (err) {
        err = error_wrap(err, "Failed to resolve filesystem path for '%s'", storage_path);
        goto cleanup;
    }

    /* Get tree entry from profile */
    if (!profile->tree) {
        /* Load tree if not loaded */
        size_t ref_name_size = strlen("refs/heads/") + strlen(profile_name) + 1;
        char *ref_name = malloc(ref_name_size);
        if (!ref_name) {
            err = ERROR(ERR_MEMORY, "Failed to allocate reference name");
            goto cleanup;
        }
        snprintf(ref_name, ref_name_size, "refs/heads/%s", profile_name);

        err = gitops_load_tree(repo, ref_name, &profile->tree);
        free(ref_name);

        if (err) {
            err = error_wrap(err, "Failed to load tree for profile '%s'", profile_name);
            goto cleanup;
        }
    }

    /* Find file entry in tree */
    int ret = git_tree_entry_bypath(&entry, profile->tree, storage_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            err = ERROR(ERR_NOT_FOUND,
                       "File '%s' not found in profile '%s' after revert",
                       storage_path, profile_name);
        } else {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    /* Check for conflicts (file modified on disk) */
    if (!force) {
        compare_result_t cmp_result;
        err = compare_tree_entry_to_disk(repo, entry, filesystem_path, &cmp_result);
        if (err) {
            err = error_wrap(err, "Failed to compare file with disk");
            goto cleanup;
        }

        if (cmp_result == CMP_DIFFERENT || cmp_result == CMP_MODE_DIFF) {
            err = ERROR(ERR_CONFLICT,
                       "File '%s' has been modified on disk\n"
                       "Use --force to overwrite local changes",
                       filesystem_path);
            goto cleanup;
        }
    }

    /* Create file entry for deployment */
    file_entry_t file_entry = {
        .storage_path = (char *)storage_path,
        .filesystem_path = filesystem_path,
        .entry = entry,
        .source_profile = profile
    };

    /* Load metadata from the profile branch (commit being reverted to) */
    error_t *meta_err = metadata_load_from_branch(repo, profile_name, &metadata);
    if (meta_err) {
        if (meta_err->code == ERR_NOT_FOUND) {
            /* No metadata in this profile - not an error, just use defaults */
            if (verbose) {
                output_print(out, OUTPUT_VERBOSE,
                            "  No metadata in profile '%s', using defaults\n", profile_name);
            }
            error_free(meta_err);
            metadata = NULL;
        } else {
            /* Real error - propagate */
            err = error_wrap(meta_err, "Failed to load metadata from profile '%s'", profile_name);
            goto cleanup;
        }
    }

    /* Deploy the file */
    deploy_options_t deploy_opts = {
        .force = force,
        .dry_run = false,
        .verbose = verbose
    };

    err = deploy_file(repo, &file_entry, metadata, &deploy_opts);
    if (err) {
        err = error_wrap(err, "Failed to deploy reverted file");
        goto cleanup;
    }

    /* Update state after successful deployment (with locking for write transaction) */
    err = state_load_for_update(repo, &state);
    if (err) {
        /* If state doesn't exist, create it */
        err = state_create_empty(&state);
        if (err) {
            err = error_wrap(err, "Failed to create state");
            goto cleanup;
        }
    }

    /* Get file metadata from tree entry */
    const git_oid *blob_oid = git_tree_entry_id(entry);
    git_filemode_t mode = git_tree_entry_filemode(entry);

    /* Determine file type */
    state_file_type_t file_type = STATE_FILE_REGULAR;
    if (mode == GIT_FILEMODE_LINK) {
        file_type = STATE_FILE_SYMLINK;
    } else if (mode == GIT_FILEMODE_BLOB_EXECUTABLE) {
        file_type = STATE_FILE_EXECUTABLE;
    }

    /* Compute hash from blob OID */
    char hash_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(hash_str, sizeof(hash_str), blob_oid);

    /* Create state entry */
    err = state_create_entry(
        storage_path,
        filesystem_path,
        profile_name,
        file_type,
        hash_str,
        NULL,  /* mode */
        &state_entry
    );
    if (err) {
        err = error_wrap(err, "Failed to create state entry");
        goto cleanup;
    }

    /* Remove old entry if exists, then add new one */
    state_remove_file(state, filesystem_path);  /* Ignore errors - file might not exist */

    err = state_add_file(state, state_entry);
    if (err) {
        err = error_wrap(err, "Failed to add file to state");
        goto cleanup;
    }

    /* Save updated state */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save state");
        goto cleanup;
    }

    /* Print success message before cleanup */
    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "%s✓%s Deployed %s\n",
                output_color_code(out, OUTPUT_COLOR_GREEN),
                output_color_code(out, OUTPUT_COLOR_RESET),
                filesystem_path);
    } else {
        output_printf(out, OUTPUT_NORMAL, "✓ Deployed %s\n", filesystem_path);
    }

cleanup:
    if (metadata) metadata_free(metadata);
    if (state_entry) state_free_entry(state_entry);
    if (state) state_free(state);
    if (entry) git_tree_entry_free(entry);
    if (filesystem_path) free(filesystem_path);
    if (profile) profile_free(profile);

    return err;
}

/**
 * Revert command implementation
 */
error_t *cmd_revert(git_repository *repo, const cmd_revert_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(opts->commit);

    error_t *err = NULL;
    dotta_config_t *config = NULL;
    char *profile_name = NULL;
    char *resolved_path = NULL;
    git_oid current_oid = {{0}};
    git_oid target_oid = {{0}};
    git_commit *current_commit = NULL;
    git_commit *target_commit = NULL;
    git_tree *current_tree = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *current_entry = NULL;
    git_tree_entry *target_entry = NULL;
    output_ctx_t *out = NULL;
    bool user_aborted = false;

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        config = config_create_default();
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Step 1: Discover file in profiles */
    output_print(out, OUTPUT_VERBOSE, "Discovering file in profiles...\n");

    err = discover_file(repo, opts->file_path, opts->profile, &profile_name, &resolved_path);
    if (err) goto cleanup;

    output_print(out, OUTPUT_VERBOSE, "Found file in profile '%s': %s\n", profile_name, resolved_path);

    /* Step 2: Resolve target commit */
    output_print(out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n", opts->commit);

    err = gitops_resolve_commit_in_branch(repo, profile_name, opts->commit, &target_oid, &target_commit);
    if (err) goto cleanup;

    /* Step 3: Get current HEAD commit for comparison */
    err = gitops_resolve_commit_in_branch(repo, profile_name, "HEAD", &current_oid, &current_commit);
    if (err) goto cleanup;

    /* Step 4: Get file entries from both commits */
    int ret = git_commit_tree(&current_tree, current_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_commit_tree(&target_tree, target_commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_tree_entry_bypath(&current_entry, current_tree, resolved_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            err = ERROR(ERR_NOT_FOUND, "File '%s' not found in current HEAD", resolved_path);
        } else {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    ret = git_tree_entry_bypath(&target_entry, target_tree, resolved_path);
    if (ret < 0) {
        if (ret == GIT_ENOTFOUND) {
            err = ERROR(ERR_NOT_FOUND, "File '%s' not found at target commit", resolved_path);
        } else {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    const git_oid *current_blob_oid = git_tree_entry_id(current_entry);
    const git_oid *target_blob_oid = git_tree_entry_id(target_entry);

    /* Step 5: Check if file is already at target state */
    if (git_oid_equal(current_blob_oid, target_blob_oid)) {
        fprintf(stderr, "File '%s' is already at target state (no changes)\n", opts->file_path);
        goto cleanup;  /* Not an error, just nothing to do */
    }

    /* Step 6: Check for uncommitted changes (unless --force) */
    if (!opts->force) {
        bool has_changes = false;
        err = check_working_tree_status(repo, profile_name, resolved_path, &has_changes);
        if (err) {
            err = error_wrap(err, "Failed to check working tree status");
            goto cleanup;
        }

        if (has_changes) {
            err = ERROR(ERR_CONFLICT,
                       "File '%s' has uncommitted changes in profile '%s'\n"
                       "Use --force to discard changes, or commit them first",
                       resolved_path, profile_name);
            goto cleanup;
        }
    }

    /* Step 7: Show preview */
    if (!opts->dry_run) {
        /* Show commit metadata */
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "\n%sRevert preview:%s\n",
                    output_color_code(out, OUTPUT_COLOR_BOLD),
                    output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_printf(out, OUTPUT_NORMAL, "\nRevert preview:\n");
        }

        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), &target_oid);

        const git_signature *author = git_commit_author(target_commit);
        time_t commit_time = (time_t)author->when.time;
        struct tm *tm_info = localtime(&commit_time);
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "  Profile: %s%s%s\n",
                    output_color_code(out, OUTPUT_COLOR_CYAN),
                    profile_name,
                    output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "  File: %s\n", resolved_path);
            output_printf(out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n", oid_str, time_buf);
        } else {
            output_printf(out, OUTPUT_NORMAL, "  Profile: %s\n", profile_name);
            output_printf(out, OUTPUT_NORMAL, "  File: %s\n", resolved_path);
            output_printf(out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n", oid_str, time_buf);
        }

        /* Show diff preview */
        err = show_diff_preview(repo, resolved_path, current_blob_oid, target_blob_oid, out);
        if (err) {
            err = error_wrap(err, "Failed to show diff preview");
            goto cleanup;
        }
    }

    /* Free tree entries and trees after preview (no longer needed) */
    git_tree_entry_free(target_entry);
    target_entry = NULL;
    git_tree_entry_free(current_entry);
    current_entry = NULL;
    git_tree_free(target_tree);
    target_tree = NULL;
    git_tree_free(current_tree);
    current_tree = NULL;

    /* Step 8: Prompt for confirmation (unless --force or --dry-run) */
    if (config->confirm_destructive && !opts->force && !opts->dry_run) {
        char prompt_msg[256];
        if (opts->apply) {
            snprintf(prompt_msg, sizeof(prompt_msg), "Revert and deploy file?");
        } else {
            snprintf(prompt_msg, sizeof(prompt_msg), "Revert file?");
        }

        if (!output_confirm(out, prompt_msg, false)) {
            fprintf(stderr, "Aborted.\n");
            user_aborted = true;
            goto cleanup;
        }
    }

    /* Free current_commit (no longer needed) */
    git_commit_free(current_commit);
    current_commit = NULL;

    /* Step 9: Perform revert (unless dry-run) */
    if (opts->dry_run) {
        output_info(out, "\nDry-run mode: No changes made");
        goto cleanup;
    }

    output_print(out, OUTPUT_VERBOSE, "\nReverting file...\n");

    err = revert_file_in_branch(
        repo,
        config,
        profile_name,
        resolved_path,
        &target_oid,
        opts->message,
        opts->commit_changes
    );
    if (err) {
        err = error_wrap(err, "Failed to revert file");
        goto cleanup;
    }

    if (output_colors_enabled(out)) {
        output_printf(out, OUTPUT_NORMAL, "%s✓%s Reverted %s in profile '%s'\n",
                output_color_code(out, OUTPUT_COLOR_GREEN),
                output_color_code(out, OUTPUT_COLOR_RESET),
                resolved_path, profile_name);
    } else {
        output_printf(out, OUTPUT_NORMAL, "✓ Reverted %s in profile '%s'\n", resolved_path, profile_name);
    }

    /* Step 10: Deploy if requested */
    if (opts->apply) {
        output_print(out, OUTPUT_VERBOSE, "\nDeploying reverted file...\n");

        err = deploy_reverted_file(repo, profile_name, resolved_path, opts->force, opts->verbose, out);
        if (err) {
            err = error_wrap(err, "Failed to deploy reverted file");
            goto cleanup;
        }
    } else if (!opts->commit_changes) {
        output_info(out, "\nRun 'dotta apply' to deploy changes to filesystem");
    }

cleanup:
    if (current_entry) git_tree_entry_free(current_entry);
    if (target_entry) git_tree_entry_free(target_entry);
    if (current_tree) git_tree_free(current_tree);
    if (target_tree) git_tree_free(target_tree);
    if (current_commit) git_commit_free(current_commit);
    if (target_commit) git_commit_free(target_commit);
    if (profile_name) free(profile_name);
    if (resolved_path) free(resolved_path);
    /* Add trailing newline for UX consistency */
    if (out) {
        output_newline(out);
    }

    if (out) output_free(out);
    if (config) config_free(config);

    /* Don't return error if user aborted */
    if (user_aborted) {
        return NULL;
    }

    return err;
}
