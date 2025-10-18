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
#include "core/profiles.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/output.h"

/**
 * Discover file in profiles
 *
 * Returns profile name and resolved storage path.
 * Accepts filesystem paths or storage paths.
 * Uses profile_build_file_index()
 *
 * Uses path_resolve_input() for unified path handling.
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
    char *storage_path = NULL;

    /* Resolve input path to storage format (flexible mode - file need not exist) */
    err = path_resolve_input(file_path, false, &storage_path);
    if (err) {
        return err;
    }

    /* Fast path: If profile specified, check only that profile */
    if (profile_hint) {
        profile_t *profile = NULL;
        err = profile_load(repo, profile_hint, &profile);
        if (err) {
            free(storage_path);
            return error_wrap(err, "Failed to load profile '%s'", profile_hint);
        }

        /* Load tree */
        err = profile_load_tree(repo, profile);
        if (err) {
            profile_free(profile);
            free(storage_path);
            return error_wrap(err, "Failed to load tree for profile '%s'", profile_hint);
        }

        /* Check if file exists in tree */
        git_tree_entry *entry = NULL;
        int git_err = git_tree_entry_bypath(&entry, profile->tree, storage_path);
        bool exists = (git_err == 0);

        if (entry) {
            git_tree_entry_free(entry);
        }
        profile_free(profile);

        if (!exists) {
            free(storage_path);
            return ERROR(ERR_NOT_FOUND,
                        "File '%s' not found in profile '%s'\n"
                        "Hint: Use 'dotta list --profile %s' to see tracked files",
                        storage_path, profile_hint, profile_hint);
        }

        *out_profile = strdup(profile_hint);
        *out_resolved_path = storage_path;

        if (!*out_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        return NULL;
    }

    /* Search across active profiles using optimized index */
    dotta_config_t *config = NULL;
    err = config_load(NULL, &config);
    if (err) {
        free(storage_path);
        return error_wrap(err, "Failed to load config");
    }

    profile_list_t *profiles = NULL;
    err = profile_resolve(repo, NULL, 0, config->strict_mode, &profiles, NULL);
    if (err) {
        config_free(config);
        free(storage_path);
        return error_wrap(err, "Failed to resolve profiles");
    }

    if (profiles->count == 0) {
        config_free(config);
        profile_list_free(profiles);
        free(storage_path);
        return ERROR(ERR_NOT_FOUND, "No active profiles found");
    }

    /* Build profile file index once - O(M×P) instead of O(M×GitOps) */
    hashmap_t *profile_index = NULL;
    err = profile_build_file_index(repo, NULL, &profile_index);
    if (err) {
        profile_list_free(profiles);
        config_free(config);
        free(storage_path);
        return error_wrap(err, "Failed to build profile index");
    }

    /* Lookup file in index - O(1) */
    string_array_t *matching_profiles = hashmap_get(profile_index, storage_path);

    if (!matching_profiles || string_array_size(matching_profiles) == 0) {
        /* Not found in any profile */
        hashmap_free(profile_index, (void (*)(void *))string_array_free);
        profile_list_free(profiles);
        config_free(config);
        free(storage_path);
        return ERROR(ERR_NOT_FOUND,
                    "File '%s' not found in any active profile\n"
                    "Hint: Use 'dotta list' to see tracked files",
                    storage_path);
    }

    if (string_array_size(matching_profiles) == 1) {
        /* Found in exactly one profile */
        const char *profile_name = string_array_get(matching_profiles, 0);
        *out_profile = strdup(profile_name);
        *out_resolved_path = storage_path;

        hashmap_free(profile_index, (void (*)(void *))string_array_free);
        profile_list_free(profiles);
        config_free(config);

        if (!*out_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        return NULL;
    }

    /* Found in multiple profiles - ambiguous */
    fprintf(stderr, "File '%s' found in multiple profiles:\n", storage_path);
    for (size_t i = 0; i < string_array_size(matching_profiles); i++) {
        fprintf(stderr, "  • %s\n", string_array_get(matching_profiles, i));
    }
    fprintf(stderr, "\nPlease specify --profile to disambiguate:\n");
    fprintf(stderr, "  dotta revert --profile <name> %s\n", storage_path);

    hashmap_free(profile_index, (void (*)(void *))string_array_free);
    profile_list_free(profiles);
    config_free(config);
    free(storage_path);

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
        if (!output_confirm(out, "Revert file?", false)) {
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

    /* Guide user to deploy changes */
    if (!opts->commit_changes) {
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

    if (out) output_free(out);
    if (config) config_free(config);

    /* Don't return error if user aborted */
    if (user_aborted) {
        return NULL;
    }

    return err;
}
