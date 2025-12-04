/**
 * ignore.c - Manage ignore patterns
 */

#include "ignore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/ignore.h"
#include "core/profiles.h"
#include "utils/config.h"
#include "utils/editor.h"
#include "utils/output.h"
#include "utils/string.h"

/**
 * Check if a pattern already exists in content
 */
static bool pattern_exists(const char *content, const char *pattern) {
    if (!content || !pattern) {
        return false;
    }

    /* Parse content line by line */
    const char *line_start = content;
    const char *line_end;

    while (*line_start) {
        /* Find end of line */
        line_end = strchr(line_start, '\n');
        if (!line_end) {
            line_end = line_start + strlen(line_start);
        }

        /* Extract line */
        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) {
            return false;
        }
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Trim whitespace */
        char *trimmed = line;
        while (*trimmed && (*trimmed == ' ' || *trimmed == '\t')) {
            trimmed++;
        }
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && (*end == ' ' || *end == '\t' || *end == '\r')) {
            *end = '\0';
            end--;
        }

        /* Compare with pattern (skip comments) */
        if (*trimmed != '#' && *trimmed != '\0' && strcmp(trimmed, pattern) == 0) {
            free(line);
            return true;
        }

        free(line);

        /* Move to next line */
        if (*line_end == '\n') {
            line_start = line_end + 1;
        } else {
            break;
        }
    }

    return false;
}

/**
 * Add patterns to .dottaignore content
 *
 * Returns new content with patterns appended.
 * Skips patterns that already exist.
 */
static error_t *add_patterns_to_content(
    const char *existing_content,
    char **patterns,
    size_t pattern_count,
    char **new_content,
    size_t *added_count
) {
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(added_count);

    *new_content = NULL;
    *added_count = 0;

    if (pattern_count == 0) {
        return NULL;
    }

    /* Calculate required buffer size */
    size_t existing_len = existing_content ? strlen(existing_content) : 0;
    size_t required_size = existing_len;

    for (size_t i = 0; i < pattern_count; i++) {
        /* Validate pattern */
        if (!patterns[i] || patterns[i][0] == '\0') {
            continue;
        }

        /* Trim whitespace from pattern */
        const char *p = patterns[i];
        while (*p && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (*p == '\0') {
            continue;
        }

        /* Skip if already exists */
        if (existing_content && pattern_exists(existing_content, p)) {
            continue;
        }

        required_size += strlen(p) + 1;  /* +1 for newline */
    }

    /* Allocate buffer */
    char *result = malloc(required_size + 1);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }

    /* Copy existing content */
    if (existing_content && existing_len > 0) {
        memcpy(result, existing_content, existing_len);
        result[existing_len] = '\0';

        /* Ensure there's a trailing newline before adding patterns */
        if (existing_len > 0 && existing_content[existing_len - 1] != '\n') {
            strcat(result, "\n");
        }
    } else {
        result[0] = '\0';
    }

    /* Append new patterns */
    for (size_t i = 0; i < pattern_count; i++) {
        /* Validate and trim pattern */
        if (!patterns[i] || patterns[i][0] == '\0') {
            continue;
        }

        const char *p = patterns[i];
        while (*p && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (*p == '\0') {
            continue;
        }

        /* Skip if already exists */
        if (existing_content && pattern_exists(existing_content, p)) {
            continue;
        }

        /* Append pattern */
        strcat(result, p);
        strcat(result, "\n");
        (*added_count)++;
    }

    *new_content = result;
    return NULL;
}

/**
 * Remove patterns from .dottaignore content
 *
 * Returns new content with patterns removed.
 * Warns if pattern not found.
 */
static error_t *remove_patterns_from_content(
    const char *existing_content,
    char **patterns,
    size_t pattern_count,
    char **new_content,
    size_t *removed_count,
    size_t *not_found_count
) {
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(removed_count);
    CHECK_NULL(not_found_count);

    *new_content = NULL;
    *removed_count = 0;
    *not_found_count = 0;

    if (!existing_content || pattern_count == 0) {
        if (existing_content) {
            *new_content = strdup(existing_content);
            if (!*new_content) {
                return ERROR(ERR_MEMORY, "Failed to duplicate content");
            }
        }
        *not_found_count = pattern_count;
        return NULL;
    }

    /* Create buffer for new content (same size or smaller) */
    size_t existing_len = strlen(existing_content);
    char *result = malloc(existing_len + 1);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }
    result[0] = '\0';

    /* Track which patterns were found */
    bool *pattern_found = calloc(pattern_count, sizeof(bool));
    if (!pattern_found) {
        free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate pattern tracking");
    }

    /* Parse content line by line */
    const char *line_start = existing_content;
    const char *line_end;

    while (*line_start) {
        /* Find end of line */
        line_end = strchr(line_start, '\n');
        bool has_newline = (line_end != NULL);
        if (!line_end) {
            line_end = line_start + strlen(line_start);
        }

        /* Extract line */
        size_t line_len = (size_t)(line_end - line_start);
        char *line = malloc(line_len + 1);
        if (!line) {
            free(result);
            free(pattern_found);
            return ERROR(ERR_MEMORY, "Failed to allocate line buffer");
        }
        memcpy(line, line_start, line_len);
        line[line_len] = '\0';

        /* Trim whitespace for comparison */
        char *trimmed = line;
        while (*trimmed && (*trimmed == ' ' || *trimmed == '\t')) {
            trimmed++;
        }
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && (*end == ' ' || *end == '\t' || *end == '\r')) {
            *end = '\0';
            end--;
        }

        /* Check if this line matches any pattern to remove */
        bool should_remove = false;
        for (size_t i = 0; i < pattern_count; i++) {
            if (!patterns[i]) {
                continue;
            }

            /* Trim pattern */
            const char *p = patterns[i];
            while (*p && (*p == ' ' || *p == '\t')) {
                p++;
            }

            /* Skip comments and empty lines */
            if (*trimmed != '#' && *trimmed != '\0' && strcmp(trimmed, p) == 0) {
                should_remove = true;
                pattern_found[i] = true;
                break;
            }
        }

        /* Keep line if not removing */
        if (!should_remove) {
            strcat(result, line);
            if (has_newline) {
                strcat(result, "\n");
            }
        }

        free(line);

        /* Move to next line */
        if (has_newline) {
            line_start = line_end + 1;
        } else {
            break;
        }
    }

    /* Count removed and not found */
    for (size_t i = 0; i < pattern_count; i++) {
        if (pattern_found[i]) {
            (*removed_count)++;
        } else {
            (*not_found_count)++;
        }
    }

    free(pattern_found);
    *new_content = result;
    return NULL;
}

/**
 * Edit baseline .dottaignore (from dotta-worktree branch)
 */
static error_t *edit_baseline_dottaignore(
    git_repository *repo,
    const dotta_config_t *config,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    (void)config;  /* Reserved for future use */

    /* Check if dotta-worktree branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        return ERROR(ERR_INTERNAL,
                    "dotta-worktree branch does not exist. Run 'dotta init' first.");
    }

    /* Create temporary file */
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) {
        tmpdir = "/tmp";
    }

    char *tmpfile = str_format("%s/dotta-ignore-XXXXXX", tmpdir);
    if (!tmpfile) {
        return ERROR(ERR_MEMORY, "Failed to allocate temporary file path");
    }

    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        return ERROR(ERR_FS, "Failed to create temporary file");
    }

    /* Load existing .dottaignore content */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, "refs/heads/dotta-worktree", &tree);
    if (err) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        return error_wrap(err, "Failed to load dotta-worktree tree");
    }

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (entry) {
        /* Load existing content */
        const git_oid *oid = git_tree_entry_id(entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, repo, oid);
        if (git_err >= 0) {
            const void *content = git_blob_rawcontent(blob);
            size_t size = git_blob_rawsize(blob);
            if (write(fd, content, size) < 0) {
                git_blob_free(blob);
                git_tree_free(tree);
                close(fd);
                unlink(tmpfile);
                free(tmpfile);
                return ERROR(ERR_FS, "Failed to write to temporary file");
            }
            git_blob_free(blob);
        }
    } else {
        /* No existing .dottaignore, create with defaults */
        const char *default_content = ignore_default_dottaignore_content();
        if (write(fd, default_content, strlen(default_content)) < 0) {
            git_tree_free(tree);
            close(fd);
            unlink(tmpfile);
            free(tmpfile);
            return ERROR(ERR_FS, "Failed to write default content");
        }
    }

    git_tree_free(tree);
    close(fd);

    /* Open in editor - priority: DOTTA_EDITOR, VISUAL, EDITOR, vi */
    err = editor_launch_with_env(tmpfile, "vi");
    if (err) {
        unlink(tmpfile);
        free(tmpfile);
        return error_wrap(err, "Failed to edit baseline .dottaignore");
    }

    /* Read back the content */
    FILE *f = fopen(tmpfile, "r");
    if (!f) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_FS, "Failed to read temporary file");
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *new_content = malloc((size_t)fsize + 1);
    if (!new_content) {
        fclose(f);
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }

    size_t read_size = fread(new_content, 1, (size_t)fsize, f);
    new_content[read_size] = '\0';
    fclose(f);
    unlink(tmpfile);
    free(tmpfile);

    /* Update .dottaignore in dotta-worktree branch */
    err = gitops_update_file(
        repo,
        "dotta-worktree",
        ".dottaignore",
        new_content,
        read_size,
        "Update baseline .dottaignore",
        GIT_FILEMODE_BLOB,
        NULL  /* Don't need modification flag */
    );

    free(new_content);

    if (err) {
        return error_wrap(err, "Failed to update .dottaignore");
    }

    /*
     * Sync working directory if dotta-worktree is the current branch.
     * Use SAFE checkout to preserve any local modifications.
     */
    bool is_current = false;
    error_t *branch_err = gitops_is_current_branch(repo, "dotta-worktree", &is_current);
    if (!branch_err && is_current) {
        error_t *sync_err = gitops_sync_worktree(repo, GIT_CHECKOUT_SAFE);
        if (sync_err) {
            /*
             * Primary operation (pattern update) succeeded.
             * Sync failed due to local modifications - warn but don't fail.
             */
            output_warning(out,
                "Patterns saved to Git, but working directory sync failed.\n"
                "  You may have local modifications to .dottaignore.\n"
                "  To sync:  dotta git checkout .dottaignore\n"
                "  To diff:  dotta git diff .dottaignore");
            error_free(sync_err);
        }
    }
    if (branch_err) {
        error_free(branch_err);
    }

    output_success(out, "Updated baseline .dottaignore in dotta-worktree branch");
    return NULL;
}

/**
 * Edit profile-specific .dottaignore
 */
static error_t *edit_profile_dottaignore(
    git_repository *repo,
    const char *profile_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);

    /* Check if profile branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        return ERROR(ERR_INVALID_ARG,
                    "Profile '%s' does not exist", profile_name);
    }

    /* Create temporary file */
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) {
        tmpdir = "/tmp";
    }

    char *tmpfile = str_format("%s/dotta-ignore-XXXXXX", tmpdir);
    if (!tmpfile) {
        return ERROR(ERR_MEMORY, "Failed to allocate temporary file path");
    }

    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        return ERROR(ERR_FS, "Failed to create temporary file");
    }

    /* Build ref name */
    char ref_name[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(ref_name, sizeof(ref_name), "refs/heads/%s", profile_name);
    if (err) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        return error_wrap(err, "Invalid profile name '%s'", profile_name);
    }

    /* Load existing .dottaignore content from profile */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, ref_name, &tree);

    if (err) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        return error_wrap(err, "Failed to load profile tree");
    }

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (entry) {
        /* Load existing content */
        const git_oid *oid = git_tree_entry_id(entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, repo, oid);
        if (git_err >= 0) {
            const void *content = git_blob_rawcontent(blob);
            size_t size = git_blob_rawsize(blob);
            if (write(fd, content, size) < 0) {
                git_blob_free(blob);
                git_tree_free(tree);
                close(fd);
                unlink(tmpfile);
                free(tmpfile);
                return ERROR(ERR_FS, "Failed to write to temporary file");
            }
            git_blob_free(blob);
        }
    } else {
        /* No existing profile .dottaignore, start with empty file and helpful comments */
        const char *template = "# Profile-specific ignore patterns\n"
                              "#\n"
                              "# This profile INHERITS all patterns from baseline .dottaignore\n"
                              "# (stored in dotta-worktree branch)\n"
                              "#\n"
                              "# Use this file to:\n"
                              "#   - Add profile-specific patterns: *.dmg\n"
                              "#   - Negate baseline patterns:      !important.log\n"
                              "#\n"
                              "# Example: If baseline ignores *.log, add '!debug.log' below\n"
                              "# to keep debug.log in THIS profile only.\n"
                              "\n"
                              "# Add your profile-specific patterns below:\n"
                              "\n";
        if (write(fd, template, strlen(template)) < 0) {
            git_tree_free(tree);
            close(fd);
            unlink(tmpfile);
            free(tmpfile);
            return ERROR(ERR_FS, "Failed to write template");
        }
    }

    git_tree_free(tree);
    close(fd);

    /* Open in editor - priority: DOTTA_EDITOR, VISUAL, EDITOR, vi */
    err = editor_launch_with_env(tmpfile, "vi");
    if (err) {
        unlink(tmpfile);
        free(tmpfile);
        return error_wrap(err, "Failed to edit profile .dottaignore");
    }

    /* Read back the content */
    FILE *f = fopen(tmpfile, "r");
    if (!f) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_FS, "Failed to read temporary file");
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *new_content = malloc((size_t)fsize + 1);
    if (!new_content) {
        fclose(f);
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }

    size_t read_size = fread(new_content, 1, (size_t)fsize, f);
    new_content[read_size] = '\0';
    fclose(f);
    unlink(tmpfile);
    free(tmpfile);

    /* Update .dottaignore in profile branch */
    char *commit_msg = str_format("Update .dottaignore for profile '%s'", profile_name);
    if (!commit_msg) {
        free(new_content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    err = gitops_update_file(
        repo,
        profile_name,
        ".dottaignore",
        new_content,
        read_size,
        commit_msg,
        GIT_FILEMODE_BLOB,
        NULL  /* Don't need modification flag */
    );

    free(commit_msg);
    free(new_content);

    if (err) {
        return error_wrap(err, "Failed to update profile .dottaignore");
    }

    output_success(out, "Updated .dottaignore for profile '%s'", profile_name);
    return NULL;
}

/**
 * Modify baseline .dottaignore by adding or removing patterns
 */
static error_t *modify_baseline_dottaignore(
    git_repository *repo,
    char **add_patterns,
    size_t add_count,
    char **remove_patterns,
    size_t remove_count,
    output_ctx_t *out
) {
    CHECK_NULL(repo);

    /* Check if dotta-worktree branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        return ERROR(ERR_INTERNAL,
                    "dotta-worktree branch does not exist. Run 'dotta init' first.");
    }

    /* Load existing .dottaignore content */
    char *existing_content = NULL;
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, "refs/heads/dotta-worktree", &tree);
    if (err) {
        return error_wrap(err, "Failed to load dotta-worktree tree");
    }

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (entry) {
        const git_oid *oid = git_tree_entry_id(entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, repo, oid);
        if (git_err >= 0) {
            const void *content = git_blob_rawcontent(blob);
            size_t size = git_blob_rawsize(blob);
            if (size > 0) {
                existing_content = malloc(size + 1);
                if (!existing_content) {
                    git_blob_free(blob);
                    git_tree_free(tree);
                    return ERROR(ERR_MEMORY, "Failed to allocate content");
                }
                memcpy(existing_content, content, size);
                existing_content[size] = '\0';
            }
            git_blob_free(blob);
        }
    } else if (!add_patterns) {
        /* No existing .dottaignore and no patterns to add */
        git_tree_free(tree);
        output_info(out, "No .dottaignore file exists in baseline");
        return NULL;
    }

    git_tree_free(tree);

    /* If no existing content, use default for adds */
    if (!existing_content && add_count > 0) {
        existing_content = strdup(ignore_default_dottaignore_content());
        if (!existing_content) {
            return ERROR(ERR_MEMORY, "Failed to allocate default content");
        }
    }

    char *new_content = existing_content;
    size_t total_added = 0;
    size_t total_removed = 0;
    size_t total_not_found = 0;

    /* Process additions */
    if (add_count > 0) {
        size_t added = 0;
        char *content_with_adds = NULL;
        err = add_patterns_to_content(new_content, add_patterns, add_count, &content_with_adds, &added);
        if (err) {
            free(existing_content);
            return error_wrap(err, "Failed to add patterns");
        }

        if (content_with_adds) {
            if (new_content != existing_content) {
                free(new_content);
            }
            new_content = content_with_adds;
            total_added = added;
        }
    }

    /* Process removals */
    if (remove_count > 0) {
        size_t removed = 0;
        size_t not_found = 0;
        char *content_with_removals = NULL;
        err = remove_patterns_from_content(new_content, remove_patterns, remove_count,
                                          &content_with_removals, &removed, &not_found);
        if (err) {
            if (new_content != existing_content) {
                free(new_content);
            }
            free(existing_content);
            return error_wrap(err, "Failed to remove patterns");
        }

        if (content_with_removals) {
            if (new_content != existing_content) {
                free(new_content);
            }
            new_content = content_with_removals;
            total_removed = removed;
            total_not_found = not_found;
        }
    }

    /* Check if any changes were made */
    if (total_added == 0 && total_removed == 0) {
        if (new_content != existing_content) {
            free(new_content);
        }
        free(existing_content);

        if (add_count > 0 && remove_count > 0) {
            output_info(out, "No changes: all patterns already exist or patterns not found");
        } else if (add_count > 0) {
            output_info(out, "No changes: all patterns already exist");
        } else {
            output_info(out, "No changes: patterns not found");
        }
        return NULL;
    }

    /* Create commit message */
    char *commit_msg = NULL;
    if (total_added > 0 && total_removed > 0) {
        commit_msg = str_format("Update baseline .dottaignore (added %zu, removed %zu patterns)",
                               total_added, total_removed);
    } else if (total_added > 0) {
        commit_msg = str_format("Add %zu pattern%s to baseline .dottaignore",
                               total_added, total_added == 1 ? "" : "s");
    } else {
        commit_msg = str_format("Remove %zu pattern%s from baseline .dottaignore",
                               total_removed, total_removed == 1 ? "" : "s");
    }

    if (!commit_msg) {
        if (new_content != existing_content) {
            free(new_content);
        }
        free(existing_content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    /* Update .dottaignore in dotta-worktree branch */
    err = gitops_update_file(
        repo,
        "dotta-worktree",
        ".dottaignore",
        new_content,
        strlen(new_content),
        commit_msg,
        GIT_FILEMODE_BLOB,
        NULL  /* Don't need modification flag */
    );

    free(commit_msg);
    if (new_content != existing_content) {
        free(new_content);
    }
    free(existing_content);

    if (err) {
        return error_wrap(err, "Failed to update .dottaignore");
    }

    /*
     * Sync working directory if dotta-worktree is the current branch.
     * Use SAFE checkout to preserve any local modifications.
     */
    bool is_current = false;
    error_t *branch_err = gitops_is_current_branch(repo, "dotta-worktree", &is_current);
    if (!branch_err && is_current) {
        error_t *sync_err = gitops_sync_worktree(repo, GIT_CHECKOUT_SAFE);
        if (sync_err) {
            /*
             * Primary operation (pattern update) succeeded.
             * Sync failed due to local modifications - warn but don't fail.
             */
            output_warning(out,
                "Patterns saved to Git, but working directory sync failed.\n"
                "  You may have local modifications to .dottaignore.\n"
                "  To sync:  dotta git checkout .dottaignore\n"
                "  To diff:  dotta git diff .dottaignore");
            error_free(sync_err);
        }
    }
    if (branch_err) {
        error_free(branch_err);
    }

    /* Report results */
    if (total_added > 0) {
        output_success(out, "Added %zu pattern%s to baseline .dottaignore",
                      total_added, total_added == 1 ? "" : "s");
    }
    if (total_removed > 0) {
        output_success(out, "Removed %zu pattern%s from baseline .dottaignore",
                      total_removed, total_removed == 1 ? "" : "s");
    }
    if (total_not_found > 0) {
        output_info(out, "Warning: %zu pattern%s not found (already removed or never added)",
                   total_not_found, total_not_found == 1 ? "" : "s");
    }

    return NULL;
}

/**
 * Modify profile-specific .dottaignore by adding or removing patterns
 */
static error_t *modify_profile_dottaignore(
    git_repository *repo,
    const char *profile_name,
    char **add_patterns,
    size_t add_count,
    char **remove_patterns,
    size_t remove_count,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);

    /* Check if profile branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        return ERROR(ERR_INVALID_ARG,
                    "Profile '%s' does not exist", profile_name);
    }

    /* Build ref name */
    char ref_name[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(ref_name, sizeof(ref_name), "refs/heads/%s", profile_name);
    if (err) {
        return error_wrap(err, "Invalid profile name '%s'", profile_name);
    }

    /* Load existing .dottaignore content from profile */
    char *existing_content = NULL;
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, ref_name, &tree);

    if (err) {
        return error_wrap(err, "Failed to load profile tree");
    }

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (entry) {
        const git_oid *oid = git_tree_entry_id(entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, repo, oid);
        if (git_err >= 0) {
            const void *content = git_blob_rawcontent(blob);
            size_t size = git_blob_rawsize(blob);
            if (size > 0) {
                existing_content = malloc(size + 1);
                if (!existing_content) {
                    git_blob_free(blob);
                    git_tree_free(tree);
                    return ERROR(ERR_MEMORY, "Failed to allocate content");
                }
                memcpy(existing_content, content, size);
                existing_content[size] = '\0';
            }
            git_blob_free(blob);
        }
    } else if (!add_patterns) {
        /* No existing .dottaignore and no patterns to add */
        git_tree_free(tree);
        output_info(out, "No .dottaignore file exists in profile '%s'", profile_name);
        return NULL;
    }

    git_tree_free(tree);

    /* If no existing content, use template for adds */
    if (!existing_content && add_count > 0) {
        existing_content = strdup(ignore_profile_dottaignore_template());
        if (!existing_content) {
            return ERROR(ERR_MEMORY, "Failed to allocate template content");
        }
    }

    char *new_content = existing_content;
    size_t total_added = 0;
    size_t total_removed = 0;
    size_t total_not_found = 0;

    /* Process additions */
    if (add_count > 0) {
        size_t added = 0;
        char *content_with_adds = NULL;
        err = add_patterns_to_content(new_content, add_patterns, add_count, &content_with_adds, &added);
        if (err) {
            free(existing_content);
            return error_wrap(err, "Failed to add patterns");
        }

        if (content_with_adds) {
            if (new_content != existing_content) {
                free(new_content);
            }
            new_content = content_with_adds;
            total_added = added;
        }
    }

    /* Process removals */
    if (remove_count > 0) {
        size_t removed = 0;
        size_t not_found = 0;
        char *content_with_removals = NULL;
        err = remove_patterns_from_content(new_content, remove_patterns, remove_count,
                                          &content_with_removals, &removed, &not_found);
        if (err) {
            if (new_content != existing_content) {
                free(new_content);
            }
            free(existing_content);
            return error_wrap(err, "Failed to remove patterns");
        }

        if (content_with_removals) {
            if (new_content != existing_content) {
                free(new_content);
            }
            new_content = content_with_removals;
            total_removed = removed;
            total_not_found = not_found;
        }
    }

    /* Check if any changes were made */
    if (total_added == 0 && total_removed == 0) {
        if (new_content != existing_content) {
            free(new_content);
        }
        free(existing_content);

        if (add_count > 0 && remove_count > 0) {
            output_info(out, "No changes: all patterns already exist or patterns not found");
        } else if (add_count > 0) {
            output_info(out, "No changes: all patterns already exist");
        } else {
            output_info(out, "No changes: patterns not found");
        }
        return NULL;
    }

    /* Create commit message */
    char *commit_msg = NULL;
    if (total_added > 0 && total_removed > 0) {
        commit_msg = str_format("Update .dottaignore for profile '%s' (added %zu, removed %zu patterns)",
                               profile_name, total_added, total_removed);
    } else if (total_added > 0) {
        commit_msg = str_format("Add %zu pattern%s to .dottaignore for profile '%s'",
                               total_added, total_added == 1 ? "" : "s", profile_name);
    } else {
        commit_msg = str_format("Remove %zu pattern%s from .dottaignore for profile '%s'",
                               total_removed, total_removed == 1 ? "" : "s", profile_name);
    }

    if (!commit_msg) {
        if (new_content != existing_content) {
            free(new_content);
        }
        free(existing_content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    /* Update .dottaignore in profile branch */
    err = gitops_update_file(
        repo,
        profile_name,
        ".dottaignore",
        new_content,
        strlen(new_content),
        commit_msg,
        GIT_FILEMODE_BLOB,
        NULL  /* Don't need modification flag */
    );

    free(commit_msg);
    if (new_content != existing_content) {
        free(new_content);
    }
    free(existing_content);

    if (err) {
        return error_wrap(err, "Failed to update profile .dottaignore");
    }

    /* Report results */
    if (total_added > 0) {
        output_success(out, "Added %zu pattern%s to profile '%s' .dottaignore",
                      total_added, total_added == 1 ? "" : "s", profile_name);
    }
    if (total_removed > 0) {
        output_success(out, "Removed %zu pattern%s from profile '%s' .dottaignore",
                      total_removed, total_removed == 1 ? "" : "s", profile_name);
    }
    if (total_not_found > 0) {
        output_info(out, "Warning: %zu pattern%s not found (already removed or never added)",
                   total_not_found, total_not_found == 1 ? "" : "s");
    }

    return NULL;
}

/**
 * Test if path is ignored across profiles
 */
static error_t *test_path_ignore(
    git_repository *repo,
    const dotta_config_t *config,
    const char *test_path,
    const char *specific_profile,
    bool verbose,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(test_path);
    CHECK_NULL(out);

    /* Check if path exists and determine if it's a directory */
    bool path_exists = fs_exists(test_path);
    bool is_directory = path_exists && fs_is_directory(test_path);

    if (!path_exists && verbose) {
        output_info(out, "Path does not exist: %s", test_path);
    }

    /* If specific profile requested, test only that one */
    if (specific_profile) {
        /* Load single profile */
        profile_t *profile = NULL;
        error_t *err = profile_load(repo, specific_profile, &profile);
        if (err) {
            return error_wrap(err, "Failed to load profile '%s'", specific_profile);
        }

        /* Create ignore context for this profile */
        ignore_context_t *ctx = NULL;
        err = ignore_context_create(repo, config, specific_profile, NULL, 0, &ctx);
        if (err) {
            profile_free(profile);
            return error_wrap(err, "Failed to create ignore context");
        }

        /* Test the path */
        ignore_test_result_t result;
        err = ignore_test_path(ctx, test_path, is_directory, &result);
        ignore_context_free(ctx);
        profile_free(profile);

        if (err) {
            return error_wrap(err, "Failed to test path");
        }

        /* Print result */
        if (result.ignored) {
            output_info(out, "✗ IGNORED by profile '%s'", specific_profile);
            output_info(out, "  Reason: %s", ignore_source_to_string(result.source));
        } else {
            output_success(out, "NOT IGNORED by profile '%s'", specific_profile);
        }

        return NULL;
    }

    /* Test against all enabled profiles */
    profile_list_t *profiles = NULL;
    error_t *err = profile_resolve(
        repo,
        NULL, 0,  /* No explicit profiles */
        false,  /* Not strict - skip missing profiles */
        &profiles,
        NULL);

    if (err) {
        return error_wrap(err, "Failed to load profiles");
    }

    if (!profiles || profiles->count == 0) {
        profile_list_free(profiles);
        output_info(out, "No enabled profiles found");
        output_info(out, "Testing against baseline .dottaignore only");

        /* Test with no profile */
        ignore_context_t *ctx = NULL;
        err = ignore_context_create(repo, config, NULL, NULL, 0, &ctx);
        if (err) {
            return error_wrap(err, "Failed to create ignore context");
        }

        ignore_test_result_t result;
        err = ignore_test_path(ctx, test_path, is_directory, &result);
        ignore_context_free(ctx);

        if (err) {
            return error_wrap(err, "Failed to test path");
        }

        if (result.ignored) {
            output_info(out, "✗ IGNORED");
            output_info(out, "  Reason: %s", ignore_source_to_string(result.source));
        } else {
            output_success(out, "NOT IGNORED");
        }

        return NULL;
    }

    /* Test against each enabled profile */
    output_info(out, "Testing path: %s", test_path);
    output_info(out, "Enabled profiles: %zu", profiles->count);
    output_newline(out);

    bool any_ignored = false;
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];

        /* Create ignore context for this profile */
        ignore_context_t *ctx = NULL;
        err = ignore_context_create(repo, config, profile->name, NULL, 0, &ctx);
        if (err) {
            profile_list_free(profiles);
            return error_wrap(err, "Failed to create ignore context for profile '%s'", profile->name);
        }

        /* Test the path */
        ignore_test_result_t result;
        err = ignore_test_path(ctx, test_path, is_directory, &result);
        ignore_context_free(ctx);

        if (err) {
            profile_list_free(profiles);
            return error_wrap(err, "Failed to test path against profile '%s'", profile->name);
        }

        /* Print result */
        if (result.ignored) {
            output_info(out, "✗ Profile '%s': IGNORED", profile->name);
            if (verbose) {
                output_info(out, "    Reason: %s", ignore_source_to_string(result.source));
            }
            any_ignored = true;
        } else {
            output_success(out, "Profile '%s': NOT IGNORED", profile->name);
        }
    }

    profile_list_free(profiles);

    /* Summary */
    output_newline(out);
    if (any_ignored) {
        output_info(out, "Result: Path would be IGNORED during add/update operations");
    } else {
        output_success(out, "Result: Path would be TRACKED");
    }

    return NULL;
}

/**
 * Main command implementation
 */
error_t *cmd_ignore(git_repository *repo, const cmd_ignore_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    /* Load configuration */
    dotta_config_t *config = NULL;
    error_t *err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        config = config_create_default();
    }

    /* Create output context */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* Validate mutual exclusivity */
    bool has_add = opts->add_count > 0;
    bool has_remove = opts->remove_count > 0;
    bool has_test = opts->test_path != NULL;
    bool has_modify = has_add || has_remove;

    if (has_test && has_modify) {
        output_free(out);
        config_free(config);
        return ERROR(ERR_INVALID_ARG, "Cannot use --test with --add or --remove");
    }

    /* Determine action */
    if (has_test) {
        /* Test mode */
        err = test_path_ignore(repo, config, opts->test_path, opts->profile, opts->verbose, out);
    } else if (has_modify) {
        /* Add/remove mode */
        if (opts->profile) {
            err = modify_profile_dottaignore(repo, opts->profile,
                                            opts->add_patterns, opts->add_count,
                                            opts->remove_patterns, opts->remove_count,
                                            out);
        } else {
            err = modify_baseline_dottaignore(repo,
                                             opts->add_patterns, opts->add_count,
                                             opts->remove_patterns, opts->remove_count,
                                             out);
        }
    } else {
        /* Edit mode (default) */
        if (opts->profile) {
            err = edit_profile_dottaignore(repo, opts->profile, out);
        } else {
            err = edit_baseline_dottaignore(repo, config, out);
        }
    }

    output_free(out);
    config_free(config);
    return err;
}
