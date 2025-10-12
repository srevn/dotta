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
#include "core/profiles.h"
#include "utils/config.h"
#include "utils/ignore.h"
#include "utils/output.h"
#include "utils/string.h"

/**
 * Get editor from environment
 *
 * Priority: DOTTA_EDITOR > VISUAL > EDITOR > vi
 */
static const char *get_editor(void) {
    const char *editor = getenv("DOTTA_EDITOR");
    if (editor) {
        return editor;
    }

    editor = getenv("VISUAL");
    if (editor) {
        return editor;
    }

    editor = getenv("EDITOR");
    if (editor) {
        return editor;
    }

    return "vi";
}

/**
 * Update a file in a branch
 *
 * Creates a new commit with the updated file content.
 */
static error_t *update_file_in_branch(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    const char *content,
    size_t content_size,
    const char *commit_message
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(file_path);
    CHECK_NULL(content);
    CHECK_NULL(commit_message);

    /* Create blob from content */
    git_oid blob_oid;
    int git_err = git_blob_create_from_buffer(&blob_oid, repo, content, content_size);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Load current tree from branch */
    char *ref_name = str_format("refs/heads/%s", branch_name);
    if (!ref_name) {
        return ERROR(ERR_MEMORY, "Failed to allocate ref name");
    }

    git_tree *current_tree = NULL;
    error_t *err = gitops_load_tree(repo, ref_name, &current_tree);
    if (err) {
        free(ref_name);
        return error_wrap(err, "Failed to load tree from branch '%s'", branch_name);
    }

    /* Create tree builder from current tree */
    git_treebuilder *builder = NULL;
    git_err = git_treebuilder_new(&builder, repo, current_tree);
    git_tree_free(current_tree);

    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Insert/update the file */
    git_err = git_treebuilder_insert(NULL, builder, file_path, &blob_oid, GIT_FILEMODE_BLOB);
    if (git_err < 0) {
        git_treebuilder_free(builder);
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Write the new tree */
    git_oid tree_oid;
    git_err = git_treebuilder_write(&tree_oid, builder);
    git_treebuilder_free(builder);

    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Load the new tree */
    git_tree *new_tree = NULL;
    git_err = git_tree_lookup(&new_tree, repo, &tree_oid);
    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Create commit */
    err = gitops_create_commit(
        repo,
        branch_name,
        new_tree,
        commit_message,
        NULL
    );

    git_tree_free(new_tree);
    free(ref_name);

    return err;
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

    /* Open in editor */
    const char *editor = get_editor();
    char *cmd = str_format("%s %s", editor, tmpfile);
    if (!cmd) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_MEMORY, "Failed to allocate editor command");
    }

    int status = system(cmd);
    free(cmd);

    if (status != 0) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_INTERNAL, "Editor exited with error");
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
    err = update_file_in_branch(
        repo,
        "dotta-worktree",
        ".dottaignore",
        new_content,
        read_size,
        "Update baseline .dottaignore"
    );

    free(new_content);

    if (err) {
        return error_wrap(err, "Failed to update .dottaignore");
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
    const dotta_config_t *config,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    (void)config;  /* Reserved for future use */

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
    char *ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_MEMORY, "Failed to allocate ref name");
    }

    /* Load existing .dottaignore content from profile */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, ref_name, &tree);
    free(ref_name);

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

    /* Open in editor */
    const char *editor = get_editor();
    char *cmd = str_format("%s %s", editor, tmpfile);
    if (!cmd) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_MEMORY, "Failed to allocate editor command");
    }

    int status = system(cmd);
    free(cmd);

    if (status != 0) {
        unlink(tmpfile);
        free(tmpfile);
        return ERROR(ERR_INTERNAL, "Editor exited with error");
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

    err = update_file_in_branch(
        repo,
        profile_name,
        ".dottaignore",
        new_content,
        read_size,
        commit_msg
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
            output_success(out, "✓ NOT IGNORED by profile '%s'", specific_profile);
        }

        return NULL;
    }

    /* Test against all active profiles */
    profile_list_t *profiles = NULL;
    error_t *err = profile_resolve(
        repo,
        NULL, 0,  /* No explicit profiles */
        config,
        false,  /* Not strict - skip missing profiles */
        &profiles
    );

    if (err) {
        return error_wrap(err, "Failed to load profiles");
    }

    if (!profiles || profiles->count == 0) {
        profile_list_free(profiles);
        output_info(out, "No active profiles found");
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
            output_success(out, "✓ NOT IGNORED");
        }

        return NULL;
    }

    /* Test against each active profile */
    output_info(out, "Testing path: %s", test_path);
    output_info(out, "Active profiles: %zu", profiles->count);
    printf("\n");

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
            output_success(out, "✓ Profile '%s': NOT IGNORED", profile->name);
        }
    }

    profile_list_free(profiles);

    /* Summary */
    printf("\n");
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

    /* Apply mode override if provided */
    profile_mode_t original_mode = config->mode;
    if (opts->mode) {
        ((dotta_config_t *)config)->mode = config_parse_mode(opts->mode, config->mode);
    }

    /* Determine action */
    if (opts->test_path) {
        /* Test mode */
        err = test_path_ignore(repo, config, opts->test_path, opts->profile, opts->verbose, out);
    } else {
        /* Edit mode */
        if (opts->profile) {
            err = edit_profile_dottaignore(repo, opts->profile, config, out);
        } else {
            err = edit_baseline_dottaignore(repo, config, out);
        }
    }

    /* Restore original mode */
    if (opts->mode) {
        ((dotta_config_t *)config)->mode = original_mode;
    }

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

    output_free(out);
    config_free(config);
    return err;
}
