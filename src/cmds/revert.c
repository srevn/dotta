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
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/stats.h"
#include "crypto/keymanager.h"
#include "infra/content.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/buffer.h"
#include "utils/commit.h"
#include "utils/config.h"
#include "utils/output.h"

/**
 * Discover file in history (fallback when not found in HEAD)
 *
 * Uses stats_get_file_history() to search the commit history of a profile
 * for evidence that a file existed. This is expensive (O(all commits)) but
 * necessary for reverting deleted files.
 *
 * This function should only be called as a fallback when the file is not
 * found in the current HEAD and the user has provided a profile hint.
 *
 * @param repo Repository (must not be NULL)
 * @param storage_path Storage path (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param out_profile Output profile name (must not be NULL, caller must free)
 * @param out_resolved_path Output storage path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *discover_file_in_history(
    git_repository *repo,
    const char *storage_path,
    const char *profile_name,
    const output_ctx_t *out,
    char **out_profile,
    char **out_resolved_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_resolved_path);

    /* Inform user about expensive operation */
    output_info(
        out, "File not found in current HEAD, "
        "searching history of '%s' profile...\n",
        profile_name
    );

    /* Use stats module to get file history */
    file_history_t *history = NULL;
    error_t *err = stats_get_file_history(
        repo, profile_name, storage_path, &history
    );
    if (err) {
        return error_wrap(err, "Failed to search history");
    }

    /* Check if file ever existed */
    if (history->count == 0) {
        stats_free_file_history(history);
        return ERROR(
            ERR_NOT_FOUND, "File '%s' has no history in profile '%s'\n"
            "The file was never tracked in this profile.\n"
            "Hint: Use 'dotta list --profile %s' to see tracked files",
            storage_path, profile_name, profile_name
        );
    }

    /* Found in history! Show user where it was last seen */
    char short_sha[8];
    git_oid_tostr(short_sha, sizeof(short_sha), &history->commits[0].oid);

    output_success(
        out, "Found in history (last modified: commit %s)",
        short_sha
    );

    stats_free_file_history(history);

    /* Return profile and path */
    *out_profile = strdup(profile_name);
    *out_resolved_path = strdup(storage_path);

    if (!*out_profile || !*out_resolved_path) {
        if (*out_profile) free(*out_profile);
        if (*out_resolved_path) free(*out_resolved_path);
        return ERROR(ERR_MEMORY, "Failed to allocate strings");
    }

    return NULL;
}

/**
 * Discover file in profiles
 *
 * Returns profile name and resolved storage path.
 * Accepts filesystem paths or storage paths.
 *
 * With profile_hint: Checks specific profile's tree, falls back to
 * history search if file deleted from HEAD.
 *
 * Without profile_hint: Uses profile_discover_file() for all-branch
 * scan. Handles disambiguation when file exists in multiple profiles.
 */
static error_t *discover_file(
    git_repository *repo,
    const char *file_path,
    const char *profile_hint,
    const output_ctx_t *out,
    bool *found_in_history,
    char **out_profile,
    char **out_resolved_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(file_path);
    CHECK_NULL(out);
    CHECK_NULL(found_in_history);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_resolved_path);

    error_t *err = NULL;
    char *storage_path = NULL;

    /* Initialize output flag */
    *found_in_history = false;

    /* Resolve input path to storage format (flexible mode - file need not exist)
     *
     * Note: No custom prefix context available for revert command - users must use
     * storage format (custom/etc/nginx.conf) for custom/ paths */
    err = path_resolve_input(file_path, false, NULL, 0, &storage_path);
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
            /* File not in HEAD - try history search as fallback */
            err = discover_file_in_history(
                repo, storage_path, profile_hint, out, out_profile, out_resolved_path
            );
            free(storage_path);

            if (err) {
                return err;
            }

            /* Found in history! */
            *found_in_history = true;
            return NULL;
        }

        /* Found in HEAD (fast path) */
        *out_profile = strdup(profile_hint);
        if (!*out_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        *out_resolved_path = storage_path;
        return NULL;
    }

    /* Search across all local branches for the file */
    string_array_t *matches = NULL;
    err = profile_discover_file(repo, storage_path, false, &matches);

    if (err) {
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            err = ERROR(
                ERR_NOT_FOUND, "File '%s' not found in any profile\n\n"
                "If you are trying to revert a deleted file, specify the profile:\n"
                "  dotta revert --profile <name> %s <commit>\n\n"
                "Use 'dotta list --all' to see all profiles.", storage_path, file_path
            );
        }
        free(storage_path);
        return err;
    }

    if (string_array_size(matches) == 1) {
        /* Found in exactly one profile */
        *out_profile = strdup(string_array_get(matches, 0));
        string_array_free(matches);

        if (!*out_profile) {
            free(storage_path);
            return ERROR(ERR_MEMORY, "Failed to allocate profile name");
        }

        *out_resolved_path = storage_path;
        return NULL;
    }

    /* Found in multiple profiles - ambiguous */
    output_print(
        out, OUTPUT_NORMAL, "File '%s' found in multiple profiles:\n",
        storage_path
    );

    for (size_t i = 0; i < string_array_size(matches); i++) {
        output_print(
            out, OUTPUT_NORMAL, "  • %s\n",
            string_array_get(matches, i)
        );
    }
    output_hint(out, "Specify --profile to disambiguate:");
    output_hint_line(out, "  dotta revert --profile <name> %s", storage_path);

    string_array_free(matches);
    free(storage_path);

    return ERROR(ERR_INVALID_ARG, "Ambiguous file reference");
}

/**
 * Show diff preview between two blobs
 *
 * Uses content layer to transparently decrypt encrypted files before diffing,
 * so users see readable plaintext diffs instead of encrypted gibberish.
 *
 * Encryption flags are passed separately for current and target blobs because
 * the encryption state may have changed between commits (e.g., file encrypted
 * after the target commit). Using a single flag would produce garbled output
 * for the blob whose state doesn't match.
 */
static error_t *show_diff_preview(
    git_repository *repo,
    const char *file_path,
    const char *profile_name,
    bool current_encrypted,
    bool target_encrypted,
    keymanager_t *km,
    const git_oid *current_oid,
    const git_oid *target_oid,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(file_path);
    CHECK_NULL(profile_name);
    CHECK_NULL(current_oid);
    CHECK_NULL(target_oid);
    CHECK_NULL(out);

    /* Check if blobs are identical */
    if (git_oid_equal(current_oid, target_oid)) {
        output_info(out, "File is already at target state (no changes)");
        return NULL;
    }

    /* Get decrypted plaintext content from both blobs
     *
     * This transparently decrypts encrypted files so we can show readable diffs.
     * For plaintext files, this just returns the raw content.
     *
     * Each blob uses its own encryption flag since the state may differ
     * between the current HEAD and the target commit.
     */
    buffer_t *current_plaintext = NULL;
    error_t *err = content_get_from_blob_oid(
        repo,
        current_oid,
        file_path,
        profile_name,
        current_encrypted,
        km,
        &current_plaintext
    );
    if (err) {
        return error_wrap(err, "Failed to get current file content");
    }

    buffer_t *target_plaintext = NULL;
    err = content_get_from_blob_oid(
        repo,
        target_oid,
        file_path,
        profile_name,
        target_encrypted,
        km,
        &target_plaintext
    );
    if (err) {
        buffer_free(current_plaintext);
        return error_wrap(err, "Failed to get target file content");
    }

    /* Create patch directly from plaintext buffers using in-memory API
     *
     * This uses libgit2's buffer-based patch API to avoid creating temporary
     * blobs in the Git ODB that would persist until gc.
     */
    git_patch *patch = NULL;
    int ret = git_patch_from_buffers(
        &patch,
        buffer_data(current_plaintext), buffer_size(current_plaintext), file_path,
        buffer_data(target_plaintext), buffer_size(target_plaintext), file_path,
        NULL  /* options */
    );

    if (ret < 0) {
        buffer_free(current_plaintext);
        buffer_free(target_plaintext);
        return error_from_git(ret);
    }

    /* Get patch stats */
    size_t additions = 0;
    size_t deletions = 0;
    git_patch_line_stats(NULL, &additions, &deletions, patch);

    /* Show header */
    output_styled(
        out, OUTPUT_NORMAL, "\n{bold}Changes preview{reset}\n"
    );

    /* Show stats */
    output_styled(
        out, OUTPUT_NORMAL, "  File: {cyan}%s{reset}\n",
        file_path
    );
    output_styled(
        out, OUTPUT_NORMAL, "  Changes: {green}+%zu{reset} / {red}-%zu{reset}\n",
        additions, deletions
    );
    output_newline(out);

    /* Print patch */
    git_buf buf = { 0 };
    ret = git_patch_to_buf(&buf, patch);
    if (ret < 0) {
        output_warning(out, "Could not format diff output");
    } else if (buf.ptr) {
        output_print_diff(out, buf.ptr);
    }

    git_buf_dispose(&buf);
    git_patch_free(patch);

    /* Free plaintext buffers */
    buffer_free(current_plaintext);
    buffer_free(target_plaintext);

    return NULL;
}

/**
 * Verify profile branch HEAD hasn't moved since we last read it
 *
 * Dotta uses atomic commits to orphan branches — there is no staging area
 * or working directory for profile branches (HEAD always points to
 * dotta-worktree). The traditional "uncommitted changes" check does not
 * apply. Instead, this verifies that no concurrent operation has modified
 * the branch between showing the preview and performing the revert.
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile branch to check (must not be NULL)
 * @param expected_oid Expected HEAD OID (must not be NULL)
 * @return Error if branch was modified, NULL if unchanged
 */
static error_t *verify_branch_unchanged(
    git_repository *repo,
    const char *profile_name,
    const git_oid *expected_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(expected_oid);

    git_oid current_oid;
    git_commit *commit = NULL;
    error_t *err = gitops_resolve_commit_in_branch(
        repo, profile_name, "HEAD", &current_oid, &commit
    );
    if (commit) git_commit_free(commit);
    if (err) return error_wrap(err, "Failed to verify branch state");

    if (!git_oid_equal(&current_oid, expected_oid)) {
        char expected_str[8], current_str[8];
        git_oid_tostr(expected_str, sizeof(expected_str), expected_oid);
        git_oid_tostr(current_str, sizeof(current_str), &current_oid);
        return ERROR(
            ERR_CONFLICT,
            "Profile '%s' was modified concurrently (expected %s, now %s)\n"
            "Another operation changed the branch since the preview.",
            profile_name, expected_str, current_str
        );
    }

    return NULL;
}

/**
 * Load metadata from branch with graceful fallback
 *
 * If metadata.json doesn't exist or can't be parsed, returns empty metadata
 * instead of failing. This is appropriate for operations that want to continue
 * even without metadata (e.g., showing diff preview, handling old commits).
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *load_metadata_graceful(
    git_repository *repo,
    const char *branch_name,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out);

    error_t *err = metadata_load_from_branch(repo, branch_name, out);
    if (err) {
        /* Graceful fallback: create empty metadata if loading fails */
        error_t *create_err = metadata_create_empty(out);
        if (create_err) {
            error_free(create_err);
            error_free(err);
            return ERROR(ERR_MEMORY, "Failed to create metadata");
        }
        error_free(err);
    }

    return NULL;
}

/**
 * Build commit message for revert operation
 *
 * Uses custom message if provided, otherwise generates from template system.
 * This centralizes message generation logic for reuse across revert operations.
 *
 * @param config Configuration (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param file_path File path (must not be NULL)
 * @param target_commit_oid Target commit OID (must not be NULL)
 * @param custom_message Custom message (can be NULL for template generation)
 * @return Allocated message string (caller must free), or NULL on allocation failure
 */
static char *build_revert_commit_message(
    const dotta_config_t *config,
    const char *profile_name,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *custom_message
) {
    if (custom_message && custom_message[0]) {
        return strdup(custom_message);
    }

    /* Generate message using template system */
    char oid_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), target_commit_oid);

    /* Build context for commit message */
    char *files[] = { (char *) file_path };
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_REVERT,
        .profile       = profile_name,
        .files         = files,
        .file_count    = 1,
        .custom_msg    = NULL,
        .target_commit = oid_str
    };

    return build_commit_message(config, &ctx);
}

/**
 * Load metadata from a specific commit
 *
 * Extracts .dotta/metadata.json from a commit's tree and parses it.
 * If metadata.json doesn't exist in the commit, returns empty metadata
 * (graceful fallback for old commits or commits without metadata).
 *
 * @param repo Repository (must not be NULL)
 * @param commit Commit to load from (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *load_metadata_from_commit(
    git_repository *repo,
    git_commit *commit,
    metadata_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(commit);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_tree *tree = NULL;
    git_tree_entry *entry = NULL;
    git_blob *blob = NULL;

    /* Get commit's tree */
    int ret = git_commit_tree(&tree, commit);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Try to find .dotta/metadata.json in tree */
    ret = git_tree_entry_bypath(&entry, tree, METADATA_FILE_PATH);
    if (ret == GIT_ENOTFOUND) {
        /* No metadata in this commit - return empty metadata (graceful fallback) */
        git_tree_free(tree);
        return metadata_create_empty(out);
    } else if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Load and parse metadata blob */
    const git_oid *blob_oid = git_tree_entry_id(entry);
    ret = git_blob_lookup(&blob, repo, blob_oid);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    const char *json_content = (const char *) git_blob_rawcontent(blob);
    if (!json_content) {
        err = ERROR(ERR_INVALID_ARG, "Metadata blob has no content");
        goto cleanup;
    }

    /* Parse JSON content */
    err = metadata_from_json(json_content, out);
    if (err) {
        err = error_wrap(err, "Failed to parse metadata from commit");
        goto cleanup;
    }

cleanup:
    if (blob) git_blob_free(blob);
    if (entry) git_tree_entry_free(entry);
    if (tree) git_tree_free(tree);

    return err;
}

/**
 * Revert file and metadata in profile branch to target commit
 *
 * This atomically reverts both file content AND its metadata entry to the
 * target commit state in a single commit. This ensures that permissions,
 * ownership, and encryption flags are restored along with file content.
 *
 * The function handles:
 * - Files that exist in both current and target (normal revert)
 * - Files deleted from HEAD (restore from history)
 * - Missing metadata gracefully (creates defaults with warning)
 * - Symlinks (restore ownership metadata if present at target commit)
 */
static error_t *revert_file_in_branch(
    git_repository *repo,
    const dotta_config_t *config,
    const char *profile_name,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *commit_message,
    const output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(file_path);
    CHECK_NULL(target_commit_oid);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_commit *target_commit = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *target_entry = NULL;
    metadata_t *target_metadata = NULL;
    metadata_item_t *meta_to_restore = NULL;
    git_reference *branch_ref = NULL;
    git_commit *head_commit = NULL;
    git_tree *head_tree = NULL;
    metadata_t *current_metadata = NULL;
    buffer_t *metadata_json_buf = NULL;
    git_index *index = NULL;
    git_tree *new_tree = NULL;
    git_signature *sig = NULL;
    char *msg = NULL;
    git_oid target_blob_oid_copy;
    git_filemode_t target_mode = 0;
    bool is_symlink = false;

    /* PHASE 1: Load Target State */

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
            err = ERROR(
                ERR_NOT_FOUND, "File '%s' not found at target commit",
                file_path
            );
        } else {
            err = error_from_git(ret);
        }
        goto cleanup;
    }

    /* Get target blob OID and mode */
    git_oid_cpy(&target_blob_oid_copy, git_tree_entry_id(target_entry));
    target_mode = git_tree_entry_filemode(target_entry);
    is_symlink = (target_mode == GIT_FILEMODE_LINK);

    /* Load metadata from target commit */
    err = load_metadata_from_commit(repo, target_commit, &target_metadata);
    if (err) {
        err = error_wrap(err, "Failed to load metadata from target commit");
        goto cleanup;
    }

    /* Extract or create metadata item for this file/symlink */
    if (is_symlink) {
        /* Symlinks: only restore ownership metadata if present at target commit.
         * No defaults needed — symlinks have no settable mode or encryption. */
        const metadata_item_t *target_meta_item = NULL;
        error_t *lookup_err = metadata_get_item(
            target_metadata, file_path, &target_meta_item
        );

        if (!lookup_err && target_meta_item &&
            target_meta_item->kind == METADATA_ITEM_SYMLINK) {
            err = metadata_item_clone(target_meta_item, &meta_to_restore);
            if (err) {
                err = error_wrap(err, "Failed to clone symlink metadata item");
                goto cleanup;
            }
        }
        /* No metadata for symlink at target commit is fine — old profiles won't have it */
        if (lookup_err) {
            error_free(lookup_err);
        }
    } else {
        const metadata_item_t *target_meta_item = NULL;
        error_t *lookup_err = metadata_get_item(
            target_metadata, file_path, &target_meta_item
        );

        if (!lookup_err && target_meta_item &&
            target_meta_item->kind == METADATA_ITEM_FILE) {
            /* Found metadata entry - clone it */
            err = metadata_item_clone(target_meta_item, &meta_to_restore);
            if (err) {
                err = error_wrap(err, "Failed to clone metadata item");
                goto cleanup;
            }
        } else {
            /* No metadata entry at target commit - create default from tree mode */
            char oid_str[8];
            git_oid_tostr(oid_str, sizeof(oid_str), target_commit_oid);

            output_warning(
                out, "No metadata found for '%s' at commit %s",
                file_path, oid_str
            );
            output_hint_line(
                out, "Using defaults (mode=%04o, encrypted=false)",
                (unsigned int) (target_mode & 0777)
            );

            err = metadata_item_create_file(
                file_path, target_mode & 0777, false, &meta_to_restore
            );
            if (err) {
                err = error_wrap(err, "Failed to create default metadata item");
                goto cleanup;
            }

            if (lookup_err) {
                error_free(lookup_err);
            }
        }
    }

    /* Free target metadata (no longer needed) */
    metadata_free(target_metadata);
    target_metadata = NULL;

    /* PHASE 2: Load Current HEAD */

    /* Build branch reference name */
    char ref_name[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(
        ref_name, sizeof(ref_name), "refs/heads/%s", profile_name
    );
    if (err) {
        err = error_wrap(err, "Invalid profile name '%s'", profile_name);
        goto cleanup;
    }

    ret = git_reference_lookup(&branch_ref, repo, ref_name);
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

    /* Load current metadata */
    err = load_metadata_from_commit(repo, head_commit, &current_metadata);
    if (err) {
        err = error_wrap(err, "Failed to load current metadata");
        goto cleanup;
    }

    /* PHASE 3: Build New Tree */

    /* Use standalone in-memory index for tree construction.
     *
     * We must NOT use git_repository_index() here — that returns the repo's
     * shared index (backed by .git/index). Modifying it would corrupt the
     * index for the dotta-worktree branch that HEAD points to.
     *
     * A standalone index has no backing file or ODB, so we:
     *   - Populate it from the HEAD tree (git_index_read_tree)
     *   - Add entries with pre-existing blob OIDs (git_index_add)
     *   - Create blobs for new content directly in the ODB (git_blob_create_from_buffer)
     *   - Write the tree via git_index_write_tree_to(index, repo)
     */
    ret = git_index_new(&index);
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

    /* Replace file entry — blob already exists in ODB from target commit */
    git_index_remove_bypath(index, file_path);

    git_index_entry source_entry;
    memset(&source_entry, 0, sizeof(source_entry));
    source_entry.mode = target_mode;
    source_entry.path = file_path;
    git_oid_cpy(&source_entry.id, &target_blob_oid_copy);

    ret = git_index_add(index, &source_entry);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Update metadata entry (if not symlink) */
    if (meta_to_restore) {
        err = metadata_add_item(current_metadata, meta_to_restore);
        if (err) {
            err = error_wrap(err, "Failed to update metadata");
            goto cleanup;
        }
    }

    /* Serialize updated metadata to JSON */
    err = metadata_to_json(current_metadata, &metadata_json_buf);
    if (err) {
        err = error_wrap(err, "Failed to serialize metadata");
        goto cleanup;
    }

    /* Create metadata blob in ODB and replace index entry */
    git_oid metadata_blob_oid;
    ret = git_blob_create_from_buffer(
        &metadata_blob_oid, repo,
        buffer_data(metadata_json_buf), buffer_size(metadata_json_buf)
    );
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Stage updated metadata.json */
    git_index_remove_bypath(index, METADATA_FILE_PATH);

    git_index_entry meta_entry;
    memset(&meta_entry, 0, sizeof(meta_entry));
    meta_entry.mode = GIT_FILEMODE_BLOB;
    meta_entry.path = METADATA_FILE_PATH;
    git_oid_cpy(&meta_entry.id, &metadata_blob_oid);

    ret = git_index_add(index, &meta_entry);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* PHASE 4: Create Atomic Commit */

    /* Create tree from standalone in-memory index.
     *
     * Do NOT call git_index_write() — this standalone index has no backing
     * file. Writing the tree directly to the repo ODB is the correct approach. */
    git_oid new_tree_oid;
    ret = git_index_write_tree_to(&new_tree_oid, index, repo);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    ret = git_tree_lookup(&new_tree, repo, &new_tree_oid);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Get signature */
    ret = git_signature_default(&sig, repo);
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* Build commit message */
    msg = build_revert_commit_message(
        config, profile_name, file_path, target_commit_oid,
        commit_message
    );
    if (!msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    /* Create commit */
    git_oid new_commit_oid;
    const git_commit *parents[] = { head_commit };
    ret = git_commit_create(
        &new_commit_oid,
        repo,
        git_reference_name(branch_ref), /* Update the branch */
        sig,        /* author */
        sig,        /* committer */
        NULL,       /* encoding (NULL = UTF-8) */
        msg,        /* message */
        new_tree,
        1,          /* parent count */
        parents
    );

    if (ret < 0) {
        err = error_from_git(ret);
    }

cleanup:
    if (target_commit) git_commit_free(target_commit);
    if (target_tree) git_tree_free(target_tree);
    if (target_entry) git_tree_entry_free(target_entry);
    if (target_metadata) metadata_free(target_metadata);
    if (meta_to_restore) metadata_item_free(meta_to_restore);
    if (branch_ref) git_reference_free(branch_ref);
    if (head_commit) git_commit_free(head_commit);
    if (head_tree) git_tree_free(head_tree);
    if (current_metadata) metadata_free(current_metadata);
    if (metadata_json_buf) buffer_free(metadata_json_buf);
    if (index) git_index_free(index);
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
    git_oid current_oid = { { 0 } };
    git_oid target_oid = { { 0 } };
    git_commit *current_commit = NULL;
    git_commit *target_commit = NULL;
    git_tree *current_tree = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *current_entry = NULL;
    git_tree_entry *target_entry = NULL;
    output_ctx_t *out = NULL;
    keymanager_t *km = NULL;
    bool user_aborted = false;

    /* Step 1: Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        error_free(err);
        err = NULL;
        config = config_create_default();
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Step 2: Discover file in profiles */
    output_print(
        out, OUTPUT_VERBOSE, "Discovering file in profiles...\n"
    );

    bool found_in_history = false;
    err = discover_file(
        repo, opts->file_path, opts->profile, out, &found_in_history,
        &profile_name, &resolved_path
    );
    if (err) goto cleanup;

    if (found_in_history) {
        output_info(
            out, "File was deleted from HEAD, reverting from history"
        );
    }

    output_print(
        out, OUTPUT_VERBOSE, "Found file in profile '%s': %s\n",
        profile_name, resolved_path
    );

    /* Step 3: Resolve target commit */
    output_print(
        out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n",
        opts->commit
    );

    err = gitops_resolve_commit_in_branch(
        repo, profile_name, opts->commit, &target_oid, &target_commit
    );
    if (err) goto cleanup;

    /* Step 4: Get current HEAD commit for comparison */
    err = gitops_resolve_commit_in_branch(
        repo, profile_name, "HEAD", &current_oid, &current_commit
    );
    if (err) goto cleanup;

    /* Step 5: Prepare for revert - two distinct workflows based on file state */
    const git_oid *current_blob_oid = NULL;
    const git_oid *target_blob_oid = NULL;

    if (found_in_history) {
        /*
         * Workflow A: Restoring Deleted File
         * File doesn't exist in current HEAD but was found in commit history.
         * Skip tree extraction entirely - not needed for restoration preview.
         * The revert operation itself will handle all necessary Git operations.
         */
        output_print(
            out, OUTPUT_VERBOSE,
            "File deleted from HEAD, preparing restoration from history\n"
        );

    } else {
        /*
         * Workflow B: Reverting Existing File
         * File exists in current HEAD - perform standard revert workflow.
         * Extract trees and entries for blob comparison and diff preview.
         */
        output_print(
            out, OUTPUT_VERBOSE,
            "File exists in HEAD, extracting trees for comparison\n"
        );

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
                err = ERROR(
                    ERR_NOT_FOUND, "File '%s' not found in current HEAD",
                    resolved_path
                );
            } else {
                err = error_from_git(ret);
            }
            goto cleanup;
        }

        ret = git_tree_entry_bypath(&target_entry, target_tree, resolved_path);
        if (ret < 0) {
            if (ret == GIT_ENOTFOUND) {
                err = ERROR(
                    ERR_NOT_FOUND, "File '%s' not found at target commit",
                    resolved_path
                );
            } else {
                err = error_from_git(ret);
            }
            goto cleanup;
        }

        current_blob_oid = git_tree_entry_id(current_entry);
        target_blob_oid = git_tree_entry_id(target_entry);

        /* Early exit: Check if file is already at target state */
        if (git_oid_equal(current_blob_oid, target_blob_oid)) {
            output_info(
                out, "File '%s' is already at target state (no changes)",
                opts->file_path
            );
            goto cleanup;  /* Not an error, just nothing to do */
        }
    }

    /* Step 6: Show preview (always, including dry-run) */
    output_styled(
        out, OUTPUT_NORMAL, "\n{bold}Revert preview:{reset}\n"
    );

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &target_oid);

    const git_signature *author = git_commit_author(target_commit);
    time_t commit_time = (time_t) author->when.time;
    struct tm *tm_info = localtime(&commit_time);

    char time_buf[64];
    if (tm_info) {
        strftime(
            time_buf, sizeof(time_buf),
            "%Y-%m-%d %H:%M:%S", tm_info
        );
    } else {
        snprintf(
            time_buf, sizeof(time_buf),
            "<invalid time>"
        );
    }

    output_styled(
        out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n",
        profile_name
    );
    output_print(
        out, OUTPUT_NORMAL, "  File: %s\n",
        resolved_path
    );
    output_print(
        out, OUTPUT_NORMAL, "  Target commit: %s (%s)\n",
        oid_str, time_buf
    );

    if (found_in_history) {
        /* File was deleted - show simple restoration message */
        output_print(out, OUTPUT_NORMAL, "\n");
        output_styled(
            out, OUTPUT_NORMAL,
            "{green}Restoring deleted file from commit history{reset}\n"
        );
    } else {
        /* File exists - show detailed diff preview with decryption support.
         * Load metadata from both current HEAD and target commit separately
         * to handle encryption state changes between commits correctly. */
        metadata_t *current_meta = NULL;
        err = load_metadata_graceful(repo, profile_name, &current_meta);
        if (err) goto cleanup;

        metadata_t *target_meta = NULL;
        err = load_metadata_from_commit(repo, target_commit, &target_meta);
        if (err) {
            metadata_free(current_meta);
            goto cleanup;
        }

        bool current_encrypted = metadata_get_file_encrypted(current_meta, resolved_path);
        bool target_encrypted = metadata_get_file_encrypted(target_meta, resolved_path);

        metadata_free(current_meta);
        metadata_free(target_meta);

        km = keymanager_get_global(config);

        err = show_diff_preview(
            repo, resolved_path, profile_name, current_encrypted, target_encrypted,
            km, current_blob_oid, target_blob_oid, out
        );
        if (err) {
            /* Non-fatal: the revert itself doesn't need decryption (copies blobs).
             * Show warning and continue to confirmation — user decides. */
            output_warning(out, "Could not show diff preview: %s", error_message(err));
            error_free(err);
            err = NULL;
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

    /* Step 7: Early exit for dry-run (preview shown, no changes to make) */
    if (opts->dry_run) {
        output_info(out, "\nDry-run mode: No changes made");
        goto cleanup;
    }

    /* Step 8: Prompt for confirmation (unless --force or config disables) */
    if (!output_confirm_destructive(out, config, "Revert file?", opts->force)) {
        output_info(out, "Aborted.");
        user_aborted = true;
        goto cleanup;
    }

    /* Free current_commit (no longer needed) */
    git_commit_free(current_commit);
    current_commit = NULL;

    /* Verify branch hasn't been modified concurrently since preview */
    if (!opts->force) {
        err = verify_branch_unchanged(repo, profile_name, &current_oid);
        if (err) goto cleanup;
    }

    output_print(out, OUTPUT_VERBOSE, "\nReverting file...\n");

    /* Perform revert (current_oid is the pre-revert HEAD for manifest sync) */
    err = revert_file_in_branch(
        repo,
        config,
        profile_name,
        resolved_path,
        &target_oid,
        opts->message,
        out
    );
    if (err) {
        err = error_wrap(err, "Failed to revert file");
        goto cleanup;
    }

    /* Step 9: Update manifest if profile is enabled */
    output_print(out, OUTPUT_VERBOSE, "Updating manifest...\n");

    /* Initialize manifest sync counters */
    size_t synced = 0, removed = 0, fallbacks = 0;

    /* Check if profile is enabled */
    state_t *read_state = NULL;
    bool profile_enabled = false;

    err = state_load(repo, &read_state);
    if (!err && read_state) {
        profile_enabled = state_has_profile(read_state, profile_name);
        state_free(read_state);
        read_state = NULL;
    } else if (err) {
        /* State doesn't exist - treat as not enabled */
        error_free(err);
        err = NULL;
    }

    if (!profile_enabled) {
        /* Profile not enabled - manifest update not needed */
        output_success(
            out, "Reverted %s in profile '%s'",
            resolved_path, profile_name
        );
        output_info(
            out, "\nNote: Profile '%s' is not enabled on this machine",
            profile_name
        );
        goto cleanup;
    }

    /* Get new HEAD OID (after revert) */
    git_oid new_head_oid;
    git_commit *new_head_commit = NULL;
    err = gitops_resolve_commit_in_branch(
        repo, profile_name, "HEAD", &new_head_oid, &new_head_commit
    );
    if (err) {
        /* Non-fatal: Git succeeded, manifest can recover */
        output_warning(
            out, "Failed to get new HEAD for manifest update: %s",
            error_message(err)
        );
        output_hint(
            out, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        err = NULL;
        goto success;
    }
    if (new_head_commit) {
        git_commit_free(new_head_commit);
        new_head_commit = NULL;
    }

    /* Open transaction for manifest update */
    state_t *state = NULL;
    err = state_load_for_update(repo, &state);
    if (err) {
        /* Non-fatal */
        output_warning(
            out, "Failed to open transaction for manifest update: %s",
            error_message(err)
        );
        output_hint(
            out, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        err = NULL;
        goto success;
    }

    /* Get enabled profiles for manifest sync */
    string_array_t *enabled_profiles = NULL;
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        output_warning(
            out, "Failed to get enabled profiles: %s",
            error_message(err)
        );
        state_free(state);
        error_free(err);
        err = NULL;
        goto success;
    }

    /* Sync manifest via diff */
    error_t *manifest_err = manifest_sync_diff(
        repo,
        state,
        profile_name,
        &current_oid,       /* Before revert (captured at step 3) */
        &new_head_oid,      /* After revert */
        enabled_profiles,
        NULL,               /* metadata_cache - will load if needed */
        &synced,
        &removed,
        &fallbacks,
        NULL                /* out_skipped - not applicable for revert */
    );

    if (manifest_err) {
        /* Non-fatal: Git succeeded, manifest can recover */
        output_warning(
            out, "Manifest sync failed: %s",
            error_message(manifest_err)
        );
        output_hint(
            out, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(manifest_err);
        state_free(state);
        string_array_free(enabled_profiles);
        goto success;
    }

    /* Commit transaction */
    err = state_save(repo, state);
    state_free(state);
    string_array_free(enabled_profiles);

    if (err) {
        /* Non-fatal */
        output_warning(
            out, "Failed to save manifest updates: %s",
            error_message(err)
        );
        output_hint(
            out, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        err = NULL;
        goto success;
    }

success:
    /* Display success message */
    output_success(
        out, "Reverted %s in profile '%s'",
        resolved_path, profile_name
    );

    /* Show manifest sync results if available */
    if (synced > 0 || removed > 0 || fallbacks > 0) {
        output_info(
            out, "Manifest: %zu staged, %zu removed, %zu fallback%s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }

    /* Guide user to deploy changes */
    output_info(
        out, "\nRun 'dotta apply' to deploy changes to filesystem"
    );

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
