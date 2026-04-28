/**
 * revert.c - Revert file to previous commit state
 */

#include "cmds/revert.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/stats.h"
#include "utils/commit.h"

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
 * @param profile Profile name (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param out_profile Output profile name (must not be NULL, caller must free)
 * @param out_resolved_path Output storage path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *discover_file_in_history(
    git_repository *repo,
    const char *storage_path,
    const char *profile,
    const output_t *out,
    char **out_profile,
    char **out_resolved_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_path);
    CHECK_NULL(profile);
    CHECK_NULL(out);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_resolved_path);

    /* Inform user about expensive operation */
    output_info(
        out, OUTPUT_NORMAL, "File not found in current HEAD, "
        "searching history of '%s' profile...\n", profile
    );

    /* Use stats module to get file history */
    file_history_t *history = NULL;
    error_t *err = stats_get_file_history(
        repo, profile, storage_path, &history
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
            storage_path, profile, profile
        );
    }

    /* Found in history! Show user where it was last seen */
    char short_sha[8];
    git_oid_tostr(short_sha, sizeof(short_sha), &history->commits[0].oid);

    output_success(
        out, OUTPUT_NORMAL, "Found in history (last modified: commit %s)",
        short_sha
    );

    stats_free_file_history(history);

    /* Return profile and path */
    *out_profile = strdup(profile);
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
    const state_t *state,
    const char *file_path,
    const char *profile_hint,
    const output_t *out,
    bool *found_in_history,
    char **out_profile,
    char **out_resolved_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(file_path);
    CHECK_NULL(out);
    CHECK_NULL(found_in_history);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_resolved_path);

    error_t *err = NULL;
    char *storage_path = NULL;

    /* Initialize output flag */
    *found_in_history = false;

    /* Load custom prefixes for path resolution (non-fatal) */
    string_array_t *prefixes STRING_ARRAY_CLEANUP = NULL;
    error_t *prefix_err = profile_load_custom_prefixes(repo, state, NULL, &prefixes);
    if (prefix_err) error_free(prefix_err);

    /* Resolve input path to storage format (file need not exist) */
    err = path_resolve_input(
        file_path, prefixes ? (const char *const *) prefixes->items : NULL,
        prefixes ? prefixes->count : 0, &storage_path
    );
    if (err) {
        return err;
    }

    /* Fast path: If profile specified, check only that profile */
    if (profile_hint) {
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile_hint, &tree, NULL);
        if (err) {
            free(storage_path);
            return error_wrap(err, "Failed to load profile '%s'", profile_hint);
        }

        /* Check if file exists in tree */
        git_tree_entry *entry = NULL;
        int git_err = git_tree_entry_bypath(&entry, tree, storage_path);
        bool exists = (git_err == 0);

        if (entry) {
            git_tree_entry_free(entry);
        }
        git_tree_free(tree);

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
    err = profile_discover_file(repo, state, storage_path, false, &matches);

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

    if (matches->count == 1) {
        /* Found in exactly one profile */
        *out_profile = strdup(matches->items[0]);
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

    for (size_t i = 0; i < matches->count; i++) {
        output_print(
            out, OUTPUT_NORMAL, "  • %s\n",
            matches->items[i]
        );
    }
    output_hint(out, OUTPUT_NORMAL, "Specify --profile to disambiguate:");
    output_hintline(out, OUTPUT_NORMAL, "  dotta revert --profile <name> %s", storage_path);

    string_array_free(matches);
    free(storage_path);

    return ERROR(ERR_INVALID_ARG, "Ambiguous file reference");
}

/**
 * Show diff preview between two blobs
 *
 * Uses content layer to transparently decrypt encrypted files before diffing,
 * so users see readable plaintext diffs instead of encrypted gibberish.
 * The content layer classifies each blob by its own bytes, so blobs with
 * different encryption states across commits are routed correctly without
 * any caller-supplied flag.
 */
static error_t *show_diff_preview(
    git_repository *repo,
    const char *file_path,
    const char *profile,
    keymgr *keymgr,
    const git_oid *current_oid,
    const git_oid *target_oid,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(file_path);
    CHECK_NULL(profile);
    CHECK_NULL(current_oid);
    CHECK_NULL(target_oid);
    CHECK_NULL(out);

    /* Check if blobs are identical */
    if (git_oid_equal(current_oid, target_oid)) {
        output_info(out, OUTPUT_NORMAL, "File is already at target state (no changes)");
        return NULL;
    }

    /* Get decrypted plaintext content from both blobs.
     *
     * Each call classifies its own blob's bytes — the routing decision lives
     * with the blob, so encryption-state changes between commits are handled
     * by the content layer with no caller participation. */
    buffer_t current_plaintext = BUFFER_INIT;
    error_t *err = content_get_from_blob_oid(
        repo,
        current_oid,
        file_path,
        profile,
        keymgr,
        &current_plaintext
    );
    if (err) {
        return error_wrap(err, "Failed to get current file content");
    }

    buffer_t target_plaintext = BUFFER_INIT;
    err = content_get_from_blob_oid(
        repo,
        target_oid,
        file_path,
        profile,
        keymgr,
        &target_plaintext
    );
    if (err) {
        buffer_free(&current_plaintext);
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
        current_plaintext.data, current_plaintext.size, file_path,
        target_plaintext.data, target_plaintext.size, file_path,
        NULL  /* options */
    );

    if (ret < 0) {
        buffer_free(&current_plaintext);
        buffer_free(&target_plaintext);
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
    output_newline(out, OUTPUT_NORMAL);

    /* Print patch */
    git_buf buf = { 0 };
    ret = git_patch_to_buf(&buf, patch);
    if (ret < 0) {
        output_warning(out, OUTPUT_NORMAL, "Could not format diff output");
    } else if (buf.ptr) {
        output_print_diff(out, buf.ptr);
    }

    git_buf_dispose(&buf);
    git_patch_free(patch);

    /* Free plaintext buffers */
    buffer_free(&current_plaintext);
    buffer_free(&target_plaintext);

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
 * @param profile Profile branch to check (must not be NULL)
 * @param expected_oid Expected HEAD OID (must not be NULL)
 * @return Error if branch was modified, NULL if unchanged
 */
static error_t *verify_branch_unchanged(
    git_repository *repo,
    const char *profile,
    const git_oid *expected_oid
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(expected_oid);

    git_oid current_oid;
    git_commit *commit = NULL;
    error_t *err = gitops_resolve_commit_in_branch(
        repo, profile, "HEAD", &current_oid, &commit
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
            profile, expected_str, current_str
        );
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
 * @param profile Profile name (must not be NULL)
 * @param file_path File path (must not be NULL)
 * @param target_commit_oid Target commit OID (must not be NULL)
 * @param custom_message Custom message (can be NULL for template generation)
 * @return Allocated message string (caller must free), or NULL on allocation failure
 */
static char *build_revert_commit_message(
    const config_t *config,
    const char *profile,
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
        .profile       = profile,
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
    char *json_str = NULL;

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

    /* Read blob content (null-terminated for JSON parsing) */
    size_t size = 0;
    err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), (void **) &json_str, &size
    );
    if (err) goto cleanup;

    /* Parse JSON content */
    err = metadata_from_json(json_str, out);
    if (err) {
        err = error_wrap(err, "Failed to parse metadata from commit");
        goto cleanup;
    }

cleanup:
    if (json_str) free(json_str);
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
    const config_t *config,
    const char *profile,
    const char *file_path,
    const git_oid *target_commit_oid,
    const char *commit_message,
    const output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(file_path);
    CHECK_NULL(target_commit_oid);
    CHECK_NULL(out);

    error_t *err = NULL;
    git_commit *target_commit = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *target_entry = NULL;
    metadata_t *target_metadata = NULL;
    metadata_item_t *meta_to_restore = NULL;
    git_commit *head_commit = NULL;
    metadata_t *current_metadata = NULL;
    buffer_t metadata_json_buf = BUFFER_INIT;
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
                out, OUTPUT_NORMAL, "No metadata found for '%s' at commit %s",
                file_path, oid_str
            );
            output_hintline(
                out, OUTPUT_NORMAL, "Using defaults (mode=%04o, encrypted=false)",
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

    /* PHASE 2: Load Current HEAD Metadata */

    git_oid head_oid;
    err = gitops_resolve_commit_in_branch(
        repo, profile, "HEAD", &head_oid, &head_commit
    );
    if (err) {
        err = error_wrap(
            err, "Failed to resolve HEAD of profile '%s'", profile
        );
        goto cleanup;
    }

    /* Load current metadata */
    err = load_metadata_from_commit(repo, head_commit, &current_metadata);
    if (err) {
        err = error_wrap(err, "Failed to load current metadata");
        goto cleanup;
    }

    /* PHASE 3: Merge target metadata item, serialize, stage blob */

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
        metadata_json_buf.data, metadata_json_buf.size
    );
    if (ret < 0) {
        err = error_from_git(ret);
        goto cleanup;
    }

    /* PHASE 4: Atomic Commit (file + metadata.json) */

    /* Build commit message */
    msg = build_revert_commit_message(
        config, profile, file_path, target_commit_oid, commit_message
    );
    if (!msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    /* Create commit (handles signature and parent lookup internally) */
    gitops_tree_update_t updates[2];
    updates[0].path = file_path;
    updates[0].mode = target_mode;
    git_oid_cpy(&updates[0].blob_oid, &target_blob_oid_copy);
    updates[1].path = METADATA_FILE_PATH;
    updates[1].mode = GIT_FILEMODE_BLOB;
    git_oid_cpy(&updates[1].blob_oid, &metadata_blob_oid);

    err = gitops_commit_tree_updates_safe(
        repo, profile, updates, 2, NULL, 0, msg, NULL
    );

cleanup:
    if (target_commit) git_commit_free(target_commit);
    if (target_tree) git_tree_free(target_tree);
    if (target_entry) git_tree_entry_free(target_entry);
    if (target_metadata) metadata_free(target_metadata);
    if (meta_to_restore) metadata_item_free(meta_to_restore);
    if (head_commit) git_commit_free(head_commit);
    if (current_metadata) metadata_free(current_metadata);
    buffer_free(&metadata_json_buf);
    if (msg) free(msg);

    return err;
}

/**
 * Revert command implementation
 */
error_t *cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);
    CHECK_NULL(opts->file_path);
    CHECK_NULL(opts->commit);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = NULL;
    char *profile = NULL;
    char *resolved_path = NULL;
    git_oid current_oid = { { 0 } };
    git_oid target_oid = { { 0 } };
    git_commit *current_commit = NULL;
    git_commit *target_commit = NULL;
    git_tree *current_tree = NULL;
    git_tree *target_tree = NULL;
    git_tree_entry *current_entry = NULL;
    git_tree_entry *target_entry = NULL;
    keymgr *keymgr = ctx->keymgr; /* Borrowed from dispatcher; NULL if encryption disabled */
    state_t *state = ctx->state;  /* Borrowed from dispatcher; do not free */
    bool user_aborted = false;

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
        repo, state, opts->file_path, opts->profile, out, &found_in_history,
        &profile, &resolved_path
    );
    if (err) goto cleanup;

    if (found_in_history) {
        output_info(
            out, OUTPUT_NORMAL,
            "File was deleted from HEAD, reverting from history"
        );
    }

    output_print(
        out, OUTPUT_VERBOSE, "Found file in profile '%s': %s\n",
        profile, resolved_path
    );

    /* Step 3: Resolve target commit */
    output_print(
        out, OUTPUT_VERBOSE, "Resolving target commit '%s'...\n",
        opts->commit
    );

    err = gitops_resolve_commit_in_branch(
        repo, profile, opts->commit, &target_oid, &target_commit
    );
    if (err) goto cleanup;

    /* Step 4: Get current HEAD commit for comparison */
    err = gitops_resolve_commit_in_branch(
        repo, profile, "HEAD", &current_oid, &current_commit
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
                out, OUTPUT_NORMAL, "File '%s' is already at target state (no changes)",
                opts->file_path
            );
            goto cleanup;  /* Not an error, just nothing to do */
        }
    }

    /* Step 6: Show preview (always, including dry-run) */
    output_styled(out, OUTPUT_NORMAL, "\n{bold}Revert preview:{reset}\n");

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), &target_oid);

    const git_signature *author = git_commit_author(target_commit);
    time_t commit_time = (time_t) author->when.time;
    struct tm *tm_info = localtime(&commit_time);

    char time_buf[64];
    if (tm_info) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(time_buf, sizeof(time_buf), "<invalid time>");
    }

    output_styled(
        out, OUTPUT_NORMAL, "  Profile: {cyan}%s{reset}\n",
        profile
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
        output_newline(out, OUTPUT_NORMAL);
        output_styled(
            out, OUTPUT_NORMAL,
            "{green}Restoring deleted file from commit history{reset}\n"
        );
    } else {
        /* File exists - show detailed diff preview with decryption support.
         * The content layer classifies each blob by its own bytes, so the
         * "current vs target may differ in encryption state" case is handled
         * inside show_diff_preview without caller-side metadata gymnastics. */
        err = show_diff_preview(
            repo, resolved_path, profile, keymgr, current_blob_oid,
            target_blob_oid, out
        );
        if (err) {
            /* Non-fatal: the revert itself doesn't need decryption (copies blobs).
             * Show warning and continue to confirmation — user decides. */
            output_warning(
                out, OUTPUT_NORMAL, "Could not show diff preview: %s",
                error_message(err)
            );
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
        output_info(out, OUTPUT_NORMAL, "\nDry-run mode: No changes made");
        goto cleanup;
    }

    /* Step 8: Prompt for confirmation (unless --force or config disables) */
    if (!output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Revert file?", opts->force
        )) {
        output_info(out, OUTPUT_NORMAL, "Aborted.");
        user_aborted = true;
        goto cleanup;
    }

    /* Free current_commit (no longer needed) */
    git_commit_free(current_commit);
    current_commit = NULL;

    /* Verify branch hasn't been modified concurrently since preview */
    if (!opts->force) {
        err = verify_branch_unchanged(repo, profile, &current_oid);
        if (err) goto cleanup;
    }

    output_print(out, OUTPUT_VERBOSE, "\nReverting file...\n");

    /* Perform revert (current_oid is the pre-revert HEAD for manifest sync) */
    err = revert_file_in_branch(
        repo,
        config,
        profile,
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

    /* Check if profile is enabled. The state handle is borrowed from the
     * dispatcher (READ); the manifest sync below upgrades it to a write
     * transaction via state_begin rather than closing and reopening the db. */
    bool profile_enabled = state_has_profile(state, profile);

    if (!profile_enabled) {
        /* Profile not enabled - manifest update not needed */
        output_success(
            out, OUTPUT_NORMAL, "Reverted %s in profile '%s'",
            resolved_path, profile
        );
        output_info(
            out, OUTPUT_NORMAL, "\nNote: Profile '%s' is not enabled on this machine",
            profile
        );
        goto cleanup;
    }

    /* Get new HEAD OID (after revert) */
    git_oid new_head_oid;
    git_commit *new_head_commit = NULL;
    err = gitops_resolve_commit_in_branch(
        repo, profile, "HEAD", &new_head_oid, &new_head_commit
    );
    if (err) {
        /* Non-fatal: Git succeeded, manifest can recover */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to get new HEAD for manifest update: %s",
            error_message(err)
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        err = NULL;
        goto success;
    }
    if (new_head_commit) {
        git_commit_free(new_head_commit);
        new_head_commit = NULL;
    }

    /* Upgrade existing handle to a write transaction. profile_enabled==true
     * proved state has a live DB (state_has_profile returns false for NULL
     * state), so state_begin is safe without an additional guard. */
    err = state_begin(state);
    if (err) {
        /* Non-fatal */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to open transaction for manifest update: %s",
            error_message(err)
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync manifest"
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
            out, OUTPUT_NORMAL, "Failed to get enabled profiles: %s",
            error_message(err)
        );
        state_rollback(state);
        error_free(err);
        err = NULL;
        goto success;
    }

    /* Sync manifest via diff */
    error_t *manifest_err = manifest_sync_diff(
        repo,
        state,
        ctx->arena,
        profile,
        &current_oid,       /* Before revert (captured at step 3) */
        &new_head_oid,      /* After revert */
        enabled_profiles,
        &synced,
        &removed,
        &fallbacks,
        NULL                /* out_skipped - not applicable for revert */
    );

    if (manifest_err) {
        /* Non-fatal: Git succeeded, manifest can recover */
        output_warning(
            out, OUTPUT_NORMAL, "Manifest sync failed: %s",
            error_message(manifest_err)
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(manifest_err);
        state_rollback(state);
        string_array_free(enabled_profiles);
        goto success;
    }

    /* Commit transaction */
    err = state_commit(state);
    string_array_free(enabled_profiles);

    if (err) {
        /* Non-fatal */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to save manifest updates: %s",
            error_message(err)
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta status' or 'dotta apply' to resync manifest"
        );
        error_free(err);
        err = NULL;
        state_rollback(state);
        goto success;
    }

success:
    /* Display success message */
    output_success(
        out, OUTPUT_NORMAL, "Reverted %s in profile '%s'", resolved_path, profile
    );

    /* Show manifest sync results if available */
    if (synced > 0 || removed > 0 || fallbacks > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Manifest: %zu staged, %zu removed, %zu fallback%s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }

    /* Guide user to deploy changes */
    output_info(
        out, OUTPUT_NORMAL, "\nRun 'dotta apply' to deploy changes to filesystem"
    );

cleanup:
    if (current_entry) git_tree_entry_free(current_entry);
    if (target_entry) git_tree_entry_free(target_entry);
    if (current_tree) git_tree_free(current_tree);
    if (target_tree) git_tree_free(target_tree);
    if (current_commit) git_commit_free(current_commit);
    if (target_commit) git_commit_free(target_commit);
    if (profile) free(profile);
    if (resolved_path) free(resolved_path);

    /* Don't return error if user aborted */
    if (user_aborted) return NULL;

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 1-3 raw positionals into `profile`, `file_path`, and
 * `commit`.
 *
 * Forms (POSITIONAL_RAW min=0, max=3; commit is always required):
 *   0 args        → error "file specification is required"
 *   1 arg         → parse [profile:]<file>[@commit] via parse_refspec
 *   2 args        → <file> <commit>         when arg[1] is a git ref;
 *                   <profile> <file[@commit]> otherwise (refspec on 2nd)
 *   3 args        → <profile> <file> <commit>
 *
 * Allocation model: refspec substrings are arena-allocated; pure
 * positional pointers borrow argv. cmd_revert does not free any of
 * these pointers — the engine's arena owns their lifetime.
 *
 * A refspec that yields an explicit profile always overrides a
 * previously-set one (from -p or a positional).
 */
static error_t *revert_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_revert_options_t *o = opts_v;
    char **args = o->positional_args;

    if (o->positional_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "file specification is required"
        );
    }

    if (o->positional_count == 1) {
        /* [profile:]<file>[@commit] */
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, args[0], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse file specification");
        }
        if (rs.profile != NULL) o->profile = rs.profile;
        o->file_path = rs.file;
        if (rs.commit != NULL) o->commit = rs.commit;
    } else if (o->positional_count == 2) {
        if (str_looks_like_git_ref(args[1])) {
            /* <file> <commit> */
            o->file_path = args[0];
            o->commit = args[1];
        } else {
            /* <profile> <file[@commit]> — refspec profile wins if present. */
            o->profile = args[0];
            refspec_t rs = { 0 };
            error_t *err = parse_refspec(arena, args[1], &rs);
            if (err != NULL) {
                return error_wrap(err, "Failed to parse file specification");
            }
            if (rs.profile != NULL) o->profile = rs.profile;
            o->file_path = rs.file;
            if (rs.commit != NULL) o->commit = rs.commit;
        }
    } else if (o->positional_count == 3) {
        o->profile = args[0];
        o->file_path = args[1];
        o->commit = args[2];
    } else {
        /* Max=3 is enforced by POSITIONAL_RAW; this branch is unreachable. */
        return ERROR(ERR_INTERNAL, "revert: too many positionals");
    }

    /* A commit is required by the command; file_path is guaranteed set
     * by successful refspec parsing or explicit positional assignment. */
    if (o->commit == NULL) {
        return ERROR(
            ERR_INVALID_ARG, "commit reference is required"
        );
    }
    return NULL;
}

static error_t *revert_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_revert(ctx, (const cmd_revert_options_t *) opts_v);
}

static const args_opt_t revert_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_revert_options_t,profile,
        "Disambiguate profile when file is ambiguous"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_revert_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "f force",
        cmd_revert_options_t,force,
        "Skip confirmation and override conflicts"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_revert_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_revert_options_t,verbose,
        "Verbose output"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_revert_options_t,positional_args, positional_count,
        0,                   3
    ),
    ARGS_END,
};

const args_command_t spec_revert = {
    .name        = "revert",
    .summary     = "Revert a file to a previous version",
    .usage       =
        "%s revert [options] <file@commit>\n"
        "   or: %s revert [options] <file> <commit>\n"
        "   or: %s revert [options] <profile>:<file@commit>\n"
        "   or: %s revert [options] <profile> <file> <commit>",
    .description =
        "Restore a file's content and metadata to its state at a past\n"
        "commit. Only the Git repository is modified; run '%s apply'\n"
        "afterward to propagate to the filesystem.\n",
    .notes       =
        "Execution Order:\n"
        "  1. Locate the file in enabled profiles (exact path).\n"
        "  2. Resolve the target commit in the profile's history.\n"
        "  3. Show a diff between current and target state.\n"
        "  4. Prompt for confirmation (bypassed by --force).\n"
        "  5. Write file and metadata back to the target state.\n"
        "  6. Create a commit capturing the restoration.\n",
    .examples    =
        "  %s revert home/.bashrc HEAD~3              # Profile inferred\n"
        "  %s revert darwin home/.bashrc a4f2c8e      # Explicit profile\n"
        "  %s revert darwin:home/.bashrc@a4f2c8e      # Compact refspec\n"
        "  %s revert -m \"Fix config\" home/.bashrc HEAD~1   # Custom message\n"
        "  %s revert -n darwin home/.config/nvim/init.lua HEAD~2  # Preview\n",
    .epilogue    =
        "See also:\n"
        "  %s list <profile> <file>   # Find commit refs for a file\n"
        "  %s apply                   # Deploy the restored content\n",
    .opts_size   = sizeof(cmd_revert_options_t),
    .opts        = revert_opts,
    .post_parse  = revert_post_parse,
    .payload     = &dotta_ext_read_key,
    .dispatch    = revert_dispatch,
};
