/**
 * add.c - Add files to profiles
 */

#include "cmds/add.h"

#include <config.h>
#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"
#include "utils/commit.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_add_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    if (!opts->files || opts->file_count == 0) {
        return ERROR(ERR_INVALID_ARG, "At least one file is required");
    }

    return NULL;
}

/**
 * Check if path should be ignored.
 *
 * Consults two independent mechanisms in order:
 *   1. `rules` — the user's `.dottaignore` layers (baseline, profile, config,
 *      CLI) compiled into a single gitignore ruleset.
 *   2. `source_filter` — the source tree's own `.gitignore`, if the caller opted
 *      in by building a filter (typically gated on `config.respect_gitignore`).
 *
 * Either input may be NULL to skip that mechanism. Source-filter errors degrade
 * to a verbose warning and a "not excluded" verdict so an odd source repo never
 * blocks the user from adding a file they explicitly named. The gitignore evaluator
 * never fails — its verdict is applied directly.
 */
static bool is_excluded(
    const char *path,
    bool is_directory,
    const gitignore_ruleset_t *rules,
    source_filter_t *source_filter,
    output_t *out
) {
    if (!path) return false;

    if (rules && gitignore_is_ignored(rules, path, is_directory)) {
        return true;
    }

    if (source_filter) {
        bool excluded = false;
        error_t *err = source_filter_is_excluded(
            source_filter, path, is_directory, &excluded
        );
        if (err) {
            output_warning(
                out, OUTPUT_VERBOSE,
                "Source .gitignore check failed for %s: %s",
                path, error_message(err)
            );
            error_free(err);
            return false;
        }
        return excluded;
    }

    return false;
}

/**
 * Recursively collect a directory tree into the caller's accumulators.
 *
 * Appends one entry to `directories` on every successful entry (the walker is
 * the sole source of truth for directory tracking), and one entry to `files`
 * for every non-excluded non-directory child. Dedups against already-collected
 * entries so overlapping CLI args (~/.config and ~/.config/fish) don't
 * double-record — within a single walk, tree recursion visits each directory
 * exactly once, so only cross-walk duplicates are possible.
 *
 * Symlinks are never recursed into: symlink-to-dir is treated as an atomic entry
 * by the outer loop and never reaches this function.
 *
 * All pushed strings are owned by the arrays (string_array_push copies). On error,
 * partial results remain in the caller's arrays; the caller's cleanup path frees
 * them.
 */
static error_t *collect_tree(
    const char *dir_path,
    const gitignore_ruleset_t *rules,
    source_filter_t *source_filter,
    output_t *out,
    string_array_t *files,
    string_array_t *directories
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(files);
    CHECK_NULL(directories);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        return ERROR(ERR_FS, "Failed to open directory: %s", dir_path);
    }

    /* Record this directory. Classification-root skip happens later in the
     * metadata-capture phase; at collection time every walked directory is a
     * tracking candidate. */
    if (!string_array_contains(directories, dir_path)) {
        error_t *push_err = string_array_push(directories, dir_path);
        if (push_err) {
            closedir(dir);
            return push_err;
        }
    }

    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            errno = 0;  /* Clear before next readdir() */
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Determine entry type */
        bool is_symlink = fs_is_symlink(full_path);
        bool is_dir = !is_symlink && fs_is_directory(full_path);

        /* Check exclude patterns */
        if (is_excluded(full_path, is_dir, rules, source_filter, out)) {
            output_info(out, OUTPUT_VERBOSE, "Excluded: %s", full_path);
            free(full_path);
            errno = 0;
            continue;
        }

        error_t *err = NULL;
        if (is_dir) {
            /* Recurse: child pushes itself on entry. */
            err = collect_tree(
                full_path, rules, source_filter, out, files, directories
            );
        } else if (!string_array_contains(files, full_path)) {
            err = string_array_push(files, full_path);
        }
        free(full_path);
        if (err) {
            closedir(dir);
            return err;
        }
        errno = 0;
    }

    /* readdir() returns NULL on both end-of-directory and error. With errno cleared
     * before each call, non-zero errno means I/O error. */
    if (errno != 0) {
        int saved_errno = errno;
        closedir(dir);
        return ERROR(
            ERR_FS, "Error reading directory '%s': %s",
            dir_path, strerror(saved_errno)
        );
    }

    closedir(dir);
    return NULL;
}

/**
 * Add single file to worktree and capture metadata
 *
 * Handles file storage, encryption, and metadata capture in a single operation.
 * Uses stat data from content layer to eliminate race conditions.
 *
 * @param wt Worktree handle
 * @param filesystem_path Source path on filesystem
 * @param storage_path Pre-computed storage path (e.g., "home/.bashrc")
 * @param opts Command options
 * @param keymgr Key manager (for encryption, can be NULL if encryption disabled)
 * @param config Configuration (for encryption policy; can be NULL)
 * @param metadata Metadata collection (captured entry will be added here)
 * @param out Output context
 * @param out_stat The capture's stat triple — taken from the same lstat as the
 *                 bytes stored, so the record can bind the committed blob to it
 *                 (must not be NULL; unset when a symlink could not be stat'd:
 *                 the next read takes the slow path)
 * @return Error or NULL on success
 */
static error_t *add_file_to_worktree(
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const cmd_add_options_t *opts,
    keymgr *keymgr,
    const config_t *config,
    metadata_t *metadata,
    output_t *out,
    stat_cache_t *out_stat
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);
    CHECK_NULL(metadata);
    CHECK_NULL(out_stat);

    *out_stat = STAT_CACHE_UNSET;

    error_t *err = NULL;
    metadata_item_t *item = NULL;  /* Will be created from captured metadata */
    struct stat file_stat;         /* Captured from content layer */

    /* Build destination path in worktree */
    const char *wt_path = worktree_get_path(wt);
    char *dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate destination path");
    }

    /* Encryption policy priority-3 source: prior committed bytes.
     *
     * Captured here so the sniff happens BEFORE the existing-file removal below
     * — that removal would destroy the byte-truth source. The dotta worktree is
     * checked out to the profile's HEAD upstream of this call, so when dest_path
     * exists it holds the previously-committed bytes — the cheapest source of
     * byte truth for priority-3. For first-time adds dest_path does not exist
     * and the flag stays false; priorities 4/5 then decide. Only consumed in
     * the regular-file branch below (symlinks carry no encryption state to
     * maintain). */
    bool previously_encrypted = false;

    /* Handle existing files */
    if (fs_lexists(dest_path)) {
        if (!opts->force) {
            error_t *exists_err = ERROR(
                ERR_EXISTS, "File '%s' (as '%s') already exists in profile '%s'. "
                "Use --force to overwrite.", filesystem_path, storage_path,
                opts->profile
            );
            free(dest_path);
            return exists_err;
        }

        /* Sniff the prior committed bytes BEFORE removing them. Tolerate a
         * transient I/O blip on dest_path: defaulting to "no prior encryption
         * known" lets priorities 4/5 decide; the next dotta update will surface
         * any divergence. */
        content_kind_t prior_kind = CONTENT_PLAINTEXT;
        error_t *classify_err = content_classify_path(dest_path, &prior_kind);
        if (classify_err) {
            error_free(classify_err);
        } else {
            previously_encrypted = (prior_kind != CONTENT_PLAINTEXT);
        }

        err = fs_remove_file(dest_path);
        if (err) {
            error_t *wrapped = error_wrap(
                err, "Failed to remove existing file '%s' in worktree",
                dest_path
            );
            free(dest_path);
            return wrapped;
        }
    }

    /* Create parent directory */
    char *parent = NULL;
    err = fs_get_parent_dir(dest_path, &parent);
    if (err) {
        free(dest_path);
        return err;
    }

    err = fs_create_dir(parent, true);
    free(parent);
    if (err) {
        free(dest_path);
        return error_wrap(err, "Failed to create parent directory");
    }

    /* Copy file to worktree */
    if (fs_is_symlink(filesystem_path)) {
        /* Handle symlink */
        char *target = NULL;
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to read symlink '%s'",
                filesystem_path
            );
        }

        err = fs_create_symlink(target, dest_path);
        free(target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to create symlink in worktree");
        }

        /* Capture symlink ownership metadata (root/ prefix + root user only).
         * Uses lstat to get the symlink's own uid/gid, not the target's. Returns
         * NULL item for home/ prefix or non-root (no metadata needed). */
        struct stat link_stat;
        if (lstat(filesystem_path, &link_stat) == 0) {
            err = metadata_capture_from_symlink(storage_path, &link_stat, &item);
            if (err) {
                free(dest_path);
                return error_wrap(
                    err, "Failed to capture symlink metadata for '%s'",
                    filesystem_path
                );
            }
            *out_stat = stat_cache_from_stat(&link_stat);
        }

        output_info(
            out, OUTPUT_VERBOSE, "Added symlink: %s -> %s",
            filesystem_path, storage_path
        );
    } else {
        /* Regular file. previously_encrypted was captured from prior committed
         * bytes in the existing-file removal block above (force re-add) or stays
         * false (first-time add); priority-3 in the encryption policy reads byte
         * truth either way. */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            opts->encrypt_mode == ADD_ENCRYPT_FORCE_ON,
            opts->encrypt_mode == ADD_ENCRYPT_FORCE_OFF,
            previously_encrypted,
            &should_encrypt
        );
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to determine encryption policy for '%s'",
                storage_path
            );
        }

        /* Store file to worktree (handles read → encrypt → write) and capture
         * both stat data and the byte-derived content kind.
         * SECURITY: Single stat() call eliminates a race condition.
         * INVARIANT: written_kind is byte-truth for the bytes that hit the
         * worktree; metadata.encrypted is stamped from it below. */
        content_kind_t written_kind = CONTENT_PLAINTEXT;
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            opts->profile,
            keymgr,
            should_encrypt,
            &file_stat,
            &written_kind
        );
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to store file to worktree");
        }

        /* Capture metadata from file using stat data from content layer
         * SECURITY: Single stat() call eliminates race condition */
        err = metadata_capture_from_file(
            filesystem_path, storage_path, &file_stat, &item
        );
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to capture metadata for '%s'",
                filesystem_path
            );
        }
        *out_stat = stat_cache_from_stat(&file_stat);

        /* Stamp metadata.encrypted from byte truth, NOT from policy. This is
         * the write-time invariant: bytes-on-disk and the metadata cache are
         * bound at the same boundary, by construction. */
        if (item && item->kind == METADATA_ITEM_FILE) {
            item->file.encrypted = (written_kind != CONTENT_PLAINTEXT);
        }

        /* Verbose output */
        if (written_kind == CONTENT_ENCRYPTED) {
            output_info(
                out, OUTPUT_VERBOSE, "Encrypted: %s -> %s",
                filesystem_path, storage_path
            );
        }
        output_info(
            out, OUTPUT_VERBOSE, "Added: %s -> %s",
            filesystem_path, storage_path
        );
    }

    /* Stage file */
    err = worktree_stage_file(wt, storage_path);
    if (err) {
        free(dest_path);
        if (item) metadata_item_free(item);
        return error_wrap(err, "Failed to stage file");
    }

    free(dest_path);

    /* Add metadata item to collection (NULL for home/ prefix symlinks) */
    if (item) {
        /* Verbose output for metadata capture */
        if (item->owner || item->group) {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured metadata: %s (mode: %04o, owner: %s:%s)",
                filesystem_path, item->mode, item->owner ? item->owner : "?",
                item->group ? item->group : "?"
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured metadata: %s (mode: %04o)",
                filesystem_path, item->mode
            );
        }

        err = metadata_add_item(metadata, item);
        metadata_item_free(item);

        if (err) {
            return error_wrap(
                err, "Failed to add metadata item for '%s'",
                filesystem_path
            );
        }
    }

    return NULL;
}

/**
 * Create commit in worktree
 *
 * @param wt Worktree handle
 * @param opts Command options
 * @param added_files Files that were added
 * @param config Configuration
 * @param out_commit_oid Output for commit OID (optional, can be NULL)
 * @return Error or NULL on success
 */
static error_t *create_commit(
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    string_array_t *added_files,
    const mount_table_t *mounts,
    arena_t *arena,
    const config_t *config,
    git_oid *out_commit_oid
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);

    /* Build commit message using storage paths */
    string_array_t *storage_paths = string_array_new(0);
    if (!storage_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    /* Convert filesystem paths to storage paths for commit message. Files come
     * from the walker output — already absolute and existing, so the walker never
     * emits a top-level mount root. ROOT outcome is impossible here by
     * construction; treat it as a skip should the invariant ever drift. */
    error_t *err = NULL;
    for (size_t i = 0; i < added_files->count; i++) {
        const char *file_path = added_files->items[i];
        mount_classify_outcome_t outcome;
        const char *storage_path = NULL;

        err = mount_classify(
            mounts, file_path, arena, &outcome, &storage_path, NULL
        );
        if (err) {
            /* Skip if conversion fails (shouldn't happen at this point) */
            error_free(err);
            err = NULL;
            continue;
        }
        if (outcome == MOUNT_CLASSIFY_ROOT) continue;

        err = string_array_push(storage_paths, storage_path);
        if (err) {
            error_free(err);
            err = NULL;
            break;
        }
    }

    /* Build commit message context */
    commit_message_context_t ctx = {
        .action        = COMMIT_ACTION_ADD,
        .profile       = opts->profile,
        .files         = storage_paths->items,
        .file_count    = storage_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &ctx);
    string_array_free(storage_paths);

    if (!message) {
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    err = worktree_commit(wt, opts->profile, message, out_commit_oid);
    free(message);

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Write the record after a successful add operation
 *
 * Called after Git commit succeeds, for a new profile and an existing one alike.
 * Anchors the files this add captured: they were captured FROM disk, so their
 * record is anchored to the just-committed blob with the stat the capture took,
 * and the next status hits the fast path; the directories it tracked are anchored
 * by the same rule — captured, so dotta's. The view is computed, so nothing
 * projects; one build over the enabled set says which rows this profile won.
 *
 * Algorithm:
 *   1. Scope. A new profile is enabled here with its deployment target — creating
 *      a profile via add enables it, in the same transaction as the record. An
 *      existing profile has rows in the view only if it is already enabled: not
 *      enabled is success with nothing to do; when a target was given it is
 *      re-bound (UPSERT)
 *   2. Build the mount table from the post-mutation row cache
 *   3. Build the view and anchor the rows this profile won
 *   4. Commit transaction (state_save)
 *
 * CRITICAL ORDER: Step 1 must precede step 3. The target stored in step 1 is
 * what lets the mount table built in step 2 resolve custom/ storage paths for
 * the view. Transaction atomicity ensures: enable + record succeed together or
 * fail together (automatic rollback on error).
 *
 * A new branch's enabled_profiles row can pre-exist only as a leftover of a branch
 * deleted behind it. state_enable_profile is an UPSERT — the row is re-bound to
 * this add's target and keeps its position — and whatever records the old branch
 * left are orphans the next load reads, since the new HEAD does not have them.
 *
 * Target Update (existing profile):
 *   When adding custom/ files to an already-enabled profile, the target must be
 *   stored in state BEFORE the view is built — the same target-before-build
 *   ordering as the new profile's enable. Only done when target is non-NULL to
 *   avoid clearing an existing target when adding home/ or root/ files. cmd_add's
 *   pre-flight has already refused the case where target differs from any existing
 *   binding, so reaching the UPSERT means either no prior binding or an idempotent
 *   re-bind to the same value.
 *
 * Ownership:
 *   Captured rows get deployed_at = time(NULL) because ADD captures files and
 *   directories FROM the filesystem. They're already at their target locations,
 *   so deployed_at is set to indicate dotta put them there. A captured file whose
 *   record another profile's deployment had written is taken over — the write
 *   rewrites the record under this profile — and counted for the receipt: nothing
 *   later says so (apply acknowledges a reassignment the scope made, not one
 *   the user's own add made).
 *
 * Error Handling:
 *   - Profile not enabled → rollback transaction, return NULL (success, no update)
 *   - The view fails to build → rollback, return error
 *
 * Non-Fatal Integration:
 *   Caller should treat a record write failure as non-fatal warning. Git commit
 *   already succeeded; the next status reads the committed blob from Git and
 *   confirms the file on its slow path. A new profile that failed to enable is
 *   enabled by hand.
 *
 * Performance: one view build + O(N) point lookups, N = files added
 *
 * @param repo Git repository (must not be NULL)
 * @param profile Profile that files were added to (must not be NULL)
 * @param target Deployment target for custom/ files (can be NULL)
 * @param profile_was_new This add created the profile's branch: enable it here
 * @param added_files Filesystem paths that were added (must not be NULL)
 * @param added_stats The capture's stat triple per added file, aligned with
 *                    added_files (must not be NULL)
 * @param added_dirs Filesystem paths of the directories the walker passed through
 *                   (must not be NULL; a classification root among them has no
 *                   row and is skipped)
 * @param out_updated Output flag: true if the record was written (must not be NULL)
 * @param out_synced Output: count of files anchored (can be NULL)
 * @param out_taken_over Output: count of those taken over from another profile's
 *                       deployment (can be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *update_manifest_after_add(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const char *profile,
    const char *target,
    bool profile_was_new,
    const string_array_t *added_files,
    const stat_cache_t *added_stats,
    const string_array_t *added_dirs,
    bool *out_updated,
    size_t *out_synced,
    size_t *out_taken_over
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(added_stats);
    CHECK_NULL(added_dirs);
    CHECK_NULL(out_updated);

    error_t *err = NULL;

    /* Initialize output */
    *out_updated = false;
    if (out_synced) *out_synced = 0;
    if (out_taken_over) *out_taken_over = 0;

    /* STEP 1: Scope.
     *
     * CRITICAL ORDER: Must enable (or re-bind) BEFORE the view is built so target
     * is available in state for path resolution during the tree walk. The
     * deployment target is stored in the enabled_profiles table and read by the
     * mount table built below to resolve custom/ storage paths.
     *
     * Transaction Safety: If the record write below fails, the dispatcher's
     * state_free automatically rolls back this change. */
    if (profile_was_new) {
        err = state_enable_profile(state, profile, target);
        if (err) {
            return error_wrap(err, "Failed to enable profile in state");
        }
    } else {
        /* Only an enabled profile has rows in the view. Not enabled is success
         * with nothing to do; the dispatcher's state_free rolls back the untouched
         * transaction. */
        if (!state_has_profile(state, profile)) {
            return NULL;
        }
        if (target) {
            err = state_enable_profile(state, profile, target);
            if (err) {
                return error_wrap(err, "Failed to update deployment target for profile");
            }
        }
    }

    /* STEP 2: Build the view and anchor the rows this profile won.
     *
     * The builder reads the rows as STEP 1 left them — a new row, or a target
     * re-bound — so a path under the just-bound target is a custom/ row here.
     *
     * Anchor only the rows this profile won: if this profile has lower precedence
     * than existing enabled profiles, some files are another profile's rows
     * (synced_count < added_files). Those correctly receive no anchor — the row
     * is the winner's and so is its record, and the capture's stat would
     * misattribute to the winner's blob_oid. Write failures are non-fatal: disk
     * is the just-committed blob, and the next status's slow path confirms it. */
    manifest_t *manifest = NULL;
    err = manifest_build(repo, state, arena, &manifest);
    if (err) return err;

    /* The record as it stands, indexed by path, so a takeover is known before
     * the write that rewrites it. */
    anchor_t *anchors = NULL;
    size_t anchor_count = 0;
    err = state_get_all_anchors(state, arena, &anchors, &anchor_count);
    if (err) {
        manifest_free(manifest);
        return error_wrap(err, "Failed to read anchors");
    }

    hashmap_t *anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
    if (!anchor_index) {
        manifest_free(manifest);
        return ERROR(ERR_MEMORY, "Failed to create anchors index");
    }
    for (size_t i = 0; i < anchor_count; i++) {
        err = hashmap_set(anchor_index, anchors[i].filesystem_path, &anchors[i]);
        if (err) {
            hashmap_free(anchor_index, NULL);
            manifest_free(manifest);
            return error_wrap(err, "Failed to index anchors");
        }
    }

    time_t now = time(NULL);
    size_t synced_count = 0;
    size_t taken_over = 0;
    for (size_t i = 0; i < added_files->count; i++) {
        const manifest_row_t *row = manifest_lookup(manifest, added_files->items[i]);
        if (!row || strcmp(row->profile, profile) != 0) continue;

        error_t *anchor_err = state_anchor(state, row, &added_stats[i], now, NULL);
        if (anchor_err) {
            error_free(anchor_err);
            continue;
        }
        synced_count++;

        const anchor_t *was = hashmap_get(anchor_index, row->filesystem_path);
        if (was && was->deployed_at > 0 && strcmp(was->profile, profile) != 0) {
            taken_over++;
        }
    }

    /* The directories this add tracked, by the same rule: captured from disk,
     * so dotta's to prune on scope exit — the ownership the gate asks for, which
     * nothing later grants a directory that was already there (apply observes
     * those; it anchors only the ones it makes). Cleanup's emptiness rule guards
     * their contents. No stat triple: a directory has no content confirmation,
     * as apply records them. */
    for (size_t i = 0; i < added_dirs->count; i++) {
        const manifest_row_t *row = manifest_lookup(manifest, added_dirs->items[i]);
        if (!row || strcmp(row->profile, profile) != 0) continue;

        error_t *anchor_err = state_anchor(state, row, NULL, now, NULL);
        if (anchor_err) error_free(anchor_err);
    }
    hashmap_free(anchor_index, NULL);
    manifest_free(manifest);

    /* STEP 3: Commit transaction. state is borrowed from the dispatcher: if
     * state_save succeeds the transaction is committed; otherwise the dispatcher's
     * state_free rolls it back. */
    err = state_save(state);
    if (err) {
        return error_wrap(err, "Failed to save record updates");
    }

    /* Success */
    *out_updated = true;
    if (out_synced) *out_synced = synced_count;
    if (out_taken_over) *out_taken_over = taken_over;

    return NULL;
}

/**
 * Add command implementation
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);

    git_repository *repo = ctx->run.repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = validate_options(opts);
    if (err) return err;

    /* Initialize all resources to NULL for safe cleanup */
    ignore_rules_t *ignore_rules = NULL;
    const gitignore_ruleset_t *profile_rules = NULL;
    source_filter_t *source_filter = NULL;
    worktree_handle_t *wt = NULL;
    string_array_t *all_files = NULL;
    string_array_t *all_directories = NULL;
    stat_cache_t *added_stats = NULL;    /* The capture's stat triple per file in all_files (arena) */
    size_t added_count = 0;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;
    const mount_table_t *mounts = NULL;

    /* Pre-flight privilege labels. STRING_ARRAY_AUTO releases the backing buffer
     * at scope exit; the privilege call window closes inside this function (or
     * the process re-execs), so the array's lifetime is contained here. */
    string_array_t preflight_labels STRING_ARRAY_AUTO = { 0 };

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Validate deployment target if provided */
    if (opts->target) {
        err = mount_validate_target(opts->target);
        if (err) goto cleanup;

        /* Pre-flight: refuse silent re-targeting. If the profile is already enabled
         * with a different target, fail BEFORE the Git commit so the user does
         * not end up with a wasted commit + stale binding. Setting a target on
         * a profile that previously had none is fine. */
        const char *existing = state_peek_profile_target(ctx->run.state, opts->profile);
        if (existing && existing[0] != '\0' && strcmp(existing, opts->target) != 0) {
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' already has deployment target '%s'.\n"
                "Cannot change target via 'dotta add'. To re-target:\n"
                "  dotta profile disable %s\n"
                "  dotta profile enable %s --target %s",
                opts->profile, existing, opts->profile, opts->profile, opts->target
            );
            goto cleanup;
        }
    }

    /* Build the per-command mount table.
     *
     * Two modes selected by --target:
     *
     *   --target given: a single-mount table pairing opts->profile with
     *     opts->target. Other enabled profiles' bindings are deliberately excluded
     *     — narrows classification to "what would adding to THIS profile see?",
     *     so a path under another profile's --target does NOT classify as that
     *     profile's custom/ namespace. The narrow view also covers the
     *     brand-new-profile case (no row in ctx->run.mounts yet) and the
     *     existing-profile-same-target case (idempotent re-bind already verified
     *     at the pre-flight check at the top of this function).
     *
     *   --target absent: borrow ctx->run.mounts. The full enabled set covers
     *     opts->profile's existing binding (if any) plus HOME and ROOT. Paths
     *     under opts->profile's stored target classify as custom/X correctly
     *     without re-deriving the binding. */
    if (opts->target) {
        mount_table_t *local_mounts = NULL;
        mount_t mount = { .profile = opts->profile, .target = opts->target };
        err = mount_table_build(ctx->arena, &mount, 1, &local_mounts);
        if (err) {
            err = error_wrap(err, "Failed to build mount table");
            goto cleanup;
        }
        mounts = local_mounts;
    } else {
        mounts = ctx->run.mounts;
    }

    /* PRE-FLIGHT PRIVILEGE CHECK
     *
     * This check happens BEFORE any operations begin to ensure we have required
     * privileges. If elevation is needed, the process will re-exec with sudo,
     * and all operations will restart cleanly from main().
     *
     * CRITICAL: Must happen before:
     * - Hook execution (avoids double execution on re-exec)
     * - Worktree creation (avoids resource leaks)
     * - Any filesystem modifications (ensures clean restart)
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     */

    err = string_array_init_cap(&preflight_labels, opts->file_count);
    if (err) {
        err = error_wrap(err, "Failed to reserve privilege label array");
        goto cleanup;
    }

    /* Pre-compute whether deployment target lies outside the user's HOME. Every
     * input in this add invocation shares opts->target, so the answer is identical
     * for the whole batch — evaluate once, reuse below. The kind-keyed predicate
     * that consumes this mirrors privilege_needs_elevation's rule (ROOT always;
     * CUSTOM iff target outside HOME); kept inline because the precomputed bool
     * would leak the privilege module's CUSTOM-vs-ROOT branch through any public
     * helper signature. */
    bool custom_needs_elevation = opts->target
        ? !privilege_path_is_user_home(opts->target)
        : false;  /* No target → no custom/ paths → irrelevant */

    /* Collect labels for inputs whose label needs elevation. Only
     *   ownership-tracking labels are pushed — home/ never does, and custom/
     *   only does when the deployment target is outside HOME. The shape of the
     *   test is uniform across both branches: spec->tracks_ownership &&
     *   (!spec->per_profile || custom_needs_elevation)
     * — ROOT (per_profile=false) is always; CUSTOM (per_profile=true) defers to
     * the precomputed bool.
     *
     * Each input branch owns its own display string:
     *   - Storage-path input ("home/X" / "root/X" / "custom/X"): the user-typed
     *     string IS the display.
     *   - Filesystem input that classifies cleanly: the classified storage path
     *     the descendants will hit (e.g. "root/etc/hosts").
     *   - Classification root (e.g. "dotta add /"): the typed filesystem path
     *     itself. No storage tail exists for the directory-of-a-mount case, so
     *     the input path is the most informative label. */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file_path = opts->files[i];
        char *absolute = NULL;

        /* Storage-path input: the input itself is the display. */
        const mount_spec_t *spec = mount_spec_for_path(file_path);
        if (spec) {
            if (spec->tracks_ownership
                && (!spec->per_profile || custom_needs_elevation)) {
                err = string_array_push(&preflight_labels, file_path);
                if (err) goto cleanup;
            }
            continue;
        }

        /* Filesystem path — normalize raw user input to absolute path first.
         * `--target` acts as a virtual root: every typed path is resolved as if
         * the user were operating inside that directory (chroot-style). Tilde
         * inputs bypass — `~/X` always means HOME. Mount classification below
         * decides which storage namespace each path lands in (longest match),
         * which for paths under --target is custom/. */
        err = path_input_normalize(file_path, opts->target, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", file_path);
            goto cleanup;
        }

        /* Pre-flight policy: skip non-existent paths silently. The main resolution
         * loop's existence check (search "Path not found" below) is the canonical
         * user-facing surface for this error; firing it twice produces no benefit
         * and the pre-flight only exists to answer "would this op touch a path
         * needing elevation?". A non-existent path contributes nothing to that
         * question. */
        if (!fs_lexists(absolute)) {
            free(absolute);
            continue;
        }

        /* Classify the path. ROOT outcome means the input equals a mount root
         * exactly ($HOME, "/", or --target). The main loop's walker will still
         * expand its descendants — what we need here is just the spec to answer
         * "would this op touch a path needing elevation?". mount_classify writes
         * the spec in both outcomes; only the storage-path materialization
         * differs. */
        mount_classify_outcome_t outcome;
        const char *storage_path = NULL;
        err = mount_classify(
            mounts, absolute, ctx->arena, &outcome, &storage_path, &spec
        );
        free(absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", file_path);
            goto cleanup;
        }

        bool is_classification_root = (outcome == MOUNT_CLASSIFY_ROOT);

        if (spec
            && spec->tracks_ownership
            && (!spec->per_profile || custom_needs_elevation)) {
            const char *display = is_classification_root ? file_path
                                                         : storage_path;
            err = string_array_push(&preflight_labels, display);
            if (err) goto cleanup;
        }
    }

    /* Check privilege requirements
     *
     * If kinds needing root detected without root privileges:
     * - Interactive: Prompts user, re-execs with sudo if approved
     * - Non-interactive: Returns error with clear message
     *
     * If re-exec succeeds, this function DOES NOT RETURN. If re-exec fails or
     * user declines, returns error.
     */
    err = privilege_ensure_for_operation(
        (const char *const *) preflight_labels.items,
        preflight_labels.count, "add",
        true, ctx->argc, ctx->argv, out
    );

    if (err) {
        /* User declined elevation or non-interactive mode blocked it */
        goto cleanup;
    }

    /* If we reach here, privileges are OK - proceed with operation */

    /* Build ignore rules once per command.
     *
     * Fatal on failure: if we cannot build the ignore rules, proceeding would
     * risk tracking files the user explicitly told us to ignore (via baseline,
     * profile, config, or CLI). Surface the error.
     *
     * The profile-specific ruleset (which layers the profile's own `.dottaignore`
     * on top of the common layers) is resolved below, after the branch exists —
     * for a brand-new profile the builder would otherwise try to load a
     * non-existent branch (a non-error, but no point walking that code path). */
    err = ignore_rules_create(
        repo, config,
        opts->exclude_patterns, opts->exclude_count,
        ctx->arena, &ignore_rules
    );
    if (err) {
        err = error_wrap(err, "Failed to build ignore rules");
        goto cleanup;
    }

    /* Source-tree .gitignore filter (opt-in via config).
     *
     * Built once per command and shared across the whole collection walk so the
     * discovered source-repo handle is reused for every file under the same source
     * tree. A non-fatal build failure leaves source_filter NULL, which
     * is_excluded() treats as "layer skipped". */
    if (config && config->respect_gitignore) {
        err = source_filter_create(&source_filter);
        if (err) {
            err = error_wrap(err, "Failed to build source .gitignore filter");
            goto cleanup;
        }
    }

    /* Build hook invocation */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_ADD,
        .profile    = opts->profile,
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = false,
    };

    /* Execute pre-add hook */
    err = hook_fire_pre(config, out, ctx->run.repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout or create profile branch */
    bool profile_exists = false;
    err = gitops_branch_exists(repo, opts->profile, &profile_exists);
    if (err) goto cleanup;

    if (profile_exists) {
        err = worktree_checkout_branch(wt, opts->profile);
    } else {
        err = worktree_create_orphan(wt, opts->profile);
        profile_was_new = true;  /* Profile is newly created */
    }

    if (err) {
        err = error_wrap(
            err, "Failed to prepare profile branch '%s'",
            opts->profile
        );
        goto cleanup;
    }

    /* Initialize .dottaignore for new profiles */
    if (!profile_exists) {
        err = ignore_seed_profile(wt);
        if (err) {
            err = error_wrap(
                err, "Failed to initialize .dottaignore for profile '%s'",
                opts->profile
            );
            goto cleanup;
        }
        output_info(
            out, OUTPUT_VERBOSE, "Created .dottaignore for profile '%s'",
            opts->profile
        );
    }

    /* Resolve the profile-specific ruleset. Safe for both paths: existing profile
     * → loads the profile's `.dottaignore`; new profile → branch doesn't exist
     * yet, builder treats that as "no profile layer" and the common layers still
     * apply. */
    err = ignore_rules_for_profile(ignore_rules, opts->profile, &profile_rules);
    if (err) {
        err = error_wrap(
            err, "Failed to load ignore rules for profile '%s'", opts->profile
        );
        goto cleanup;
    }

    /* Collect all files to add (expanding directories). The walker appends to
     * both arrays; the caller owns both. */
    all_files = string_array_new(0);
    all_directories = string_array_new(0);
    if (!all_files || !all_directories) {
        err = ERROR(ERR_MEMORY, "Failed to allocate collection arrays");
        goto cleanup;
    }

    /* Process each input path */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file = opts->files[i];
        char *absolute = NULL;

        /* Check if input is a storage path */
        const mount_spec_t *spec = mount_spec_for_path(file);
        if (spec) {

            /* per_profile labels (custom/) require --target. Pre-validate at
             * the call site so the user gets the directive "pass --target" message
             * rather than mount_resolve's generic "no deployment target for
             * profile" surface. */
            if (spec->per_profile) {
                if (!opts->target || opts->target[0] == '\0') {
                    err = ERROR(
                        ERR_INVALID_ARG, "Storage path '%s' requires --target flag\n"
                        "Usage: dotta add -p %s --target /path/to/target %s",
                        file, opts->profile, file
                    );
                    goto cleanup;
                }
            }

            /* CLI input is the write boundary for storage-path arguments. Validate
             * the syntactic shape here so mount_resolve below can trust its input
             * — establishes the invariant once and downstream readers (manifest
             * tree-walk, sync, remove) trust it for the rest of the command. */
            err = mount_validate_storage(file);
            if (err) {
                err = error_wrap(err, "Invalid storage path '%s'", file);
                goto cleanup;
            }

            /* Convert storage path to filesystem path via the mount table. For
             * home/ and root/ the profile is ignored; for custom/ the per-profile
             * target binding is consulted. The earlier spec->per_profile
             * precondition above (--target check) guarantees the lookup binds —
             * surface a contract violation via ERR_INTERNAL if a future change
             * weakens that invariant. */
            mount_resolve_outcome_t outcome;
            const char *fs_path = NULL;
            err = mount_resolve(
                mounts, opts->profile, file, ctx->arena, &outcome, &fs_path
            );
            if (err) {
                err = error_wrap(err, "Failed to convert storage path '%s'", file);
                goto cleanup;
            }
            if (outcome != MOUNT_RESOLVE_BOUND) {
                err = ERROR(
                    ERR_INTERNAL,
                    "mount_resolve unexpectedly UNBOUND for '%s' "
                    "after --target precondition", file
                );
                goto cleanup;
            }

            /* Make absolute without following symlinks */
            err = fs_make_absolute(fs_path, &absolute);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        } else {
            /* Regular filesystem path - normalize it */
            err = path_input_normalize(file, opts->target, &absolute);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
        }

        /* Check path exists (use lexists to allow broken symlinks) */
        if (!fs_lexists(absolute)) {
            err = ERROR(ERR_NOT_FOUND, "Path not found: %s", absolute);
            free(absolute);
            goto cleanup;
        }

        /* Handle symlinks, directories, and files */
        if (!fs_is_symlink(absolute) && fs_is_directory(absolute)) {
            /* Remember counts so we can describe what the walk produced. */
            size_t files_before = all_files->count;
            size_t dirs_before = all_directories->count;

            err = collect_tree(
                absolute, profile_rules, source_filter, out,
                all_files, all_directories
            );
            if (err) {
                free(absolute);
                err = error_wrap(err, "Failed to collect from '%s'", file);
                goto cleanup;
            }

            /* Diagnostic: the walker always pushes the CLI-arg directory itself,
             * so all_directories grows by at least one. The file count reflects
             * whether anything trackable was inside. */
            if (all_files->count == files_before &&
                all_directories->count == dirs_before + 1) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Directory has no trackable contents (tracking dir only): %s",
                    absolute
                );
            } else if (all_files->count == files_before) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "All files excluded (tracking directory tree only): %s",
                    absolute
                );
            } else {
                output_info(out, OUTPUT_VERBOSE, "Added directory: %s", absolute);
            }
        } else {
            /* Single file or symlink - check if excluded */
            if (is_excluded(absolute, false, profile_rules, source_filter, out)) {
                output_info(out, OUTPUT_VERBOSE, "Excluded: %s", absolute);
                free(absolute);
                continue;
            }

            /* Add to list (dedup: skip if already collected via directory expansion) */
            if (!string_array_contains(all_files, absolute)) {
                err = string_array_push(all_files, absolute);
                if (err) {
                    free(absolute);
                    goto cleanup;
                }
            }
        }

        free(absolute);
    }

    /* Check if we have anything to add (files or directories). all_directories
     * may contain classification-root entries that Phase 3 skips, but it also
     * captures descendants — so a non-empty array is sufficient evidence that
     * the walk produced something worth committing. */
    if (all_files->count == 0 && all_directories->count == 0) {
        if (opts->exclude_count > 0) {
            err = ERROR(
                ERR_INVALID_ARG,
                "No files or directories to add (all excluded by patterns)"
            );
        } else {
            err = ERROR(ERR_INVALID_ARG, "No files or directories to add");
        }
        goto cleanup;
    }

    /* Load or create metadata collection before processing files */
    const char *worktree_path = worktree_get_path(wt);
    char *metadata_file_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_file_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
        goto cleanup;
    }

    err = metadata_load_from_file(metadata_file_path, &metadata);
    free(metadata_file_path);

    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - create new */
            error_free(err);
            err = metadata_create_empty(&metadata);
            if (err) goto cleanup;
        } else {
            /* Real error - propagate */
            err = error_wrap(err, "Failed to load existing metadata");
            goto cleanup;
        }
    }

    /* Single-pass: add files and capture metadata inline. Files come from the
     * walker output — already absolute and existing, never equal to a mount root.
     * ROOT outcome is impossible by construction; surface as ERR_INTERNAL if
     * the invariant ever drifts. Each capture's stat triple is kept, aligned
     * with all_files, for the record: it is the stat of the bytes committed,
     * which a later lstat could not promise. */
    added_stats = arena_calloc(ctx->arena, all_files->count, sizeof(*added_stats));
    if (!added_stats) {
        err = ERROR(ERR_MEMORY, "Failed to allocate capture stats");
        goto cleanup;
    }

    for (size_t i = 0; i < all_files->count; i++) {
        const char *file_path = all_files->items[i];

        /* Compute storage path once */
        mount_classify_outcome_t outcome;
        const char *storage_path = NULL;
        err = mount_classify(
            mounts, file_path, ctx->arena, &outcome, &storage_path, NULL
        );
        if (err) {
            err = error_wrap(err, "Failed to convert path '%s'", file_path);
            goto cleanup;
        }
        if (outcome != MOUNT_CLASSIFY_TAIL) {
            err = ERROR(
                ERR_INTERNAL,
                "Walker emitted classification root for '%s'", file_path
            );
            goto cleanup;
        }

        /* Validate storage path: this is the write boundary into the worktree
         * (and thence into Git). Establish the well-formed invariant here so
         * downstream readers (manifest, sync, remove) can trust the bytes they
         * read. */
        err = mount_validate_storage(storage_path);
        if (err) goto cleanup;

        /* Add file to worktree and capture metadata
         * ARCHITECTURE: add_file_to_worktree handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate
         * TOCTOU */
        err = add_file_to_worktree(
            wt, file_path, storage_path, opts, ctx->run.keymgr, config, metadata, out,
            &added_stats[i]
        );
        if (err) {
            err = error_wrap(err, "Failed to add file '%s'", file_path);
            goto cleanup;
        }
        added_count++;
    }

    /* Capture directory metadata for every walked directory.
     *
     * Iterates `all_directories` (filesystem paths produced by the walker) and
     * converts each to a storage path here. The walker records every directory
     * it walks into — including the CLI-arg top-level — so this loop captures
     * the full tree, not just the CLI-named entry points.
     *
     * Classification roots ($HOME, "/", --target) have no storage-path
     * representation: mount_classify surfaces MOUNT_CLASSIFY_ROOT and we skip
     * them by design. Their descendants are captured normally.
     */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < all_directories->count; i++) {
        const char *filesystem_path = all_directories->items[i];

        mount_classify_outcome_t outcome;
        const char *storage_path = NULL;
        err = mount_classify(
            mounts, filesystem_path, ctx->arena, &outcome, &storage_path, NULL
        );
        if (err) {
            err = error_wrap(
                err, "Failed to convert directory path '%s'", filesystem_path
            );
            goto cleanup;
        }
        if (outcome == MOUNT_CLASSIFY_ROOT) {
            /* Skip the root itself; its descendants appear as separate entries
             * and are captured normally. */
            continue;
        }

        /* Stat directory to capture mode (and ownership if root/custom). */
        struct stat dir_stat;
        if (stat(filesystem_path, &dir_stat) != 0) {
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                filesystem_path, strerror(errno)
            );
            continue;
        }

        /* Capture directory metadata using stat data */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_from_directory(storage_path, &dir_stat, &dir_item);
        if (err) {
            /* Non-fatal: log warning and continue */
            output_warning(
                out, OUTPUT_VERBOSE,
                "Failed to capture metadata for directory '%s': %s",
                filesystem_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            continue;
        }

        /* Verbose output before consuming the item */
        if (dir_item->owner || dir_item->group) {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured directory metadata: %s (mode: %04o, owner: %s:%s)",
                filesystem_path, dir_item->mode,
                dir_item->owner ? dir_item->owner : "?",
                dir_item->group ? dir_item->group : "?"
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "Captured directory metadata: %s (mode: %04o)",
                filesystem_path, dir_item->mode
            );
        }

        /* Add directory to metadata */
        err = metadata_add_item(metadata, dir_item);
        metadata_item_free(dir_item);

        if (err) {
            /* Non-fatal: log warning and continue */
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to track directory '%s': %s",
                filesystem_path, error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            dir_tracked_count++;
            output_info(
                out, OUTPUT_VERBOSE, "Tracked directory: %s -> %s",
                filesystem_path, storage_path
            );
        }
    }

    /* Save metadata to worktree */
    err = metadata_save_to_worktree(worktree_path, metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    /* Stage metadata.json file */
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        err = error_wrap(err, "Failed to stage metadata");
        goto cleanup;
    }

    /* Verbose summary */
    if (dir_tracked_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Tracked %zu director%s for change detection",
            dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
        );
    }

    /* Create commit */
    err = create_commit(wt, opts, all_files, mounts, ctx->arena, config, NULL);
    if (err) goto cleanup;

    /* Write the record - auto-enable new profiles, anchor for enabled ones
     *
     * The files were captured from disk, so their record is anchored to the
     * just-committed blob now rather than left for a later status to confirm.
     * The view itself is computed at every load and needs no update.
     *
     * For NEW profiles: Auto-enable provides intuitive UX (creating via 'add'
     * enables it). UX Decision: Creating a profile via 'add' should enable it
     * automatically. This matches user expectations: "I just added a file, it
     * should be active." For EXISTING profiles: Standard behavior (anchor only
     * if already enabled).
     *
     * Both end in the same loop: one view build says which rows this profile
     * won, and add's contribution is the anchor — the files were just captured
     * from disk, so the anchor is stamped from that capture rather than left
     * for a later status to fill in.
     *
     * Non-fatal: If the record write fails, Git commit still succeeded. A new
     * profile that failed to enable is enabled by hand; the next status confirms
     * the committed files on its slow path.
     */
    bool manifest_updated = false;
    size_t manifest_synced_count = 0;
    size_t manifest_taken_over = 0;

    error_t *manifest_err = update_manifest_after_add(
        repo, ctx->run.state, ctx->arena, opts->profile, opts->target, profile_was_new,
        all_files, added_stats, all_directories,
        &manifest_updated, &manifest_synced_count, &manifest_taken_over
    );
    if (manifest_err) {
        if (profile_was_new) {
            /* Non-fatal: Git commit succeeded, user can manually enable later */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to auto-enable profile: %s",
                error_message(manifest_err)
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to enable manually",
                opts->profile
            );
        } else {
            /* Non-fatal: Git commit succeeded */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update the record: %s",
                error_message(manifest_err)
            );
            output_info(
                out, OUTPUT_NORMAL, "Files committed to Git successfully"
            );
        }
        error_free(manifest_err);
        manifest_updated = false;
        manifest_synced_count = 0;
        manifest_taken_over = 0;
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(&wt);

    /* Execute post-add hook */
    hook_fire_post(config, out, ctx->run.repo_path, &hook_inv);

    /* Show summary on success */
    if ((added_count > 0 || dir_tracked_count > 0)) {
        /* Primary success message */
        if (added_count > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Added %zu file%s to profile '%s'",
                added_count, added_count == 1 ? "" : "s",
                opts->profile
            );
        } else {
            /* Directory-only add */
            output_success(
                out, OUTPUT_NORMAL, "Tracking %zu director%s in profile '%s'",
                dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies",
                opts->profile
            );
        }

        if (profile_was_new) {
            output_success(
                out, OUTPUT_NORMAL, "Profile '%s' created and enabled",
                opts->profile
            );
        }

        /* Show directory tracking info only when files were also added */
        if (added_count > 0 && dir_tracked_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Tracking %zu director%s for change detection",
                dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
            );
        }

        output_newline(out, OUTPUT_NORMAL);

        /* Manifest status feedback */
        if (manifest_updated) {
            if (added_count > 0) {
                /* Files were added - show sync results with precedence awareness:
                 * the rows a higher profile owns got no anchor; the ones another
                 * profile's deployment had written were taken over. */
                if (manifest_synced_count == added_count) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Manifest updated (%zu file%s marked as deployed)",
                        manifest_synced_count, manifest_synced_count == 1 ? "" : "s"
                    );
                } else {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Manifest updated (%zu/%zu file%s marked as deployed)",
                        manifest_synced_count, added_count, added_count == 1 ? "" : "s"
                    );

                    size_t skipped = added_count - manifest_synced_count;
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s overridden by higher-precedence profiles",
                        skipped, skipped == 1 ? "" : "s"
                    );
                }
                if (manifest_taken_over > 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s taken over from other profiles",
                        manifest_taken_over, manifest_taken_over == 1 ? "" : "s"
                    );
                }
                if (!profile_was_new) {
                    /* Existing enabled profile */
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "Files captured from filesystem (already deployed)"
                    );
                }
            } else {
                /* Directory-only add */
                output_info(
                    out, OUTPUT_NORMAL, "Manifest updated (%zu director%s synced)",
                    dir_tracked_count, dir_tracked_count == 1 ? "y" : "ies"
                );
            }
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta status' to verify");
        } else {
            /* Existing disabled profile - original behavior */
            output_info(
                out, OUTPUT_NORMAL, "Profile not enabled - manifest not updated"
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to activate and deploy",
                opts->profile
            );
        }
    }

cleanup:
    /* Free resources in reverse order of allocation */
    if (metadata) metadata_free(metadata);
    if (all_directories) string_array_free(all_directories);
    if (all_files) string_array_free(all_files);
    if (wt) worktree_cleanup(&wt);
    source_filter_free(source_filter);
    ignore_rules_free(ignore_rules);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `files[]`.
 *
 * Two legacy-compatible cases:
 *   1. -p/--profile was given: every positional is a file path.
 *   2. -p not given: first positional is the profile, rest are files.
 *
 * The count check lives here, after the routing, so the error message can
 * reference the effective invariant rather than a raw count.
 */
static error_t *add_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_add_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->files = o->positional_args;
        o->file_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->files = o->positional_args + 1;
        o->file_count = o->positional_count - 1;
    }

    if (o->file_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "at least one file is required"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, read off the buckets add_post_parse routes:
 * a local profile in the profile slot — the first positional, unless -p
 * took it — then filesystem paths, listed under --target when one re-roots
 * them. A new profile's name is typed, not offered.
 */
static args_want_t add_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_add_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_add_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (ARGS_VALUE_IS(at, cmd_add_options_t, target)) {
        return ARGS_WANT_DIRS;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m, -e: free text */
    }

    if (o->profile == NULL && o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    return completion_paths_under(out, o->target, at->current)
        ? ARGS_WANT_NONE : ARGS_WANT_FILES;
}

static error_t *add_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_add(ctx, (const cmd_add_options_t *) opts_v);
}

static const args_opt_t add_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",          "<name>",
        cmd_add_options_t,    profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "target",             "<path>",
        cmd_add_options_t,    target,
        "Declare a relocatable storage root"
    ),
    ARGS_STRING(
        "m message",          "<msg>",
        cmd_add_options_t,    message,
        "Commit message"
    ),
    ARGS_APPEND(
        "e exclude",          "<pattern>",
        cmd_add_options_t,    exclude_patterns, exclude_count,
        "Skip matching files (glob, repeatable)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_add_options_t,    force,
        "Overwrite existing entries in the profile"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_add_options_t,    verbose,
        "Verbose output"
    ),
    ARGS_FLAG_SET(
        "encrypt",
        cmd_add_options_t,    encrypt_mode,
        ADD_ENCRYPT_FORCE_ON,
        "Force encryption for the given files"
    ),
    ARGS_FLAG_SET(
        "no-encrypt",
        cmd_add_options_t,    encrypt_mode,
        ADD_ENCRYPT_FORCE_OFF,
        "Bypass auto-encryption patterns"
    ),
    /* <profile> <file|dir>... — order-dependent, first is profile. Mirrors clone's
     * raw-bucket-plus-post_parse approach. */
    ARGS_POSITIONAL_RAW(
        cmd_add_options_t,    positional_args,  positional_count,
        0,                    0
    ),
    ARGS_END,
};

const args_command_t spec_add = {
    .name        = "add",
    .summary     = "Add files or directories to a profile",
    .usage       =
        "%s add [options] <profile> <file|dir>...\n"
        "   or: %s add [options] --profile <name> <file|dir>...",
    .description =
        "Import files or directories into a profile branch. The storage\n"
        "prefix derives from the source path — home/ under $HOME, root/\n"
        "otherwise — unless --target declares a relocatable root, in\n"
        "which case files are stored as custom/<path-relative-to-root>.\n"
        "Metadata (mode, owner) is captured outside HOME.\n",
    .notes       =
        "Exclude Patterns:\n"
        "  Glob syntax with *, ?, [abc]. Flag is repeatable.\n"
        "    --exclude '*.log'                    # Skip .log files\n"
        "    --exclude '.git/*'                   # Skip .git directory\n"
        "    --exclude '*.log' --exclude '*.tmp'  # Multiple patterns\n",
    .examples    =
        "  %s add global ~/.bashrc                   # Basic add\n"
        "  %s add darwin ~/.config/nvim              # Directory\n"
        "  %s add global ~/.ssh/config -e '*.pub'    # With exclude\n"
        "  %s add global ~/.ssh/id_rsa --encrypt     # Force encryption\n"
        "  %s add web /mnt/jails/web/nginx.conf --target /mnt/jails/web\n",
    .epilogue    =
        "See also:\n"
        "  %s key set                 # Set encryption passphrase\n"
        "  %s apply                   # Deploy the new entries\n",
    .opts_size   = sizeof(cmd_add_options_t),
    .opts        = add_opts,
    .post_parse  = add_post_parse,
    .complete    = add_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = true,
        .state   = DOTTA_STATE_WRITE,
        .mounts  = true,
        .crypto  = true,
    },
    .dispatch    = add_dispatch,
};
