/**
 * update.c - Update profiles with modified files
 */

#include "cmds/update.h"

#include <config.h>
#include <dirent.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "utils/commit.h"
#include "utils/hooks.h"
#include "utils/privilege.h"

/**
 * Copy file from filesystem to worktree (with optional encryption)
 *
 * @param ctx Dispatch context (must not be NULL; supplies the key and the
 *            encryption policy)
 * @param previously_encrypted Whether the file's prior bytes (the branch's
 *                             HEAD blob) were encrypted — the caller's to
 *                             source
 * @param out_was_encrypted Optional output - set to true if file was encrypted
 *                          (can be NULL)
 * @param out_stat Optional output - filled with stat data from source file (can
 *                 be NULL)
 */
static error_t *copy_file_to_worktree(
    const dotta_ctx_t *ctx,
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    bool previously_encrypted,
    bool *out_was_encrypted,
    struct stat *out_stat
) {
    CHECK_NULL(ctx);
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);

    keymgr *keymgr = ctx->run.keymgr;

    /* Initialize all resources to NULL for goto cleanup */
    char *dest_path = NULL;
    char *parent = NULL;
    char *target = NULL;
    error_t *err = NULL;

    const char *wt_path = worktree_get_path(wt);
    if (!wt_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    dest_path = str_format("%s/%s", wt_path, storage_path);
    if (!dest_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate destination path");
        goto cleanup;
    }

    /* Create parent directory */
    err = fs_get_parent_dir(dest_path, &parent);
    if (err) {
        goto cleanup;
    }

    err = fs_create_dir(parent, true);
    if (err) {
        err = error_wrap(err, "Failed to create parent directory");
        goto cleanup;
    }

    /* Remove existing file if present */
    if (fs_lexists(dest_path)) {
        err = fs_remove_file(dest_path);
        if (err) {
            err = error_wrap(err, "Failed to remove existing file");
            goto cleanup;
        }
    }

    /* Copy file (with optional encryption). One lstat decides the kind and is
     * the stat a symlink capture keeps, so the kind and the triple come from
     * the same observation. A regular file's authoritative stat is taken inside
     * content_store_file_to_worktree, beside the bytes it reads. */
    struct stat src_stat;
    if (lstat(filesystem_path, &src_stat) != 0) {
        err = ERROR(
            ERR_FS, "Failed to stat '%s': %s",
            filesystem_path, strerror(errno)
        );
        goto cleanup;
    }

    if (S_ISLNK(src_stat.st_mode)) {
        /* Handle symlink - no encryption for symlinks */
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            err = error_wrap(err, "Failed to read symlink");
            goto cleanup;
        }

        err = fs_create_symlink(target, dest_path);
        if (err) {
            err = error_wrap(err, "Failed to create symlink");
            goto cleanup;
        }

        /* The lstat above is the capture: metadata_capture_from_file detects
         * S_ISLNK from it. */
        if (out_stat) {
            *out_stat = src_stat;
        }

        /* Symlinks are never encrypted */
        if (out_was_encrypted) {
            *out_was_encrypted = false;
        }
    } else {
        /* Handle regular file - determine encryption policy using centralized
         * logic. previously_encrypted is the branch's flag for this path, the
         * caller's to source (the walk reads it off the view row). */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            ctx->config,
            storage_path,
            false,                  /* No explicit --encrypt flag in update.c */
            false,                  /* No explicit --no-encrypt flag in update.c */
            previously_encrypted,
            &should_encrypt
        );
        if (err) {
            err = error_wrap(
                err, "Failed to determine encryption policy for '%s'",
                storage_path
            );
            goto cleanup;
        }

        /* Store file to worktree (handles read → encrypt → write) and capture
         * stat + byte-derived content kind atomically.
         * ARCHITECTURE: Single lstat() inside content_store_file_to_worktree is
         * captured and propagated to caller for metadata operations, eliminating
         * a race condition.
         * INVARIANT: written_kind is byte-truth for the bytes that hit the
         * worktree; out_was_encrypted reflects byte truth, not policy. */
        struct stat file_stat;
        content_kind_t written_kind = CONTENT_PLAINTEXT;
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            profile,
            keymgr,
            should_encrypt,
            &file_stat,
            &written_kind
        );
        if (err) {
            err = error_wrap(err, "Failed to store file to worktree");
            goto cleanup;
        }

        /* Propagate stat to caller if requested */
        if (out_stat) {
            memcpy(out_stat, &file_stat, sizeof(struct stat));
        }

        /* Propagate encryption status to caller — byte-derived, NOT policy */
        if (out_was_encrypted) {
            *out_was_encrypted = (written_kind != CONTENT_PLAINTEXT);
        }
    }

cleanup:
    if (target) free(target);
    if (parent) free(parent);
    if (dest_path) free(dest_path);

    return err;
}

/**
 * Confirmation result codes
 */
typedef enum {
    CONFIRM_PROCEED,        /* Proceed with operation */
    CONFIRM_CANCELLED,      /* User cancelled */
    CONFIRM_DRY_RUN,        /* Dry run mode */
    CONFIRM_SKIP_NEW_FILES  /* Skip new files but continue */
} confirm_result_t;

/**
 * One path an update commit captured from disk
 *
 * A file's triple is the one the copy step took from the bytes it committed
 * (content_store_file_to_worktree's single lstat), so the record binds the blob
 * to the stat that matched it — not to a later lstat that could see an edit made
 * since. A directory's is unset: a directory has no content confirmation, and
 * its record carries none.
 */
typedef struct {
    const workspace_item_t *item;   /* The captured item (borrowed, workspace lifetime) */
    stat_cache_t stat;              /* The copy's triple; STAT_CACHE_UNSET for a directory */
} update_capture_t;

/**
 * What one profile's update commit did, path by path
 *
 * Filled by the walk that does the work — one writer per item: the copy +
 * capture for a file, the claim capture for a directory, the entry removal
 * for a deletion, the prune for the directory entries dropped as redundant —
 * and read back by the commit message and by the record loop
 * (update_write_record), so both follow the commit and nothing else:
 * an item the walk skipped (a directory the race guard refused) lands in no
 * list, is not named, and gets no record write.
 *
 * Items are borrowed (workspace lifetime); the pruned keys are storage paths
 * the prune copies out, resolved through the mount table by the record
 * loop — the same route remove's record loop takes.
 *
 * Memory: the caller zero-fills the struct; update_profile allocates `captured`
 * (sized to its item count, an upper bound); release with update_commits_free.
 */
typedef struct {
    const char *profile;            /* Borrowed from the item group */
    update_capture_t *captured;     /* Files copied and directory claims captured */
    size_t captured_count;
    ptr_array_t deleted;            /* Items whose deletion the commit recorded (const workspace_item_t *) */
    string_array_t pruned;          /* Directory entries dropped as redundant (storage paths) */
} update_commit_t;

/**
 * Release an array of commits — the bookkeeping, never the items.
 */
static void update_commits_free(update_commit_t *commits, size_t count) {
    if (!commits) return;
    for (size_t i = 0; i < count; i++) {
        free(commits[i].captured);
        ptr_array_deinit(&commits[i].deleted);
        string_array_deinit(&commits[i].pruned);
    }
    free(commits);
}

/**
 * Check if a workspace item's state/divergence qualifies for update
 *
 * Pure predicate — no side effects, no filtering by path/profile/exclusion.
 * Extracted to single source of truth for state eligibility logic.
 */
static bool is_update_candidate(
    const workspace_item_t *item,
    const cmd_update_options_t *opts,
    const config_t *config
) {
    /* Determine if item should be included based on state + divergence */
    switch (item->state) {
        case WORKSPACE_STATE_DEPLOYED:
            /* Deployed files/dirs with divergence - check what kind.
             *
             * An [unverified] path could not be read at load (EACCES, ELOOP,
             * EIO — both kinds): known-unactionable, so the filter refuses it
             * and cmd_update counts it, instead of admitting it for the copy
             * to crash on the same errno. */
            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                return false;
            }
            /* Any STALE item is skipped: Git moved past the blob dotta deployed,
             * and update stores bytes — the bytes on disk are old whether or
             * not a mode bit also differs. [stale] alone is apply's to resolve;
             * [modified] [stale] is the user's. */
            if (item->divergence & DIVERGENCE_STALE) {
                return false;
            }
            /* A tracked directory whose path is now a file or a symlink is never
             * captured through the type change (the walk's race guard refuses it:
             * a symlink would stat as its target and launder the target's attributes
             * into metadata). Resolution is explicit — apply --force replaces
             * it, remove untracks it — so it is not a candidate, and the preview
             * does not promise an update the executor would refuse. A file's
             * type change (file ↔ symlink) is captured as the new kind and stays
             * a candidate. */
            if (item->item_kind == PATH_KIND_DIRECTORY && (item->divergence & DIVERGENCE_TYPE)) {
                return false;
            }
            /* DEPLOYED + NONE = clean, exclude */
            return item->divergence != DIVERGENCE_NONE && !opts->only_new;

        case WORKSPACE_STATE_DELETED:
            /* File removed from filesystem - include unless --only-new */
            return !opts->only_new;

        case WORKSPACE_STATE_UNTRACKED:
            /* New files - include if:
             * - Explicit flags set (--include-new or --only-new), OR
             * - Config auto_detect_new_files is enabled (for confirmation
             *   prompt) */
            return (opts->include_new || opts->only_new || config->auto_detect_new_files);

        case WORKSPACE_STATE_UNDEPLOYED:
        case WORKSPACE_STATE_ORPHANED:
        case WORKSPACE_STATE_RELEASED:
            /* Not relevant for update command:
             * - UNDEPLOYED: handled by apply command
             * - ORPHANED: apply's — cleanup prunes it, or holds it when it was
             *   changed (never update's to commit)
             * - RELEASED: handled by apply command */
            return false;
    }

    return false;
}

/**
 * Filter workspace items relevant for update command
 *
 * Returns items that should be updated based on command options, workspace state,
 * and divergence.
 *
 * INCLUDED ITEMS (STATE + DIVERGENCE):
 * - DEPLOYED + any divergence but STALE (content/mode/ownership/encryption/type
 *   changed)
 * - DELETED state (removed from filesystem)
 * - UNTRACKED state (new files, if flags OR config->auto_detect_new_files)
 *
 * EXCLUDED ITEMS:
 * - UNDEPLOYED state (not modified, just not deployed yet - handled by apply)
 * - ORPHANED state (apply's: cleanup prunes or holds it)
 * - DEPLOYED + NONE divergence (clean, nothing to update)
 * - DEPLOYED + UNVERIFIED (a path that could not be read at load, either kind:
 *   nothing can be captured from it; cmd_update counts these and says so)
 * - DEPLOYED + STALE (Git moved since deployment: apply's work when alone, the
 *   user's conflict next to CONTENT — never committed; counted and said the
 *   same way)
 * - DEPLOYED + TYPE on a directory (a file or symlink where a tracked directory
 *   should be: apply --force's or remove's to resolve; counted and said the same
 *   way)
 *
 * CLI FILTERS APPLIED:
 * - opts->files: Only specific files (if provided)
 * - opts->exclude_patterns: Gitignore-style exclusions
 * - opts->only_new: Only untracked files (excludes modified)
 * - operation_profiles: Only items from specified profiles (CLI -p filter)
 *
 * @param ws Workspace (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param config Configuration (can be NULL, used for auto_detect_new_files)
 * @param out Output context (for verbose logging, can be NULL)
 * @param out_items Output slice (must not be NULL; entries field is heap-allocated,
 *                  caller frees with free((void *) out_items->entries))
 * @return Error or NULL on success (out_items zeroed if no matches)
 */
static error_t *filter_items_for_update(
    const workspace_t *ws,
    const cmd_update_options_t *opts,
    const scope_t *scope,
    const config_t *config,
    output_t *out,
    workspace_items_t *out_items
) {
    CHECK_NULL(ws);
    CHECK_NULL(opts);
    CHECK_NULL(scope);
    CHECK_NULL(out_items);

    *out_items = (workspace_items_t){ 0 };

    /* Get all diverged items from workspace */
    size_t all_count = 0;
    const workspace_item_t *all = workspace_get_all_diverged(ws, &all_count);

    if (!all || all_count == 0) {
        return NULL;  /* No items - not an error */
    }

    ptr_array_t matches PTR_ARRAY_AUTO = { 0 };

    for (size_t i = 0; i < all_count; i++) {
        const workspace_item_t *item = &all[i];

        if (!is_update_candidate(item, opts, config)) {
            continue;
        }

        /* Apply CLI file filter (using storage_path for canonical matching) */
        if (!scope_accepts_path(scope, item->storage_path, item->item_kind)) {
            continue;
        }

        /* Apply exclusion patterns (granular: preserves verbose "Excluded" log) */
        if (scope_is_excluded(scope, item->storage_path, item->item_kind)) {
            output_info(out, OUTPUT_VERBOSE, "Excluded: %s", item->filesystem_path);
            continue;
        }

        /* Apply profile filter (CLI -p filtering) */
        if (!scope_accepts_profile(scope, item->profile)) {
            continue;
        }

        RETURN_IF_ERROR(ptr_array_push(&matches, item));
    }

    out_items->entries = (const workspace_item_t *const *)
        ptr_array_steal(&matches, &out_items->count);

    return NULL;
}

/**
 * Update a single profile with workspace items
 *
 * One walk, one writer per item, over one metadata load (the worktree file
 * the checkout materialized — the branch's own bytes). Each arm does its
 * item's work and fills the commit's bookkeeping beside it: copy + capture +
 * stage for a file, the claim capture for a directory, the entry removal for
 * a deletion. The walk ends with the redundancy prune, one metadata save,
 * and the commit.
 *
 * Success means committed or untouched: a walk that captured nothing and
 * deleted nothing saves nothing, stages nothing, commits nothing — the
 * worktree stays exactly as checked out. A mid-walk failure returns with the
 * worktree dirty: the executor stops the run there, and the temp worktree's
 * checkout contract (a scratch tree may always be discarded) keeps any later
 * checkout safe regardless.
 *
 * @param ctx Dispatch context (must not be NULL; the copy step reads the key
 *            and the encryption policy off it)
 * @param ws Workspace (must not be NULL; the walk reads previously_encrypted
 *           off the load's view rows)
 * @param wt Worktree handle (must not be NULL, already checked out to profile
 *           branch)
 * @param profile Profile to update (must not be NULL)
 * @param items Array of workspace items to update (must not be NULL)
 * @param item_count Number of items
 * @param opts Update options (must not be NULL)
 * @param commit The commit's bookkeeping, zero-filled by the caller; the walk
 *               fills it (must not be NULL)
 * @param out_processed Output: number of items committed (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_profile(
    const dotta_ctx_t *ctx,
    const workspace_t *ws,
    worktree_handle_t *wt,
    const char *profile,
    const workspace_item_t **items,
    size_t item_count,
    const cmd_update_options_t *opts,
    update_commit_t *commit,
    size_t *out_processed
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ws);
    CHECK_NULL(wt);
    CHECK_NULL(profile);
    CHECK_NULL(items);
    CHECK_NULL(opts);
    CHECK_NULL(commit);
    CHECK_NULL(out_processed);

    output_t *out = ctx->out;

    *out_processed = 0;
    commit->profile = profile;

    if (item_count == 0) {
        return NULL;
    }

    const char *worktree_path = worktree_get_path(wt);
    if (!worktree_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    /* Initialize all resources to NULL for goto cleanup */
    git_index *index = NULL;
    metadata_t *metadata = NULL;
    char **storage_paths = NULL;
    char *message = NULL;
    error_t *err = NULL;

    /* The one metadata load: the worktree file the checkout materialized —
     * the branch's own bytes — mutated as the walk goes, saved once. */
    char *metadata_file_path = str_format("%s/%s", worktree_path, METADATA_FILE_PATH);
    if (!metadata_file_path) {
        return ERROR(ERR_MEMORY, "Failed to allocate metadata file path");
    }
    err = metadata_load_from_file(metadata_file_path, &metadata);
    free(metadata_file_path);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* No existing metadata - create new */
            error_free(err);
            err = metadata_create_empty(&metadata);
            if (err) {
                return err;
            }
        } else {
            return error_wrap(err, "Failed to load existing metadata");
        }
    }

    /* The capture list can hold every item; the walk fills it with the ones
     * that landed. */
    commit->captured = calloc(item_count, sizeof(update_capture_t));
    if (!commit->captured) {
        err = ERROR(ERR_MEMORY, "Failed to allocate capture list");
        goto cleanup;
    }

    /* Get worktree index for staging */
    err = worktree_get_index(wt, &index);
    if (err) {
        err = error_wrap(err, "Failed to get worktree index");
        goto cleanup;
    }

    size_t captured_file_count = 0;
    size_t updated_dir_count = 0;

    /* One walk, one writer per item: each arm does its item's work and fills
     * the commit's bookkeeping beside it. */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        switch (item->item_kind) {
            case PATH_KIND_FILE: {
                output_info(out, OUTPUT_VERBOSE, "  %s", item->filesystem_path);

                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    /* Remove from index (stage deletion) */
                    int git_err = git_index_remove_bypath(index, item->storage_path);
                    if (git_err < 0) {
                        err = error_from_git(git_err);
                        goto cleanup;
                    }
                    /* Remove metadata entry if it exists */
                    if (metadata_has_item(metadata, item->storage_path)) {
                        err = metadata_remove_item(metadata, item->storage_path);
                        if (err) {
                            err = error_wrap(err, "Failed to remove metadata entry");
                            goto cleanup;
                        }
                        output_info(
                            out, OUTPUT_VERBOSE, "  Removed metadata: %s",
                            item->filesystem_path
                        );
                    }
                    err = ptr_array_push(&commit->deleted, item);
                    if (err) {
                        goto cleanup;
                    }
                    continue;
                }

                /* Source of previously_encrypted: the load's view row —
                 * row->encrypted is projected at build from the same
                 * metadata.json this branch carries, so this is the branch's
                 * flag read off the frozen view instead of a second metadata
                 * load (an untracked file has no row: never previously
                 * encrypted). Under the write-time invariant the flag is
                 * byte-truth for the HEAD blob — reading it is equivalent to
                 * classifying the existing bytes, but cheaper (no fs read). */
                const manifest_row_t *row =
                    workspace_lookup(ws, item->filesystem_path);
                bool previously_encrypted = row ? row->encrypted : false;

                /* Copy to worktree and capture stat atomically */
                struct stat copy_stat;
                bool copy_encrypted = false;
                err = copy_file_to_worktree(
                    ctx, wt, item->filesystem_path, item->storage_path,
                    profile, previously_encrypted, &copy_encrypted, &copy_stat
                );
                if (err) {
                    err = error_wrap(err, "Failed to copy '%s'", item->filesystem_path);
                    goto cleanup;
                }

                /* Capture metadata from the copy's stat */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_file(
                    item->filesystem_path,
                    item->storage_path,
                    &copy_stat,
                    &meta_item
                );
                if (err) {
                    err = error_wrap(
                        err, "Failed to capture metadata for: %s",
                        item->filesystem_path
                    );
                    goto cleanup;
                }

                /* meta_item is NULL for home/ prefix symlinks (no metadata needed).
                 * Non-NULL for files and root/ prefix symlinks (ownership
                 * tracked). */
                if (meta_item) {
                    /* Only set encrypted flag for FILE kind (symlinks are never encrypted) */
                    if (meta_item->kind == METADATA_ITEM_FILE) {
                        meta_item->file.encrypted = copy_encrypted;
                    }

                    /* Say what the capture took before metadata_add_item copies
                     * and frees it */
                    bool is_encrypted = (meta_item->kind == METADATA_ITEM_FILE)
                                      ? meta_item->file.encrypted : false;
                    if (meta_item->owner || meta_item->group) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o, owner: %s:%s%s)",
                            item->filesystem_path, meta_item->mode,
                            meta_item->owner ? meta_item->owner : "?",
                            meta_item->group ? meta_item->group : "?",
                            is_encrypted ? ", encrypted" : ""
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o%s)",
                            item->filesystem_path, meta_item->mode,
                            is_encrypted ? ", encrypted" : ""
                        );
                    }

                    /* Add to metadata collection */
                    err = metadata_add_item(metadata, meta_item);
                    metadata_item_free(meta_item);

                    if (err) {
                        err = error_wrap(err, "Failed to add metadata entry");
                        goto cleanup;
                    }

                    captured_file_count++;
                }

                /* Stage file */
                int git_err = git_index_add_bypath(index, item->storage_path);
                if (git_err < 0) {
                    err = error_from_git(git_err);
                    goto cleanup;
                }

                commit->captured[commit->captured_count++] = (update_capture_t){
                    .item = item,
                    .stat = stat_cache_from_stat(&copy_stat)
                };
                break;
            }

            case PATH_KIND_DIRECTORY: {
                /* Handle deleted directories (symmetric with the file branch
                 * above). Without this, the stat() below would fail with ENOENT
                 * and the metadata entry would survive, letting the view keep
                 * claiming a directory the user just deleted. A deleted
                 * directory is a deletion: the entry's removal goes on the
                 * commit's bookkeeping like a deleted file, so the commit gate
                 * counts it, the message names it, and the record loop retires
                 * it. */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    if (metadata_has_item(metadata, item->storage_path)) {
                        err = metadata_remove_item(metadata, item->storage_path);
                        if (err) {
                            err = error_wrap(
                                err, "Failed to remove directory metadata entry"
                            );
                            goto cleanup;
                        }
                        output_info(
                            out, OUTPUT_VERBOSE, "  Removed directory metadata: %s",
                            item->filesystem_path
                        );
                        err = ptr_array_push(&commit->deleted, item);
                        if (err) {
                            goto cleanup;
                        }
                    }
                    continue;
                }

                /* lstat + S_ISDIR: the race guard. The filter refused load-time
                 * [type] and [unverified]; this refuses a change since load — a
                 * path that vanished, or a tracked directory replaced by a
                 * symlink, which would stat() as its target and launder the
                 * target's attributes into metadata. Skip; the next load
                 * classifies what now stands there. */
                struct stat dir_stat;
                if (lstat(item->filesystem_path, &dir_stat) != 0) {
                    output_warning(
                        out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                        item->filesystem_path, strerror(errno)
                    );
                    continue;
                }
                if (!S_ISDIR(dir_stat.st_mode)) {
                    output_warning(
                        out, OUTPUT_NORMAL,
                        "Skipping '%s': tracked as directory but type changed on disk",
                        item->filesystem_path
                    );
                    continue;
                }

                /* Capture directory metadata */
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_directory(
                    item->storage_path, &dir_stat, &meta_item
                );

                if (err) {
                    output_warning(
                        out, OUTPUT_VERBOSE,
                        "Failed to capture metadata for directory '%s': %s",
                        item->filesystem_path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;
                    continue;
                }

                /* Say what the capture took before metadata_add_item copies
                 * and frees it */
                if (meta_item->owner || meta_item->group) {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o, owner: %s:%s)",
                        item->filesystem_path, meta_item->mode,
                        meta_item->owner ? meta_item->owner : "?",
                        meta_item->group ? meta_item->group : "?"
                    );
                } else {
                    output_info(
                        out, OUTPUT_VERBOSE,
                        "  Updated directory metadata: %s (mode: %04o)",
                        item->filesystem_path, meta_item->mode
                    );
                }

                /* Add to metadata collection (upsert - updates if exists) */
                err = metadata_add_item(metadata, meta_item);
                metadata_item_free(meta_item);

                if (err) {
                    err = error_wrap(
                        err, "Failed to update directory metadata for '%s'",
                        item->filesystem_path
                    );
                    goto cleanup;
                }

                updated_dir_count++;
                commit->captured[commit->captured_count++] = (update_capture_t){
                    .item = item,
                    .stat = STAT_CACHE_UNSET
                };
                break;
            }
        }
    }

    /* A profile whose walk captured nothing and deleted nothing has nothing to
     * commit, and a no-commit profile leaves the worktree exactly as checked
     * out: nothing saved, nothing staged. The prune is skipped with the save —
     * imported redundancy rides whatever commit triggers the metadata rewrite,
     * never drives one. */
    size_t path_count = commit->captured_count + commit->deleted.count;
    if (path_count == 0) {
        goto cleanup;
    }

    /* Prune redundant directory entries.
     *
     * Catches the implicit-orphaning case (the DELETED branch above handles
     * explicit removals): file removals can leave a parent directory's metadata
     * entry with no anchoring descendants. Anchoring is judged against the
     * post-edit index (deletions removed, updates staged by the walk) — never
     * against metadata items, which omit unelevated symlinks. Only entries that
     * carry no actionable information are pruned — custom-attribute entries survive
     * as potential empty-dir intent. Without this, the view would keep claiming
     * the orphaned entry indefinitely. The keys go on the commit's bookkeeping:
     * the entry leaves the view by this commit, so its record is this verb's to
     * retire. */
    err = metadata_prune_directories(metadata, index, &commit->pruned);
    if (err) {
        err = error_wrap(err, "Failed to prune redundant directories");
        goto cleanup;
    }

    if (commit->pruned.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Pruned %zu redundant directory entr%s",
            commit->pruned.count, commit->pruned.count == 1 ? "y" : "ies"
        );
    }

    /* Save metadata to worktree (single save for both files and directories) */
    err = metadata_save_to_worktree(worktree_path, metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    /* Stage metadata.json file (single stage operation) */
    err = worktree_stage_file(wt, METADATA_FILE_PATH);
    if (err) {
        err = error_wrap(err, "Failed to stage metadata");
        goto cleanup;
    }

    if (captured_file_count > 0 || updated_dir_count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Updated metadata for %zu file%s and %zu director%s",
            captured_file_count, captured_file_count == 1 ? "" : "s",
            updated_dir_count, updated_dir_count == 1 ? "y" : "ies"
        );
    }

    /* Build array of storage paths for commit message: what the commit captured
     * and what it let go — the bookkeeping, so an item the walk skipped is not
     * named. */
    storage_paths = malloc(path_count * sizeof(char *));
    if (!storage_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
        goto cleanup;
    }

    size_t named = 0;
    for (size_t i = 0; i < commit->captured_count; i++) {
        storage_paths[named++] = commit->captured[i].item->storage_path;
    }
    for (size_t i = 0; i < commit->deleted.count; i++) {
        const workspace_item_t *item = commit->deleted.items[i];
        storage_paths[named++] = item->storage_path;
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_UPDATE,
        .profile       = profile,
        .files         = storage_paths,
        .file_count    = path_count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    message = build_commit_message(ctx->config, &msg_ctx);
    if (!message) {
        err = ERROR(ERR_MEMORY, "Failed to build commit message");
        goto cleanup;
    }

    /* Create commit */
    err = worktree_commit(wt, profile, message, NULL);
    if (err) {
        err = error_wrap(err, "Failed to create commit");
        goto cleanup;
    }

    *out_processed = path_count;

cleanup:
    /* Free resources in reverse order */
    if (message) free(message);
    if (storage_paths) free(storage_paths);
    if (index) git_index_free(index);
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * Write the record for the commits that landed
 *
 * Called over the commits that landed — error or no: a later profile's failure
 * invalidates nothing about an earlier profile's landed commit, so the record
 * follows each one. The view is computed, so nothing
 * projects; what update writes is the one thing only it knows about the paths
 * it committed — read off each commit's own bookkeeping (update_commit_t), so a
 * path the walk skipped gets no record write. A modified or new file was captured
 * FROM disk, so for the row its profile won in the post-commit view the record
 * advances to the just-committed blob with the stat the copy took (the next status
 * takes the fast path). A path the commit let go — a deleted item, or a directory
 * entry the walk's prune dropped as redundant — left Git by this commit: with
 * no row left at the path its record retires (nothing backs it now); with a lower
 * profile's row at the path it is a fallback — the record stays and reads
 * [reassigned] until apply deploys it. The rule "anchor only the rows this profile
 * won" is the same one add applies: a higher profile's row is its own, and its
 * record is its own. Both kinds: a directory's claim (mode, ownership) is captured
 * from disk exactly as add captures it, so the capture owns the directory the
 * same way — the ownership the orphan gate asks for on scope exit — with no stat
 * triple, a directory having no content to confirm.
 *
 * Algorithm:
 *   1. Begin write transaction on caller's handle
 *   2. Build the post-commit view once; one lookup per committed path
 *   3. Commit transaction
 *   4. Set *out_updated = true
 *
 * Preconditions:
 *   - Every entry in commits is a landed Git commit
 *   - the run's state is a live handle (DB open), borrowed from the dispatcher
 *   - commits is what update_execute_for_all_profiles returned
 *
 * Postconditions:
 *   - The record written for the committed paths as above
 *   - Transaction committed or rolled back atomically; state handle left clean
 *   - out_updated flag reflects whether the record was written
 *
 * Error Handling:
 *   - Non-fatal: Git commits succeeded and stand
 *   - On any error after begin_transaction, explicit rollback keeps state clean
 *     so the caller can continue to post-update hook and cleanup deterministically
 *   - Caller should warn user
 *
 * Performance: one view build + O(N) point lookups, N = committed paths
 *
 * @param ctx Dispatch context (must not be NULL; the repository, the state
 *            handle and the mount table come off the run, the view is built
 *            into ctx->arena)
 * @param commits One commit's bookkeeping per landed commit (may be NULL when
 *                count is 0)
 * @param commit_count Number of commits
 * @param out_updated Output flag: true if the record was written (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_write_record(
    const dotta_ctx_t *ctx,
    const update_commit_t *commits,
    size_t commit_count,
    bool *out_updated
) {
    CHECK_NULL(ctx);
    CHECK_NULL(out_updated);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    bool in_transaction = false;

    /* Initialize output */
    *out_updated = false;

    /* Begin write transaction on caller's handle */
    err = state_begin(state);
    if (err) {
        return error_wrap(err, "Failed to begin record update transaction");
    }
    in_transaction = true;

    if (commit_count == 0) {
        /* No commits to sync - commit the no-op transaction */
        goto commit;
    }

    /* The post-commit view, once */
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) goto cleanup;

    /* One lookup per committed path, both kinds; the arms of the header doc. A
     * path let go and a fallback receive no anchor: there is no disk confirmation
     * for a deleted path, and a fallback's disk content is what this profile's
     * blob was, not the fallback blob. */
    time_t now = time(NULL);
    size_t synced = 0, removed = 0, fallbacks = 0;

    for (size_t c = 0; c < commit_count; c++) {
        const update_commit_t *commit = &commits[c];

        for (size_t i = 0; i < commit->captured_count; i++) {
            const update_capture_t *capture = &commit->captured[i];
            const manifest_row_t *row = manifest_lookup(
                manifest, capture->item->filesystem_path
            );
            if (!row || strcmp(row->profile, commit->profile) != 0) continue;

            err = state_anchor(
                state, row,
                row->type == PATH_TYPE_DIRECTORY ? NULL : &capture->stat,
                now, NULL
            );
            if (err) goto cleanup;
            synced++;
        }

        /* What the commit let go: the deleted items by their own path, the pruned
         * entries by the path this profile deploys them at (UNBOUND names nothing
         * on this machine: nothing to release). */
        for (size_t i = 0; i < commit->deleted.count; i++) {
            const workspace_item_t *item = commit->deleted.items[i];
            const manifest_row_t *row = manifest_lookup(manifest, item->filesystem_path);

            if (!row) {
                err = state_retire_anchor(state, item->filesystem_path);
                if (err) goto cleanup;
                removed++;
            } else if (strcmp(row->profile, commit->profile) != 0) {
                fallbacks++;
            }
            /* else: still this profile's row — the commit did not remove it;
             * not ours to count. */
        }

        for (size_t i = 0; i < commit->pruned.count; i++) {
            mount_resolve_outcome_t outcome;
            const char *fs_path = NULL;
            err = mount_resolve(
                mounts, commit->profile, commit->pruned.items[i], ctx->arena,
                &outcome, &fs_path
            );
            if (err) goto cleanup;
            /* UNBOUND is mount_resolve's batch contract, honoured; it cannot
             * fire today — manifest_build hard-errors on an unbound custom
             * directory claim at dispatch, so a run that could prune one never
             * starts. */
            if (outcome == MOUNT_RESOLVE_UNBOUND) continue;

            const manifest_row_t *row = manifest_lookup(manifest, fs_path);
            if (!row) {
                err = state_retire_anchor(state, fs_path);
                if (err) goto cleanup;
                removed++;
            } else if (strcmp(row->profile, commit->profile) != 0) {
                fallbacks++;
            }
        }
    }

    /* Verbose summary (emit before commit so failure diagnostics still have it) */
    if (synced > 0 || removed > 0 || fallbacks > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Manifest synced: %zu staged, %zu removed, %zu fallback%s",
            synced, removed, fallbacks, fallbacks == 1 ? "" : "s"
        );
    }

commit:
    err = state_commit(state);
    if (err) {
        err = error_wrap(err, "Failed to save record updates");
        goto cleanup;
    }
    in_transaction = false;

    *out_updated = true;

cleanup:
    /* Leave state handle clean for the caller by rolling back any uncommitted
     * transaction. state_rollback is a no-op if already committed. */
    if (in_transaction) {
        state_rollback(state);
    }
    manifest_free(manifest);

    return err;
}

/**
 * Execute profile updates, in enabled-set order
 *
 * Creates a single shared worktree and reuses it for every profile update,
 * eliminating expensive worktree creation/destruction overhead. Each profile
 * is checked out into the same worktree before updating.
 *
 * Profiles are walked in enabled-set order — the model's one canonical
 * profile order — so multi-profile runs commit, report, and (on a stop)
 * strand in one predictable sequence; within a profile, items keep filter
 * order. Every item's profile is in the enabled set by construction (the
 * view is built from it), so the per-profile gather drops nothing.
 *
 * The commits that landed cross the error boundary: out_commits receives one
 * bookkeeping entry per landed commit, handed to the caller even when a later
 * profile fails, so the record write follows what Git shows. A profile that
 * committed nothing — a walk that touched nothing, or a failure before its
 * commit — contributes no entry.
 *
 * @param ctx Dispatch context (must not be NULL; the run's repository carries
 *            the shared worktree, the copy step reads the key and the
 *            encryption policy)
 * @param ws Workspace (must not be NULL; threaded to the walk for view-row
 *           reads)
 * @param enabled The enabled set, in order (must not be NULL)
 * @param update_items Pre-filtered items to update (must not be NULL)
 * @param update_count Number of items
 * @param opts Update options (must not be NULL)
 * @param total_updated Output: total items committed across all profiles (must
 *                      not be NULL)
 * @param out_commits Output: one commit's bookkeeping per landed commit; set
 *                    even on error (must not be NULL; caller frees with
 *                    update_commits_free)
 * @param out_commit_count Output: number of entries in out_commits (must not be
 *                         NULL)
 * @return Error or NULL on success
 */
static error_t *update_execute_for_all_profiles(
    const dotta_ctx_t *ctx,
    const workspace_t *ws,
    const string_array_t *enabled,
    const workspace_item_t **update_items,
    size_t update_count,
    const cmd_update_options_t *opts,
    size_t *total_updated,
    update_commit_t **out_commits,
    size_t *out_commit_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(ws);
    CHECK_NULL(enabled);
    CHECK_NULL(update_items);
    CHECK_NULL(opts);
    CHECK_NULL(total_updated);
    CHECK_NULL(out_commits);
    CHECK_NULL(out_commit_count);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    *total_updated = 0;
    *out_commits = NULL;
    *out_commit_count = 0;

    if (update_count == 0) {
        return NULL;
    }

    worktree_handle_t *wt = NULL;
    update_commit_t *commits = NULL;
    size_t commit_count = 0;
    error_t *err = NULL;

    /* Create shared temporary worktree for all profile updates */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        return error_wrap(err, "Failed to create temporary worktree");
    }

    /* One bookkeeping slot per enabled profile — an upper bound; only landed
     * commits fill one. */
    commits = calloc(enabled->count, sizeof(update_commit_t));
    if (!commits) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit bookkeeping");
        goto cleanup;
    }

    for (size_t p = 0; p < enabled->count; p++) {
        const char *profile = enabled->items[p];

        /* This profile's items, in filter order */
        ptr_array_t group PTR_ARRAY_AUTO = { 0 };
        for (size_t i = 0; i < update_count; i++) {
            if (strcmp(update_items[i]->profile, profile) == 0) {
                err = ptr_array_push(&group, update_items[i]);
                if (err) {
                    goto cleanup;
                }
            }
        }
        if (group.count == 0) {
            continue;
        }

        /* Display profile header */
        output_section(
            out, OUTPUT_NORMAL, "Updating profile '{cyan}%s{reset}':",
            profile
        );

        /* Checkout profile branch in shared worktree */
        err = worktree_checkout_branch(wt, profile);
        if (err) {
            err = error_wrap(
                err, "Failed to checkout profile '%s'",
                profile
            );
            goto cleanup;
        }

        /* Update this profile using shared worktree */
        update_commit_t bookkeeping = { 0 };
        size_t processed = 0;
        err = update_profile(
            ctx, ws, wt, profile, (const workspace_item_t **) group.items,
            group.count, opts, &bookkeeping, &processed
        );

        if (!err && processed > 0) {
            /* The commit landed: its bookkeeping is the record write's now */
            commits[commit_count++] = bookkeeping;
            *total_updated += processed;

            if (!output_is_verbose(out)) {
                output_styled(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Updated %zu item%s\n",
                    processed, processed == 1 ? "" : "s"
                );
            }
        } else {
            /* No commit landed — a walk that touched nothing, or a failure
             * before the commit: the bookkeeping describes nothing */
            free(bookkeeping.captured);
            ptr_array_deinit(&bookkeeping.deleted);
            string_array_deinit(&bookkeeping.pruned);
        }

        if (err) {
            err = error_wrap(
                err, "Failed to update profile '%s'",
                profile
            );
            goto cleanup;
        }
    }

cleanup:
    /* The commits that landed cross the error boundary: the caller writes the
     * record for them either way */
    *out_commits = commits;
    *out_commit_count = commit_count;
    if (wt) worktree_cleanup(&wt);

    return err;
}

/**
 * Display summary of items to be updated
 *
 * @param out Output context (must not be NULL)
 * @param items Items to display (must not be NULL)
 * @param item_count Number of items
 * @param opts Update options (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_display_summary(
    output_t *out,
    const workspace_item_t **items,
    size_t item_count,
    const cmd_update_options_t *opts
) {
    CHECK_NULL(out);
    CHECK_NULL(items);

    /* Early exit for empty data - not an error */
    if (item_count == 0) {
        return NULL;
    }

    /* Show dry-run banner if applicable */
    if (opts && opts->dry_run) {
        output_styled(
            out, OUTPUT_NORMAL, "{bold}Dry Run{reset} - No changes will be committed\n\n"
        );
    }

    /* Show filter context if any filters are active */
    if (opts) {
        bool has_filters = false;

        if (opts->only_new) {
            output_info(
                out, OUTPUT_NORMAL,
                "Filter: Showing only new files (--only-new)"
            );
            has_filters = true;
        } else if (opts->include_new) {
            output_info(
                out, OUTPUT_NORMAL,
                "Filter: Including new files from tracked directories (--include-new)"
            );
            has_filters = true;
        }

        if (opts->file_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Filter: Limiting to %zu specified file%s",
                opts->file_count, opts->file_count == 1 ? "" : "s"
            );
            has_filters = true;
        }

        if (opts->exclude_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Filter: Excluding %zu pattern%s",
                opts->exclude_count, opts->exclude_count == 1 ? "" : "s"
            );
            has_filters = true;
        }

        if (has_filters) {
            output_newline(out, OUTPUT_NORMAL);
        }
    }

    /* Categorize items for display */
    size_t modified_count = 0;
    size_t new_count = 0;
    size_t deleted_count = 0;
    size_t dir_count = 0;
    size_t encryption_count = 0;

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == PATH_KIND_FILE) {
            /* Count by state */
            switch (item->state) {
                case WORKSPACE_STATE_DEPLOYED:
                    /* Has some divergence (filtered items always have divergence) */
                    modified_count++;
                    /* Also count encryption divergence separately for informational display */
                    if (item->divergence & DIVERGENCE_ENCRYPTION) {
                        encryption_count++;
                    }
                    break;

                case WORKSPACE_STATE_DELETED:
                    deleted_count++;
                    break;

                case WORKSPACE_STATE_UNTRACKED:
                    new_count++;
                    break;

                case WORKSPACE_STATE_UNDEPLOYED:
                case WORKSPACE_STATE_ORPHANED:
                case WORKSPACE_STATE_RELEASED:
                    /* Should not appear in filtered results, but be defensive */
                    break;
            }
        } else if (item->item_kind == PATH_KIND_DIRECTORY) {
            dir_count++;
        }
    }

    /* Display modified files section */
    if (modified_count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified files",
            "use \"dotta update\" to commit these changes"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != PATH_KIND_FILE) {
                    continue;
                }

                /* Check if file is deployed and has divergence (filtered items
                 * never carry STALE) */
                bool is_modified = (item->state == WORKSPACE_STATE_DEPLOYED &&
                    item->divergence != DIVERGENCE_NONE);

                if (!is_modified) {
                    continue;
                }

                /* Extract tags using shared helper */
                const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                size_t tag_count;
                output_color_t color;
                char base_metadata[256];

                if (!workspace_item_extract_display_info(
                    item, tags, &tag_count, &color,
                    base_metadata, sizeof(base_metadata)
                    )) {
                    continue;
                }

                output_list_add(
                    list, tags, tag_count, color,
                    item->filesystem_path, base_metadata
                );
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display new files section */
    if (new_count > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "use \"dotta update --include-new\" to track these files"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind == PATH_KIND_FILE &&
                    item->state == WORKSPACE_STATE_UNTRACKED
                ) {
                    const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                    size_t tag_count;
                    output_color_t color;
                    char metadata[256];

                    if (workspace_item_extract_display_info(
                        item, tags, &tag_count, &color,
                        metadata, sizeof(metadata)
                        )) {
                        output_list_add(
                            list, tags, tag_count, color,
                            item->filesystem_path, metadata
                        );
                    }
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display deleted files section (if any - rare in update context) */
    if (deleted_count > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted files",
            "these files will be removed from the profile"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind == PATH_KIND_FILE &&
                    item->state == WORKSPACE_STATE_DELETED
                ) {
                    const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                    size_t tag_count;
                    output_color_t color;
                    char metadata[256];

                    if (workspace_item_extract_display_info(
                        item, tags, &tag_count, &color,
                        metadata, sizeof(metadata)
                        )) {
                        output_list_add(
                            list, tags, tag_count, color,
                            item->filesystem_path, metadata
                        );
                    }
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display modified directories section */
    if (dir_count > 0) {
        output_list_t *list = output_list_create(
            out, "Modified directories",
            "directory metadata will be updated"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != PATH_KIND_DIRECTORY) {
                    continue;
                }

                /* Extract tags and metadata using helper */
                const char *tags[WORKSPACE_ITEM_MAX_DISPLAY_TAGS];
                size_t tag_count;
                output_color_t color;
                char base_metadata[256];

                if (workspace_item_extract_display_info(
                    item, tags, &tag_count, &color,
                    base_metadata, sizeof(base_metadata)
                    )) {
                    /* Build custom content with trailing slash for directories */
                    char path_with_slash[PATH_MAX + 2];
                    snprintf(
                        path_with_slash, sizeof(path_with_slash), "%s/",
                        item->filesystem_path
                    );

                    /* Build custom metadata with explicit "directory" indicator */
                    char metadata[256];
                    snprintf(
                        metadata, sizeof(metadata), "directory %s",
                        base_metadata
                    );

                    output_list_add(
                        list, tags, tag_count, color,
                        path_with_slash, metadata
                    );
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display encryption policy violations section */
    if (encryption_count > 0) {
        output_list_t *list = output_list_create(
            out, "Encryption policy violations",
            "match auto-encrypt patterns but are stored as plaintext"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                /* DEPLOYED violators only — the set the section's count gated
                 * on: a deleted violator is in the deleted section, and its
                 * commit resolves the violation by removing the plaintext. */
                if (item->item_kind != PATH_KIND_FILE ||
                    item->state != WORKSPACE_STATE_DEPLOYED ||
                    !(item->divergence & DIVERGENCE_ENCRYPTION)) {
                    continue;
                }

                char metadata[512];
                snprintf(
                    metadata, sizeof(metadata), "from %s, will be encrypted",
                    item->profile
                );

                /* Single tag for policy violation */
                const char *tags[] = { "plaintext" };
                output_list_add(
                    list, tags, 1, OUTPUT_COLOR_RED,
                    item->filesystem_path, metadata
                );
            }

            output_list_render(list);
            output_list_free(list);
        }

        output_newline(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "These files will be encrypted on the next commit, "
            "per auto_encrypt in your config's [encryption] section."
        );
        output_info(
            out, OUTPUT_NORMAL, "To keep a file as plaintext, "
            "narrow the pattern that matches it."
        );
    }

    return NULL;
}

/**
 * Handle user confirmations for update operation
 *
 * @param out Output context (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param items Items to update (must not be NULL)
 * @param item_count Number of items
 * @param config Configuration (can be NULL)
 * @param result Output parameter for confirmation result (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_confirm_operation(
    output_t *out,
    const cmd_update_options_t *opts,
    const workspace_item_t **items,
    size_t item_count,
    const config_t *config,
    confirm_result_t *result
) {
    CHECK_NULL(out);
    CHECK_NULL(opts);
    CHECK_NULL(items);
    CHECK_NULL(result);

    *result = CONFIRM_PROCEED;

    /* Count items by category */
    size_t modified_count = 0;
    size_t deleted_count = 0;
    size_t new_count = 0;
    size_t dir_count = 0;

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        if (item->item_kind == PATH_KIND_FILE) {
            if (item->state == WORKSPACE_STATE_UNTRACKED) {
                new_count++;
            } else if (item->state == WORKSPACE_STATE_DELETED) {
                deleted_count++;
            } else {
                modified_count++;
            }
        } else if (item->item_kind == PATH_KIND_DIRECTORY) {
            dir_count++;
        }
    }

    /* Dry run - show breakdown and exit */
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "Dry run: no changes will be committed");
        if (modified_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu modified file%s to update",
                modified_count, modified_count == 1 ? "" : "s"
            );
        if (deleted_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu deleted file%s to remove",
                deleted_count, deleted_count == 1 ? "" : "s"
            );
        if (new_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu new file%s to add",
                new_count, new_count == 1 ? "" : "s"
            );
        if (dir_count > 0)
            output_info(
                out, OUTPUT_NORMAL, "  %zu director%s to update metadata",
                dir_count, dir_count == 1 ? "y" : "ies"
            );
        *result = CONFIRM_DRY_RUN;
        return NULL;
    }

    /* Interactive confirmation */
    if (opts->interactive) {
        if (!output_confirm(out, "Update these items?", false)) {
            output_info(out, OUTPUT_NORMAL, "Cancelled");
            *result = CONFIRM_CANCELLED;
            return NULL;
        }
    }

    /* Confirmation for new files (if auto-detected, not explicit flag) */
    if (new_count > 0 && config && config->confirm_new_files &&
        !opts->include_new && !opts->only_new && config->auto_detect_new_files) {

        char confirm_msg[128];
        snprintf(
            confirm_msg, sizeof(confirm_msg), "Found %zu new file%s. Add %s to profiles?",
            new_count, new_count == 1 ? "" : "s", new_count == 1 ? "it" : "them"
        );
        if (!output_confirm(out, confirm_msg, false)) {
            *result = CONFIRM_SKIP_NEW_FILES;
            return NULL;
        }
    }

    *result = CONFIRM_PROCEED;

    return NULL;
}

/**
 * Update command implementation
 */
error_t *cmd_update(const dotta_ctx_t *ctx, const cmd_update_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *content_cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources at top, initialized to NULL */
    error_t *err = NULL;
    workspace_t *ws = NULL;
    scope_t *scope = NULL;
    char *profiles_str = NULL;
    workspace_items_t update_items = { 0 };
    size_t total_updated = 0;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Build operation scope
     *
     *   scope_enabled — the persistent enabled set, the CLI filter's bound.
     *   scope_active  — update operation face (hook context string).
     *   scope_paths / scope_is_excluded — per-item gates in filter_items_for_update
     */
    scope_inputs_t scope_inputs = {
        .profiles         = opts->profiles,
        .profile_count    = opts->profile_count,
        .files            = opts->files,
        .file_count       = opts->file_count,
        .exclude_patterns = opts->exclude_patterns,
        .exclude_count    = opts->exclude_count,
    };
    err = scope_build(
        repo, state, &scope_inputs, config, mounts, ctx->arena, &scope
    );
    if (err) goto cleanup;

    if (scope_enabled(scope)->count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No enabled profiles found\n"
            "Hint: Run 'dotta profile enable <name>' to enable profiles"
        );
        goto cleanup;
    }

    /* Build hook invocation using active profile names for context */
    profiles_str = string_array_join(scope_active(scope), " ");
    if (!profiles_str) {
        err = ERROR(ERR_MEMORY, "Failed to join profile names for hook");
        goto cleanup;
    }
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_UPDATE,
        .profile    = profiles_str,
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-update hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Load workspace for update analysis
     *
     * Update processes files from the filesystem (either modified tracked files
     * or new files) and commits them to Git profiles. Analysis configuration:
     *
     * - analyze_files: Detects content and metadata changes in tracked files
     * - analyze_orphans: Disabled - update doesn't process orphaned records
     * - analyze_untracked: Discovers new files in tracked directories (when
     *   enabled)
     * - analyze_directories: Detects directory metadata changes for update
     * - analyze_encryption: Validates encryption policy for files being updated
     *
     * Orphan detection is unnecessary because update operates on view rows (files
     * from enabled profiles) and new files. Orphans (recorded but not in any
     * enabled profile) are out of scope for update operations.
     *
     * State is borrowed from the dispatcher (ctx->run.state). Read-only analysis.
     * The transaction for the record write opens later in
     * update_write_record().
     */
    workspace_load_t ws_opts = {
        .analyze_files       = true,                    /* Detect content and metadata changes */
        .analyze_orphans     = false,                   /* Update doesn't process orphaned files */
        .analyze_untracked   = (opts->include_new || opts->only_new ||
            config->auto_detect_new_files), /* Explicit flags or config auto-detect */
        .analyze_directories = true,                    /* Directory metadata change detection */
        .analyze_encryption  = true                     /* Encryption policy validation */
    };
    err = workspace_load(
        repo, state, config, content_cache, manifest, &ws_opts, ctx->arena, &ws
    );
    if (err) {
        err = error_wrap(err, "Failed to analyze workspace");
        goto cleanup;
    }

    /* Persist deployment-anchor advances from slow-path CMP_EQUAL checks
     * (self-healing optimization). Seeds the fast path for subsequent
     * status/apply/update calls, including this command's post-privilege re-exec
     * if one occurs. Non-fatal on failure — update still proceeds; just won't
     * seed the fast path.
     *
     * Files actually updated by this command get their anchor advanced separately
     * inside update_write_record(); this flush covers the clean files
     * the analysis verified but didn't modify. */
    error_t *flush_err = workspace_flush_updates(ws);
    if (flush_err) {
        error_free(flush_err);
    }

    /* Filter items for update (handles all flags and edge cases internally).
     * scope_t carries the path/profile/exclude filter dimensions. */
    err = filter_items_for_update(
        ws, opts, scope, config, out, &update_items
    );
    if (err) {
        err = error_wrap(err, "Failed to filter items for update");
        goto cleanup;
    }

    /* What the filter left out on purpose, said once — above the exit below, so
     * a workspace whose only divergence is stale explains itself, and above the
     * prompt. Same scope triplet as the filter. An [unverified] path could not
     * be read; its line names the remedies without claiming an errno (EACCES,
     * ELOOP and EIO all read the same). [stale] alone is apply's to
     * resolve; [modified] [stale] is a conflict no dotta verb resolves toward
     * disk, so its line must not send the user to a plain apply that preflight
     * will refuse. A directory with [type] is not captured through the change
     * (is_update_candidate); its line names the two verbs that resolve it. */
    size_t all_count = 0;
    const workspace_item_t *all = workspace_get_all_diverged(ws, &all_count);
    size_t unverified_skipped = 0; size_t retyped_skipped = 0;
    size_t stale_skipped = 0; size_t conflict_skipped = 0;

    for (size_t i = 0; i < all_count; i++) {
        const workspace_item_t *item = &all[i];

        if (item->state != WORKSPACE_STATE_DEPLOYED ||
            !scope_accepts_entry(scope, item->profile, item->storage_path, item->item_kind)) {
            continue;
        }
        if (item->divergence & DIVERGENCE_UNVERIFIED) {
            unverified_skipped++;
        } else if (item->item_kind == PATH_KIND_DIRECTORY && (item->divergence & DIVERGENCE_TYPE)) {
            retyped_skipped++;
        } else if (!(item->divergence & DIVERGENCE_STALE)) {
            continue;
        } else if (item->divergence & DIVERGENCE_CONTENT) {
            conflict_skipped++;
        } else {
            stale_skipped++;
        }
    }

    if (unverified_skipped > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: cannot be read — fix permissions, or exclude with -e",
            unverified_skipped, unverified_skipped == 1 ? "" : "s"
        );
    }
    if (retyped_skipped > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu director%s skipped: tracked as directory but type changed on disk — "
            "'dotta apply --force' replaces %s, 'dotta remove' untracks %s",
            retyped_skipped, retyped_skipped == 1 ? "y" : "ies",
            retyped_skipped == 1 ? "it" : "them", retyped_skipped == 1 ? "it" : "them"
        );
    }
    if (stale_skipped > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu file%s skipped: changed in Git since deployment — run 'dotta apply' first",
            stale_skipped, stale_skipped == 1 ? "" : "s"
        );
    }
    if (conflict_skipped > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu file%s skipped: changed in Git and on disk — 'dotta diff' shows "
            "Git's version against disk, 'dotta apply --force' keeps Git's",
            conflict_skipped, conflict_skipped == 1 ? "" : "s"
        );
    }

    /* Check if we have anything to update */
    if (update_items.count == 0) {
        if (opts->only_new) {
            output_info(out, OUTPUT_NORMAL, "No new files to add");
        } else if (opts->include_new) {
            output_info(out, OUTPUT_NORMAL, "No modified or new files/directories to update");
        } else {
            output_info(out, OUTPUT_NORMAL, "No modified files or directories to update");
        }
        err = NULL;  /* Not an error */
        goto cleanup;
    }

    /* PRE-FLIGHT PRIVILEGE CHECK
     *
     * This check happens AFTER finding modified files but BEFORE any write
     * operations begin. If elevation is needed, the process will re-exec with
     * sudo, and all operations will restart cleanly from main().
     *
     * NOTE: Pre-update hook may run twice on re-exec (once before privilege check,
     * once after). Hooks should be idempotent to handle this correctly.
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     */
    {
        string_array_t labels STRING_ARRAY_AUTO = { 0 };
        for (size_t i = 0; i < update_items.count; i++) {
            const workspace_item_t *item = update_items.entries[i];
            if (item->item_kind != PATH_KIND_FILE) continue;
            err = privilege_collect_label(
                &labels, item->storage_path, item->filesystem_path
            );
            if (err) goto cleanup;
        }

        /* Check privilege requirements
         *
         * If labels needing root were collected without root privileges:
         * - Interactive: Prompts user, re-execs with sudo if approved
         * - Non-interactive: Returns error with clear message
         *
         * If re-exec succeeds, this function DOES NOT RETURN. If re-exec fails
         * or user declines, returns error.
         */
        err = privilege_ensure_for_operation(
            (const char *const *) labels.items,
            labels.count,
            "update",
            opts->interactive,  /* Use existing interactive flag */
            ctx->argc,
            ctx->argv,
            out
        );

        if (err) {
            /* User declined elevation or non-interactive mode blocked it */
            goto cleanup;
        }

        /* If we reach here, privileges are OK - proceed with operation */
    }

    /* Display summary of items to update */
    err = update_display_summary(
        out, (const workspace_item_t **) update_items.entries,
        update_items.count, opts
    );
    if (err) {
        goto cleanup;
    }

    /* Handle user confirmations */
    confirm_result_t confirm_result;
    err = update_confirm_operation(
        out, opts, (const workspace_item_t **) update_items.entries,
        update_items.count, config, &confirm_result
    );
    if (err) {
        goto cleanup;
    }

    /* Handle confirmation result */
    switch (confirm_result) {
        case CONFIRM_CANCELLED:
        case CONFIRM_DRY_RUN:
            /* User cancelled or dry run - clean exit (not an error) */
            goto cleanup;

        case CONFIRM_SKIP_NEW_FILES: {
            /* User declined new files - filter them out, keep modified/deleted */
            const workspace_item_t **writable =
                (const workspace_item_t **) update_items.entries;
            size_t filtered = 0;
            for (size_t i = 0; i < update_items.count; i++) {
                if (writable[i]->state != WORKSPACE_STATE_UNTRACKED) {
                    writable[filtered++] = writable[i];
                }
            }
            update_items.count = filtered;

            if (update_items.count == 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "No modified files remaining after skipping new files"
                );
                goto cleanup;
            }
            break;
        }

        case CONFIRM_PROCEED:
            /* Continue with operation */
            break;
    }

    /* Execute profile updates, in enabled-set order. Filtered to operation
     * scope. ctx->run.keymgr is borrowed by the copy step inside per-profile
     * iteration. */
    update_commit_t *commits = NULL;
    size_t commit_count = 0;
    err = update_execute_for_all_profiles(
        ctx, ws, scope_enabled(scope),
        (const workspace_item_t **) update_items.entries,
        update_items.count, opts,
        &total_updated, &commits, &commit_count
    );

    /* Write the record — for the commits that landed, error or no
     *
     * Captured files get their record advanced because UPDATE captures them FROM
     * the filesystem (already at target locations); the view itself is computed
     * at every load and needs no update. A mid-sequence stop above changes
     * nothing here: the landed commits are Git truth and the record follows
     * them; the profiles that never committed have nothing to write.
     *
     * Non-fatal: if the record write fails, Git commits still succeeded; the
     * next status re-confirms the captured files on its slow path.
     */
    bool manifest_updated = false;
    error_t *manifest_err = update_write_record(
        ctx, commits, commit_count, &manifest_updated
    );

    /* The bookkeeping has served the record */
    update_commits_free(commits, commit_count);

    if (manifest_err) {
        /* Non-fatal: commits succeeded but the record write failed. The next
         * load reads the committed blobs from Git and re-confirms the captured
         * files against disk. */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to update the record: %s",
            error_message(manifest_err)
        );

        output_info(
            out, OUTPUT_NORMAL, "Files committed to Git successfully"
        );
        error_free(manifest_err);
        /* Continue to post-update hook and success output */
    }

    if (err) {
        /* The executor stopped mid-sequence. The commits that landed are
         * recorded (just above); say so before reporting the stop, so the
         * ✓ lines above are accounted for. */
        if (manifest_updated && commit_count > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "Manifest updated (%zu item%s synced)",
                total_updated, total_updated == 1 ? "" : "s"
            );
        }
        goto cleanup;
    }

    /* Execute post-update hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Summary (report landed commits) */
    output_newline(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Updated %zu item%s across %zu profile%s",
        total_updated, total_updated == 1 ? "" : "s",
        commit_count, commit_count == 1 ? "" : "s"
    );

    /* Record feedback. The failure case already said what happened (warning
     * above). */
    if (manifest_updated) {
        output_info(
            out, OUTPUT_NORMAL,
            "Manifest updated (%zu item%s synced)",
            total_updated, total_updated == 1 ? "" : "s"
        );
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta status' to verify state"
        );
    }

cleanup:
    free((void *) update_items.entries);  /* Free array, items are borrowed */
    if (ws) workspace_free(ws);
    if (profiles_str) free(profiles_str);
    if (scope) scope_free(scope);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `files[]` and `profiles[]`.
 *
 * Positional rule (differs from add — position-dependent):
 *   - First positional: classified as a file path or a profile name via
 *     `str_looks_like_file_path`. A file path lands in `files`; a bare name lands
 *     in `profiles`.
 *   - Remaining positionals: always file paths.
 *
 * Profiles from `-p` are already populated in `profiles` by the APPEND row; a
 * positional profile appends onto that list. Files go into a fresh arena-backed
 * array.
 */
static error_t *update_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_update_options_t *o = opts_v;

    if (o->positional_count == 0) {
        return NULL;
    }

    /* Worst case: every positional becomes a file. */
    char **files = arena_calloc(arena, o->positional_count, sizeof(char *));
    if (files == NULL) {
        return ERROR(ERR_MEMORY, "Failed to allocate file list");
    }
    size_t file_count = 0;

    for (size_t i = 0; i < o->positional_count; i++) {
        char *arg = o->positional_args[i];

        /* Only the first positional is ambiguous (profile or file). It becomes
         * a profile only if -p was not given AND it doesn't look like a file
         * path. */
        if (i == 0 && o->profile_count == 0 &&
            !str_looks_like_file_path(arg)) {
            /* Arena-backed 1-slot profile array for the positional. */
            char **profiles = arena_calloc(arena, 1, sizeof(char *));
            if (profiles == NULL) {
                return ERROR(ERR_MEMORY, "Failed to allocate profile list");
            }
            profiles[0] = arg;
            o->profiles = profiles;
            o->profile_count = 1;
            continue;
        }

        files[file_count++] = arg;
    }

    if (file_count > 0) {
        o->files = files;
        o->file_count = file_count;
    }

    return NULL;
}

/**
 * What can stand at the cursor, by the rule update_post_parse routes with:
 * an enabled profile while the first positional is still open and -p has
 * not taken it; at every position a file of the view — narrowed to what the
 * profiles named so far win — or a filesystem path.
 */
static args_want_t update_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_update_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_update_options_t, profiles)) {
        completion_profiles(ctx, out, COMPLETION_ENABLED);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m, -e: free text */
    }

    char *const *winners = o->profiles;
    size_t winner_count = o->profile_count;
    if (o->profile_count == 0) {
        if (o->positional_count == 0) {
            completion_profiles(ctx, out, COMPLETION_ENABLED);
        } else if (!str_looks_like_file_path(o->positional_args[0])) {
            winners = o->positional_args;   /* the profile slot was taken */
            winner_count = 1;
        }
    }
    completion_files(ctx, out, winners, winner_count);
    return ARGS_WANT_FILES;
}

static error_t *update_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_update(ctx, (const cmd_update_options_t *) opts_v);
}

static const args_opt_t update_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_update_options_t,message,
        "Commit message"
    ),
    ARGS_APPEND(
        "p profile",         "<name>",
        cmd_update_options_t,profiles,         profile_count,
        "Filter update to profile(s) (repeatable)"
    ),
    ARGS_APPEND(
        "e exclude",         "<pattern>",
        cmd_update_options_t,exclude_patterns, exclude_count,
        "Skip paths matching a .dottaignore-style pattern (repeatable)"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_update_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_update_options_t,interactive,
        "Prompt for confirmation before committing"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_update_options_t,verbose,
        "Verbose output"
    ),
    ARGS_FLAG(
        "include-new",
        cmd_update_options_t,include_new,
        "Also stage new files inside tracked directories"
    ),
    ARGS_FLAG(
        "only-new",
        cmd_update_options_t,only_new,
        "Stage only new files; skip modifications"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_update_options_t,positional_args,  positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_update = {
    .name         = "update",
    .summary      = "Commit filesystem changes back to profiles",
    .usage        = "%s update [options] [profile|file]...",
    .description  =
        "Commit filesystem modifications to the matching profile branches\n"
        "(the reverse direction of 'apply'). Metadata changes on root/\n"
        "files are captured alongside content.\n",
    .notes        =
        "File Detection:\n"
        "  New files inside tracked directories are included based on\n"
        "  config: core.auto_detect_new_files toggles detection,\n"
        "  security.confirm_new_files toggles the prompt. --include-new\n"
        "  and --only-new override both for this invocation.\n",
    .examples     =
        "  %s update                             # All modified files\n"
        "  %s update ~/.bashrc                   # Specific file\n"
        "  %s update -p global                   # Filter to 'global'\n"
        "  %s update --include-new               # Modified + new files\n"
        "  %s update --only-new                  # New files only\n"
        "  %s update -n                          # Preview without writing\n"
        "  %s update --exclude '*.log'           # Skip log files\n"
        "  %s update -m \"Update shell config\"    # Custom commit message\n",
    .epilogue     =
        "See also:\n"
        "  %s status          # See what will be committed\n"
        "  %s sync            # Publish committed changes to remote\n",
    .opts_size    = sizeof(cmd_update_options_t),
    .opts         = update_opts,
    .post_parse   = update_post_parse,
    .complete     = update_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = true,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .crypto   = true,
        .manifest = true,
    },
    .dispatch     = update_dispatch,
};
