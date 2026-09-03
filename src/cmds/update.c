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
#include "sys/identity.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * Copy file from filesystem to worktree (with optional encryption)
 *
 * @param ctx Dispatch context (must not be NULL; supplies the key and the
 *            encryption policy)
 * @param previously_encrypted Whether the file's prior bytes (the branch's HEAD
 *                             blob) were encrypted — the caller's to source
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
    if (fs_lstat(filesystem_path, &src_stat) != 0) {
        err = error_from_errno(errno, "Failed to stat '%s'", filesystem_path);
        goto cleanup;
    }

    if (S_ISLNK(src_stat.st_mode)) {
        /* Handle symlink - no encryption for symlinks */
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            err = error_wrap(err, "Failed to read symlink");
            goto cleanup;
        }

        err = fs_create_symlink(target, dest_path, (uid_t) -1, (gid_t) -1);
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
            ENCRYPTION_REQUEST_NONE,  /* update carries no encryption flags */
            previously_encrypted,
            &should_encrypt
        );
        if (err) {
            goto cleanup;
        }

        /* Store file to worktree (handles read → encrypt → write) and capture
         * the stat.
         * ARCHITECTURE: the store's fstat of the descriptor it read is captured
         * and propagated to caller for metadata operations — bytes and stat one
         * inode by construction. */
        struct stat file_stat;
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            profile,
            keymgr,
            should_encrypt,
            &file_stat
        );
        if (err) {
            err = error_wrap(err, "Failed to store file to worktree");
            goto cleanup;
        }

        /* Propagate stat to caller if requested */
        if (out_stat) {
            memcpy(out_stat, &file_stat, sizeof(struct stat));
        }

        /* The store's write-time invariant: the bytes it wrote classify as the
         * decision says (a plaintext that would not is refused there), so the
         * decision is what the caller stamps. */
        if (out_was_encrypted) {
            *out_was_encrypted = should_encrypt;
        }
    }

cleanup:
    if (target) free(target);
    if (parent) free(parent);
    if (dest_path) free(dest_path);

    return err;
}

/**
 * The plan's shape, counted once
 *
 * Filled by one walk over the partition's accepted items; the preview gates its
 * sections on these and the new-files prompt binds on new_files. Buckets follow
 * the preview's sections: the modified fate splits by kind (a directory's
 * modification is a claim recapture, not a content commit), deleted deliberately
 * does not (a deleted directory is a deletion), and the deployed files split by
 * divergence family (types.h): a path-family bit is a modification, the blob-family
 * ENCRYPTION bit is a policy violation. A file with both diverged families counts
 * in both; a violator with nothing changed on disk counts only as a violation —
 * it is committed for the re-store, not for a modification.
 */
typedef struct {
    size_t modified_files;  /* DEPLOYED files with a path-family bit: divergent content or metadata */
    size_t new_files;       /* UNTRACKED files from tracked directories */
    size_t deleted;         /* DELETED paths, both kinds */
    size_t modified_dirs;   /* DEPLOYED directories: claim capture */
    size_t encryption;      /* DEPLOYED policy violators (either family beside it or alone) */
} update_counts_t;

/**
 * One path an update commit captured from disk
 *
 * A file's triple is the one the copy step took from the bytes it committed
 * (content_store_file_to_worktree's fstat of the fd it read), so the record binds
 * the blob to the stat that matched it — not to a later lstat that could see an
 * edit made since. A directory's is unset: a directory has no content confirmation,
 * and its record carries none.
 */
typedef struct {
    const workspace_item_t *item;   /* The captured item (borrowed, workspace lifetime) */
    stat_cache_t stat;              /* The copy's triple; STAT_CACHE_UNSET for a directory */
} update_capture_t;

/**
 * What one profile's update commit did, path by path
 *
 * Filled by the walk that does the work — one writer per item: the copy + capture
 * for a file, the claim capture for a directory, the entry removal for a deletion,
 * the ancestry derivation for the chains it climbed, the prune for the directory
 * entries dropped as redundant — and read back by the commit message and by the
 * record loop (update_write_record), so both follow the commit and nothing else:
 * an item the walk skipped (a directory the race guard refused) lands in no list,
 * is not named, and gets no record write.
 *
 * Items are borrowed (workspace lifetime); the pruned and retired keys are storage
 * paths their writers copy out, resolved through the mount table by the record
 * loop — the same route remove's record loop takes. The derivation's two outs
 * are shaped by what a reader can do with them (metadata.h): an authored claim
 * has no consequence beyond the sheet, so `claimed` is the count the commit gate
 * and the receipt read, while a dropped claim leaves the view by this commit
 * and only its key can settle the record it strands.
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
    size_t claimed;                 /* Ancestor claims the derivation authored or refreshed */
    string_array_t retired;         /* Ancestor claims the derivation dropped (storage paths) */
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
        string_array_deinit(&commits[i].retired);
    }
    free(commits);
}

/**
 * What the filter made of the diverged spine, in scope
 *
 * One walk partitions every in-scope item three ways. Accepted — the run's work:
 * a deployed item on the capture route, a deleted path, a new file under a tracked
 * directory when a flag or the config asked for it. Refused — a deployed item
 * on any other route (workspace_item_route), counted under that route so the
 * census names the table's own reason; a multi-bit divergence counts under the
 * route that refused it. Or neither — a state that is another verb's, and, under
 * --only-new, every deployed and deleted item: the user asked about new files,
 * nothing about the others answers that, so none is accepted and none is counted
 * (a refused route would name a reason the user did not ask for).
 *
 * The equation: in-scope deployed items = accepted deployed ∪ Σ refused[arm],
 * by one switch that routes each item once — nothing is counted twice, nothing
 * falls through. CAPTURE's slot stays zero (that arm is accepted) and CLEAN's
 * (a clean row is no item); REASSIGNED's counts a handover the census has no
 * line for — apply acknowledges it, the filter only declines it.
 */
typedef struct {
    workspace_items_t accepted;              /* The run's work; entries heap-owned, the caller frees */
    size_t refused[WORKSPACE_ROUTE_COUNT];   /* In scope, deployed, refused — by the route that refused it */
} update_partition_t;

/**
 * Partition the workspace's diverged items for update
 *
 * The scope triplet first — the user's paths, minus the patterns they excluded,
 * from the profiles they named — as three calls so the exclude arm keeps its
 * verbose log; the log is the pattern's, and fires for every in-scope item the
 * pattern hits whatever the state rule then says of it. Then the state rule under
 * the flags, and for a deployed item the route: the partition (update_partition_t).
 *
 * @param ws Workspace (must not be NULL)
 * @param opts Update options (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param config Configuration (must not be NULL; auto_detect_new_files admits
 *               new files for the consent prompt)
 * @param out Output context (for the verbose "Excluded" log, can be NULL)
 * @param partition Output, zeroed then filled; accepted.entries is heap-allocated
 *                  and the caller frees it with free((void *) entries) (must
 *                  not be NULL)
 * @return Error or NULL on success
 */
static error_t *filter_items_for_update(
    const workspace_t *ws,
    const cmd_update_options_t *opts,
    const scope_t *scope,
    const config_t *config,
    output_t *out,
    update_partition_t *partition
) {
    CHECK_NULL(ws);
    CHECK_NULL(opts);
    CHECK_NULL(scope);
    CHECK_NULL(config);
    CHECK_NULL(partition);

    *partition = (update_partition_t){ 0 };

    workspace_items_t all = workspace_get_all_diverged(ws);
    ptr_array_t accepted PTR_ARRAY_AUTO = { 0 };

    for (size_t i = 0; i < all.count; i++) {
        const workspace_item_t *item = all.entries[i];

        /* The scope triplet, on the storage path (canonical matching) */
        if (!scope_accepts_path(scope, item->storage_path, item->item_kind)) {
            continue;
        }
        if (scope_is_excluded(scope, item->storage_path, item->item_kind)) {
            output_info(out, OUTPUT_VERBOSE, "Excluded: %s", item->filesystem_path);
            continue;
        }
        if (!scope_accepts_profile(scope, item->profile)) {
            continue;
        }

        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED: {
                /* The route table partitions the deployed items — the same producer
                 * status's sections and sync's guard read (workspace_item_route;
                 * workspace.h carries each arm's why). CAPTURE is the one arm
                 * update commits; every other arm is refused and counted under
                 * its route, so the preview never promises an update the executor
                 * would refuse and the census says why in the table's words.
                 * Under --only-new the user asked about new files alone: neither
                 * accepted nor counted. */
                if (opts->only_new) continue;
                workspace_route_t route = workspace_item_route(item);
                if (route != WORKSPACE_ROUTE_CAPTURE) {
                    partition->refused[route]++;
                    continue;
                }
                break;
            }

            case WORKSPACE_STATE_DELETED:
                /* Removed from disk since deployment: the deletion is update's
                 * to commit, unless the user asked about new files alone */
                if (opts->only_new) continue;
                break;

            case WORKSPACE_STATE_UNTRACKED:
                /* A new file under a tracked directory: by flag (--include-new,
                 * --only-new), or by config, for the consent prompt */
                if (!opts->include_new && !opts->only_new &&
                    !config->auto_detect_new_files) {
                    continue;
                }
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
                /* Another verb's: not deployed yet (apply's), or a record the
                 * view lacks (cleanup prunes or releases it; never update's to
                 * commit) */
                continue;
        }

        RETURN_IF_ERROR(ptr_array_push(&accepted, item));
    }

    partition->accepted.entries = (const workspace_item_t *const *)
        ptr_array_steal(&accepted, &partition->accepted.count);

    return NULL;
}

/**
 * Update a single profile with workspace items
 *
 * One walk, one writer per item, over one metadata load (the worktree file the
 * checkout materialized — the branch's own bytes). Each arm does its item's work
 * and fills the commit's bookkeeping beside it: copy + capture + stage for a
 * file, the claim capture for a directory, the entry removal for a deletion.
 * The chain rides the capture: after the walk, every captured leaf's ancestry
 * is re-derived into the same sheet — the content now comes from this machine,
 * and so does its way — and a named run hands in the profile's in-scope rows,
 * each a leaf whose chain is climbed whether or not anything about it diverged.
 * The walk ends with the redundancy prune, one metadata save, and the commit.
 *
 * Success means committed or untouched: a walk that captured nothing and deleted
 * nothing saves nothing, stages nothing, commits nothing — the worktree stays
 * exactly as checked out. A mid-walk failure returns with the worktree dirty:
 * the executor stops the run there, and the temp worktree's checkout contract
 * (a scratch tree may always be discarded) keeps any later checkout safe
 * regardless.
 *
 * @param ctx Dispatch context (must not be NULL; the copy step reads the key
 *            and the encryption policy off it)
 * @param wt Worktree handle (must not be NULL, already checked out to profile
 *           branch)
 * @param profile Profile to update (must not be NULL)
 * @param items Array of workspace items to update (may be NULL when item_count
 *              is 0)
 * @param item_count Number of items
 * @param rows The named run's in-scope view rows for this profile, each the leaf
 *             of a chain to re-derive (may be NULL when row_count is 0; a bare
 *             run names no paths and hands none)
 * @param row_count Number of rows
 * @param opts Update options (must not be NULL)
 * @param commit The commit's bookkeeping, zero-filled by the caller; the walk
 *               fills it (must not be NULL)
 * @param out_processed Output: number of user items committed — captured plus
 *                      deleted; the derivation's motions are the bookkeeping's,
 *                      never this count's (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_profile(
    const dotta_ctx_t *ctx,
    worktree_handle_t *wt,
    const char *profile,
    const workspace_item_t **items,
    size_t item_count,
    const manifest_row_t **rows,
    size_t row_count,
    const cmd_update_options_t *opts,
    update_commit_t *commit,
    size_t *out_processed
) {
    CHECK_NULL(ctx);
    CHECK_NULL(wt);
    CHECK_NULL(profile);
    CHECK_NULL(opts);
    CHECK_NULL(commit);
    CHECK_NULL(out_processed);

    output_t *out = ctx->out;

    *out_processed = 0;
    commit->profile = profile;

    if (item_count == 0 && row_count == 0) {
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

    /* The one metadata load: the worktree file the checkout materialized — the
     * branch's own bytes — mutated as the walk goes, saved once. */
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

    /* The capture list can hold every item; the walk fills it with the ones that
     * landed. A rows-only call has nothing to capture and no list to size. */
    if (item_count > 0) {
        commit->captured = calloc(item_count, sizeof(update_capture_t));
        if (!commit->captured) {
            err = ERROR(ERR_MEMORY, "Failed to allocate capture list");
            goto cleanup;
        }
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
                /* Handle deleted files */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    output_info(
                        out, OUTPUT_VERBOSE, "  Removed: %s",
                        item->filesystem_path
                    );
                    /* Remove from index (stage deletion) */
                    int git_err = git_index_remove_bypath(index, item->storage_path);
                    if (git_err < 0) {
                        err = error_from_git(git_err);
                        goto cleanup;
                    }
                    /* Remove metadata entry if it exists */
                    metadata_remove_item(metadata, item->storage_path);
                    err = ptr_array_push(&commit->deleted, item);
                    if (err) {
                        goto cleanup;
                    }
                    continue;
                }

                output_info(out, OUTPUT_VERBOSE, "  %s", item->filesystem_path);

                /* Source of previously_encrypted: the item's view row —
                 * row->encrypted is projected at build from the same metadata.json
                 * this branch carries, so this is the branch's flag read off
                 * the frozen view instead of a second metadata load (an untracked
                 * file has no row: never previously encrypted). Under the
                 * write-time invariant the flag is byte-truth for the HEAD blob
                 * — reading it is equivalent to classifying the existing bytes,
                 * but cheaper (no fs read). */
                bool previously_encrypted = item->row ? item->row->encrypted : false;

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

                /* meta_item is NULL for a link that claims nothing — no mode to
                 * take, no ownership tracked. A capture that claims nothing retires
                 * the standing claim: an item at the key is the replaced
                 * state's. */
                if (meta_item) {
                    /* Stamp the encrypted cache from the copy's byte truth (false
                     * for a link — the copy never encrypts one) */
                    meta_item->encrypted = copy_encrypted;

                    /* Say what the capture took before metadata_add_item takes
                     * it — the claim decides the shape. The fourth combination
                     * (no mode, no ownership) has no line: such an item does
                     * not exist. The ownership-only shape carries no encrypted
                     * suffix by construction: it is a link's entry, and the copy
                     * never encrypts one. */
                    if (meta_item->mode != MODE_UNCLAIMED &&
                        (meta_item->owner || meta_item->group)) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o, owner: %s:%s%s)",
                            item->filesystem_path, meta_item->mode,
                            meta_item->owner ? meta_item->owner : "?",
                            meta_item->group ? meta_item->group : "?",
                            meta_item->encrypted ? ", encrypted" : ""
                        );
                    } else if (meta_item->mode != MODE_UNCLAIMED) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (mode: %04o%s)",
                            item->filesystem_path, meta_item->mode,
                            meta_item->encrypted ? ", encrypted" : ""
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "  Captured metadata: %s (owner: %s:%s)",
                            item->filesystem_path,
                            meta_item->owner ? meta_item->owner : "?",
                            meta_item->group ? meta_item->group : "?"
                        );
                    }

                    /* Add to metadata collection */
                    err = metadata_add_item(metadata, &meta_item);
                    if (err) {
                        metadata_item_free(meta_item);
                        err = error_wrap(err, "Failed to add metadata entry");
                        goto cleanup;
                    }

                    captured_file_count++;
                } else {
                    metadata_remove_item(metadata, item->storage_path);
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
                 * claiming a directory the user just deleted. A deleted directory
                 * is a deletion: the entry's removal goes on the commit's
                 * bookkeeping like a deleted file, so the commit gate counts
                 * it, the message names it, and the record loop retires it. */
                if (item->state == WORKSPACE_STATE_DELETED) {
                    if (metadata_remove_item(metadata, item->storage_path)) {
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
                 * path that vanished, or a tracked directory replaced by a symlink,
                 * which would stat() as its target and launder the target's
                 * attributes into metadata. Skip; the next load classifies what
                 * now stands there. */
                struct stat dir_stat;
                if (fs_lstat(item->filesystem_path, &dir_stat) != 0) {
                    output_warning(
                        out, OUTPUT_VERBOSE,
                        "Failed to stat directory '%s': %s",
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

                /* Capture directory metadata. A re-derivation replaces the
                 * attributes and never the class: whether the profile manages
                 * this directory or only passes through it was decided by the
                 * walk that authored the claim, and an update is not that walk.
                 * The standing item is the authority for it — this is the profile's
                 * own sheet, not the resolved view, so precedence has nothing
                 * to say here — and a key it does not hold answers with the class
                 * dotta does less with. */
                const metadata_item_t *held = metadata_lookup(metadata, item->storage_path);
                metadata_item_t *meta_item = NULL;
                err = metadata_capture_from_directory(
                    item->storage_path, &dir_stat, held && held->tracked, &meta_item
                );

                if (err) {
                    /* Non-fatal, and said at the verbosity its sibling above is
                     * said at: the claim standing on the directory is left exactly
                     * as it is — absence of a capture is not knowledge that the
                     * claim is wrong — so the sheet quietly keeps saying something
                     * this run could not confirm. */
                    output_warning(
                        out, OUTPUT_NORMAL, "Skipping directory '%s': %s",
                        item->filesystem_path, error_message(err)
                    );
                    error_free(err);
                    err = NULL;
                    continue;
                }

                /* Say what the capture took before metadata_add_item takes it */
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
                err = metadata_add_item(metadata, &meta_item);
                if (err) {
                    metadata_item_free(meta_item);
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

    /* The chain rides the capture: every leaf the walk took has its ancestry
     * re-derived — the content now comes from this machine, and so does its way
     * (add's own rule, applied to the re-capture an update is). After the walk,
     * so a rung the walk itself claimed stands as the walk's word; over both
     * kinds, a captured tracked directory having a chain of its own; and never
     * over a deleted item — the absence of a leaf says nothing about the chain
     * that led to it. This trigger authors and refreshes but structurally never
     * retires: a leaf read through a squatted rung was refused at the filter
     * (the route's displaced arms), whichever profile's claim the squatter
     * displaced, so a chain that reaches here holds directories at every claimed
     * rung. */
    for (size_t i = 0; i < commit->captured_count; i++) {
        const workspace_item_t *item = commit->captured[i].item;

        err = metadata_capture_ancestors(
            metadata, item->storage_path, item->filesystem_path,
            &commit->claimed, &commit->retired
        );
        if (err) goto cleanup;
    }

    /* A named path re-derives its subtree's chains: the rows the caller gathered
     * are the leaves the run's paths named, each climbed whether or not anything
     * about it diverged — naming is consent, and this is the derivation's one
     * route to a retire (a captured leaf's chain cannot hold a squatted rung; a
     * named one can, and naming it is the remedy). A row the walk also captured
     * climbs twice for free: the derivation counts only differences. */
    for (size_t i = 0; i < row_count; i++) {
        err = metadata_capture_ancestors(
            metadata, rows[i]->storage_path, rows[i]->filesystem_path,
            &commit->claimed, &commit->retired
        );
        if (err) goto cleanup;
    }

    if (commit->claimed > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Captured %zu ancestor director%s",
            commit->claimed, commit->claimed == 1 ? "y" : "ies"
        );
    }
    if (commit->retired.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "  Dropped %zu ancestor claim%s",
            commit->retired.count, commit->retired.count == 1 ? "" : "s"
        );
    }

    /* A profile whose walk captured nothing and deleted nothing, and whose
     * derivation moved nothing, has nothing to commit, and a no-commit profile
     * leaves the worktree exactly as checked out: nothing saved, nothing staged.
     * The prune is skipped with the save — imported redundancy rides whatever
     * commit triggers the metadata rewrite, never drives one. The derivation is
     * not redundancy: a chain re-derived under a captured leaf or a named path
     * is the user's own word about the disk, and it drives the commit it needs
     * — which is how the remedy for a rung the world moved under works at all. */
    size_t path_count = commit->captured_count + commit->deleted.count +
        commit->claimed + commit->retired.count;
    if (path_count == 0) {
        goto cleanup;
    }

    /* Prune redundant directory entries.
     *
     * Catches the implicit-orphaning case (the DELETED branch above handles
     * explicit removals): file removals can leave a parent directory's metadata
     * entry with nothing managed beneath it. That set is judged against the
     * post-edit index (deletions removed, updates staged by the walk) for every
     * path a tree can hold — never against metadata items, which omit unelevated
     * symlinks — and against the sheet's own standing claims for the one path
     * it cannot, an empty directory. Only entries that claim nothing of their
     * own are pruned; a tracked claim carrying real attributes survives as the
     * empty-dir intent it is. Without this, the view would keep claiming the
     * orphaned entry indefinitely. The keys go on the commit's bookkeeping: the
     * entry leaves the view by this commit, so its record is this verb's to
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
     * named. A retired claim is named with them (it leaves the view by this
     * commit); an authored one only rides, the pruned-keys precedent, so a
     * derivation that only refreshed names nothing and the message's file list
     * says so. */
    size_t named_count = commit->captured_count + commit->deleted.count +
        commit->retired.count;
    if (named_count > 0) {
        storage_paths = malloc(named_count * sizeof(char *));
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
        for (size_t i = 0; i < commit->retired.count; i++) {
            storage_paths[named++] = commit->retired.items[i];
        }
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_UPDATE,
        .profile       = profile,
        .files         = storage_paths,
        .file_count    = named_count,
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

    *out_processed = commit->captured_count + commit->deleted.count;

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
 * follows each one. The view is computed, so nothing projects; what update writes
 * is the one thing only it knows about the paths it committed — read off each
 * commit's own bookkeeping (update_commit_t), so a path the walk skipped gets
 * no record write. A modified or new file was captured FROM disk, so for the
 * row its profile won in the post-commit view the record advances to the
 * just-committed blob with the stat the copy took (the next status takes the
 * fast path). A path the commit let go — a deleted item, a directory entry the
 * walk's prune dropped as redundant, or an ancestor claim the derivation dropped
 * — left Git by this commit: with no row left at the path its record retires
 * (nothing backs it now); with a lower profile's row at the path it is a fallback
 * — the record stays and reads [reassigned] until apply deploys it. The rule
 * "anchor only the rows this profile won" is the same one add applies: a higher
 * profile's row is its own, and its record is its own. Both kinds: a directory's
 * claim (mode, ownership) is captured from disk exactly as add captures it, so
 * the capture owns the directory the same way — the ownership the orphan gate
 * asks for on scope exit — with no stat triple, a directory having no content
 * to confirm.
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
 * @param ctx Dispatch context (must not be NULL; the repository, the state handle
 *            and the mount table come off the run, the view is built into
 *            ctx->arena)
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

        /* What the commit let go: the deleted items by their own path, the keys
         * — the pruned entries and the dropped ancestor claims — by the path
         * this profile deploys them at (UNBOUND names nothing on this machine:
         * nothing to release). */
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

        const string_array_t *let_go[] = { &commit->pruned, &commit->retired };
        for (size_t b = 0; b < sizeof(let_go) / sizeof(let_go[0]); b++) {
            for (size_t i = 0; i < let_go[b]->count; i++) {
                mount_resolve_outcome_t outcome;
                const char *fs_path = NULL;
                err = mount_resolve(
                    mounts, commit->profile, let_go[b]->items[i], ctx->arena,
                    &outcome, &fs_path
                );
                if (err) goto cleanup;
                /* An unbound claim resolves nowhere on this machine: no filesystem
                 * path, so nothing to look up and no record of this run's to
                 * retire. Whatever record a once-bound era may have left is an
                 * orphan the next load's analysis settles. */
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
 * eliminating expensive worktree creation/destruction overhead. Each profile is
 * checked out into the same worktree before updating.
 *
 * Profiles are walked in enabled-set order — the model's one canonical profile
 * order — so multi-profile runs commit, report, and (on a stop) strand in one
 * predictable sequence; within a profile, items keep filter order. Every item's
 * and every row's profile is in the enabled set by construction (the view is
 * built from it), so the per-profile gathers drop nothing. A profile is visited
 * when it has items to commit or chains to re-derive: a named run's row slice
 * reaches profiles whose items all held still, which is what makes the derivation's
 * consent trigger — and the remedy it carries — work on a quiet tree at all. A
 * bare run hands no rows and visits exactly the profiles it always did.
 *
 * The commits that landed cross the error boundary: out_commits receives one
 * bookkeeping entry per landed commit, handed to the caller even when a later
 * profile fails, so the record write follows what Git shows. A profile that
 * committed nothing — a walk that touched nothing, or a failure before its commit
 * — contributes no entry.
 *
 * @param ctx Dispatch context (must not be NULL; the run's repository carries
 *            the shared worktree, the copy step reads the key and the encryption
 *            policy)
 * @param enabled The enabled set, in order (must not be NULL)
 * @param update_items Pre-filtered items to update (may be NULL when update_count
 *                     is 0)
 * @param update_count Number of items
 * @param derive_rows The named run's in-scope view rows, the chains to re-derive
 *                    (may be NULL when derive_count is 0)
 * @param derive_count Number of rows
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
    const string_array_t *enabled,
    const workspace_item_t **update_items,
    size_t update_count,
    const manifest_row_t **derive_rows,
    size_t derive_count,
    const cmd_update_options_t *opts,
    size_t *total_updated,
    update_commit_t **out_commits,
    size_t *out_commit_count
) {
    CHECK_NULL(ctx);
    CHECK_NULL(enabled);
    CHECK_NULL(opts);
    CHECK_NULL(total_updated);
    CHECK_NULL(out_commits);
    CHECK_NULL(out_commit_count);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    *total_updated = 0;
    *out_commits = NULL;
    *out_commit_count = 0;

    if (update_count == 0 && derive_count == 0) {
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

        /* This profile's chains to re-derive, when the run named paths */
        ptr_array_t rows PTR_ARRAY_AUTO = { 0 };
        for (size_t i = 0; i < derive_count; i++) {
            if (strcmp(derive_rows[i]->profile, profile) == 0) {
                err = ptr_array_push(&rows, derive_rows[i]);
                if (err) {
                    goto cleanup;
                }
            }
        }

        if (group.count == 0 && rows.count == 0) {
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
            ctx, wt, profile, (const workspace_item_t **) group.items,
            group.count, (const manifest_row_t **) rows.items, rows.count,
            opts, &bookkeeping, &processed
        );

        /* The commit gate's own sum, read back off the bookkeeping the walk filled:
         * on a clean return, zero means the gate closed without a commit and
         * anything else means one landed — a derivation-only commit carries no
         * user item, so `processed` alone cannot say. Any error means no commit
         * landed, whatever the bookkeeping holds. */
        size_t landed = bookkeeping.captured_count + bookkeeping.deleted.count +
            bookkeeping.claimed + bookkeeping.retired.count;
        if (!err && landed > 0) {
            /* The commit landed: its bookkeeping is the record write's now */
            commits[commit_count++] = bookkeeping;
            *total_updated += processed;

            if (!output_is_verbose(out)) {
                if (processed > 0) {
                    output_styled(
                        out, OUTPUT_NORMAL, "  {green}✓{reset} Updated %zu item%s\n",
                        processed, processed == 1 ? "" : "s"
                    );
                } else {
                    /* A derivation-only commit: no user item moved, the chains
                     * did */
                    output_styled(
                        out, OUTPUT_NORMAL, "  {green}✓{reset} Re-derived the ancestry\n"
                    );
                }
            }
        } else {
            /* No commit landed — a walk that touched nothing, or a failure before
             * the commit: the bookkeeping describes nothing */
            free(bookkeeping.captured);
            ptr_array_deinit(&bookkeeping.deleted);
            string_array_deinit(&bookkeeping.pruned);
            string_array_deinit(&bookkeeping.retired);
        }

        if (err) {
            err = error_wrap(err, "Failed to update profile '%s'", profile);
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
 * Render the preview: the run's work, grouped by fate
 *
 * One section per fate — modified, new, deleted (both kinds), directory claims,
 * encryption violations — each gated on the plan's counts, every hint speaking
 * update's own voice: what this run will do. A dry run renders identically; whether
 * anything was written is the summary's one line at the end of the run, not the
 * preview's.
 *
 * @param out Output context (must not be NULL)
 * @param items The accepted items (may be NULL when item_count is 0: a named
 *              run whose rows all held still has nothing to preview — its filter
 *              context printed ahead of the census)
 * @param item_count Number of items
 * @param counts The accepted items counted by fate (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *update_display_preview(
    output_t *out,
    const workspace_item_t **items,
    size_t item_count,
    const update_counts_t *counts
) {
    CHECK_NULL(out);
    CHECK_NULL(counts);

    /* Display modified files section */
    if (counts->modified_files > 0) {
        output_list_t *list = output_list_create(
            out, "Modified files",
            "will be committed to their profiles"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                /* The counted set: a DEPLOYED file with a path-family bit. An
                 * ENCRYPTION-only violator lists in the policy section below. */
                if (item->item_kind != PATH_KIND_FILE ||
                    item->state != WORKSPACE_STATE_DEPLOYED ||
                    (item->divergence & ~DIVERGENCE_ENCRYPTION) == DIVERGENCE_NONE) {
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
    if (counts->new_files > 0) {
        output_list_t *list = output_list_create(
            out, "New files",
            "will be added to their profiles"
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

    /* Display deleted paths section — one fate, both kinds: a deleted directory
     * is a deletion, so it lists beside the deleted files rather than under a
     * section that promises a metadata update */
    if (counts->deleted > 0) {
        output_list_t *list = output_list_create(
            out, "Deleted paths",
            "will be removed from their profiles"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->state != WORKSPACE_STATE_DELETED) {
                    continue;
                }

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

                /* Directory rows read as directories: trailing slash, kind named
                 * — the same shape the claims section uses */
                char path[PATH_MAX + 2];
                snprintf(
                    path, sizeof(path), "%s%s", item->filesystem_path,
                    path_kind_suffix(item->item_kind)
                );

                if (item->item_kind == PATH_KIND_DIRECTORY) {
                    char metadata[256];
                    snprintf(
                        metadata, sizeof(metadata), "directory %s",
                        base_metadata
                    );

                    output_list_add(
                        list, tags, tag_count, color,
                        path, metadata
                    );
                } else {
                    output_list_add(
                        list, tags, tag_count, color,
                        path, base_metadata
                    );
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display modified directories section */
    if (counts->modified_dirs > 0) {
        output_list_t *list = output_list_create(
            out, "Modified directories",
            "directory metadata will be updated"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                if (item->item_kind != PATH_KIND_DIRECTORY ||
                    item->state == WORKSPACE_STATE_DELETED) {
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
                    char path[PATH_MAX + 2];
                    snprintf(
                        path, sizeof(path), "%s%s", item->filesystem_path,
                        path_kind_suffix(item->item_kind)
                    );

                    /* Build custom metadata with explicit "directory" indicator */
                    char metadata[256];
                    snprintf(
                        metadata, sizeof(metadata), "directory %s",
                        base_metadata
                    );

                    output_list_add(
                        list, tags, tag_count, color,
                        path, metadata
                    );
                }
            }

            output_list_render(list);
            output_list_free(list);
        }
    }

    /* Display encryption policy violations section */
    if (counts->encryption > 0) {
        output_list_t *list = output_list_create(
            out, "Encryption policy violations",
            "match auto-encrypt patterns but are stored as plaintext"
        );

        if (list) {
            for (size_t i = 0; i < item_count; i++) {
                const workspace_item_t *item = items[i];

                /* DEPLOYED violators only — the set the section's count gated
                 * on: a deleted violator is in the deleted section, and its commit
                 * resolves the violation by removing the plaintext. */
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
            "narrow the pattern that matches it before this commit."
        );
    }

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
    update_partition_t partition = { 0 };
    ptr_array_t derive_rows = { 0 };
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

    /* Load workspace for update analysis
     *
     * Update processes files from the filesystem (either modified tracked files
     * or new files) and commits them to Git profiles. Analysis configuration:
     *
     * - analyze_files: Detects content and metadata changes in tracked files
     *   (the encryption-policy audit rides on this pass)
     * - analyze_orphans: Disabled - update doesn't process orphaned records
     * - analyze_untracked: Discovers new files in tracked directories (when
     *   enabled)
     * - analyze_directories: Detects directory metadata changes for update
     *
     * Orphan detection is unnecessary because update operates on view rows (files
     * from enabled profiles) and new files. Orphans (recorded but not in any
     * enabled profile) are out of scope for update operations.
     *
     * State is borrowed from the dispatcher (ctx->run.state). Read-only analysis.
     * The transaction for the record write opens later in update_write_record().
     */
    workspace_load_t ws_opts = {
        .analyze_files       = true,                    /* Detect content and metadata changes */
        .analyze_orphans     = false,                   /* Update doesn't process orphaned files */
        .analyze_untracked   = (opts->include_new || opts->only_new ||
            config->auto_detect_new_files), /* Explicit flags or config auto-detect */
        .analyze_directories = true                     /* Directory metadata change detection */
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
     * status/apply/update calls. Non-fatal on failure — update still proceeds;
     * just won't seed the fast path.
     *
     * Files actually updated by this command get their anchor advanced separately
     * inside update_write_record(); this flush covers the clean files the analysis
     * verified but didn't modify. */
    error_t *flush_err = workspace_flush_updates(ws);
    if (flush_err) {
        error_free(flush_err);
    }

    /* The run's filter context, ahead of everything the filter says against it:
     * the verbose "Excluded" log, the census, the nothing-exit and the preview */
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
            out, OUTPUT_NORMAL,
            "Filter: Limiting to %zu specified path%s",
            opts->file_count, opts->file_count == 1 ? "" : "s"
        );
        has_filters = true;
    }
    if (opts->exclude_count > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Filter: Excluding %zu pattern%s",
            opts->exclude_count, opts->exclude_count == 1 ? "" : "s"
        );
        has_filters = true;
    }
    if (has_filters) {
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Partition the diverged items: the scope, the flags, and for a deployed
     * item the route table. */
    err = filter_items_for_update(ws, opts, scope, config, out, &partition);
    if (err) {
        err = error_wrap(err, "Failed to filter items for update");
        goto cleanup;
    }

    /* What the filter refused, said once — above the exit below, so a workspace
     * whose only divergence is stale explains itself, and above the prompt. One
     * line per refusing arm, read off the partition's counts in the table's order
     * (workspace_item_route), each naming its route's way out. Two families arrive
     * split from the route by the claim that holds the offender — the same split
     * apply prints from the fate-borne ancestor_class: the displaced family
     * (DISPLACED_TRACKED beneath a planned squatter --force replaces,
     * DISPLACED_DERIVED beneath a rung the named re-derivation drops) and the
     * retyped family (KIND on a row a plan can hold, KIND_DERIVED on a rung dotta
     * only passes through). */
    const size_t *refused = partition.refused;

    if (refused[WORKSPACE_ROUTE_DISPLACED_TRACKED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: observed through a displaced directory — "
            "'dotta apply --force' replaces the squatter first",
            refused[WORKSPACE_ROUTE_DISPLACED_TRACKED],
            refused[WORKSPACE_ROUTE_DISPLACED_TRACKED] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_DISPLACED_DERIVED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: observed through a displaced directory — "
            "'dotta update <dir>' re-derives the way there",
            refused[WORKSPACE_ROUTE_DISPLACED_DERIVED],
            refused[WORKSPACE_ROUTE_DISPLACED_DERIVED] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_UNVERIFIABLE] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: cannot be read — fix permissions, or exclude with -e",
            refused[WORKSPACE_ROUTE_UNVERIFIABLE],
            refused[WORKSPACE_ROUTE_UNVERIFIABLE] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_CONFLICT] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu file%s skipped: changed in Git and on disk — 'dotta diff' shows "
            "Git's version against disk, 'dotta apply --force' keeps Git's, "
            "'dotta add --force' keeps disk's",
            refused[WORKSPACE_ROUTE_CONFLICT],
            refused[WORKSPACE_ROUTE_CONFLICT] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_STALE] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu file%s skipped: changed in Git since deployment — run 'dotta apply' first",
            refused[WORKSPACE_ROUTE_STALE],
            refused[WORKSPACE_ROUTE_STALE] == 1 ? "" : "s"
        );
    }
    if (refused[WORKSPACE_ROUTE_KIND] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: a different kind stands on disk — "
            "'dotta apply --force' replaces %s, 'dotta remove' untracks %s",
            refused[WORKSPACE_ROUTE_KIND],
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "" : "s",
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "it" : "them",
            refused[WORKSPACE_ROUTE_KIND] == 1 ? "it" : "them"
        );
    }
    if (refused[WORKSPACE_ROUTE_KIND_DERIVED] > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "%zu path%s skipped: a different kind stands at a directory dotta "
            "only passes through — 'dotta update <dir>' re-derives %s",
            refused[WORKSPACE_ROUTE_KIND_DERIVED],
            refused[WORKSPACE_ROUTE_KIND_DERIVED] == 1 ? "" : "s",
            refused[WORKSPACE_ROUTE_KIND_DERIVED] == 1 ? "it" : "them"
        );
    }

    /* A named path re-derives its subtree's chains. Naming is consent, so a run
     * given paths climbs the chain of every in-scope row under them, captured
     * or not — the explicit backfill, and the remedy for a rung the world moved
     * under. The slice is the leaves: blob rows and tracked directory rows, each
     * the root of its own chain; an ancestor claim is never a leaf — its own
     * re-derivation is carried by the leaves beneath it, which the residue rule
     * guarantees exist. The exclude gate binds here (the user excluded the path
     * from this operation), where the chain riding a captured leaf stays
     * scope-blind like add's — an exclusion names a path, never the way to it.
     * A bare run names nothing and derives nothing. */
    if (opts->file_count > 0) {
        manifest_rows_t all_rows = manifest_rows(manifest);
        for (size_t i = 0; i < all_rows.count; i++) {
            const manifest_row_t *row = all_rows.entries[i];

            if (row->type == PATH_TYPE_DIRECTORY && !row->tracked) {
                continue;
            }
            if (!scope_accepts_entry(
                scope, row->profile, row->storage_path,
                path_type_kind(row->type)
                )) {
                continue;
            }
            err = ptr_array_push(&derive_rows, row);
            if (err) goto cleanup;
        }
    }

    /* Check if we have anything to update — or, on a named run, any chains to
     * re-derive: whether a chain moved is the walk's to discover, so the named
     * run proceeds on the slice alone and the summary says what came of it */
    if (partition.accepted.count == 0 && derive_rows.count == 0) {
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

    /* The plan's shape, counted once: the preview gates its sections on these
     * and the new-files prompt binds on new_files */
    update_counts_t counts = { 0 };
    for (size_t i = 0; i < partition.accepted.count; i++) {
        const workspace_item_t *item = partition.accepted.entries[i];

        if (item->state == WORKSPACE_STATE_DELETED) {
            counts.deleted++;
        } else if (item->item_kind == PATH_KIND_DIRECTORY) {
            counts.modified_dirs++;
        } else if (item->state == WORKSPACE_STATE_UNTRACKED) {
            counts.new_files++;
        } else {
            /* A DEPLOYED file on the capture route, counted by divergence family:
             * a path-family bit is a modification, the ENCRYPTION bit a violation,
             * and a violator with nothing changed on disk is not a modified file
             * — the policy section alone names it. */
            if ((item->divergence & ~DIVERGENCE_ENCRYPTION) != DIVERGENCE_NONE) {
                counts.modified_files++;
            }
            if (item->divergence & DIVERGENCE_ENCRYPTION) {
                counts.encryption++;
            }
        }
    }

    /* Preview: what this run will do, grouped by fate */
    err = update_display_preview(
        out, (const workspace_item_t **) partition.accepted.entries,
        partition.accepted.count, &counts
    );
    if (err) {
        goto cleanup;
    }

    /* The hooks fire around the work — after the nothing-exit (a no-op run fires
     * nothing), before the prompt: apply's order. The preview's verdicts predate
     * the pre-hook, but the capture stores execute-time bytes — a pre-hook that
     * edits a candidate still commits what it wrote. */
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

    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* The prompts — none bind a dry run: it executes nothing, so there is nothing
     * to consent to */
    if (!opts->dry_run) {
        if (opts->interactive) {
            if (!output_confirm(out, "Update these items?", false)) {
                output_info(out, OUTPUT_NORMAL, "Cancelled");
                goto cleanup;
            }
        }

        /* New files the scan found (not asked for by flag) are added only with
         * consent. Declining keeps the rest of the run: the re-filter compacts
         * the accepted array in place — the preview named the new files separately,
         * and the receipt reports what actually happens. */
        if (counts.new_files > 0 && config->confirm_new_files &&
            !opts->include_new && !opts->only_new && config->auto_detect_new_files) {

            char confirm_msg[128];
            snprintf(
                confirm_msg, sizeof(confirm_msg), "Found %zu new file%s. Add %s to profiles?",
                counts.new_files, counts.new_files == 1 ? "" : "s",
                counts.new_files == 1 ? "it" : "them"
            );
            if (!output_confirm(out, confirm_msg, false)) {
                const workspace_item_t **writable =
                    (const workspace_item_t **) partition.accepted.entries;
                size_t kept = 0;
                for (size_t i = 0; i < partition.accepted.count; i++) {
                    if (writable[i]->state != WORKSPACE_STATE_UNTRACKED) {
                        writable[kept++] = writable[i];
                    }
                }
                partition.accepted.count = kept;

                if (partition.accepted.count == 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "No modified files remaining after skipping new files"
                    );
                    goto cleanup;
                }
            }
        }
    }

    /* Execute profile updates, in enabled-set order. Filtered to operation scope.
     * ctx->run.keymgr is borrowed by the copy step inside per-profile iteration.
     * A dry run executes nothing: the sections above are its preview, and the
     * summary below is its one sentence. */
    update_commit_t *commits = NULL;
    size_t commit_count = 0;
    bool manifest_updated = false;
    if (!opts->dry_run) {
        err = update_execute_for_all_profiles(
            ctx, scope_enabled(scope),
            (const workspace_item_t **) partition.accepted.entries,
            partition.accepted.count,
            (const manifest_row_t **) derive_rows.items, derive_rows.count,
            opts, &total_updated, &commits, &commit_count
        );

        /* Write the record — for the commits that landed, error or no
         *
         * Captured files get their record advanced because UPDATE captures them
         * FROM the filesystem (already at target locations); the view itself is
         * computed at every load and needs no update. A mid-sequence stop above
         * changes nothing here: the landed commits are Git truth and the record
         * follows them; the profiles that never committed have nothing to write.
         *
         * Non-fatal: if the record write fails, Git commits still succeeded;
         * the next status re-confirms the captured files on its slow path.
         */
        error_t *manifest_err = update_write_record(
            ctx, commits, commit_count, &manifest_updated
        );

        /* The bookkeeping has served the record */
        update_commits_free(commits, commit_count);

        if (manifest_err) {
            /* Non-fatal: the landed commits are Git truth and the record write
             * failed behind them. The next load reads the committed blobs from
             * Git and re-confirms the captured files against disk. Said in landed
             * terms — after a mid-sequence stop only some profiles committed,
             * and this line must not claim more. */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update the record: %s",
                error_message(manifest_err)
            );

            output_info(
                out, OUTPUT_NORMAL,
                "The commits that landed are in Git; the record follows on the next status"
            );
            error_free(manifest_err);
            /* Continue to post-update hook and success output */
        }

        if (err) {
            /* The executor stopped mid-sequence. The commits that landed are
             * recorded (just above); say so before reporting the stop, so the ✓
             * lines above are accounted for. */
            if (manifest_updated && commit_count > 0) {
                output_info(out, OUTPUT_NORMAL, "Manifest updated");
            }
            goto cleanup;
        }
    }

    /* Execute post-update hook (the hooks layer suppresses it on a dry run) */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Summary — one truthful line */
    output_newline(out, OUTPUT_NORMAL);
    if (opts->dry_run) {
        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
    } else if (commit_count == 0) {
        /* Every profile committed nothing (the walk's race guard refused what
         * the plan admitted): say so instead of counting zero */
        output_info(out, OUTPUT_NORMAL, "Nothing was committed");
    } else {
        if (total_updated > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Updated %zu item%s across %zu profile%s",
                total_updated, total_updated == 1 ? "" : "s",
                commit_count, commit_count == 1 ? "" : "s"
            );
        } else {
            /* Every landed commit was derivation-only: say what moved instead
             * of counting zero items */
            output_success(
                out, OUTPUT_NORMAL, "Re-derived the ancestry across %zu profile%s",
                commit_count, commit_count == 1 ? "" : "s"
            );
        }

        /* Record feedback, plain: the per-path split is the verbose "Manifest
         * synced" line, and the failure case already said what happened (warning
         * above) */
        if (manifest_updated) {
            output_info(out, OUTPUT_NORMAL, "Manifest updated");
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta status' to verify state"
            );
        }
    }

cleanup:
    free((void *) partition.accepted.entries); /* The array; the items are the workspace's */
    ptr_array_deinit(&derive_rows);            /* Rows are the view's */
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
 * What can stand at the cursor, by the rule update_post_parse routes with: an
 * enabled profile while the first positional is still open and -p has not taken
 * it; at every position a path of the view (files, and directory claims as subtree
 * filters) — narrowed to what the profiles named so far win — or a filesystem path.
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
    completion_files(ctx, out, winners, winner_count, true);
    return ARGS_WANT_FILES;
}

static error_t *update_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    error_t *err = cmd_update(ctx, (const cmd_update_options_t *) opts_v);

    /* A refusal the invoker met reading a source (add_dispatch has the list)
     * ends the update before its commit; a run that holds root reads through
     * it, so the one thing left to say is the command that would. */
    if (err && err->code == ERR_PERMISSION && !identity()->privileged) {
        char *hint = identity_sudo_hint(ctx->argc, ctx->argv);
        if (hint) {
            err = error_wrap(err, "Only root can read it; run: %s", hint);
            free(hint);
        }
    }

    return err;
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
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .crypto   = DOTTA_CRYPTO_OBTAIN,
        .manifest = true,
    },
    .dispatch     = update_dispatch,
};
