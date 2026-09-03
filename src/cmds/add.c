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
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/source.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * One path the walk collected, under both its names
 *
 * The walk is where the mount boundary is crossed: each path it collects is
 * classified there, once, through the command's table, and everything after reads
 * the name it needs — the capture and the commit message the storage path, the
 * record loop the filesystem path. A file's stat is the capture's
 * (add_file_to_worktree's one look at the bytes it stored), so the record binds
 * the committed blob to it; a directory's stays unset, as apply records them.
 */
typedef struct {
    const char *fs_path;          /* Absolute, as walked (arena) */
    const char *storage_path;     /* Classified at collection (arena) */
    stat_cache_t stat;            /* The capture's triple; STAT_CACHE_UNSET for a directory */
} add_path_t;

/**
 * The walk: what every frame reads, and the two lists it fills
 *
 * `seen` holds every filesystem path the walk passed so far, so overlapping CLI
 * arguments (~/.config and ~/.config/fish) list each path once: a directory already
 * walked is skipped with its subtree, a file already listed is not listed again.
 * Keys borrow the arena strings the lists hold.
 */
typedef struct {
    const dotta_ctx_t *ctx;              /* The arena the paths live in, and the output */
    const mount_table_t *mounts;         /* The command's table (see cmd_add) */
    const gitignore_ruleset_t *rules;    /* The profile's .dottaignore layers */
    source_filter_t *source_filter;      /* The source tree's .gitignore, when consulted */
    hashmap_t *seen;                     /* Filesystem path -> walked (borrowed keys) */
    ptr_array_t files;                   /* add_path_t *: every non-directory listed */
    ptr_array_t directories;             /* add_path_t *: every directory walked into */
} add_walk_t;

/**
 * What the record phase did, for the receipt
 *
 * `updated` is the phase's word that the anchor pass ran and its transaction
 * committed — the receipt's "Manifest updated" line and its counts speak only
 * then; false reads "profile not enabled". The counts qualify it: how many of
 * the captured files this profile's rows actually took (a higher-precedence profile
 * keeps its own), and how many of those took over a record another profile's
 * deployment had written.
 */
typedef struct {
    bool updated;          /* The anchor pass ran and the transaction committed */
    size_t synced;         /* Files anchored under this profile's rows */
    size_t taken_over;     /* Of those, records taken over from another profile */
} record_receipt_t;

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_add_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    if (!opts->files || opts->file_count == 0) {
        return ERROR(ERR_INVALID_ARG, "At least one path is required");
    }

    return NULL;
}

/**
 * Check if path should be ignored.
 *
 * Consults two independent mechanisms in order, each on the name it is written
 * against:
 *   1. The `.dottaignore` layers (baseline, profile, config, CLI) compiled into
 *      a single gitignore ruleset, evaluated on the mount-relative path
 *      (mount_strip_label of `storage_path`): what a `.gitignore` at the mount
 *      root would see.
 *   2. The source tree's own `.gitignore`, if the command built a filter (gated
 *      on `config.respect_gitignore`), evaluated on `fs_path`: that repository's
 *      root is the root its rules are relative to. The lowest layer: asked only
 *      when no `.dottaignore` layer decided, so a `!` rule in any of them overrides
 *      it.
 *
 * Either mechanism may be absent. `*out_match` is the rules' verdict — the layer
 * and the rule as written when they decided, undecided when the source tree's
 * .gitignore gave the verdict — so a caller can say who excluded the path.
 * Source-filter errors degrade to a verbose warning and a "not excluded" verdict
 * so an odd source repo never blocks the user from adding a file they explicitly
 * named. The gitignore evaluator never fails — its verdict is applied directly.
 */
static bool is_excluded(
    const add_walk_t *walk,
    const char *fs_path,
    const char *storage_path,
    bool is_directory,
    gitignore_match_t *out_match
) {
    gitignore_eval(
        walk->rules, mount_strip_label(storage_path), is_directory, out_match
    );
    if (out_match->decided) {
        return out_match->ignored;
    }

    if (walk->source_filter) {
        bool excluded = false;
        error_t *err = source_filter_is_excluded(
            walk->source_filter, fs_path, is_directory, &excluded
        );
        if (err) {
            output_warning(
                walk->ctx->out, OUTPUT_VERBOSE,
                "Source .gitignore check failed for %s: %s",
                fs_path, error_message(err)
            );
            error_free(err);
            return false;
        }
        return excluded;
    }

    return false;
}

/**
 * List `fs_path` under both names. The item is the arena's; the list borrows it.
 */
static error_t *list_path(
    arena_t *arena,
    ptr_array_t *list,
    const char *fs_path,
    const char *storage_path
) {
    add_path_t *path = arena_calloc(arena, 1, sizeof(*path));
    if (!path) {
        return ERROR(ERR_MEMORY, "Failed to allocate path entry");
    }
    path->fs_path = fs_path;
    path->storage_path = storage_path;
    path->stat = STAT_CACHE_UNSET;

    return ptr_array_push(list, path);
}

/**
 * Collect a directory tree into the walk.
 *
 * `dir_storage` is the directory's own storage path, NULL when it is a mount
 * root ($HOME, "/", a --target): a root has no name in the storage namespace
 * and is not listed; its descendants are. Every other directory walked into is
 * listed — the walk is the sole source of directory tracking — and so is every
 * non-excluded non-directory child. Symlinks are never followed: a symlink to a
 * directory is an entry like any other.
 *
 * Each child is classified here, once; the recursion receives both names and
 * never classifies again. A child that is itself a mount root (a --target nested
 * in the tree being walked) is walked through unlisted when it is a directory,
 * and skipped otherwise: nothing in the namespace names it.
 *
 * On error the lists keep what was collected; the caller's cleanup owns them.
 */
static error_t *collect_tree(
    add_walk_t *walk,
    const char *dir_fs,
    const char *dir_storage
) {
    CHECK_NULL(walk);
    CHECK_NULL(dir_fs);

    arena_t *arena = walk->ctx->arena;
    output_t *out = walk->ctx->out;

    /* A directory already walked was walked whole: nothing new beneath it. */
    if (hashmap_has(walk->seen, dir_fs)) return NULL;

    DIR *dir = fs_opendir(dir_fs);
    if (!dir) {
        return error_from_errno(errno, "Failed to open directory '%s'", dir_fs);
    }

    error_t *err = hashmap_set(walk->seen, dir_fs, (void *) 1);
    if (!err && dir_storage) {
        err = list_path(arena, &walk->directories, dir_fs, dir_storage);
    }
    if (err) {
        closedir(dir);
        return err;
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

        const char *child_fs =
            arena_str_format(arena, "%s/%s", dir_fs, entry->d_name);
        if (!child_fs) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* One lstat decides the kind: a symlink is never a directory here. */
        struct stat st;
        if (fs_lstat(child_fs, &st) != 0) {
            int saved_errno = errno;
            closedir(dir);
            return error_from_errno(
                saved_errno, "Failed to stat '%s'", child_fs
            );
        }
        bool is_dir = S_ISDIR(st.st_mode);

        /* The crossing: the child's storage name, or ROOT when it is a mount
         * root — not a name in the namespace, so neither excludable nor listed. */
        mount_classify_outcome_t outcome;
        const char *child_storage = NULL;
        err = mount_classify(
            walk->mounts, child_fs, arena, &outcome, &child_storage, NULL
        );
        if (err) {
            closedir(dir);
            return error_wrap(err, "Failed to classify '%s'", child_fs);
        }

        if (outcome == MOUNT_CLASSIFY_ROOT && !is_dir) {
            /* A symlink standing at a mount root (a --target the user reaches
             * through a symlink): the walk does not follow symlinks, and the
             * root itself has no name. */
            output_info(out, OUTPUT_VERBOSE, "Skipped mount root: %s", child_fs);
            errno = 0;
            continue;
        }

        /* Check exclude patterns */
        gitignore_match_t match;
        if (child_storage &&
            is_excluded(walk, child_fs, child_storage, is_dir, &match)) {
            if (match.decided) {
                output_info(
                    out, OUTPUT_VERBOSE, "Excluded: %s (%s: '%s')", child_fs,
                    ignore_origin_describe((ignore_origin_t) match.origin),
                    match.pattern
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "Excluded: %s (source .gitignore)",
                    child_fs
                );
            }
            errno = 0;
            continue;
        }

        if (is_dir) {
            /* Recurse: the child lists itself on entry. */
            err = collect_tree(walk, child_fs, child_storage);
        } else if (!hashmap_has(walk->seen, child_fs)) {
            err = hashmap_set(walk->seen, child_fs, (void *) 1);
            if (!err) {
                err = list_path(arena, &walk->files, child_fs, child_storage);
            }
        }
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
        return error_from_errno(
            saved_errno, "Error reading directory '%s'", dir_fs
        );
    }

    closedir(dir);
    return NULL;
}

/**
 * Say what a capture claimed — the claim decides the shape
 *
 * Three claim shapes exist, by the sheet's own existence rule (an item exists
 * iff it claims something): mode and ownership, mode alone, ownership alone — a
 * home/ symlink's entry, which a directory capture never produces since a directory
 * always claims its mode. The fourth combination has no line to print: such an
 * item does not exist, the capture returned NULL instead. Ownership is all-or-none
 * at the capture boundary (core/metadata's capture_ownership), so a present owner
 * implies a present group.
 *
 * The one voice for the file capture and the directory capture, which had drifted
 * apart; update's sibling line is not this one — it speaks at the receipt's indent
 * and carries the copy's encrypted suffix.
 *
 * @param out Output context (must not be NULL)
 * @param what The claim's noun: "metadata" or "directory metadata"
 * @param filesystem_path The captured path (must not be NULL)
 * @param item The capture's claim (must not be NULL)
 */
static void report_capture(
    output_t *out,
    const char *what,
    const char *filesystem_path,
    const metadata_item_t *item
) {
    if (item->mode != MODE_UNCLAIMED && item->owner) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (mode: %04o, owner: %s:%s)",
            what, filesystem_path, item->mode, item->owner, item->group
        );
    } else if (item->mode != MODE_UNCLAIMED) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (mode: %04o)",
            what, filesystem_path, item->mode
        );
    } else {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (owner: %s:%s)",
            what, filesystem_path, item->owner, item->group
        );
    }
}

/**
 * Add single file to worktree and capture metadata
 *
 * Handles file storage, encryption, and metadata capture in a single operation.
 * Uses stat data from content layer to eliminate race conditions.
 *
 * @param ctx Dispatch context (must not be NULL; reads ctx->run.keymgr for
 *            encryption — NULL when encryption is disabled — and ctx->config
 *            for the encryption policy)
 * @param wt Worktree handle
 * @param filesystem_path Source path on filesystem
 * @param storage_path Pre-computed storage path (e.g., "home/.bashrc")
 * @param opts Command options
 * @param metadata Metadata collection (captured entry will be added here)
 * @param out_stat The capture's stat triple — taken from the same stat as the
 *                 bytes stored, so the record can bind the committed blob to it
 *                 (must not be NULL; set on every success)
 * @return Error or NULL on success
 */
static error_t *add_file_to_worktree(
    const dotta_ctx_t *ctx,
    worktree_handle_t *wt,
    const char *filesystem_path,
    const char *storage_path,
    const cmd_add_options_t *opts,
    metadata_t *metadata,
    stat_cache_t *out_stat
) {
    CHECK_NULL(ctx);
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);
    CHECK_NULL(metadata);
    CHECK_NULL(out_stat);

    keymgr *keymgr = ctx->run.keymgr;  /* NULL if encryption disabled */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

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

        err = fs_create_symlink(target, dest_path, (uid_t) -1, (gid_t) -1);
        free(target);
        if (err) {
            free(dest_path);
            return error_wrap(err, "Failed to create symlink in worktree");
        }

        /* Capture the link's claim from its own lstat (the link's uid/gid, not
         * the target's). The link was read and copied lines above, so a failed
         * look here is a mid-add race — refused, the way the regular arm's store
         * fails on its equivalent. */
        struct stat link_stat;
        if (fs_lstat(filesystem_path, &link_stat) != 0) {
            free(dest_path);
            return error_from_errno(
                errno, "Failed to stat symlink '%s'", filesystem_path
            );
        }
        err = metadata_capture_from_file(
            filesystem_path, storage_path, &link_stat, &item
        );
        if (err) {
            free(dest_path);
            return error_wrap(
                err, "Failed to capture symlink metadata for '%s'",
                filesystem_path
            );
        }
        *out_stat = stat_cache_from_stat(&link_stat);

        /* The capture claims nothing (a link with no ownership to track): an
         * item standing at the key is the replaced state's — retire it. */
        if (!item) {
            metadata_remove_item(metadata, storage_path);
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
            opts->encrypt_mode,
            previously_encrypted,
            &should_encrypt
        );
        /* Returned as it is. The policy's refusals are the user's to read — they
         * name the path, the fact that stood and the way on — and a wrap saying
         * the policy could not be determined would say the opposite of what
         * happened. */
        if (err) {
            free(dest_path);
            return err;
        }

        /* Store file to worktree (handles read → encrypt → write) and capture
         * the stat.
         * SECURITY: the stat is the fstat of the fd the store read — bytes and
         * triple one inode by construction. */
        err = content_store_file_to_worktree(
            filesystem_path,
            dest_path,
            storage_path,
            opts->profile,
            keymgr,
            should_encrypt,
            &file_stat
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

        /* The store's write-time invariant: the bytes it wrote classify as the
         * decision says (a plaintext that would not is refused there), so the
         * claim is stamped from the decision and every reader of the bytes agrees
         * with it. */
        if (item) item->encrypted = should_encrypt;

        /* Verbose output */
        if (should_encrypt) {
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
        report_capture(out, "metadata", filesystem_path, item);

        err = metadata_add_item(metadata, &item);
        if (err) {
            metadata_item_free(item);
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
 * @param ctx Dispatch context (must not be NULL)
 * @param wt Worktree handle
 * @param opts Command options
 * @param added_files The files the walk listed, as captured (must not be NULL)
 * @param out_commit_oid Output for commit OID (optional, can be NULL)
 * @return Error or NULL on success
 */
static error_t *create_commit(
    const dotta_ctx_t *ctx,
    worktree_handle_t *wt,
    const cmd_add_options_t *opts,
    const ptr_array_t *added_files,
    git_oid *out_commit_oid
) {
    CHECK_NULL(ctx);
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);

    const config_t *config = ctx->config;

    /* Build commit message using storage paths — the walk's, classified once. */
    string_array_t *storage_paths = string_array_new(0);
    if (!storage_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    error_t *err = NULL;
    for (size_t i = 0; i < added_files->count; i++) {
        const add_path_t *path = added_files->items[i];
        err = string_array_push(storage_paths, path->storage_path);
        if (err) {
            string_array_free(storage_paths);
            return err;
        }
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_ADD,
        .profile       = opts->profile,
        .files         = storage_paths->items,
        .file_count    = storage_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &msg_ctx);
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
 *      enabled skips the anchor pass (nothing to win) and the target UPSERT
 *      (enable's business), never the settle
 *   2. Build the mount table from the post-mutation row cache
 *   3. Build the view; anchor the rows this profile won; settle what the commit
 *      let go
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
 *   - Profile not enabled, nothing let go → rollback transaction, return NULL
 *     (success, no update)
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
 * @param ctx Dispatch context (must not be NULL; reads the repository, the state
 *            and the command arena)
 * @param mounts The command's table, which binds this profile's target whether
 *               the run brought one or state already held it (must not be NULL)
 * @param opts Command options — the profile added to and the deployment target
 *             for custom/ files, as create_commit reads them (must not be NULL)
 * @param profile_was_new This add created the profile's branch: enable it here
 * @param added_files The files the walk listed, each with the capture's stat
 *                    (must not be NULL)
 * @param added_dirs The directories the walk passed through (must not be NULL)
 * @param retired The ancestor claims the ancestry pass dropped, by key (must
 *                not be NULL)
 * @param receipt What the phase did, zeroed first (must not be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *update_manifest_after_add(
    const dotta_ctx_t *ctx,
    const mount_table_t *mounts,
    const cmd_add_options_t *opts,
    bool profile_was_new,
    const ptr_array_t *added_files,
    const ptr_array_t *added_dirs,
    const string_array_t *retired,
    record_receipt_t *receipt
) {
    CHECK_NULL(ctx);
    CHECK_NULL(mounts);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);
    CHECK_NULL(added_dirs);
    CHECK_NULL(retired);
    CHECK_NULL(receipt);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;   /* Borrowed from dispatcher (WRITE) */

    error_t *err = NULL;

    *receipt = (record_receipt_t){ 0 };

    /* STEP 1: Scope.
     *
     * CRITICAL ORDER: Must enable (or re-bind) BEFORE the view is built so target
     * is available in state for path resolution during the tree walk. The
     * deployment target is stored in the enabled_profiles table and read by the
     * mount table built below to resolve custom/ storage paths.
     *
     * Transaction Safety: If the record write below fails, the dispatcher's
     * state_free automatically rolls back this change. */
    bool enabled = true;
    if (profile_was_new) {
        err = state_enable_profile(state, opts->profile, opts->target);
        if (err) {
            return error_wrap(err, "Failed to enable profile in state");
        }
    } else if (!state_has_profile(state, opts->profile)) {
        /* Only an enabled profile has rows in the view, so the anchor pass has
         * no subject and a given target stays unbound (enable's business, when
         * the user gets there). The settle is not gated with them: the commit
         * just dropped whatever `retired` names, whatever the enabled set says,
         * and a path the commit let go settles by its record, enabled set or
         * no. With nothing let go there is nothing to write at all — success,
         * and the dispatcher's state_free rolls back the untouched transaction. */
        if (retired->count == 0) {
            return NULL;
        }
        enabled = false;
    } else if (opts->target) {
        err = state_enable_profile(state, opts->profile, opts->target);
        if (err) {
            return error_wrap(err, "Failed to update deployment target for profile");
        }
    }

    /* STEP 2: Build the view; anchor the rows this profile won; settle what the
     * commit let go.
     *
     * The builder reads the rows as STEP 1 left them — a new row, or a target
     * re-bound — so a path under the just-bound target is a custom/ row here. A
     * disabled profile contributes no rows, and that is the build the settle
     * wants: its guard asks what the view still claims without this profile. */
    manifest_t *manifest = NULL;
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) return err;

    hashmap_t *anchor_index = NULL;   /* Built with the anchor pass it serves */
    if (enabled) {
        /* Anchor only the rows this profile won: if this profile has lower
         * precedence than existing enabled profiles, some files are another
         * profile's rows (receipt->synced < added_files). Those correctly receive
         * no anchor — the row is the winner's and so is its record, and the
         * capture's stat would misattribute to the winner's blob_oid. Write
         * failures are non-fatal: disk is the just-committed blob, and the next
         * status's slow path confirms it.
         *
         * The record as it stands first, indexed by path, so a takeover is known
         * before the write that rewrites it. */
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        err = state_get_all_anchors(state, ctx->arena, &anchors, &anchor_count);
        if (err) {
            manifest_free(manifest);
            return error_wrap(err, "Failed to read anchors");
        }

        anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
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
        for (size_t i = 0; i < added_files->count; i++) {
            const add_path_t *path = added_files->items[i];
            const manifest_row_t *row = manifest_lookup(manifest, path->fs_path);
            if (!row || strcmp(row->profile, opts->profile) != 0) continue;

            error_t *anchor_err = state_anchor(state, row, &path->stat, now, NULL);
            if (anchor_err) {
                error_free(anchor_err);
                continue;
            }
            receipt->synced++;

            const anchor_t *was = hashmap_get(anchor_index, row->filesystem_path);
            if (was && was->deployed_at > 0 && strcmp(was->profile, opts->profile) != 0) {
                receipt->taken_over++;
            }
        }

        /* The directories this add tracked, by the same rule: captured from disk,
         * so dotta's to prune on scope exit — the ownership the gate asks for,
         * which nothing later grants a directory that was already there (apply
         * observes those; it anchors only the ones it makes). Cleanup's emptiness
         * rule guards their contents. No stat triple: a directory has no content
         * confirmation, as apply records them. */
        for (size_t i = 0; i < added_dirs->count; i++) {
            const add_path_t *path = added_dirs->items[i];
            const manifest_row_t *row = manifest_lookup(manifest, path->fs_path);
            if (!row || strcmp(row->profile, opts->profile) != 0) continue;

            error_t *anchor_err = state_anchor(state, row, NULL, now, NULL);
            if (anchor_err) error_free(anchor_err);
        }
    }

    /* What the commit let go: an ancestor claim the derivation retired leaves
     * the view by this very commit, so its record settles here rather than
     * orphaning until an apply gets around to it — the record the commit stranded
     * is the commit's to settle. It refuses nothing while it stands: a directory
     * only a record remembers reaches no view row (the reach rule,
     * core/workspace.h), so the leaf this add just captured through the arrangement
     * is judged on its own occupant either way, and a retire that fails here
     * leaves a [released] [type] row under status's Issues until an apply releases
     * it. Enablement was not consulted on the way here: the derivation saw the
     * disk contradict the claim whatever the enabled set says, and the record
     * its drop strands is stale under a disabled profile exactly as under an
     * enabled one. A rung some other profile still claims keeps its row and its
     * record — the retire is this profile's word about its own claim, never about
     * the path — and an unbound claim names nothing on this machine to retire. */
    for (size_t i = 0; i < retired->count; i++) {
        mount_resolve_outcome_t outcome;
        const char *fs_path = NULL;

        err = mount_resolve(
            mounts, opts->profile, retired->items[i], ctx->arena, &outcome, &fs_path
        );
        if (err) {
            hashmap_free(anchor_index, NULL);
            manifest_free(manifest);
            return error_wrap(
                err, "Failed to derive filesystem path from storage path: %s",
                retired->items[i]
            );
        }
        if (outcome == MOUNT_RESOLVE_UNBOUND || manifest_lookup(manifest, fs_path)) {
            continue;
        }

        error_t *retire_err = state_retire_anchor(state, fs_path);
        if (retire_err) error_free(retire_err);
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

    /* Success. A settle committed for a disabled profile is not the anchor pass
     * having run: the receipt still reads "profile not enabled". */
    receipt->updated = enabled;

    return NULL;
}

/**
 * Add command implementation
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;   /* Borrowed from dispatcher (WRITE) */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = validate_options(opts);
    if (err) return err;

    /* Initialize all resources to NULL for safe cleanup */
    ignore_rules_t *ignore_rules = NULL;
    const gitignore_ruleset_t *profile_rules = NULL;
    source_filter_t *source_filter = NULL;
    worktree_handle_t *wt = NULL;
    add_walk_t walk = { .ctx = ctx };    /* Filled once the table and the rules are known */
    size_t added_count = 0;
    bool profile_exists = false;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;
    const mount_table_t *mounts = NULL;   /* The command's table: see below */

    /* The ancestry pass's other half: the keys it retired, read by the record
     * write once the commit that drops them has landed. */
    string_array_t ancestry_retired STRING_ARRAY_AUTO = { 0 };

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* The branch this add will write to: checked out below when it is there,
     * created when it is not. Both answers are needed here, before the command
     * has any effect — a name Git's ref namespace cannot hold beside the names
     * already there is refused now, ahead of the pre-add hook and the worktree,
     * because a refusal that has already run the user's hook is not a refusal.
     *
     * A branch and any branch beneath it are exclusive, which is why a base profile
     * and its variants are (docs/profiles.md). libgit2 refuses at commit time
     * with a message about directories that names neither profile; this refuses
     * by name, and names both. */
    err = gitops_branch_exists(repo, opts->profile, &profile_exists);
    if (err) goto cleanup;

    if (!profile_exists) {
        char *blocker = NULL;
        err = gitops_branch_blocker(repo, opts->profile, &blocker);
        if (err) goto cleanup;
        if (blocker) {
            const char *base = strlen(blocker) < strlen(opts->profile)
                ? blocker : opts->profile;
            err = ERROR(
                ERR_INVALID_ARG, "Profile '%s' cannot exist beside profile '%s'\n\n"
                "Git stores each profile as a branch, and '%s' cannot be both "
                "a branch and a folder of branches.\n", opts->profile, blocker, base
            );
            free(blocker);
            goto cleanup;
        }
    }

    /* Validate deployment target if provided */
    if (opts->target) {
        err = mount_validate_target(opts->target);
        if (err) goto cleanup;

        /* Pre-flight: refuse silent re-targeting. If the profile is already enabled
         * with a different target, fail BEFORE the Git commit so the user does
         * not end up with a wasted commit + stale binding. Setting a target on
         * a profile that previously had none is fine. */
        const char *existing = state_peek_profile_target(state, opts->profile);
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
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* Create temporary worktree */
    err = worktree_create_temp(repo, &wt);
    if (err) {
        err = error_wrap(err, "Failed to create temporary worktree");
        goto cleanup;
    }

    /* Checkout or create the profile branch, as the pre-flight above resolved it */
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

    /* Collect every path to add, expanding directories. The walk lists each path
     * once, under both names: the CLI argument crosses the mount boundary here,
     * and what the walk finds beneath it crosses in the walk. */
    walk.mounts = mounts;
    walk.rules = profile_rules;
    walk.source_filter = source_filter;
    walk.seen = hashmap_borrow(0);
    if (!walk.seen) {
        err = ERROR(ERR_MEMORY, "Failed to allocate the walk's index");
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

        /* The walk keeps what it lists, so the path lives in the arena. */
        const char *fs_path = arena_strdup(ctx->arena, absolute);
        free(absolute);
        if (!fs_path) {
            err = ERROR(ERR_MEMORY, "Failed to allocate path");
            goto cleanup;
        }

        /* What stands at the path — the link itself for a symlink, a broken one
         * included. Absence and a refusal are two answers: a storage path that
         * resolves to nothing is as likely a relative path whose first component
         * happens to be a label — `root/x` typed from `/` — so the message says
         * where it looked and how to say the other; a path the invoker cannot
         * reach names its reason, and the dispatch tail names the command that
         * could. */
        switch (fs_lstat_occupant(fs_path, NULL)) {
            case FS_OCCUPANT_NONE:
                if (spec) {
                    err = ERROR(
                        ERR_NOT_FOUND, "Path not found: %s (storage path '%s')\n"
                        "For a relative path, write ./%s", fs_path, file, file
                    );
                } else {
                    err = ERROR(ERR_NOT_FOUND, "Path not found: %s", fs_path);
                }
                goto cleanup;

            case FS_OCCUPANT_UNKNOWN: {
                int saved_errno = errno;
                err = error_from_errno(
                    saved_errno, "Cannot access '%s'", fs_path
                );
                goto cleanup;
            }

            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK:
            case FS_OCCUPANT_DIRECTORY:
            case FS_OCCUPANT_OTHER:
                break;
        }

        /* The argument's storage name — NULL for a mount root ($HOME, "/", the
         * --target), which has none. */
        mount_classify_outcome_t outcome;
        const char *storage_path = NULL;
        err = mount_classify(
            mounts, fs_path, ctx->arena, &outcome, &storage_path, NULL
        );
        if (err) {
            err = error_wrap(err, "Failed to classify '%s'", file);
            goto cleanup;
        }

        bool is_dir = !fs_is_symlink(fs_path) && fs_is_directory(fs_path);

        /* A path named on the command line is subject to the rules like any the
         * walk finds, but a verdict against it is an error, not a silent skip:
         * the user asked for it by name, and the answer says which rule stands
         * in the way and how to get past it. A mount root has no name for a pattern
         * to match. */
        gitignore_match_t match;
        if (storage_path &&
            is_excluded(&walk, fs_path, storage_path, is_dir, &match)) {
            if (match.decided) {
                err = ERROR(
                    ERR_INVALID_ARG, "'%s' is ignored by %s: '%s'\n"
                    "Add it anyway with -e '!%s', or edit the rule with "
                    "'dotta ignore'",
                    file, ignore_origin_describe((ignore_origin_t) match.origin),
                    match.pattern, match.pattern
                );
            } else {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' is ignored by its source tree's .gitignore\n"
                    "Set respect_gitignore = false in the config to add it",
                    file
                );
            }
            goto cleanup;
        }

        /* Handle symlinks, directories, and files */
        if (is_dir) {
            /* Remember counts so we can describe what the walk produced. */
            size_t files_before = walk.files.count;
            size_t dirs_before = walk.directories.count;

            /* A root is walked through unlisted: its descendants are listed. */
            err = collect_tree(&walk, fs_path, storage_path);
            if (err) {
                err = error_wrap(err, "Failed to collect from '%s'", file);
                goto cleanup;
            }

            size_t files_found = walk.files.count - files_before;
            size_t dirs_found = walk.directories.count - dirs_before;
            output_info(
                out, OUTPUT_VERBOSE,
                "Collected %zu file%s and %zu director%s under %s",
                files_found, files_found == 1 ? "" : "s",
                dirs_found, dirs_found == 1 ? "y" : "ies", fs_path
            );
        } else {
            if (outcome == MOUNT_CLASSIFY_ROOT) {
                /* A symlink standing at a mount root: $HOME itself when HOME is
                 * a symlink, or a --target reached through one. The root has no
                 * name, and the walk does not follow symlinks. */
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' is a mount root and cannot be added itself; "
                    "name what is inside it", file
                );
                goto cleanup;
            }

            /* List it, unless a walk already did. */
            if (hashmap_has(walk.seen, fs_path)) continue;
            err = hashmap_set(walk.seen, fs_path, (void *) 1);
            if (!err) {
                err = list_path(ctx->arena, &walk.files, fs_path, storage_path);
            }
            if (err) goto cleanup;
        }
    }

    /* Check if we have anything to add (files or directories). A named path the
     * rules refused was an error above, so this is a mount root with nothing
     * listable beneath it. */
    if (walk.files.count == 0 && walk.directories.count == 0) {
        err = ERROR(ERR_INVALID_ARG, "No files or directories to add");
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

    /* Single-pass: add files and capture metadata inline. Each capture's stat
     * triple is kept on the path, for the record: it is the stat of the bytes
     * committed, which a later lstat could not promise. */
    for (size_t i = 0; i < walk.files.count; i++) {
        add_path_t *path = walk.files.items[i];

        /* Validate storage path: this is the write boundary into the worktree
         * (and thence into Git). Establish the well-formed invariant here so
         * downstream readers (manifest, sync, remove) can trust the bytes they
         * read. */
        err = mount_validate_storage(path->storage_path);
        if (err) goto cleanup;

        /* Add file to worktree and capture metadata
         * ARCHITECTURE: add_file_to_worktree handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate
         * TOCTOU */
        err = add_file_to_worktree(
            ctx, wt, path->fs_path, path->storage_path, opts, metadata, &path->stat
        );
        if (err) {
            err = error_wrap(err, "Failed to add file '%s'", path->fs_path);
            goto cleanup;
        }
        added_count++;
    }

    /* Capture directory metadata for every walked directory.
     *
     * The walk lists every directory it walks into — including the CLI-arg
     * top-level — so this loop captures the full tree, not just the CLI-named
     * entry points. A mount root ($HOME, "/", --target) is never listed: it has
     * no storage name; its descendants are captured normally.
     */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < walk.directories.count; i++) {
        const add_path_t *path = walk.directories.items[i];
        const char *filesystem_path = path->fs_path;
        const char *storage_path = path->storage_path;

        /* Stat directory to capture mode (and ownership if root/custom). lstat
         * + S_ISDIR: the race guard update's capture arm has. The walk classified
         * with lstat, so anything else standing here changed since — skip; a
         * follow-stat would launder the target's attributes into the claim. */
        struct stat dir_stat;
        if (fs_lstat(filesystem_path, &dir_stat) != 0) {
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                filesystem_path, strerror(errno)
            );
            continue;
        }
        if (!S_ISDIR(dir_stat.st_mode)) {
            output_warning(
                out, OUTPUT_NORMAL,
                "Skipping '%s': walked as directory but type changed on disk",
                filesystem_path
            );
            continue;
        }

        /* Capture directory metadata using stat data. The walk entered this
         * directory, so the claim is a tracked one: the profile manages the path
         * itself, scans it for new files and converges its attributes. */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_from_directory(storage_path, &dir_stat, true, &dir_item);
        if (err) {
            /* Non-fatal, and said at the verbosity its sibling above is said
             * at: the walk's files are added either way, but the directory itself
             * takes no claim from this run and so is not tracked at all — a loss
             * the user only weighs if they are told about it. */
            output_warning(
                out, OUTPUT_NORMAL, "Skipping directory '%s': %s",
                filesystem_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            continue;
        }

        /* Verbose output before consuming the item */
        report_capture(out, "directory metadata", filesystem_path, dir_item);

        /* Add directory to metadata */
        err = metadata_add_item(metadata, &dir_item);
        if (err) {
            /* Non-fatal: log warning and continue */
            metadata_item_free(dir_item);
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

    /* The ancestry: the chain above every path this add captured, claimed as
     * the derivation it is — the attributes to give a rung if dotta ever has to
     * create it, and nothing more. It runs after the walk's own claims so that
     * a rung the walk entered is left exactly as the loop above wrote it, and
     * over both lists: a directory the walk listed has a chain of its own, and
     * an empty one has no file beneath it to carry that chain. Scope-blind by
     * design, as the pass that reads it is — an exclusion names a path, never
     * the way to it.
     */
    size_t ancestors_captured = 0;
    const ptr_array_t *chains[] = { &walk.files, &walk.directories };
    for (size_t b = 0; b < sizeof(chains) / sizeof(chains[0]); b++) {
        for (size_t i = 0; i < chains[b]->count; i++) {
            const add_path_t *path = chains[b]->items[i];

            err = metadata_capture_ancestors(
                metadata, path->storage_path, path->fs_path,
                &ancestors_captured, &ancestry_retired
            );
            if (err) goto cleanup;
        }
    }
    if (ancestors_captured > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %zu ancestor director%s",
            ancestors_captured, ancestors_captured == 1 ? "y" : "ies"
        );
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
    err = create_commit(ctx, wt, opts, &walk.files, NULL);
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
    record_receipt_t record = { 0 };

    error_t *manifest_err = update_manifest_after_add(
        ctx, mounts, opts, profile_was_new,
        &walk.files, &walk.directories, &ancestry_retired, &record
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
                out, OUTPUT_NORMAL, "Paths committed to Git successfully"
            );
        }
        error_free(manifest_err);
        record = (record_receipt_t){ 0 };
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(&wt);

    /* Execute post-add hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

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
        if (record.updated) {
            if (added_count > 0) {
                /* Files were added - show sync results with precedence awareness:
                 * the rows a higher profile owns got no anchor; the ones another
                 * profile's deployment had written were taken over. */
                if (record.synced == added_count) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Manifest updated (%zu file%s marked as deployed)",
                        record.synced, record.synced == 1 ? "" : "s"
                    );
                } else {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Manifest updated (%zu/%zu file%s marked as deployed)",
                        record.synced, added_count, added_count == 1 ? "" : "s"
                    );

                    size_t skipped = added_count - record.synced;
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s overridden by higher-precedence profiles",
                        skipped, skipped == 1 ? "" : "s"
                    );
                }
                if (record.taken_over > 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s taken over from other profiles",
                        record.taken_over, record.taken_over == 1 ? "" : "s"
                    );
                }
                if (!profile_was_new) {
                    /* Existing enabled profile */
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "Paths captured from filesystem (already deployed)"
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
    ptr_array_deinit(&walk.directories);
    ptr_array_deinit(&walk.files);
    hashmap_free(walk.seen, NULL);
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
 * The count check lives here, after the routing, so the error message can reference
 * the effective invariant rather than a raw count.
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
            ERR_INVALID_ARG, "at least one path is required"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, read off the buckets add_post_parse routes: a
 * local profile in the profile slot — the first positional, unless -p took it —
 * then filesystem paths, listed under --target when one re-roots them. A new
 * profile's name is typed, not offered.
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
    error_t *err = cmd_add(ctx, (const cmd_add_options_t *) opts_v);

    /* A refusal the invoker met reading a source — the walk's opendir and lstat,
     * the open behind the policy sniff and the copy (infra/content), the existence
     * check — ends the add before anything durable is written: the temp worktree
     * is removed on the error path and the commit is after the walk. A run that
     * holds root reads through it (sys/filesystem's second try), so the one thing
     * left to say is sudo. */
    if (err && err->code == ERR_PERMISSION && !identity()->privileged) {
        err = error_wrap(err, "Only root can read it; re-run under sudo");
    }

    return err;
}

static const args_opt_t add_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",                 "<name>",
        cmd_add_options_t,           profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "target",                    "<path>",
        cmd_add_options_t,           target,
        "Declare a relocatable storage root"
    ),
    ARGS_STRING(
        "m message",                 "<msg>",
        cmd_add_options_t,           message,
        "Commit message"
    ),
    ARGS_APPEND(
        "e exclude",                 "<pattern>",
        cmd_add_options_t,           exclude_patterns, exclude_count,
        "Skip paths matching a .dottaignore-style pattern (repeatable)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_add_options_t,           force,
        "Overwrite existing entries in the profile"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_add_options_t,           verbose,
        "Verbose output"
    ),
    ARGS_FLAG_SET(
        "encrypt",
        cmd_add_options_t,           encrypt_mode,
        ENCRYPTION_REQUEST_ENCRYPT,
        "Force encryption for the given files"
    ),
    ARGS_FLAG_SET(
        "no-encrypt",
        cmd_add_options_t,           encrypt_mode,
        ENCRYPTION_REQUEST_PLAINTEXT,
        "Bypass auto-encryption patterns"
    ),
    /* <profile> <file|dir>... — order-dependent, first is profile. Mirrors clone's
     * raw-bucket-plus-post_parse approach. */
    ARGS_POSITIONAL_RAW(
        cmd_add_options_t,           positional_args,  positional_count,
        0,                           0
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
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_WRITE,
        .mounts  = true,
        .crypto  = DOTTA_CRYPTO_OBTAIN,
    },
    .dispatch    = add_dispatch,
};
