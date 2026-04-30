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

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/output.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
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
 * Boundary-aware "is `path` under `dir`" predicate.
 *
 * Pure string check; no syscalls. Callers that need symlink equivalence
 * pre-resolve the canonical form of `dir` and call this twice (once
 * per surface form). NULL `dir` returns false — gates the cross-product
 * canonical check when realpath() yielded no distinct second form.
 *
 * Boundary rule: matches when `path` equals `dir` exactly, or has a
 * '/' at the dir-length offset (rejects /home/user against /home/userX
 * false-prefixes).
 */
static bool path_under_dir(const char *path, const char *dir) {
    if (!path || !dir) return false;
    size_t dir_len = strlen(dir);
    if (strncmp(path, dir, dir_len) != 0) return false;
    char boundary = path[dir_len];
    return boundary == '/' || boundary == '\0';
}

/**
 * Normalize a CLI filesystem-path argument to an absolute path,
 * honoring `--target` jail semantics.
 *
 * Transformation order:
 *   1. Tilde expansion (~/ -> $HOME)               — bypasses jail
 *   2. Jail interpretation (when virtual_root set):
 *      - Relative paths: join with virtual_root
 *      - Absolute paths under virtual_root: pass through
 *      - Absolute paths NOT under virtual_root: prepend virtual_root
 *   3. CWD joining (relative paths, no jail)
 *   4. Lexical normalization (resolves '.', '..', '//')
 *   5. Post-condition: when virtual_root is set, the final result
 *      MUST remain under virtual_root. This catches `/jail/../etc/secret`
 *      style inputs that pass step 2 (already_under is true) but escape
 *      after lexical normalization in step 4.
 *
 * Symlink awareness: in steps 2 and 5, the boundary check against
 * `virtual_root` cross-products both raw and realpath-canonical forms
 * (computed once at function entry) so canonical inputs (from getcwd,
 * find, tab-completion) under a raw `--target` aren't re-prepended to
 * nonsense. The raw form is preserved in the output — symlink
 * resolution does not leak into the user-visible path.
 *
 * Examples:
 *   ("~/file", NULL)              -> "$HOME/file"
 *   ("rel/file", "/jail")         -> "/jail/rel/file"
 *   ("/etc/hosts", "/jail")       -> "/jail/etc/hosts"
 *   ("/jail/etc/hosts", "/jail")  -> "/jail/etc/hosts" (already under root)
 *   ("rel/file", NULL)            -> "$CWD/rel/file"
 *   ("../escape", "/jail")        -> ERROR (relative traversal)
 *   ("/jail/../escape", "/jail")  -> ERROR (post-condition trips)
 *
 * Privacy: this helper is `dotta add`-specific. The jail mode encodes
 * the user's mental model when they pass `--target` ("operate inside
 * this directory"). Other commands convert input via mount_resolve_input,
 * which classifies against the mount table without re-rooting absolute
 * paths.
 *
 * @param user_path    User-provided path (filesystem or tilde)
 * @param virtual_root Optional jail root from `--target` (NULL = no jail)
 * @param out          Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
static error_t *add_normalize_input(
    const char *user_path,
    const char *virtual_root,
    char **out
) {
    CHECK_NULL(user_path);
    CHECK_NULL(out);

    error_t *err = NULL;
    char *expanded = NULL;
    char *joined = NULL;
    char *absolute = NULL;
    char *virtual_root_canonical = NULL;
    const char *path_to_make_absolute = user_path;

    /* When --target is active, pre-resolve its realpath-canonical form
     * once. Best-effort: realpath() failure leaves the canonical NULL
     * and the cross-product checks below degrade to raw-only (correct
     * when the target genuinely has no symlinks on its path). When
     * canonical equals raw, drop it so path_under_dir's NULL gate
     * skips the redundant second comparison. */
    if (virtual_root && virtual_root[0] != '\0') {
        error_t *canon_err = fs_canonicalize_path(
            virtual_root, &virtual_root_canonical
        );
        if (canon_err) {
            error_free(canon_err);
            virtual_root_canonical = NULL;
        }
        if (virtual_root_canonical &&
            strcmp(virtual_root_canonical, virtual_root) == 0) {
            free(virtual_root_canonical);
            virtual_root_canonical = NULL;
        }
    }

    /* Step 1: Expand tilde (canonical, bypasses virtual_root). */
    if (user_path[0] == '~') {
        err = fs_expand_tilde(user_path, &expanded);
        if (err) goto out;
        path_to_make_absolute = expanded;
    }
    /* Step 2: Resolve paths within virtual_root context. Tilde paths
     * skip this — ~/file always means $HOME/file regardless of root. */
    else if (virtual_root && virtual_root[0] != '\0') {
        const char *path = path_to_make_absolute;

        if (path[0] != '/') {
            /* SECURITY: Reject '..' as a path component (not as substring).
             * Prevents virtual_root escape: ../foo + /jail -> /jail/../foo -> /foo */
            for (const char *p = path; *p; p++) {
                if ((p == path || *(p - 1) == '/') && p[0] == '.' && p[1] == '.' &&
                    (p[2] == '/' || p[2] == '\0')) {
                    err = ERROR(
                        ERR_INVALID_ARG,
                        "Path traversal (..) not allowed in relative paths "
                        "with --target.\nUse absolute paths if you need to "
                        "reference files outside the deployment target."
                    );
                    goto out;
                }
            }

            err = fs_path_join(virtual_root, path, &joined);
            if (err) {
                err = error_wrap(
                    err,
                    "Failed to join deployment target with relative path"
                );
                goto out;
            }
            path_to_make_absolute = joined;
        } else {
            /* Absolute path: prepend virtual_root unless already under it.
             * Cross-product the boundary check against both raw and
             * canonical virtual_root so canonical inputs (from getcwd,
             * find, tab-completion) under a raw --target don't re-prepend
             * to nonsense like /jail/<canonical>/jail/etc/x. */
            bool already_under =
                path_under_dir(path, virtual_root) ||
                path_under_dir(path, virtual_root_canonical);

            if (!already_under) {
                joined = str_format("%s%s", virtual_root, path);
                if (!joined) {
                    err = ERROR(
                        ERR_MEMORY,
                        "Failed to prepend deployment target to path"
                    );
                    goto out;
                }
                path_to_make_absolute = joined;
            }
            /* Otherwise already under virtual_root (raw or canonical),
             * pass through. The post-condition catches lexical traversal
             * that escapes after `..` resolution. */
        }
    }

    /* Step 3: Make absolute (handles absolute pass-through and CWD joining). */
    err = fs_make_absolute(path_to_make_absolute, &absolute);
    if (err) goto out;

    /* Step 4: Normalize (resolve ., .., consecutive slashes). */
    err = fs_normalize_path(absolute, out);
    if (err) goto out;

    /* Step 5: Post-condition — when target mode is active, the normalized
     * result MUST remain under virtual_root in either surface form. Step 2
     * only verifies the input shape; lexical .. resolution in step 4 can
     * move an already_under absolute path back outside (e.g.,
     * /jail/../etc/secret -> /etc/secret). */
    if (virtual_root && virtual_root[0] != '\0') {
        bool under =
            path_under_dir(*out, virtual_root) ||
            path_under_dir(*out, virtual_root_canonical);
        if (!under) {
            char *bad = *out;
            *out = NULL;
            err = ERROR(
                ERR_INVALID_ARG,
                "Path '%s' resolves outside deployment target '%s' after "
                "normalization.\n"
                "Path traversal (..) cannot be used to escape --target.",
                bad, virtual_root
            );
            free(bad);
        }
    }

out:
    free(expanded);
    free(joined);
    free(absolute);
    free(virtual_root_canonical);
    return err;
}

/**
 * Check if path should be ignored.
 *
 * Consults two independent mechanisms in order:
 *   1. `rules` — the user's `.dottaignore` layers (baseline, profile,
 *      config, CLI) compiled into a single gitignore ruleset.
 *   2. `source_filter` — the source tree's own `.gitignore`, if the
 *      caller opted in by building a filter (typically gated on
 *      `config.respect_gitignore`).
 *
 * Either input may be NULL to skip that mechanism. Source-filter
 * errors degrade to a verbose warning and a "not excluded" verdict
 * so an odd source repo never blocks the user from adding a file
 * they explicitly named. The gitignore evaluator never fails — its
 * verdict is applied directly.
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
 * Appends one entry to `directories` on every successful entry (the walker
 * is the sole source of truth for directory tracking), and one entry to
 * `files` for every non-excluded non-directory child. Dedups against
 * already-collected entries so overlapping CLI args (~/.config and
 * ~/.config/fish) don't double-record — within a single walk, tree
 * recursion visits each directory exactly once, so only cross-walk
 * duplicates are possible.
 *
 * Symlinks are never recursed into: symlink-to-dir is treated as an
 * atomic entry by the outer loop and never reaches this function.
 *
 * All pushed strings are owned by the arrays (string_array_push copies).
 * On error, partial results remain in the caller's arrays; the caller's
 * cleanup path frees them.
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

    /* Record this directory. Classification-root skip happens later in
     * the metadata-capture phase; at collection time every walked
     * directory is a tracking candidate. */
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

    /* readdir() returns NULL on both end-of-directory and error.
     * With errno cleared before each call, non-zero errno means I/O error. */
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
    output_t *out
) {
    CHECK_NULL(wt);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);
    CHECK_NULL(metadata);

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
     * Captured here so the sniff happens BEFORE the existing-file
     * removal below — that removal would destroy the byte-truth source.
     * The dotta worktree is checked out to the profile's HEAD upstream
     * of this call, so when dest_path exists it holds the previously-
     * committed bytes — the cheapest source of byte truth for priority-3.
     * For first-time adds dest_path does not exist and the flag stays
     * false; priorities 4/5 then decide. Only consumed in the regular-
     * file branch below (symlinks carry no encryption state to maintain). */
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

        /* Sniff the prior committed bytes BEFORE removing them. Tolerate
         * a transient I/O blip on dest_path: defaulting to "no prior
         * encryption known" lets priorities 4/5 decide; the next dotta
         * update will surface any divergence. */
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
         * Uses lstat to get the symlink's own uid/gid, not the target's.
         * Returns NULL item for home/ prefix or non-root (no metadata needed). */
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
        }

        output_info(
            out, OUTPUT_VERBOSE, "Added symlink: %s -> %s",
            filesystem_path, storage_path
        );
    } else {
        /* Regular file. previously_encrypted was captured from prior
         * committed bytes in the existing-file removal block above (force
         * re-add) or stays false (first-time add); priority-3 in the
         * encryption policy reads byte truth either way. */
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

        /* Store file to worktree (handles read → encrypt → write) and
         * capture both stat data and the byte-derived content kind.
         * SECURITY: Single stat() call eliminates a race condition.
         * INVARIANT: written_kind is byte-truth for the bytes that hit
         * the worktree; metadata.encrypted is stamped from it below. */
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

        /* Stamp metadata.encrypted from byte truth, NOT from policy.
         * This is the write-time invariant: bytes-on-disk and the
         * metadata cache are bound at the same boundary, by construction. */
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
    const config_t *config,
    git_oid *out_commit_oid
) {
    CHECK_NULL(wt);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);
    CHECK_NULL(mounts);

    /* Build commit message using storage paths */
    string_array_t *storage_paths = string_array_new(0);
    if (!storage_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    /* Convert filesystem paths to storage paths for commit message.
     * Files come from the walker output — already absolute and existing. */
    error_t *err = NULL;
    for (size_t i = 0; i < added_files->count; i++) {
        const char *file_path = added_files->items[i];
        char *storage_path = NULL;

        err = mount_classify(mounts, file_path, &storage_path, NULL);
        if (err) {
            /* Skip if conversion fails (shouldn't happen at this point) */
            error_free(err);
            continue;
        }

        err = string_array_push(storage_paths, storage_path);
        free(storage_path);
        if (err) {
            error_free(err);
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
 * Auto-enable newly created profile and sync files to manifest
 *
 * Called when `dotta add -p <profile>` creates a NEW profile branch for the first
 * time. Combines profile enabling with manifest sync in a single atomic transaction.
 *
 * WHY manifest_add_files (not manifest_apply_scope):
 * - These files were just captured FROM disk; the deployment anchor
 *   (deployed_blob_oid, stat_*, deployed_at) should be stamped from that
 *   witness so the next status hits the fast path.
 * - manifest_apply_scope is a pure VWD-cache writer; it never advances the
 *   anchor, which is correct for scope reconciliation but wrong here — we
 *   want fully deployed rows, not staged-for-deployment rows.
 *
 * Algorithm:
 *   1. Open write transaction (creates DB if missing)
 *   2. Read enabled profiles under the transaction snapshot
 *   3. If already enabled: commit (no-op) and return
 *   4. Enable profile in state with deployment target (makes binding available)
 *   5. Sync files to manifest with DEPLOYED status (uses target;
 *      advances deployment anchor for synced entries)
 *   6. Commit transaction atomically
 *
 * CRITICAL ORDER: Step 4 must precede step 5. The target stored in step 4
 * is required by manifest_add_files() in step 5 (which loads the mount table
 * internally) to resolve custom/ storage paths. Transaction atomicity ensures:
 * enable + sync succeed together or fail together (automatic rollback on error).
 *
 * @param repo Git repository (must not be NULL)
 * @param profile Profile to auto-enable (must not be NULL, must exist in Git)
 * @param target Deployment target for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added (must not be NULL)
 * @param out_updated Output flag: true if successful (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *auto_enable_and_sync_profile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const char *profile,
    const char *target,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    string_array_t *enabled_profiles = NULL;
    size_t synced_count = 0;

    *out_updated = false;
    if (out_synced) {
        *out_synced = 0;
    }

    /* STEP 1: Read enabled profiles from the state dispatcher (WRITE) */
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* STEP 2: Check if already enabled (defensive) */
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        if (strcmp(enabled_profiles->items[i], profile) == 0) {
            /* Already enabled - idempotent success. The dispatcher's
             * state_free rolls back the untouched transaction. */
            *out_updated = true;
            goto cleanup;
        }
    }

    /* Append new profile to enabled list for manifest_add_files precedence */
    err = string_array_push(enabled_profiles, profile);
    if (err) {
        err = error_wrap(err, "Failed to add profile to enabled list");
        goto cleanup;
    }

    /* STEP 3: Enable profile in state with deployment target (if provided).
     *
     * CRITICAL ORDER: Must enable BEFORE manifest sync so target
     * is available in state for path resolution during manifest_add_files().
     * The deployment target is stored in the enabled_profiles table and loaded
     * internally by the manifest layer to resolve custom/ storage paths.
     *
     * Transaction Safety: If manifest sync below fails, the dispatcher's
     * state_free automatically rolls back this change. */
    err = state_enable_profile(state, profile, target);
    if (err) {
        err = error_wrap(err, "Failed to enable profile in state");
        goto cleanup;
    }

    /* Build a fresh mount table from the post-enable row cache.
     *
     * STEP 3 mutated enabled_profiles (a new row + target binding), so
     * ctx->mounts (built in run_spec from the pre-mutation snapshot) is
     * stale here. The fresh table is the only handle that classifies
     * paths under the just-bound target as custom/ for manifest_add_files
     * below. Allocated into ctx->arena, reclaimed at command end. */
    mount_table_t *post_enable_mounts = NULL;
    err = profile_build_mount_table(state, arena, &post_enable_mounts);
    if (err) {
        err = error_wrap(err, "Failed to build mount table after enable");
        goto cleanup;
    }

    /* STEP 4: Sync files to manifest with DEPLOYED status
     *
     * manifest_add_files advances the deployment anchor internally for
     * synced entries, so the next status can short-circuit on the fast
     * path without an extra pass here.
     *
     * Precedence: If this profile has lower precedence than existing enabled
     * profiles, some files may be skipped (synced_count < added_files). Those
     * skipped entries correctly receive no anchor advance — any disk stat
     * captured at this site would misattribute to the winner's blob_oid. */
    err = manifest_add_files(
        repo,
        state,
        arena,
        post_enable_mounts,
        profile,
        added_files,
        enabled_profiles,
        &synced_count
    );
    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 5: Commit transaction atomically */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to commit transaction");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) *out_synced = synced_count;

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }

    return err;
}

/**
 * Update manifest after successful add operation
 *
 * Called after Git commit succeeds. Updates manifest for all added files
 * if the profile is enabled. This is part of the Virtual Working Directory
 * integration - maintaining the manifest as an expected state cache.
 *
 * OPTIMIZED: Uses bulk manifest sync (manifest_add_files) with O(M+N) complexity.
 * manifest_add_files builds its own fresh manifest from Git (post-commit state),
 * ensuring all newly-added files are found during precedence checks.
 *
 * Algorithm:
 *   1. Read enabled profiles under the borrowed write transaction
 *   2. If profile not enabled: return (dispatcher's state_free rolls back)
 *   3. If target provided: update target in state (UPSERT)
 *   4. Call manifest_add_files() (builds fresh manifest internally;
 *      advances deployment anchor for synced entries)
 *   5. Commit transaction (state_save)
 *
 * Target Update:
 *   When adding custom/ files to an already-enabled profile, the target
 *   must be stored in state BEFORE manifest_add_files(). This is the same
 *   target-before-sync ordering enforced by auto_enable_and_sync_profile().
 *   Only called when target is non-NULL to avoid clearing an existing
 *   target when adding home/ or root/ files.
 *
 * Lifecycle Tracking:
 *   Files get deployed_at = time(NULL) because ADD captures files FROM the
 *   filesystem. They're already at their target locations, so deployed_at
 *   is set to indicate dotta knows about them.
 *
 * Error Handling:
 *   - Profile not enabled → rollback transaction, return NULL (success, no update)
 *   - Manifest sync fails → rollback, return error
 *
 * Non-Fatal Integration:
 *   Caller should treat manifest update failure as non-fatal warning.
 *   Git commit already succeeded; user can repair with `profile enable`.
 *
 * Performance: O(M + N) where M = total files in all profiles, N = files added
 *
 * @param repo Git repository
 * @param profile Profile that files were added to
 * @param target Deployment target for custom/ files (can be NULL)
 * @param added_files Filesystem paths that were added
 * @param out_updated Output flag: true if manifest was updated (must not be NULL)
 * @param out_synced Output: count of files synced (can be NULL)
 * @return Error or NULL on success
 */
static error_t *update_manifest_after_add(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const char *profile,
    const char *target,
    const string_array_t *added_files,
    bool *out_updated,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(out_updated);

    error_t *err = NULL;
    string_array_t *enabled_profiles = NULL;

    /* Initialize output */
    *out_updated = false;

    /* STEP 1: Read enabled profiles from the state dispatcher (WRITE) */
    err = state_get_profiles(state, &enabled_profiles);
    if (err) {
        err = error_wrap(err, "Failed to get enabled profiles");
        goto cleanup;
    }

    /* STEP 2: Check if this profile is enabled */
    bool is_enabled = false;
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        if (strcmp(enabled_profiles->items[i], profile) == 0) {
            is_enabled = true;
            break;
        }
    }

    if (!is_enabled) {
        /* Profile not enabled - skip manifest update (this is success).
         * The dispatcher's state_free rolls back the untouched
         * transaction. */
        goto cleanup;
    }

    /* STEP 3: Update deployment target in state if adding custom/ files
     *
     * CRITICAL ORDER: Must store target BEFORE manifest_add_files() so
     * the mount table (loaded internally) can resolve custom/ storage paths
     * during manifest building. Same target-before-sync ordering as
     * auto_enable_and_sync_profile().
     *
     * Only called when target is non-NULL to avoid clearing an
     * existing target when adding home/ or root/ files.
     * state_enable_profile() uses UPSERT — cmd_add's pre-flight has
     * already refused the case where target differs from any existing
     * binding, so reaching here means either no prior binding or an
     * idempotent re-bind to the same value. */
    if (target) {
        err = state_enable_profile(state, profile, target);
        if (err) {
            err = error_wrap(err, "Failed to update deployment target for profile");
            goto cleanup;
        }
    }

    /* Build a fresh mount table from the (possibly post-mutation) row
     * cache. When `target` is non-NULL, STEP 3's UPSERT may have rebound
     * the target, invalidating ctx->mounts' classification for paths
     * under the new binding. Build unconditionally so the call shape
     * stays uniform — when no UPSERT ran, the fresh table is equivalent
     * to ctx->mounts (one extra build is the cost of a uniform site). */
    mount_table_t *post_mutation_mounts = NULL;
    err = profile_build_mount_table(state, arena, &post_mutation_mounts);
    if (err) {
        err = error_wrap(err, "Failed to build mount table after add");
        goto cleanup;
    }

    /* STEP 4: Bulk sync operation (O(M+N))
     *
     * manifest_add_files advances the deployment anchor internally for
     * synced entries. Entries skipped by precedence correctly receive
     * no anchor advance, so the winning profile's anchor stays
     * untouched. */
    size_t synced_count = 0;
    err = manifest_add_files(
        repo,
        state,
        arena,
        post_mutation_mounts,
        profile,
        added_files,
        enabled_profiles,
        &synced_count
    );

    if (err) {
        err = error_wrap(err, "Failed to sync files to manifest");
        goto cleanup;
    }

    /* STEP 5: Commit transaction */
    err = state_save(repo, state);
    if (err) {
        err = error_wrap(err, "Failed to save manifest updates");
        goto cleanup;
    }

    /* Success */
    *out_updated = true;
    if (out_synced) *out_synced = synced_count;

cleanup:
    if (enabled_profiles) {
        string_array_free(enabled_profiles);
    }
    /* state is borrowed from the dispatcher. If state_save above
     * succeeded the transaction is committed; otherwise the
     * dispatcher's state_free rolls it back. */

    return err;
}

/**
 * Add command implementation
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->state);

    git_repository *repo = ctx->repo;
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
    size_t added_count = 0;
    bool profile_was_new = false;
    metadata_t *metadata = NULL;
    const mount_table_t *mounts = NULL;

    /* Pre-flight privilege labels. STRING_ARRAY_AUTO releases the
     * backing buffer at scope exit; the privilege call window closes
     * inside this function (or the process re-execs), so the array's
     * lifetime is contained here. */
    string_array_t preflight_labels STRING_ARRAY_AUTO = {0};

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Validate deployment target if provided */
    if (opts->target) {
        err = mount_validate_target(opts->target);
        if (err) goto cleanup;

        /* Pre-flight: refuse silent re-targeting. If the profile is already
         * enabled with a different target, fail BEFORE the Git commit so
         * the user does not end up with a wasted commit + stale binding.
         * Setting a target on a profile that previously had none is fine. */
        const char *existing = state_peek_profile_target(ctx->state, opts->profile);
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
     *     opts->target. Other enabled profiles' bindings are deliberately
     *     excluded — narrows classification to "what would adding to THIS
     *     profile see?", so a path under another profile's --target does
     *     NOT classify as that profile's custom/ namespace. The narrow
     *     view also covers the brand-new-profile case (no row in
     *     ctx->mounts yet) and the existing-profile-same-target case
     *     (idempotent re-bind already verified at the pre-flight check
     *     at the top of this function).
     *
     *   --target absent: borrow ctx->mounts. The full enabled set covers
     *     opts->profile's existing binding (if any) plus HOME and ROOT.
     *     Paths under opts->profile's stored target classify as custom/X
     *     correctly without re-deriving the binding. */
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
        mounts = ctx->mounts;
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

    /* Pre-compute whether deployment target needs elevation. Every
     * input in this add invocation shares opts->target, so the answer
     * is identical for the whole batch — evaluate once, reuse below.
     * The kind-keyed predicate that consumes this mirrors
     * privilege_needs_elevation's rule (ROOT always; CUSTOM iff target
     * outside $HOME); kept inline because the precomputed bool would
     * leak the privilege module's CUSTOM-vs-ROOT branch through any
     * public helper signature. */
    bool custom_needs_elevation = opts->target
        ? privilege_target_needs_elevation(opts->target)
        : false;  /* No target → no custom/ paths → irrelevant */

    /* Collect labels for inputs whose kind needs elevation. Only kinds
     * that actually need elevation are pushed — home/ never does, and
     * custom/ only does when the deployment target is outside $HOME.
     *
     * Each input branch owns its own display string:
     *   - Storage-path input ("home/X" / "root/X" / "custom/X"): the
     *     user-typed string IS the display.
     *   - Filesystem input that classifies cleanly: the classified
     *     storage path the descendants will hit (e.g. "root/etc/hosts").
     *   - Classification root (e.g. "dotta add /"): the typed filesystem
     *     path itself. No storage tail exists for the directory-of-a-mount
     *     case, so the input path is the most informative label. */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file_path = opts->files[i];
        char *absolute = NULL;
        char *storage_path_heap = NULL;
        mount_kind_t kind;

        /* Storage-path input: the input itself is the display. */
        if (mount_kind_extract(file_path, &kind)) {
            if (kind == MOUNT_ROOT ||
                (kind == MOUNT_CUSTOM && custom_needs_elevation)) {
                err = string_array_push(&preflight_labels, file_path);
                if (err) goto cleanup;
            }
            continue;
        }

        /* Filesystem path — normalize raw user input to absolute path first */
        err = add_normalize_input(file_path, opts->target, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", file_path);
            goto cleanup;
        }

        /* Pre-flight policy: skip non-existent paths silently. The main
         * resolution loop's existence check (search "Path not found" below)
         * is the canonical user-facing surface for this error; firing it
         * twice produces no benefit and the pre-flight only exists to
         * answer "would this op touch a path needing elevation?". A
         * non-existent path contributes nothing to that question. */
        if (!fs_lexists(absolute)) {
            free(absolute);
            continue;
        }

        bool is_classification_root = false;
        err = mount_classify(mounts, absolute, &storage_path_heap, &kind);
        if (err) {
            /* A directory input equal to a classification root ($HOME, "/",
             * or --target) has no storage representation; mount_classify
             * returns ERR_INVALID_ARG. The main loop's walker will still
             * expand its descendants — the metadata path handles that fine.
             *
             * What DOES need handling here: the pre-flight's only question
             * is "will this path's expanded descendants need elevation?".
             * mount_classify_kind answers exactly that — same longest-match
             * algorithm, but skips the root-equality error branch. */
            if (err->code == ERR_INVALID_ARG &&
                !fs_is_symlink(file_path) && fs_is_directory(file_path)) {
                error_free(err);
                err = mount_classify_kind(mounts, absolute, &kind);
                free(absolute);
                if (err) {
                    err = error_wrap(err, "Failed to classify '%s'", file_path);
                    goto cleanup;
                }
                is_classification_root = true;
            } else {
                free(absolute);
                err = error_wrap(err, "Failed to resolve path '%s'", file_path);
                goto cleanup;
            }
        } else {
            free(absolute);
        }

        if (kind == MOUNT_ROOT ||
            (kind == MOUNT_CUSTOM && custom_needs_elevation)) {
            const char *display =
                is_classification_root ? file_path : storage_path_heap;
            err = string_array_push(&preflight_labels, display);
            if (err) {
                free(storage_path_heap);
                goto cleanup;
            }
        }
        free(storage_path_heap);  /* may be NULL — free(NULL) is well-defined */
    }

    /* Check privilege requirements
     *
     * If kinds needing root detected without root privileges:
     * - Interactive: Prompts user, re-execs with sudo if approved
     * - Non-interactive: Returns error with clear message
     *
     * If re-exec succeeds, this function DOES NOT RETURN.
     * If re-exec fails or user declines, returns error.
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
     * Fatal on failure: if we cannot build the ignore rules, proceeding
     * would risk tracking files the user explicitly told us to ignore
     * (via baseline, profile, config, or CLI). Surface the error.
     *
     * The profile-specific ruleset (which layers the profile's own
     * `.dottaignore` on top of the common layers) is resolved below,
     * after the branch exists — for a brand-new profile the builder
     * would otherwise try to load a non-existent branch (a non-error,
     * but no point walking that code path). */
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
     * Built once per command and shared across the whole collection
     * walk so the discovered source-repo handle is reused for every
     * file under the same source tree. A non-fatal build failure leaves
     * source_filter NULL, which is_excluded() treats as "layer skipped". */
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
    err = hook_fire_pre(config, out, ctx->repo_path, &hook_inv);
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

    /* Resolve the profile-specific ruleset. Safe for both paths:
     * existing profile → loads the profile's `.dottaignore`; new
     * profile → branch doesn't exist yet, builder treats that as
     * "no profile layer" and the common layers still apply. */
    err = ignore_rules_for_profile(ignore_rules, opts->profile, &profile_rules);
    if (err) {
        err = error_wrap(
            err, "Failed to load ignore rules for profile '%s'", opts->profile
        );
        goto cleanup;
    }

    /* Collect all files to add (expanding directories).
     * The walker appends to both arrays; the caller owns both. */
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
        mount_kind_t kind;
        if (mount_kind_extract(file, &kind)) {

            /* custom/ paths require --target. Pre-validate at the call
             * site so the user gets the directive "pass --target" message
             * rather than mount_resolve's generic "no deployment target
             * for profile" surface. */
            if (kind == MOUNT_CUSTOM) {
                if (!opts->target || opts->target[0] == '\0') {
                    err = ERROR(
                        ERR_INVALID_ARG, "Storage path '%s' requires --target flag\n"
                        "Usage: dotta add -p %s --target /path/to/target %s",
                        file, opts->profile, file
                    );
                    goto cleanup;
                }
            }

            /* CLI input is the write boundary for storage-path arguments.
             * Validate the syntactic shape here so mount_resolve below can
             * trust its input — establishes the invariant once and
             * downstream readers (manifest tree-walk, sync, remove) trust
             * it for the rest of the command. */
            err = mount_validate_storage(file);
            if (err) {
                err = error_wrap(err, "Invalid storage path '%s'", file);
                goto cleanup;
            }

            /* Convert storage path to filesystem path via the mount table.
             * For home/ and root/ the profile is ignored; for custom/
             * the per-profile target binding is consulted. The earlier
             * `kind == MOUNT_CUSTOM` precondition above (--target check)
             * guarantees the lookup binds — surface a contract violation
             * via ERR_INTERNAL if a future change weakens that
             * invariant. */
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
            err = add_normalize_input(file, opts->target, &absolute);
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

            /* Diagnostic: the walker always pushes the CLI-arg directory
             * itself, so all_directories grows by at least one. The file
             * count reflects whether anything trackable was inside. */
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

    /* Check if we have anything to add (files or directories).
     * all_directories may contain classification-root entries that Phase 3
     * skips, but it also captures descendants — so a non-empty array is
     * sufficient evidence that the walk produced something worth committing. */
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

    /* Single-pass: add files and capture metadata inline.
     * Files come from the walker output — already absolute and existing,
     * so mount_classify cannot trip on the existence check that the old
     * legacy wrapper performed. */
    for (size_t i = 0; i < all_files->count; i++) {
        const char *file_path = all_files->items[i];

        /* Compute storage path once */
        char *storage_path = NULL;
        err = mount_classify(mounts, file_path, &storage_path, NULL);
        if (err) {
            err = error_wrap(err, "Failed to convert path '%s'", file_path);
            goto cleanup;
        }

        /* Validate storage path */
        err = mount_validate_storage(storage_path);
        if (err) {
            free(storage_path);
            goto cleanup;
        }

        /* Add file to worktree and capture metadata
         * ARCHITECTURE: add_file_to_worktree handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate TOCTOU */
        err = add_file_to_worktree(
            wt, file_path, storage_path, opts, ctx->keymgr, config, metadata, out
        );
        if (err) {
            free(storage_path);
            err = error_wrap(err, "Failed to add file '%s'", file_path);
            goto cleanup;
        }

        free(storage_path);
        added_count++;
    }

    /* Capture directory metadata for every walked directory.
     *
     * Iterates `all_directories` (filesystem paths produced by the walker)
     * and converts each to a storage path here. The walker records every
     * directory it walks into — including the CLI-arg top-level — so this
     * loop captures the full tree, not just the CLI-named entry points.
     *
     * Classification roots ($HOME, "/", --target) have no storage-path
     * representation: mount_classify returns ERR_INVALID_ARG and we skip
     * them by design. Their descendants are captured normally.
     */
    size_t dir_tracked_count = 0;
    for (size_t i = 0; i < all_directories->count; i++) {
        const char *filesystem_path = all_directories->items[i];

        char *storage_path = NULL;
        err = mount_classify(mounts, filesystem_path, &storage_path, NULL);
        if (err) {
            /* Classification root (filesystem_path equals $HOME, "/", or --target):
             * no storage encoding exists. Skip the root itself; its descendants
             * appear as separate entries and are captured normally. The error
             * message in mount_classify makes this semantic explicit. */
            if (err->code == ERR_INVALID_ARG) {
                error_free(err);
                err = NULL;
                continue;
            }
            err = error_wrap(
                err, "Failed to convert directory path '%s'", filesystem_path
            );
            goto cleanup;
        }

        /* Stat directory to capture mode (and ownership if root/custom). */
        struct stat dir_stat;
        if (stat(filesystem_path, &dir_stat) != 0) {
            output_warning(
                out, OUTPUT_VERBOSE, "Failed to stat directory '%s': %s",
                filesystem_path, strerror(errno)
            );
            free(storage_path);
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
            free(storage_path);
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
        free(storage_path);
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
    err = create_commit(wt, opts, all_files, mounts, config, NULL);
    if (err) goto cleanup;

    /* Update manifest - auto-enable new profiles, sync existing enabled profiles
     *
     * VWD Architecture: When files are committed to an enabled profile, the manifest
     * (virtual working directory) must be updated immediately to maintain consistency.
     *
     * For NEW profiles: Auto-enable provides intuitive UX (creating via 'add' enables it).
     * For EXISTING profiles: Standard behavior (sync only if already enabled).
     *
     * Non-fatal: If manifest update fails, Git commit still succeeded.
     * User can repair manifest by running 'dotta profile enable <profile>'.
     */
    bool manifest_updated = false;
    size_t manifest_synced_count = 0;

    if (profile_was_new) {
        /* AUTO-ENABLE NEW PROFILE
         *
         * UX Decision: Creating a profile via 'add' should enable it automatically.
         * This matches user expectations: "I just added a file, it should be active."
         *
         * Uses manifest_add_files (not manifest_apply_scope) because the files
         * were just captured from disk: we want the deployment anchor stamped
         * from that witness, not left unset for a later status to fill in.
         * apply_scope is the scope reconciler; add is the disk-capture path.
         */
        error_t *enable_err = auto_enable_and_sync_profile(
            repo, ctx->state, ctx->arena, opts->profile, opts->target,
            all_files, &manifest_updated, &manifest_synced_count
        );

        if (enable_err) {
            /* Non-fatal: Git commit succeeded, user can manually enable later */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to auto-enable profile: %s",
                error_message(enable_err)
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to enable manually",
                opts->profile
            );
            error_free(enable_err);
            manifest_updated = false;
            manifest_synced_count = 0;
        }
    } else {
        /* EXISTING PROFILE - Standard manifest update
         *
         * Checks if profile is enabled and syncs if so.
         * If not enabled, skips manifest update (user must explicitly enable).
         */
        error_t *manifest_err = update_manifest_after_add(
            repo, ctx->state, ctx->arena, opts->profile, opts->target,
            all_files, &manifest_updated, &manifest_synced_count
        );

        if (manifest_err) {
            /* Non-fatal: Git commit succeeded */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update manifest: %s",
                error_message(manifest_err)
            );
            output_info(
                out, OUTPUT_NORMAL, "Files committed to Git successfully"
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to sync manifest",
                opts->profile
            );
            error_free(manifest_err);
            manifest_updated = false;
            manifest_synced_count = 0;
        }
    }

    /* Cleanup worktree before post-processing */
    worktree_cleanup(&wt);

    /* Execute post-add hook */
    hook_fire_post(config, out, ctx->repo_path, &hook_inv);

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
                /* Files were added */
                if (profile_was_new) {
                    /* New profile - show sync results with precedence awareness */
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

                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(
                                out, OUTPUT_NORMAL,
                                "Note: %zu file%s overridden by higher-precedence profiles",
                                skipped, skipped == 1 ? "" : "s"
                            );
                        }
                    }
                } else {
                    /* Existing enabled profile */
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
                        if (manifest_synced_count < added_count) {
                            size_t skipped = added_count - manifest_synced_count;
                            output_info(
                                out, OUTPUT_NORMAL,
                                "Note: %zu file%s overridden by higher-precedence profiles",
                                skipped, skipped == 1 ? "" : "s"
                            );
                        }
                    }
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
 * All validation lives here (not in a separate `validate` hook) so
 * the error message can reference the effective invariant rather
 * than a raw count.
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
    /* <profile> <file|dir>... — order-dependent, first is profile.
     * Mirrors clone's raw-bucket-plus-post_parse approach. */
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
    .payload     = &dotta_ext_write_crypto,
    .dispatch    = add_dispatch,
};
