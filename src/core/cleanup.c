/**
 * cleanup.c - Orphaned file and directory pruning implementation
 *
 * Implements safe pruning of orphaned files and directories detected by the
 * workspace module. Provides preflight analysis, safety validation, and
 * deepest-first directory pruning with detailed result reporting.
 *
 * Orphan detection is performed by workspace module (see workspace.c).
 * This module focuses exclusively on safe pruning operations.
 */

#include "core/cleanup.h"

#include <git2.h>
#include <stdlib.h>
#include <string.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "core/safety.h"
#include "core/state.h"
#include "sys/filesystem.h"

/**
 * What stands at an orphaned directory's path, right now
 *
 * The one question the preview and the prune must answer identically, so
 * one function answers it for both.
 *
 * ABSENT is stat truth — a dangling symlink reads absent and its row is
 * reclaimed, which is what the prune's reclaim arm has always done and
 * what the workspace's own on_filesystem says for a directory orphan.
 * Making it lstat-based would change behavior rather than counts, and
 * belongs with the decision about what to do with a foreign occupant.
 *
 * FOREIGN is anything rmdir(2) cannot remove and dotta does not own — a
 * symlink, a regular file. Both phases skip it, under the label the
 * outcome already uses.
 *
 * Only a real directory earns an emptiness verdict, and that is the one
 * thing the two phases decide differently on purpose: the preview against
 * this run's planned effects, the prune against the disk it has changed.
 */
typedef enum {
    DIR_PROBE_ABSENT,      /* Nothing there — reclaimed, no filesystem effect */
    DIR_PROBE_FOREIGN,     /* A symlink or a non-directory — skipped */
    DIR_PROBE_DIRECTORY    /* A directory — emptiness decides */
} dir_probe_t;

static dir_probe_t probe_orphan_directory(const char *path) {
    if (!fs_exists(path)) {
        return DIR_PROBE_ABSENT;
    }
    if (fs_is_symlink(path) || !fs_is_directory(path)) {
        return DIR_PROBE_FOREIGN;
    }

    return DIR_PROBE_DIRECTORY;
}

/**
 * Order two orphaned directories deepest first
 *
 * Descending path length, then ascending path so the order is total and
 * the reports are reproducible.
 */
static int compare_deepest_first(const void *a, const void *b) {
    const char *pa = (*(const workspace_item_t *const *) a)->filesystem_path;
    const char *pb = (*(const workspace_item_t *const *) b)->filesystem_path;

    size_t la = strlen(pa);
    size_t lb = strlen(pb);

    if (la != lb) {
        return (la < lb) ? 1 : -1;
    }

    return strcmp(pa, pb);
}

/**
 * Order orphaned directories so every child precedes its parent
 *
 * A child's path is its parent's path plus a separator and a name, so it
 * is strictly longer; descending length therefore places every directory
 * after its own descendants, and two paths of equal length can never be
 * parent and child. That order is what lets a single pass decide a
 * directory whose emptiness depends on its children — no second look, no
 * iterating to a fixpoint.
 *
 * Established here rather than borrowed from the state layer's
 * ORDER BY filesystem_path: it is this module's correctness that rests on
 * it, and a producer two layers away is free to change its sort.
 *
 * @param dirs Orphaned directory slice (empty yields *out == NULL)
 * @param out Heap array of borrowed items; caller frees with free()
 * @return Error on allocation failure
 */
static error_t *order_deepest_first(
    workspace_items_t dirs,
    const workspace_item_t ***out
) {
    CHECK_NULL(out);

    *out = NULL;

    if (dirs.count == 0) {
        return NULL;
    }

    const workspace_item_t **ordered = malloc(dirs.count * sizeof(*ordered));
    if (!ordered) {
        return ERROR(ERR_MEMORY, "Failed to allocate orphaned directory ordering");
    }

    memcpy(ordered, dirs.entries, dirs.count * sizeof(*ordered));
    qsort(ordered, dirs.count, sizeof(*ordered), compare_deepest_first);

    *out = ordered;
    return NULL;
}

/**
 * Index a safety result by filesystem path
 *
 * O(1) "does a violation stand against this orphan, and which one?" for
 * the walks that ask it: the preflight partition and both of the prune
 * loop's routes to a violation list.
 *
 * Borrowed keys and values — the map must not outlive the safety result it
 * indexes. Yields NULL when there is nothing to index; hashmap_get is
 * NULL-safe, so callers probe the result without a guard.
 *
 * @param violations Safety result to index (may be NULL or empty)
 * @param out Receives the map, or NULL (must not be NULL)
 * @return Error on allocation failure
 */
static error_t *index_violations(const safety_result_t *violations, hashmap_t **out) {
    CHECK_NULL(out);

    *out = NULL;

    if (!violations || violations->count == 0) {
        return NULL;
    }

    hashmap_t *map = hashmap_borrow(violations->count);
    if (!map) {
        return ERROR(ERR_MEMORY, "Failed to create safety violations index");
    }

    for (size_t i = 0; i < violations->count; i++) {
        const safety_violation_t *v = &violations->violations[i];

        error_t *err = hashmap_set(map, v->filesystem_path, (void *) v);
        if (err) {
            hashmap_free(map, NULL);
            return error_wrap(err, "Failed to index safety violations");
        }
    }

    *out = map;
    return NULL;
}

/**
 * Create cleanup result structure
 *
 * Initializes all counters to 0 and allocates string arrays for detailed tracking.
 */
static error_t *create_result(cleanup_result_t **out) {
    CHECK_NULL(out);

    cleanup_result_t *result = calloc(1, sizeof(cleanup_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result");
    }

    /* Allocate detailed tracking arrays (for caller display) */
    result->pruned_files = string_array_new(0);
    result->reclaimed_files = string_array_new(0);
    result->skipped_files = string_array_new(0);
    result->failed_files = string_array_new(0);
    result->released_files = string_array_new(0);
    result->pruned_dirs = string_array_new(0);
    result->reclaimed_dirs = string_array_new(0);
    result->skipped_dirs = string_array_new(0);
    result->failed_dirs = string_array_new(0);

    /* Check allocations */
    if (!result->pruned_files || !result->reclaimed_files || !result->skipped_files ||
        !result->failed_files || !result->released_files || !result->pruned_dirs ||
        !result->reclaimed_dirs || !result->skipped_dirs || !result->failed_dirs) {
        cleanup_result_free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup result arrays");
    }

    /* All other fields initialized to 0/NULL by calloc */
    *out = result;
    return NULL;
}

/**
 * Free cleanup result
 *
 * Frees all allocated resources including detailed tracking arrays and safety violations.
 */
void cleanup_result_free(cleanup_result_t *result) {
    if (!result) {
        return;
    }

    /* Free detailed tracking arrays */
    if (result->pruned_files) string_array_free(result->pruned_files);
    if (result->reclaimed_files) string_array_free(result->reclaimed_files);
    if (result->skipped_files) string_array_free(result->skipped_files);
    if (result->failed_files) string_array_free(result->failed_files);
    if (result->released_files) string_array_free(result->released_files);
    if (result->pruned_dirs) string_array_free(result->pruned_dirs);
    if (result->reclaimed_dirs) string_array_free(result->reclaimed_dirs);
    if (result->skipped_dirs) string_array_free(result->skipped_dirs);
    if (result->failed_dirs) string_array_free(result->failed_dirs);

    /* Free embedded safety violations */
    if (result->safety_violations) {
        safety_result_free(result->safety_violations);
    }

    free(result);
}

/**
 * Free cleanup preflight result
 *
 * Frees all allocated resources including string arrays and safety violations.
 */
void cleanup_preflight_result_free(cleanup_preflight_result_t *result) {
    if (!result) {
        return;
    }

    /* All NULL-safe: a result abandoned part-way through construction is
     * freed by the same call as a complete one. */
    string_array_free(result->prunable_files);
    string_array_free(result->prunable_dirs);
    string_array_free(result->skipped_dirs);
    safety_result_free(result->safety_violations);

    free(result);
}

/**
 * Prune orphaned files from the filesystem
 *
 * Uses pre-computed orphan list from opts->orphaned_files to prune files
 * after safety validation. Integrates with safety module to prevent data loss.
 *
 * Algorithm:
 * 1. Use pre-computed orphan list (workspace items with divergence data)
 * 2. Run safety checks using safety_check_orphans() (trusts workspace divergence)
 * 3. Prune the files safety cleared, skip the rest, track failures
 *
 * Key Optimization:
 *   Passes workspace items directly to safety_check_orphans() which trusts
 *   workspace's pre-computed divergence. No path extraction or redundant
 *   verification needed.
 *
 * @param repo Repository (must not be NULL)
 * @param state State for safety check lookups (must not be NULL)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL, orphaned_files slice may be empty)
 * @return Error or NULL on success
 */
static error_t *prune_orphaned_files(
    git_repository *repo,
    const state_t *state,
    cleanup_result_t *result,
    const cleanup_options_t *opts
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(result);
    CHECK_NULL(opts);

    error_t *err = NULL;
    hashmap_t *violations_map = NULL;

    bool dry_run = opts->dry_run;
    bool force = opts->force;

    workspace_items_t orphans = opts->orphaned_files;

    /* Early exit if no orphaned files */
    if (orphans.count == 0) {
        return NULL;
    }

    /* Build violations map from preflight data or run safety check
     *
     * Three paths for handling safety validation:
     * 1. Preflight was run (preflight_violations != NULL) - trust completely
     * 2. No preflight, run safety check (preflight_violations == NULL, !skip_safety_check)
     * 3. No preflight, skip safety (preflight_violations == NULL, skip_safety_check)
     *
     * Key insight: Non-NULL preflight_violations means preflight was performed.
     * Trust the results completely, even if count == 0 (means all files are safe).
     * This eliminates redundant safety checks and makes the API self-documenting.
     */
    if (!force) {
        if (opts->preflight_violations != NULL) {
            /* Path 1: Preflight was run - trust results completely
             *
             * Non-NULL preflight_violations indicates preflight check was performed.
             * Trust the results even if count == 0 (means all files verified safe).
             *
             * This avoids re-running expensive safety checks (Git comparisons,
             * content decryption) that were already performed in preflight.
             *
             * TOCTOU trust model: This function trusts preflight results completely.
             * The CALLER is responsible for passing NULL when preflight results may
             * be stale (e.g., after interactive confirmation prompts where user delay
             * could allow file modifications). See cleanup.h for full contract.
             *
             * Memory ownership: opts->preflight_violations is a BORROWED reference.
             * We index it but do NOT store it in result. The caller (apply.c)
             * owns and will free the safety_result_t.
             */
            RETURN_IF_ERROR(index_violations(opts->preflight_violations, &violations_map));

        } else if (!opts->skip_safety_check) {
            /* Path 2: No preflight - run safety check now
             *
             * This path is taken when:
             * - No preflight was run (preflight_violations == NULL)
             * - Caller wants safety validation (skip_safety_check == false)
             *
             * Uses safety_check_orphans() which trusts workspace divergence
             * completely. Non-encrypted files use streaming OID verification
             * (any size). Encrypted >100MB get CANNOT_VERIFY violation.
             */
            err = safety_check_orphans(
                repo,
                state,
                orphans,
                force,
                &result->safety_violations
            );

            if (err) {
                /* Fatal error during safety check */
                return error_wrap(err, "Safety check failed");
            }

            RETURN_IF_ERROR(index_violations(result->safety_violations, &violations_map));
        }
        /* Path 3 (implicit): preflight_violations == NULL && skip_safety_check == true
         * No safety check runs, no violations map built.
         * Used for emergency cleanup when caller explicitly skips safety.
         */
    }

    /* Prune the orphaned files and populate result arrays for caller display */
    for (size_t i = 0; i < orphans.count; i++) {
        const char *path = orphans.entries[i]->filesystem_path;

        /* Check for safety violations using O(1) hashmap lookup
         * (a NULL map reads as "no violation" — see index_violations) */
        const safety_violation_t *violation = hashmap_get(violations_map, path);

        if (violation) {
            if (strcmp(violation->reason, SAFETY_REASON_RELEASED) == 0) {
                /* RELEASED: File removed from Git externally (loss of authority)
                 *
                 * Triggers: branch deleted, file removed from branch, LIFECYCLE_RELEASED.
                 * - DO NOT remove file (Git cannot back it, protect user data)
                 * - DO track for state cleanup (can't manage without Git backing)
                 *
                 * The file is "released" from dotta's management.
                 */
                err = string_array_push(result->released_files, path);
                if (err) {
                    err = error_wrap(err, "Failed to track released file");
                    if (violations_map) hashmap_free(violations_map, NULL);
                    return err;
                }
                continue;
            }

            /* Other violations (MODIFIED, MODE_CHANGED, etc.): full skip */
            err = string_array_push(result->skipped_files, path);
            if (err) {
                err = error_wrap(err, "Failed to track skipped file");
                if (violations_map) hashmap_free(violations_map, NULL);
                return err;
            }
            continue;
        }

        /* Already-absent orphan: no filesystem effect happened or was
         * needed — track for state retirement only. Reporting it as
         * "pruned" would claim an effect that never occurred.
         *
         * lstat, matching both the workspace's on_filesystem for a file
         * orphan and unlink's own view of the path: a symlink row whose
         * link now dangles is an object dotta deployed and is here to
         * remove, not an absence to reclaim around. stat would follow the
         * link, call it gone, retire the row and leave the link behind
         * with nothing left that knows about it. */
        if (!fs_lexists(path)) {
            if (!dry_run) {
                err = string_array_push(result->reclaimed_files, path);
                if (err) {
                    err = error_wrap(err, "Failed to track reclaimed file");
                    if (violations_map) hashmap_free(violations_map, NULL);
                    return err;
                }
            }
            continue;
        }

        /* Dry run: nothing is pruned. cleanup_preflight_check is the
         * answer to "what would be". */
        if (dry_run) {
            continue;
        }

        error_t *remove_err = fs_remove_file(path);
        if (remove_err) {
            /* Non-fatal: track failure and continue */
            err = string_array_push(result->failed_files, path);
            if (err) {
                error_free(remove_err);
                err = error_wrap(err, "Failed to track failed file");
                if (violations_map) hashmap_free(violations_map, NULL);
                return err;
            }
            error_free(remove_err);
        } else {
            err = string_array_push(result->pruned_files, path);
            if (err) {
                err = error_wrap(err, "Failed to track pruned file");
                if (violations_map) hashmap_free(violations_map, NULL);
                return err;
            }
        }
    }

    /* Cleanup */
    if (violations_map) hashmap_free(violations_map, NULL);
    return NULL;
}

/**
 * Prune orphaned directories
 *
 * Runs after the orphaned files have been pruned, so the filesystem it
 * looks at is the one the user will be left with: a directory whose only
 * contents were orphaned files is empty by now and is seen as such.
 *
 * One deepest-first pass. Every child is decided before its parent, so a
 * parent that this run empties is seen empty when its turn comes — the
 * whole reason the old iterate-until-stable loop existed. Emptiness is
 * read from the disk this run has just changed; cleanup_preflight_check
 * predicted the same answer from the plan, and this is where the
 * prediction is confirmed or reported broken.
 *
 * fs_remove_empty_dir is the mechanism and also the guard: it clears the
 * OS metadata fs_is_directory_empty looked past and nothing else, so an
 * entry that arrives between the check and the removal stops it rather
 * than going with it. That refusal is the "not empty" verdict by another
 * route — ERR_CONFLICT — not a failure.
 *
 * @param orphaned_dirs Pre-computed orphan slice (count == 0 is valid)
 * @param result Cleanup result to update (must not be NULL)
 * @param opts Cleanup options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *prune_orphaned_directories(
    workspace_items_t orphaned_dirs,
    cleanup_result_t *result,
    const cleanup_options_t *opts
) {
    CHECK_NULL(result);
    CHECK_NULL(opts);

    const workspace_item_t **ordered = NULL;
    RETURN_IF_ERROR(order_deepest_first(orphaned_dirs, &ordered));

    /* Early exit: no orphaned directories */
    if (!ordered) {
        return NULL;
    }

    error_t *err = NULL;

    for (size_t i = 0; i < orphaned_dirs.count && !err; i++) {
        const char *dir_path = ordered[i]->filesystem_path;

        switch (probe_orphan_directory(dir_path)) {
            case DIR_PROBE_ABSENT:
                /* No filesystem effect happened or was needed — the row is
                 * retired, nothing is removed. */
                if (!opts->dry_run) {
                    err = string_array_push(result->reclaimed_dirs, dir_path);
                }
                continue;

            case DIR_PROBE_FOREIGN:
                err = string_array_push(result->skipped_dirs, dir_path);
                continue;

            case DIR_PROBE_DIRECTORY:
                break;
        }

        if (!fs_is_directory_empty(dir_path)) {
            err = string_array_push(result->skipped_dirs, dir_path);
            continue;
        }

        /* Dry run: nothing is pruned. cleanup_preflight_check is the
         * answer to "what would be". */
        if (opts->dry_run) {
            continue;
        }

        error_t *remove_err = fs_remove_empty_dir(dir_path);
        if (!remove_err) {
            err = string_array_push(result->pruned_dirs, dir_path);
            continue;
        }

        /* Non-fatal either way: record which it was and carry on. */
        bool gained_content = (error_code(remove_err) == ERR_CONFLICT);
        error_free(remove_err);

        err = string_array_push(
            gained_content ? result->skipped_dirs : result->failed_dirs, dir_path
        );
    }

    free(ordered);

    return err ? error_wrap(err, "Failed to record orphaned directory outcome") : NULL;
}

/**
 * Is this directory entry one the run is about to prune?
 *
 * The hole in the preview's emptiness walk. Membership is keyed by
 * filesystem path, which is why the entry arrives as a full path rather
 * than a basename.
 */
static bool entry_is_prunable(const char *child, void *prunable) {
    return hashmap_has((const hashmap_t *) prunable, child);
}

/**
 * Is `path` strictly inside `dir`?
 *
 * A prefix test with a separator, so "/a/bc" is not inside "/a/b" — and
 * neither is "/a/b" itself. Both sides are canonical filesystem paths
 * without a trailing separator.
 */
static bool path_is_under(const char *path, const char *dir) {
    size_t len = strlen(dir);

    /* strncmp == 0 guarantees path has at least len bytes, so reading
     * path[len] is in bounds — it is either the terminator or a real
     * character. */
    return strncmp(path, dir, len) == 0 && path[len] == '/';
}

/**
 * Will this run's deployment put something inside this directory?
 *
 * Deployment runs before cleanup, so a path the plan is about to
 * materialize is content that will be there when the prune looks — even
 * though nothing of it is on disk now, which is exactly why the disk
 * cannot answer this and the plan must.
 *
 * Every directory above a deployed path is occupied by it, not just its
 * immediate parent: the ones deployment creates on the way count too.
 */
static bool deploys_into(const cleanup_options_t *opts, const char *dir) {
    for (size_t i = 0; i < opts->deploying_files.count; i++) {
        if (path_is_under(opts->deploying_files.entries[i]->filesystem_path, dir)) {
            return true;
        }
    }

    for (size_t i = 0; i < opts->deploying_directories.count; i++) {
        if (path_is_under(opts->deploying_directories.entries[i]->filesystem_path, dir)) {
            return true;
        }
    }

    return false;
}

/**
 * Predict which orphaned directories the prune will reach
 *
 * A directory is prunable iff everything in it is OS metadata, a file this
 * run unlinks, or an orphaned directory beneath it that is itself prunable
 * — and nothing this run deploys lands inside it. That is what the prune
 * arrives at by acting, read off the plan here in one pass because
 * order_deepest_first decides every child before its parent.
 *
 * `prunable` enters holding every prunable file and leaves holding every
 * prunable directory as well, which is what lets a parent see its pruned
 * children as gone. Borrowed keys, all workspace-owned.
 *
 * The arrays fill in walk order, which is prune order: deepest first.
 *
 * @param opts Cleanup options (orphaned and deploying slices)
 * @param prunable Set of paths this run prunes (must not be NULL)
 * @param result Preflight result to fill (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *predict_prunable_dirs(
    const cleanup_options_t *opts,
    hashmap_t *prunable,
    cleanup_preflight_result_t *result
) {
    CHECK_NULL(opts);
    CHECK_NULL(prunable);
    CHECK_NULL(result);

    workspace_items_t dirs = opts->orphaned_directories;

    const workspace_item_t **ordered = NULL;
    RETURN_IF_ERROR(order_deepest_first(dirs, &ordered));

    if (!ordered) {
        return NULL;
    }

    error_t *err = NULL;

    for (size_t i = 0; i < dirs.count && !err; i++) {
        const char *path = ordered[i]->filesystem_path;

        switch (probe_orphan_directory(path)) {
            case DIR_PROBE_ABSENT:
                /* A pure state reclaim: no filesystem effect to preview. Not a
                 * departure either — a dangling link reads absent here and
                 * still occupies its parent, and nothing removes it. */
                continue;

            case DIR_PROBE_FOREIGN:
                err = string_array_push(result->skipped_dirs, path);
                continue;

            case DIR_PROBE_DIRECTORY:
                break;
        }

        if (fs_is_directory_empty_except(path, entry_is_prunable, prunable) &&
            !deploys_into(opts, path)) {
            err = string_array_push(result->prunable_dirs, path);

            /* Its parent must see it as gone when its own turn comes. */
            if (!err) {
                err = hashmap_set(prunable, path, (void *) path);
            }
        } else {
            err = string_array_push(result->skipped_dirs, path);
        }
    }

    free(ordered);

    return err ? error_wrap(err, "Failed to preview orphaned directories") : NULL;
}

/**
 * Run cleanup preflight checks
 *
 * Analyzes what cleanup will do WITHOUT modifying the filesystem, and
 * decides every verdict its callers display: which present orphaned files
 * will be pruned, which are held back and why, and which orphaned
 * directories the prune will reach once those files have gone.
 */
error_t *cleanup_preflight_check(
    git_repository *repo,
    const state_t *state,
    const cleanup_options_t *opts,
    cleanup_preflight_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(opts);
    CHECK_NULL(out_result);

    error_t *err = NULL;
    hashmap_t *violations = NULL;   /* path -> safety_violation_t *, NULL when none */
    hashmap_t *prunable = NULL;     /* every path this run prunes, as it is decided */

    cleanup_preflight_result_t *result = calloc(1, sizeof(cleanup_preflight_result_t));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate cleanup preflight result");
    }

    /* Always allocated, so an empty answer needs no NULL guard downstream. */
    result->prunable_files = string_array_new(0);
    result->prunable_dirs = string_array_new(0);
    result->skipped_dirs = string_array_new(0);
    if (!result->prunable_files || !result->prunable_dirs || !result->skipped_dirs) {
        err = ERROR(ERR_MEMORY, "Failed to allocate cleanup preflight arrays");
        goto cleanup;
    }

    /* Safety decides each present file orphan; the partition is taken once,
     * here. force goes through rather than around it: an empty verdict is
     * the answer under force, and routing it the same way keeps
     * safety_violations allocated so no consumer NULL-checks it. */
    err = safety_check_orphans(
        repo, state, opts->orphaned_files, opts->force, &result->safety_violations
    );
    if (err) {
        err = error_wrap(err, "Safety check failed");
        goto cleanup;
    }

    err = index_violations(result->safety_violations, &violations);
    if (err) {
        goto cleanup;
    }

    /* Everything this run prunes, in one set: the directory prediction
     * asks it about every entry it meets. */
    prunable = hashmap_borrow(
        opts->orphaned_files.count + opts->orphaned_directories.count
    );
    if (!prunable) {
        err = ERROR(ERR_MEMORY, "Failed to allocate prune set");
        goto cleanup;
    }

    /* Present orphans that no violation holds back. An already-absent one
     * is a pure state reclaim with no filesystem effect, so it belongs to
     * neither the preview nor the prune set; on_filesystem was
     * established by workspace orphan analysis and is trusted here. */
    for (size_t i = 0; i < opts->orphaned_files.count; i++) {
        const workspace_item_t *orphan = opts->orphaned_files.entries[i];

        if (!orphan->on_filesystem) {
            continue;
        }
        if (hashmap_get(violations, orphan->filesystem_path)) {
            continue;   /* Safety counted it, as blocking or as released */
        }

        err = string_array_push(result->prunable_files, orphan->filesystem_path);
        if (!err) {
            err = hashmap_set(
                prunable, orphan->filesystem_path, (void *) orphan->filesystem_path
            );
        }
        if (err) {
            err = error_wrap(err, "Failed to record prunable orphan");
            goto cleanup;
        }
    }

    err = predict_prunable_dirs(opts, prunable, result);
    if (err) {
        goto cleanup;
    }

    *out_result = result;
    result = NULL;

cleanup:
    hashmap_free(prunable, NULL);
    hashmap_free(violations, NULL);
    cleanup_preflight_result_free(result);   /* NULL unless an error path still owns it */

    return err;
}

/**
 * Execute cleanup operations
 *
 * Main entry point for cleanup module. Coordinates orphaned file pruning
 * and the pruning of the directories those files emptied, with safety
 * checks.
 */
error_t *cleanup_execute(
    git_repository *repo,
    const state_t *state,
    const cleanup_options_t *opts,
    cleanup_result_t **out_result
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(opts);
    CHECK_NULL(out_result);

    error_t *err = NULL;
    cleanup_result_t *result = NULL;

    /* Create result structure */
    err = create_result(&result);
    if (err) {
        return err;
    }

    /* Step 1: Prune the orphaned files safety clears */
    err = prune_orphaned_files(repo, state, result, opts);
    if (err) {
        cleanup_result_free(result);
        return error_wrap(err, "Failed to prune orphaned files");
    }

    /* Step 2: Prune the orphaned directories those files emptied */
    err = prune_orphaned_directories(opts->orphaned_directories, result, opts);
    if (err) {
        cleanup_result_free(result);
        return error_wrap(err, "Failed to prune orphaned directories");
    }

    /* Return result */
    *out_result = result;
    return NULL;
}
