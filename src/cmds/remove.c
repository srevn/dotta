/**
 * remove.c - Remove paths from profiles or delete profiles
 */

#include "cmds/remove.h"

#include <config.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_remove_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    /* If deleting profile, paths are optional */
    if (opts->delete_profile) {
        if (opts->paths && opts->path_count > 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Cannot specify paths when using --delete-profile"
            );
        }
        return NULL;
    }

    /* If not deleting profile, paths are required */
    if (!opts->paths || opts->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "At least one path is required (or use --delete-profile)"
        );
    }

    /* Interactive mode requires a terminal for user prompts — refused at entry,
     * before any hook fires or any work begins */
    if (opts->interactive && !isatty(STDIN_FILENO)) {
        return ERROR(
            ERR_INVALID_ARG,
            "Interactive mode requires a terminal (stdin is not a TTY)"
        );
    }

    return NULL;
}

/**
 * One claim of the profile branch: a tracked path in storage terms, either kind
 * — a tree blob (FILE) or a metadata directory item (DIRECTORY).
 *
 * The branch's claims are the argument universe of a removal — never the view:
 * a disabled profile's paths must stay removable (the view holds only enabled
 * profiles), an unbound custom claim too (the view refuses it), and a shadowed
 * claim is still the branch's to remove (the view is precedence-resolved).
 */
typedef struct {
    const char *storage_path;      /* arena */
    const char *filesystem_path;   /* arena; the storage path itself when this
                                    * machine cannot project the claim */
    path_kind_t kind;
} removal_claim_t;

/**
 * Resolve the arguments to the claims they remove
 *
 * Accepts both filesystem paths and storage paths as input. Each argument matches
 * claims of either kind: the exact claim and — at a '/' boundary, never a false
 * prefix like home/dir2 for home/dir — every claim beneath it (naming a directory
 * means untracking it whole). A claim is removed once, however many arguments
 * match it.
 *
 * The claims array starts as everything the branch holds, in branch order (the
 * tree's blobs, then the directory items); the arguments mark what they take,
 * and the array compacts to just that. The filesystem path is filled at compaction
 * — it is display and record plumbing, not resolution: when this machine cannot
 * project a claim, the storage path stands in and removal proceeds regardless.
 *
 * The branch's metadata rides out through `metadata_out` for the commit's edit
 * — loaded once, where the directory claims are enumerated. NULL when the branch
 * has none; caller frees.
 *
 * @param ctx Dispatch context (must not be NULL). ctx->run.mounts covers HOME,
 *            ROOT, and every enabled profile's binding. Unenabled-profile lookups
 *            (custom/X) surface MOUNT_RESOLVE_UNBOUND, which the compaction handles
 *            as "no filesystem path on this machine".
 * @param claims_out The claims the arguments took, borrowed from ctx->arena (do
 *            not free)
 */
static error_t *resolve_removal_claims(
    const dotta_ctx_t *ctx,
    const char *profile,
    char **input_paths,
    size_t path_count,
    const cmd_remove_options_t *opts,
    removal_claim_t **claims_out,
    size_t *count_out,
    metadata_t **metadata_out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(profile);
    CHECK_NULL(input_paths);
    CHECK_NULL(opts);
    CHECK_NULL(claims_out);
    CHECK_NULL(count_out);
    CHECK_NULL(metadata_out);

    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    string_array_t *profile_files = NULL;
    metadata_t *metadata = NULL;
    const metadata_item_t **dir_items = NULL;

    /* The branch's claims: the tree's blobs, then the metadata's directory
     * claims. */
    err = profile_list_files(repo, profile, &profile_files);
    if (err) {
        return error_wrap(err, "Failed to list files in profile");
    }

    err = metadata_load_from_branch(repo, profile, &metadata);
    if (err) {
        if (err->code != ERR_NOT_FOUND) {
            err = error_wrap(
                err, "Failed to load metadata for profile '%s'", profile
            );
            goto cleanup;
        }
        /* No metadata file: no directory claims */
        error_free(err);
        err = NULL;
    }

    size_t dir_count = 0;
    if (metadata) {
        dir_items = metadata_get_items_by_kind(
            metadata, METADATA_ITEM_DIRECTORY, &dir_count
        );
    }

    removal_claim_t *claims = NULL;
    bool *taken = NULL;            /* beside claims[j]: an argument took it */
    size_t claim_count = 0;
    if (profile_files->count + dir_count > 0) {
        claims = arena_alloc(
            ctx->arena,
            (profile_files->count + dir_count) * sizeof(removal_claim_t)
        );
        taken = arena_calloc(
            ctx->arena, profile_files->count + dir_count, sizeof(bool)
        );
        if (!claims || !taken) {
            err = ERROR(ERR_MEMORY, "Failed to allocate claims array");
            goto cleanup;
        }
    }

    for (size_t i = 0; i < profile_files->count; i++) {
        const char *copy = arena_strdup(ctx->arena, profile_files->items[i]);
        if (!copy) {
            err = ERROR(ERR_MEMORY, "Failed to copy claim path");
            goto cleanup;
        }
        claims[claim_count++] = (removal_claim_t) {
            .storage_path = copy, .kind = PATH_KIND_FILE
        };
    }

    for (size_t i = 0; i < dir_count; i++) {
        const char *key = dir_items[i]->key;

        /* Same-profile rule as the view's claim routine (manifest.c): a key the
         * tree holds as a blob cannot also stand as a directory claim — the tree's
         * blob outranks the stale item. Keeps every claim path unique, so one
         * argument takes one claim. */
        bool held_as_blob = false;
        for (size_t j = 0; j < profile_files->count && !held_as_blob; j++) {
            held_as_blob = strcmp(profile_files->items[j], key) == 0;
        }
        if (held_as_blob) continue;

        const char *copy = arena_strdup(ctx->arena, key);
        if (!copy) {
            err = ERROR(ERR_MEMORY, "Failed to copy claim path");
            goto cleanup;
        }
        claims[claim_count++] = (removal_claim_t) {
            .storage_path = copy, .kind = PATH_KIND_DIRECTORY
        };
    }

    /* Match each argument, marking the claims it takes */
    for (size_t i = 0; i < path_count; i++) {
        const char *input_path = input_paths[i];
        const char *storage_path = NULL;

        /* Resolve input path to storage format (file need not exist) */
        err = path_input_resolve(mounts, input_path, ctx->arena, &storage_path);
        if (err) {
            if (!opts->force) {
                goto cleanup;
            }
            /* With --force, skip this path */
            output_warning(
                out, OUTPUT_VERBOSE, "Skipping invalid path '%s': %s",
                input_path, error_message(err)
            );
            error_free(err);
            err = NULL;
            continue;
        }

        size_t storage_path_len = strlen(storage_path);
        size_t matches_found = 0;

        for (size_t j = 0; j < claim_count; j++) {
            /* The exact claim, or one beneath it at a directory boundary */
            if (!str_starts_with(claims[j].storage_path, storage_path)) continue;
            char boundary = claims[j].storage_path[storage_path_len];
            if (boundary != '\0' && boundary != '/') continue;

            matches_found++;
            taken[j] = true;
        }

        if (matches_found == 0) {
            if (!opts->force) {
                err = ERROR(
                    ERR_NOT_FOUND, "Path '%s' not found in profile '%s'\n"
                    "Hint: Use 'dotta list --profile %s' to see tracked paths",
                    storage_path, profile, profile
                );
                goto cleanup;
            }
            /* With --force, warn and skip */
            output_warning(
                out, OUTPUT_VERBOSE, "Path '%s' not found in profile, skipping",
                storage_path
            );
        }
    }

    /* Compact to the taken claims and fill their filesystem paths — the path as
     * this profile deploys the claim, for display and the hook context. UNBOUND
     * fires when the profile has no --target on this machine; genuine resolve
     * errors (malformed storage, OOM) are non-fatal here too — the storage path
     * serves as fallback either way, and downstream consumers handle it gracefully:
     * state lookups return "not found", display shows storage format. */
    size_t taken_count = 0;
    for (size_t j = 0; j < claim_count; j++) {
        if (!taken[j]) continue;

        mount_resolve_outcome_t outcome;
        const char *fs_path = NULL;
        error_t *resolve_err = mount_resolve(
            mounts, profile, claims[j].storage_path, ctx->arena,
            &outcome, &fs_path
        );
        if (resolve_err) {
            error_free(resolve_err);
            fs_path = NULL;
        } else if (outcome == MOUNT_RESOLVE_UNBOUND) {
            fs_path = NULL;
        }

        claims[j].filesystem_path = fs_path ? fs_path : claims[j].storage_path;
        claims[taken_count++] = claims[j];
    }

    /* Check if the arguments took any claims */
    if (taken_count == 0) {
        err = ERROR(
            ERR_NOT_FOUND, "No paths found to remove from profile '%s'",
            profile
        );
        goto cleanup;
    }

    /* Success — the claims are arena-backed; the metadata rides out for the
     * commit's edit */
    *claims_out = claims;
    *count_out = taken_count;
    *metadata_out = metadata;
    metadata = NULL;

cleanup:
    /* Free all resources */
    free(dir_items);
    if (metadata) metadata_free(metadata);
    if (profile_files) string_array_free(profile_files);

    return err;
}

/**
 * Analyze multi-profile conflicts for claims to be removed
 *
 * Checks each file claim against all other profiles and determines:
 * - Which other profiles contain the file
 * - Whether the file is owned by another profile in the view — the enabled set's
 *   precedence gives the path to a profile other than the one the user is removing
 *   from, so the removal changes nothing on disk
 *
 * Directory claims are not in the file index and get no cross-profile warning:
 * the record step's fallback detection covers the semantic half (a lower enabled
 * profile still claiming the path keeps the record, which reads [reassigned]
 * until apply).
 *
 * Performance: O(M×P + N) where M=profiles, P=avg files/profile, N=claims checked
 * Uses centralized profile_build_file_index() for optimal performance.
 *
 * Hands the profile file index (storage_path → the other profiles claiming it)
 * to the caller so the display can borrow from it; free with hashmap_free(...,
 * string_array_free_cb).
 */
static error_t *analyze_multi_profile_conflicts(
    const dotta_ctx_t *ctx,
    const removal_claim_t *claims,
    size_t claim_count,
    const char *current_profile,
    hashmap_t **profile_index_out,
    size_t *multi_profile_count_out,
    bool *has_deployed_from_other_out
) {
    CHECK_NULL(ctx);
    CHECK_NULL(claims);
    CHECK_NULL(current_profile);
    CHECK_NULL(profile_index_out);
    CHECK_NULL(multi_profile_count_out);
    CHECK_NULL(has_deployed_from_other_out);

    git_repository *repo = ctx->run.repo;
    const manifest_t *view = ctx->run.manifest;

    /* Build profile file index once (O(M×P) - loads all profiles) Uses centralized
     * function from core/profiles.c */
    hashmap_t *profile_index = NULL;
    error_t *err = profile_build_file_index(repo, current_profile, &profile_index);
    if (err) {
        return error_wrap(err, "Failed to build profile index");
    }

    size_t multi_profile_count = 0;
    bool has_deployed_from_other = false;

    /* Check each claim using O(1) index lookups */
    for (size_t i = 0; i < claim_count; i++) {
        const removal_claim_t *claim = &claims[i];

        /* Lookup profiles containing this file - O(1) */
        string_array_t *indexed_profiles = hashmap_get(
            profile_index, claim->storage_path
        );
        if (!indexed_profiles || indexed_profiles->count == 0) {
            continue;
        }
        multi_profile_count++;

        /* Check if another profile owns the path in the view. Only valid with
         * actual filesystem paths (absolute), not storage path fallbacks (relative,
         * e.g., "home/.bashrc"). */
        if (claim->filesystem_path[0] == '/') {
            const manifest_row_t *row = manifest_lookup(view, claim->filesystem_path);
            if (row && strcmp(row->profile, current_profile) != 0) {
                has_deployed_from_other = true;
            }
        }
    }

    *profile_index_out = profile_index;
    *multi_profile_count_out = multi_profile_count;
    *has_deployed_from_other_out = has_deployed_from_other;

    return NULL;
}

/**
 * Display multi-profile warnings to the user
 *
 * Shows which files exist in multiple profiles and explains the implications.
 * Borrows the analysis's profile index for each file's "also in" list.
 */
static void display_multi_profile_warnings(
    output_t *out,
    const removal_claim_t *claims,
    size_t claim_count,
    const hashmap_t *profile_index,
    size_t multi_profile_count,
    bool has_deployed_from_other,
    const char *current_profile
) {
    if (!out || multi_profile_count == 0) return;

    output_section(out, OUTPUT_NORMAL, "Multi-profile file warning");
    output_warning(
        out, OUTPUT_NORMAL, "Found %zu file%s in multiple profiles:",
        multi_profile_count, multi_profile_count == 1 ? "" : "s"
    );

    /* Display each multi-profile file */
    for (size_t i = 0; i < claim_count; i++) {
        const string_array_t *others = hashmap_get(
            profile_index, claims[i].storage_path
        );
        if (!others || others->count == 0) {
            continue;
        }

        output_styled(
            out, OUTPUT_NORMAL, "  {yellow}%s{reset} also in:",
            claims[i].filesystem_path
        );

        for (size_t j = 0; j < others->count; j++) {
            output_styled(
                out, OUTPUT_NORMAL, " {cyan}%s{reset}",
                others->items[j]
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

    /* Explain implications */
    output_newline(out, OUTPUT_NORMAL);
    output_info(
        out, OUTPUT_NORMAL,
        "These files will be removed only from profile '%s'.",
        current_profile
    );

    if (has_deployed_from_other) {
        output_warning(
            out, OUTPUT_NORMAL,
            "Some files are currently deployed from other profiles."
        );
        output_info(
            out, OUTPUT_NORMAL,
            "Those files will remain on the filesystem."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "Files deployed from '%s' will remain until 'dotta apply'.",
            current_profile
        );
    }
    output_newline(out, OUTPUT_NORMAL);
}

/**
 * Format a claim count for display: "2 files", "1 directory", or "2 files and 1
 * directory". The directory half appears only when dirs is non-zero, so file-only
 * wordings stay exactly what they were. Three distant sites print the phrase
 * (the dry-run total, the confirmation prompt, the receipt) and tests pin the
 * wording — one spelling.
 */
static void format_claim_counts(
    char *buf, size_t size, size_t files, size_t dirs
) {
    if (dirs == 0) {
        snprintf(buf, size, "%zu file%s", files, files == 1 ? "" : "s");
    } else if (files == 0) {
        snprintf(buf, size, "%zu director%s", dirs, dirs == 1 ? "y" : "ies");
    } else {
        snprintf(
            buf, size, "%zu file%s and %zu director%s",
            files, files == 1 ? "" : "s", dirs, dirs == 1 ? "y" : "ies"
        );
    }
}

/**
 * Confirm removal operation
 */
static bool confirm_removal(
    const removal_claim_t *claims,
    size_t claim_count,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    if (!claims || !opts || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    /* Skip confirmation for dry run */
    if (opts->dry_run) {
        return true;
    }

    /* Check config threshold */
    size_t threshold = 5; /* Default threshold */
    if (config->confirm_destructive) {
        threshold = 1;    /* Always confirm in strict mode */
    }

    /* No confirmation needed for small operations below threshold */
    if (claim_count < threshold) {
        return true;
    }

    size_t files = 0, dirs = 0;
    for (size_t i = 0; i < claim_count; i++) {
        if (claims[i].kind == PATH_KIND_DIRECTORY) dirs++;
        else files++;
    }
    char counts[64];
    format_claim_counts(counts, sizeof(counts), files, dirs);

    /* Prompt user */
    char prompt[512];
    if (opts->delete_files) {
        snprintf(
            prompt, sizeof(prompt), "Remove %s from profile '%s'?\n"
            "(Deployed files will be pruned on 'dotta apply')",
            counts, opts->profile
        );
    } else {
        snprintf(
            prompt, sizeof(prompt), "Remove %s from profile '%s'?\n"
            "(Deployed files will be released from management)",
            counts, opts->profile
        );
    }

    return output_confirm(out, prompt, false);
}

/**
 * Confirm profile deletion
 */
static bool confirm_profile_deletion(
    const char *profile,
    size_t file_count,
    const cmd_remove_options_t *opts,
    const config_t *config,
    output_t *out
) {
    if (!profile || !out) {
        return false;
    }

    /* Skip confirmation if --force */
    if (opts->force) {
        return true;
    }

    output_newline(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL, "This will delete profile '%s' (%zu file%s)",
        profile, file_count, file_count == 1 ? "" : "s"
    );
    if (opts->delete_files) {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be pruned when you run 'dotta apply'."
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "         Deployed files will be released from management."
        );
    }
    output_newline(out, OUTPUT_NORMAL);

    bool confirmed = output_confirm_destructive(
        out, config ? config->confirm_destructive : true, "Continue?", opts->force
    );

    return confirmed;
}

/**
 * Remove files from profile
 *
 * `before` is the view ahead of the commit (the dispatcher's): who owns a path
 * a moment before this command removes it is a fact neither the post-commit view
 * nor the record can state — a path never seen here has no record, and a record
 * can be a higher profile's — so it serves both the conflict analysis and the
 * record update.
 */
static error_t *remove_files_from_profile(
    const dotta_ctx_t *ctx,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    const manifest_t *before = ctx->run.manifest;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL for safe cleanup */
    error_t *err = NULL;
    removal_claim_t *claims = NULL;        /* arena — the resolver's */
    size_t claim_count = 0;
    metadata_t *metadata = NULL;           /* the branch's, from the resolver (owned) */
    hashmap_t *profile_index = NULL;       /* storage_path → the other profiles claiming it (owned) */
    size_t multi_profile_count = 0;
    string_array_t *removed_paths = NULL;
    string_array_t pruned_dirs = { 0 };    /* Directory entries the metadata step pruned (storage paths) */
    buffer_t metadata_json = BUFFER_INIT;
    char *message = NULL;
    manifest_t *after = NULL;
    hashmap_t *anchor_index = NULL;
    bool profile_enabled = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Resolve the arguments to the claims they remove */
    err = resolve_removal_claims(
        ctx, opts->profile, opts->paths, opts->path_count, opts,
        &claims, &claim_count, &metadata
    );
    if (err) {
        goto cleanup;
    }

    /* Analyze multi-profile conflicts (critical safety check) */
    bool has_deployed_from_other = false;
    err = analyze_multi_profile_conflicts(
        ctx,
        claims,
        claim_count,
        opts->profile,
        &profile_index,
        &multi_profile_count,
        &has_deployed_from_other
    );

    if (err) {
        goto cleanup;
    }

    /* Capture profile-enabled status. The record-update phase below promotes
     * the borrowed read handle to a write transaction via state_begin; no reopen
     * needed. */
    profile_enabled = state_has_profile(state, opts->profile);

    /* Display multi-profile warnings BEFORE any operation */
    display_multi_profile_warnings(
        out,
        claims,
        claim_count,
        profile_index,
        multi_profile_count,
        has_deployed_from_other,
        opts->profile
    );

    /* Dry run - just show what would be removed */
    if (opts->dry_run) {
        size_t dry_files = 0, dry_dirs = 0;
        output_print(
            out, OUTPUT_NORMAL, "Would remove from profile '%s':\n",
            opts->profile
        );
        for (size_t i = 0; i < claim_count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  - %s%s\n",
                claims[i].storage_path, path_kind_suffix(claims[i].kind)
            );
            if (claims[i].kind == PATH_KIND_DIRECTORY) dry_dirs++;
            else dry_files++;
        }
        char counts[64];
        format_claim_counts(counts, sizeof(counts), dry_files, dry_dirs);
        output_print(
            out, OUTPUT_NORMAL, "\nTotal: %s would be removed from profile\n",
            counts
        );
        if (opts->delete_files) {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be removed on 'dotta apply')\n"
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL, "(Deployed files would be released from management)\n"
            );
        }

        goto cleanup;  /* err is NULL, will return success */
    }

    /* Confirm operation */
    if (!confirm_removal(claims, claim_count, opts, config, out)) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Done with the profile index — the display was its last reader */
    hashmap_free(profile_index, string_array_free_cb);
    profile_index = NULL;

    /* Selection: the accepted claims, before anything fires. In interactive mode
     * each claim is confirmed here, so the hooks and the plan below see exactly
     * what will happen — a declined claim is out before the pre-hook names the
     * set. */
    if (opts->interactive) {
        size_t kept = 0;
        for (size_t i = 0; i < claim_count; i++) {
            char prompt[PATH_MAX + 16];
            snprintf(
                prompt, sizeof(prompt), "Remove %s%s?",
                claims[i].storage_path, path_kind_suffix(claims[i].kind)
            );
            if (!output_confirm(out, prompt, false)) {
                output_info(out, OUTPUT_VERBOSE, "Skipped: %s", claims[i].storage_path);
                continue;
            }
            claims[kept++] = claims[i];
        }
        claim_count = kept;
    }
    if (claim_count == 0) {
        output_info(out, OUTPUT_NORMAL, "Nothing removed");
        goto cleanup;
    }

    /* Build hook invocation with the claims' filesystem paths (resolved by
     * resolve_removal_claims). Reached only on non-dry-run: the dry-run branch
     * above early-cleanups before this point, so dry_run is always false here
     * in practice — still passed for honesty. */
    char **hook_paths = arena_alloc(ctx->arena, claim_count * sizeof(char *));
    if (!hook_paths) {
        err = ERROR(ERR_MEMORY, "Failed to allocate hook path array");
        goto cleanup;
    }
    for (size_t i = 0; i < claim_count; i++) {
        /* Arena-backed and never written through; the cast bridges the hook
         * contract's char *const *. */
        hook_paths[i] = (char *) claims[i].filesystem_path;
    }
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_paths,
        .file_count = claim_count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* The plan, all in memory: which tree entries leave, and the metadata edit
     * riding the same commit. A FILE claim is a tree entry; a DIRECTORY claim
     * has no tree entry — its whole Git footprint is its metadata item. Every
     * FILE claim is in the branch tree (the resolver's universe is
     * profile_list_files over this branch, and the branch cannot move between
     * resolve and commit — one process, one command), so the primitive's
     * missing-entry error cannot fire. */
    size_t removed_files = 0, removed_dirs = 0;
    size_t removal_count = 0, meta_edits = 0;
    removed_paths = string_array_new(0);
    const char **removals = arena_alloc(ctx->arena, claim_count * sizeof(const char *));
    if (!removed_paths || !removals) {
        err = ERROR(ERR_MEMORY, "Failed to allocate removal plan");
        goto cleanup;
    }

    for (size_t i = 0; i < claim_count; i++) {
        const removal_claim_t *claim = &claims[i];

        if (claim->kind == PATH_KIND_FILE) {
            removals[removal_count++] = claim->storage_path;
            removed_files++;
        } else {
            removed_dirs++;
        }

        if (metadata && metadata_has_item(metadata, claim->storage_path)) {
            err = metadata_remove_item(metadata, claim->storage_path);
            if (err) {
                err = error_wrap(
                    err, "Failed to remove metadata item: %s",
                    claim->storage_path
                );
                goto cleanup;
            }
            meta_edits++;
        }

        err = string_array_push(removed_paths, claim->storage_path);
        if (err) {
            err = error_wrap(err, "Failed to track removed path");
            goto cleanup;
        }
        output_info(out, OUTPUT_VERBOSE, "Removed: %s", claim->storage_path);
    }

    /* Prune redundant directory entries against the post-edit index — the branch
     * tree minus the removed file claims, the tree the impending commit will
     * record (the judge's own contract, metadata.h). Removing a file may leave
     * its parent directory metadata entry with no anchoring descendants. Anchoring
     * is judged against the index — never against metadata items, which omit
     * unelevated symlinks. Only entries that carry no actionable information
     * are dropped (default mode, no ownership, no tracked descendants);
     * custom-attribute entries are preserved as potential empty-dir intent. */
    if (metadata) {
        git_tree *branch_tree = NULL;
        git_index *judge = NULL;
        err = gitops_load_branch_tree(repo, opts->profile, &branch_tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree of profile '%s'", opts->profile
            );
            goto cleanup;
        }
        int git_err = git_index_new(&judge);
        if (git_err == 0) git_err = git_index_read_tree(judge, branch_tree);
        for (size_t i = 0; git_err == 0 && i < removal_count; i++) {
            git_err = git_index_remove(judge, removals[i], 0);
        }
        if (git_err < 0) {
            git_index_free(judge);
            git_tree_free(branch_tree);
            err = error_from_git(git_err);
            goto cleanup;
        }
        err = metadata_prune_directories(metadata, judge, &pruned_dirs);
        git_index_free(judge);
        git_tree_free(branch_tree);
        if (err) {
            err = error_wrap(err, "Failed to prune redundant directories");
            goto cleanup;
        }
        if (pruned_dirs.count > 0) {
            output_info(
                out, OUTPUT_VERBOSE, "Pruned %zu redundant directory entr%s",
                pruned_dirs.count, pruned_dirs.count == 1 ? "y" : "ies"
            );
        }
    }

    /* The metadata blob, only when the collection actually changed — a removal
     * that touched no items and pruned nothing keeps the branch's metadata.json
     * byte-identical, so no rewrite is committed. */
    gitops_tree_update_t meta_update;
    size_t update_count = 0;
    if (meta_edits + pruned_dirs.count > 0) {
        err = metadata_to_json(metadata, &metadata_json);
        if (err) {
            err = error_wrap(err, "Failed to serialize metadata");
            goto cleanup;
        }
        int git_err = git_blob_create_from_buffer(
            &meta_update.blob_oid, repo, metadata_json.data, metadata_json.size
        );
        if (git_err < 0) {
            err = error_from_git(git_err);
            goto cleanup;
        }
        meta_update.path = METADATA_FILE_PATH;
        meta_update.mode = GIT_FILEMODE_BLOB;
        update_count = 1;
    }

    /* One atomic commit: the file claims leave the tree, metadata.json follows
     * in the same tree write. HEAD-safe and all-or-nothing — any failure up to
     * here leaves the repository byte-identical. */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_REMOVE,
        .profile       = opts->profile,
        .files         = removed_paths->items,
        .file_count    = removed_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };
    message = build_commit_message(config, &msg_ctx);
    if (!message) {
        err = ERROR(ERR_MEMORY, "Failed to build commit message");
        goto cleanup;
    }
    err = gitops_commit_tree_updates_safe(
        repo, opts->profile,
        update_count > 0 ? &meta_update : NULL, update_count,
        removals, removal_count, message, NULL
    );
    if (err) {
        err = error_wrap(err, "Failed to create commit");
        goto cleanup;
    }

    /*
     * Architectural note: We do NOT delete files from the filesystem here. This
     * maintains separation of concerns:
     * - `remove` modifies the Git repository (profile branches)
     * - `apply` synchronizes the filesystem (prunes orphaned files by default)
     *
     * This ensures `apply` has global context from all enabled profiles to
     * correctly determine if a file should be removed (avoiding premature deletion
     * of files still needed by higher-priority profiles).
     */

    /* Write the record if the profile is enabled.
     *
     * profile_enabled==true implies state was successfully loaded with a live
     * DB (state_has_profile returns false for NULL/empty state), so state_begin
     * is safe without an additional guard. The handle is reused — no second
     * state_open that would re-prepare statements and re-query enabled_profiles
     * from scratch.
     *
     * Which paths this commit let go is read off the two views: `before` says
     * which were this profile's a moment ago; `after` (the enabled set at its
     * post-commit HEADs) says which a lower profile provides now — a fallback,
     * whose record stays and reads [reassigned] until apply deploys it. A path
     * that was ours and that nothing provides now gets the fate the user chose,
     * if dotta has a record of it at all (never seen here: nothing to release
     * or prune): --delete-files orders the deployed copy pruned at the next apply;
     * the default retires the record — released from management now. The directory
     * entries the metadata step pruned as redundant left the view by the same
     * commit and take the same route: an owned directory is pruned under cleanup's
     * emptiness rule, or released.
     *
     * Non-fatal throughout: Git succeeded and stands. A record this block fails
     * to write is an orphan the next apply reads, asks Git about, finds let go,
     * and releases — the default outcome, minus the prune order under
     * --delete-files. */
    size_t manifest_removed_count = 0, manifest_fallback_count = 0;

    if (profile_enabled) {
        /* Open transaction for the record update */
        error_t *manifest_err = state_begin(state);
        if (manifest_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to open transaction for record update: %s",
                error_message(manifest_err)
            );
            error_free(manifest_err);
        } else {
            anchor_t *anchors = NULL;
            size_t anchor_count = 0;

            manifest_err = manifest_build(repo, state, ctx->arena, &after);
            if (!manifest_err) {
                manifest_err = state_get_all_anchors(
                    state, ctx->arena, &anchors, &anchor_count
                );
            }
            if (!manifest_err) {
                anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
                if (!anchor_index) {
                    manifest_err = ERROR(ERR_MEMORY, "Failed to create anchors index");
                }
            }
            for (size_t i = 0; !manifest_err && i < anchor_count; i++) {
                manifest_err = hashmap_set(
                    anchor_index, anchors[i].filesystem_path, &anchors[i]
                );
            }

            const string_array_t *let_go[] = { removed_paths, &pruned_dirs };
            for (size_t b = 0; !manifest_err && b < sizeof(let_go) / sizeof(let_go[0]); b++) {
                for (size_t i = 0; !manifest_err && i < let_go[b]->count; i++) {
                    const char *storage_path = let_go[b]->items[i];

                    /* The path as this profile deploys it. UNBOUND (custom/ under
                     * a profile with no target here) names nothing on this machine:
                     * nothing to release. */
                    mount_resolve_outcome_t outcome;
                    const char *fs_path = NULL;
                    manifest_err = mount_resolve(
                        mounts, opts->profile, storage_path, ctx->arena,
                        &outcome, &fs_path
                    );
                    if (manifest_err || outcome == MOUNT_RESOLVE_UNBOUND) continue;

                    const manifest_row_t *was = manifest_lookup(before, fs_path);
                    if (!was || strcmp(was->profile, opts->profile) != 0) continue;

                    if (manifest_lookup(after, fs_path)) {
                        manifest_fallback_count++;
                        continue;
                    }

                    if (!hashmap_has(anchor_index, fs_path)) continue;

                    manifest_err = opts->delete_files
                        ? state_order_prune(state, fs_path)
                        : state_retire_anchor(state, fs_path);
                    if (!manifest_err) manifest_removed_count++;
                }
            }

            if (manifest_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Record update failed: %s",
                    error_message(manifest_err)
                );
                error_free(manifest_err);
                state_rollback(state);
            } else {
                /* Commit transaction */
                error_t *commit_err = state_commit(state);
                if (commit_err) {
                    output_warning(
                        out, OUTPUT_NORMAL, "Failed to save record updates: %s",
                        error_message(commit_err)
                    );
                    error_free(commit_err);
                    state_rollback(state);
                } else if (manifest_removed_count > 0 || manifest_fallback_count > 0) {
                    if (opts->delete_files) {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "Manifest: %zu staged for removal, %zu fallback%s",
                            manifest_removed_count, manifest_fallback_count,
                            manifest_fallback_count == 1 ? "" : "s"
                        );
                    } else {
                        output_info(
                            out, OUTPUT_VERBOSE,
                            "Manifest: %zu released, %zu fallback%s",
                            manifest_removed_count, manifest_fallback_count,
                            manifest_fallback_count == 1 ? "" : "s"
                        );
                    }
                }
            }
        }
    } else {
        output_info(out, OUTPUT_VERBOSE, "Profile not enabled, Git updated only");
    }

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success */
    if (!opts->quiet) {
        char counts[64];
        format_claim_counts(counts, sizeof(counts), removed_files, removed_dirs);
        output_success(
            out, OUTPUT_NORMAL, "Removed %s from profile '%s'",
            counts, opts->profile
        );
        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to remove files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation. state is borrowed from
     * the dispatcher — do not free it. state_rollback is a no-op if no transaction
     * is active (state.c:2898-2906), so it safely closes any partially-begun
     * record-update transaction on error paths. */
    state_rollback(state);
    if (anchor_index) hashmap_free(anchor_index, NULL);
    manifest_free(after);
    free(message);
    buffer_free(&metadata_json);
    string_array_deinit(&pruned_dirs);
    if (removed_paths) string_array_free(removed_paths);
    if (profile_index) hashmap_free(profile_index, string_array_free_cb);
    if (metadata) metadata_free(metadata);

    return err;
}

/**
 * Delete entire profile branch
 */
static error_t *delete_profile_branch(
    const dotta_ctx_t *ctx,
    const cmd_remove_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL */
    error_t *err = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    string_array_t *all_profiles = NULL;
    string_array_t *files = NULL;
    string_array_t *hook_fs_paths = NULL;
    bool performed = false;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    } else if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Check if profile exists */
    if (!profile_exists(repo, opts->profile)) {
        if (!opts->force) {
            err = ERROR(
                ERR_NOT_FOUND, "Profile '%s' does not exist\n"
                "Hint: Use 'dotta list' to see available profiles",
                opts->profile
            );
            goto cleanup;
        }
        /* With --force, just warn and exit */
        output_warning(
            out, OUTPUT_VERBOSE, "Profile '%s' does not exist",
            opts->profile
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* SAFETY: Prevent deletion of last remaining profile */
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        err = error_wrap(err, "Failed to list profiles");
        goto cleanup;
    }

    if (all_profiles->count <= 1) {
        err = ERROR(
            ERR_INVALID_ARG, "Cannot delete last remaining profile '%s'\n"
            "Hint: A repository must have at least one profile", opts->profile
        );
        goto cleanup;
    }
    string_array_free(all_profiles);
    all_profiles = NULL;

    /* Load profile to count files */
    err = profile_list_files(repo, opts->profile, &files);
    if (err) {
        err = error_wrap(err, "Failed to list files in profile '%s'", opts->profile);
        goto cleanup;
    }

    size_t file_count = files->count;

    /* Dry run */
    if (opts->dry_run) {
        output_print(
            out, OUTPUT_NORMAL, "Would delete profile '%s' (%zu file%s)\n",
            opts->profile, file_count, file_count == 1 ? "" : "s"
        );
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Check for unpushed changes and detect remote Keep remote_name for later
     * use when pushing deletion
     */
    bool has_unpushed = false;
    bool is_local_only = false;

    /* Resolve remote name + URL up-front: the URL feeds the credential helper
     * for the deletion-push xfer further down (see line where
     * transfer_context_create is called). One resolve, two consumers. */
    err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, &remote_url
    );
    if (!err && remote_name) {
        /* Remote exists - check upstream state */
        upstream_info_t upstream_info;
        err = upstream_analyze_profile(
            repo, remote_name, opts->profile, &upstream_info
        );
        if (!err) {
            /* Determine if profile has actual remote tracking */
            if (upstream_info.state == UPSTREAM_NO_REMOTE) {
                /* Profile exists locally but was never pushed to remote */
                is_local_only = true;
            } else if (upstream_info.state == UPSTREAM_LOCAL_AHEAD ||
                upstream_info.state == UPSTREAM_DIVERGED){
                /* Profile has remote tracking and has unpushed changes */
                has_unpushed = true;
            }
        } else {
            /* Non-fatal: can't determine upstream state */
            error_free(err);
            err = NULL;
        }
    } else if (err) {
        /* No remote configured - treat as local-only */
        is_local_only = true;
        error_free(err);
        err = NULL;
    }

    /* Warn about unpushed changes (only if profile has remote tracking) */
    if (has_unpushed && !opts->force) {
        output_newline(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "Profile '%s' has unpushed changes!", opts->profile);
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta sync' first to avoid data loss");
        output_newline(out, OUTPUT_NORMAL);
    } else if (is_local_only) {
        /* Inform about local-only status in verbose mode (not a warning) */
        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' is local-only (not pushed to remote)",
            opts->profile
        );
    }

    /* Informational queries and enabled check on the borrowed state. Under
     * spec-driven READ the handle is always non-NULL here (CHECK_NULL at entry),
     * and state_load for a missing DB still returns a usable handle (DB-less,
     * reads degrade to empty) — no defensive fallback needed. */
    bool profile_was_enabled = state_has_profile(state, opts->profile);
    size_t deployed_count = 0;

    /* Count the records dotta owns under the profile for informational display.
     * Failure is non-fatal: the count is purely cosmetic, so swallow any error
     * and display 0. Read outside the transaction the record update below takes;
     * that update reads the record again, inside it. */
    {
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        error_t *count_err = state_get_all_anchors(
            state, ctx->arena, &anchors, &anchor_count
        );
        if (count_err) {
            error_free(count_err);
        } else {
            for (size_t i = 0; i < anchor_count; i++) {
                if (anchors[i].deployed_at > 0 &&
                    strcmp(anchors[i].profile, opts->profile) == 0) {
                    deployed_count++;
                }
            }
        }
    }

    /* Inform about deployed paths (informational, not a warning) */
    if (deployed_count > 0) {
        output_newline(out, OUTPUT_VERBOSE);

        output_info(
            out, OUTPUT_VERBOSE, "Note: Profile '%s' has %zu deployed entr%s",
            opts->profile, deployed_count, deployed_count == 1 ? "y" : "ies"
        );

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These will be pruned when you run 'dotta apply'."
            );
        } else {
            output_info(
                out, OUTPUT_VERBOSE,
                "      These files will be released from management."
            );
        }
        output_newline(out, OUTPUT_VERBOSE);
    }

    /* Confirm deletion */
    if (!confirm_profile_deletion(
        opts->profile, file_count, opts, config, out
        )) {
        output_print(out, OUTPUT_NORMAL, "Cancelled\n");
        goto cleanup;  /* err is NULL, will return success */
    }

    /* Convert storage paths to filesystem paths for hook consistency. The file
     * removal path passes filesystem paths to hooks; do the same here.
     *
     * Borrows the run's mount table. HOME and ROOT are always present, so home/
     * and root/ paths resolve unconditionally. CUSTOM paths resolve only when
     * the profile is enabled with a binding; otherwise MOUNT_RESOLVE_UNBOUND
     * fires and the loop substitutes the storage path as the user-visible
     * fallback. */
    if (files) {
        hook_fs_paths = string_array_new(0);
        if (hook_fs_paths) {
            for (size_t i = 0; i < files->count; i++) {
                mount_resolve_outcome_t outcome;
                const char *fs_path = NULL;
                error_t *conv_err = mount_resolve(
                    mounts, opts->profile, files->items[i], ctx->arena,
                    &outcome, &fs_path
                );
                if (conv_err) {
                    error_free(conv_err);
                    /* Fall back to storage path (allocation failure or malformed
                     * input — non-fatal here). */
                    string_array_push(hook_fs_paths, files->items[i]);
                } else if (outcome == MOUNT_RESOLVE_BOUND) {
                    string_array_push(hook_fs_paths, fs_path);
                } else {
                    /* UNBOUND: custom/ profile without binding on this host.
                     * Fall back to storage path so the hook sees a meaningful
                     * name. */
                    string_array_push(hook_fs_paths, files->items[i]);
                }
            }
        }
    }

    /* Build hook invocation. Prefer filesystem paths (consistent with the
     * file-removal subcommand); fall back to storage paths if synthesis was
     * skipped. Both arrays live until cleanup. */
    const string_array_t *hook_files = hook_fs_paths ? hook_fs_paths : files;
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_REMOVE,
        .profile    = opts->profile,
        .files      = hook_files ? hook_files->items : NULL,
        .file_count = hook_files ? hook_files->count : 0,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-remove hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* No filesystem deletion here either — see the Architectural note in
     * remove_files_from_profile: apply owns deferred filesystem cleanup. */

    /* Delete local branch */
    err = gitops_delete_branch(repo, opts->profile);
    if (err) {
        err = error_wrap(err, "Failed to delete profile '%s'", opts->profile);
        goto cleanup;
    }

    performed = true;

    /* Post-deletion: the enabled set and the record, in one transaction.
     *
     * The order of the branch deletion and this block does not matter: the view
     * is computed, and prune_ordered is the one fact the workspace reads for
     * these records — written once, here, after the branch is gone. The profile
     * leaves the enabled set (if it was in it), and every record under it is
     * decided against the view that remains: a path the view still has is a
     * fallback — its record is kept and reads [reassigned] P → Q until apply
     * deploys Q's; a path the view lacks gets the fate the user chose —
     * --delete-files orders the deployed copy pruned at the next apply, the default
     * retires the record (released from management now). One rule whether P was
     * enabled or not, and whether P's tree still claimed the path or had let it
     * go: the user is deleting P and P's files.
     *
     * Non-fatal: the branch is gone and stands. A record this block fails to
     * write is an orphan the next apply reads, asks Git about, finds the branch
     * gone, and releases. */
    error_t *delete_err = state_begin(state);
    if (!delete_err) {
        manifest_t *after = NULL;
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        size_t removed = 0, fallbacks = 0;

        if (profile_was_enabled) {
            delete_err = state_disable_profile(state, opts->profile);
        }

        /* The view that remains — the builder over the post-disable rows. */
        if (!delete_err) {
            delete_err = manifest_build(repo, state, ctx->arena, &after);
        }
        if (!delete_err) {
            delete_err = state_get_all_anchors(
                state, ctx->arena, &anchors, &anchor_count
            );
        }

        for (size_t i = 0; !delete_err && i < anchor_count; i++) {
            const anchor_t *anchor = &anchors[i];
            if (strcmp(anchor->profile, opts->profile) != 0) continue;

            if (manifest_lookup(after, anchor->filesystem_path)) {
                fallbacks++;
                continue;
            }

            delete_err = opts->delete_files
                ? state_order_prune(state, anchor->filesystem_path)
                : state_retire_anchor(state, anchor->filesystem_path);
            if (!delete_err) removed++;
        }

        /* Commit transaction */
        if (!delete_err) delete_err = state_commit(state);

        if (delete_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update state after branch deletion: %s",
                error_message(delete_err)
            );
            error_free(delete_err);
            state_rollback(state);
        } else if (removed > 0 || fallbacks > 0) {
            if (opts->delete_files) {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu entr%s staged for removal, %zu fallback%s",
                    removed, removed == 1 ? "y" : "ies",
                    fallbacks, fallbacks == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "%zu entr%s released from management, %zu fallback%s",
                    removed, removed == 1 ? "y" : "ies",
                    fallbacks, fallbacks == 1 ? "" : "s"
                );
            }
        }

        manifest_free(after);
    } else {
        /* Non-fatal: the next workspace load observes the branch gone and releases
         * these records conservatively */
        output_warning(
            out, OUTPUT_NORMAL, "Failed to begin transaction for post-deletion update: %s",
            error_message(delete_err)
        );
        error_free(delete_err);
    }

    /* Push deletion to remote if remote exists This is critical for sync to work -
     * other repos need to know the branch was deleted
     */
    if (remote_name && !is_local_only) {
        output_info(
            out, OUTPUT_NORMAL, "Pushing profile deletion to remote '%s'...",
            remote_name
        );

        /* remote_url was resolved alongside remote_name above. NULL is legal —
         * unauthenticated paths still work, helper approve/reject become no-ops. */
        transfer_context_t *del_xfer = NULL;
        transfer_options_t del_opts = { .output = out, .url = remote_url };
        error_t *del_xfer_err = transfer_context_create(&del_opts, &del_xfer);

        if (del_xfer_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to create transfer context: %s",
                error_message(del_xfer_err)
            );
            error_free(del_xfer_err);
            err = NULL;
        } else {
            err = gitops_delete_remote_branch(
                repo, remote_name, opts->profile, del_xfer
            );
            transfer_context_free(del_xfer);
        }
        if (err) {
            /* Non-fatal: warn but don't fail the whole operation The local branch
             * is already deleted, so this is just about syncing
             */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to push deletion to remote: %s",
                error_message(err)
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         The profile was deleted locally, but sync could fail."
            );
            output_info(
                out, OUTPUT_NORMAL,
                "         You can manually push the deletion with: git push %s :%s",
                remote_name, opts->profile
            );
            error_free(err);
            err = NULL;
        } else {
            output_info(out, OUTPUT_NORMAL, "Profile deletion pushed to remote");
        }
    }

    /*
     * Architectural note: the profile's records were prune-ordered (with
     * --delete-files) or retired in the post-deletion block above. The prune
     * itself happens on `apply`.
     */

    /* Execute post-remove hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Success message (only on actual deletion, not dry-run/cancel/error) */
    if (performed && !opts->quiet) {
        output_success(out, OUTPUT_NORMAL, "Profile '%s' deleted", opts->profile);

        if (opts->delete_files) {
            output_info(
                out, OUTPUT_NORMAL,
                "Run 'dotta apply' to remove deployed files from filesystem"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "Files released from management (no apply needed)"
            );
        }
        output_newline(out, OUTPUT_NORMAL);
    }

cleanup:
    /* Free all resources in reverse order of allocation. state is borrowed from
     * the dispatcher — do not free it. state_rollback is a no-op if no transaction
     * is active; this safely closes any partially-begun record-update or
     * post-deletion transaction on an error path. */
    state_rollback(state);

    if (hook_fs_paths) string_array_free(hook_fs_paths);
    if (files) string_array_free(files);
    if (all_profiles) string_array_free(all_profiles);

    return err;
}

/**
 * Remove command implementation
 */
error_t *cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    /* Validate options */
    error_t *err = validate_options(opts);
    if (err) {
        return err;
    }

    /* Branch: Delete profile or remove files */
    if (opts->delete_profile) {
        return delete_profile_branch(ctx, opts);
    }

    return remove_files_from_profile(ctx, opts);
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `paths[]`.
 *
 * Legacy-compatible rules:
 *   1. -p/--profile was given: every positional is a path.
 *   2. -p not given: first positional is the profile, rest are paths.
 *   3. --delete-profile: paths must be empty (mutually exclusive).
 *   4. Without --delete-profile: at least one path is required.
 */
static error_t *remove_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_remove_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->paths = o->positional_args;
        o->path_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->paths = o->positional_args + 1;
        o->path_count = o->positional_count - 1;
    }

    if (o->delete_profile && o->path_count > 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "cannot specify paths when using --delete-profile"
        );
    }
    if (!o->delete_profile && o->path_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "at least one path is required (or use --delete-profile)"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, read off the buckets remove_post_parse routes:
 * a local profile in the profile slot — the first positional, unless -p took it
 * — then the files of that profile's branch, shadowed and disabled ones included;
 * nothing after --delete-profile, which takes no path.
 */
static args_want_t remove_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_remove_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_remove_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m: free text */
    }

    if (o->profile == NULL && o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (o->delete_profile) {
        return ARGS_WANT_NONE;
    }
    completion_refspecs(
        ctx, out, o->profile ? o->profile : o->positional_args[0]
    );
    return ARGS_WANT_NONE;
}

static error_t *remove_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remove(ctx, (const cmd_remove_options_t *) opts_v);
}

static const args_opt_t remove_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_remove_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "m message",         "<msg>",
        cmd_remove_options_t,message,
        "Commit message"
    ),
    ARGS_FLAG(
        "delete-profile",
        cmd_remove_options_t,delete_profile,
        "Delete the entire profile branch"
    ),
    ARGS_FLAG(
        "delete-files",
        cmd_remove_options_t,delete_files,
        "Stage deployed items for removal on next apply"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_remove_options_t,dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG(
        "f force",
        cmd_remove_options_t,force,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "i interactive",
        cmd_remove_options_t,interactive,
        "Prompt for each file"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_remove_options_t,verbose,
        "Verbose output"
    ),
    ARGS_FLAG(
        "q quiet",
        cmd_remove_options_t,quiet,
        "Minimal output"
    ),
    /* <profile> [<path>...]. -p promotes positionals to all-paths. */
    ARGS_POSITIONAL_RAW(
        cmd_remove_options_t,positional_args, positional_count,
        0,                   0
    ),
    ARGS_END,
};

const args_command_t spec_remove = {
    .name         = "remove",
    .summary      = "Remove paths from a profile or delete profile",
    .usage        =
        "%s remove [options] <profile> <path>...\n"
        "   or: %s remove [options] <profile> --delete-profile\n"
        "   or: %s remove [options] --profile <name> <path>...",
    .description  =
        "Untrack paths — files and tracked directories — from a profile,\n"
        "optionally scheduling removal of the deployed copies, or delete\n"
        "the profile branch outright.\n",
    .notes        =
        "Operation Modes:\n"
        "  (default)           Remove paths from the profile branch. Deployed\n"
        "                      items are released from management and stay\n"
        "                      on the filesystem untouched.\n"
        "  --delete-files      Same as default, plus stage the deployed\n"
        "                      items for removal on the next '%s apply'.\n"
        "  --delete-profile    Delete the entire profile branch. No paths\n"
        "                      may be given; with --delete-files the deployed\n"
        "                      items are staged for removal as well.\n",
    .examples     =
        "  %s remove global ~/.bashrc                  # Untrack, keep on disk\n"
        "  %s remove darwin ~/.config/nvim -n          # Preview removal\n"
        "  %s remove darwin ~/.config/nvim --delete-files  # Remove on apply\n"
        "  %s remove staging --delete-profile          # Delete whole profile\n"
        "  %s remove staging --delete-profile --delete-files  # ...and its copies\n",
    .epilogue     =
        "See also:\n"
        "  %s profile disable <name>  # Stop deploying without deleting\n"
        "  %s apply                   # Carry out staged file removals\n",
    .opts_size    = sizeof(cmd_remove_options_t),
    .opts         = remove_opts,
    .post_parse   = remove_post_parse,
    .complete     = remove_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = true,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .manifest = true,
    },
    .dispatch     = remove_dispatch,
};
