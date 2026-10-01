/**
 * profile.c - Profile lifecycle management
 *
 * Explicit profile management commands for controlling which profiles are enabled
 * vs merely available on this machine.
 */

#include "cmds/profile.h"

#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/transfer.h"
#include "sys/upstream.h"

/**
 * Print manifest enable statistics
 *
 * Reports gain-side attribution for one enabled profile from the diff of the
 * view before the enable against the view after it: claimed (rows the profile
 * won precedence for, both kinds), of which added + updated are staged — new to
 * the view, or moved past what it held — and the rest were already at the view's
 * values. The diff reads no disk; what is deployed and what is not is status's
 * to say.
 */
static void profile_print_enable_stats(
    output_t *out,
    const char *profile,
    const manifest_diff_stats_t *stats
) {
    if (stats->claimed == 0) return;

    size_t staged = stats->added + stats->updated;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(
            out, OUTPUT_VERBOSE, "  Profile: %s\n",
            profile
        );
        output_print(
            out, OUTPUT_VERBOSE, "  Total entries: %zu\n",
            stats->claimed
        );

        if (staged > 0) {
            output_print(
                out, OUTPUT_VERBOSE,
                "    - {yellow}%zu{reset} staged for deployment\n",
                staged
            );
        }
    } else {
        /* Compact summary */
        if (staged > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu entr%s for deployment\n",
                staged, staged == 1 ? "y" : "ies"
            );
        }
    }
}

/**
 * Print manifest disable statistics
 *
 * Reports loss-side attribution for one disabled profile from the diff of the
 * view before the disable against the view after it: reassigned (picked up by a
 * fallback profile) + orphans.owned (left the view with a record dotta owns —
 * apply prunes the deployed copy) + orphans.observed (left the view with a record
 * dotta never owned — apply releases it, the copy stays). A departure with no
 * record is not counted: nothing was ever seen at the path, so nothing pends
 * for apply.
 */
static void profile_print_disable_stats(
    output_t *out,
    const char *profile,
    const manifest_diff_stats_t *stats
) {
    if (!stats) return;

    size_t total = stats->reassigned + stats->orphans.owned + stats->orphans.observed;
    if (total == 0) return;

    if (output_is_verbose(out)) {
        /* Detailed breakdown */
        output_section(out, OUTPUT_VERBOSE, "Manifest Analysis");
        output_print(out, OUTPUT_VERBOSE, "  Profile: %s\n", profile);

        output_print(
            out, OUTPUT_VERBOSE,
            "  Total entries affected: %zu\n", total
        );

        if (stats->reassigned > 0) {
            output_print(
                out, OUTPUT_VERBOSE,
                "    - {green}%zu{reset} path%s with fallback (will reassign)\n",
                stats->reassigned,
                stats->reassigned == 1 ? "" : "s"
            );
        }

        if (stats->orphans.owned > 0) {
            output_print(
                out, OUTPUT_VERBOSE,
                "    - {red}%zu{reset} path%s without fallback (will be pruned)\n",
                stats->orphans.owned,
                stats->orphans.owned == 1 ? "" : "s"
            );
        }

        if (stats->orphans.observed > 0) {
            output_print(
                out, OUTPUT_VERBOSE,
                "    - {cyan}%zu{reset} path%s never deployed here (left alone)\n",
                stats->orphans.observed,
                stats->orphans.observed == 1 ? "" : "s"
            );
        }
    } else {
        /* Compact summary */
        if (stats->orphans.owned > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Staged %zu path%s for removal\n",
                stats->orphans.owned, stats->orphans.owned == 1 ? "" : "s"
            );
        }

        if (stats->reassigned > 0) {
            output_print(
                out, OUTPUT_NORMAL, "  Reassigned %zu path%s to lower precedence\n",
                stats->reassigned,
                stats->reassigned == 1 ? "" : "s"
            );
        }
    }
}

/**
 * Profile list subcommand
 *
 * Shows enabled vs available profiles with clear visual distinction.
 */
static error_t profile_list(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    /* Resource tracking for cleanup. remote_name/remote_url are arena-borrowed
     * when the --remote branch resolves them. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    error_t err = NULL;

    /* The enabled rows, where the handle holds them: a listing moves none of
     * them (core/state.h state_profiles) */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* Every profile here */
    string_array_t all_branches;
    err = gitops_list_branches(repo, ctx->arena, &all_branches);
    if (err) {
        err = error_wrap(err, "Failed to list branches");
        goto cleanup;
    }

    /* Separate into enabled and available */
    string_array_t available;
    string_array_init(&available, ctx->arena);
    for (size_t i = 0; i < all_branches.count; i++) {
        const char *profile = all_branches.entries[i];
        if (state_enabled(state, profile)) continue;

        string_array_push(&available, profile);
    }

    /* Print enabled profiles: the name, what the branch holds, and the binding
     * beside the name when the row has one — the thing is never printed without
     * the where. */
    if (enabled_profiles.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Enabled profiles (in layering order)");
        for (size_t i = 0; i < enabled_profiles.count; i++) {
            const state_profile_entry_t *entry = &enabled_profiles.entries[i];
            const char *profile = entry->name;
            profile_stats_t stats = { 0 };
            error_t row_err = profile_get_stats(repo, profile, &stats);

            /* Name what the branch holds where it reads, otherwise say so: the
             * row's error is dropped, one per unreadable branch */
            if (row_err) {
                output_print(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (counts unavailable)",
                    i + 1, profile
                );
            } else {
                char counts[64];
                output_format_counts(
                    stats.file_count, stats.directory_count, counts, sizeof(counts)
                );
                output_print(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (%s)",
                    i + 1, profile, counts
                );
            }

            if (entry->target) {
                char shown[PATH_MAX];
                output_format_path(entry->target, identity()->home, shown, sizeof(shown));
                output_print(out, OUTPUT_NORMAL, " {dim}→ %s{reset}", shown);
            }
            output_endline(out, OUTPUT_NORMAL);
        }
    } else {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles");
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>'");
    }

    /* Print available (disabled) profiles, marking the ones that need a target:
     * such a profile is enabled only with one, so this is the mark on exactly
     * the profile clone and --all left here, and the answer is the view's over
     * the branch alone (core/profiles.h profile_needs_target). Two reads of one
     * branch, one failure arm: both open the same tree first, and a row that
     * would not count says so rather than marking nothing in silence. */
    if (available.count > 0 && opts->show_available) {
        output_section(out, OUTPUT_NORMAL, "Available (disabled)");
        for (size_t i = 0; i < available.count; i++) {
            const char *profile = available.entries[i];
            profile_stats_t stats = { 0 };
            bool needs_target = false;
            error_t row_err = profile_get_stats(repo, profile, &stats);
            if (!row_err) row_err = profile_needs_target(repo, profile, &needs_target);

            /* Name what the branch holds where it reads, otherwise say so: the
             * row's error is dropped, one per unreadable branch */
            if (row_err) {
                output_print(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (counts unavailable)",
                    profile
                );
            } else {
                char counts[64];
                output_format_counts(
                    stats.file_count, stats.directory_count, counts, sizeof(counts)
                );
                output_print(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (%s)", profile, counts
                );
                if (needs_target) {
                    output_print(out, OUTPUT_NORMAL, " {dim}(needs a target){reset}");
                }
            }
            output_endline(out, OUTPUT_NORMAL);
        }
    }

    /* Show remote profiles if requested */
    if (opts->show_remote) {
        error_t remote_err = gitops_resolve_default_remote(
            repo, ctx->arena, &remote_name, &remote_url
        );
        if (remote_err) {
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_message(remote_err)
            );
        } else {
            /* Create transfer context for credentials */
            transfer_options_t xfer_opts = {
                .output = out,
                .url    = remote_url,
            };
            xfer = transfer_context_create(&xfer_opts);

            /*
             * Query remote server for available branches (network operation)
             * This contacts the remote server to get the current list of profiles,
             * ensuring we see newly added profiles that haven't been fetched yet.
             */
            string_array_t remote_branches;
            remote_err = gitops_list_remote_branches(
                repo, remote_name, xfer, ctx->arena, &remote_branches
            );
            if (remote_err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Could not query remote: %s",
                    error_message(remote_err)
                );
            } else if (remote_branches.count > 0) {
                /* Filter out branches that already exist locally */
                string_array_t remote_only;
                string_array_init_cap(&remote_only, ctx->arena, remote_branches.count);
                for (size_t ri = 0; ri < remote_branches.count; ri++) {
                    if (!string_array_contains(&all_branches, remote_branches.entries[ri])) {
                        string_array_push(&remote_only, remote_branches.entries[ri]);
                    }
                }

                if (remote_only.count > 0) {
                    output_section(out, OUTPUT_NORMAL, "Remote (not fetched)");
                    for (size_t i = 0; i < remote_only.count; i++) {
                        output_print(
                            out, OUTPUT_NORMAL, "  • %s\n", remote_only.entries[i]
                        );
                    }
                }
            }
        }
    }

cleanup:
    /* Cleanup all resources. remote_name/remote_url are arena-borrowed. */
    transfer_context_free(xfer);

    return err;
}

/**
 * Profile fetch subcommand
 *
 * Downloads profiles without enabling them.
 */
static error_t profile_fetch(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* Resource tracking for cleanup. remote_name/remote_url are arena-borrowed. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    error_t err = NULL;

    /* Counters for summary (not cleaned up) */
    size_t fetched_count = 0;
    size_t failed_count = 0;

    /* Detect remote (name + URL — URL feeds the credential helper). */
    err = gitops_resolve_default_remote(repo, ctx->arena, &remote_name, &remote_url);
    if (err) {
        err = error_wrap(err, "No remote configured");
        goto cleanup;
    }

    /* Create transfer context for progress reporting and credentials */
    transfer_options_t xfer_opts = {
        .output             = out,
        .url                = remote_url,
        .ephemeral_progress = true,
    };
    xfer = transfer_context_create(&xfer_opts);

    output_section(out, OUTPUT_NORMAL, "Fetching profiles");

    if (opts->fetch_all) {
        /* Query remote server for all available branches */
        string_array_t remote_branches;
        err = gitops_list_remote_branches(
            repo, remote_name, xfer, ctx->arena, &remote_branches
        );
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        for (size_t i = 0; i < remote_branches.count; i++) {
            const char *branch_name = remote_branches.entries[i];

            output_info(out, OUTPUT_VERBOSE, "  Fetching %s...", branch_name);

            /* A branch that fails is named and counted, its error dropped — at
             * most one per branch */
            error_t fetch_err = gitops_fetch_branch(repo, remote_name, branch_name, xfer);
            if (fetch_err) {
                output_print(
                    out, OUTPUT_NORMAL, "  {red}✗{reset} Failed to fetch %s: %s\n",
                    branch_name, error_message(fetch_err)
                );
                failed_count++;
                continue;
            }

            /* The local branch: created at the remote's commit, or already
             * here and left where it stands (the fetch moved the remote ref;
             * sync moves the branch) */
            fetch_err = upstream_ensure_tracking_branch(
                repo, remote_name, branch_name
            );
            if (fetch_err) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  {red}✗{reset} Failed to create local branch %s: %s\n",
                    branch_name, error_message(fetch_err)
                );
                failed_count++;
            } else {
                fetched_count++;
                output_print(
                    out, OUTPUT_VERBOSE, "  {green}✓{reset} Fetched %s\n",
                    branch_name
                );
            }
        }
    } else {
        /* Fetch specific profiles */
        if (opts->profile_count == 0) {
            err = error_hint(
                ERROR(ERR_INVALID_ARG, "No profiles specified"),
                "Use 'dotta profile fetch <name>' or '--all'"
            );
            goto cleanup;
        }

        /* Pre-flight validation: query remote for available branches */
        string_array_t available_remote;
        err = gitops_list_remote_branches(
            repo, remote_name, xfer, ctx->arena, &available_remote
        );
        if (err) {
            err = error_wrap(err, "Failed to query remote branches");
            goto cleanup;
        }

        /* Every name the remote does not hold, refused together before anything
         * is fetched: a fetch of named branches is whole or nothing, as git's
         * is. The names the remote does hold are in hand, so the way out lists
         * them. */
        string_array_t missing;
        string_array_init(&missing, ctx->arena);
        for (size_t i = 0; i < opts->profile_count; i++) {
            if (!string_array_contains(&available_remote, opts->profiles[i])) {
                string_array_push(&missing, opts->profiles[i]);
            }
        }
        if (missing.count > 0) {
            err = ERROR(
                ERR_NOT_FOUND, "%s '%s' %s not on remote '%s'",
                missing.count == 1 ? "Profile" : "Profiles",
                string_array_join(ctx->arena, &missing, "', '"),
                missing.count == 1 ? "is" : "are", remote_name
            );
            err = error_hint(
                err, "Remote '%s' holds %s", remote_name,
                available_remote.count > 0
                    ? string_array_join(ctx->arena, &available_remote, ", ")
                    : "no profiles"
            );
            goto cleanup;
        }

        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile = opts->profiles[i];

            /* A profile that fails is named and counted, its error dropped — at
             * most one per profile */
            error_t fetch_err = gitops_fetch_branch(repo, remote_name, profile, xfer);
            if (fetch_err) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  {red}✗{reset} Failed to fetch %s: %s\n",
                    profile, error_message(fetch_err)
                );
                failed_count++;
                continue;
            }

            /* The local branch: created at the remote's commit, or already
             * here and left where it stands (the fetch moved the remote ref;
             * sync moves the branch) */
            fetch_err = upstream_ensure_tracking_branch(
                repo, remote_name, profile
            );
            if (fetch_err) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  {red}✗{reset} Failed to create local branch %s: %s\n",
                    profile, error_message(fetch_err)
                );
                failed_count++;
            } else {
                fetched_count++;
                output_print(
                    out, OUTPUT_VERBOSE,
                    "  {green}✓{reset} Fetched %s\n",
                    profile
                );
            }
        }
    }

cleanup:
    /* Session-level wire stats (silent on failed sessions or no data). Emit before
     * freeing xfer so stats are still live. */
    transfer_summarize(xfer, out, OUTPUT_NORMAL);

    /* Cleanup all resources */
    transfer_context_free(xfer);

    /* If there's an error, return it now */
    if (err) return err;

    /* Summary (only shown on success) */
    output_gap(out, OUTPUT_NORMAL);
    if (fetched_count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Fetched %zu profile%s",
            fetched_count, fetched_count == 1 ? "" : "s"
        );
    }
    if (failed_count > 0) {
        output_print(
            out, OUTPUT_NORMAL,
            "{red}✗{reset} Failed to fetch %zu profile%s\n",
            failed_count, failed_count == 1 ? "" : "s"
        );
    }

    /* The run's failure. A branch the fetch tried and could not get is a broken
     * promise whether or not the others landed: the reason was printed beside
     * the branch it belongs to and the count above is the receipt, but only the
     * return value reaches the caller, and no flag here licenses swallowing it. */
    if (failed_count > 0) {
        /* The plural agrees with the total, which is the noun it qualifies: "1
         * of 2 profiles failed", "1 of 1 profile failed". */
        size_t attempted = fetched_count + failed_count;
        return ERROR(
            ERR_GIT, "%zu of %zu profile%s failed to fetch",
            failed_count, attempted, attempted == 1 ? "" : "s"
        );
    }

    if (fetched_count == 0) {
        return ERROR(
            ERR_GIT, "No profiles available to fetch"
        );
    }

    return NULL;
}

/**
 * Profile enable subcommand
 *
 * Four-phase flow over the view before — the dispatcher's, built over the enabled
 * set as it stands at dispatch (the spec declares it; a set that will not build
 * ends dispatch with the builder's message, and the enable never runs):
 *   1. Gather & validate — resolve --all/args to a request set, then filter out
 *      the already-enabled, the missing, and the ones that need a target and
 *      were named without one: such a profile is enabled only with one, so it
 *      is skipped and told the flag, whatever the request shape, and a run that
 *      enabled nothing is an error. Emits per-profile warnings; produces
 *      to_enable_validated. An already-enabled profile named with a --target
 *      that differs from its row's is not a skip: it re-enters the validated
 *      set as a retarget, and `retarget` remembers which one (at most one — the
 *      --target-single-profile rule above).
 *   2. Write scope to state — state_enable_profile per target. The one call serves
 *      both kinds: a fresh enable inserts the row, a retarget runs the UPSERT
 *      arm state.h documents (the target moves, the position stays).
 *      enabled_profiles membership and order are now authoritative. Nothing else
 *      is written: the view is computed, never stored. `before` borrows nothing
 *      from the row cache the mutation replaces.
 *   3. The view after — manifest_build over the post-enable set; manifest_diff
 *      attributes the transition to the newly enabled profiles, so gain-side
 *      stats (claimed / added / updated) land in the right slot per profile.
 *      A retarget reads as its claims materializing at the new target (staged);
 *      what departs at the old one is apply's to relocate.
 *   4. The save, then per-profile feedback — state_save, and only once it lands
 *      the lines that say what it made true: iterate the validated targets to
 *      preserve per-profile output (the retarget's line says so).
 */
static error_t profile_enable(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    const manifest_t *before = ctx->run.manifest;
    output_t *out = ctx->out;

    const char *target = NULL; /* --target, absolute: what the row stores */
    error_t err = NULL;

    /* Phase 1 observations — tallied during the validation loop. retarget names
     * the one already-enabled profile whose binding this run updates (borrowed
     * from to_enable; at most one, by the --target-single-profile rule). */
    const char *retarget = NULL;
    size_t already_enabled = 0;
    size_t not_found = 0;
    size_t no_target = 0;

    /* Phase 1: Gather & validate
     *
     * Whether a profile is enabled is the handle's to answer, from the rows it
     * holds (state_enabled), which nothing in this phase moves. seen_set tracks
     * profiles decided-about within this command pass, so duplicate args like
     * `enable foo foo` are silently deduped instead of producing two rows in
     * to_enable_validated (and, downstream, two "Enabled foo" lines with split
     * stats attribution). Its keys are borrowed from to_enable, the command arena's
     * as the set is. */
    hashmap_t *seen_set = hashmap_borrow(ctx->arena, 0);

    /* Resolve the request set (--all → list of local branches; args → verbatim).
     * Both paths deposit into to_enable; Phase 1's filter loop decides which
     * ones are actually actionable. */
    string_array_t to_enable;

    if (opts->all_profiles) {
        /* Enable every profile here, in the convention's order: a set the machine
         * enumerated has no other, and the rows appended below take the order
         * this list has. Named profiles keep the order typed; a row that exists
         * keeps its slot. */
        err = gitops_list_branches(repo, ctx->arena, &to_enable);
        if (err) return error_wrap(err, "Failed to list branches");
        profile_order(&to_enable);
    } else {
        /* Enable specified profiles */
        if (opts->profile_count == 0) {
            return error_hint(
                ERROR(ERR_INVALID_ARG, "No profiles specified"),
                "Use 'dotta profile enable <name>' or '--all'"
            );
        }

        string_array_init_cap(&to_enable, ctx->arena, opts->profile_count);
        for (size_t i = 0; i < opts->profile_count; i++) {
            string_array_push(&to_enable, opts->profiles[i]);
        }
    }

    /* Fatal up-front: --target binds to a specific profile and cannot disambiguate
     * among many. Caught here before any state mutation, one refusal with its
     * way out: the verb's own shape, never the user's command lines spelled
     * back. */
    if (opts->target && to_enable.count > 1) {
        return error_hint(
            ERROR(ERR_INVALID_ARG, "Cannot use --target with multiple profiles"),
            "Enable each profile on its own, each with its --target"
        );
    }

    /* Fatal up-front: the target itself. A target is a filesystem-shaped argument
     * — absolute, tilde, or relative to the working directory, the spelling
     * completion offers — read through the target's door (infra/path.h
     * path_input_target): the absolute path the row stores, held to the target's
     * rules. Validating inside the per-profile loop used to categorize a bad
     * target as not_found, which mislabels a CLI input problem as a missing
     * profile. With the --target-requires-single-profile rule above, a single
     * validation here covers every path that can reach Phase 2. */
    if (opts->target) {
        err = path_input_target(opts->target, ctx->arena, &target);
        if (err) return error_wrap(err, "Invalid --target value");
    }

    /* Filter: already-enabled, missing-branch and needs-a-target are per-profile
     * skips, each with its own tally — unless the already-enabled profile came
     * with a differing --target, which is a retarget and stays in the run's work.
     * The surviving set lands in to_enable_validated. */
    string_array_t to_enable_validated;
    string_array_init(&to_enable_validated, ctx->arena);

    for (size_t i = 0; i < to_enable.count; i++) {
        const char *profile = to_enable.entries[i];

        /* Silently dedupe duplicate args — decided about earlier in this pass */
        if (!hashmap_add(seen_set, profile, NULL)) continue;

        if (state_enabled(state, profile)) {
            /* --target on an enabled profile is a retarget: the binding is the
             * verb's subject, and state_enable_profile's UPSERT arm updates it
             * in place. Only another directory is work — the row's own, under
             * its spelling or another (mount_same_target), is an idempotent re-run
             * and stays the skip below, the row's spelling kept. */
            if (target) {
                const char *current = state_target(state, profile);
                if (!current || !mount_same_target(current, target)) {
                    retarget = profile;
                    string_array_push(&to_enable_validated, profile);
                    continue;
                }
                /* The row's own directory, spelled another way: the binding stands
                 * and keeps the spelling its binder typed, because that spelling
                 * is the key of every path beneath it (infra/mount.h). Said at
                 * NORMAL: the user typed a flag and it was not written, and the
                 * row's spelling — not theirs — is the one their next argument
                 * is read under. */
                if (strcmp(current, target) != 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "  %s is already bound at %s — the same directory, "
                        "spelled another way", profile, current
                    );
                }
            }
            output_info(out, OUTPUT_VERBOSE, "  %s already enabled", profile);
            already_enabled++;
            continue;
        }

        /* Is the profile here? Git's answer or Git's error: an unreadable ref
         * is not an absence, and read as one it sent the user to fetch a profile
         * that was here. */
        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) return err;
        if (!exists) {
            output_warning(
                out, OUTPUT_NORMAL, "Profile '%s' doesn't exist locally", profile
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile list' for the local "
                "profiles, or 'dotta profile fetch %s' to bring it from the remote",
                profile
            );
            not_found++;
            continue;
        }

        /* A profile that needs a target is enabled only with one: the binding
         * is part of the enablement, and a row without one would hold every custom/
         * claim while the screens said "enabled". Whether it needs one is the
         * view's answer over the branch alone (core/profiles.h
         * profile_needs_target), asked whatever the flag says, so the branch is
         * the earlier question: a tree Git cannot read, or a sheet this build
         * cannot, is the error here and not one phase later, after the row was
         * written. Skipped and named with the flag, whatever the request shape;
         * a run that enabled nothing ends in the error below. */
        bool needs_target = false;
        err = profile_needs_target(repo, profile, &needs_target);
        if (err) return err;
        if (needs_target && !target) {
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s' holds custom/ paths and needs a target here", profile
            );
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --target /path", profile
            );
            no_target++;
            continue;
        }

        string_array_push(&to_enable_validated, profile);
    }

    /* Dry-run: preview what a live run would do, skip every state mutation. Dry-run
     * owns its complete UX below — the live-path summary is unreachable on this
     * branch, which returns before it. */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);

        size_t would_enable = to_enable_validated.count - (retarget ? 1 : 0);
        if (would_enable > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would enable %zu profile%s:",
                would_enable, would_enable == 1 ? "" : "s"
            );
            for (size_t i = 0; i < to_enable_validated.count; i++) {
                const char *name = to_enable_validated.entries[i];
                if (retarget && strcmp(name, retarget) == 0) continue;
                output_print(out, OUTPUT_NORMAL, "  - %s\n", name);
            }
        }
        if (retarget) {
            output_info(
                out, OUTPUT_NORMAL, "Would update deployment target for '%s'",
                retarget
            );
        }
        if (to_enable_validated.count > 0) {
            output_gap(out, OUTPUT_NORMAL);
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy paths"
            );
        }
        if (already_enabled > 0) {
            output_info(
                out, OUTPUT_NORMAL, "%zu profile%s already enabled",
                already_enabled, already_enabled == 1 ? "" : "s"
            );
        }
        if (not_found > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "%zu profile%s not found",
                not_found, not_found == 1 ? "" : "s"
            );
        }
        if (no_target > 0) {
            output_warning(
                out, OUTPUT_NORMAL, "%zu profile%s need%s a target",
                no_target, no_target == 1 ? "" : "s",
                no_target == 1 ? "s" : ""
            );
        }
        /* Mirror the live-path terminal: if nothing would be enabled because
         * every requested profile was missing or needs a target, surface the
         * same error a live run would produce. Idempotent cases (all already
         * enabled) succeed. */
        if (to_enable_validated.count == 0 && (not_found > 0 || no_target > 0)) {
            return ERROR(
                not_found > 0 ? ERR_NOT_FOUND : ERR_INVALID_ARG,
                "No profiles were enabled"
            );
        }
        return NULL;
    }

    /* Phases 2–4 share the "we have work to do" precondition. Wrapping them
     * together makes the "nothing validated → exit without touching state" path
     * explicit; the transaction opened by state_open then rolls back via state_free
     * on the no-op exit. */
    if (to_enable_validated.count > 0) {
        /* Phase 2: Write scope to state */
        for (size_t i = 0; i < to_enable_validated.count; i++) {
            const char *profile = to_enable_validated.entries[i];

            err = state_enable_profile(state, profile, target);
            if (err) {
                return error_wrap(
                    err, "Failed to enable profile '%s' in state", profile
                );
            }
        }

        /* Phase 3: The view after, and the diff. The builder reads the rows as
         * the loop above left them — any --target supplied for the new entries,
         * and the retargeted row's new binding, included. */
        manifest_t *after = NULL;
        err = manifest_build(repo, state, ctx->arena, &after);
        if (err) return error_wrap(err, "Failed to build manifest after enable");

        state_record_t *records = NULL;
        size_t record_count = 0;
        err = state_records(state, ctx->arena, &records, &record_count);
        if (err) return err;

        manifest_diff_stats_t *stats = arena_calloc(
            ctx->arena, to_enable_validated.count, sizeof(*stats)
        );

        manifest_diff(before, after, records, record_count, &to_enable_validated, stats);

        /* Phase 4: The save, then per-profile feedback — the retarget's line
         * names its verb. Each line says what the save made true, so none is
         * said before it: the COMMIT is a write the store can refuse on its own,
         * where a full disk meets the transaction (core/state.h state_commit),
         * and a line above it would stand over the refusal. */
        err = state_save(state);
        if (err) return error_wrap(err, "Failed to save state");

        for (size_t i = 0; i < to_enable_validated.count; i++) {
            const char *name = to_enable_validated.entries[i];
            if (retarget && strcmp(name, retarget) == 0) {
                output_print(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Updated target for %s\n",
                    name
                );
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} Enabled %s\n", name
                );
            }
            profile_print_enable_stats(out, name, &stats[i]);
        }
    }

    /* Live summary — only runs on non-dry-run, non-error completion. Any failure
     * in Phases 2-4, the save's included, returns before it; dry-run owns its
     * own messaging above. */
    output_gap(out, OUTPUT_NORMAL);

    {
        size_t enabled_count = to_enable_validated.count - (retarget ? 1 : 0);
        if (enabled_count > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Enabled %zu profile%s",
                enabled_count, enabled_count == 1 ? "" : "s"
            );
        }
        if (retarget) {
            output_success(
                out, OUTPUT_NORMAL, "Updated deployment target for '%s'", retarget
            );
        }
        if (to_enable_validated.count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to deploy paths"
            );
        }
    }
    if (already_enabled > 0) {
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s already enabled",
            already_enabled, already_enabled == 1 ? "" : "s"
        );
    }
    if (not_found > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "%zu profile%s not found",
            not_found, not_found == 1 ? "" : "s"
        );
    }
    if (no_target > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "%zu profile%s need%s a target",
            no_target, no_target == 1 ? "" : "s",
            no_target == 1 ? "s" : ""
        );
    }

    /* Terminal: error only if the user's inputs produced zero validated profiles
     * AND at least one was genuinely missing or needs a target — the code names
     * which, for the reader; every error exits the same. Pure idempotent cases
     * (all already-enabled, or --all on an empty repo) succeed. */
    if (to_enable_validated.count == 0 && (not_found > 0 || no_target > 0)) {
        return ERROR(
            not_found > 0 ? ERR_NOT_FOUND : ERR_INVALID_ARG,
            "No profiles were enabled"
        );
    }

    return NULL;
}

/**
 * Profile disable subcommand
 *
 * Five-phase flow, the mirror of profile_enable's:
 *   1. Gather & validate — filter requested profiles to those actually enabled;
 *      emit not-enabled diagnostics up front. Read the bindings the deletes will
 *      forget: the one fact disable destroys that the user cannot recompute,
 *      copied before the deletes replace the row cache they borrow from.
 *   2. The view before — manifest_build over the enabled set as it stands. It
 *      feeds the receipt only: a set that will not build is warned about and
 *      the disable lands without one.
 *   3. Write scope to state — state_disable_profile per validated target;
 *      enabled_profiles is now authoritative for the target set, the line gone
 *      whole, target included. Nothing else is written: what the next apply prunes
 *      or releases is derivable — the disabled profile's records are no longer
 *      in the view, and the orphan analysis asks Git about each.
 *   4. The view after — manifest_build over the post-disable set; manifest_diff
 *      attributes the transition to the disabled profiles, so loss-side stats
 *      (reassigned / orphans.owned / orphans.observed) land in the right slot.
 *   5. The save, then per-profile feedback — state_save, and only once it lands
 *      the lines that say what it made true: iterate the validated targets to
 *      preserve the existing per-profile UX; a forgotten target is named with
 *      the way back, so `disable --all` then `enable --all` is a copy-paste per
 *      line.
 */
static error_t profile_disable(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    error_t err = NULL;

    /* Phase 1 observation — tallied during explicit-args validation. */
    size_t not_enabled = 0;

    /* Phase 1: Gather & validate
     *
     * The enabled rows, where the handle holds them, read until Phase 3's first
     * delete replaces them (core/state.h state_profiles). What outlives that is
     * copied: the names into to_disable_validated, the targets into forgotten. */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* --all on an empty enabled set is idempotent: there is nothing to disable,
     * which matches `disable <name>` where <name> is not enabled (also a no-op
     * success). The historic ERR_NOT_FOUND here made the two paths inconsistent
     * for the same user intent. */
    if (opts->all_profiles && enabled_profiles.count == 0) {
        output_info(out, OUTPUT_NORMAL, "No enabled profiles to disable");
        return NULL;
    }

    /* Whether a named profile is enabled is the handle's to answer, from the
     * same rows (state_enabled). seen_set tracks profiles decided-about within
     * this command pass, so duplicate args (`disable foo foo`) are silently deduped
     * and don't produce two rows in to_disable_validated. Only the explicit-args
     * path consults it; --all iterates the unique enabled set. Its keys are
     * borrowed from opts->profiles, which outlive it. */
    hashmap_t *seen_set = hashmap_borrow(ctx->arena, 0);
    string_array_t to_disable_validated;
    string_array_init(&to_disable_validated, ctx->arena);

    if (opts->all_profiles) {
        /* --all: every currently enabled profile is, by definition, valid. */
        for (size_t i = 0; i < enabled_profiles.count; i++) {
            string_array_push(&to_disable_validated, enabled_profiles.entries[i].name);
        }
    } else {
        /* Disable specified profiles */
        if (opts->profile_count == 0) {
            return error_hint(
                ERROR(ERR_INVALID_ARG, "No profiles specified"),
                "Use 'dotta profile disable <name>' or '--all'"
            );
        }

        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *profile = opts->profiles[i];

            /* Silently dedupe duplicate args — decided about earlier in this pass */
            if (!hashmap_add(seen_set, profile, NULL)) continue;

            if (state_enabled(state, profile)) {
                string_array_push(&to_disable_validated, profile);
            } else {
                output_info(
                    out, OUTPUT_VERBOSE, "  %s was not enabled", profile
                );
                not_enabled++;
            }
        }
    }

    /* The bindings the deletes forget, spelled as the screens print them — arena
     * copies, because Phase 3's first delete replaces the row cache state_target
     * lends from. NULL where the row had none. */
    const char **forgotten = arena_calloc(
        ctx->arena, to_disable_validated.count, sizeof(*forgotten)
    );
    for (size_t i = 0; i < to_disable_validated.count; i++) {
        const char *bound =
            state_target(state, to_disable_validated.entries[i]);
        if (!bound) continue;
        char shown[PATH_MAX];
        output_format_path(bound, identity()->home, shown, sizeof(shown));
        forgotten[i] = arena_strdup(ctx->arena, shown);
    }

    /* Dry-run: preview what a live run would do, skip every state mutation. Dry-run
     * owns its complete UX below — the live-path summary is unreachable on this
     * branch, which returns before it. */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);

        if (to_disable_validated.count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would disable %zu profile%s:",
                to_disable_validated.count,
                to_disable_validated.count == 1 ? "" : "s"
            );
            for (size_t i = 0; i < to_disable_validated.count; i++) {
                output_print(
                    out, OUTPUT_NORMAL, "  - %s", to_disable_validated.entries[i]
                );
                if (forgotten[i]) {
                    output_print(
                        out, OUTPUT_NORMAL, " (forgets target %s)", forgotten[i]
                    );
                }
                output_endline(out, OUTPUT_NORMAL);
            }
            output_gap(out, OUTPUT_NORMAL);
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta apply' to remove deployed paths"
            );
        }
        if (not_enabled > 0) {
            output_info(
                out, OUTPUT_NORMAL, "%zu profile%s not enabled",
                not_enabled, not_enabled == 1 ? "" : "s"
            );
        }
        return NULL;
    }

    /* Phases 2–5 share the "we have work to do" precondition. Wrapping them
     * together makes the "nothing validated → exit without touching state" path
     * explicit; the transaction opened by state_open then rolls back via state_free
     * on the no-op exit. */
    if (to_disable_validated.count > 0) {
        /* Phase 2: The view before (see profile_enable).
         *
         * Unlike enable's, this build gates nothing: the disable is a membership
         * write that needs no view, and it must land whatever the enabled set
         * looks like — it is the way out of a set the loads cannot build (a profile
         * whose metadata.json will not parse, a branch that will not load), and
         * that set is exactly the one this build fails on. The message names
         * the profile; warn with it and disable without the receipt. */
        manifest_t *before = NULL;
        err = manifest_build(repo, state, ctx->arena, &before);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Manifest build failed: %s", error_message(err)
            );
        }

        /* Phase 3: Write scope to state */
        for (size_t i = 0; i < to_disable_validated.count; i++) {
            err = state_disable_profile(state, to_disable_validated.entries[i]);
            if (err) {
                return error_wrap(
                    err, "Failed to remove profile '%s' from state",
                    to_disable_validated.entries[i]
                );
            }
        }

        /* Phase 4: The view after, and the diff — skipped with `before`, whose
         * warning already covers it. Once `before` has built, this build cannot
         * fail on Git's account: the post-disable set is a subset of the same
         * profiles at the same HEADs. */
        manifest_diff_stats_t *stats = NULL;
        if (before) {
            manifest_t *after = NULL;
            err = manifest_build(repo, state, ctx->arena, &after);
            if (err) return error_wrap(err, "Failed to build manifest after disable");

            state_record_t *records = NULL;
            size_t record_count = 0;
            err = state_records(state, ctx->arena, &records, &record_count);
            if (err) return err;

            stats = arena_calloc(ctx->arena, to_disable_validated.count, sizeof(*stats));

            manifest_diff(
                before, after, records, record_count, &to_disable_validated, stats
            );
        }

        /* Phase 5: The save, then per-profile feedback (no stats when the receipt
         * was skipped) — each line said once the save made it true, as enable's
         * are. The target the row carried went with it; the line says so and
         * names the command that puts it back. */
        err = state_save(state);
        if (err) return error_wrap(err, "Failed to save state");

        for (size_t i = 0; i < to_disable_validated.count; i++) {
            const char *name = to_disable_validated.entries[i];
            output_print(
                out, OUTPUT_NORMAL, "  {green}✓{reset} Disabled %s\n", name
            );
            profile_print_disable_stats(out, name, stats ? &stats[i] : NULL);
            if (forgotten[i]) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  Forgot target %s (dotta profile enable %s --target %s "
                    "restores it)\n", forgotten[i], name, forgotten[i]
                );
            }
        }
    }

    /* Live summary — only runs on non-dry-run, non-error completion. All reachable
     * states here are successes:
     *   - count > 0: actual work performed.
     *   - count == 0 && not_enabled > 0: idempotent (user asked to disable profiles
     *     that weren't enabled).
     *   - count == 0 && not_enabled == 0 is unreachable: the explicit-args path
     *     requires opts->profile_count > 0 (caught earlier), and the --all-on-empty
     *     case is caught by the early exit. */
    output_gap(out, OUTPUT_NORMAL);

    if (to_disable_validated.count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Disabled %zu profile%s",
            to_disable_validated.count,
            to_disable_validated.count == 1 ? "" : "s"
        );
        output_info(
            out, OUTPUT_NORMAL, "Run 'dotta apply' to remove deployed paths"
        );
    }

    if (not_enabled > 0) {
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s not enabled",
            not_enabled, not_enabled == 1 ? "" : "s"
        );
    }

    return NULL;
}

/**
 * Profile reorder subcommand
 *
 * Rewrites this machine's order, which is the precedence: the user names every
 * enabled profile once, in the order wanted. Three checks make the list the enabled
 * set permuted — no name twice, every name enabled, the counts equal — and the
 * state's own boundary refuses the same (state_reorder_profiles).
 */
static error_t profile_reorder(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    /* Validation: at least one profile specified */
    if (opts->profile_count == 0) {
        return error_hint(
            ERROR(ERR_INVALID_ARG, "No profiles specified"),
            "Provide profiles in desired order: dotta profile reorder <p1> <p2> ..."
        );
    }

    /* The enabled rows, where the handle holds them, read up to the rewrite below,
     * which replaces them (core/state.h state_profiles) */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* Edge case: no enabled profiles */
    if (enabled_profiles.count == 0) {
        return error_hint(
            ERROR(ERR_VALIDATION, "No enabled profiles to reorder"),
            "Run 'dotta profile enable <name>' first"
        );
    }

    /* Validation 1: Check for duplicates in new order */
    for (size_t i = 0; i < opts->profile_count; i++) {
        for (size_t j = i + 1; j < opts->profile_count; j++) {
            if (strcmp(opts->profiles[i], opts->profiles[j]) == 0) {
                return ERROR(
                    ERR_VALIDATION,
                    "Profile '%s' appears multiple times in reorder list",
                    opts->profiles[i]
                );
            }
        }
    }

    /* Validation 2: All provided profiles must be currently enabled */
    for (size_t i = 0; i < opts->profile_count; i++) {
        if (!state_enabled(state, opts->profiles[i])) {
            return error_hint(
                ERROR(ERR_VALIDATION, "Profile '%s' is not enabled", opts->profiles[i]),
                "Run 'dotta profile list' to see enabled profiles"
            );
        }
    }

    /* Validation 3: Profile count must match. With no name twice and every name
     * enabled, equal counts make the named set the enabled set — nothing is left
     * to check for. */
    if (opts->profile_count != enabled_profiles.count) {
        return ERROR(
            ERR_VALIDATION, "Profile count mismatch: %zu enabled, %zu provided; a "
            "reorder names every enabled profile",
            enabled_profiles.count, opts->profile_count
        );
    }

    /* Check if order actually changed (idempotency) */
    bool order_changed = false;
    for (size_t i = 0; i < opts->profile_count; i++) {
        if (strcmp(opts->profiles[i], enabled_profiles.entries[i].name) != 0) {
            order_changed = true;
            break;
        }
    }

    if (!order_changed) {
        output_info(out, OUTPUT_NORMAL, "Profiles already in requested order");
        return NULL;  /* Success, but no-op */
    }

    /* Show before/after in verbose mode */
    output_section(out, OUTPUT_VERBOSE, "Profile order change");

    output_print(out, OUTPUT_VERBOSE, "  Before:");
    for (size_t i = 0; i < enabled_profiles.count; i++) {
        output_print(
            out, OUTPUT_VERBOSE, " %s",
            enabled_profiles.entries[i].name
        );
    }
    output_endline(out, OUTPUT_VERBOSE);

    output_print(out, OUTPUT_VERBOSE, "  After: ");
    for (size_t i = 0; i < opts->profile_count; i++) {
        output_print(
            out, OUTPUT_VERBOSE, " %s",
            opts->profiles[i]
        );
    }
    output_endline(out, OUTPUT_VERBOSE);

    /* Update state with new order */
    string_array_t order;
    string_array_init_cap(&order, ctx->arena, opts->profile_count);
    for (size_t i = 0; i < opts->profile_count; i++) {
        string_array_push(&order, opts->profiles[i]);
    }
    error_t err = state_reorder_profiles(state, &order);
    if (err) {
        return error_wrap(err, "Failed to update state");
    }

    /* Nothing else to write: the view is computed from the enabled set at every
     * load, so the new precedence is simply what the next status, diff or apply
     * reads. */

    /* Save state (releases lock automatically) */
    err = state_save(state);
    if (err) {
        return error_wrap(err, "Failed to save state");
    }

    /* Success message */
    output_gap(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Reordered %zu profile%s",
        opts->profile_count, opts->profile_count == 1 ? "" : "s"
    );
    output_info(out, OUTPUT_NORMAL, "New precedence takes effect on the next run");
    output_hint(out, OUTPUT_NORMAL, "Run 'dotta status' to review changes");

    return NULL;
}

/**
 * Profile validate subcommand
 *
 * Checks state consistency and offers to fix issues.
 */
static error_t profile_validate(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    error_t err = NULL;

    /* State for reporting */
    bool has_issues = false;
    bool fixed_enabled_profiles = false;  /* Track what we actually fixed */
    bool has_orphaned_files = false;      /* Track issues we can't fix */
    size_t orphaned_files = 0;

    /* Promote to a write transaction when we intend to mutate */
    if (opts->fix) {
        err = state_begin(state);
        if (err) {
            err = error_wrap(err, "Failed to begin state transaction");
            goto cleanup;
        }
    }

    /* The enabled rows, where the handle holds them: read after the promotion,
     * which reads them again under its lock, and until the first fix below replaces
     * them (core/state.h state_profiles) — the missing ones are copied into their
     * own list first */
    state_profiles_t enabled_profiles = state_profiles(state);

    output_section(out, OUTPUT_NORMAL, "Validating profile state");

    /* Check 1: Enabled profiles exist as branches */
    string_array_t missing;
    string_array_init(&missing, ctx->arena);

    for (size_t i = 0; i < enabled_profiles.count; i++) {
        const char *profile = enabled_profiles.entries[i].name;

        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) goto cleanup;
        if (!exists) {
            string_array_push(&missing, profile);
            has_issues = true;
        }
    }

    if (missing.count > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Found %zu missing profile%s in state:",
            missing.count, missing.count == 1 ? "" : "s"
        );

        for (size_t i = 0; i < missing.count; i++) {
            output_print(out, OUTPUT_NORMAL, "  • %s\n", missing.entries[i]);
        }

        if (opts->fix) {
            /* Remove missing profiles from state */
            for (size_t i = 0; i < missing.count; i++) {
                const char *profile = missing.entries[i];
                err = state_disable_profile(state, profile);
                if (err) {
                    err = error_wrap(
                        err, "Failed to remove missing profile '%s' from state",
                        profile
                    );
                    goto cleanup;
                }
            }

            err = state_commit(state);
            if (err) {
                err = error_wrap(err, "Failed to commit state transaction");
                goto cleanup;
            }

            output_success(out, OUTPUT_NORMAL, "Removed missing profiles from state");
            fixed_enabled_profiles = true;
        } else {
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile validate --fix' to remove them");
        }
    }

    /* Check 2: The record references valid profiles
     *
     * One read of the path_records table, walked once; each distinct profile is
     * asked of Git once (`probed` remembers the answer), so R records cost P
     * probes, where P is the distinct-profile count, typically < 10. `deleted`
     * keeps the missing profiles in first-seen order so the report is reproducible.
     * Nothing here is fixable in place: a record whose profile is gone is an
     * orphan the next apply reads, asks Git about, finds LOST, and releases. */
    state_record_t *records = NULL;
    size_t record_count = 0;
    err = state_records(state, ctx->arena, &records, &record_count);
    if (err) goto cleanup;

    string_array_t deleted;
    string_array_init(&deleted, ctx->arena);
    hashmap_t *probed = hashmap_borrow(ctx->arena, 16);   /* profile → its branch gone (non-NULL) or not */

    for (size_t i = 0; i < record_count; i++) {
        const char *profile = records[i].profile;

        void *gone = NULL;
        if (!hashmap_find(probed, profile, &gone)) {
            bool exists = false;
            err = gitops_branch_exists(repo, profile, &exists);
            if (err) goto cleanup;
            gone = (void *) (uintptr_t) !exists;
            hashmap_set(probed, profile, gone);
            if (gone) string_array_push(&deleted, profile);
        }

        if (gone) {
            orphaned_files++;
            has_issues = true;
            has_orphaned_files = true;
        }
    }

    if (orphaned_files > 0) {
        output_warning(
            out, OUTPUT_NORMAL, "Found %zu entr%s from deleted profile%s in state:",
            orphaned_files, orphaned_files == 1 ? "y" : "ies",
            deleted.count == 1 ? "" : "s"
        );

        for (size_t i = 0; i < deleted.count; i++) {
            size_t n = 0;
            for (size_t j = 0; j < record_count; j++) {
                if (strcmp(records[j].profile, deleted.entries[i]) == 0) n++;
            }
            output_print(
                out, OUTPUT_NORMAL, "  • %zu entr%s from %s\n",
                n, n == 1 ? "y" : "ies", deleted.entries[i]
            );
        }

        output_hint(out, OUTPUT_NORMAL, "Run 'dotta apply' to release them");
    }

cleanup:
    /* Cleanup all resources. state_rollback is a no-op if no transaction is active,
     * so it's safe to call unconditionally on the borrowed handle */
    state_rollback(state);

    /* If there's an error, return it now */
    if (err) return err;

    /* Summary (only shown on success) */
    output_gap(out, OUTPUT_NORMAL);
    if (!has_issues) {
        output_success(out, OUTPUT_NORMAL, "Profile state is valid");
    } else {
        if (opts->fix) {
            /* Be accurate about what was actually fixed */
            if (fixed_enabled_profiles && !has_orphaned_files) {
                output_success(
                    out, OUTPUT_NORMAL, "Fixed all profile state issues"
                );
            } else if (fixed_enabled_profiles && has_orphaned_files) {
                output_info(
                    out, OUTPUT_NORMAL, "Fixed enabled profile list"
                );
                output_info(
                    out, OUTPUT_NORMAL,
                    "Entries from deleted profiles require 'dotta apply' to release"
                );
            } else if (!fixed_enabled_profiles && has_orphaned_files) {
                output_warning(
                    out, OUTPUT_NORMAL, "Profile state has issues that require 'dotta apply'"
                );
            } else {  /* Shouldn't reach here, but handle gracefully */
                output_warning(
                    out, OUTPUT_NORMAL, "Profile state has issues"
                );
            }
        } else {
            output_warning(
                out, OUTPUT_NORMAL, "Profile state has issues"
            );
            output_info(
                out, OUTPUT_NORMAL, "Run 'dotta profile validate --fix'"
            );
        }
    }

    return NULL;
}

/**
 * Profile command dispatcher
 */
error_t cmd_profile(const dotta_ctx_t *ctx, const cmd_profile_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    /* Dispatch to subcommand */
    switch (opts->subcommand) {
        case PROFILE_LIST:     return profile_list(ctx, opts);
        case PROFILE_FETCH:    return profile_fetch(ctx, opts);
        case PROFILE_ENABLE:   return profile_enable(ctx, opts);
        case PROFILE_DISABLE:  return profile_disable(ctx, opts);
        case PROFILE_REORDER:  return profile_reorder(ctx, opts);
        case PROFILE_VALIDATE: return profile_validate(ctx, opts);
    }

    CHECK_ARG(false, "a profile subcommand no enumerator names");
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Single dispatch wrapper shared by every subcommand.
 *
 * Each sub's `init_defaults` already set the `subcommand` discriminator, so
 * `cmd_profile`'s switch routes the call.
 */
static error_t profile_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_profile(ctx, (const cmd_profile_options_t *) opts_v);
}

/* --- list --- */

static void profile_list_defaults(void *o) {
    cmd_profile_options_t *opts = o;
    opts->subcommand = PROFILE_LIST;
    opts->show_available = true;
}

static const args_opt_t profile_list_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",             cmd_profile_options_t,show_remote,
        "Show all available and remote profiles"
    ),
    ARGS_END,
};

static const args_command_t spec_profile_list = {
    .name          = "profile list",
    .summary       = "Show all profiles and their enabled status",
    .usage         = "%s profile list [--all]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_list_opts,
    .init_defaults = profile_list_defaults,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_READ,
    },
    .dispatch      = profile_dispatch,
};

/* --- fetch --- */

static void profile_fetch_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_FETCH;
}

/* What can stand at the cursor: a profile to download — a remote-tracking branch
 * not yet local, or a local one to refresh. */
static args_want_t profile_fetch_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    (void) at;
    completion_profiles(ctx_v, out, COMPLETION_ALL);
    return ARGS_WANT_NONE;
}

static const args_opt_t profile_fetch_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",                  cmd_profile_options_t,  fetch_all,
        "Fetch all remote profiles"
    ),
    ARGS_FLAG_SET(
        "v verbose",            cmd_profile_options_t,  verbosity,
        DOTTA_VERBOSITY_VERBOSE,
        "Show detailed progress"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,
        profiles,               profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_fetch = {
    .name          = "profile fetch",
    .summary       = "Download profiles from a remote without enabling them",
    .usage         = "%s profile fetch [--all] [-v] [<name>...]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_fetch_opts,
    .init_defaults = profile_fetch_defaults,
    .complete      = profile_fetch_complete,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = profile_dispatch,
};

/* --- enable --- */

static void profile_enable_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_ENABLE;
}

/* What can stand at the cursor: a local profile, marked when already enabled;
 * for --target, a directory. */
static args_want_t profile_enable_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    if (ARGS_VALUE_IS(at, cmd_profile_options_t, target)) {
        return ARGS_WANT_DIRS;
    }
    completion_profiles(ctx_v, out, COMPLETION_LOCAL);
    return ARGS_WANT_NONE;
}

static const args_opt_t profile_enable_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",
        cmd_profile_options_t,all_profiles,
        "Enable all local profiles"
    ),
    ARGS_STRING(
        "target",             "<path>",
        cmd_profile_options_t,target,
        "Bind the profile's custom/ tree at this directory"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_profile_options_t,dry_run,
        "Show what would change without modifying state"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_profile_options_t,verbosity,    DOTTA_VERBOSITY_VERBOSE,
        "Show detailed progress"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_profile_options_t,verbosity,    DOTTA_VERBOSITY_QUIET,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles,     profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_enable = {
    .name          = "profile enable",
    .summary       = "Enable profiles for deployment",
    .usage         = "%s profile enable [options] [<name>...]",
    .description   =
        "Enables one or more profiles so that 'dotta apply' deploys their files.\n"
        "\n"
        "  A newly enabled profile is appended above the ones already enabled, and\n"
        "  later wins where two profiles provide one path. Named profiles are\n"
        "  appended in the order given; --all enables every local profile in the\n"
        "  layering convention's order (global, the OS, then the hosts). 'dotta\n"
        "  profile reorder' moves them afterwards.\n"
        "\n"
        "  --target <path> binds the profile's custom/ tree at that directory\n"
        "  (e.g. --target /mnt/jails/web; a relative path is read from the\n"
        "  working directory). A profile with custom/ paths is enabled only\n"
        "  with one, and one profile per invocation may take it. On an\n"
        "  already-enabled profile it moves the binding in place; the claims\n"
        "  re-resolve at the next apply.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_enable_opts,
    .init_defaults = profile_enable_defaults,
    .complete      = profile_enable_complete,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_WRITE,
        .manifest  = true,
    },
    .dispatch      = profile_dispatch,
};

/* --- disable --- */

static void profile_disable_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_DISABLE;
}

/* What can stand at the cursor: an enabled profile. */
static args_want_t profile_disable_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    (void) at;
    completion_profiles(ctx_v, out, COMPLETION_ENABLED);
    return ARGS_WANT_NONE;
}

static const args_opt_t profile_disable_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "all",
        cmd_profile_options_t,all_profiles,
        "Disable all currently enabled profiles"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_profile_options_t,dry_run,
        "Show what would change without modifying state"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_profile_options_t,verbosity,    DOTTA_VERBOSITY_VERBOSE,
        "Show detailed progress"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_profile_options_t,verbosity,    DOTTA_VERBOSITY_QUIET,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles,     profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_disable = {
    .name          = "profile disable",
    .summary       = "Disable profiles, mark for removal on next apply",
    .usage         = "%s profile disable [options] [<name>...]",
    .description   =
        "Disables one or more profiles; the next 'dotta apply' removes what they\n"
        "deployed. A disabled profile's target goes with its row — nothing\n"
        "remembers it — and the receipt names the target it forgets with the\n"
        "command that restores it.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_disable_opts,
    .init_defaults = profile_disable_defaults,
    .complete      = profile_disable_complete,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_WRITE,
    },
    .dispatch      = profile_dispatch,
};

/* --- reorder --- */

static void profile_reorder_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_REORDER;
}

/* What can stand at the cursor: an enabled profile, every one in the new order. */
static args_want_t profile_reorder_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    (void) at;
    completion_profiles(ctx_v, out, COMPLETION_ENABLED);
    return ARGS_WANT_NONE;
}

static const args_opt_t profile_reorder_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_profile_options_t,verbosity,  DOTTA_VERBOSITY_VERBOSE,
        "Show the profile order before and after the change"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_profile_options_t,verbosity,  DOTTA_VERBOSITY_QUIET,
        "Suppress non-error output"
    ),
    ARGS_POSITIONAL_ANY(
        cmd_profile_options_t,profiles,   profile_count
    ),
    ARGS_END,
};

static const args_command_t spec_profile_reorder = {
    .name          = "profile reorder",
    .summary       = "Change the layering order of enabled profiles",
    .usage         = "%s profile reorder [options] [<name>...]",
    .description   =
        "Provide every enabled profile in the desired order. Later profiles\n"
        "override earlier ones during layering.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_reorder_opts,
    .init_defaults = profile_reorder_defaults,
    .complete      = profile_reorder_complete,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_WRITE,
    },
    .dispatch      = profile_dispatch,
};

/* --- validate --- */

static void profile_validate_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_VALIDATE;
}

static const args_opt_t profile_validate_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "fix",
        cmd_profile_options_t,fix,
        "Automatically fix any detected inconsistencies"
    ),
    ARGS_END,
};

static const args_command_t spec_profile_validate = {
    .name          = "profile validate",
    .summary       = "Check for and fix inconsistencies in the profile state",
    .usage         = "%s profile validate [--fix]",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_validate_opts,
    .init_defaults = profile_validate_defaults,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_READ,
    },
    .dispatch      = profile_dispatch,
};

/* --- parent: subcommand index + spec --- */

/* Every verb but `list` — `dotta list` is the list command — also stands at the
 * root: `dotta enable work` for `dotta profile enable work`. */
static const args_subcommand_t profile_subs[] = {
    /* aliases     spec                    hidden shortcut */
    { "list",     &spec_profile_list,     false, false },
    { "fetch",    &spec_profile_fetch,    false, true  },
    { "enable",   &spec_profile_enable,   false, true  },
    { "disable",  &spec_profile_disable,  false, true  },
    { "reorder",  &spec_profile_reorder,  false, true  },
    { "validate", &spec_profile_validate, false, true  },
    { NULL,       NULL,                   false, false }
};

const args_command_t spec_profile = {
    .name               = "profile",
    .summary            = "Profile management and layering",
    .usage              = "%s profile <subcommand> [options]",
    .description        =
        "Enabling a profile is a persistent choice that marks it for deployment.\n"
        "Run 'dotta apply' to synchronize the workspace with the set of enabled profiles.\n",
    .notes              =
        "Manage which profiles are used in your current workspace.\n"
        "Profile States:\n"
        "  • Available  - Profiles that exist locally but are not enabled\n"
        "  • Enabled    - Profiles that will be deployed by 'dotta apply'\n"
        "  • Remote     - Profiles on a remote that have not been fetched yet\n",
    .examples           =
        "  %s profile list --all              # Show local and remote profiles\n"
        "  %s profile fetch darwin            # Download a profile\n"
        "  %s profile enable darwin           # Enable a profile for deployment\n"
        "  %s profile disable --all           # Disable all enabled profiles\n"
        "  %s profile reorder global darwin   # Change layering priority\n"
        "  %s profile validate --fix          # Fix state inconsistencies\n",
    .opts_size          = sizeof(cmd_profile_options_t),
    .subcommands        = profile_subs,
    .default_subcommand = &spec_profile_list,
};
