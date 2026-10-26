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
#include "core/workspace.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/identity.h"
#include "sys/transfer.h"
#include "sys/upstream.h"

/**
 * Profile list subcommand
 *
 * Shows enabled vs available profiles with clear visual distinction.
 */
static error_t profile_list(const dotta_ctx_t *ctx, const cmd_profile_options_t *opts) {
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
    string_array_t profiles;
    err = gitops_list_branches(repo, ctx->arena, &profiles);
    if (err) goto cleanup;

    /* Separate into enabled and available */
    string_array_t available;
    string_array_init(&available, ctx->arena, 0);
    for (size_t i = 0; i < profiles.count; i++) {
        const char *profile = profiles.entries[i];
        if (state_enabled(state, profile)) continue;

        string_array_push(&available, profile);
    }

    /* Print enabled profiles: the name, what the profile holds, and the binding
     * beside the name when the row has one — the thing is never printed without
     * the where. */
    if (enabled_profiles.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Enabled profiles (in layering order)");
        for (size_t i = 0; i < enabled_profiles.count; i++) {
            const state_profile_entry_t *entry = &enabled_profiles.entries[i];
            const char *name = entry->name;

            /* What the profile holds, counted over its head (core/profiles.h
             * profile_counts) */
            profile_t *profile = NULL;
            profile_counts_t count = { 0 };
            error_t row_err = profile_load(repo, name, &profile);
            if (!row_err) row_err = profile_counts(profile, &count);
            profile_free(profile);

            /* Name what the profile holds where it reads, otherwise say so: a
             * branch Git does not hold in the health channel's word
             * (core/manifest.h manifest_missing), off the load's refusal, whose
             * code no count's failure answers (core/profiles.h profile_load);
             * any other failure as one. The row's error is dropped, one per
             * unreadable profile */
            if (error_code(row_err) == ERR_NOT_FOUND) {
                output_print(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} {yellow}(no branch){reset}",
                    i + 1, name
                );
            } else if (row_err) {
                output_print(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (counts unavailable)",
                    i + 1, name
                );
            } else {
                char counts[64];
                output_format_counts(
                    count.file_count, count.directory_count, counts, sizeof(counts)
                );
                output_print(
                    out, OUTPUT_NORMAL, "  %zu. {cyan}%s{reset} (%s)",
                    i + 1, name, counts
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
        /* Enable takes only a profile whose branch is here: the ones listed below */
        output_info(out, OUTPUT_NORMAL, "No enabled profiles");
        if (available.count > 0) {
            output_hint(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>'");
        }
    }

    /* Print available (disabled) profiles, marking the ones that need a target:
     * such a profile is enabled only with one, so this is the mark on exactly
     * the profile clone and --all left here, and the answer is the profile's
     * own (core/profiles.h profile_needs_target). One handle serves both: the
     * count and the mark walk one head and parse its sheet once, and a row that
     * would not count says so rather than marking nothing in silence. */
    if (available.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Available (disabled)");
        for (size_t i = 0; i < available.count; i++) {
            const char *name = available.entries[i];

            /* What the profile holds, and whether it needs a target, both asked
             * of the one handle loaded at its head */
            profile_t *profile = NULL;
            profile_counts_t count = { 0 };
            bool needs_target = false;
            error_t row_err = profile_load(repo, name, &profile);
            if (!row_err) row_err = profile_counts(profile, &count);
            if (!row_err) row_err = profile_needs_target(profile, &needs_target);
            profile_free(profile);

            /* Name what the profile holds where it reads, otherwise say so: the
             * row's error is dropped, one per unreadable profile */
            if (row_err) {
                output_print(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (counts unavailable)",
                    name
                );
            } else {
                char counts[64];
                output_format_counts(
                    count.file_count, count.directory_count, counts, sizeof(counts)
                );
                output_print(
                    out, OUTPUT_NORMAL, "  • {cyan}%s{reset} (%s)", name, counts
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
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL, "Could not detect remote: %s",
                error_line(remote_err)
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
                output_gap(out, OUTPUT_NORMAL);
                output_warning(out, OUTPUT_NORMAL, "%s", error_line(remote_err));
            } else if (remote_branches.count > 0) {
                /* Filter out branches that already exist locally */
                string_array_t remote_only;
                string_array_init(&remote_only, ctx->arena, remote_branches.count);
                for (size_t ri = 0; ri < remote_branches.count; ri++) {
                    if (!string_array_contains(&profiles, remote_branches.entries[ri])) {
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
 * Brings profiles from the remote without enabling them: what the remote holds,
 * asked once; one fetch of the selection; and each profile made local where no
 * branch of its name stands here. The report is one table titled by the remote,
 * a row a profile in the selection's order, in the grammar of sync's receipt
 * (cmds/sync.c sync_print_receipt): its local branch created, or where the one
 * already here stands against the remote's the fetch brought, or why neither
 * could be said.
 */
static error_t profile_fetch(const dotta_ctx_t *ctx, const cmd_profile_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* Resource tracking for cleanup. remote_name/remote_url are arena-borrowed. */
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;
    error_t err = NULL;

    /* Detect remote (name + URL — URL feeds the credential helper). Its refusal
     * says which absence it met, none or several, and stands alone. */
    err = gitops_resolve_default_remote(repo, ctx->arena, &remote_name, &remote_url);
    if (err) goto cleanup;

    /* Create transfer context for progress reporting and credentials */
    transfer_options_t xfer_opts = {
        .output             = out,
        .url                = remote_url,
        .ephemeral_progress = true,
    };
    xfer = transfer_context_create(&xfer_opts);

    /* What the remote holds, asked once: every profile --all fetches, and the
     * pre-flight the names the line gives are held to. Asked unannounced: the
     * announce waits for the fetch it says, so a refusal here or below stands
     * alone on the report. */
    string_array_t remote_branches;
    err = gitops_list_remote_branches(repo, remote_name, xfer, ctx->arena, &remote_branches);
    if (err) goto cleanup;

    /* The selection, in the order it is fetched and reported: every profile the
     * remote holds under --all, else the ones the line names (profile_post_parse),
     * each once — a name given twice is decided once, as enable and disable take
     * it. Every name the remote does not hold is refused together before anything
     * is fetched: a fetch of named branches is whole or nothing, as git's is.
     * The names the remote does hold are in hand, and the refusal says them:
     * what the remote holds is the rest of the fact. */
    string_array_t selection;
    if (opts->all_profiles) {
        if (remote_branches.count == 0) {
            err = error_create(ERR_NOT_FOUND, "Remote '%s' holds no profiles", remote_name);
            goto cleanup;
        }
        selection = remote_branches;
    } else {
        string_array_t missing;
        string_array_init(&selection, ctx->arena, opts->profile_count);
        string_array_init(&missing, ctx->arena, 0);
        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *name = opts->profiles[i];
            if (string_array_contains(&selection, name) ||
                string_array_contains(&missing, name)) {
                continue;
            }

            string_array_push(
                string_array_contains(&remote_branches, name) ? &selection : &missing, name
            );
        }
        if (missing.count > 0) {
            err = error_create(
                ERR_NOT_FOUND, "%s '%s' %s not on remote '%s', which holds %s",
                missing.count == 1 ? "Profile" : "Profiles",
                string_array_join(ctx->arena, &missing, "', '"),
                missing.count == 1 ? "is" : "are", remote_name,
                remote_branches.count > 0
                    ? string_array_join(ctx->arena, &remote_branches, ", ")
                    : "no profiles"
            );
            goto cleanup;
        }
    }

    /* One fetch brings the selection, as sync's brings its scope (cmds/sync.c
     * sync_fetch): one negotiation and one pack for every profile, so what can
     * still fail profile by profile is the profile's own, below. Announced while
     * it runs — on a terminal the transfer's progress draws over the line and
     * both are cleared, on a pipe the announce stands, ended here — and its failure
     * is the run's, naming the act and the remote. */
    output_print(out, OUTPUT_NORMAL, "Fetching from '%s'...", remote_name);
    fflush(out->stream);

    const transfer_stats_t mark = transfer_stats(xfer);
    err = gitops_fetch_branches(repo, remote_name, &selection, xfer);

    if (output_is_tty(out)) {
        output_clear_line(out);
    } else {
        output_endline(out, OUTPUT_NORMAL);
    }
    if (err) goto cleanup;

    /* At verbose, the fetch done and what it moved: one op and one pack, so one
     * wire, never a profile's (lib/libgit2/include/git2/indexer.h
     * git_indexer_progress) — dim beside the line, and nothing where nothing
     * moved */
    const transfer_wire_t received = transfer_stats_since(xfer, mark).received;
    output_print(out, OUTPUT_VERBOSE, "{green}✓{reset} Fetched from '%s'", remote_name);
    if (received.objects > 0) {
        char phrase[TRANSFER_PHRASE_MAX];
        transfer_wire_phrase(received, phrase, sizeof(phrase));
        output_print(out, OUTPUT_VERBOSE, " {dim}(%s){reset}", phrase);
    }
    output_endline(out, OUTPUT_VERBOSE);

    /* The table, titled by the remote: a row a profile, in the selection's order,
     * in the grammar and the glyphs of sync's (cmds/sync.c sync_print_lead) */
    output_section(out, OUTPUT_NORMAL, "Fetch from '{cyan}%s{reset}'", remote_name);

    size_t failed = 0;
    for (size_t i = 0; i < selection.count; i++) {
        const char *profile = selection.entries[i];

        /* Where the profile stands against the remote's branch the fetch brought,
         * read as sync's and status's rows read it (sys/upstream.h
         * upstream_analyze_profile). One with no local branch is made local at
         * the remote's commit, the one act a fetch takes on a profile; a branch
         * already here is left where it stands — the fetch moved its
         * remote-tracking ref, and merging the two is sync's. */
        upstream_info_t upstream;
        error_t row_err = upstream_analyze_profile(repo, remote_name, profile, &upstream);
        if (!row_err && upstream.state == UPSTREAM_NO_LOCAL) {
            row_err = upstream_ensure_tracking_branch(repo, remote_name, profile);
        }

        /* A profile that fails is named and counted, its error dropped — at most
         * one per profile. The row is one the run's refusal counts, so it prints
         * at every level, naming its profile (base/output.h OUTPUT_QUIET). */
        if (row_err) {
            output_print(
                out, OUTPUT_QUIET, "  {red}✗{reset} {cyan}%s{reset}: %s\n",
                profile, error_line(row_err)
            );
            failed++;
            continue;
        }

        /* Made local: the act carried out */
        if (upstream.state == UPSTREAM_NO_LOCAL) {
            output_print(
                out, OUTPUT_NORMAL, "  {green}✓{reset} {cyan}%s{reset}: created local branch\n",
                profile
            );
            continue;
        }

        /* Otherwise where the branch here stands: its state's glyph in its colour,
         * and its phrase (sys/upstream.h) */
        char phrase[UPSTREAM_PHRASE_MAX];
        upstream_state_phrase(&upstream, phrase, sizeof(phrase));
        output_colored(
            out, OUTPUT_NORMAL, upstream_state_color(upstream.state), "  %s",
            upstream_state_symbol(upstream.state)
        );
        output_print(out, OUTPUT_NORMAL, " {cyan}%s{reset}: %s\n", profile, phrase);
    }

    /* The run's failure. A profile the fetch brought and the run could not make
     * local, or could not read, is a broken promise whether or not the others
     * landed: the reason was printed beside the profile it belongs to, but only
     * the return value reaches the caller, and no flag here licenses swallowing
     * it. The plural agrees with the total, which is the noun it qualifies: "1
     * of 2 profiles failed", "1 of 1 profile failed". */
    if (failed > 0) {
        err = error_create(
            ERR_GIT, "%zu of %zu profile%s failed to fetch",
            failed, selection.count, selection.count == 1 ? "" : "s"
        );
    }

cleanup:
    /* The one handle the run holds: the transfer, whose close commits the
     * credential decision (sys/transfer.h) */
    transfer_context_free(xfer);

    return err;
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
 *      is skipped and told the flag, whatever the request shape. Each skip is
 *      said once — a refused profile by its warning, the already-enabled by one
 *      count — and a run that enabled nothing is an error where one was refused.
 *      An enabled profile whose claims hold no target is told the flag too;
 *      produces to_enable_validated. An already-enabled profile named with a
 *      --target that differs from its row's is not a skip: it re-enters the
 *      validated set as a retarget, and `retarget` remembers which one (at most
 *      one: a target binds the one profile the line names,
 *      profile_enable_post_parse).
 *   2. Write scope to state — state_enable_profile per target. The one call serves
 *      both kinds: a fresh enable inserts the row, a retarget runs the UPSERT
 *      arm state.h documents (the target moves, the position stays).
 *      enabled_profiles membership and order are now authoritative. Nothing else
 *      is written: the view is computed, never stored. `before` borrows nothing
 *      from the row cache the mutation replaces.
 *   3. The view after and the record — manifest_build over the post-enable set,
 *      and the record held against it: whether the next apply has work there
 *      (core/workspace.h workspace_pending). A retarget's claims stand at the
 *      new target, and what its records hold at the old one is apply's to relocate.
 *   4. The save, then per-profile feedback — state_save, and only once it lands
 *      the lines that say what it made true: one per validated target (the
 *      retarget's line says so), then the next step where apply has work.
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
     * from to_enable; at most one, the line naming one with a target —
     * profile_enable_post_parse). */
    const char *retarget = NULL;
    size_t already_enabled = 0;
    size_t refused = 0;    /* Missing, or needing a target the line did not give */

    /* Phase 1: Gather & validate
     *
     * Whether a profile is enabled is the handle's to answer, from the rows it
     * holds (state_enabled), which nothing in this phase moves. seen_set tracks
     * profiles decided-about within this command pass, so duplicate args like
     * `enable foo foo` are silently deduped instead of producing two rows in
     * to_enable_validated (and, downstream, two "Enabled foo" lines). Its keys
     * are borrowed from to_enable, the command arena's as the set is. */
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
        if (err) return err;
        profile_order(&to_enable);
    } else {
        /* Enable the profiles the line names, one at least (profile_post_parse) */
        string_array_init(&to_enable, ctx->arena, opts->profile_count);
        for (size_t i = 0; i < opts->profile_count; i++) {
            string_array_push(&to_enable, opts->profiles[i]);
        }
    }

    /* Fatal up-front: the target itself. A target is a filesystem-shaped argument
     * — absolute, tilde, or relative to the working directory, the spelling
     * completion offers — spelled by the target's reading (infra/path.h
     * path_input_target): the absolute path the row stores, held to the target's
     * rules. Validating inside the per-profile loop would refuse a bad target
     * as a profile's skip, which mislabels a CLI input problem as a missing
     * profile. A target binds the one profile the line names, never --all
     * (profile_enable_post_parse), so a single validation here covers every path
     * that can reach Phase 2. */
    if (opts->target) {
        err = path_input_target(opts->target, ctx->arena, &target);
        if (err) return error_wrap(err, "Invalid --target value");
    }

    /* Filter: already-enabled, missing-branch and needs-a-target are per-profile
     * skips — unless the already-enabled profile came with a differing --target,
     * which is a retarget and stays in the run's work. The surviving set lands
     * in to_enable_validated. */
    string_array_t to_enable_validated;
    string_array_init(&to_enable_validated, ctx->arena, 0);

    for (size_t i = 0; i < to_enable.count; i++) {
        const char *name = to_enable.entries[i];

        /* Silently dedupe duplicate args — decided about earlier in this pass */
        if (!hashmap_add(seen_set, name, NULL)) continue;

        if (state_enabled(state, name)) {
            /* --target on an enabled profile is a retarget: the binding is the
             * verb's subject, and state_enable_profile's UPSERT arm updates it
             * in place. Only another directory is work — the row's own, under
             * its spelling or another (mount_same_target), is an idempotent re-run
             * and stays the skip below, the row's spelling kept. */
            if (target) {
                const char *current = state_target(state, name);
                if (!current || !mount_same_target(current, target)) {
                    retarget = name;
                    string_array_push(&to_enable_validated, name);
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
                        "spelled another way", name, current
                    );
                }
            }
            output_info(out, OUTPUT_VERBOSE, "  %s already enabled", name);
            already_enabled++;

            /* A row with no binding whose claims need one: said as the
             * needs-a-target skip below says it, with the flag. The fact is the
             * view before's, as status's legend reads it (core/manifest.h
             * manifest_unbound): a claim placed nowhere for want of a target,
             * which a bound row has none of. */
            manifest_unbound_t unbound = manifest_unbound(before);
            for (size_t j = 0; j < unbound.count; j++) {
                if (strcmp(unbound.entries[j].profile, name) != 0) continue;

                output_gap(out, OUTPUT_NORMAL);
                output_warning(
                    out, OUTPUT_NORMAL,
                    "Profile '%s' holds custom/ paths and needs a target here", name
                );
                output_hint(
                    out, OUTPUT_NORMAL, "dotta profile enable %s --target /path", name
                );
                break;
            }
            continue;
        }

        /* Is the profile here? Git's answer or Git's error: an unreadable ref
         * is not an absence, and read as one it sent the user to fetch a profile
         * that was here. */
        bool exists = false;
        err = gitops_branch_exists(repo, name, &exists);
        if (err) return err;
        if (!exists) {
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL, "Profile '%s' doesn't exist locally", name
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile list' for the local "
                "profiles, or 'dotta profile fetch %s' to bring it from the remote",
                name
            );
            refused++;
            continue;
        }

        /* A profile that needs a target is enabled only with one: the binding
         * is part of the enablement, and a row without one would hold every custom/
         * claim while the screens said "enabled". Whether it needs one is the
         * profile's own answer, the labels its walk shows asked of a table with
         * no binding (core/profiles.h profile_needs_target), asked whatever the
         * flag says, so the profile is the earlier question: a tree Git cannot
         * read, or a sheet this build cannot, is the error here and not one phase
         * later, after the row was written. Skipped and named with the flag,
         * whatever the request shape; a run that enabled nothing ends in the
         * error below. */
        profile_t *profile = NULL;
        bool needs_target = false;
        err = profile_load(repo, name, &profile);
        if (!err) err = profile_needs_target(profile, &needs_target);
        profile_free(profile);
        if (err) return err;
        if (needs_target && !target) {
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s' holds custom/ paths and needs a target here", name
            );
            output_hint(
                out, OUTPUT_NORMAL, "dotta profile enable %s --target /path", name
            );
            refused++;
            continue;
        }

        string_array_push(&to_enable_validated, name);
    }

    /* Each skip said once: a refused profile by its warning above, an enabled
     * one by this count, its own line being verbose's */
    if (already_enabled > 0) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s already enabled",
            already_enabled, already_enabled == 1 ? "" : "s"
        );
    }

    /* Nothing to enable, live or dry: a refusal where a profile the line named
     * was refused, each said above; a success where every one was enabled already,
     * or --all met a repository with no profile to enable. Either exit leaves
     * the state untouched: the transaction state_open began rolls back at
     * state_free. */
    if (to_enable_validated.count == 0) {
        if (refused == 0) return NULL;
        return error_create(ERR_INVALID_ARG, "No profiles were enabled");
    }

    /* Dry-run: preview what a live run would do, skip every state mutation. It
     * changes the enabled set nowhere, so it leaves apply nothing to do, and
     * names no next step. */
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
        return NULL;
    }

    /* Phase 2: Write scope to state */
    for (size_t i = 0; i < to_enable_validated.count; i++) {
        const char *profile = to_enable_validated.entries[i];

        err = state_enable_profile(state, profile, target);
        if (err) return err;
    }

    /* Phase 3: The view after, and the record held against it. The builder reads
     * the rows as the loop above left them — any --target supplied for the new
     * entries, and the retargeted row's new binding, included. */
    manifest_t *after = NULL;
    err = manifest_build(repo, state, ctx->arena, &after);
    if (err) return err;

    state_record_t *records = NULL;
    size_t record_count = 0;
    err = state_records(state, ctx->arena, &records, &record_count);
    if (err) return err;

    /* Phase 4: The save, then per-profile feedback — the retarget's line names
     * its verb. Each line says what the save made true, so none is said before
     * it: the COMMIT is a write the store can refuse on its own, where a full
     * disk meets the transaction (core/state.h state_commit), and a line above
     * it would stand over the refusal. */
    err = state_save(state);
    if (err) return err;

    output_gap(out, OUTPUT_NORMAL);
    for (size_t i = 0; i < to_enable_validated.count; i++) {
        const char *name = to_enable_validated.entries[i];
        if (retarget && strcmp(name, retarget) == 0) {
            output_success(out, OUTPUT_NORMAL, "Updated target for %s", name);
        } else {
            output_success(out, OUTPUT_NORMAL, "Enabled %s", name);
        }
    }

    /* The next step, where the record owes apply work against the view the save
     * leaves (core/workspace.h workspace_pending) — whatever began it, this enable
     * or a change no apply has followed — and nowhere else: a profile enabled
     * again before an apply let its copies go owes it nothing, and neither does
     * one this machine places nothing of. Whatever the work is, too: the words
     * name apply's aim and no outcome */
    if (workspace_pending(after, records, record_count)) {
        output_gap(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta apply' to bring the workspace in line with the enabled profiles"
        );
    }

    return NULL;
}

/**
 * Profile disable subcommand
 *
 * Four-phase flow, the mirror of profile_enable's:
 *   1. Gather & validate — filter requested profiles to those actually enabled;
 *      emit not-enabled diagnostics up front. Read the bindings the deletes will
 *      forget: the one fact disable destroys that the user cannot recompute,
 *      copied before the deletes replace the row cache they borrow from.
 *   2. Write scope to state — state_disable_profile per validated target;
 *      enabled_profiles is now authoritative for the target set, the line gone
 *      whole, target included. Nothing else is written: what the next apply does
 *      at each path the profile leaves is derivable — the view after holds none
 *      of its claims, and the orphan analysis decides each record left with no
 *      row (core/workspace.c workspace_analyze_orphans).
 *   3. The view after and the record — manifest_build over the post-disable set,
 *      and the record held against it: whether the next apply has work there
 *      (core/workspace.h workspace_pending). A set that will not build is warned
 *      about and the disable lands without the answer.
 *   4. The save, then per-profile feedback — state_save, and only once it lands
 *      the lines that say what it made true: iterate the validated targets to
 *      preserve the existing per-profile UX; a forgotten target is named with
 *      the way back, so `disable --all` then `enable --all` is a copy-paste per
 *      line. Then the next step where apply has work.
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
     * The enabled rows, where the handle holds them, read until Phase 2's first
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
    string_array_init(&to_disable_validated, ctx->arena, 0);

    if (opts->all_profiles) {
        /* --all: every currently enabled profile is, by definition, valid. */
        for (size_t i = 0; i < enabled_profiles.count; i++) {
            string_array_push(&to_disable_validated, enabled_profiles.entries[i].name);
        }
    } else {
        /* Disable the profiles the line names, one at least (profile_post_parse) */
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
     * copies, because Phase 2's first delete replaces the row cache state_target
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

    /* The skip said once: a named profile that was not enabled, by this count,
     * its own line being verbose's */
    if (not_enabled > 0) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "%zu profile%s not enabled",
            not_enabled, not_enabled == 1 ? "" : "s"
        );
    }

    /* Nothing to disable: every profile the line named was not enabled, a success,
     * as --all over an empty set is above, the transaction state_open began rolling
     * back at state_free */
    if (to_disable_validated.count == 0) return NULL;

    /* Dry-run: preview what a live run would do, skip every state mutation. It
     * changes the enabled set nowhere, so it leaves apply nothing to do, and
     * names no next step. */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "Would disable %zu profile%s:",
            to_disable_validated.count, to_disable_validated.count == 1 ? "" : "s"
        );
        for (size_t i = 0; i < to_disable_validated.count; i++) {
            output_print(out, OUTPUT_NORMAL, "  - %s", to_disable_validated.entries[i]);
            if (forgotten[i]) {
                output_print(out, OUTPUT_NORMAL, " (forgets target %s)", forgotten[i]);
            }
            output_endline(out, OUTPUT_NORMAL);
        }
        return NULL;
    }

    /* Phase 2: Write scope to state */
    for (size_t i = 0; i < to_disable_validated.count; i++) {
        err = state_disable_profile(state, to_disable_validated.entries[i]);
        if (err) return err;
    }

    /* Phase 3: The view after, and the record held against it (see profile_enable).
     *
     * Unlike enable's, this build gates nothing: the disable is a membership
     * write that needs no view, and it must land whatever the enabled set looks
     * like — it is the way out of a set the loads cannot build (a profile whose
     * metadata.json will not parse, a branch that will not load), and what it
     * leaves can hold another such profile still. The message names the profile;
     * warn with it and disable without the next step. */
    manifest_t *after = NULL;
    state_record_t *records = NULL;
    size_t record_count = 0;
    err = manifest_build(repo, state, ctx->arena, &after);
    if (err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
    } else {
        err = state_records(state, ctx->arena, &records, &record_count);
        if (err) return err;
    }

    /* Phase 4: The save, then per-profile feedback — each line said once the
     * save made it true, as enable's are. The target the row carried went with
     * it; the line says so and names the command that puts it back. */
    err = state_save(state);
    if (err) return err;

    output_gap(out, OUTPUT_NORMAL);
    for (size_t i = 0; i < to_disable_validated.count; i++) {
        const char *name = to_disable_validated.entries[i];
        output_success(out, OUTPUT_NORMAL, "Disabled %s", name);
        if (forgotten[i]) {
            output_print(
                out, OUTPUT_NORMAL,
                "  Forgot target %s (dotta profile enable %s --target %s "
                "restores it)\n", forgotten[i], name, forgotten[i]
            );
        }
    }

    /* The next step, where the record owes apply work against the view the save
     * leaves (core/workspace.h workspace_pending), as enable's and in its words
     * — none where nothing this machine recorded leaves with the profile, nor
     * where no view after was built to ask */
    if (after && workspace_pending(after, records, record_count)) {
        output_gap(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta apply' to bring the workspace in line with the enabled profiles"
        );
    }

    return NULL;
}

/**
 * Profile reorder subcommand
 *
 * Rewrites this machine's order, which is the precedence: the user names every
 * enabled profile once, in the order wanted. The line names each once, one at
 * least (profile_reorder_post_parse); two checks of the state's make the list
 * the enabled set permuted — every name enabled, the counts equal — and the state's
 * own boundary refuses the same (state_reorder_profiles).
 */
static error_t profile_reorder(
    const dotta_ctx_t *ctx,
    const cmd_profile_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    /* The enabled rows, where the handle holds them, read up to the rewrite below,
     * which replaces them (core/state.h state_profiles) */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* Edge case: no enabled profiles */
    if (enabled_profiles.count == 0) {
        return error_create(ERR_VALIDATION, "No enabled profiles to reorder");
    }

    /* Validation 1: All provided profiles must be currently enabled */
    for (size_t i = 0; i < opts->profile_count; i++) {
        if (!state_enabled(state, opts->profiles[i])) {
            return error_create(
                ERR_VALIDATION, "Profile '%s' is not enabled", opts->profiles[i]
            );
        }
    }

    /* Validation 2: Profile count must match. With no name twice — the line's
     * own (profile_reorder_post_parse) — and every name enabled, equal counts
     * make the named set the enabled set: nothing is left to check for. */
    if (opts->profile_count != enabled_profiles.count) {
        return error_create(
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
    string_array_init(&order, ctx->arena, opts->profile_count);
    for (size_t i = 0; i < opts->profile_count; i++) {
        string_array_push(&order, opts->profiles[i]);
    }
    error_t err = state_reorder_profiles(state, &order);
    if (err) return err;

    /* Nothing else to write: the view is computed from the enabled set at every
     * load, so the new precedence is simply what the next status, diff or apply
     * reads. */

    /* Save state (releases lock automatically) */
    err = state_save(state);
    if (err) return err;

    /* Success message */
    output_gap(out, OUTPUT_NORMAL);
    output_success(
        out, OUTPUT_NORMAL, "Reordered %zu profile%s",
        opts->profile_count, opts->profile_count == 1 ? "" : "s"
    );

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

/**
 * The selection fetch, enable and disable share: the profiles the line names,
 * or --all for every one, and exactly one of the two. clone_post_parse refuses
 * the same pair for clone's -p, and bootstrap_post_parse for bootstrap's, where
 * naming none has a meaning of its own.
 */
static error_t profile_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_profile_options_t *o = opts_v;

    if (o->all_profiles && o->profile_count > 0) {
        return error_create(ERR_INVALID_ARG, "--all and profile names are mutually exclusive");
    }
    return o->all_profiles || o->profile_count > 0
        ? NULL : error_create(ERR_INVALID_ARG, "No profiles specified");
}

/* --- list --- */

static void profile_list_defaults(void *o) {
    ((cmd_profile_options_t *) o)->subcommand = PROFILE_LIST;
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
        "all",                  cmd_profile_options_t,  all_profiles,
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
    .usage         =
        "%s profile fetch [-v] <name>...\n"
        "   or: %s profile fetch [-v] --all",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_fetch_opts,
    .init_defaults = profile_fetch_defaults,
    .post_parse    = profile_post_parse,
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

/**
 * Enable's selection (profile_post_parse), and a target that binds one profile:
 * the one the line names — --all names none, and two names are two profiles.
 */
static error_t profile_enable_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    const cmd_profile_options_t *o = opts_v;

    error_t err = profile_post_parse(opts_v, arena, cmd);
    if (err) return err;

    return o->target && o->profile_count != 1
        ? error_create(ERR_INVALID_ARG, "--target binds exactly one named profile")
        : NULL;
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
    .usage         =
        "%s profile enable [options] <name>...\n"
        "   or: %s profile enable [options] --all",
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
    .post_parse    = profile_enable_post_parse,
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
    .summary       = "Disable profiles; next apply prunes unchanged copies",
    .usage         =
        "%s profile disable [options] <name>...\n"
        "   or: %s profile disable [options] --all",
    .description   =
        "Disables one or more profiles; the next 'dotta apply' prunes the\n"
        "unchanged copies they deployed. A disabled profile's target goes with\n"
        "its row — nothing remembers it — and the receipt names the target it\n"
        "forgets with the command that restores it.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_disable_opts,
    .init_defaults = profile_disable_defaults,
    .post_parse    = profile_post_parse,
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

/**
 * A reorder names every enabled profile once, in its new order. The names are
 * the line's to check — one at least, none twice; whether they are the enabled
 * set is the handler's, which reads the state.
 */
static error_t profile_reorder_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_profile_options_t *o = opts_v;

    if (o->profile_count == 0) {
        return error_create(
            ERR_INVALID_ARG,
            "No profiles specified; a reorder names every enabled profile, in its "
            "new order"
        );
    }
    for (size_t i = 0; i < o->profile_count; i++) {
        for (size_t j = i + 1; j < o->profile_count; j++) {
            if (strcmp(o->profiles[i], o->profiles[j]) == 0) {
                return error_create(
                    ERR_INVALID_ARG,
                    "Profile '%s' appears multiple times in reorder list",
                    o->profiles[i]
                );
            }
        }
    }
    return NULL;
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
    .usage         = "%s profile reorder [options] <name>...",
    .description   =
        "Provide every enabled profile in the desired order. Later profiles\n"
        "override earlier ones during layering.\n",
    .opts_size     = sizeof(cmd_profile_options_t),
    .opts          = profile_reorder_opts,
    .init_defaults = profile_reorder_defaults,
    .post_parse    = profile_reorder_post_parse,
    .complete      = profile_reorder_complete,
    .payload       = &(const dotta_needs_t){
        .repo      = DOTTA_REPO_OPEN,
        .state     = DOTTA_STATE_WRITE,
    },
    .dispatch      = profile_dispatch,
};

/* --- parent: subcommand index + spec --- */

/* Every verb but `list` — `dotta list` is the list command — also stands at the
 * root: `dotta enable work` for `dotta profile enable work`. */
static const args_subcommand_t profile_subs[] = {
    /* aliases    spec                  hidden shortcut */
    { "list",    &spec_profile_list,    false, false },
    { "fetch",   &spec_profile_fetch,   false, true  },
    { "enable",  &spec_profile_enable,  false, true  },
    { "disable", &spec_profile_disable, false, true  },
    { "reorder", &spec_profile_reorder, false, true  },
    { NULL,      NULL,                  false, false }
};

const args_command_t spec_profile = {
    .name               = "profile",
    .summary            = "Profile management and layering",
    .usage              = "%s profile <subcommand> [options]",
    .description        =
        "Enabling a profile is a persistent choice that marks it for deployment.\n"
        "Run 'dotta apply' to bring the workspace in line with the enabled profiles.\n",
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
        "  %s profile reorder global darwin   # Change layering priority\n",
    .opts_size          = sizeof(cmd_profile_options_t),
    .subcommands        = profile_subs,
    .default_subcommand = &spec_profile_list,
};
