/**
 * interactive.c - Interactive TUI implementation
 *
 * Inline interface for profile management and ordering.
 */

#include "cmds/interactive.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/terminal.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"

/**
 * Inline prompt state for the target-capture overlay.
 *
 * Active for the duration the user is typing a deployment path; the
 * cursor row is rendered as a one-line text field and key handling
 * shifts to byte-insertion mode. The buffer is allocated once at
 * interactive_state_create time (initial cap 256) and reused across
 * multiple prompt cycles via prompt_close, which resets len/active
 * but keeps the allocation. Growth is geometric on overflow.
 */
typedef struct {
    bool active;             /* True while the prompt is open */
    size_t item_index;       /* Row anchor (state->items index) */
    char *buffer;            /* Heap-grown, NUL-terminated; freed in free */
    size_t len;              /* Bytes in buffer, excluding NUL */
    size_t cap;              /* Allocated capacity */
} prompt_t;

/**
 * Interactive UI state
 */
struct interactive_state {
    git_repository *repo;    /* Repository (borrowed) */
    profile_item_t *items;   /* Profile items */
    size_t item_count;       /* Number of items */
    size_t cursor;           /* Current cursor position */
    bool modified;           /* True if there are unsaved changes */
    prompt_t prompt;         /* Target-capture overlay */
};

/* Profile Item Utilities */

void profile_item_free(profile_item_t *item) {
    if (!item) {
        return;
    }
    free(item->name);
    free(item);
}

static void free_profile_items(profile_item_t *items, size_t count) {
    if (!items) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(items[i].name);
        free(items[i].target);
    }
    free(items);
}

/* State Management */

error_t *interactive_state_create(
    git_repository *repo,
    state_t *deploy_state,
    interactive_state_t **out
) {
    if (!repo || !deploy_state || !out) {
        return error_create(ERR_INVALID_ARG, "repo, deploy_state and out cannot be NULL");
    }

    error_t *err = NULL;
    interactive_state_t *state = NULL;
    string_array_t *all_profiles = NULL;
    string_array_t *state_profiles = NULL;
    hashmap_t *profile_map = NULL;
    bool *used = NULL;
    size_t item_idx = 0;  /* Track number of items allocated for cleanup */

    /* Allocate state */
    state = calloc(1, sizeof(interactive_state_t));
    if (!state) {
        err = error_create(ERR_MEMORY, "failed to allocate interactive state");
        goto cleanup;
    }

    state->repo = repo;
    state->cursor = 0;
    state->modified = false;

    /* Load all available profiles */
    err = profile_list_all_local(repo, &all_profiles);
    if (err) {
        goto cleanup;
    }

    if (all_profiles->count == 0) {
        err = error_create(ERR_NOT_FOUND, "no profiles found in repository");
        goto cleanup;
    }

    /* Read current enabled profiles from the borrowed state handle. A
     * missing DB resolves to a handle with no underlying connection
     * under spec-driven READ; state_get_profiles returns an empty list
     * in that case — never an error for first-run. Saving via 'w'
     * triggers lazy DB creation in state_begin (see interactive_save_
     * profile_order below). */
    err = state_get_profiles(deploy_state, &state_profiles);
    if (err) {
        error_free(err);
        err = NULL;
        state_profiles = NULL;
    }

    /* Build hashmap for O(1) profile lookups: name -> (index + 1) in all_profiles
     * We store (i + 1) instead of i because NULL (0) means "not found" */
    profile_map = hashmap_borrow(0);
    if (!profile_map) {
        err = error_create(ERR_MEMORY, "failed to create profile hashmap");
        goto cleanup;
    }

    for (size_t i = 0; i < all_profiles->count; i++) {
        /* Store (index + 1) to avoid NULL for index 0 */
        err = hashmap_set(
            profile_map,
            all_profiles->items[i],
            (void *) (uintptr_t) (i + 1)
        );
        if (err) goto cleanup;
    }

    /* Allocate tracking array to mark used profiles */
    used = calloc(all_profiles->count, sizeof(bool));
    if (!used) {
        err = error_create(ERR_MEMORY, "failed to allocate tracking array");
        goto cleanup;
    }

    /* Allocate items array (max size = all_profiles->count) */
    state->items = calloc(all_profiles->count, sizeof(profile_item_t));
    if (!state->items) {
        err = error_create(ERR_MEMORY, "failed to allocate profile items");
        goto cleanup;
    }

    /* First: Add profiles from state in their saved order (enabled) */
    if (state_profiles) {
        for (size_t i = 0; i < state_profiles->count; i++) {
            const char *profile = state_profiles->items[i];

            /* O(1) lookup to verify profile still exists */
            void *idx_ptr = hashmap_get(profile_map, profile);
            if (!idx_ptr) {
                /* Profile in state but doesn't exist locally anymore - skip */
                continue;
            }

            /* Subtract 1 to get actual index (we stored i + 1) */
            size_t profile_idx = (size_t) (uintptr_t) idx_ptr - 1;
            used[profile_idx] = true;

            /* Add to items */
            state->items[item_idx].name = strdup(profile);
            if (!state->items[item_idx].name) {
                err = error_create(ERR_MEMORY, "failed to duplicate profile name");
                goto cleanup;
            }

            state->items[item_idx].enabled = true;
            state->items[item_idx].exists_locally = true;
            item_idx++;
        }
    }

    /* Second: Add remaining profiles not in state (disabled, at bottom) */
    for (size_t i = 0; i < all_profiles->count; i++) {
        /* O(1) check if already added */
        if (used[i]) continue;

        /* Add to items */
        state->items[item_idx].name = strdup(all_profiles->items[i]);
        if (!state->items[item_idx].name) {
            err = error_create(ERR_MEMORY, "failed to duplicate profile name");
            goto cleanup;
        }

        state->items[item_idx].enabled = false;
        state->items[item_idx].exists_locally = true;
        item_idx++;
    }

    state->item_count = item_idx;

    /* Pass 2 — eagerly seed per-item Git/state facts.
     *
     * Computing has_custom up front turns "does this profile need a
     * deployment target?" into a constant-time field lookup at toggle
     * time. Probing lazily would force a Git tree load while the
     * terminal is in raw mode — visible latency on the first space
     * press for a custom-bearing profile. Eager wins on determinism.
     *
     * Failure is loud: a profile whose tree we cannot read is a
     * profile whose enableability we cannot answer; silently
     * defaulting to has_custom = false would push the trap one layer
     * downstream (the manifest tripwire). Abort startup instead. */
    for (size_t i = 0; i < state->item_count; i++) {
        err = profile_has_custom_files(
            repo, state->items[i].name, &state->items[i].has_custom
        );
        if (err) {
            err = error_wrap(
                err, "Failed to inspect profile '%s' for custom files",
                state->items[i].name
            );
            goto cleanup;
        }

        /* Seed target for already-enabled profiles. state_peek_profile_target
         * returns a borrowed pointer into the row cache whose lifetime is
         * bounded by the next enabled-set mutation (state_enable_profile /
         * state_disable_profile / state_reorder_profiles). The save path
         * runs those calls long after this seeding completes, so we copy
         * across the lifetime boundary now and free the strdup with the item. */
        if (state->items[i].enabled) {
            const char *t = state_peek_profile_target(
                deploy_state, state->items[i].name
            );
            if (t) {
                state->items[i].target = strdup(t);
                if (!state->items[i].target) {
                    err = error_create(
                        ERR_MEMORY,
                        "failed to duplicate target for profile '%s'",
                        state->items[i].name
                    );
                    goto cleanup;
                }
            }
        }
    }

    /* Pre-allocate the prompt buffer at create time. Two reasons:
     *   1. The keystroke handler stays alloc-failure-free for the common
     *      typing path; an OOM during typing is recoverable in-session
     *      (we silently drop bytes) rather than propagating up.
     *   2. 256 bytes covers typical absolute paths without growth; the
     *      geometric realloc in prompt_buffer_push handles the long-path
     *      edge case. */
    state->prompt.cap = 256;
    state->prompt.buffer = calloc(state->prompt.cap, sizeof(char));
    if (!state->prompt.buffer) {
        state->prompt.cap = 0;
        err = error_create(ERR_MEMORY, "failed to allocate prompt buffer");
        goto cleanup;
    }

    /* Success - cleanup temporary resources and return.
     * deploy_state is borrowed from the caller; do not free it. */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    string_array_free(all_profiles);
    hashmap_free(profile_map, NULL);
    free(used);

    *out = state;
    return NULL;

cleanup:
    /* Error path - free all resources.
     * deploy_state is borrowed from the caller; do not free it. */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    string_array_free(all_profiles);
    hashmap_free(profile_map, NULL);
    free(used);
    if (state) {
        if (state->items) {
            /* Pass 2 may have allocated targets on items below item_idx,
             * so free_profile_items walks the full populated range and
             * releases name + target alike (free(NULL) is safe for
             * items that never reached pass 2). */
            free_profile_items(state->items, item_idx);
        }
        free(state->prompt.buffer);
        free(state);
    }
    return err;
}

void interactive_state_free(interactive_state_t *state) {
    if (!state) {
        return;
    }

    free_profile_items(state->items, state->item_count);
    free(state->prompt.buffer);
    free(state);
}

void interactive_state_get_items(
    const interactive_state_t *state,
    const profile_item_t **out_items,
    size_t *out_count
) {
    if (!state || !out_items || !out_count) {
        return;
    }

    *out_items = state->items;
    *out_count = state->item_count;
}

size_t interactive_state_get_cursor(const interactive_state_t *state) {
    return state ? state->cursor : 0;
}

/* Profile Reordering */

/**
 * Swap two profile items
 */
static void swap_profile_items(profile_item_t *items, size_t i, size_t j) {
    profile_item_t temp = items[i];
    items[i] = items[j];
    items[j] = temp;
}

/**
 * Move current profile up in list
 */
static void interactive_move_profile_up(interactive_state_t *state) {
    if (!state || state->cursor == 0) {
        return;
    }

    swap_profile_items(state->items, state->cursor, state->cursor - 1);
    state->cursor--;
    state->modified = true;
}

/**
 * Move current profile down in list
 */
static void interactive_move_profile_down(interactive_state_t *state) {
    if (!state || state->cursor >= state->item_count - 1) {
        return;
    }

    swap_profile_items(state->items, state->cursor, state->cursor + 1);
    state->cursor++;
    state->modified = true;
}

/**
 * Save current profile management and order to state
 *
 * Diff-validate-mutate-reorder. The TUI accepts arbitrary toggle and move
 * operations in memory; on 'w' this function reconciles the in-memory set
 * against the persisted set in three phases:
 *
 *   1. Diff. Build new_order alongside a parallel array of profile_item_t
 *      pointers so each save-time row can be traced back to its in-memory
 *      origin (for the user-supplied target). Snapshot persisted
 *      enabled_profiles, classify each name in the new order as
 *      addition-or-reorder, and stash removed names in arena-owned
 *      scratch (the row-cache borrows die at the first state_enable /
 *      state_disable call).
 *   2. Validate. Every addition's captured target (set via the inline
 *      prompt during the session or seeded from a prior CLI enable) is
 *      checked at the boundary via mount_validate_target — the same
 *      validator `cmd profile enable` uses. Additions without a target
 *      are permitted: legitimate for non-custom profiles, and for
 *      custom profiles the prompt is the source-of-truth gate. If a
 *      bug ever breaches that gate, manifest_apply_scope's UNBOUND
 *      tripwire fires loud one layer downstream — no double guard
 *      lives here.
 *   3. Mutate. Apply additions (state_enable_profile + persist_head),
 *      then removals (state_disable_profile), then reorder. Finally
 *      rebuild the mount table and apply_scope reconciles
 *      virtual_manifest + tracked_directories.
 *
 * Takes a scoped write transaction on the borrowed READ handle —
 * declaring WRITE at the spec level would hold BEGIN IMMEDIATE for the
 * whole TUI session, blocking other dotta processes on the write lock
 * while the user interacts.
 */
static error_t *interactive_save_profile_order(
    git_repository *repo,
    state_t *deploy_state,
    arena_t *arena,
    interactive_state_t *state
) {
    if (!state || !repo || !deploy_state || !arena) {
        return error_create(ERR_INVALID_ARG, "invalid arguments");
    }

    /* Allocate the parallel item-pointer scratch up front. Sized by the
     * upper bound (item_count); the loop below fills only the enabled
     * slots, so new_order.count == k (the fill count) on exit. Arena-
     * owned for this function's lifetime; no leak on early return. */
    profile_item_t **new_order_items = NULL;
    if (state->item_count > 0) {
        new_order_items = arena_calloc(
            arena, state->item_count, sizeof(*new_order_items)
        );
        if (!new_order_items) {
            return ERROR(ERR_MEMORY, "Failed to allocate item pointer scratch");
        }
    }

    /* Extract the new ordered name list AND the parallel item pointers
     * in a single sweep. Strings are borrowed from state->items[i].name,
     * which outlives this call — interactive_state owns them (along
     * with .target) for the whole TUI session. The two arrays describe
     * the same row from two angles, indexed identically. */
    string_array_t new_order STRING_ARRAY_AUTO = { 0 };
    size_t k = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (!state->items[i].enabled) continue;
        error_t *push_err = string_array_push(&new_order, state->items[i].name);
        if (push_err) return push_err;
        new_order_items[k++] = &state->items[i];
    }

    /* Refuse a save that would empty enabled_profiles. The user can
     * re-enable at least one profile in the TUI and try again.
     * (Inline-error UX is out of scope — the wrapping dispatcher exits
     * the TUI with the error.) Checked here — after the array is built
     * — instead of via a cached counter on interactive_state. The items
     * array is the single source of truth for "is this enabled?"; a
     * sibling counter is a cache of a cache. */
    if (new_order.count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles enabled");
    }

    /* Promote the borrowed READ handle to a write transaction for the
     * duration of this save. state_rollback on any error path is
     * idempotent. */
    error_t *err = state_begin(deploy_state);
    if (err) return err;

    /* Phase 1 — diff against the persisted set BEFORE any mutation.
     *
     * state_peek_profiles returns borrowed pointers into the row cache.
     * The first state_enable_profile / state_disable_profile call below
     * invalidates the cache and free()s the underlying name/target
     * strings, so `persisted` is dangling after that point. Capture
     * everything we need from the borrows in this scope and stash it
     * in arena-owned scratch before any mutation runs. */
    const state_profile_entry_t *persisted = NULL;
    size_t persisted_count = 0;
    err = state_peek_profiles(deploy_state, &persisted, &persisted_count);
    if (err) goto rollback;

    /* per-new_order flag: true iff the name is an addition (not currently
     * enabled). Allocated even at count=0 to keep the deref site uniform;
     * the loop body never runs at count=0 so the pointer stays unused. */
    bool *is_addition = NULL;
    if (new_order.count > 0) {
        is_addition = arena_calloc(arena, new_order.count, sizeof(*is_addition));
        if (!is_addition) {
            err = ERROR(ERR_MEMORY, "Failed to allocate addition flags");
            goto rollback;
        }
    }

    /* Persisted names not in new_order; arena-strdup'd so the string
     * survives cache invalidation by the first enable/disable call. */
    char **removal_names = NULL;
    size_t removal_count = 0;
    if (persisted_count > 0) {
        removal_names = arena_calloc(arena, persisted_count, sizeof(*removal_names));
        if (!removal_names) {
            err = ERROR(ERR_MEMORY, "Failed to allocate removal scratch");
            goto rollback;
        }
    }

    /* Walk persisted; classify each as retained or removed. Sets are
     * tiny in practice (typically < 10 profiles), so a nested linear
     * scan beats a hashmap on both clarity and cycles. */
    for (size_t i = 0; i < persisted_count; i++) {
        const char *p_name = persisted[i].name;
        bool retained = false;
        for (size_t j = 0; j < new_order.count; j++) {
            if (strcmp(new_order.items[j], p_name) == 0) {
                retained = true;
                break;
            }
        }
        if (!retained) {
            char *name_dup = arena_strdup(arena, p_name);
            if (!name_dup) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate removal name");
                goto rollback;
            }
            removal_names[removal_count++] = name_dup;
        }
    }

    /* Walk new_order; classify each as addition or reorder-only. */
    for (size_t i = 0; i < new_order.count; i++) {
        bool was_enabled = false;
        for (size_t j = 0; j < persisted_count; j++) {
            if (strcmp(persisted[j].name, new_order.items[i]) == 0) {
                was_enabled = true;
                break;
            }
        }
        is_addition[i] = !was_enabled;
    }

    /* Borrowed cache no longer needed; drop the reference so a stray
     * post-mutation use is a NULL-deref at the test boundary instead of
     * a quiet use-after-invalidate. */
    persisted = NULL;
    persisted_count = 0;

    /* Phase 2 — validate user-supplied targets at the boundary.
     *
     * The inline prompt is the source-of-truth gate: a custom-bearing
     * profile cannot leave the TUI as an addition without a captured
     * target. Trust the gate. The remaining job is to confirm the
     * string the user typed is a real absolute path — the same check
     * `cmd profile enable` performs at its own boundary. Wrapping the
     * validator here keeps the error topology uniform across entry
     * points (CLI, TUI) so the same input failure produces the same
     * diagnostic.
     *
     * An addition with target == NULL is legitimate when has_custom is
     * false (no target needed). When has_custom is true, the gate is
     * supposed to have prevented this — but we deliberately do NOT add
     * a second guard layer here. A bug that lets a custom-bearing row
     * through with no target writes NULL into enabled_profiles.target,
     * and manifest_apply_scope's UNBOUND tripwire (ERR_STATE_INVALID)
     * fires downstream with the repair hint. Two layers of defense
     * against the same fault is one too many. */
    for (size_t i = 0; i < new_order.count; i++) {
        if (!is_addition[i]) continue;
        profile_item_t *it = new_order_items[i];

        if (!it->target) continue;

        err = mount_validate_target(it->target);
        if (err) {
            err = error_wrap(
                err, "Invalid deployment target for profile '%s'",
                it->name
            );
            goto rollback;
        }
    }

    /* Phase 3 — apply diff, then reorder.
     *
     * Additions first so the row cache holds every reorder name when
     * state_reorder_profiles fires; removals next; the reorder runs last over
     * the post-diff set. Each state_enable_profile / state_disable_profile
     * call invalidates the cache, but state_reorder_profiles reloads it on
     * entry, so the precondition (every name in cache) holds.
     *
     * The user-supplied target rides through state_enable_profile's
     * UPSERT path; it->target may be NULL (no custom files, or a seeded
     * row whose CLI-bound target is being preserved through a same-
     * session disable/enable cycle is moot here because that row would
     * be reorder-only, not an addition). */
    for (size_t i = 0; i < new_order.count; i++) {
        if (!is_addition[i]) continue;
        profile_item_t *it = new_order_items[i];

        err = state_enable_profile(deploy_state, it->name, it->target);
        if (err) {
            err = error_wrap(err, "Failed to enable profile '%s'", it->name);
            goto rollback;
        }

        /* Replace the zero-OID sentinel state_enable_profile writes with
         * the real branch HEAD so enabled_profiles is fully authoritative
         * before apply_scope runs. */
        err = manifest_persist_profile_head(repo, deploy_state, it->name);
        if (err) {
            err = error_wrap(
                err, "Failed to persist HEAD for profile '%s'", it->name
            );
            goto rollback;
        }
    }

    for (size_t i = 0; i < removal_count; i++) {
        err = state_disable_profile(deploy_state, removal_names[i]);
        if (err) {
            err = error_wrap(
                err, "Failed to disable profile '%s'", removal_names[i]
            );
            goto rollback;
        }
    }

    err = state_reorder_profiles(deploy_state, &new_order);
    if (err) {
        err = error_wrap(err, "Failed to apply new profile order");
        goto rollback;
    }

    /* Build a fresh mount table reflecting the post-mutation binding set.
     * State mutations above invalidated any prior mount table's borrows
     * from the row cache, and the diff may have added or removed
     * custom-target bindings. */
    mount_table_t *post_mutation_mounts = NULL;
    err = profile_build_mount_table(deploy_state, arena, &post_mutation_mounts);
    if (err) {
        err = error_wrap(err, "Failed to rebuild mount table after profile diff");
        goto rollback;
    }

    err = manifest_apply_scope(
        repo, deploy_state, arena, post_mutation_mounts, NULL, NULL
    );
    if (err) {
        err = error_wrap(err, "Failed to reconcile manifest with new scope");
        goto rollback;
    }

    /* Commit transaction */
    err = state_commit(deploy_state);
    if (err) goto rollback;

    /* Update interactive state on success */
    state->modified = false;
    return NULL;

rollback:
    state_rollback(deploy_state);
    return err;
}

/* UI Rendering */

int interactive_get_required_lines(const interactive_state_t *state) {
    if (!state) {
        return 0;
    }

    /* Header + blank + profiles + blank + footer */
    return 1 + 1 + (int) state->item_count + 1 + 1;
}

/**
 * Render a single row.
 *
 * Three shapes:
 *   1. Prompt-active row: cursor + "Target: <buffer>_" overlay. The
 *      trailing '_' is the visible caret — the hardware cursor stays
 *      hidden across the whole session (no per-redraw repositioning).
 *   2. Enabled with custom + captured target: cursor + checkbox + name
 *      + dim "→ <target>" annotation.
 *   3. Disabled with custom (no target yet): cursor + space + dim name
 *      + dim "(custom)" hint, signaling that toggling will require a
 *      path.
 *
 * Line count is the same across all shapes — the prompt overlay
 * replaces the cursor row's content but not its existence, so
 * interactive_get_required_lines stays correct and interactive_run's
 * cursor-up math is unchanged.
 *
 * The optional annotation emits via its own fprintf rather than
 * composing into a stack buffer; stdout is line-buffered with a
 * single fflush at the end of interactive_render, so the extra calls
 * do not flicker and they sidestep the "how big must the buffer be"
 * question for unbounded target strings.
 */
static void render_row(const interactive_state_t *state, size_t i) {
    const profile_item_t *it = &state->items[i];
    bool is_cursor = (i == state->cursor);
    bool is_prompt = (state->prompt.active && i == state->prompt.item_index);

    fprintf(stdout, "\r" ANSI_CLEAR_LINE);

    const char *cursor_glyph = is_cursor ? "\033[1;36m▶\033[0m" : " ";

    if (is_prompt) {
        /* Replace the checkbox + name area with the input field.
         * Column alignment: "  " (2) + cursor (1) + "   " (3 spaces in
         * place of " " + checkbox + " ") = 6 visible chars of prefix,
         * matching the regular row prefix so "Target:" starts at the
         * same column as a profile name would. */
        fprintf(
            stdout, "  %s   \033[1mTarget:\033[0m %s_\r\n",
            cursor_glyph, state->prompt.buffer
        );
        return;
    }

    const char *checkbox = it->enabled ? "\033[1;32m✓\033[0m" : " ";
    const char *name_open = (it->enabled || is_cursor) ? "" : "\033[2m";
    const char *name_close = (it->enabled || is_cursor) ? "" : "\033[0m";

    fprintf(
        stdout, "  %s %s %s%s%s",
        cursor_glyph, checkbox, name_open, it->name, name_close
    );

    if (it->enabled && it->has_custom && it->target) {
        fprintf(stdout, " \033[2m→ %s\033[0m", it->target);
    } else if (!it->enabled && it->has_custom) {
        fprintf(stdout, " \033[2m(custom)\033[0m");
    }

    fprintf(stdout, "\r\n");
}

int interactive_render(const interactive_state_t *state) {
    if (!state) {
        return 0;
    }

    int lines_rendered = 0;

    /* Header */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (state->modified) {
        fprintf(
            stdout,
            "  \033[1mProfiles:\033[0m \033[33m(modified)\033[0m\r\n"
        );
    } else {
        fprintf(
            stdout,
            "  \033[1mProfiles:\033[0m\r\n"
        );
    }
    lines_rendered++;

    /* Blank line */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE "\r\n");
    lines_rendered++;

    /* Profile items */
    for (size_t i = 0; i < state->item_count; i++) {
        render_row(state, i);
        lines_rendered++;
    }

    /* Blank line */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE "\r\n");
    lines_rendered++;

    /* Footer / keybinding help - adapt to current mode */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (state->prompt.active) {
        /* Prompt mode: a tighter key set is in effect */
        fprintf(
            stdout, "\033[2menter\033[0m confirm  "
            "\033[2mesc\033[0m cancel  "
            "\033[2mbackspace\033[0m delete"
        );
    } else if (state->modified) {
        /* Modified mode keys with save highlighted */
        fprintf(
            stdout, "\033[2m↑↓\033[0m navigate  "
            "\033[2mspace\033[0m toggle  "
            "\033[2mJ/K\033[0m move  "
            "\033[1;33mw\033[0m \033[1;33msave\033[0m  "
            "\033[2mq\033[0m quit"
        );
    } else {
        /* Normal mode keys */
        fprintf(
            stdout, "\033[2m↑↓\033[0m navigate  "
            "\033[2mspace\033[0m toggle  "
            "\033[2mJ/K\033[0m move  "
            "\033[2mq\033[0m quit"
        );
    }
    lines_rendered++;

    /* Single flush at end instead of after every line */
    fflush(stdout);

    return lines_rendered;
}

/* Input Handling */

/**
 * Reset the prompt back to its dormant shape.
 *
 * Keeps the buffer allocation around so successive prompts reuse it —
 * the typical typing path stays alloc-free after the first cycle.
 */
static void prompt_close(prompt_t *p) {
    p->active = false;
    p->item_index = 0;
    p->len = 0;
    if (p->buffer && p->cap > 0) {
        p->buffer[0] = '\0';
    }
}

/**
 * Append one byte to the prompt buffer; grow geometrically on overflow.
 *
 * The buffer always carries a NUL terminator one past `len`, so the
 * trigger condition `len + 1 >= cap` reserves room for the new byte
 * (at index len) plus its NUL (at index len + 1). On OOM the buffer
 * is left untouched and the caller (the keystroke handler) drops the
 * byte silently — the user can retry or Esc.
 *
 * @return 0 on success, -1 on allocation failure
 */
static int prompt_buffer_push(prompt_t *p, char c) {
    if (p->len + 1 >= p->cap) {
        size_t new_cap = p->cap ? p->cap * 2 : 256;
        char *new_buf = realloc(p->buffer, new_cap);
        if (!new_buf) {
            return -1;
        }
        p->buffer = new_buf;
        p->cap = new_cap;
    }
    p->buffer[p->len++] = c;
    p->buffer[p->len] = '\0';
    return 0;
}

/**
 * Key dispatch while the inline target prompt is active.
 *
 * Mode shadowing is the entire point: every navigation key (j/k/g/G/J/K),
 * the save key (w), and the quit key (q) lose their TUI meaning while
 * `prompt.active` is set, because they are valid bytes in a path. The
 * prompt branch only responds to Enter (commit), Esc / Ctrl-C / Ctrl-D
 * (cancel), Backspace (delete-last), and printable bytes (insert).
 * Everything else — Tab, arrows, Home, End, Delete, Page-Up/Down — is
 * a no-op.
 *
 * No error path: the prompt's effects (buffer mutation, item.target
 * commit) are in-memory and recoverable. OOM during typing drops the
 * byte; OOM at commit time keeps the prompt open so the user retries.
 */
static interactive_result_t handle_key_prompt(
    interactive_state_t *state, int key
) {
    prompt_t *p = &state->prompt;

    switch (key) {
        case TERM_KEY_ENTER: {
            if (p->len == 0) {
                /* Empty Enter is a no-op; only Esc closes without a value. */
                return INTERACTIVE_CONTINUE;
            }
            char *captured = strdup(p->buffer);
            if (!captured) {
                /* Recoverable: keep the prompt open, let the user retry. */
                return INTERACTIVE_CONTINUE;
            }
            profile_item_t *it = &state->items[p->item_index];
            /* it->target is guaranteed NULL by the gate that opened the
             * prompt; the free is defensive scar-tissue insurance. */
            free(it->target);
            it->target = captured;
            it->enabled = true;
            state->modified = true;
            prompt_close(p);
            return INTERACTIVE_CONTINUE;
        }

        case TERM_KEY_ESCAPE:
        case TERM_KEY_CTRL_C:
        case TERM_KEY_CTRL_D:
            /* Cancel: row stays disabled, target stays NULL, modified
             * flag untouched (no edit happened). */
            prompt_close(p);
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_BACKSPACE:
            if (p->len > 0) {
                p->buffer[--p->len] = '\0';
            }
            return INTERACTIVE_CONTINUE;

        default:
            /* Accept any non-control byte. The range covers printable
             * ASCII (0x20..0x7E) and the high-bit band (0x80..0xFF) so
             * UTF-8 byte sequences in paths pass through verbatim. 0x7F
             * (DEL) is excluded defensively — the terminal layer maps
             * both 0x7F and 0x08 to TERM_KEY_BACKSPACE before they
             * reach this default branch, so 0x7F should be unreachable
             * here, but the guard makes the policy explicit. */
            if (key >= 0x20 && key <= 0xFF && key != 0x7F) {
                (void) prompt_buffer_push(p, (char) key);
            }
            return INTERACTIVE_CONTINUE;
    }
}

/**
 * Key dispatch for the normal navigation/reorder mode.
 *
 * This is the prior interactive_handle_key body verbatim, except the
 * space-key branch gains the three-gate prompt trigger and the
 * (former) cached enabled_count update was removed when that field
 * was retired.
 */
static interactive_result_t handle_key_normal(
    interactive_state_t *state,
    git_repository *repo,
    state_t *deploy_state,
    arena_t *arena,
    int key,
    error_t **out_err
) {
    switch (key) {
        /* Navigation */
        case TERM_KEY_UP:
        case 'k':
            if (state->cursor > 0) {
                state->cursor--;
            }
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_DOWN:
        case 'j':
            if (state->cursor < state->item_count - 1) {
                state->cursor++;
            }
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_HOME:
        case 'g':
            state->cursor = 0;
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_END:
        case 'G':
            state->cursor = state->item_count - 1;
            return INTERACTIVE_CONTINUE;

        /* Toggle enabled state — with target-prompt gate. */
        case TERM_KEY_SPACE: {
            if (state->cursor >= state->item_count) {
                return INTERACTIVE_CONTINUE;
            }
            profile_item_t *it = &state->items[state->cursor];
            bool toggling_on = !it->enabled;

            /* Three-gate trigger: prompt opens iff the row has custom/
             * files, the toggle is OFF→ON, and no target has been
             * captured or seeded yet. The user-supplied target survives
             * transient toggle-off / toggle-on cycles within a session,
             * so a re-enable after a same-session disable skips the
             * prompt naturally via the third gate. */
            if (toggling_on && it->has_custom && it->target == NULL) {
                state->prompt.active = true;
                state->prompt.item_index = state->cursor;
                /* Buffer is empty by prompt_close on the previous cycle
                 * (or by interactive_state_create's calloc on the first
                 * cycle). No need to reset here. */
                return INTERACTIVE_CONTINUE;
            }

            /* Every other shape — toggling-off, plain non-custom toggle,
             * or re-enabling with a still-present target — is a direct
             * flip. */
            it->enabled = !it->enabled;
            state->modified = true;
            return INTERACTIVE_CONTINUE;
        }

        /* Reorder - move profile up */
        case 'K':
            interactive_move_profile_up(state);
            return INTERACTIVE_CONTINUE;

        /* Reorder - move profile down */
        case 'J':
            interactive_move_profile_down(state);
            return INTERACTIVE_CONTINUE;

        /* Save changes - silent operation, no terminal restoration needed */
        case 'w':
        case 'W': {
            if (!state->modified) {
                /* Nothing to save */
                return INTERACTIVE_CONTINUE;
            }

            error_t *err = interactive_save_profile_order(
                repo, deploy_state, arena, state
            );
            if (err) {
                /* Exit and return error to caller */
                *out_err = err;
                return INTERACTIVE_EXIT_ERROR;
            }
            return INTERACTIVE_CONTINUE;
        }

        /* Exit */
        case 'q':
        case 'Q':
        case TERM_KEY_ESCAPE:
        case TERM_KEY_CTRL_C:
        case TERM_KEY_CTRL_D:
            return INTERACTIVE_EXIT_OK;

        default:
            /* Unknown key - ignore */
            return INTERACTIVE_CONTINUE;
    }
}

interactive_result_t interactive_handle_key(
    interactive_state_t *state,
    git_repository *repo,
    state_t *deploy_state,
    arena_t *arena,
    int key,
    terminal_t **term_ptr,
    error_t **out_err
) {
    if (!state || !repo || !deploy_state || !arena || !term_ptr || !out_err) {
        return INTERACTIVE_EXIT_ERROR;
    }

    *out_err = NULL;

    /* Mode dispatch. The prompt branch consumes every byte while active
     * — q/w/J/K/j/k/g/G all lose their navigation meaning, by
     * construction (key-set shadowing), not by per-key filtering. */
    if (state->prompt.active) {
        return handle_key_prompt(state, key);
    }
    return handle_key_normal(state, repo, deploy_state, arena, key, out_err);
}

/* Main Entry Point */

error_t *interactive_run(
    git_repository *repo, state_t *deploy_state, arena_t *arena
) {
    if (!repo || !deploy_state || !arena) {
        return error_create(
            ERR_INVALID_ARG, "repo, deploy_state, and arena cannot be NULL"
        );
    }

    /* Check if terminal is a TTY */
    if (!terminal_is_tty()) {
        return error_create(
            ERR_INVALID_ARG, "interactive mode requires a TTY"
        );
    }

    /* Initialize terminal */
    terminal_t *term = NULL;
    error_t *err = terminal_init(&term);
    if (err) {
        return err;
    }

    /* Get terminal size */
    terminal_size_t size;
    err = terminal_get_size(&size);
    if (err) {
        terminal_restore(term);
        return err;
    }

    /* Create interactive state */
    interactive_state_t *state = NULL;
    err = interactive_state_create(repo, deploy_state, &state);
    if (err) {
        terminal_restore(term);
        return err;
    }

    /* Check if we have enough screen space (lines) */
    int required_lines = interactive_get_required_lines(state);
    if (required_lines > size.rows) {
        interactive_state_free(state);
        terminal_restore(term);
        return error_create(
            ERR_INVALID_ARG, "terminal too small (need %d lines, have %d)",
            required_lines, size.rows
        );
    }

    /* Check terminal width to prevent line wrapping.
     *
     * Static row layout:
     *   "  " + cursor + " " + checkbox + " " + name + annotation
     *
     * Prefix is fixed at 6 visible columns ("  " + cursor + " " +
     * checkbox + " "). The annotation column reserves space for the
     * widest static tag — " (custom)" — which is 9 visible columns
     * including its leading separator. The dynamic "→ <target>"
     * annotation can run longer than that, but it is data the user
     * already supplied (or a path realpath-bounded by the save) and
     * its visual overflow is intentionally allowed to wrap rather
     * than block the TUI startup. Mirror the same accounting for the
     * mid-session prompt overlay ("Target: " + buffer): the static
     * gate covers only what we can size up front; the buffer's wrap
     * is documented per design.
     */
    const profile_item_t *items;
    size_t item_count;
    interactive_state_get_items(state, &items, &item_count);

    size_t max_name_len = 0;
    for (size_t i = 0; i < item_count; i++) {
        size_t len = strlen(items[i].name);
        if (len > max_name_len) {
            max_name_len = len;
        }
    }

    const size_t ROW_PREFIX_WIDTH = 6;
    const size_t ROW_ANNOTATION_RESERVE = 9; /* " (custom)" */
    size_t worst_row_width =
        ROW_PREFIX_WIDTH + max_name_len + ROW_ANNOTATION_RESERVE;

    if (worst_row_width > (size_t) size.cols) {
        interactive_state_free(state);
        terminal_restore(term);
        return error_create(
            ERR_INVALID_ARG, "terminal too narrow (longest profile name: "
            "%zu chars, need %zu columns, have %d)",
            max_name_len, worst_row_width, size.cols
        );
    }

    /* Hide cursor */
    terminal_cursor_hide();

    /* Render initial UI inline */
    int lines_drawn = interactive_render(state);

    /* Main loop */
    interactive_result_t result = INTERACTIVE_CONTINUE;
    error_t *loop_err = NULL;
    while (result == INTERACTIVE_CONTINUE) {
        /* Read key */
        int key = terminal_read_key();

        /* Handle key */
        result = interactive_handle_key(
            state, repo, deploy_state, arena, key, &term, &loop_err
        );

        /* Re-render: move cursor up, then redraw */
        if (result == INTERACTIVE_CONTINUE) {
            /* Move up to start of first line
             * We drew N lines, cursor is on line N,
             * need to move up N-1 to get to line 1 */
            if (lines_drawn > 0) {
                terminal_cursor_up(lines_drawn - 1);
            }
            lines_drawn = interactive_render(state);
        }
    }

    /* Cleanup: move cursor past UI */
    fprintf(stdout, "\r\n");
    fflush(stdout);

    /* Show cursor */
    terminal_cursor_show();

    /* Free resources */
    interactive_state_free(state);
    terminal_restore(term);

    /* Return error if one occurred */
    if (result == INTERACTIVE_EXIT_ERROR) {
        if (loop_err) {
            return loop_err;
        }
        return error_create(
            ERR_INTERNAL, "interactive mode exited with error"
        );
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

static error_t *interactive_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    CHECK_NULL(ctx->state);
    (void) opts_v;
    return interactive_run(ctx->repo, ctx->state, ctx->arena);
}

const args_command_t spec_interactive = {
    .name         = "interactive",
    .summary      = "Interactive profile management and ordering",
    /* Root-level flag aliases: `dotta --interactive` and `dotta -i`
     * both dispatch here. The bare `dotta interactive` form is served
     * by `.name`; `.root_aliases` covers only the flag-prefixed forms.
     * Short-first order matches the project convention for `flags`
     * strings (e.g., `"p profile"` → `-p, --profile`). */
    .root_aliases = "i interactive",
    .usage        =
        "%s interactive\n"
        "   or: %s --interactive\n"
        "   or: %s -i",
    .description  =
        "Keybindings:\n"
        "  ↑↓, j/k, g/G    Navigate profiles\n"
        "  space           Enable/disable profiles\n"
        "  J/K             Move profile up/down\n"
        "  w               Save profile order and choice\n"
        "  q, ESC          Quit\n"
        "\n"
        "Notes:\n"
        "  - Enabled profiles are saved to state in the displayed order\n"
        "  - Profile order determines layering (later overrides earlier)\n"
        "  - Use regular commands (apply, update, sync) after enabling profiles\n",
    .payload      = &dotta_ext_read,
    .dispatch     = interactive_dispatch,
};
