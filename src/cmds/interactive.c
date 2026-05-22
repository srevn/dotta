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
 * Interactive UI state
 */
struct interactive_state {
    git_repository *repo;          /* Repository (borrowed) */
    profile_item_t *items;         /* Profile items */
    size_t item_count;             /* Number of items */
    size_t enabled_count;          /* Number of enabled items (cached) */
    size_t cursor;                 /* Current cursor position */
    bool modified;                 /* True if there are unsaved changes */
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

    /* Count enabled items (all from state_profiles) */
    state->enabled_count = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].enabled) {
            state->enabled_count++;
        }
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
            /* Free any profile names that were allocated */
            free_profile_items(state->items, item_idx);
        }
        free(state);
    }
    return err;
}

void interactive_state_free(interactive_state_t *state) {
    if (!state) {
        return;
    }

    free_profile_items(state->items, state->item_count);
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
 *   1. Diff. Snapshot persisted enabled_profiles, classify each name in
 *      the new order as addition-or-reorder, and stash removed names in
 *      arena-owned scratch (the row-cache borrows die at the first
 *      state_enable/disable call).
 *   2. Validate. Every addition is checked for custom/ files — the TUI
 *      has no UI for collecting a --target, so a custom-bearing profile
 *      cannot be enabled here. The check runs before any DB mutation,
 *      so a blocked save leaves enabled_profiles untouched.
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

    /* Refuse a save that would empty enabled_profiles. The user can
     * re-enable at least one profile in the TUI and try again.
     * (Inline-error UX is out of scope — the wrapping dispatcher exits
     * the TUI with the error.) */
    if (state->enabled_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles enabled");
    }

    /* Extract the new ordered name list from the TUI items. Strings are
     * borrowed from state->items[i].name, which outlives this call —
     * interactive_state owns them for the whole TUI session. */
    string_array_t new_order STRING_ARRAY_AUTO = { 0 };
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].enabled) {
            error_t *push_err = string_array_push(&new_order, state->items[i].name);
            if (push_err) return push_err;
        }
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

    /* Phase 2 — validate additions before any DB mutation. A profile
     * with custom/ files cannot be enabled without a deployment target;
     * the TUI has no UI for collecting one, so block the trap at the
     * write boundary. A blocked save leaves the DB untouched (apart
     * from the harmless BEGIN IMMEDIATE that state_rollback releases). */
    for (size_t i = 0; i < new_order.count; i++) {
        if (!is_addition[i]) continue;
        const char *name = new_order.items[i];
        bool has_custom = false;
        err = profile_has_custom_files(repo, name, &has_custom);
        if (err) {
            err = error_wrap(
                err, "Failed to inspect profile '%s' for custom files", name
            );
            goto rollback;
        }
        if (has_custom) {
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' contains custom/ files; cannot enable interactively "
                "without a deployment target.\n"
                "Run: dotta profile enable %s --target /path", name, name
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
     * entry, so the precondition (every name in cache) holds. */
    for (size_t i = 0; i < new_order.count; i++) {
        if (!is_addition[i]) continue;
        const char *name = new_order.items[i];

        err = state_enable_profile(deploy_state, name, NULL);
        if (err) {
            err = error_wrap(err, "Failed to enable profile '%s'", name);
            goto rollback;
        }

        /* Replace the zero-OID sentinel state_enable_profile writes with
         * the real branch HEAD so enabled_profiles is fully authoritative
         * before apply_scope runs. */
        err = manifest_persist_profile_head(repo, deploy_state, name);
        if (err) {
            err = error_wrap(err, "Failed to persist HEAD for profile '%s'", name);
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
        const profile_item_t *item = &state->items[i];

        fprintf(stdout, "\r" ANSI_CLEAR_LINE);

        /* Cursor indicator */
        const char *cursor = (i == state->cursor) ? "\033[1;36m▶\033[0m" : " ";

        /* Selection checkbox */
        const char *checkbox = item->enabled ? "\033[1;32m✓\033[0m" : " ";

        /* Profile name (dim if not selected) - all aligned at same column */
        if (item->enabled || i == state->cursor) {
            fprintf(
                stdout, "  %s %s %s\r\n",
                cursor, checkbox, item->name
            );
        } else {
            fprintf(
                stdout, "  %s %s \033[2m%s\033[0m\r\n",
                cursor, checkbox, item->name
            );
        }
        lines_rendered++;
    }

    /* Blank line */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE "\r\n");
    lines_rendered++;

    /* Footer / keybinding help - adapt based on state */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (state->modified) {
        /* Show modified mode keys with save highlighted */
        fprintf(
            stdout, "\033[2m↑↓\033[0m navigate  "
            "\033[2mspace\033[0m toggle  "
            "\033[2mJ/K\033[0m move  "
            "\033[1;33mw\033[0m \033[1;33msave\033[0m  "
            "\033[2mq\033[0m quit"
        );
    } else {
        /* Show normal mode keys */
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

        /* Toggle enabled state */
        case TERM_KEY_SPACE:
            if (state->cursor < state->item_count) {
                bool was_enabled = state->items[state->cursor].enabled;
                state->items[state->cursor].enabled = !was_enabled;

                /* Update cached count */
                if (was_enabled) {
                    state->enabled_count--;
                } else {
                    state->enabled_count++;
                }

                state->modified = true;
            }
            return INTERACTIVE_CONTINUE;

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
     * Display format: "  ▶ ✓   profile/name"
     * - 2 spaces prefix
     * - 1 char cursor indicator
     * - 1 space
     * - 1 char checkbox
     * - 1 space
     * - 0-2 spaces indent
     * Total overhead: ~8 chars
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

    /* Check if longest name + UI elements fits in terminal width */
    const int UI_OVERHEAD = 10;  /* Extra margin for safety */
    if (max_name_len + UI_OVERHEAD > (size_t) size.cols) {
        interactive_state_free(state);
        terminal_restore(term);
        return error_create(
            ERR_INVALID_ARG, "terminal too narrow (longest profile name: "
            "%zu chars, need %d columns, have %d)", max_name_len,
            (int) max_name_len + UI_OVERHEAD, size.cols
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
