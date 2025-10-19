/**
 * interactive.c - Interactive TUI implementation
 *
 * Inline interface for profile selection and management.
 */

#include "interactive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "core/profiles.h"
#include "core/state.h"
#include "utils/array.h"
#include "utils/hashmap.h"
#include "utils/terminal.h"

/**
 * Interactive UI state
 */
struct interactive_state {
    git_repository *repo;          /* Repository (borrowed) */
    profile_item_t *items;         /* Profile items */
    size_t item_count;             /* Number of items */
    size_t selected_count;         /* Number of selected items (cached) */
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

error_t *interactive_state_create(git_repository *repo, interactive_state_t **out) {
    if (!repo || !out) {
        return error_create(ERR_INVALID_ARG, "repo and out cannot be NULL");
    }

    error_t *err = NULL;
    interactive_state_t *state = NULL;
    profile_list_t *all_profiles = NULL;
    state_t *deploy_state = NULL;
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

    /* Load current selections from state */
    err = state_load(repo, &deploy_state);
    if (err) {
        /* State load failure is not fatal - might be first run */
        error_free(err);
        err = NULL;
    } else {
        err = state_get_profiles(deploy_state, &state_profiles);
        if (err) {
            error_free(err);
            err = NULL;
            state_profiles = NULL;
        }
    }

    /* Build hashmap for O(1) profile lookups: name -> (index + 1) in all_profiles
     * We store (i + 1) instead of i because NULL (0) means "not found" */
    profile_map = hashmap_create(0);
    if (!profile_map) {
        err = error_create(ERR_MEMORY, "failed to create profile hashmap");
        goto cleanup;
    }

    for (size_t i = 0; i < all_profiles->count; i++) {
        /* Store (index + 1) to avoid NULL for index 0 */
        err = hashmap_set(profile_map, all_profiles->profiles[i].name, (void*)(uintptr_t)(i + 1));
        if (err) {
            goto cleanup;
        }
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

    /* First: Add profiles from state in their saved order (selected) */
    if (state_profiles) {
        for (size_t i = 0; i < state_profiles->count; i++) {
            const char *profile_name = state_profiles->items[i];

            /* O(1) lookup to verify profile still exists */
            void *idx_ptr = hashmap_get(profile_map, profile_name);
            if (!idx_ptr) {
                /* Profile in state but doesn't exist locally anymore - skip */
                continue;
            }

            /* Subtract 1 to get actual index (we stored i + 1) */
            size_t profile_idx = (size_t)(uintptr_t)idx_ptr - 1;
            used[profile_idx] = true;

            /* Add to items */
            state->items[item_idx].name = strdup(profile_name);
            if (!state->items[item_idx].name) {
                err = error_create(ERR_MEMORY, "failed to duplicate profile name");
                goto cleanup;
            }

            state->items[item_idx].selected = true;
            state->items[item_idx].exists_locally = true;
            item_idx++;
        }
    }

    /* Second: Add remaining profiles not in state (unselected, at bottom) */
    for (size_t i = 0; i < all_profiles->count; i++) {
        /* O(1) check if already added */
        if (used[i]) {
            continue;
        }

        profile_t *p = &all_profiles->profiles[i];

        /* Add to items */
        state->items[item_idx].name = strdup(p->name);
        if (!state->items[item_idx].name) {
            err = error_create(ERR_MEMORY, "failed to duplicate profile name");
            goto cleanup;
        }

        state->items[item_idx].selected = false;
        state->items[item_idx].exists_locally = true;
        item_idx++;
    }

    state->item_count = item_idx;

    /* Count selected items (all from state_profiles) */
    state->selected_count = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].selected) {
            state->selected_count++;
        }
    }

    /* Success - cleanup temporary resources and return */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    state_free(deploy_state);
    profile_list_free(all_profiles);
    hashmap_free(profile_map, NULL);
    free(used);

    *out = state;
    return NULL;

cleanup:
    /* Error path - free all resources */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    state_free(deploy_state);
    profile_list_free(all_profiles);
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
 * Save current profile selection and order to state
 *
 * Saves which profiles are selected and their display order. This is a silent
 * operation that doesn't require terminal restoration.
 */
static error_t *interactive_save_profile_order(
    git_repository *repo,
    interactive_state_t *state
) {
    if (!state || !repo) {
        return error_create(ERR_INVALID_ARG, "invalid arguments");
    }

    /* Check if any profiles selected (use cached count) */
    if (state->selected_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles selected");
    }

    /* Extract selected profile names in current display order */
    const char **profile_names = malloc(state->selected_count * sizeof(char *));
    if (!profile_names) {
        return error_create(ERR_MEMORY, "failed to allocate profile names");
    }

    size_t idx = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].selected) {
            profile_names[idx++] = state->items[i].name;
        }
    }

    /* Load state for update */
    state_t *deploy_state = NULL;
    error_t *err = state_load_for_update(repo, &deploy_state);
    if (err) {
        free(profile_names);
        return err;
    }

    /* Set profiles in new order */
    err = state_set_profiles(deploy_state, profile_names, state->selected_count);
    if (!err) {
        err = state_save(repo, deploy_state);
    }

    state_free(deploy_state);
    free(profile_names);

    /* Update state on success */
    if (!err) {
        state->modified = false;
    }

    return err;
}

/* UI Rendering */

int interactive_get_required_lines(const interactive_state_t *state) {
    if (!state) {
        return 0;
    }

    /* Header + blank + profiles + blank + footer */
    return 1 + 1 + (int)state->item_count + 1 + 1;
}

int interactive_render(const interactive_state_t *state) {
    if (!state) {
        return 0;
    }

    int lines_rendered = 0;

    /* Header */
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (state->modified) {
        fprintf(stdout, "  \033[1mProfiles:\033[0m \033[33m(modified)\033[0m\r\n");
    } else {
        fprintf(stdout, "  \033[1mProfiles:\033[0m\r\n");
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
        const char *checkbox = item->selected ? "\033[1;32m✓\033[0m" : " ";

        /* Profile name (dim if not selected) - all aligned at same column */
        if (item->selected || i == state->cursor) {
            fprintf(stdout, "  %s %s %s\r\n", cursor, checkbox, item->name);
        } else {
            fprintf(stdout, "  %s %s \033[2m%s\033[0m\r\n", cursor, checkbox, item->name);
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
        fprintf(stdout, "\033[2m↑↓\033[0m navigate  "
                        "\033[2mspace\033[0m toggle  "
                        "\033[2mJ/K\033[0m move  "
                        "\033[1;33mw\033[0m \033[1;33msave\033[0m  "
                        "\033[2mq\033[0m quit");
    } else {
        /* Show normal mode keys */
        fprintf(stdout, "\033[2m↑↓\033[0m navigate  "
                        "\033[2mspace\033[0m toggle  "
                        "\033[2mJ/K\033[0m move  "
                        "\033[2mq\033[0m quit");
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
    int key,
    terminal_t **term_ptr,
    error_t **out_err
) {
    if (!state || !repo || !term_ptr || !out_err) {
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

        /* Toggle selection */
        case TERM_KEY_SPACE:
            if (state->cursor < state->item_count) {
                bool was_selected = state->items[state->cursor].selected;
                state->items[state->cursor].selected = !was_selected;

                /* Update cached count */
                if (was_selected) {
                    state->selected_count--;
                } else {
                    state->selected_count++;
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

            error_t *err = interactive_save_profile_order(repo, state);
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

error_t *interactive_run(git_repository *repo) {
    if (!repo) {
        return error_create(ERR_INVALID_ARG, "repo cannot be NULL");
    }

    /* Check if terminal is a TTY */
    if (!terminal_is_tty()) {
        return error_create(ERR_INVALID_ARG, "interactive mode requires a TTY");
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
    err = interactive_state_create(repo, &state);
    if (err) {
        terminal_restore(term);
        return err;
    }

    /* Check if we have enough screen space (lines) */
    int required_lines = interactive_get_required_lines(state);
    if (required_lines > size.rows) {
        interactive_state_free(state);
        terminal_restore(term);
        return error_create(ERR_INVALID_ARG,
            "terminal too small (need %d lines, have %d)",
            required_lines, size.rows);
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
    if (max_name_len + UI_OVERHEAD > (size_t)size.cols) {
        interactive_state_free(state);
        terminal_restore(term);
        return error_create(ERR_INVALID_ARG,
            "terminal too narrow (longest profile name: %zu chars, need %d columns, have %d)",
            max_name_len, (int)max_name_len + UI_OVERHEAD, size.cols);
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
        result = interactive_handle_key(state, repo, key, &term, &loop_err);

        /* Re-render: move cursor up, then redraw */
        if (result == INTERACTIVE_CONTINUE) {
            /* Move up to start of first line
             * We drew N lines, cursor is on line N, need to move up N-1 to get to line 1 */
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
        return error_create(ERR_INTERNAL, "interactive mode exited with error");
    }

    return NULL;
}
