/**
 * interactive.c - Interactive TUI implementation
 *
 * Inline, fzf-style interface for profile selection and management.
 */

#include "utils/interactive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/error.h"
#include "cmds/apply.h"
#include "cmds/sync.h"
#include "cmds/update.h"
#include "core/profiles.h"
#include "core/state.h"
#include "utils/array.h"
#include "utils/output.h"
#include "utils/terminal.h"

/**
 * Profile namespace prefixes
 *
 * Host profiles use a different depth mapping because they have an extra
 * namespace level. For example:
 * - OS profiles: "darwin" (base, depth 0), "darwin/work" (sub, depth 1)
 * - Host profiles: "hosts/macbook" (base, depth 1), "hosts/macbook/work" (sub, depth 2)
 *
 * We normalize indentation by treating "hosts/<name>" as depth 0 for display.
 */
#define PROFILE_PREFIX_HOSTS "hosts/"
#define PROFILE_PREFIX_HOSTS_LEN 6

/**
 * Interactive UI state
 */
struct interactive_state {
    git_repository *repo;          /* Repository (borrowed) */
    profile_item_t *items;         /* Profile items */
    size_t item_count;             /* Number of items */
    size_t cursor;                 /* Current cursor position */
    int screen_start_row;          /* Starting row for rendering */
    bool order_modified;           /* True if profile order changed */
};

/* ========================================================================
 * Profile Item Utilities
 * ======================================================================== */

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

int interactive_get_indent_level(const char *profile_name) {
    if (!profile_name) {
        return 0;
    }

    /* Count slashes to determine depth */
    int depth = 0;
    for (const char *p = profile_name; *p; p++) {
        if (*p == '/') {
            depth++;
        }
    }

    /* For hosts profiles, depth 1 = "hosts/foo" (base), depth 2 = "hosts/foo/bar" (sub)
     * Normalize by subtracting 1 from depth for display consistency */
    if (strncmp(profile_name, PROFILE_PREFIX_HOSTS, PROFILE_PREFIX_HOSTS_LEN) == 0) {
        return depth > 1 ? 1 : 0;
    }

    /* For OS profiles, depth 0 = "darwin" (base), depth 1 = "darwin/work" (sub) */
    return depth;
}

bool interactive_is_host_profile(const char *profile_name) {
    return profile_name && strncmp(profile_name, PROFILE_PREFIX_HOSTS, PROFILE_PREFIX_HOSTS_LEN) == 0;
}

/* ========================================================================
 * State Management
 * ======================================================================== */

error_t *interactive_state_create(git_repository *repo, interactive_state_t **out) {
    if (!repo || !out) {
        return error_create(ERR_INVALID_ARG, "repo and out cannot be NULL");
    }

    error_t *err = NULL;
    interactive_state_t *state = NULL;
    profile_list_t *all_profiles = NULL;
    state_t *deploy_state = NULL;
    string_array_t *state_profiles = NULL;
    size_t item_idx = 0;  /* Track number of items allocated for cleanup */

    /* Allocate state */
    state = calloc(1, sizeof(interactive_state_t));
    if (!state) {
        err = error_create(ERR_MEMORY, "failed to allocate interactive state");
        goto cleanup;
    }

    state->repo = repo;
    state->cursor = 0;
    state->order_modified = false;

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

            /* Find this profile in all_profiles to verify it still exists */
            bool found = false;
            for (size_t j = 0; j < all_profiles->count; j++) {
                if (strcmp(all_profiles->profiles[j].name, profile_name) == 0) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                /* Profile in state but doesn't exist locally anymore - skip */
                continue;
            }

            /* Add to items */
            state->items[item_idx].name = strdup(profile_name);
            if (!state->items[item_idx].name) {
                err = error_create(ERR_MEMORY, "failed to duplicate profile name");
                goto cleanup;
            }

            state->items[item_idx].selected = true;
            state->items[item_idx].exists_locally = true;
            state->items[item_idx].exists_remotely = false;  /* TODO: check remote */
            state->items[item_idx].indent_level = interactive_get_indent_level(profile_name);
            state->items[item_idx].is_host_profile = interactive_is_host_profile(profile_name);
            item_idx++;
        }
    }

    /* Second: Add remaining profiles not in state (unselected, at bottom) */
    for (size_t i = 0; i < all_profiles->count; i++) {
        profile_t *p = &all_profiles->profiles[i];

        /* Check if already added from state */
        bool already_added = false;
        if (state_profiles) {
            already_added = string_array_contains(state_profiles, p->name);
        }

        if (already_added) {
            continue;
        }

        /* Add to items */
        state->items[item_idx].name = strdup(p->name);
        if (!state->items[item_idx].name) {
            err = error_create(ERR_MEMORY, "failed to duplicate profile name");
            goto cleanup;
        }

        state->items[item_idx].selected = false;
        state->items[item_idx].exists_locally = true;
        state->items[item_idx].exists_remotely = false;  /* TODO: check remote */
        state->items[item_idx].indent_level = interactive_get_indent_level(p->name);
        state->items[item_idx].is_host_profile = interactive_is_host_profile(p->name);
        item_idx++;
    }

    state->item_count = item_idx;

    /* Success - cleanup temporary resources and return */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    state_free(deploy_state);
    profile_list_free(all_profiles);

    *out = state;
    return NULL;

cleanup:
    /* Error path - free all resources */
    if (state_profiles) {
        string_array_free(state_profiles);
    }
    state_free(deploy_state);
    profile_list_free(all_profiles);
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

/* ========================================================================
 * Profile Reordering
 * ======================================================================== */

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
    state->order_modified = true;
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
    state->order_modified = true;
}

/**
 * Save current profile order to state
 *
 * This is a silent operation that doesn't require terminal restoration.
 */
static error_t *interactive_save_profile_order(
    git_repository *repo,
    interactive_state_t *state
) {
    if (!state || !repo) {
        return error_create(ERR_INVALID_ARG, "invalid arguments");
    }

    /* Count selected profiles */
    size_t selected_count = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].selected) {
            selected_count++;
        }
    }

    if (selected_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles selected");
    }

    /* Extract selected profile names in current display order */
    const char **profile_names = malloc(selected_count * sizeof(char *));
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
    err = state_set_profiles(deploy_state, profile_names, selected_count);
    if (!err) {
        err = state_save(repo, deploy_state);
    }

    state_free(deploy_state);
    free(profile_names);

    /* Update state on success */
    if (!err) {
        state->order_modified = false;
    }

    return err;
}

/* ========================================================================
 * UI Rendering
 * ======================================================================== */

int interactive_get_required_lines(const interactive_state_t *state) {
    if (!state) {
        return 0;
    }

    /* Header + blank + profiles + blank + footer */
    return 1 + 1 + (int)state->item_count + 1 + 1;
}

int interactive_render(const interactive_state_t *state, int start_row) {
    if (!state) {
        return 0;
    }

    (void)start_row;  /* Not used in inline rendering */

    int lines_rendered = 0;

    /* Header */
    fprintf(stdout, "\r");
    terminal_clear_line();
    if (state->order_modified) {
        fprintf(stdout, "  \033[1mProfiles:\033[0m \033[33m(modified)\033[0m\r\n");
    } else {
        fprintf(stdout, "  \033[1mProfiles:\033[0m\r\n");
    }
    lines_rendered++;

    /* Blank line */
    fprintf(stdout, "\r");
    terminal_clear_line();
    fprintf(stdout, "\r\n");
    lines_rendered++;

    /* Profile items */
    for (size_t i = 0; i < state->item_count; i++) {
        const profile_item_t *item = &state->items[i];

        fprintf(stdout, "\r");
        terminal_clear_line();

        /* Cursor indicator */
        const char *cursor = (i == state->cursor) ? "\033[1;36m▶\033[0m" : " ";

        /* Selection checkbox */
        const char *checkbox = item->selected ? "\033[1;32m✓\033[0m" : " ";

        /* Indentation */
        const char *indent = "";
        if (item->indent_level == 1) {
            indent = "  ";  /* 2 spaces for sub-profiles */
        }

        /* Profile name (dim if not selected) */
        if (item->selected || i == state->cursor) {
            fprintf(stdout, "  %s %s %s%s\r\n", cursor, checkbox, indent, item->name);
        } else {
            fprintf(stdout, "  %s %s \033[2m%s%s\033[0m\r\n", cursor, checkbox, indent, item->name);
        }
        lines_rendered++;
    }

    /* Blank line */
    fprintf(stdout, "\r");
    terminal_clear_line();
    fprintf(stdout, "\r\n");
    lines_rendered++;

    /* Footer / keybinding help - adapt based on state */
    fprintf(stdout, "\r");
    terminal_clear_line();
    if (state->order_modified) {
        /* Show reorder mode keys */
        fprintf(stdout, "\033[2m↑↓\033[0m navigate  "
                        "\033[2mspace\033[0m toggle  "
                        "\033[2mJ/K\033[0m move  "
                        "\033[1;33mw\033[0m \033[1;33msave order\033[0m  "
                        "\033[2mq\033[0m quit");
    } else {
        /* Show normal mode keys */
        fprintf(stdout, "\033[2m↑↓\033[0m navigate  "
                        "\033[2mspace\033[0m toggle  "
                        "\033[2mJ/K\033[0m move  "
                        "\033[2ma\033[0m apply  "
                        "\033[2mu\033[0m update  "
                        "\033[2ms\033[0m sync  "
                        "\033[2mq\033[0m quit");
    }
    lines_rendered++;

    fflush(stdout);

    return lines_rendered;
}

/* ========================================================================
 * Commands
 * ======================================================================== */

/**
 * Get selected profile names
 *
 * Builds an array of profile name pointers for currently selected profiles.
 *
 * MEMORY OWNERSHIP:
 * - Allocates and returns a new array via *out_profiles
 * - Caller MUST free this array with free() when done
 * - The profile name strings themselves are borrowed from state
 *   and MUST NOT be freed individually
 *
 * Example usage:
 *   const char **profiles = NULL;
 *   size_t count = 0;
 *   error_t *err = get_selected_profiles(state, &profiles, &count);
 *   if (!err) {
 *       // ... use profiles ...
 *       free(profiles);  // Free the array, not the strings
 *   }
 *
 * @param state State (must not be NULL)
 * @param out_profiles Profile array pointer (must not be NULL, caller frees)
 * @param out_count Profile count (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *get_selected_profiles(
    const interactive_state_t *state,
    const char ***out_profiles,
    size_t *out_count
) {
    if (!state || !out_profiles || !out_count) {
        return error_create(ERR_INVALID_ARG, "invalid arguments");
    }

    /* Count selected profiles */
    size_t selected_count = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].selected) {
            selected_count++;
        }
    }

    if (selected_count == 0) {
        *out_profiles = NULL;
        *out_count = 0;
        return NULL;
    }

    /* Allocate profile name array */
    const char **profiles = malloc(selected_count * sizeof(char *));
    if (!profiles) {
        return error_create(ERR_MEMORY, "failed to allocate profile array");
    }

    /* Fill array */
    size_t idx = 0;
    for (size_t i = 0; i < state->item_count; i++) {
        if (state->items[i].selected) {
            profiles[idx++] = state->items[i].name;
        }
    }

    *out_profiles = profiles;
    *out_count = selected_count;
    return NULL;
}

error_t *interactive_cmd_apply(
    git_repository *repo,
    const interactive_state_t *state,
    const interactive_options_t *opts
) {
    const char **profiles = NULL;
    size_t profile_count = 0;

    error_t *err = get_selected_profiles(state, &profiles, &profile_count);
    if (err) {
        return err;
    }

    if (profile_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles selected");
    }

    /* Build apply options */
    cmd_apply_options_t apply_opts = {
        .profiles = profiles,
        .profile_count = profile_count,
        .force = false,
        .dry_run = opts ? opts->dry_run : false,
        .keep_orphans = false,
        .verbose = opts ? opts->verbose : false,
        .skip_existing = false,
        .skip_unchanged = true
    };

    err = cmd_apply(repo, &apply_opts);
    free(profiles);
    return err;
}

error_t *interactive_cmd_update(
    git_repository *repo,
    const interactive_state_t *state,
    const interactive_options_t *opts
) {
    const char **profiles = NULL;
    size_t profile_count = 0;

    error_t *err = get_selected_profiles(state, &profiles, &profile_count);
    if (err) {
        return err;
    }

    if (profile_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles selected");
    }

    /* Build update options */
    cmd_update_options_t update_opts = {
        .files = NULL,
        .file_count = 0,
        .profiles = profiles,
        .profile_count = profile_count,
        .message = NULL,
        .exclude_patterns = NULL,
        .exclude_count = 0,
        .dry_run = opts ? opts->dry_run : false,
        .interactive = false,  /* Already in interactive mode */
        .verbose = opts ? opts->verbose : false,
        .include_new = false,
        .only_new = false
    };

    err = cmd_update(repo, &update_opts);
    free(profiles);
    return err;
}

error_t *interactive_cmd_sync(
    git_repository *repo,
    const interactive_state_t *state,
    const interactive_options_t *opts
) {
    const char **profiles = NULL;
    size_t profile_count = 0;

    error_t *err = get_selected_profiles(state, &profiles, &profile_count);
    if (err) {
        return err;
    }

    if (profile_count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles selected");
    }

    /* Build sync options */
    cmd_sync_options_t sync_opts = {
        .profiles = profiles,
        .profile_count = profile_count,
        .dry_run = opts ? opts->dry_run : false,
        .no_push = false,
        .no_pull = false,
        .verbose = opts ? opts->verbose : false,
        .force = false,
        .diverged = NULL
    };

    err = cmd_sync(repo, &sync_opts);
    free(profiles);
    return err;
}

/* ========================================================================
 * Input Handling
 * ======================================================================== */

/**
 * Temporarily restore terminal and run command
 */
static interactive_result_t run_command_with_normal_terminal(
    terminal_t **term_ptr,
    error_t *(*cmd_func)(git_repository *, const interactive_state_t *, const interactive_options_t *),
    git_repository *repo,
    const interactive_state_t *state,
    const interactive_options_t *opts,
    const char *cmd_name
) {
    /* Restore terminal to normal mode */
    terminal_cursor_show();
    terminal_restore(*term_ptr);

    /* Run command - let it produce its normal output */
    error_t *err = cmd_func(repo, state, opts);

    /* Show result - only show errors, success is silent */
    if (err) {
        fprintf(stderr, "\n\033[1;31m%s failed:\033[0m ", cmd_name);
        error_print(err, stderr);
        error_free(err);
        fprintf(stderr, "\n");
    }
    fflush(stdout);

    /* Re-initialize raw mode */
    terminal_t *new_term = NULL;
    err = terminal_init(&new_term);
    if (err) {
        fprintf(stderr, "\nFailed to re-initialize terminal: ");
        error_print(err, stderr);
        error_free(err);
        return INTERACTIVE_EXIT_ERROR;
    }

    /* Wait for keypress */
    terminal_read_key();

    /* Hide cursor again */
    terminal_cursor_hide();

    /* Update terminal pointer */
    *term_ptr = new_term;

    /* Don't try to clear output - just add a blank line for separation
     * The UI will render inline at the current cursor position */
    fprintf(stdout, "\n");

    return INTERACTIVE_CONTINUE;
}

interactive_result_t interactive_handle_key(
    interactive_state_t *state,
    git_repository *repo,
    int key,
    const interactive_options_t *opts,
    terminal_t **term_ptr
) {
    if (!state || !repo || !term_ptr) {
        return INTERACTIVE_EXIT_ERROR;
    }

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
        case '\n':
        case '\r':
            if (state->cursor < state->item_count) {
                state->items[state->cursor].selected = !state->items[state->cursor].selected;
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

        /* Save profile order - silent operation, no terminal restoration needed */
        case 'w':
        case 'W': {
            if (!state->order_modified) {
                /* Nothing to save */
                return INTERACTIVE_CONTINUE;
            }

            error_t *err = interactive_save_profile_order(repo, state);
            if (err) {
                /* Silently ignore errors for now - could add error indicator to UI */
                error_free(err);
            }
            return INTERACTIVE_CONTINUE;
        }

        /* Commands */
        case 'a':
        case 'A':
            return run_command_with_normal_terminal(term_ptr,
                interactive_cmd_apply, repo, state, opts, "Applying profiles");

        case 'u':
        case 'U':
            return run_command_with_normal_terminal(term_ptr,
                interactive_cmd_update, repo, state, opts, "Updating profiles");

        case 's':
        case 'S':
            return run_command_with_normal_terminal(term_ptr,
                interactive_cmd_sync, repo, state, opts, "Syncing profiles");

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

/* ========================================================================
 * Main Entry Point
 * ======================================================================== */

error_t *interactive_run(git_repository *repo, const interactive_options_t *opts) {
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
    int lines_drawn = interactive_render(state, 0);
    state->screen_start_row = 0;  /* Not used anymore */

    /* Main loop */
    interactive_result_t result = INTERACTIVE_CONTINUE;
    while (result == INTERACTIVE_CONTINUE) {
        /* Read key */
        int key = terminal_read_key();

        /* Check if this is a command key - if so, clear UI first
         * Note: 'w' is NOT a command - it's a silent save operation */
        bool is_command = (key == 'a' || key == 'A' || key == 'u'
                        || key == 'U' || key == 's' || key == 'S');
        if (is_command) {
            /* Clear current UI by moving up and clearing lines */
            terminal_cursor_up(lines_drawn);
            for (int i = 0; i < lines_drawn; i++) {
                terminal_clear_line();
                fprintf(stdout, "\r\n");
            }
            terminal_cursor_up(lines_drawn);
        }

        /* Handle key */
        result = interactive_handle_key(state, repo, key, opts, &term);

        /* Re-render: move cursor up, then redraw */
        if (result == INTERACTIVE_CONTINUE) {
            if (!is_command) {
                /* Move up to start of first line
                 * We drew N lines, cursor is on line N, need to move up N-1 to get to line 1 */
                if (lines_drawn > 0) {
                    terminal_cursor_up(lines_drawn - 1);
                }
            }
            lines_drawn = interactive_render(state, 0);
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

    if (result == INTERACTIVE_EXIT_ERROR) {
        return error_create(ERR_INTERNAL, "interactive mode exited with error");
    }

    return NULL;
}
