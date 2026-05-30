/**
 * interactive.c - Interactive TUI for profile management and ordering
 *
 * Single-entrypoint module. Inline raw-mode interface that lets the user
 * select, reorder, and target-bind profiles before applying them. The
 * public surface is exactly `spec_interactive`; everything below is
 * file-local.
 */

#include "cmds/interactive.h"

#include <runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/terminal.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"

/* --- Style macros --- */

#define UI_BOLD          "\033[1m"
#define UI_DIM           "\033[2m"
#define UI_RESET         "\033[0m"
#define UI_YELLOW        "\033[33m"
#define UI_BOLD_YELLOW   "\033[1;33m"

#define UI_CURSOR        "\033[1;36m▶\033[0m"
#define UI_CHECK         "\033[1;32m✓\033[0m"

/* Row prefix: "  " + cursor + " " + checkbox + " " = 6 visible columns. */
#define ROW_PREFIX_COLS       6
/* Worst static annotation: " (custom)" = 9 visible columns. */
#define ROW_ANNOTATION_COLS   9

/* Pre-allocated prompt buffer size; geometric realloc covers overflow. */
#define PROMPT_INITIAL_CAP    256

/* --- Types --- */

typedef struct {
    char *name;            /* Owned profile name */
    char *target;          /* Owned deployment target for custom/ files; NULL when unset */
    bool enabled;          /* Selected for save; toggled by space, persisted by save_order */
    bool exists_locally;   /* Profile branch is present in this clone */
    bool has_custom;       /* Profile contains custom/ files (eager probe at create) */
} item_t;

typedef struct {
    char *buffer;          /* Owned, NUL-terminated input scratch */
    size_t len;            /* Bytes in buffer, excluding NUL */
    size_t cap;            /* Allocated capacity */
    size_t item_index;     /* Row anchor (view->items index) the prompt is over */
    bool active;           /* True while the prompt overlay is open */
    bool enable;           /* True iff opened via space-on-disabled-custom (commit flips enabled) */
} prompt_t;

typedef struct {
    item_t *items;         /* Owned array of profile rows */
    size_t item_count;     /* Number of valid entries in items */
    size_t cursor;         /* Selected row (0..item_count-1; valid iff item_count > 0) */
    bool modified;         /* Unsaved edits pending; cleared by a successful save_order */
    prompt_t prompt;       /* Inline target-capture overlay state */
} view_t;

typedef enum {
    INTERACTIVE_CONTINUE,     /* Keep looping; re-render and read next key */
    INTERACTIVE_EXIT_OK,      /* User quit cleanly */
    INTERACTIVE_EXIT_ERROR    /* Quit on error; out_err carries the cause */
} interactive_result_t;

/* Save-time diff plan. Pointer arrays live in the caller's arena;
 * new_order owns its strings via string_array_deinit. */
typedef struct {
    string_array_t new_order;  /* Ordered enabled names, in display order */
    item_t **new_order_items;  /* Parallel pointers into view->items (same indexing as new_order) */
    bool *needs_enable;        /* Per new_order row: true iff row needs a state_enable_profile write */
    char **removal_names;      /* Arena-strdup'd persisted names absent from new_order */
    size_t removal_count;      /* Number of valid entries in removal_names */
} plan_t;

/* --- Items --- */

static void free_items(item_t *items, size_t count) {
    if (!items) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(items[i].name);
        free(items[i].target);
    }
    free(items);
}

static void swap_items(item_t *items, size_t i, size_t j) {
    item_t tmp = items[i];
    items[i] = items[j];
    items[j] = tmp;
}

/* --- Prompt --- */

static void prompt_close(prompt_t *p) {
    p->active = false;
    p->enable = false;
    p->item_index = 0;
    p->len = 0;
    p->buffer[0] = '\0';
}

/* Append one byte; grow geometrically. Returns -1 on OOM. */
static int prompt_push(prompt_t *p, char c) {
    if (p->len + 1 >= p->cap) {
        size_t new_cap = p->cap * 2;
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

/* Replace the buffer with a copy of src (empty when src is NULL/empty).
 * On OOM the buffer is left empty so the caller can fall back to a
 * fresh prompt. */
static int prompt_set(prompt_t *p, const char *src) {
    if (!src || *src == '\0') {
        p->len = 0;
        p->buffer[0] = '\0';
        return 0;
    }
    size_t src_len = strlen(src);
    size_t need = src_len + 1;
    if (need > p->cap) {
        size_t new_cap = p->cap;
        while (new_cap < need) {
            new_cap *= 2;
        }
        char *new_buf = realloc(p->buffer, new_cap);
        if (!new_buf) {
            p->len = 0;
            p->buffer[0] = '\0';
            return -1;
        }
        p->buffer = new_buf;
        p->cap = new_cap;
    }
    memcpy(p->buffer, src, src_len);
    p->buffer[src_len] = '\0';
    p->len = src_len;
    return 0;
}

/* Opening helpers — mirror prompt_close so the input dispatcher never
 * reaches into the prompt's representation. */
static void prompt_open_capture(prompt_t *p, size_t item_index) {
    p->active = true;
    p->enable = true;
    p->item_index = item_index;
    /* Buffer is empty (prompt_close on prior cycle, calloc on first). */
}

static void prompt_open_edit(prompt_t *p, size_t item_index, const char *current) {
    p->active = true;
    p->enable = false;
    p->item_index = item_index;
    /* OOM here is acceptable: fall back to an empty buffer rather than
     * refuse to open the prompt; the user can type a fresh path. */
    (void) prompt_set(p, current);
}

/* --- View lifecycle --- */

/* Allocate view->items and populate name/enabled/exists_locally. On
 * failure, item_count is set to the populated prefix and view_free
 * (via view_create's fail path) releases what was allocated. */
static error_t *build_items(
    git_repository *repo, state_t *deploy_state, view_t *view
) {
    error_t *err = NULL;
    string_array_t *all_profiles = NULL;
    string_array_t *state_profiles = NULL;
    hashmap_t *profile_map = NULL;
    bool *used = NULL;
    size_t item_idx = 0;

    err = profile_list_all_local(repo, &all_profiles);
    if (err) goto cleanup;

    if (all_profiles->count == 0) {
        err = error_create(ERR_NOT_FOUND, "no profiles found in repository");
        goto cleanup;
    }

    /* First-run case: a handle whose underlying DB doesn't exist yields
     * an empty enabled set, not an error. Save via 'w' lazily creates
     * .git/dotta.db in state_begin. */
    err = state_get_profiles(deploy_state, &state_profiles);
    if (err) {
        error_free(err);
        err = NULL;
        state_profiles = NULL;
    }

    /* Hash map for O(1) lookups. Store (i + 1) so index 0 doesn't
     * collide with the "not found" NULL return. */
    profile_map = hashmap_borrow(0);
    if (!profile_map) {
        err = error_create(ERR_MEMORY, "failed to create profile hashmap");
        goto cleanup;
    }
    for (size_t i = 0; i < all_profiles->count; i++) {
        err = hashmap_set(
            profile_map, all_profiles->items[i], (void *) (uintptr_t) (i + 1)
        );
        if (err) goto cleanup;
    }

    used = calloc(all_profiles->count, sizeof(bool));
    if (!used) {
        err = error_create(ERR_MEMORY, "failed to allocate tracking array");
        goto cleanup;
    }

    view->items = calloc(all_profiles->count, sizeof(item_t));
    if (!view->items) {
        err = error_create(ERR_MEMORY, "failed to allocate profile items");
        goto cleanup;
    }

    /* Pass A: enabled profiles in their saved order. */
    if (state_profiles) {
        for (size_t i = 0; i < state_profiles->count; i++) {
            const char *name = state_profiles->items[i];
            void *idx_ptr = hashmap_get(profile_map, name);
            if (!idx_ptr) {
                /* Persisted name no longer exists locally — drop silently. */
                continue;
            }
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
            used[idx] = true;
            view->items[item_idx].name = strdup(name);
            if (!view->items[item_idx].name) {
                err = error_create(ERR_MEMORY, "failed to duplicate profile name");
                goto cleanup;
            }
            view->items[item_idx].enabled = true;
            view->items[item_idx].exists_locally = true;
            item_idx++;
        }
    }

    /* Pass B: remaining profiles, disabled, in list order. */
    for (size_t i = 0; i < all_profiles->count; i++) {
        if (used[i]) continue;
        view->items[item_idx].name = strdup(all_profiles->items[i]);
        if (!view->items[item_idx].name) {
            err = error_create(ERR_MEMORY, "failed to duplicate profile name");
            goto cleanup;
        }
        view->items[item_idx].enabled = false;
        view->items[item_idx].exists_locally = true;
        item_idx++;
    }

cleanup:
    view->item_count = item_idx;
    string_array_free(state_profiles);
    string_array_free(all_profiles);
    hashmap_free(profile_map, NULL);
    free(used);
    return err;
}

/* Pass two: eagerly seed has_custom and target.
 *
 * has_custom is computed up front so toggling becomes a constant-time
 * field check. Lazy probing would force a Git tree read inside a
 * raw-mode keystroke handler — visible latency on the first space.
 *
 * Target borrows from state_peek_profile_target's row cache, whose
 * lifetime ends at the next state_enable/disable/reorder. Save runs
 * those calls much later; copy across the boundary now. */
static error_t *seed_metadata(
    git_repository *repo, state_t *deploy_state, view_t *view
) {
    for (size_t i = 0; i < view->item_count; i++) {
        error_t *err = profile_has_custom_files(
            repo, view->items[i].name, &view->items[i].has_custom
        );
        if (err) {
            return error_wrap(
                err, "Failed to inspect profile '%s' for custom files",
                view->items[i].name
            );
        }
        if (!view->items[i].enabled) continue;

        const char *t = state_peek_profile_target(
            deploy_state, view->items[i].name
        );
        if (!t) continue;

        view->items[i].target = strdup(t);
        if (!view->items[i].target) {
            return error_create(
                ERR_MEMORY,
                "failed to duplicate target for profile '%s'",
                view->items[i].name
            );
        }
    }
    return NULL;
}

static void view_free(view_t *view) {
    if (!view) {
        return;
    }
    free_items(view->items, view->item_count);
    free(view->prompt.buffer);
    free(view);
}

static inline void view_cleanup(view_t **v) {
    if (v && *v) {
        view_free(*v);
        *v = NULL;
    }
}
#define VIEW_AUTO __attribute__((cleanup(view_cleanup)))

static error_t *view_create(
    git_repository *repo, state_t *deploy_state, view_t **out
) {
    view_t *view = calloc(1, sizeof(view_t));
    if (!view) {
        return error_create(ERR_MEMORY, "failed to allocate interactive view");
    }

    error_t *err = build_items(repo, deploy_state, view);
    if (err) goto fail;

    err = seed_metadata(repo, deploy_state, view);
    if (err) goto fail;

    /* Pre-allocate the prompt buffer so the keystroke handler stays
     * alloc-free on the common typing path. */
    view->prompt.cap = PROMPT_INITIAL_CAP;
    view->prompt.buffer = calloc(view->prompt.cap, sizeof(char));
    if (!view->prompt.buffer) {
        view->prompt.cap = 0;
        err = error_create(ERR_MEMORY, "failed to allocate prompt buffer");
        goto fail;
    }

    *out = view;
    return NULL;

fail:
    view_free(view);
    return err;
}

/* --- Reorder --- */

static void move_up(view_t *view) {
    if (view->cursor == 0) {
        return;
    }
    swap_items(view->items, view->cursor, view->cursor - 1);
    view->cursor--;
    view->modified = true;
}

static void move_down(view_t *view) {
    if (view->cursor + 1 >= view->item_count) {
        return;
    }
    swap_items(view->items, view->cursor, view->cursor + 1);
    view->cursor++;
    view->modified = true;
}

/* --- Save plan --- */

static inline void plan_cleanup(plan_t *p) {
    if (p) {
        string_array_deinit(&p->new_order);
    }
}
#define PLAN_AUTO __attribute__((cleanup(plan_cleanup)))

/* Phase: collect enabled rows in display order. Pure view sweep; no
 * state interaction. */
static error_t *plan_collect(arena_t *arena, view_t *view, plan_t *plan) {
    if (view->item_count > 0) {
        plan->new_order_items = arena_calloc(
            arena, view->item_count, sizeof(*plan->new_order_items)
        );
        if (!plan->new_order_items) {
            return ERROR(ERR_MEMORY, "Failed to allocate item pointer scratch");
        }
    }

    size_t k = 0;
    for (size_t i = 0; i < view->item_count; i++) {
        if (!view->items[i].enabled) continue;
        error_t *err = string_array_push(&plan->new_order, view->items[i].name);
        if (err) return err;
        plan->new_order_items[k++] = &view->items[i];
    }
    return NULL;
}

/* Phase: classify diff against the persisted set BEFORE any mutation.
 *
 * state_peek_profiles returns borrowed pointers into the row cache. The
 * first state_enable/disable call invalidates the cache and frees the
 * underlying strings. Both needs_enable (additions plus retained rows
 * whose target was edited in-session) and removal_names must be decided
 * here, while the borrows are live. Removal names are arena-strdup'd
 * so they survive the invalidation. */
static error_t *plan_classify(
    arena_t *arena, state_t *deploy_state, plan_t *plan
) {
    const state_profile_entry_t *persisted = NULL;
    size_t persisted_count = 0;
    error_t *err = state_peek_profiles(
        deploy_state, &persisted, &persisted_count
    );
    if (err) return err;

    if (plan->new_order.count > 0) {
        plan->needs_enable = arena_calloc(
            arena, plan->new_order.count, sizeof(*plan->needs_enable)
        );
        if (!plan->needs_enable) {
            return ERROR(ERR_MEMORY, "Failed to allocate enable flags");
        }
    }
    if (persisted_count > 0) {
        plan->removal_names = arena_calloc(
            arena, persisted_count, sizeof(*plan->removal_names)
        );
        if (!plan->removal_names) {
            return ERROR(ERR_MEMORY, "Failed to allocate removal scratch");
        }
    }

    /* Walk persisted; nested linear scan beats a hashmap on these tiny
     * sets (typically < 10 profiles). */
    for (size_t i = 0; i < persisted_count; i++) {
        const char *p_name = persisted[i].name;
        bool retained = false;
        for (size_t j = 0; j < plan->new_order.count; j++) {
            if (strcmp(plan->new_order.items[j], p_name) == 0) {
                retained = true;
                break;
            }
        }
        if (retained) continue;

        char *dup = arena_strdup(arena, p_name);
        if (!dup) {
            return ERROR(ERR_MEMORY, "Failed to duplicate removal name");
        }
        plan->removal_names[plan->removal_count++] = dup;
    }

    /* Walk new_order; flag rows that must be re-written via
     * state_enable_profile. */
    for (size_t i = 0; i < plan->new_order.count; i++) {
        item_t *it = plan->new_order_items[i];
        bool was_enabled = false;
        const char *persisted_target = NULL;
        for (size_t j = 0; j < persisted_count; j++) {
            if (strcmp(persisted[j].name, it->name) == 0) {
                was_enabled = true;
                persisted_target = persisted[j].target;
                break;
            }
        }
        if (!was_enabled) {
            plan->needs_enable[i] = true;
            continue;
        }
        /* Retained: re-enable only when the user changed the target
         * in-session. Strict equality, NULL == NULL counts as same. */
        const char *a = it->target;
        const char *b = persisted_target;
        bool same_target = (a == NULL && b == NULL) ||
            (a != NULL && b != NULL && strcmp(a, b) == 0);
        plan->needs_enable[i] = !same_target;
    }

    return NULL;
}

/* Phase: validate user-supplied targets at the boundary, mirroring the
 * check `cmd profile enable` runs. NULL targets are legitimate for
 * non-custom rows; for custom rows the prompt is the source-of-truth
 * gate, and manifest_apply_scope's UNBOUND tripwire fires downstream
 * if a bug ever breaches that gate. No second guard here. */
static error_t *plan_validate(const plan_t *plan) {
    for (size_t i = 0; i < plan->new_order.count; i++) {
        if (!plan->needs_enable[i]) continue;
        const item_t *it = plan->new_order_items[i];
        if (!it->target) continue;

        error_t *err = mount_validate_target(it->target);
        if (err) {
            return error_wrap(
                err, "Invalid deployment target for profile '%s'", it->name
            );
        }
    }
    return NULL;
}

/* Phase: apply the diff. Enables first (cache holds every reorder name
 * when reorder runs), removals next, reorder last over the post-diff
 * set. Each enable/disable invalidates the row cache; reorder reloads
 * it on entry so the precondition holds. */
static error_t *plan_apply(
    git_repository *repo, state_t *deploy_state, const plan_t *plan
) {
    for (size_t i = 0; i < plan->new_order.count; i++) {
        if (!plan->needs_enable[i]) continue;
        const item_t *it = plan->new_order_items[i];

        error_t *err = state_enable_profile(deploy_state, it->name, it->target);
        if (err) {
            return error_wrap(err, "Failed to enable profile '%s'", it->name);
        }

        /* Replace the zero-OID sentinel state_enable_profile writes
         * with the real branch HEAD so enabled_profiles is fully
         * authoritative before apply_scope runs. */
        err = manifest_persist_profile_head(repo, deploy_state, it->name);
        if (err) {
            return error_wrap(
                err, "Failed to persist HEAD for profile '%s'", it->name
            );
        }
    }

    for (size_t i = 0; i < plan->removal_count; i++) {
        error_t *err = state_disable_profile(deploy_state, plan->removal_names[i]);
        if (err) {
            return error_wrap(
                err, "Failed to disable profile '%s'", plan->removal_names[i]
            );
        }
    }

    error_t *err = state_reorder_profiles(deploy_state, &plan->new_order);
    if (err) {
        return error_wrap(err, "Failed to apply new profile order");
    }
    return NULL;
}

/* Phase: rebuild the mount table from the post-mutation binding set
 * and reconcile virtual_manifest + tracked_directories. */
static error_t *plan_reconcile(
    git_repository *repo, state_t *deploy_state, arena_t *arena
) {
    mount_table_t *mounts = NULL;
    error_t *err = profile_build_mount_table(deploy_state, arena, &mounts);
    if (err) {
        return error_wrap(err, "Failed to rebuild mount table after profile diff");
    }
    err = manifest_apply_scope(repo, deploy_state, arena, mounts, NULL, NULL);
    if (err) {
        return error_wrap(err, "Failed to reconcile manifest with new scope");
    }
    return NULL;
}

/* Save orchestrator. Holds a scoped write transaction for the diff
 * window only; declaring WRITE at the spec level would hold BEGIN
 * IMMEDIATE for the whole session, blocking other dotta processes. */
static error_t *save_order(
    git_repository *repo, state_t *deploy_state, arena_t *arena, view_t *view
) {
    plan_t plan PLAN_AUTO = { 0 };
    error_t *err = plan_collect(arena, view, &plan);
    if (err) return err;

    /* Refuse a save that would empty enabled_profiles. Checked here —
     * after collect — instead of via a cached counter on view: the
     * items array is the single source of truth for "is this enabled?".
     * A sibling counter would be a cache of a cache. */
    if (plan.new_order.count == 0) {
        return error_create(ERR_INVALID_ARG, "no profiles enabled");
    }

    err = state_begin(deploy_state);
    if (err) return err;

    err = plan_classify(arena, deploy_state, &plan);
    if (err) goto rollback;

    err = plan_validate(&plan);
    if (err) goto rollback;

    err = plan_apply(repo, deploy_state, &plan);
    if (err) goto rollback;

    err = plan_reconcile(repo, deploy_state, arena);
    if (err) goto rollback;

    err = state_commit(deploy_state);
    if (err) goto rollback;

    view->modified = false;
    return NULL;

rollback:
    state_rollback(deploy_state);
    return err;
}

/* --- Render --- */

/* Three row shapes, all the same line count:
 *   1. Prompt-active   "  ▶   Target: <buffer>_"
 *   2. Enabled custom  "  ▶ ✓ name → <target>"
 *   3. Disabled custom "    name (custom)"
 *
 * Trailing '_' is the visible caret; hardware cursor stays hidden for
 * the whole session. Annotations print from their own fprintf so the
 * unbounded target string sidesteps the "how big a buffer" question;
 * stdout is line-buffered and view_render emits a single fflush. */
static void row_render(const view_t *view, size_t i) {
    const item_t *it = &view->items[i];
    bool is_cursor = (i == view->cursor);
    bool is_prompt = (view->prompt.active && i == view->prompt.item_index);

    fprintf(stdout, "\r" ANSI_CLEAR_LINE);

    if (is_prompt) {
        /* The cursor is always on the prompt row by construction
         * (prompt_open_* anchors item_index to view->cursor and
         * navigation keys are shadowed while active). */
        fprintf(
            stdout, "  " UI_CURSOR "   " UI_BOLD "Target:" UI_RESET " %s_\r\n",
            view->prompt.buffer
        );
        return;
    }

    const char *cursor_glyph = is_cursor ? UI_CURSOR : " ";
    const char *checkbox = it->enabled ? UI_CHECK : " ";
    bool dim_name = !it->enabled && !is_cursor;
    const char *name_open = dim_name ? UI_DIM : "";
    const char *name_close = dim_name ? UI_RESET : "";

    fprintf(
        stdout, "  %s %s %s%s%s",
        cursor_glyph, checkbox, name_open, it->name, name_close
    );

    if (it->enabled && it->has_custom && it->target) {
        fprintf(stdout, " " UI_DIM "→ %s" UI_RESET, it->target);
    } else if (!it->enabled && it->has_custom) {
        fprintf(stdout, " " UI_DIM "(custom)" UI_RESET);
    }
    fprintf(stdout, "\r\n");
}

static void render_header(const view_t *view) {
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (view->modified) {
        fprintf(
            stdout, "  " UI_BOLD "Profiles:" UI_RESET
            " " UI_YELLOW "(modified)" UI_RESET "\r\n"
        );
    } else {
        fprintf(stdout, "  " UI_BOLD "Profiles:" UI_RESET "\r\n");
    }
}

static void render_footer(const view_t *view) {
    fprintf(stdout, "\r" ANSI_CLEAR_LINE);
    if (view->prompt.active) {
        fprintf(
            stdout,
            UI_DIM "enter" UI_RESET " confirm  "
            UI_DIM "esc" UI_RESET " cancel  "
            UI_DIM "backspace" UI_RESET " delete"
        );
        return;
    }

    const char *target_hint =
        (view->item_count > 0 && view->items[view->cursor].has_custom)
            ? UI_DIM "t" UI_RESET " target  "
            : "";

    if (view->modified) {
        fprintf(
            stdout,
            UI_DIM "↑↓" UI_RESET " navigate  "
            UI_DIM "space" UI_RESET " toggle  "
            UI_DIM "J/K" UI_RESET " move  "
            "%s"
            UI_BOLD_YELLOW "w" UI_RESET " " UI_BOLD_YELLOW "save" UI_RESET "  "
            UI_DIM "q" UI_RESET " quit",
            target_hint
        );
    } else {
        fprintf(
            stdout,
            UI_DIM "↑↓" UI_RESET " navigate  "
            UI_DIM "space" UI_RESET " toggle  "
            UI_DIM "J/K" UI_RESET " move  "
            "%s"
            UI_DIM "q" UI_RESET " quit",
            target_hint
        );
    }
}

/* Layout: header + blank + items + blank + footer = 4 fixed + items. */
static int view_required_lines(const view_t *view) {
    return (int) view->item_count + 4;
}

static int view_render(const view_t *view) {
    render_header(view);
    fprintf(stdout, "\r" ANSI_CLEAR_LINE "\r\n");
    for (size_t i = 0; i < view->item_count; i++) {
        row_render(view, i);
    }
    fprintf(stdout, "\r" ANSI_CLEAR_LINE "\r\n");
    render_footer(view);
    fflush(stdout);
    return view_required_lines(view);
}

/* --- Input --- */

/* Prompt mode: every navigation/save/quit key loses its TUI meaning by
 * key-set shadowing — they are valid bytes in a path. Only Enter
 * (commit), Esc/Ctrl-C/Ctrl-D (cancel), Backspace, and printable bytes
 * are honored. Effects are in-memory and recoverable; OOM at commit
 * keeps the prompt open so the user can retry. */
static interactive_result_t handle_key_prompt(view_t *view, int key) {
    prompt_t *p = &view->prompt;

    switch (key) {
        case TERM_KEY_ENTER: {
            if (p->len == 0) {
                /* Empty Enter is a no-op; Esc is the cancel key. */
                return INTERACTIVE_CONTINUE;
            }
            char *captured = strdup(p->buffer);
            if (!captured) {
                return INTERACTIVE_CONTINUE;
            }
            item_t *it = &view->items[p->item_index];
            /* Replace whatever target was on the item (NULL for capture,
             * the prior string for edit). free(NULL) is safe. */
            free(it->target);
            it->target = captured;
            if (p->enable) {
                /* Capture path: the prompt was the gate guarding OFF→ON. */
                it->enabled = true;
            }
            view->modified = true;
            prompt_close(p);
            return INTERACTIVE_CONTINUE;
        }

        case TERM_KEY_ESCAPE:
        case TERM_KEY_CTRL_C:
        case TERM_KEY_CTRL_D:
            prompt_close(p);
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_BACKSPACE:
            if (p->len > 0) {
                p->buffer[--p->len] = '\0';
            }
            return INTERACTIVE_CONTINUE;

        default:
            /* Printable ASCII (0x20..0x7E) plus the high-bit band
             * (0x80..0xFF) for UTF-8 path bytes. 0x7F (DEL) is excluded
             * defensively — the terminal layer maps both 0x7F and 0x08
             * to TERM_KEY_BACKSPACE, so 0x7F should be unreachable. */
            if (key >= 0x20 && key <= 0xFF && key != 0x7F) {
                (void) prompt_push(p, (char) key);
            }
            return INTERACTIVE_CONTINUE;
    }
}

static interactive_result_t handle_key_normal(
    view_t *view, git_repository *repo, state_t *deploy_state,
    arena_t *arena, int key, error_t **out_err
) {
    switch (key) {
        case TERM_KEY_UP:
        case 'k':
            if (view->cursor > 0) {
                view->cursor--;
            }
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_DOWN:
        case 'j':
            if (view->cursor + 1 < view->item_count) {
                view->cursor++;
            }
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_HOME:
        case 'g':
            view->cursor = 0;
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_END:
        case 'G':
            if (view->item_count > 0) {
                view->cursor = view->item_count - 1;
            }
            return INTERACTIVE_CONTINUE;

        case TERM_KEY_SPACE: {
            if (view->cursor >= view->item_count) {
                return INTERACTIVE_CONTINUE;
            }
            item_t *it = &view->items[view->cursor];
            bool toggling_on = !it->enabled;

            /* Three-gate trigger: prompt opens iff (1) row has custom
             * files, (2) toggle is OFF→ON, (3) no target captured or
             * seeded yet. The captured target survives transient
             * toggle-off / toggle-on cycles within a session, so a
             * re-enable skips the prompt naturally via gate 3. */
            if (toggling_on && it->has_custom && it->target == NULL) {
                prompt_open_capture(&view->prompt, view->cursor);
                return INTERACTIVE_CONTINUE;
            }

            it->enabled = !it->enabled;
            view->modified = true;
            return INTERACTIVE_CONTINUE;
        }

        case 't':
        case 'T': {
            /* Edit existing target on a custom-bearing row. Same prompt
             * as space but with enable cleared so committing only
             * updates the target string. No-op on non-custom rows. */
            if (view->cursor >= view->item_count) {
                return INTERACTIVE_CONTINUE;
            }
            item_t *it = &view->items[view->cursor];
            if (!it->has_custom) {
                return INTERACTIVE_CONTINUE;
            }
            prompt_open_edit(&view->prompt, view->cursor, it->target);
            return INTERACTIVE_CONTINUE;
        }

        case 'K':
            move_up(view);
            return INTERACTIVE_CONTINUE;

        case 'J':
            move_down(view);
            return INTERACTIVE_CONTINUE;

        case 'w':
        case 'W': {
            if (!view->modified) {
                return INTERACTIVE_CONTINUE;
            }
            error_t *err = save_order(repo, deploy_state, arena, view);
            if (err) {
                *out_err = err;
                return INTERACTIVE_EXIT_ERROR;
            }
            return INTERACTIVE_CONTINUE;
        }

        case 'q':
        case 'Q':
        case TERM_KEY_ESCAPE:
        case TERM_KEY_CTRL_C:
        case TERM_KEY_CTRL_D:
            return INTERACTIVE_EXIT_OK;

        default:
            return INTERACTIVE_CONTINUE;
    }
}

static interactive_result_t view_handle_key(
    view_t *view, git_repository *repo, state_t *deploy_state,
    arena_t *arena, int key, error_t **out_err
) {
    *out_err = NULL;
    if (view->prompt.active) {
        return handle_key_prompt(view, key);
    }
    return handle_key_normal(view, repo, deploy_state, arena, key, out_err);
}

/* --- Run --- */

/* Reject the session if the terminal can't host the static row layout.
 *
 * Row geometry: "  " + cursor + " " + checkbox + " " + name + annotation.
 * The static prefix is ROW_PREFIX_COLS; the worst static annotation is
 * " (custom)" at ROW_ANNOTATION_COLS. The dynamic "→ <target>" can run
 * longer than that, but it is user data and its visual overflow is
 * allowed to wrap rather than block startup. Same logic applies to the
 * mid-session "Target: <buffer>" overlay. */
static error_t *check_screen(const view_t *view) {
    terminal_size_t size;
    error_t *err = terminal_get_size(&size);
    if (err) return err;

    int required_lines = view_required_lines(view);
    if (required_lines > size.rows) {
        return error_create(
            ERR_INVALID_ARG, "terminal too small (need %d lines, have %d)",
            required_lines, size.rows
        );
    }

    size_t max_name = 0;
    for (size_t i = 0; i < view->item_count; i++) {
        size_t len = strlen(view->items[i].name);
        if (len > max_name) {
            max_name = len;
        }
    }
    size_t worst_width = ROW_PREFIX_COLS + max_name + ROW_ANNOTATION_COLS;
    if (worst_width > (size_t) size.cols) {
        return error_create(
            ERR_INVALID_ARG, "terminal too narrow (longest profile name: "
            "%zu chars, need %zu columns, have %d)",
            max_name, worst_width, size.cols
        );
    }
    return NULL;
}

static error_t *view_loop(
    view_t *view, git_repository *repo, state_t *deploy_state,
    arena_t *arena, int initial_lines
) {
    int lines_drawn = initial_lines;
    interactive_result_t result = INTERACTIVE_CONTINUE;
    error_t *loop_err = NULL;

    while (result == INTERACTIVE_CONTINUE) {
        int key = terminal_read_key();
        result = view_handle_key(
            view, repo, deploy_state, arena, key, &loop_err
        );
        if (result == INTERACTIVE_CONTINUE) {
            terminal_cursor_up(lines_drawn - 1);
            lines_drawn = view_render(view);
        }
    }

    if (result == INTERACTIVE_EXIT_ERROR) {
        return loop_err
            ? loop_err
            : ERROR(ERR_INTERNAL, "interactive mode exited with error");
    }
    return NULL;
}

static error_t *interactive_run(
    git_repository *repo, state_t *deploy_state, arena_t *arena
) {
    if (!terminal_is_tty()) {
        return error_create(ERR_INVALID_ARG, "interactive mode requires a TTY");
    }

    terminal_t *term TERMINAL_CLEANUP = NULL;
    error_t *err = terminal_init(&term);
    if (err) return err;

    view_t *view VIEW_AUTO = NULL;
    err = view_create(repo, deploy_state, &view);
    if (err) return err;

    err = check_screen(view);
    if (err) return err;

    terminal_cursor_hide();
    int lines = view_render(view);

    err = view_loop(view, repo, deploy_state, arena, lines);

    /* Always move past the UI before terminal_restore brings the cursor
     * back, regardless of whether the loop exited cleanly or with an
     * error. VIEW_AUTO and TERMINAL_CLEANUP handle the rest. */
    fprintf(stdout, "\r\n");
    fflush(stdout);
    return err;
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
     * by `.name`; `.root_aliases` covers only the flag-prefixed forms. */
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
        "  t               Set/edit deployment target\n"
        "  w               Save profile order and choice\n"
        "  q, ESC          Quit\n"
        "\n"
        "Target prompt:\n"
        "  enter           Commit the target\n"
        "  esc             Cancel\n"
        "  backspace       Delete last character\n"
        "\n"
        "Notes:\n"
        "  - Enabled profiles are saved to state in the displayed order\n"
        "  - Profile order determines layering (later overrides earlier)\n"
        "  - Toggling on a custom/-bearing profile opens an inline target prompt\n"
        "  - Use regular commands (apply, update, sync) after enabling profiles\n",
    .payload      = &dotta_ext_read,
    .dispatch     = interactive_dispatch,
};
