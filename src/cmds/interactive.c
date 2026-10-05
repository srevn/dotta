/**
 * interactive.c - Interactive TUI for profile management and ordering
 *
 * Single-entrypoint module. Inline raw-mode interface that lets the user select,
 * reorder, and target-bind profiles before applying them. The public surface is
 * exactly `spec_interactive`; everything below is file-local.
 */

#include "cmds/interactive.h"

#include <limits.h>
#include <runtime.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/heap.h"
#include "base/output.h"
#include "base/string.h"
#include "base/terminal.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/identity.h"

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
/* Worst static annotation: " (needs a target)" = 17 visible columns. */
#define ROW_ANNOTATION_COLS   17

/* The prompt's reserved bytes; an append past them grows as any buffer grows. */
#define PROMPT_INITIAL_CAP    256

/* --- Types --- */

typedef struct {
    const char *name;      /* Profile name, the listing's */
    const char *target;    /* The store's spelling, or text this session typed */
    bool enabled;          /* Selected for save; toggled by space, persisted by view_save */
    bool needs_target;     /* A claim of the profile needs a binding (core/profiles.h) */
    bool unreadable;       /* The profile would not read: the seed absorbed it, the row says so */
} item_t;

typedef struct {
    buffer_t buffer;       /* The input typed so far: the heap's, given back at the session's end */
    size_t item_index;     /* Row anchor (view->items index) the prompt is over */
    bool active;           /* True while the prompt overlay is open */
    bool enable;           /* True iff opened by space on a row that needs a target (commit flips enabled) */
} prompt_t;

typedef struct {
    arena_t *arena;        /* The command arena: the view, its rows and every target the session sets */
    item_t *items;         /* Profile rows */
    size_t item_count;     /* Number of valid entries in items */
    size_t cursor;         /* Selected row (0..item_count-1; valid iff item_count > 0) */
    bool modified;         /* Unsaved edits pending; cleared by a successful view_save */
    prompt_t prompt;       /* Inline target-capture overlay state */
} view_t;

typedef enum {
    INTERACTIVE_CONTINUE,     /* Keep looping; re-render and read next key */
    INTERACTIVE_SAVE,         /* Save the edits (view_save), then keep looping */
    INTERACTIVE_EXIT          /* The session ends: a quit key, or the input's end */
} interactive_result_t;

/* Save-time diff plan: made in the view's arena at each save, new_order's names
 * copies made there, and abandoned there once the save ends — O(profiles) bytes
 * per save, and a save is human-paced, the reason a replaced target is abandoned
 * too. */
typedef struct {
    string_array_t new_order;  /* Ordered enabled names, in display order */
    item_t **new_order_items;  /* Parallel pointers into view->items (same indexing as new_order) */
    bool *needs_enable;        /* Per new_order row: true iff row needs a state_enable_profile write */
    char **removal_names;      /* Arena-strdup'd persisted names absent from new_order */
    size_t removal_count;      /* Number of valid entries in removal_names */
} plan_t;

/* --- Items --- */

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
    buffer_clear(&p->buffer);
}

/* Opening helpers — mirror prompt_close so the input dispatcher never reaches
 * into the prompt's representation. */
static void prompt_open_capture(prompt_t *p, size_t item_index) {
    p->active = true;
    p->enable = true;
    p->item_index = item_index;
    /* Buffer is empty (prompt_close on the prior cycle, the reserve on the first). */
}

static void prompt_open_edit(prompt_t *p, size_t item_index, const char *current) {
    p->active = true;
    p->enable = false;
    p->item_index = item_index;
    /* The empty buffer takes the row's target, and stays empty when it has none. */
    if (current) buffer_append_string(&p->buffer, current);
}

/* --- View lifecycle --- */

/* Allocate view->items and populate name/enabled. */
static error_t build_items(git_repository *repo, state_t *deploy_state, view_t *view) {
    arena_t *arena = view->arena;

    string_array_t all_profiles;
    error_t err = gitops_list_branches(repo, arena, &all_profiles);
    if (err) return err;

    if (all_profiles.count == 0) {
        return error_create(ERR_NOT_FOUND, "No profiles found in repository");
    }

    /* First-run case: a handle whose underlying DB doesn't exist holds a load
     * of zero rows, which is the correct empty enabled set rather than a failure
     * to absorb. Save via 'w' publishes the store's dotta.db in state_begin.
     * The rows are read where the handle holds them: nothing here moves them
     * (core/state.h state_profiles). */
    state_profiles_t enabled_profiles = state_profiles(deploy_state);

    /* Each name to its index, the arena's: hashmap_find tells index 0 from a
     * name the map does not hold. */
    hashmap_t *profile_map = hashmap_borrow(arena, all_profiles.count);
    for (size_t i = 0; i < all_profiles.count; i++) {
        hashmap_set(profile_map, all_profiles.entries[i], (void *) (uintptr_t) i);
    }

    /* The rows, and which listed names an enabled row took. Every name is the
     * listing's, the view's arena's as the rows are — never the state's row cache,
     * which a save replaces while the session goes on. */
    bool *used = arena_calloc(arena, all_profiles.count, sizeof(*used));
    view->items = arena_calloc(arena, all_profiles.count, sizeof(*view->items));

    /* Pass A: enabled profiles in their saved order. */
    for (size_t i = 0; i < enabled_profiles.count; i++) {
        void *found = NULL;
        if (!hashmap_find(profile_map, enabled_profiles.entries[i].name, &found)) {
            /* Persisted name no longer exists locally — drop silently. */
            continue;
        }
        size_t at = (size_t) (uintptr_t) found;
        used[at] = true;
        view->items[view->item_count++] = (item_t){
            .name = all_profiles.entries[at], .enabled = true
        };
    }

    /* Pass B: remaining profiles, disabled, in list order. */
    for (size_t i = 0; i < all_profiles.count; i++) {
        if (used[i]) continue;
        view->items[view->item_count++] = (item_t){ .name = all_profiles.entries[i] };
    }

    return NULL;
}

/* Pass two, the target column of every row: the binding an enabled row holds
 * (its arrow), and whether its profile needs one (its mark, and the OFF→ON gate)
 * — both read up front so a keystroke never reads Git: the gate is a field test,
 * where a lazy probe would be a tree read inside a raw-mode handler, visible
 * latency on the first space.
 *
 * The binding first, and it cannot fail: the row's target is the store's fact
 * whatever the profile says, so a profile that will not read keeps its arrow.
 * It borrows from state_target's row cache, whose lifetime ends at the next
 * state_enable/disable/reorder; save runs those much later, so the copy — the
 * view's arena's — crosses the boundary now.
 *
 * The need is absorbed, not propagated: the editor is the way out of an enabled
 * set the next load cannot build. A sheet this build refuses on one enabled profile
 * kills status; here SPACE disables the profile and `w` saves, plan_check building
 * over the post-mutation set — the door tests/test-claims.sh pins for `profile
 * disable`, and a strict seed would close it. The row says what the seed could
 * not, and is not gated: we do not know, so we do not prompt. */
static void read_targets(git_repository *repo, state_t *deploy_state, view_t *view) {
    for (size_t i = 0; i < view->item_count; i++) {
        item_t *it = &view->items[i];

        /* The binding the store holds for this row — only an enabled row has
         * one, the word cmd_add spells the same read with. */
        const char *bound = it->enabled
            ? state_target(deploy_state, it->name) : NULL;
        if (bound) {
            it->target = arena_strdup(view->arena, bound);
        }

        /* The need, absorbed (above), asked of the profile at its tip: the error
         * is dropped, one per row whose profile will not read. */
        profile_t *profile = NULL;
        error_t err = profile_load(repo, it->name, &profile);
        if (!err) err = profile_needs_target(profile, &it->needs_target);
        profile_free(profile);
        if (err) {
            it->unreadable = true;
        }
    }
}

/* The view, made in `arena` and remembering it: its rows, their names and every
 * target the session sets live there, and nothing frees one. An edit is
 * human-paced, so a target the session replaces is abandoned in the arena — one
 * string per committed prompt. The prompt's text is the heap's, the one part
 * the session gives back (interactive_run). */
static error_t view_create(
    git_repository *repo, state_t *deploy_state, arena_t *arena, view_t **out
) {
    view_t *view = arena_calloc(arena, 1, sizeof(*view));
    view->arena = arena;

    error_t err = build_items(repo, deploy_state, view);
    if (err) return err;
    read_targets(repo, deploy_state, view);

    *out = view;
    return NULL;
}

/* --- Reorder --- */

static void move_up(view_t *view) {
    if (view->cursor == 0) return;
    swap_items(view->items, view->cursor, view->cursor - 1);
    view->cursor--;
    view->modified = true;
}

static void move_down(view_t *view) {
    if (view->cursor + 1 >= view->item_count) return;
    swap_items(view->items, view->cursor, view->cursor + 1);
    view->cursor++;
    view->modified = true;
}

/* --- Save plan --- */

/* Phase: collect enabled rows in display order. Pure view sweep; no state
 * interaction. */
static void plan_collect(view_t *view, plan_t *plan) {
    string_array_init(&plan->new_order, view->arena);

    if (view->item_count > 0) {
        plan->new_order_items = arena_calloc(
            view->arena, view->item_count, sizeof(*plan->new_order_items)
        );
    }

    size_t k = 0;
    for (size_t i = 0; i < view->item_count; i++) {
        if (!view->items[i].enabled) continue;
        string_array_push(&plan->new_order, view->items[i].name);
        plan->new_order_items[k++] = &view->items[i];
    }
}

/* Phase: classify diff against the persisted set BEFORE any state mutation, reading
 * each target the session typed — a refusal ends the save there.
 *
 * state_profiles lends the row cache, which the first state_enable/disable call
 * replaces, so everything a row has to give is decided or copied here, while
 * the borrows are live: needs_enable (additions, plus retained rows whose target
 * names another directory), removal_names (arena-strdup'd so they outlive the
 * slice), and the spelling a retained binding keeps, copied onto the item that
 * offered another for it. All of it into the view's arena: the plan's, and the
 * item's, which lives there.
 *
 * A row's target is the store's own spelling or the text the session typed
 * (handle_key_prompt), told apart by the question the save asks of it: does the
 * store hold this binding as written? A NULL target is legitimate on every row:
 * one that needs no target has nothing to place, and one that needs a target
 * and is saved without it is a normal lifecycle stage the health channel names
 * (core/manifest.h manifest_unbound) — the OFF→ON prompt asks for a target, a
 * row already enabled without one keeps that, and nothing downstream refuses
 * either. No second guard here. */
static error_t plan_classify(state_t *deploy_state, view_t *view, plan_t *plan) {
    state_profiles_t persisted = state_profiles(deploy_state);

    if (plan->new_order.count > 0) {
        plan->needs_enable = arena_calloc(
            view->arena, plan->new_order.count, sizeof(*plan->needs_enable)
        );
    }
    if (persisted.count > 0) {
        plan->removal_names = arena_calloc(
            view->arena, persisted.count, sizeof(*plan->removal_names)
        );
    }

    /* Walk persisted; a linear search beats a hashmap on these tiny sets (typically
     * < 10 profiles). */
    for (size_t i = 0; i < persisted.count; i++) {
        const char *p_name = persisted.entries[i].name;
        if (string_array_contains(&plan->new_order, p_name)) continue;

        plan->removal_names[plan->removal_count++] = arena_strdup(view->arena, p_name);
    }

    /* Walk new_order; read each target the session typed, and flag rows that
     * must be re-written via state_enable_profile. */
    for (size_t i = 0; i < plan->new_order.count; i++) {
        item_t *it = plan->new_order_items[i];
        bool was_enabled = false;
        const char *persisted_target = NULL;
        for (size_t j = 0; j < persisted.count; j++) {
            if (strcmp(persisted.entries[j].name, it->name) == 0) {
                was_enabled = true;
                persisted_target = persisted.entries[j].target;
                break;
            }
        }

        /* Every text but the row's own spelling is read now, through the binders'
         * one door (infra/path.h path_input_target), at the moment the target
         * is written: a refusal is the door's or the rules' in their own words,
         * and the item takes the spelling it read, the one the store keeps. The
         * row's own spelling is the binding the store holds and is not read again,
         * so a save that touches no target stands over a directory gone since. */
        if (it->target != NULL &&
            (persisted_target == NULL || strcmp(it->target, persisted_target) != 0)) {
            const char *target = NULL;
            error_t err = path_input_target(it->target, view->arena, &target);
            if (err) {
                return error_wrap(
                    err, "Invalid deployment target for profile '%s'", it->name
                );
            }
            it->target = target;
        }

        if (!was_enabled) {
            plan->needs_enable[i] = true;
            continue;
        }
        /* Retained with nothing pending: a NULL is no offer of a target — the
         * UPSERT keeps the row's for one (state_enable_profile), and no key unbinds
         * — so the row stands as it is and this flag keeps the zero it was
         * allocated with. */
        if (!it->target) continue;

        /* Re-enable only when the pending target names a directory the row does
         * not hold — the row's own under another spelling is the same binding
         * (mount_same_target), and the row keeps its spelling, the key of every
         * path beneath it (infra/mount.h). */
        plan->needs_enable[i] = persisted_target == NULL ||
            !mount_same_target(persisted_target, it->target);

        /* A same-directory target is the one edit this save declines while the
         * session goes on, and the row it is shown on is the only sentence this
         * editor has: the two CLI binders answer one with a line at NORMAL
         * (cmds/profile.c, cmds/add.c), while here the items are built once, at
         * open, with nothing reloaded after the commit — so an item left holding
         * the spelling the save threw away would render it on every screen after,
         * and seed the next prompt with it. It takes the row's instead. Not a
         * reconciliation with the store: what is put back is this save's own
         * decision, which is why a NULL (no offer) and an equal string (nothing
         * declined) are both left alone. The spelling it replaces is abandoned
         * in the view's arena. */
        if (!plan->needs_enable[i] && strcmp(it->target, persisted_target) != 0) {
            it->target = arena_strdup(view->arena, persisted_target);
        }
    }
    return NULL;
}

/* Phase: apply the diff. Enables first (cache holds every reorder name when reorder
 * runs), removals next, reorder last over the post-diff set. Each enable/disable
 * re-reads the row cache after its write, so reorder's precondition reads the
 * post-diff set. */
static error_t plan_apply(state_t *deploy_state, const plan_t *plan) {
    for (size_t i = 0; i < plan->new_order.count; i++) {
        if (!plan->needs_enable[i]) continue;
        const item_t *it = plan->new_order_items[i];

        error_t err = state_enable_profile(deploy_state, it->name, it->target);
        if (err) return err;
    }

    for (size_t i = 0; i < plan->removal_count; i++) {
        error_t err = state_disable_profile(deploy_state, plan->removal_names[i]);
        if (err) return err;
    }

    return state_reorder_profiles(deploy_state, &plan->new_order);
}

/* Phase: build the view over the post-mutation binding set — the enabled set as
 * the state now holds it, which is what the next load will read. The view is
 * computed, never stored — the build writes nothing and its result is discarded.
 * It is the tripwire that keeps the save from landing an enabled set the next
 * load cannot build: a branch that exists but will not load. Not a target gate
 * — the build is total over a custom/ claim whose profile has no binding, which
 * contributes no row and is recorded for the health channel to say (core/manifest.h
 * manifest_unbound) — so an unbound row saves here as a clone's and a sync's do.
 *
 * Built only to learn that it can be, in a frame of the check's own, freed before
 * the answer: a session of N saves holds no view, where the view's arena would
 * hold one per save. The error outlives the frame: it lives in the errors' own
 * arena (base/error.h "Lifetime"). */
static error_t plan_check(git_repository *repo, state_t *deploy_state) {
    arena_t *frame = arena_create(0);
    manifest_t *view = NULL;
    error_t err = manifest_build(repo, deploy_state, frame, &view);
    arena_free(frame);
    return err;
}

/* Save orchestrator. Holds a scoped write transaction for the diff window only;
 * declaring WRITE at the spec level would hold BEGIN IMMEDIATE for the whole
 * session, blocking other dotta processes. The plan is built in the view's arena
 * (plan_t), the view it checks in a frame of the check's own (plan_check). */
static error_t view_save(git_repository *repo, state_t *deploy_state, view_t *view) {
    plan_t plan = { 0 };
    plan_collect(view, &plan);

    /* Refuse a save that would empty enabled_profiles. Checked here — after collect
     * — instead of via a cached counter on view: the items array is the single
     * source of truth for "is this enabled?". A sibling counter would be a cache
     * of a cache. */
    if (plan.new_order.count == 0) {
        return error_create(ERR_INVALID_ARG, "No profiles enabled");
    }

    error_t err = state_begin(deploy_state);
    if (err) return err;

    err = plan_classify(deploy_state, view, &plan);
    if (err) goto rollback;

    err = plan_apply(deploy_state, &plan);
    if (err) goto rollback;

    err = plan_check(repo, deploy_state);
    if (err) goto rollback;

    err = state_commit(deploy_state);
    if (err) goto rollback;

    /* A row the save did not enable carries no binding past it. A target held
     * on a disabled row — typed with `t`, or captured at the prompt and toggled
     * off again — renders as an arrow, and once (modified) clears every arrow
     * on the screen is the store's; this one the store never took. Released here
     * and not refused at `t`: setting the target and then toggling on is a way
     * to enable, and the survival across a toggle-off is the capture's own promise
     * (handle_key_normal) for the window before a save. The precedent is
     * plan_classify's write-back: the item takes what the save decided, never
     * what it happened to hold. */
    for (size_t i = 0; i < view->item_count; i++) {
        if (view->items[i].enabled) continue;
        view->items[i].target = NULL;
    }
    view->modified = false;
    return NULL;

rollback:
    state_rollback(deploy_state);
    return err;
}

/* --- Render --- */

/* A datum onto the row, as a terminal may show it: a profile's name, a target,
 * the text typed at the prompt — each spelled by str_display (base/string.h),
 * whole, so no byte one holds moves the cursor or sets a colour in the editor's
 * screen. Measured, then spelled into the heap: a row is redrawn per key, and a
 * datum has no bound a row can promise. */
static void interactive_datum(const char *datum) {
    size_t len = strlen(datum);
    size_t shown = str_display(NULL, 0, datum, len);
    char *spelled = heap_alloc(shown + 1);
    str_display(spelled, shown + 1, datum, len);
    fputs(spelled, stdout);
    free(spelled);
}

/* Four row shapes, all the same line count:
 *   1. Prompt-active   "  ▶   Target: <buffer>_"
 *   2. Bound           "  ▶ ✓ name → <target>"
 *   3. Needs a target  "    name (needs a target)"
 *   4. Unreadable      "    name (unreadable)"
 *
 * Trailing '_' is the visible caret; hardware cursor stays hidden for the whole
 * session. Every datum prints through interactive_datum, the row's layout through
 * its own fprintf; stdout is line-buffered and view_render emits a single
 * fflush. */
static void row_render(const view_t *view, size_t i) {
    const item_t *it = &view->items[i];
    bool is_cursor = (i == view->cursor);
    bool is_prompt = (view->prompt.active && i == view->prompt.item_index);

    fprintf(stdout, "\r" ANSI_CLEAR_LINE);

    if (is_prompt) {
        /* The cursor is always on the prompt row by construction (prompt_open_*
         * anchors item_index to view->cursor and navigation keys are shadowed
         * while active). */
        fputs("  " UI_CURSOR "   " UI_BOLD "Target:" UI_RESET " ", stdout);
        interactive_datum(view->prompt.buffer.data);
        fputs("_\r\n", stdout);
        return;
    }

    const char *cursor_glyph = is_cursor ? UI_CURSOR : " ";
    const char *checkbox = it->enabled ? UI_CHECK : " ";
    bool dim_name = !it->enabled && !is_cursor;
    const char *name_open = dim_name ? UI_DIM : "";
    const char *name_close = dim_name ? UI_RESET : "";

    fprintf(stdout, "  %s %s %s", cursor_glyph, checkbox, name_open);
    interactive_datum(it->name);
    fputs(name_close, stdout);

    /* Three questions, in order. Does the row hold a binding — the store's, or
     * this session's? Shown wherever one is held: on a home-only row bound on
     * purpose, as profile list and status show it; and on a disabled row, where
     * it is what the next toggle-on writes (view_save releases it if no save
     * takes it). Could the seed not say? Does the profile need a binding it has
     * not got — the same answer status prints for an enabled row, and here `t`
     * is the remedy. */
    if (it->target) {
        char shown[PATH_MAX];
        output_format_path(it->target, identity()->home, shown, sizeof(shown));
        fputs(" " UI_DIM "→ ", stdout);
        interactive_datum(shown);
        fputs(UI_RESET, stdout);
    } else if (it->unreadable) {
        fprintf(stdout, " " UI_DIM "(unreadable)" UI_RESET);
    } else if (it->needs_target) {
        fprintf(stdout, " " UI_DIM "(needs a target)" UI_RESET);
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

    /* `t` is named where it is live: on a row whose profile needs a target
     * (handle_key_normal). */
    const char *target_hint =
        (view->item_count > 0 && view->items[view->cursor].needs_target)
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

/* Prompt mode: every navigation/save/quit key loses its TUI meaning by key-set
 * shadowing — they are valid bytes in a path. Only Enter (commit),
 * Esc/Ctrl-C/Ctrl-D (cancel), Backspace, and printable bytes are honored. Effects
 * are in-memory and recoverable. */
static interactive_result_t handle_key_prompt(view_t *view, int key) {
    prompt_t *p = &view->prompt;

    switch (key) {
        case TERM_KEY_ENTER: {
            if (p->buffer.size == 0) {
                /* Empty Enter is a no-op; Esc is the cancel key. */
                return INTERACTIVE_CONTINUE;
            }
            /* The text as typed — absolute, tilde, or relative to the working
             * directory, like a shell's — the row's until the save reads it
             * (plan_classify): a target is read where it is written, so a refusal
             * is said once, in its reader's words, and nothing is read here.
             * The copy is the view's arena's, and the target it replaces — NULL
             * for capture, the prior text for edit — is abandoned there. */
            item_t *it = &view->items[p->item_index];
            it->target = arena_strdup(view->arena, p->buffer.data);
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
            if (p->buffer.size > 0) {
                buffer_resize(&p->buffer, p->buffer.size - 1);
            }
            return INTERACTIVE_CONTINUE;

        default:
            /* Printable ASCII (0x20..0x7E) plus the high-bit band (0x80..0xFF)
             * for UTF-8 path bytes. 0x7F (DEL) is excluded defensively — the
             * terminal layer maps both 0x7F and 0x08 to TERM_KEY_BACKSPACE, so
             * 0x7F should be unreachable. */
            if (key >= 0x20 && key <= 0xFF && key != 0x7F) {
                const char byte = (char) key;
                buffer_append(&p->buffer, &byte, 1);
            }
            return INTERACTIVE_CONTINUE;
    }
}

static interactive_result_t handle_key_normal(view_t *view, int key) {
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

            /* Three-gate trigger: prompt opens iff (1) the profile needs a target,
             * (2) toggle is OFF→ON, (3) no target captured or seeded yet. The
             * captured target survives transient toggle-off / toggle-on cycles
             * within a session, so a re-enable skips the prompt naturally via
             * gate 3 (until a save releases it: view_save). A row the seed could
             * not read needs nothing it can say, so it toggles without a prompt
             * and plan_check refuses the save that would enable it. */
            if (toggling_on && it->needs_target && it->target == NULL) {
                prompt_open_capture(&view->prompt, view->cursor);
                return INTERACTIVE_CONTINUE;
            }

            it->enabled = !it->enabled;
            view->modified = true;
            return INTERACTIVE_CONTINUE;
        }

        case 't':
        case 'T': {
            /* Set or edit the target on a row whose profile needs one: the same
             * prompt as space, with enable cleared so committing only sets the
             * string. No-op on a row that needs none — a binding places custom/
             * claims, and a profile with none has nothing for one to place. On
             * a disabled row the target is what the next toggle-on writes. */
            if (view->cursor >= view->item_count) {
                return INTERACTIVE_CONTINUE;
            }
            item_t *it = &view->items[view->cursor];
            if (!it->needs_target) {
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
        case 'W':
            return view->modified ? INTERACTIVE_SAVE : INTERACTIVE_CONTINUE;

        case 'q':
        case 'Q':
        case TERM_KEY_ESCAPE:
        case TERM_KEY_CTRL_C:
        case TERM_KEY_CTRL_D:
            return INTERACTIVE_EXIT;

        default:
            return INTERACTIVE_CONTINUE;
    }
}

static interactive_result_t view_handle_key(view_t *view, int key) {
    /* No key at all — the input stream ended, or the read failed (base/terminal.h):
     * the quit Ctrl-D already spells, taken above both dispatchers because each
     * would take it for a key it does not know, ignore it, and read the same
     * answer again for as long as the loop runs. The terminal going away usually
     * sends SIGHUP first and the process ends there; a pty closed by something
     * that is not the session leader sends nothing, and this is the whole of
     * what stops the session. A prompt open at that moment is abandoned, as Esc
     * then q abandons it. */
    if (key < 0) {
        return INTERACTIVE_EXIT;
    }

    if (view->prompt.active) {
        return handle_key_prompt(view, key);
    }
    return handle_key_normal(view, key);
}

/* --- Run --- */

/* Reject the session if the terminal can't host the static row layout.
 *
 * Row geometry: "  " + cursor + " " + checkbox + " " + name + annotation.
 * The static prefix is ROW_PREFIX_COLS; the worst static annotation is " (needs
 * a target)" at ROW_ANNOTATION_COLS. The dynamic "→ <target>" can run longer
 * than that, but it is user data and its visual overflow is allowed to wrap rather
 * than block startup. Same logic applies to the mid-session "Target: <buffer>"
 * overlay. */
static error_t check_screen(const view_t *view) {
    terminal_size_t size;
    error_t err = terminal_get_size(&size);
    if (err) return err;

    int required_lines = view_required_lines(view);
    if (required_lines > size.rows) {
        return error_create(
            ERR_INVALID_ARG, "Terminal too small (need %d lines, have %d)",
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
            ERR_INVALID_ARG, "Terminal too narrow (longest profile name: "
            "%zu chars, need %zu columns, have %d)",
            max_name, worst_width, size.cols
        );
    }
    return NULL;
}

static error_t view_loop(
    view_t *view, git_repository *repo, state_t *deploy_state, int initial_lines
) {
    int lines_drawn = initial_lines;

    /* A key's handler decides what comes next and the loop does it: the save is
     * the one step that can fail, and its failure ends the session. */
    for (;;) {
        switch (view_handle_key(view, terminal_read_key())) {
            case INTERACTIVE_CONTINUE:
                break;

            case INTERACTIVE_SAVE: {
                error_t err = view_save(repo, deploy_state, view);
                if (err) return err;
                break;
            }

            case INTERACTIVE_EXIT:
                return NULL;
        }

        terminal_cursor_up(lines_drawn - 1);
        lines_drawn = view_render(view);
    }
}

static error_t interactive_run(
    git_repository *repo, state_t *deploy_state, arena_t *arena
) {
    if (!terminal_is_tty()) {
        return error_create(ERR_INVALID_ARG, "Interactive mode requires a TTY");
    }

    terminal_t *term TERMINAL_CLEANUP = NULL;
    error_t err = terminal_init(&term);
    if (err) return err;

    view_t *view = NULL;
    err = view_create(repo, deploy_state, arena, &view);
    if (err) return err;

    err = check_screen(view);
    if (err) return err;

    terminal_cursor_hide();
    int lines = view_render(view);

    /* The prompt's text is the user's typing: a buffer, reserved so the keystroke
     * handler stays alloc-free on the common typing path, and given back when
     * the loop ends — the session's one exit past it. */
    buffer_reserve(&view->prompt.buffer, PROMPT_INITIAL_CAP);
    err = view_loop(view, repo, deploy_state, lines);
    buffer_deinit(&view->prompt.buffer);

    /* Always move past the UI before terminal_restore brings the cursor back,
     * regardless of whether the loop exited cleanly or with an error.
     * TERMINAL_CLEANUP handles the rest. */
    fprintf(stdout, "\r\n");
    fflush(stdout);
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

static error_t interactive_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    (void) opts_v;
    return interactive_run(ctx->run.repo, ctx->run.state, ctx->arena);
}

const args_command_t spec_interactive = {
    .name         = "interactive",
    .summary      = "Interactive profile management and ordering",
    /* Root-level flag aliases: `dotta --interactive` and `dotta -i` both dispatch
     * here. The bare `dotta interactive` form is served by `.name`; `.root_aliases`
     * covers only the flag-prefixed forms. */
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
        "  - Toggling on a profile that needs a target opens an inline target prompt\n"
        "  - A relative target is resolved from this directory, like a shell's\n"
        "  - Use regular commands (apply, update, sync) after enabling profiles\n",
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
    },
    .dispatch     = interactive_dispatch,
};
