/**
 * commit.c - Commit message template builder implementation
 */

#include "utils/commit.h"

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/identity.h"

/* Maximum length for hostname */
#define MAX_HOSTNAME 256

/* The names a heading shows before its tail counts the rest */
#define MAX_PATHS_DETAIL 5

/**
 * One template variable, and what it renders to
 *
 * The values a message is made of are resolved once and read by both substitutions,
 * so a title and a body cannot disagree about one of them, and the header's list
 * of variables is one row each (utils/commit.h) — a row being where the name
 * and the value are written beside each other, which is what makes a transposition
 * among ten same-typed strings a thing that cannot be written rather than a thing
 * that compiles.
 *
 * A value is never NULL: NULL is the reader's word for "no such variable", and
 * what it does with one is leave the template's own bytes standing. A variable
 * that is legitimately absent — a target commit outside a revert — renders empty,
 * which is the row's business and not the reader's.
 */
typedef struct {
    const char *name;    /* As a template spells it, without the braces */
    const char *value;   /* Never NULL */
} template_t;

/**
 * The host's name, written into `buf` — "unknown" where the kernel will not say
 */
static void commit_hostname(char *buf, size_t size) {
    if (gethostname(buf, size) != 0) {
        snprintf(buf, size, "unknown");
        return;
    }

    /* gethostname need not terminate a name it truncated */
    buf[size - 1] = '\0';
}

/**
 * The local time `now` in strftime's `format`, written into `buf` — "unknown"
 * where the clock cannot be read as local time
 *
 * Every time a message renders is this one instant's (commit_message reads the
 * clock once), so a `{date}` and a `{datetime}` cannot name two days.
 */
static void commit_time(time_t now, const char *format, char *buf, size_t size) {
    const struct tm *local = localtime(&now);
    if (!local || strftime(buf, size, format, local) == 0) snprintf(buf, size, "unknown");
}

/**
 * The action's name, as {action} renders it
 *
 * Every action, and no default arm: -Wswitch names this function and its past
 * tense the day a fifth action lands, where a default would have rendered the
 * new one "Unknown" into a commit nobody re-reads. What falls past the switch
 * is a value no enumerator names, which only a cast can produce, and it dies
 * rather than name itself "Unknown" there (base/error.h CHECK_ARG).
 */
static const char *commit_action_name(commit_action_t action) {
    switch (action) {
        case COMMIT_ACTION_ADD:    return "Add";
        case COMMIT_ACTION_UPDATE: return "Update";
        case COMMIT_ACTION_REMOVE: return "Remove";
        case COMMIT_ACTION_REVERT: return "Revert";
    }
    CHECK_ARG(false, "a commit action no enumerator names");
}

/**
 * The action's name in the past tense, as {action_past} renders it
 */
static const char *commit_action_name_past(commit_action_t action) {
    switch (action) {
        case COMMIT_ACTION_ADD:    return "Added";
        case COMMIT_ACTION_UPDATE: return "Updated";
        case COMMIT_ACTION_REMOVE: return "Removed";
        case COMMIT_ACTION_REVERT: return "Reverted";
    }
    CHECK_ARG(false, "a commit action no enumerator names");
}

/**
 * A name as display text, into the arena — or the name itself where nothing in
 * it needs spelling
 *
 * Its bytes as a terminal may show them (base/string.h str_display): a spelling
 * lengthens every byte it spells, so one as long as the name changed nothing.
 */
static const char *commit_spelled(arena_t *arena, const char *name) {
    size_t len = strlen(name);
    size_t shown = str_display(NULL, 0, name, len);
    if (shown == len) return name;

    char *spelled = arena_alloc(arena, shown + 1);
    str_display(spelled, shown + 1, name, len);

    return spelled;
}

/**
 * {paths}: each change under its heading — Added, Updated, Removed, in that order
 * — or, where the commit changes no explicit claim, the one line that says so
 *
 * A heading stands over a list that names something, and nowhere else. Each name
 * is spelled where it enters (commit_spelled); the headings, the bullets and
 * the newlines between them are the rendering's own.
 *
 * @param arena The arena a spelled name lives in (must not be NULL)
 * @param ctx The commit's changes (must not be NULL)
 * @param out The rendering (must not be NULL; cleared, then written, its bytes
 *            the caller's to free)
 */
static void commit_paths(
    arena_t *arena, const commit_message_context_t *ctx, buffer_t *out
) {
    const struct {
        const char *heading;
        const string_array_t *names;
    } changes[] = {
        { "Added:",   &ctx->added   },
        { "Updated:", &ctx->updated },
        { "Removed:", &ctx->removed },
    };

    *out = (buffer_t){ 0 };

    for (size_t c = 0; c < sizeof(changes) / sizeof(changes[0]); c++) {
        const string_array_t *names = changes[c].names;
        if (names->count == 0) continue;

        /* One commit's changes are one block: a heading stands beneath the list
         * before it, no blank line between */
        if (out->size > 0) buffer_append_string(out, "\n");
        buffer_append_string(out, changes[c].heading);

        /* Five names a heading, and a tail counting the rest beneath them: a
         * long change hides no other */
        size_t shown = names->count < MAX_PATHS_DETAIL ? names->count : MAX_PATHS_DETAIL;
        for (size_t i = 0; i < shown; i++) {
            buffer_append_string(out, "\n  - ");
            buffer_append_string(out, commit_spelled(arena, names->entries[i]));
        }

        size_t rest = names->count - shown;
        if (rest > 0) {
            buffer_appendf(out, "\n  ... and %zu more path%s", rest, rest == 1 ? "" : "s");
        }
    }

    /* No heading stood: the commit changes no explicit claim, so its edits moved
     * only the way to the claims — every writer's edit moves a claim or its way
     * (core/profiles.h profile_changes) — and the line in the headings' place
     * says so */
    if (out->size == 0) buffer_append_string(out, "Only ancestor claims changed");
}

/**
 * A template with its variables substituted, appended to `text`
 *
 * Replaces {variable} placeholders with the table's values. A name the table
 * has no row for is left as the template spelled it, braces and all, so a typo
 * empties no line and prose survives a stray brace.
 *
 * @param text Where the substitution is appended (must not be NULL)
 * @param template Template string with {variable} placeholders (must not be NULL)
 * @param vars The variables and their values, resolved once by the caller
 * @param var_count How many
 */
static void commit_substitute(
    buffer_t *text, const char *template, const template_t *vars, size_t var_count
) {
    CHECK_NULL(template);

    /* Process template character by character. Three cases, each leaving the
     * loop at its own line: what is not a variable, what is shaped like one and
     * cannot be read, and the name the table answers for. */
    const char *p = template;
    while (*p) {
        /* Where this variable would end. A brace nothing closes opens nothing:
         * it is a character of the template like any other, as is every character
         * that is not a brace at all. */
        const char *end = *p == '{' ? strchr(p, '}') : NULL;
        if (!end) {
            buffer_append(text, p, 1);
            p++;
            continue;
        }

        /* A name too long for the scratch is no name: the braced run stands as
         * the template spelled it, and the reader resumes past it. */
        size_t var_len = (size_t) (end - p - 1);
        char var_name[64];

        if (var_len >= sizeof(var_name)) {
            buffer_append(text, p, (size_t) (end - p) + 1);
            p = end + 1;
            continue;
        }

        memcpy(var_name, p + 1, var_len);
        var_name[var_len] = '\0';

        /* Substitute variable: the table's row, or no row at all */
        const char *value = NULL;
        for (size_t i = 0; i < var_count; i++) {
            if (strcmp(var_name, vars[i].name) == 0) {
                value = vars[i].value;
                break;
            }
        }

        if (value) {
            buffer_append_string(text, value);
        } else {
            /* Unknown variable - keep as-is */
            buffer_appendf(text, "{%s}", var_name);
        }

        p = end + 1;
    }
}

/**
 * Build commit message from context
 */
const char *commit_message(
    arena_t *arena, const config_t *config, const commit_message_context_t *ctx
) {
    CHECK_NULL(arena);
    CHECK_NULL(config);
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->profile);

    /* A message the user wrote is the whole message, and an empty one is none:
     * Git itself refuses to commit an empty message (lib/git/builtin/commit.c
     * cmd_commit, "Aborting commit due to empty commit message"), so the template
     * speaks where `-m ""` — a script's unset variable — said nothing */
    if (ctx->custom_msg && ctx->custom_msg[0]) {
        return arena_strdup(arena, ctx->custom_msg);
    }

    /* The values this message is made of, resolved once for both templates: the
     * clock read once, so every time the message names is one instant's. The
     * count is rendered here and not in the reader, which is what keeps it the
     * three lists' summed length under any template that names it beside them. */
    const time_t now = time(NULL);
    char hostname[MAX_HOSTNAME], date[16], datetime[64], count[32];
    commit_hostname(hostname, sizeof(hostname));
    commit_time(now, "%Y-%m-%d", date, sizeof(date));
    commit_time(now, "%Y-%m-%d %H:%M:%S %z", datetime, sizeof(datetime));
    snprintf(
        count, sizeof(count), "%zu",
        ctx->added.count + ctx->updated.count + ctx->removed.count
    );

    buffer_t paths = BUFFER_INIT;
    commit_paths(arena, ctx, &paths);

    /* {user} is the invoker's (sys/identity): under sudo the user who typed the
     * command, not the root that $USER names there — "unknown" for a uid with
     * no passwd entry */
    const char *user = identity()->name;

    /* The names the machine and the user gave are spelled where they enter
     * (utils/commit.h); the rest are this function's own text */
    const template_t vars[] = {
        { "host",          commit_spelled(arena, hostname)                },
        { "user",          commit_spelled(arena, user ? user : "unknown") },
        { "profile",       commit_spelled(arena, ctx->profile)            },
        { "action",        commit_action_name(ctx->action) },
        { "action_past",   commit_action_name_past(ctx->action) },
        { "count",         count },
        { "date",          date },
        { "datetime",      datetime },
        { "paths",         paths.data },
        { "target_commit", ctx->target_commit ? ctx->target_commit : "" },
    };
    const size_t var_count = sizeof(vars) / sizeof(vars[0]);

    /* The title, and the body beneath a blank line — which stands only above a
     * body its template did not substitute to nothing. */
    buffer_t text = BUFFER_INIT;
    commit_substitute(&text, config->commit_title, vars, var_count);
    size_t title_end = text.size;
    buffer_append_string(&text, "\n\n");
    size_t body_at = text.size;
    commit_substitute(&text, config->commit_body, vars, var_count);

    const char *message = arena_strndup(
        arena, text.data, text.size == body_at ? title_end : text.size
    );

    buffer_deinit(&text);
    buffer_deinit(&paths);
    return message;
}
