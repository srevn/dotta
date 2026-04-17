/**
 * args.c - Declarative argument-parser engine
 *
 * Straight-line parse over a caller-supplied (command, argv) pair, with
 * every allocation drawn from a caller-supplied arena. Errors are
 * accumulated in a fixed-capacity collector so a single mis-typed argv
 * reports every mistake at once.
 *
 * Layout:
 *   1) internal cursor + token classifier,
 *   2) flag-name matcher (whitespace-aware linear scan),
 *   3) error collector helpers,
 *   4) typed-int parser,
 *   5) per-kind "apply" routines that write into the options struct,
 *   6) args_parse entry point,
 *   7) rendering (root usage, single-command help, error batch).
 */

#include "base/args.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"

/* ══════════════════════════════════════════════════════════════════
 * Cursor + token classification
 * ══════════════════════════════════════════════════════════════════ */

typedef struct args_cursor {
    int argc;
    char **argv;
    int index;
} args_cursor_t;

static bool cur_more(const args_cursor_t *c) {
    return c->index < c->argc;
}

static char *cur_take(args_cursor_t *c) {
    return cur_more(c) ? c->argv[c->index++] : NULL;
}

enum token_kind {
    TOK_END_OF_OPTS,   /* "--" */
    TOK_HELP,          /* "-h" or "--help" */
    TOK_LONG_OPT,      /* "--name" or "--name=value" */
    TOK_SHORT_OPT,     /* "-X" where X is a non-digit single char */
    TOK_POSITIONAL     /* everything else: "foo", "-", "-1", "-fv"-like */
};

/**
 * Classify a token into one of the kinds above.
 *
 * Handles a handful of POSIX subtleties:
 *   - lone `-`      → positional (stdin sentinel; no command
 *                     reads stdin today, but the classification is
 *                     forward-compatible);
 *   - `-<digit>`    → positional (negative-number), never a flag;
 *   - `--`          → end-of-options marker;
 *   - `-h`/`--help` → help request, irrespective of the opts table.
 */
static enum token_kind classify_token(const char *t, bool end_of_opts) {
    if (end_of_opts) return TOK_POSITIONAL;

    /* Bare "-" is a positional. */
    if (t[0] == '-' &&
        t[1] == '\0')
        return TOK_POSITIONAL;

    /* "--" exactly is end-of-options. */
    if (t[0] == '-' &&
        t[1] == '-' &&
        t[2] == '\0')
        return TOK_END_OF_OPTS;

    /* "-h" or "--help" is always a help request. */
    if ((t[0] == '-' &&
        t[1] == 'h' &&
        t[2] == '\0') || strcmp(t, "--help") == 0) {
        return TOK_HELP;
    }

    /* Long option: starts with "--" and has at least one more char. */
    if (t[0] == '-' &&
        t[1] == '-' &&
        t[2] != '\0')
        return TOK_LONG_OPT;

    /* Short option: "-X" where X is a non-digit, non-dash char. */
    if (t[0] == '-' &&
        t[1] != '\0' &&
        t[1] != '-' && !isdigit((unsigned char) t[1])) {
        return TOK_SHORT_OPT;
    }

    return TOK_POSITIONAL;
}

/* ══════════════════════════════════════════════════════════════════
 * Name matching over space-separated `flags` strings
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Return true iff any whitespace-separated token in `flags` equals
 * `tok[0..tok_len)` and has the expected is_long length class
 * (single-char = short, multi-char = long).
 *
 * Zero allocation, zero bookkeeping. For N ≤ 12 opts per command
 * this scans the whole table in a handful of memcmps per parse.
 */
static bool opt_matches(
    const char *flags, const char *tok, size_t tok_len, bool is_long
) {
    if (flags == NULL) return false;

    for (const char *p = flags; *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;

        bool name_is_long = (len > 1);
        if (name_is_long != is_long) continue;
        if (len == tok_len && memcmp(s, tok, tok_len) == 0) return true;
    }
    return false;
}

static const args_opt_t *find_long(
    const args_opt_t *opts, const char *name, size_t name_len
) {
    if (opts == NULL) return NULL;
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (opt_matches(o->flags, name, name_len, true)) return o;
    }
    return NULL;
}

static const args_opt_t *find_short(const args_opt_t *opts, char c) {
    if (opts == NULL) return NULL;
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (opt_matches(o->flags, &c, 1, false)) return o;
    }
    return NULL;
}

static const args_subcommand_t *find_subcommand(
    const args_subcommand_t *subs, const char *name
) {

    if (subs == NULL) return NULL;
    size_t name_len = strlen(name);

    for (const args_subcommand_t *s = subs; s->name != NULL; s++) {
        for (const char *p = s->name; *p;) {
            while (*p == ' ') p++;
            if (*p == '\0') break;
            const char *start = p;
            while (*p && *p != ' ') p++;
            size_t len = (size_t) (p - start);
            if (len == name_len && memcmp(start, name, name_len) == 0) {
                return s;
            }
        }
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Error collector
 * ══════════════════════════════════════════════════════════════════ */

static void record_error_v(
    args_errors_t *errors, arena_t *arena, int token_index,
    const args_opt_t *opt, const char *fmt, va_list ap
) {
    if (errors == NULL) return;

    if (errors->count >= ARGS_ERRORS_CAP) {
        errors->overflowed = true;
        return;
    }

    /* Two-pass formatting: first pass sizes the buffer, second fills
     * it. `vsnprintf(NULL, 0, ...)` is a standard C99 idiom. */
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap_copy);
    va_end(ap_copy);
    if (needed < 0) return;

    char *msg = arena_alloc(arena, (size_t) needed + 1);
    if (msg == NULL) return;
    (void) vsnprintf(msg, (size_t) needed + 1, fmt, ap);

    errors->items[errors->count] = (args_error_t) {
        .message = msg,
        .opt = opt,
        .token_index = token_index,
    };
    errors->count++;
}

static void record_error(
    args_errors_t *errors, arena_t *arena, int token_index,
    const args_opt_t *opt, const char *fmt, ...
) {
    va_list ap;
    va_start(ap, fmt);
    record_error_v(errors, arena, token_index, opt, fmt, ap);
    va_end(ap);
}

static void record_error_from_err(
    args_errors_t *errors, arena_t *arena, int token_index,
    const args_opt_t *opt, const error_t *err
) {
    record_error(errors, arena, token_index, opt, "%s", error_message(err));
}

/* ══════════════════════════════════════════════════════════════════
 * Typed int parser (public — also used by hooks)
 * ══════════════════════════════════════════════════════════════════ */

error_t *args_parse_long(const char *text, long min, long max, long *out) {
    CHECK_NULL(out);
    if (text == NULL || *text == '\0') {
        return ERROR(ERR_INVALID_ARG, "empty integer value");
    }

    errno = 0;
    char *end = NULL;
    long val = strtol(text, &end, 10);

    if (end == text || *end != '\0') {
        return ERROR(
            ERR_INVALID_ARG, "'%s' is not a valid integer", text
        );
    }
    if (errno == ERANGE || val < min || val > max) {
        return ERROR(
            ERR_INVALID_ARG, "'%s' out of range [%ld, %ld]", text, min, max
        );
    }

    *out = val;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Field-writer helpers
 *
 *   `offsetof` rows in the opts table point into a `void *opts` struct.
 *   These helpers cast back to typed pointers for assignment.
 * ══════════════════════════════════════════════════════════════════ */

static bool *bool_field(void *opts, const args_opt_t *opt) {
    return (bool *) ((char *) opts + opt->offset);
}

static int *int_field(void *opts, const args_opt_t *opt) {
    return (int *) ((char *) opts + opt->offset);
}

static long *long_field(void *opts, const args_opt_t *opt) {
    return (long *) ((char *) opts + opt->offset);
}

static const char **string_field(void *opts, const args_opt_t *opt) {
    return (const char **) ((char *) opts + opt->offset);
}

static char ***array_field(void *opts, const args_opt_t *opt) {
    return (char ***) ((char *) opts + opt->offset);
}

static size_t *count_field(void *opts, const args_opt_t *opt) {
    return (size_t *) ((char *) opts + opt->count_offset);
}

/**
 * Lazy-allocate an array large enough to hold every remaining argv
 * token. Over-allocates the common case; the arena makes that cheap.
 * Idempotent — subsequent calls with a non-NULL slot are no-ops.
 */
static char **ensure_array(
    char ***arr_ptr, arena_t *arena, int argc
) {
    if (*arr_ptr != NULL) return *arr_ptr;
    size_t cap = (size_t) (argc > 0 ? argc : 1);
    *arr_ptr = arena_calloc(arena, cap, sizeof(char *));
    return *arr_ptr;
}

/* ══════════════════════════════════════════════════════════════════
 * Per-kind application routines
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Apply a value-taking opt (STRING / APPEND / INT).
 *
 * `inline_value` is non-NULL iff the user wrote `--name=value`; else
 * the value is consumed from the cursor's next token.
 */
static void apply_value_opt(
    const args_opt_t *opt, const char *inline_value, args_cursor_t *cur,
    void *opts, arena_t *arena, args_errors_t *errors, int tok_idx
) {
    char *v = (char *) inline_value;
    if (v == NULL) {
        if (!cur_more(cur)) {
            record_error(
                errors, arena, tok_idx, opt, "option '%s' requires a value",
                cur->argv[tok_idx]
            );
            return;
        }
        v = cur_take(cur);
    }

    switch (opt->kind) {
        case ARGS_KIND_STRING: {
            *string_field(opts, opt) = v;
            break;
        }

        case ARGS_KIND_APPEND: {
            char ***arr = array_field(opts, opt);
            size_t *cnt = count_field(opts, opt);
            if (ensure_array(arr, arena, cur->argc) == NULL) {
                record_error(errors, arena, tok_idx, opt, "out of memory");
                return;
            }
            (*arr)[(*cnt)++] = v;
            break;
        }

        case ARGS_KIND_INT: {
            long parsed = 0;
            error_t *err = args_parse_long(v, opt->int_min, opt->int_max, &parsed);
            if (err != NULL) {
                record_error_from_err(errors, arena, tok_idx, opt, err);
                error_free(err);
                return;
            }
            *long_field(opts, opt) = parsed;
            break;
        }

        default:
            /* Caller should route FLAG/FLAG_SET directly; this path is a bug. */
            record_error(
                errors, arena, tok_idx, opt,
                "internal: option kind %d is not value-taking", (int) opt->kind
            );
            break;
    }
}

static void apply_long_opt(
    const args_command_t *cmd, char *tok, args_cursor_t *cur, void *opts,
    arena_t *arena, args_errors_t *errors, int tok_idx
) {
    /* tok starts with "--" (verified by classify_token). */
    const char *name_start = tok + 2;
    const char *eq = strchr(name_start, '=');
    size_t name_len = eq ? (size_t) (eq - name_start) : strlen(name_start);
    const char *inline_val = eq ? eq + 1 : NULL;

    const args_opt_t *opt = find_long(cmd->opts, name_start, name_len);
    if (opt == NULL) {
        record_error(
            errors, arena, tok_idx, NULL,
            "unknown option '%s'", tok
        );
        return;
    }

    switch (opt->kind) {
        case ARGS_KIND_FLAG:
            if (inline_val != NULL) {
                record_error(
                    errors, arena, tok_idx, opt,
                    "option '%s' does not take a value", tok
                );
                return;
            }
            *bool_field(opts, opt) = true;
            break;

        case ARGS_KIND_FLAG_SET:
            if (inline_val != NULL) {
                record_error(
                    errors, arena, tok_idx, opt,
                    "option '%s' does not take a value", tok
                );
                return;
            }
            *int_field(opts, opt) = opt->set_value;
            break;

        case ARGS_KIND_STRING:
        case ARGS_KIND_APPEND:
        case ARGS_KIND_INT:
            apply_value_opt(opt, inline_val, cur, opts, arena, errors, tok_idx);
            break;

        default:
            record_error(
                errors, arena, tok_idx, opt,
                "internal: option kind %d", (int) opt->kind
            );
            break;
    }
}

static void apply_short_opt(
    const args_command_t *cmd,
    char *tok,
    args_cursor_t *cur,
    void *opts,
    arena_t *arena,
    args_errors_t *errors,
    int tok_idx
) {
    /* v1 rejects bundling (`-fv` != `-f -v`); each short opt must be
     * exactly `-X`. The bundling enhancement can be added later
     * without breaking any existing spec. */
    if (tok[2] != '\0') {
        record_error(
            errors, arena, tok_idx, NULL,
            "unknown option '%s'", tok
        );
        return;
    }

    const args_opt_t *opt = find_short(cmd->opts, tok[1]);
    if (opt == NULL) {
        record_error(
            errors, arena, tok_idx, NULL,
            "unknown option '%s'", tok
        );
        return;
    }

    switch (opt->kind) {
        case ARGS_KIND_FLAG:
            *bool_field(opts, opt) = true;
            break;
        case ARGS_KIND_FLAG_SET:
            *int_field(opts, opt) = opt->set_value;
            break;
        case ARGS_KIND_STRING:
        case ARGS_KIND_APPEND:
        case ARGS_KIND_INT:
            apply_value_opt(opt, NULL, cur, opts, arena, errors, tok_idx);
            break;
        default:
            record_error(
                errors, arena, tok_idx, opt,
                "internal: option kind %d", (int) opt->kind
            );
            break;
    }
}

static void apply_positional(
    const args_command_t *cmd,
    char *tok,
    void *opts,
    arena_t *arena,
    args_errors_t *errors,
    int tok_idx,
    int argc
) {
    /* Classify the token. cls=0 when the command has no classifier,
     * matching rows declared via ARGS_POSITIONAL_ANY (zero-init on
     * class_accept). Commands with a classifier enumerate their
     * classes from 1. */
    args_class_t cls = 0;
    if (cmd->classify != NULL) cls = cmd->classify(tok);

    /* Select the matching row:
     *   - first POSITIONAL or POSITIONAL_ARG with matching class wins;
     *   - else fall back to the first POSITIONAL_RAW bucket (if any).
     */
    const args_opt_t *matched = NULL;
    const args_opt_t *raw = NULL;

    if (cmd->opts != NULL) {
        for (const args_opt_t *o = cmd->opts; o->kind != ARGS_KIND_END; o++) {
            if ((o->kind == ARGS_KIND_POSITIONAL ||
                o->kind == ARGS_KIND_POSITIONAL_ARG) &&
                o->class_accept == cls) {
                matched = o;
                break;
            }
            if (o->kind == ARGS_KIND_POSITIONAL_RAW && raw == NULL) {
                raw = o;
            }
        }
    }
    if (matched == NULL) matched = raw;

    if (matched == NULL) {
        record_error(
            errors, arena, tok_idx, NULL,
            "unexpected argument '%s'", tok
        );
        return;
    }

    if (matched->kind == ARGS_KIND_POSITIONAL_ARG) {
        *string_field(opts, matched) = tok;
        return;
    }

    /* POSITIONAL or POSITIONAL_RAW: append to the backing array. */
    char ***arr = array_field(opts, matched);
    size_t *cnt = count_field(opts, matched);

    if (matched->kind == ARGS_KIND_POSITIONAL_RAW &&
        matched->positional_max > 0 &&
        *cnt >= matched->positional_max) {
        record_error(
            errors, arena, tok_idx, NULL,
            "too many arguments (max %zu allowed)",
            matched->positional_max
        );
        return;
    }

    if (ensure_array(arr, arena, argc) == NULL) {
        record_error(errors, arena, tok_idx, NULL, "out of memory");
        return;
    }
    (*arr)[(*cnt)++] = tok;
}

/**
 * Validate POSITIONAL_RAW count against declared `min`. The `max`
 * bound is enforced during parse (it's a cap, not a floor).
 */
static void check_positional_counts(
    const args_command_t *cmd,
    void *opts,
    args_errors_t *errors,
    arena_t *arena
) {
    if (cmd->opts == NULL) return;

    for (const args_opt_t *o = cmd->opts; o->kind != ARGS_KIND_END; o++) {
        if (o->kind != ARGS_KIND_POSITIONAL_RAW) continue;
        size_t cnt = *(size_t *) ((char *) opts + o->count_offset);
        if (cnt < o->positional_min) {
            record_error(
                errors, arena, -1, o,
                "at least %zu positional argument(s) required",
                o->positional_min
            );
        }
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Root dispatcher
 * ══════════════════════════════════════════════════════════════════ */

args_root_outcome_t args_resolve_root(
    const args_command_t *const *commands,
    int argc, char **argv,
    const args_command_t **command_out
) {
    if (argc < 2) return ARGS_ROOT_NONE;
    if (commands == NULL) return ARGS_ROOT_UNKNOWN;

    const char *tok = argv[1];

    /* Universal CLI conventions. Matched first so a misdeclared
     * `root_aliases = "help h"` cannot shadow them — the built-ins
     * always win, the collision is ignored silently. */
    if (strcmp(tok, "-h") == 0 || strcmp(tok, "--help") == 0) {
        return ARGS_ROOT_HELP;
    }
    if (strcmp(tok, "-v") == 0 || strcmp(tok, "--version") == 0) {
        return ARGS_ROOT_VERSION;
    }

    /* Flag form (`-X` or `--XXX`): match against each command's
     * `root_aliases` using the same flag-matcher the parser uses.
     * `opt_matches()` tolerates a NULL flags string, so commands
     * without `root_aliases` skip cleanly. */
    if (tok[0] == '-') {
        const char *name;
        size_t name_len;
        bool is_long;

        if (tok[1] == '-') {
            /* "--" alone or "--=..." are not valid root tokens. */
            if (tok[2] == '\0') return ARGS_ROOT_UNKNOWN;
            name = tok + 2;
            name_len = strlen(name);
            is_long = true;
        } else {
            /* "-" alone and multi-char "-XX" are not valid root tokens. */
            if (tok[1] == '\0' ||
                tok[2] != '\0') return ARGS_ROOT_UNKNOWN;
            name = tok + 1;
            name_len = 1;
            is_long = false;
        }

        for (size_t i = 0; commands[i] != NULL; i++) {
            const args_command_t *c = commands[i];
            if (opt_matches(c->root_aliases, name, name_len, is_long)) {
                if (command_out != NULL) *command_out = c;
                return ARGS_ROOT_COMMAND;
            }
        }
        return ARGS_ROOT_UNKNOWN;
    }

    /* Bare word: match by command name. */
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->name != NULL && strcmp(c->name, tok) == 0) {
            if (command_out != NULL) *command_out = c;
            return ARGS_ROOT_COMMAND;
        }
    }
    return ARGS_ROOT_UNKNOWN;
}

/* ══════════════════════════════════════════════════════════════════
 * Entry point
 * ══════════════════════════════════════════════════════════════════ */

args_outcome_t args_parse(
    const args_command_t *command, int argc, char **argv, int start_idx,
    arena_t *arena, void *opts_out, args_errors_t *errors_out,
    const args_command_t **resolved_out
) {
    /* Reset the error collector in-place so callers can stack-declare
     * it without pre-zeroing. */
    if (errors_out != NULL) {
        errors_out->count = 0;
        errors_out->overflowed = false;
    }

    /* Surface the current command as the resolved leaf. Recursive calls
     * into a subcommand will overwrite this with the deeper command, so
     * after the top-level call returns, *resolved_out points to the
     * leaf actually reached (whichever subcommand owned the parse). */
    if (resolved_out != NULL) {
        *resolved_out = command;
    }

    /* Seed caller-provided non-zero defaults. */
    if (command->init_defaults != NULL) {
        command->init_defaults(opts_out);
    }

    /* --- Subcommand tree path ---------------------------------------
     *
     * A pure-subcommand parent has `subcommands != NULL`. The first
     * positional token selects the child; a flag at that position
     * falls through to `default_subcommand` when set, matching how
     * `git fetch --all` implies `git fetch`. */
    if (command->subcommands != NULL) {
        /* Spec-author guard: the subcommand path never parses the
         * parent's opts — flags fall through to the default sub.
         * Catching a stray ARGS_FLAG/STRING/etc. on a tree parent
         * here turns a silent-no-op bug into a visible parse error. */
        if (command->opts != NULL) {
            for (const args_opt_t *o = command->opts;
                o->kind != ARGS_KIND_END; o++) {
                if (o->kind == ARGS_KIND_GROUP) continue;
                record_error(
                    errors_out, arena, -1, o,
                    "internal: command '%s' has subcommands; "
                    "opts[] must be empty (move flags to each subcommand)",
                    command->name ? command->name : "?"
                );
                return ARGS_FAILED;
            }
        }

        if (start_idx >= argc) {
            if (command->default_subcommand != NULL) {
                return args_parse(
                    command->default_subcommand, argc, argv,
                    start_idx, arena, opts_out, errors_out, resolved_out
                );
            }
            record_error(
                errors_out, arena, -1, NULL,
                "command '%s' requires a subcommand",
                command->name ? command->name : "?"
            );
            return ARGS_FAILED;
        }

        const char *first = argv[start_idx];

        if (strcmp(first, "-h") == 0 || strcmp(first, "--help") == 0) {
            return ARGS_HELP_REQUESTED;
        }

        if (first[0] == '-') {
            if (command->default_subcommand != NULL) {
                return args_parse(
                    command->default_subcommand, argc, argv,
                    start_idx, arena, opts_out, errors_out, resolved_out
                );
            }
            record_error(
                errors_out, arena, start_idx, NULL,
                "command '%s' requires a subcommand (got '%s')",
                command->name ? command->name : "?", first
            );
            return ARGS_FAILED;
        }

        const args_subcommand_t *sub = find_subcommand(
            command->subcommands,
            first
        );
        if (sub != NULL) {
            return args_parse(
                sub->command, argc, argv, start_idx + 1,
                arena, opts_out, errors_out, resolved_out
            );
        }

        record_error(
            errors_out, arena, start_idx, NULL,
            "unknown subcommand '%s' of '%s'",
            first, command->name ? command->name : "?"
        );
        return ARGS_FAILED;
    }

    /* --- Passthrough path -------------------------------------------
     *
     * `git`-style commands that fork a child process with the raw
     * argv. The engine skips parsing entirely; the dispatcher sees
     * the full argv. */
    if (command->passthrough) {
        return ARGS_OK;
    }

    /* --- Standard option loop ---------------------------------------
     *
     * Once `-h`/`--help` is seen the loop short-circuits: the user's
     * intent is to read help, and any trailing argv is about to be
     * thrown away by the render path. Processing further tokens would
     * only record errors that help_seen suppresses anyway — wasted
     * work and misleading if a post_parse hook were still invoked. */
    args_cursor_t cur = { .argc = argc, .argv = argv, .index = start_idx };
    bool end_of_opts = false;

    while (cur_more(&cur)) {
        int tok_idx = cur.index;
        char *t = cur_take(&cur);

        switch (classify_token(t, end_of_opts)) {
            case TOK_END_OF_OPTS:
                end_of_opts = true;
                break;
            case TOK_HELP:
                return ARGS_HELP_REQUESTED;
            case TOK_LONG_OPT:
                apply_long_opt(
                    command, t, &cur, opts_out, arena,
                    errors_out, tok_idx
                );
                break;
            case TOK_SHORT_OPT:
                apply_short_opt(
                    command, t, &cur, opts_out, arena,
                    errors_out, tok_idx
                );
                break;
            case TOK_POSITIONAL:
                apply_positional(
                    command, t, opts_out, arena,
                    errors_out, tok_idx, argc
                );
                break;
        }
    }

    if (errors_out != NULL && errors_out->count > 0) return ARGS_FAILED;

    check_positional_counts(command, opts_out, errors_out, arena);
    if (errors_out != NULL && errors_out->count > 0) return ARGS_FAILED;

    /* Hook: interpret positional buckets, parse refspecs, etc. */
    if (command->post_parse != NULL) {
        error_t *err = command->post_parse(opts_out, arena, command);
        if (err != NULL) {
            record_error_from_err(errors_out, arena, -1, NULL, err);
            error_free(err);
            return ARGS_FAILED;
        }
    }

    /* Hook: cross-field invariants. */
    if (command->validate != NULL) {
        error_t *err = command->validate(opts_out, command);
        if (err != NULL) {
            record_error_from_err(errors_out, arena, -1, NULL, err);
            error_free(err);
            return ARGS_FAILED;
        }
    }

    return ARGS_OK;
}

/* ══════════════════════════════════════════════════════════════════
 * Rendering
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Emit `text` to `out`, substituting `%s` → `prog` and `%%` → `%`.
 * Any other `%X` sequence is emitted verbatim. Avoids passing
 * attacker-controlled strings to printf's format parser.
 */
static void render_with_prog(FILE *out, const char *text, const char *prog) {
    for (const char *p = text; *p;) {
        if (p[0] == '%' && p[1] == 's') {
            fputs(prog, out);
            p += 2;
        } else if (p[0] == '%' && p[1] == '%') {
            fputc('%', out);
            p += 2;
        } else {
            fputc(*p, out);
            p++;
        }
    }
}

/* Column where option help text begins (after two-space indent and
 * the flag+label block). Matches the existing hand-written help
 * style closely enough that migrated commands look identical. */
#define HELP_OPT_COL 28

/**
 * Format a space-separated flags string ("force f") into a
 * "--force, -f"-style label in `buf`. Tokens are emitted in source
 * order, single-char tokens as `-X`, multi-char as `--XXX`, joined
 * with `", "`. Returns bytes written (excluding the terminator);
 * truncates silently if `buf` is too small. Accepts NULL flags.
 *
 * Used by every renderer that needs a human-readable flag label:
 * `render_option_row` (per-command options table) and
 * `args_render_root_usage` (root-level aliases in the Options block).
 */
static size_t format_flag_label(
    char *buf, size_t buf_size, const char *flags
) {
    if (buf_size == 0) return 0;
    buf[0] = '\0';

    size_t pos = 0;
    bool first = true;

    for (const char *p = (flags ? flags : ""); *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;

        if (!first) {
            int n = snprintf(buf + pos, buf_size - pos, ", ");
            if (n < 0) break;
            pos += (size_t) n;
        }
        first = false;

        int n = snprintf(
            buf + pos, buf_size - pos, "%s%.*s",
            len == 1 ? "-" : "--", (int) len, s
        );
        if (n < 0) break;
        pos += (size_t) n;
        if (pos + 1 >= buf_size) break;
    }
    return pos;
}

/**
 * Render a single opts[] row as:
 *     "  -f, --force <value>  Description text"
 *
 * For unusually long flag blocks that would push help past the
 * column, the help text is wrapped onto a second line aligned to
 * the column.
 */
static void render_option_row(FILE *out, const args_opt_t *opt) {
    if (opt->hidden) return;

    char buf[192];
    size_t pos = format_flag_label(buf, sizeof(buf), opt->flags);

    if (opt->value_label != NULL && pos < sizeof(buf)) {
        int n = snprintf(
            buf + pos, sizeof(buf) - pos, " %s",
            opt->value_label
        );
        if (n > 0) pos += (size_t) n;
    }

    const char *help = opt->help ? opt->help : "";
    if (pos > (size_t) HELP_OPT_COL) {
        fprintf(out, "  %s\n  %-*s %s\n", buf, HELP_OPT_COL, "", help);
    } else {
        fprintf(out, "  %-*s %s\n", HELP_OPT_COL, buf, help);
    }
}

void args_render_root_usage(
    FILE *out,
    const args_command_t *const *commands,
    const char *prog
) {
    fprintf(out, "Usage: %s <command> [options]\n\n", prog);

    /* Commands section: verb-style commands only. Commands with
     * `root_aliases` are flag-mode actions (e.g. `--interactive`) and
     * appear in Options instead, alongside `-h`/`-v`. The bareword
     * still dispatches and still tab-completes — help just promotes
     * the canonical (flag) form rather than advertising both. Help
     * and completion serve different audiences: help shows canonical
     * shape, completion accepts anything the parser will dispatch. */
    fputs("Commands:\n", out);
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden || c->root_aliases != NULL) continue;
        fprintf(
            out, "  %-14s %s\n",
            c->name, c->summary ? c->summary : ""
        );
    }

    /* Options section: built-ins (`-h`/`-v`) plus the canonical home
     * for every command with `root_aliases`. Built-in labels are bound
     * to locals so the width pass and the emit pass agree without
     * scrolling; help text appears once per built-in and stays inline
     * at its emit site. Column width is computed from content so a
     * long alias like "-i, --interactive" fits without a magic
     * number. */
    const char *help_label = "-h, --help";
    const char *vers_label = "-v, --version";

    size_t col = strlen(help_label);
    size_t vlen = strlen(vers_label);
    if (vlen > col) col = vlen;

    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden || c->root_aliases == NULL) continue;
        char label[64];
        size_t n = format_flag_label(label, sizeof(label), c->root_aliases);
        if (n > col) col = n;
    }

    fputs("\nOptions:\n", out);
    fprintf(
        out, "  %-*s %s\n", (int) col, help_label,
        "Show help (use <command> --help for details)"
    );
    fprintf(
        out, "  %-*s %s\n", (int) col, vers_label,
        "Show version information"
    );
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden || c->root_aliases == NULL) continue;
        char label[64];
        format_flag_label(label, sizeof(label), c->root_aliases);
        fprintf(
            out, "  %-*s %s\n", (int) col,
            label, c->summary ? c->summary : ""
        );
    }

    fprintf(
        out,
        "\nRun '%s <command> --help' for more information on a command.\n",
        prog
    );
}

void args_render_usage_line(
    FILE *out,
    const args_command_t *command,
    const char *prog
) {
    fputs("Usage: ", out);
    if (command->usage != NULL) {
        render_with_prog(out, command->usage, prog);
    } else {
        fprintf(
            out, "%s %s [options]",
            prog, command->name ? command->name : "?"
        );
    }
    fputc('\n', out);
}

/**
 * True if this row is a positional of any flavor.
 */
static bool is_positional_kind(args_kind_t k) {
    return k == ARGS_KIND_POSITIONAL ||
           k == ARGS_KIND_POSITIONAL_ARG ||
           k == ARGS_KIND_POSITIONAL_RAW;
}

/**
 * Render an "Arguments:" section from positional rows that carry a
 * value_label + help. Opt-in: rows without a label stay invisible
 * (commands that prefer prose-in-description keep working unchanged).
 *
 * Called between `description` and the options table so the order
 * mirrors the natural reading of a usage line: positional args first,
 * then flags. Returns true iff the section was emitted; the caller
 * uses that signal to manage the inter-section blank line (the first
 * ARGS_GROUP in options does NOT emit its own leading blank, so the
 * caller has to).
 */
static bool render_arguments(FILE *out, const args_opt_t *opts) {
    if (opts == NULL) return false;

    /* Two-pass: only emit the header if at least one row qualifies.
     * Avoids an empty "Arguments:" block on commands with prose-only
     * positional docs. */
    bool any = false;
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (!is_positional_kind(o->kind)) continue;
        if (o->hidden) continue;
        if (o->value_label == NULL) continue;
        any = true;
        break;
    }
    if (!any) return false;

    fputs("Arguments:\n", out);
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (!is_positional_kind(o->kind)) continue;
        if (o->hidden) continue;
        if (o->value_label == NULL) continue;

        const char *help = o->help ? o->help : "";
        fprintf(out, "  %-*s %s\n", HELP_OPT_COL, o->value_label, help);
    }
    return true;
}

/**
 * Render the "Subcommands:" section, showing the first token of each
 * sub's alias list as the canonical form and the child command's
 * summary as its one-liner.
 */
static void render_subcommands(FILE *out, const args_subcommand_t *subs) {
    fputs("\nSubcommands:\n", out);
    for (const args_subcommand_t *s = subs; s->name != NULL; s++) {
        if (s->hidden) continue;

        const char *p = s->name;
        while (*p == ' ') p++;
        const char *q = p;
        while (*q && *q != ' ') q++;
        size_t len = (size_t) (q - p);

        const char *sum =
            (s->command && s->command->summary) ? s->command->summary : "";
        fprintf(
            out, "  %-*.*s %s\n",
            HELP_OPT_COL, (int) len, p, sum
        );
    }
}

void args_render_help(
    FILE *out,
    const args_command_t *command,
    const char *prog
) {
    args_render_usage_line(out, command, prog);
    fputc('\n', out);

    if (command->summary != NULL) {
        fprintf(out, "%s\n\n", command->summary);
    }

    if (command->description != NULL) {
        render_with_prog(out, command->description, prog);
        fputc('\n', out);   /* Blank-line separator before next section. */
    }

    /* Arguments — opt-in, rendered from rows that declare a value_label.
     * POSITIONAL_ARG / POSITIONAL_ANY_ARG declare both via their macro;
     * POSITIONAL and POSITIONAL_RAW can set them via struct literal for
     * commands that want row-level argument docs.
     *
     * render_arguments itself emits NO leading or trailing blank line.
     * The preceding section (description/summary) already ended with a
     * blank; we add a trailing blank here ONLY when the section fired,
     * so Options — which has no self-leading blank on its first group
     * — gets the separator it needs. */
    if (render_arguments(out, command->opts)) {
        fputc('\n', out);
    }

    /* Options — sectioned by ARGS_GROUP rows. */
    bool any_shown = false;
    if (command->opts != NULL) {
        for (const args_opt_t *o = command->opts;
            o->kind != ARGS_KIND_END; o++) {
            if (o->kind == ARGS_KIND_GROUP) {
                fprintf(
                    out, "%s%s\n", any_shown ? "\n" : "",
                    o->help ? o->help : ""
                );
                any_shown = true;
                continue;
            }
            /* Positional rows are rendered separately (see render_arguments
             * above) — skip them here, since they lack the flag syntax
             * that render_option_row emits. */
            if (is_positional_kind(o->kind)) continue;

            render_option_row(out, o);
            any_shown = true;
        }

        if (any_shown) {
            fprintf(
                out, "  %-*s %s\n",
                HELP_OPT_COL, "-h, --help",
                "Show this help message"
            );
        }
    }

    if (command->subcommands != NULL) {
        render_subcommands(out, command->subcommands);
    }

    /* Section separation convention for `notes`, `examples`,
     * `epilogue`: each block adds exactly one leading `\n` for the
     * blank line before the section; the content itself must end
     * with `\n` for the final line to terminate. We do NOT append a
     * trailing `\n` here because the NEXT block (or the renderer's
     * own end-of-output) handles its own separation. Adding one
     * would double the blank line between consecutive blocks such
     * as notes → examples.
     *
     * `description` is different: its next section (options) deliberately
     * has no leading `\n` on the first ARGS_GROUP header, so the
     * trailing `\n` there IS the separator. See render loop above. */
    if (command->notes != NULL) {
        fputc('\n', out);
        render_with_prog(out, command->notes, prog);
    }

    if (command->examples != NULL) {
        fputs("\nExamples:\n", out);
        render_with_prog(out, command->examples, prog);
    }

    if (command->epilogue != NULL) {
        fputc('\n', out);
        render_with_prog(out, command->epilogue, prog);
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Completion export (fish)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * True if this opt kind takes a value (and hence should appear in the
 * `__<prog>_value_flags` list so fish's positional counter can skip it).
 */
static bool opt_takes_value(const args_opt_t *o) {
    switch (o->kind) {
        case ARGS_KIND_STRING:
        case ARGS_KIND_APPEND:
        case ARGS_KIND_INT:
            return true;
        default:
            return false;
    }
}

/**
 * Write `s` into `out` with fish double-quoted-string escaping. Fish
 * treats `"`, `$`, and `\` as special inside double quotes, and a raw
 * `\n` (newline) would break a `complete -c <prog> ... -d "..."` line
 * mid-description. Defensive — current help strings don't contain any
 * of these, but the generated script is user-facing; a future `Cost:
 * $5`, `"quoted"`, or multi-line help must not break the output.
 *
 * Newline is translated to the two-character sequence `\n` (a backslash
 * followed by the letter n), which fish's double-quoted-string lexer
 * parses back into a newline. Carriage returns get the same treatment
 * for symmetry.
 */
static void fputs_fish_escaped(FILE *out, const char *s) {
    if (s == NULL) return;
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char) *s;
        if (c == '\n') { fputs("\\n", out); continue; }
        if (c == '\r') { fputs("\\r", out); continue; }
        if (c == '"' || c == '$' || c == '\\') {
            fputc('\\', out);
        }
        fputc((int) c, out);
    }
}

/**
 * Emit a `complete -c <prog> ...` line for one opt row. `condition_fish`
 * is the fish `-n` guard expression (e.g., `__<prog>_using_command init`).
 *
 * Every short-form token in the opt's `flags` becomes a `-s X`; every
 * long-form token becomes a `-l XXX`. Fish renders the aliases as
 * a single completion entry (that's the whole reason we can list them
 * all on one `complete` line). Value-taking kinds add `-r` so fish
 * knows the flag needs a parameter and defers other suggestions until
 * it's supplied.
 */
static void emit_complete_line(
    FILE *out,
    const char *prog,
    const char *condition_fish,
    const args_opt_t *opt
) {
    if (opt->hidden) return;
    if (opt->kind == ARGS_KIND_END || opt->kind == ARGS_KIND_GROUP ||
        opt->kind == ARGS_KIND_POSITIONAL ||
        opt->kind == ARGS_KIND_POSITIONAL_ARG ||
        opt->kind == ARGS_KIND_POSITIONAL_RAW) return;

    fprintf(out, "complete -c %s -n \"%s\"", prog, condition_fish);

    /* Walk space-separated names in `flags`, emitting -s or -l. */
    for (const char *p = opt->flags ? opt->flags : ""; *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;

        if (len == 1) {
            fprintf(out, " -s %c", s[0]);
        } else {
            fprintf(out, " -l %.*s", (int) len, s);
        }
    }

    if (opt_takes_value(opt)) {
        fputs(" -r", out);
    }

    if (opt->help != NULL && opt->help[0] != '\0') {
        fputs(" -d \"", out);
        fputs_fish_escaped(out, opt->help);
        fputc('"', out);
    }
    fputc('\n', out);
}

/**
 * Emit a root-level `complete -c <prog>` line for a command's flag
 * aliases — no `-n` guard, since root options are valid at the start
 * of argv regardless of what follows. Each space-separated token in
 * `aliases` becomes a `-s X` (single-char) or `-l XXX` (multi-char)
 * entry; all tokens share the single line so fish renders them as
 * aliases of the same completion.
 */
static void emit_root_alias_complete(
    FILE *out, const char *prog,
    const char *aliases, const char *summary
) {
    if (aliases == NULL) return;
    fprintf(out, "complete -c %s", prog);
    for (const char *p = aliases; *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;
        if (len == 1) {
            fprintf(out, " -s %c", s[0]);
        } else {
            fprintf(out, " -l %.*s", (int) len, s);
        }
    }
    if (summary != NULL && summary[0] != '\0') {
        fputs(" -d \"", out);
        fputs_fish_escaped(out, summary);
        fputc('"', out);
    }
    fputc('\n', out);
}

/**
 * Emit a `complete -c <prog> ... -a NAME -d "SUMMARY"` line for a
 * subcommand entry. NAME is the first alias (canonical form).
 */
static void emit_sub_row(
    FILE *out, const char *prog,
    const char *condition_fish, const args_subcommand_t *sub
) {
    if (sub->hidden) return;

    const char *p = sub->name;
    while (*p == ' ') p++;
    const char *q = p;
    while (*q && *q != ' ') q++;
    size_t len = (size_t) (q - p);

    const char *summary =
        (sub->command && sub->command->summary) ? sub->command->summary : "";

    fprintf(
        out, "complete -c %s -n \"%s\" -a %.*s -d \"",
        prog, condition_fish, (int) len, p
    );
    fputs_fish_escaped(out, summary);
    fputs("\"\n", out);
}

/* Value-flag deduplication. Many commands share the same value-bearing
 * flag (e.g. `--profile` appears on 9+ specs); emitting one token per
 * occurrence makes the generated `__<prog>_value_flags` list grow
 * quadratically in N (commands) × F (flags) and adds no information.
 */
typedef struct value_flag_set {
    const char **tokens;   /* Each entry is a fish argv token (`-p`,    */
    size_t count;          /* `--profile`, ...). Borrowed from args_opt */
    size_t cap;            /* `flags` strings — stable for the process. */
} value_flag_set_t;

static bool value_flag_set_has(
    const value_flag_set_t *set, const char *token, size_t len
) {
    for (size_t i = 0; i < set->count; i++) {
        const char *t = set->tokens[i];
        if (strlen(t) == len && memcmp(t, token, len) == 0) return true;
    }
    return false;
}

static void value_flag_set_add(
    value_flag_set_t *set, const char *token, arena_t *arena
) {
    if (set->count == set->cap) {
        size_t ncap = set->cap ? set->cap * 2 : 16;
        const char **nptr = arena_calloc(arena, ncap, sizeof(*set->tokens));
        if (nptr == NULL) return;
        if (set->count > 0) {
            memcpy(nptr, set->tokens, set->count * sizeof(*set->tokens));
        }
        set->tokens = nptr;
        set->cap = ncap;
    }
    set->tokens[set->count++] = token;
}

/**
 * Scan every value-taking flag-token in `opts` and add the formatted
 * argv form (`-X` or `--XXX`) to `set`. Duplicates (same token already
 * seen) are skipped so a flag declared on N commands appears once.
 *
 * The tokens themselves are written out in `args_export_completion_fish`
 * after the full scan; this function never writes to `out`.
 */
static void collect_value_flags(
    const args_opt_t *opts, value_flag_set_t *set, arena_t *arena
) {
    if (opts == NULL) return;
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (o->hidden) continue;
        if (!opt_takes_value(o)) continue;

        for (const char *p = o->flags ? o->flags : ""; *p;) {
            while (*p == ' ') p++;
            if (*p == '\0') break;
            const char *s = p;
            while (*p && *p != ' ') p++;
            size_t len = (size_t) (p - s);
            if (len == 0) continue;

            /* Format as fish argv token: single-char → `-X`, multi → `--XXX`. */
            size_t tok_len = (len == 1) ? 2 : (len + 2);
            char *tok = arena_alloc(arena, tok_len + 1);
            if (tok == NULL) continue;
            if (len == 1) {
                tok[0] = '-';
                tok[1] = s[0];
                tok[2] = '\0';
            } else {
                tok[0] = '-';
                tok[1] = '-';
                memcpy(tok + 2, s, len);
                tok[tok_len] = '\0';
            }

            if (!value_flag_set_has(set, tok, tok_len)) {
                value_flag_set_add(set, tok, arena);
            }
        }
    }
}

/**
 * True if `opts` holds at least one opt that would produce a
 * `complete` line. Mirrors the early-returns in emit_complete_line():
 * GROUP is help-only, POSITIONAL kinds don't surface in fish
 * completion, and hidden opts are skipped everywhere.
 */
static bool has_visible_completable_opt(const args_opt_t *opts) {
    if (opts == NULL) return false;
    for (const args_opt_t *o = opts; o->kind != ARGS_KIND_END; o++) {
        if (o->hidden) continue;
        if (o->kind == ARGS_KIND_GROUP ||
            o->kind == ARGS_KIND_POSITIONAL ||
            o->kind == ARGS_KIND_POSITIONAL_ARG ||
            o->kind == ARGS_KIND_POSITIONAL_RAW) continue;
        return true;
    }
    return false;
}

/**
 * True if emit_command() would produce at least one `complete` line
 * for `cmd`. Used by the per-command section loop to suppress orphan
 * `# NAME` headers for commands that exist only as dispatch shells
 * (bareword + root-alias flag with no flags/subs/passthrough, e.g.
 * `spec_interactive`). The gates below mirror emit_command() exactly;
 * any change there must be reflected here or headers will drift.
 */
static bool command_has_completions(const args_command_t *cmd) {
    if (cmd == NULL || cmd->hidden) return false;
    if (cmd->passthrough) return true;
    if (has_visible_completable_opt(cmd->opts)) return true;
    if (cmd->subcommands != NULL) {
        for (const args_subcommand_t *s = cmd->subcommands;
            s->name != NULL; s++) {
            if (!s->hidden) return true;
        }
        /* A hidden subcommand list can still contribute opts via
         * default_subcommand — emit_command() emits those at the
         * pre-sub position regardless of sibling visibility. */
        if (cmd->default_subcommand != NULL &&
            has_visible_completable_opt(cmd->default_subcommand->opts)) {
            return true;
        }
    }
    return false;
}

/**
 * Walk a command and its subcommand tree, emitting completion lines.
 * `parent_fish` is the fish `-n` condition fragment identifying the
 * caller's context; for root commands it's `__<prog>_using_command NAME`.
 */
static void emit_command(
    FILE *out,
    const char *prog,
    const args_command_t *cmd,
    const char *parent_fish
) {
    if (cmd == NULL || cmd->hidden) return;

    /* Passthrough commands hand the tail of argv to an external tool
     * (e.g. `<prog> git <git-args...>` forwards everything after `git`
     * to a spawned git process). Delegate completion for the entire
     * tail to that tool's fish integration — there are no flags or
     * subs to emit on our side, since the spec is intentionally empty. */
    if (cmd->passthrough) {
        fprintf(
            out,
            "complete -c %s -n \"%s\" -xa \"(__fish_complete_subcommand --command %s)\"\n",
            prog, parent_fish, cmd->name
        );
        return;
    }

    /* Flag rows. */
    if (cmd->opts != NULL) {
        for (const args_opt_t *o = cmd->opts; o->kind != ARGS_KIND_END; o++) {
            emit_complete_line(out, prog, parent_fish, o);
        }
    }

    /* Subcommand rows and their own options. */
    if (cmd->subcommands != NULL) {
        /* One-liner pointing users at each sub. The guard must require
         * both the parent context AND the absence of a sub selection
         * so names only show as completions before the sub is chosen. */
        char needs_sub[256];
        snprintf(
            needs_sub, sizeof(needs_sub),
            "%s; and __%s_needs_subcommand %s",
            parent_fish, prog, cmd->name
        );

        for (const args_subcommand_t *s = cmd->subcommands;
            s->name != NULL; s++) {
            emit_sub_row(out, prog, needs_sub, s);
        }

        /* Parse accepts `<prog> <cmd> --flag` as a shorthand for
         * `<prog> <cmd> <default-sub> --flag` when a default_subcommand
         * is set. Mirror that in completion: at the pre-sub position
         * (parent ctx AND no sub chosen yet), offer the default sub's
         * flags so tab-complete matches the parser's behavior. */
        if (cmd->default_subcommand != NULL &&
            cmd->default_subcommand->opts != NULL) {
            for (const args_opt_t *o = cmd->default_subcommand->opts;
                o->kind != ARGS_KIND_END; o++) {
                emit_complete_line(out, prog, needs_sub, o);
            }
        }

        /* Each sub's own flags live under __<prog>_using_subcommand. */
        for (const args_subcommand_t *s = cmd->subcommands;
            s->name != NULL; s++) {
            if (s->hidden || s->command == NULL) continue;

            /* Canonical sub token (first in alias list). */
            const char *p = s->name;
            while (*p == ' ') p++;
            const char *q = p;
            while (*q && *q != ' ') q++;

            char sub_cond[256];
            snprintf(
                sub_cond, sizeof(sub_cond),
                "__%s_using_subcommand %s %.*s",
                prog, cmd->name, (int) (q - p), p
            );

            if (s->command->opts != NULL) {
                for (const args_opt_t *o = s->command->opts;
                    o->kind != ARGS_KIND_END; o++) {
                    emit_complete_line(out, prog, sub_cond, o);
                }
            }
        }
    }
}

void args_export_completion_fish(
    FILE *out,
    const args_command_t *const *commands,
    const char *prog
) {
    fprintf(out, "# Auto-generated by `%s __complete spec fish`.\n", prog);
    fprintf(out, "# Dynamic completion helpers live in %s.fish.\n\n", prog);

    /* Disable fish's default file completion for `<prog>` — our commands
     * use explicit rules (or helper-provided value completions) and
     * letting the shell fall back to filenames creates noisy TAB
     * expansions for commands that accept profile names, not paths. */
    fprintf(out, "complete -c %s -f\n\n", prog);

    /* Token storage and the dedup set both live in a local scratch
     * arena so no stdlib heap is touched. Arena is destroyed at the
     * bottom of this function, which invalidates every pointer in
     * `vset.tokens` — safe because the tokens are emitted via fprintf
     * BEFORE the destroy call. */
    arena_t *scratch = arena_create(4 * 1024);
    value_flag_set_t vset = { 0 };

    /* Collect value-taking flag tokens across every non-hidden command
     * (and its non-hidden subcommands). Dedup happens at insert time, so
     * `--profile` appears once even if nine specs declare it. */
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden) continue;
        if (scratch != NULL) collect_value_flags(c->opts, &vset, scratch);

        /* Also scan subcommands' opts. */
        if (c->subcommands != NULL) {
            for (const args_subcommand_t *s = c->subcommands;
                s->name != NULL; s++) {
                if (s->hidden || s->command == NULL) continue;
                if (scratch != NULL) {
                    collect_value_flags(s->command->opts, &vset, scratch);
                }
            }
        }
    }

    /* Value-taking flags: used by fish's positional-arg counter in
     * <prog>.fish to know which tokens are "flag + value" pairs. */
    fprintf(out, "set -g __%s_value_flags", prog);
    for (size_t i = 0; i < vset.count; i++) {
        fprintf(out, " %s", vset.tokens[i]);
    }
    fputs("\n\n", out);

    if (scratch != NULL) arena_destroy(scratch);

    /* Top-level flags. `-h` / `-v` are universal conventions so they
     * stay hardcoded here; command-declared root aliases are projected
     * from the registry so the data flows from one source of truth. */
    fputs("# Root options\n", out);
    fprintf(out, "complete -c %s -s h -l help -d \"Show help\"\n", prog);
    fprintf(out, "complete -c %s -s v -l version -d \"Show version\"\n", prog);
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden || c->root_aliases == NULL) continue;
        emit_root_alias_complete(out, prog, c->root_aliases, c->summary);
    }
    fputc('\n', out);

    /* Command list. */
    fputs("# Commands\n", out);
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden) continue;
        fprintf(
            out, "complete -c %s -n __%s_needs_command -a %s -d \"",
            prog, prog, c->name
        );
        fputs_fish_escaped(out, c->summary ? c->summary : "");
        fputs("\"\n", out);
    }
    fputc('\n', out);

    /* Per-command options. Skip commands with no body to emit — purely
     * dispatch shells (e.g. `spec_interactive`, reachable only via
     * bareword or root-alias flag) otherwise leave an orphan `# NAME`
     * header with nothing underneath. */
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (!command_has_completions(c)) continue;

        char cond[128];
        snprintf(cond, sizeof(cond), "__%s_using_command %s", prog, c->name);

        fprintf(out, "# %s\n", c->name);
        emit_command(out, prog, c, cond);
        fputc('\n', out);
    }
}

void args_render_errors(
    FILE *out,
    const args_errors_t *errors,
    const args_command_t *command,
    const char *prog
) {
    if (errors != NULL) {
        for (size_t i = 0; i < errors->count; i++) {
            fprintf(out, "%s", prog);
            if (command && command->name) fprintf(out, " %s", command->name);
            fprintf(out, ": error: %s\n", errors->items[i].message);
        }
        if (errors->overflowed) {
            fprintf(out, "%s: error: (more errors suppressed)\n", prog);
        }
        if (errors->count > 0 || errors->overflowed) fputc('\n', out);
    }

    if (command != NULL) {
        args_render_usage_line(out, command, prog);
        if (command->name != NULL) {
            fprintf(
                out, "Try '%s %s --help' for more information.\n",
                prog, command->name
            );
        }
    }
}
