/**
 * args.c - Declarative argument-parser engine
 *
 * Straight-line parse over a caller-supplied (command, argv) pair, with every
 * allocation drawn from a caller-supplied arena. Errors are accumulated in a
 * fixed-capacity collector so a single mis-typed argv reports every mistake at
 * once.
 *
 * Layout:
 *   1) internal cursor + token classifier,
 *   2) flag-name matcher (whitespace-aware linear scan),
 *   3) error collector helpers,
 *   4) typed-int parser,
 *   5) per-kind "apply" routines that write into the options struct,
 *   6) the token consumer (tree resolution + option loop) and the args_parse
 *      entry point that settles what it consumed,
 *   7) completion: the candidates driver, a partial consume and the hook,
 *   8) rendering (root usage, single-command help, error batch),
 *   9) the fish completion exporter.
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

/**
 * The token stream: argv with a read position, plus the state the stream carries
 * across tokens — whether `--` has been consumed, after which every token is
 * positional.
 *
 * A partial stream is a command line cut at the cursor, read for completion: a
 * value flag that runs out of tokens is not an error there but the value being
 * typed, reported through `pending`.
 */
typedef struct args_cursor {
    int argc;
    char **argv;
    int index;
    bool end_of_opts;
    bool partial;
    const args_opt_t *pending;   /* Partial: the value flag the stream ended on */
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
 * `tok[0..tok_len)` and has the expected is_long length class (single-char =
 * short, multi-char = long).
 *
 * Zero allocation, zero bookkeeping. For N ≤ 12 opts per command this scans the
 * whole table in a handful of memcmps per parse.
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

    /* Two-pass formatting: first pass sizes the buffer, second fills it.
     * `vsnprintf(NULL, 0, ...)` is a standard C99 idiom. */
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
 *   `offsetof` rows in the opts table point into a `void *opts` struct. These
 *   helpers cast back to typed pointers for assignment.
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
 * Lazy-allocate an array large enough to hold every remaining argv token.
 * Over-allocates the common case; the arena makes that cheap. Idempotent —
 * subsequent calls with a non-NULL slot are no-ops.
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
 * True if this opt kind consumes the next token (or an inline `=value`).
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
 * Apply a value-taking opt (STRING / APPEND / INT).
 *
 * `inline_value` is non-NULL iff the user wrote `--name=value`; else the value
 * is consumed from the cursor's next token. A partial stream that ends on the
 * flag has its value at the cursor: reported, not an error.
 */
static void apply_value_opt(
    const args_opt_t *opt, const char *inline_value, args_cursor_t *cur,
    void *opts, arena_t *arena, args_errors_t *errors, int tok_idx
) {
    char *v = (char *) inline_value;
    if (v == NULL) {
        if (!cur_more(cur)) {
            if (cur->partial) {
                cur->pending = opt;
                return;
            }
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
    const args_command_t *cmd, char *tok, args_cursor_t *cur,
    void *opts, arena_t *arena, args_errors_t *errors, int tok_idx
) {
    /* v1 rejects bundling (`-fv` != `-f -v`); each short opt must be exactly
     * `-X`. The bundling enhancement can be added later without breaking any
     * existing spec. */
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
    const args_command_t *cmd, char *tok, void *opts, arena_t *arena,
    args_errors_t *errors, int tok_idx, int argc
) {
    /* Classify the token. cls=0 when the command has no classifier, matching
     * rows declared via ARGS_POSITIONAL_ANY (zero-init on class_accept). Commands
     * with a classifier enumerate their classes from 1. */
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
 * Validate POSITIONAL_RAW count against declared `min`. The `max` bound is enforced
 * during parse (it's a cap, not a floor).
 */
static void check_positional_counts(
    const args_command_t *cmd, void *opts,
    args_errors_t *errors, arena_t *arena
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

    /* Universal CLI conventions. Matched first so a misdeclared `root_aliases =
     * "help h"` cannot shadow them — the built-ins always win, the collision is
     * ignored silently. */
    if (strcmp(tok, "-h") == 0 || strcmp(tok, "--help") == 0) {
        return ARGS_ROOT_HELP;
    }
    if (strcmp(tok, "-v") == 0 || strcmp(tok, "--version") == 0) {
        return ARGS_ROOT_VERSION;
    }

    /* Flag form (`-X` or `--XXX`): match against each command's `root_aliases`
     * using the same flag-matcher the parser uses. `opt_matches()` tolerates a
     * NULL flags string, so commands without `root_aliases` skip cleanly. */
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

/**
 * Resolve the subcommand tree and consume the token stream into the buckets.
 *
 * The first half of a parse, shared by `args_parse` — which then settles: the
 * error gate, the positional counts, `post_parse` — and by the completion driver,
 * which reads the cursor instead. Seeds defaults at every tree level, recurses
 * into the matched subcommand, and walks the option loop of the leaf; `*leaf_out`
 * is the command whose buckets were filled.
 *
 * @return ARGS_OK when the stream was consumed — the loop's errors, if any, are
 *         in `errors`; ARGS_HELP_REQUESTED on `-h`/`--help`; ARGS_FAILED when
 *         the tree could not be resolved and there is no leaf to fill.
 */
static args_outcome_t consume_tokens(
    const args_command_t *command, args_cursor_t *cur, arena_t *arena,
    void *opts, args_errors_t *errors, const args_command_t **leaf_out
) {
    /* Surface the current command as the leaf. Recursive calls into a subcommand
     * overwrite this with the deeper command, so after the top-level call returns,
     * *leaf_out points to the command that owned the loop (whichever subcommand
     * was reached). */
    *leaf_out = command;

    /* Seed caller-provided non-zero defaults. */
    if (command->init_defaults != NULL) {
        command->init_defaults(opts);
    }

    /* --- Subcommand tree path ---------------------------------------
     *
     * A pure-subcommand parent has `subcommands != NULL`. The first positional
     * token selects the child; a flag at that position falls through to
     * `default_subcommand` when set, matching how `git fetch --all` implies `git
     * fetch`. */
    if (command->subcommands != NULL) {
        /* Spec-author guard: the subcommand path never parses the parent's opts
         * — flags fall through to the default sub. Catching a stray
         * ARGS_FLAG/STRING/etc. on a tree parent here turns a silent-no-op bug
         * into a visible parse error. */
        if (command->opts != NULL) {
            for (const args_opt_t *o = command->opts;
                o->kind != ARGS_KIND_END; o++) {
                if (o->kind == ARGS_KIND_GROUP) continue;
                record_error(
                    errors, arena, -1, o,
                    "internal: command '%s' has subcommands; "
                    "opts[] must be empty (move flags to each subcommand)",
                    command->name ? command->name : "?"
                );
                return ARGS_FAILED;
            }
        }

        if (!cur_more(cur)) {
            /* A partial stream that ends here stands at the subcommand slot:
             * the parent is the leaf, nothing consumed. */
            if (cur->partial) {
                return ARGS_OK;
            }
            if (command->default_subcommand != NULL) {
                return consume_tokens(
                    command->default_subcommand, cur, arena,
                    opts, errors, leaf_out
                );
            }
            record_error(
                errors, arena, -1, NULL,
                "command '%s' requires a subcommand",
                command->name ? command->name : "?"
            );
            return ARGS_FAILED;
        }

        const char *first = cur->argv[cur->index];

        if (strcmp(first, "-h") == 0 || strcmp(first, "--help") == 0) {
            return ARGS_HELP_REQUESTED;
        }

        if (first[0] == '-') {
            if (command->default_subcommand != NULL) {
                return consume_tokens(
                    command->default_subcommand, cur, arena,
                    opts, errors, leaf_out
                );
            }
            record_error(
                errors, arena, cur->index, NULL,
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
            cur->index++;
            return consume_tokens(
                sub->command, cur, arena, opts, errors, leaf_out
            );
        }

        record_error(
            errors, arena, cur->index, NULL,
            "unknown subcommand '%s' of '%s'",
            first, command->name ? command->name : "?"
        );
        return ARGS_FAILED;
    }

    /* --- Passthrough path -------------------------------------------
     *
     * `git`-style commands that fork a child process with the raw argv. The engine
     * skips parsing entirely; the dispatcher sees the full argv. */
    if (command->passthrough) {
        return ARGS_OK;
    }

    /* --- Standard option loop ---------------------------------------
     *
     * Once `-h`/`--help` is seen the loop short-circuits: the user's intent is
     * to read help, and any trailing argv is about to be thrown away by the render
     * path. Processing further tokens would only record errors that help_seen
     * suppresses anyway — wasted work and misleading if a post_parse hook were
     * still invoked. */
    while (cur_more(cur)) {
        int tok_idx = cur->index;
        char *t = cur_take(cur);

        switch (classify_token(t, cur->end_of_opts)) {
            case TOK_END_OF_OPTS:
                cur->end_of_opts = true;
                break;
            case TOK_HELP:
                return ARGS_HELP_REQUESTED;
            case TOK_LONG_OPT:
                apply_long_opt(
                    command, t, cur, opts, arena, errors, tok_idx
                );
                break;
            case TOK_SHORT_OPT:
                apply_short_opt(
                    command, t, cur, opts, arena, errors, tok_idx
                );
                break;
            case TOK_POSITIONAL:
                apply_positional(
                    command, t, opts, arena, errors, tok_idx, cur->argc
                );
                break;
        }
    }

    return ARGS_OK;
}

args_outcome_t args_parse(
    const args_command_t *command, int argc, char **argv, int start_idx,
    arena_t *arena, void *opts_out, args_errors_t *errors_out,
    const args_command_t **resolved_out
) {
    /* Reset the error collector in-place so callers can stack-declare it without
     * pre-zeroing. */
    if (errors_out != NULL) {
        errors_out->count = 0;
        errors_out->overflowed = false;
    }

    args_cursor_t cur = { .argc = argc, .argv = argv, .index = start_idx };
    const args_command_t *leaf = command;
    args_outcome_t outcome = consume_tokens(
        command, &cur, arena, opts_out, errors_out, &leaf
    );
    if (resolved_out != NULL) {
        *resolved_out = leaf;
    }
    if (outcome != ARGS_OK) return outcome;

    if (errors_out != NULL && errors_out->count > 0) return ARGS_FAILED;

    check_positional_counts(leaf, opts_out, errors_out, arena);
    if (errors_out != NULL && errors_out->count > 0) return ARGS_FAILED;

    /* Hook: interpret positional buckets, parse refspecs, reject what the rows
     * cannot express. */
    if (leaf->post_parse != NULL) {
        error_t *err = leaf->post_parse(opts_out, arena, leaf);
        if (err != NULL) {
            record_error_from_err(errors_out, arena, -1, NULL, err);
            error_free(err);
            return ARGS_FAILED;
        }
    }

    return ARGS_OK;
}

/* ══════════════════════════════════════════════════════════════════
 * Completion — the candidates at the cursor
 * ══════════════════════════════════════════════════════════════════ */

void args_complete_candidates(
    const args_command_t *const *commands, int argc, char **argv,
    const char *current, arena_t *arena, const void *ctx, FILE *out
) {
    /* The root slot, a built-in flag, an unknown word: the exported command rows
     * answer, or nothing does. */
    const args_command_t *command = NULL;
    if (args_resolve_root(commands, argc, argv, &command) != ARGS_ROOT_COMMAND) {
        return;
    }

    void *opts = NULL;
    if (command->opts_size > 0) {
        opts = arena_calloc(arena, 1, command->opts_size);
        if (opts == NULL) return;
    }

    /* Consume the line as the parser would, to where it stops. A line the command
     * would reject still has a next token: the loop's errors are collected here
     * and ignored. */
    args_errors_t errors = { 0 };
    args_cursor_t cur = {
        .argc = argc, .argv = argv, .index = 2, .partial = true
    };
    const args_command_t *leaf = command;
    if (consume_tokens(command, &cur, arena, opts, &errors, &leaf) != ARGS_OK) {
        return;   /* `-h` on the line, or a tree that did not resolve */
    }
    if (leaf->subcommands != NULL) {
        return;   /* The subcommand slot: the exported sub rows answer */
    }
    if (leaf->passthrough || leaf->complete == NULL) {
        return;
    }

    /* Where the cursor stands: the value of the flag the stream ended on; else
     * by the shape of what is being typed — a positional, the value of an inline
     * `--name=text`, or a flag name (the exported flag rows answer, as they do
     * for `--` and `-h`). */
    args_completion_t at = { .current = current };
    if (cur.pending != NULL) {
        at.value_of = cur.pending;
    } else {
        switch (classify_token(current, cur.end_of_opts)) {
            case TOK_POSITIONAL:
                break;
            case TOK_LONG_OPT: {
                const char *name = current + 2;
                const char *eq = strchr(name, '=');
                if (eq == NULL) return;
                const args_opt_t *opt = find_long(
                    leaf->opts, name, (size_t) (eq - name)
                );
                if (opt == NULL || !opt_takes_value(opt)) return;
                at.value_of = opt;
                at.current = eq + 1;
                break;
            }
            default:
                return;
        }
    }

    /* The request follows the candidates: the last line, at most one. */
    switch (leaf->complete(ctx, opts, &at, out)) {
        case ARGS_WANT_NONE:
            break;
        case ARGS_WANT_FILES:
            fprintf(out, "\tfiles\t%s\n", at.current);
            break;
        case ARGS_WANT_DIRS:
            fprintf(out, "\tdirs\t%s\n", at.current);
            break;
    }
}

/* ══════════════════════════════════════════════════════════════════
 * Rendering
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Emit `text` to `out`, substituting `%s` → `prog` and `%%` → `%`. Any other
 * `%X` sequence is emitted verbatim. Avoids passing attacker-controlled strings
 * to printf's format parser.
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

/* Column where option help text begins (after two-space indent and the flag+label
 * block). Matches the existing hand-written help style closely enough that migrated
 * commands look identical. */
#define HELP_OPT_COL 28

/**
 * Format a space-separated flags string ("force f") into a "--force, -f"-style
 * label in `buf`. Tokens are emitted in source order, single-char tokens as `-X`,
 * multi-char as `--XXX`, joined
 * with `", "`. Returns bytes written (excluding the terminator);
 * truncates silently if `buf` is too small. Accepts NULL flags.
 *
 * Used by every renderer that needs a human-readable flag label:
 * `render_option_row` (per-command options table) and `args_render_root_usage`
 * (root-level aliases in the Options block).
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
 * For unusually long flag blocks that would push help past the column, the help
 * text is wrapped onto a second line aligned to the column.
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

    /* Commands section: verb-style commands only. Commands with `root_aliases`
     * are flag-mode actions (e.g. `--interactive`) and appear in Options instead,
     * alongside `-h`/`-v`. The bareword still dispatches and still tab-completes
     * — help just promotes the canonical (flag) form rather than advertising
     * both. Help and completion serve different audiences: help shows canonical
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

    /* Options section: built-ins (`-h`/`-v`) plus the canonical home for every
     * command with `root_aliases`. Built-in labels are bound to locals so the
     * width pass and the emit pass agree without scrolling; help text appears
     * once per built-in and stays inline at its emit site. Column width is computed
     * from content so a long alias like "-i, --interactive" fits without a magic
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
 * Render an "Arguments:" section from positional rows that carry a value_label
 * + help. Opt-in: rows without a label stay invisible (commands that prefer
 * prose-in-description keep working unchanged).
 *
 * Called between `description` and the options table so the order mirrors the
 * natural reading of a usage line: positional args first, then flags. Returns
 * true iff the section was emitted; the caller uses that signal to manage the
 * inter-section blank line (the first ARGS_GROUP in options does NOT emit its
 * own leading blank, so the caller has to).
 */
static bool render_arguments(FILE *out, const args_opt_t *opts) {
    if (opts == NULL) return false;

    /* Two-pass: only emit the header if at least one row qualifies. Avoids an
     * empty "Arguments:" block on commands with prose-only positional docs. */
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
 * Render the "Subcommands:" section, showing the first token of each sub's alias
 * list as the canonical form and the child command's summary as its one-liner.
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
     * POSITIONAL_ARG / POSITIONAL_ANY_ARG declare both via their macro; POSITIONAL
     * and POSITIONAL_RAW can set them via struct literal for commands that want
     * row-level argument docs.
     *
     * render_arguments itself emits NO leading or trailing blank line. The
     * preceding section (description/summary) already ended with a blank; we
     * add a trailing blank here ONLY when the section fired, so Options — which
     * has no self-leading blank on its first group — gets the separator it
     * needs. */
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
            /* Positional rows are rendered separately (see render_arguments above)
             * — skip them here, since they lack the flag syntax that
             * render_option_row emits. */
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

    /* Section separation convention for `notes`, `examples`, `epilogue`: each
     * block adds exactly one leading `\n` for the blank line before the section;
     * the content itself must end with `\n` for the final line to terminate. We
     * do NOT append a trailing `\n` here because the NEXT block (or the renderer's
     * own end-of-output) handles its own separation. Adding one would double
     * the blank line between consecutive blocks such as notes → examples.
     *
     * `description` is different: its next section (options) deliberately has
     * no leading `\n` on the first ARGS_GROUP header, so the trailing `\n` there
     * IS the separator. See render loop above. */
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
 * Write `s` into `out` with fish double-quoted-string escaping. Fish treats `"`,
 * `$`, and `\` as special inside double quotes, and a raw `\n` (newline) would
 * break a `complete -c <prog> ... -d "..."` line mid-description. Defensive —
 * current help strings don't contain any of these, but the generated script is
 * user-facing; a future `Cost: $5`, `"quoted"`, or multi-line help must not break
 * the output.
 *
 * Newline is translated to the two-character sequence `\n` (a backslash followed
 * by the letter n), which fish's double-quoted-string lexer parses back into a
 * newline. Carriage returns get the same treatment for symmetry.
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
 * The `-n` guard a rule is emitted under: `__<prog>_<helper> <command> [<sub>]`.
 * Printed from its parts at every rule rather than formatted into a buffer once
 * per context — `using_command <cmd>` for a command's own rows, `needs_subcommand
 * <cmd>` for a tree's subcommand slot (the names, and the default sub's flags),
 * `using_subcommand <cmd> <aliases>` for one subcommand's rows, its alias list
 * verbatim so every spelling of the sub matches.
 */
typedef struct fish_guard {
    const char *helper;
    const char *command;
    const char *sub;       /* The subcommand's alias list; NULL otherwise */
} fish_guard_t;

static void emit_guard(FILE *out, const char *prog, const fish_guard_t *guard) {
    fprintf(out, " -n \"__%s_%s %s", prog, guard->helper, guard->command);
    if (guard->sub != NULL) {
        fprintf(out, " %s", guard->sub);
    }
    fputc('"', out);
}

/**
 * Emit a `complete -c <prog> ...` line for one opt row under `guard`.
 *
 * Every short-form token in the opt's `flags` becomes a `-o X`; every long-form
 * token becomes a `-l XXX`. Fish renders the aliases as a single completion entry
 * (that's the whole reason we can list them all on one `complete` line).
 * Value-taking kinds ask the binary for the value (`-xa`): fish then knows the
 * flag needs a parameter, consults only that rule at its value position — inline
 * `--name=text` included — and defers other suggestions until it's supplied.
 *
 * `-o` — fish's "old-style option" — declares a single-dash option that is exactly
 * `-X`: never grouped, its value the next token. That is what the parser reads
 * (`apply_short_opt` rejects `-fv` and `-pVALUE` alike). `-s` would declare a
 * POSIX short option, and fish would then offer the bundles `-fv`, `-fn`… and
 * probe a value flag for `-pVALUE` — forms the parser rejects. If short bundling
 * ever lands in the engine, this is the line that flips back to `-s`.
 */
static void emit_complete_line(
    FILE *out,
    const char *prog,
    const fish_guard_t *guard,
    const args_opt_t *opt
) {
    if (opt->hidden) return;
    if (opt->kind == ARGS_KIND_END || opt->kind == ARGS_KIND_GROUP ||
        opt->kind == ARGS_KIND_POSITIONAL ||
        opt->kind == ARGS_KIND_POSITIONAL_ARG ||
        opt->kind == ARGS_KIND_POSITIONAL_RAW) return;

    fprintf(out, "complete -c %s", prog);
    emit_guard(out, prog, guard);

    /* Walk space-separated names in `flags`, emitting -o or -l. */
    for (const char *p = opt->flags ? opt->flags : ""; *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;

        if (len == 1) {
            fprintf(out, " -o %c", s[0]);
        } else {
            fprintf(out, " -l %.*s", (int) len, s);
        }
    }

    if (opt_takes_value(opt)) {
        fprintf(out, " -xa \"(__%s_candidates)\"", prog);
    }

    if (opt->help != NULL && opt->help[0] != '\0') {
        fputs(" -d \"", out);
        fputs_fish_escaped(out, opt->help);
        fputc('"', out);
    }
    fputc('\n', out);
}

/**
 * Emit a root-level `complete -c <prog>` line for a command's flag aliases, guarded
 * by `__<prog>_needs_command`: the root resolver reads a flag form only as argv[1],
 * so once a command is typed the alias is no longer valid there. Each
 * space-separated token in `aliases` becomes a `-o X` (single-char; see
 * `emit_complete_line` for why not `-s`) or `-l XXX` (multi-char) entry; all
 * tokens share the single line so fish renders them as aliases of the same
 * completion.
 */
static void emit_root_alias_complete(
    FILE *out, const char *prog,
    const char *aliases, const char *summary
) {
    if (aliases == NULL) return;
    fprintf(out, "complete -c %s -n __%s_needs_command", prog, prog);
    for (const char *p = aliases; *p;) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        const char *s = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t) (p - s);
        if (len == 0) continue;
        if (len == 1) {
            fprintf(out, " -o %c", s[0]);
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
 * Emit a `complete -c <prog> ... -a NAME -d "SUMMARY"` line for a subcommand
 * entry under `guard`. NAME is the first alias (canonical form).
 */
static void emit_sub_row(
    FILE *out, const char *prog,
    const fish_guard_t *guard, const args_subcommand_t *sub
) {
    if (sub->hidden) return;

    const char *p = sub->name;
    while (*p == ' ') p++;
    const char *q = p;
    while (*q && *q != ' ') q++;
    size_t len = (size_t) (q - p);

    const char *summary =
        (sub->command && sub->command->summary) ? sub->command->summary : "";

    fprintf(out, "complete -c %s", prog);
    emit_guard(out, prog, guard);
    fprintf(out, " -a %.*s -d \"", (int) len, p);
    fputs_fish_escaped(out, summary);
    fputs("\"\n", out);
}

/**
 * Walk a top-level command and its subcommand tree, emitting its rules.
 */
static void emit_command(
    FILE *out,
    const char *prog,
    const args_command_t *cmd
) {
    const fish_guard_t own = { "using_command", cmd->name, NULL };

    /* Passthrough commands hand the tail of argv to an external tool (e.g. `<prog>
     * git <git-args...>` forwards everything after `git` to a spawned git process).
     * Delegate completion for the entire tail to that tool's fish integration —
     * there are no flags or subs to emit on our side, since the spec is
     * intentionally empty. */
    if (cmd->passthrough) {
        fprintf(out, "complete -c %s", prog);
        emit_guard(out, prog, &own);
        fprintf(
            out, " -xa \"(__fish_complete_subcommand --command %s)\"\n",
            cmd->name
        );
        return;
    }

    /* Flag rows. */
    if (cmd->opts != NULL) {
        for (const args_opt_t *o = cmd->opts; o->kind != ARGS_KIND_END; o++) {
            emit_complete_line(out, prog, &own, o);
        }
    }

    /* Subcommand rows and their own options. */
    if (cmd->subcommands != NULL) {
        /* One-liner pointing users at each sub, offered only while the subcommand
         * slot is still open. */
        const fish_guard_t slot = { "needs_subcommand", cmd->name, NULL };

        for (const args_subcommand_t *s = cmd->subcommands;
            s->name != NULL; s++) {
            emit_sub_row(out, prog, &slot, s);
        }

        /* Parse accepts `<prog> <cmd> --flag` as a shorthand for `<prog> <cmd>
         * <default-sub> --flag` when a default_subcommand is set. Mirror that
         * in completion: at the open slot, offer the default sub's flags so
         * tab-complete matches the parser's behavior. */
        if (cmd->default_subcommand != NULL &&
            cmd->default_subcommand->opts != NULL) {
            for (const args_opt_t *o = cmd->default_subcommand->opts;
                o->kind != ARGS_KIND_END; o++) {
                emit_complete_line(out, prog, &slot, o);
            }
        }

        /* Each sub's own flags live under __<prog>_using_subcommand. */
        for (const args_subcommand_t *s = cmd->subcommands;
            s->name != NULL; s++) {
            if (s->hidden || s->command == NULL) continue;

            const fish_guard_t under = { "using_subcommand", cmd->name, s->name };
            if (s->command->opts != NULL) {
                for (const args_opt_t *o = s->command->opts;
                    o->kind != ARGS_KIND_END; o++) {
                    emit_complete_line(out, prog, &under, o);
                }
            }
        }
    }
}

/**
 * The condition helpers the rules are guarded by, and the wrapper that asks the
 * binary. `%s` is the program name; the line is read the way the engine reads
 * it — the command is the second token, a bare word or a root alias; in a tree,
 * a flag at the subcommand slot routes to the default subcommand, so the subcommand
 * is the third token exactly when it is one.
 *
 * The positional guard mirrors `classify_token` for the token being typed: fish
 * runs the positional rule's generator for a flag name too, and the binary would
 * answer it with nothing (`args_complete_candidates`) after a full start. The
 * mirror errs toward asking — a `--` standing as a flag's value reads as the
 * end of options here, not in the engine — so it can only spare a call, never a
 * candidate.
 */
static const char fish_helpers[] =
    "function __%s_needs_command\n"
    "    # True while no command has been typed (only `%s` so far).\n"
    "    test (count (commandline -opc)) -eq 1\n"
    "end\n"
    "\n"
    "function __%s_using_command\n"
    "    # True when the command -- the second token -- is one of $argv.\n"
    "    set -l tokens (commandline -opc)\n"
    "    test (count $tokens) -ge 2; and contains -- $tokens[2] $argv\n"
    "end\n"
    "\n"
    "function __%s_needs_subcommand\n"
    "    # True while command $argv[1]'s subcommand slot is open: nothing after\n"
    "    # the command yet, or a flag, which the parser hands to the default\n"
    "    # subcommand.\n"
    "    set -l tokens (commandline -opc)\n"
    "    test (count $tokens) -ge 2; and test \"$tokens[2]\" = \"$argv[1]\"; or return 1\n"
    "    test (count $tokens) -eq 2; or string match -q -- '-*' $tokens[3]\n"
    "end\n"
    "\n"
    "function __%s_using_subcommand\n"
    "    # True when the command is $argv[1] and its subcommand -- the third\n"
    "    # token -- is spelled as one of $argv[2..].\n"
    "    set -l tokens (commandline -opc)\n"
    "    test (count $tokens) -ge 3; and test \"$tokens[2]\" = \"$argv[1]\"; "
    "and contains -- $tokens[3] $argv[2..]\n"
    "end\n"
    "\n"
    "function __%s_positional\n"
    "    # True when the token being typed can be a positional, as the engine\n"
    "    # reads it: anything once `--` has ended the options; else not a flag\n"
    "    # name (`-x`, `--name`, `--`), which the rules answer -- `-` alone and\n"
    "    # `-<digit>` are positionals. Spares the binary a call it would answer\n"
    "    # with nothing.\n"
    "    contains -- -- (commandline -opc)[3..]; and return 0\n"
    "    not string match -qr -- '^-[^0-9]' (commandline -ct)\n"
    "end\n"
    "\n";

/**
 * The wrapper reads the candidates protocol (`args_complete_candidates`) by its
 * one positional fact: a request, when there is one, is the last line. That line
 * alone is inspected; the candidates before it are printed back as they came,
 * so the shell's work does not grow with their number. The guard on the final
 * printf keeps an empty answer empty — fish's printf prints its format once with
 * no arguments.
 */
static const char fish_candidates_head[] =
    "function __%s_candidates\n"
    "    # Ask the binary what can stand at the cursor: the complete tokens after\n"
    "    # `%s`, and the token being typed. One candidate per line; a last line\n"
    "    # beginning with a tab asks for the shell's own path completion.\n"
    "    set -l current (commandline -ct)\n"
    "    set -l out (";

static const char fish_candidates_tail[] =
    " --current=\"$current\" -- (commandline -opc)[2..] 2>/dev/null)\n"
    "    if string match -q -- \\t'*' \"$out[-1]\"\n"
    "        set -l request (string split \\t -- $out[-1])\n"
    "        set -e out[-1]\n"
    "        switch $request[2]\n"
    "            case files\n"
    "                __fish_complete_path $request[3]\n"
    "            case dirs\n"
    "                __fish_complete_directories $request[3]\n"
    "        end\n"
    "    end\n"
    "    set -q out[1]; and printf '%%s\\n' $out\n"
    "end\n"
    "\n";

void args_export_completion_fish(
    FILE *out,
    const args_command_t *const *commands,
    const char *prog,
    const char *candidates
) {
    fprintf(
        out, "# Fish completions for %s, generated from its command registry. "
        "Do not edit.\n\n", prog
    );

    render_with_prog(out, fish_helpers, prog);
    render_with_prog(out, fish_candidates_head, prog);
    fprintf(out, "%s %s", prog, candidates);
    render_with_prog(out, fish_candidates_tail, prog);

    /* Disable fish's default file completion for `<prog>`: the rules below name
     * every candidate, and the binary asks for path completion where a path can
     * stand. Once a command is typed, every positional is the binary's to answer;
     * a flag name being typed is the flag rows'. */
    fprintf(out, "complete -c %s -f\n", prog);
    fprintf(
        out,
        "complete -c %s -n \"not __%s_needs_command; and __%s_positional\" "
        "-xa \"(__%s_candidates)\"\n\n",
        prog, prog, prog, prog
    );

    /* Top-level flags. `-h` / `-v` are universal conventions so they stay hardcoded
     * here; command-declared root aliases are projected from the registry so
     * the data flows from one source of truth. Help is a token every command
     * accepts, so its row carries no guard; version and the aliases are read as
     * argv[1] only and are guarded by `__<prog>_needs_command`. */
    fputs("# Root options\n", out);
    fprintf(out, "complete -c %s -o h -l help -d \"Show help\"\n", prog);
    fprintf(
        out, "complete -c %s -n __%s_needs_command -o v -l version -d \"Show version\"\n",
        prog, prog
    );
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

    /* Per-command rules, each block under a `# NAME` header. The block is rendered
     * first so a command with nothing to say — a dispatch shell reachable by
     * bareword or root alias alone, like `interactive` — leaves no orphan header.
     * Without a memstream (out of memory) the block goes straight through, header
     * and all: a cosmetic degradation. */
    for (size_t i = 0; commands[i] != NULL; i++) {
        const args_command_t *c = commands[i];
        if (c->hidden) continue;

        char *block = NULL;
        size_t block_len = 0;
        FILE *mem = open_memstream(&block, &block_len);
        if (mem == NULL) {
            fprintf(out, "# %s\n", c->name);
            emit_command(out, prog, c);
            fputc('\n', out);
            continue;
        }

        emit_command(mem, prog, c);
        fclose(mem);
        if (block_len > 0) {
            fprintf(out, "# %s\n", c->name);
            fwrite(block, 1, block_len, out);
            fputc('\n', out);
        }
        free(block);
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
