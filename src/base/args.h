/**
 * args.h - Declarative argument-parser engine
 *
 * A command's argument signature is data, not imperative code. The
 * `args_command_t` struct is the single source of truth: parser, help,
 * completion, and dispatch are all projections of the same row.
 *
 * A command is declared as:
 *   - an options-struct typedef owned by `src/cmds/<name>.h`;
 *   - a `static const args_opt_t opts[]` table terminated by ARGS_END;
 *   - a `const args_command_t` static value exposing name, summary, usage,
 *     help text, the opts table, hooks, and a dispatch function.
 *
 * The engine:
 *   - never writes to stdio (rendering is caller-driven);
 *   - never calls exit();
 *   - holds no global state;
 *   - uses a caller-supplied arena for every allocation (error messages,
 *     positional arrays, post-parse strings).
 *
 * Key design points
 * -----------------
 *   `flags`                Space-separated list of names. Single-char tokens
 *                          are short forms (emitted with a single dash);
 *                          multi-char tokens are long forms (double dash).
 *                          Display order follows write order — no "canonical"
 *                          vs "alias" distinction in the renderer.
 *
 *   Positional model       Three shapes: classified (engine routes token
 *                          by `classify(token)` to the matching POSITIONAL
 *                          / POSITIONAL_ARG row), unclassified bucket
 *                          (POSITIONAL_ANY / POSITIONAL_ANY_ARG — all
 *                          tokens land together, no classify needed), and
 *                          raw bucket (POSITIONAL_RAW — commands interpret
 *                          in post_parse). Anything that needs order-
 *                          sensitive interpretation uses POSITIONAL_RAW.
 *
 *   Tri-state flags        Model as `int` fields with init_defaults seeding
 *                          a default value; use `ARGS_FLAG_SET` rows whose
 *                          set_value is the enum value.
 *
 *   Subcommand trees       Parent has `subcommands`. Every subcommand in a
 *                          tree MUST share the parent's options struct type
 *                          (so `opts_size` allocates enough for any sub).
 *                          Each sub's `init_defaults` sets the discriminator.
 *
 *   Root-level dispatch    `args_resolve_root` classifies argv[1] into a
 *                          built-in flag (`-h`/`--help`, `-v`/`--version`),
 *                          a command (by name), or a root alias (declared
 *                          via `args_command_t::root_aliases`).
 *
 *   Cleanup chain          The engine is signal-safe and key-zero-safe: no
 *                          `exit()`, no libc-free in the error path, no
 *                          process-level state. The dispatcher owns the
 *                          arena and destroys it after dispatch returns.
 *
 * Picking a subcommand pattern
 * ----------------------------
 * Three patterns coexist because real CLIs vary. Pick by shape, not by
 * taste:
 *
 *   Subcommand tree        Use when each sub has a DISJOINT option set
 *   (.subcommands)         and there's no shorthand to a default action.
 *                          Example: `dotta profile {list|enable|...}` —
 *                          each sub owns different flags.
 *
 *   POSITIONAL_RAW         Use when subs SHARE options or when a bareword
 *   + post_parse switch    positional encodes the mode. Also required
 *                          for bareword-fallback forms like
 *                          `dotta remote <name>` → `remote show <name>`.
 *                          Example: `dotta key {set|clear|status}` —
 *                          all three share `-v`.
 *
 *   Classify + POSITIONAL  Use for a SINGLE action whose positionals
 *   (multiple class rows)  are polymorphic by shape. The classifier
 *                          maps each token to a class; matching rows
 *                          route to distinct fields.
 *                          Example: `dotta apply [profile|file]...` —
 *                          both kinds can appear in any order.
 *
 * If two or more fit, prefer the tree: it gives per-sub `--help` for free,
 * cleanest fish completion, and no hand-rolled dispatch switch.
 */

#ifndef DOTTA_ARGS_H
#define DOTTA_ARGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Local forward declarations of base-layer types. Defined as typedefs
 * in <types.h>; we re-declare here (compatible since the struct tags
 * match) so args.h has zero domain dependencies and can compile as a
 * standalone parser engine. */
typedef struct error error_t;
typedef struct arena arena_t;

/* Forward declarations for types fully defined below. */
typedef struct args_opt args_opt_t;
typedef struct args_command args_command_t;
typedef struct args_subcommand args_subcommand_t;
typedef struct args_error args_error_t;
typedef struct args_errors args_errors_t;

/* ══════════════════════════════════════════════════════════════════
 * Enums
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Option kind — determines how a row is applied to the options struct.
 */
typedef enum args_kind {
    ARGS_KIND_END,             /* Sentinel. Terminates an opts[] table */
    ARGS_KIND_GROUP,           /* Help-only: section title for render */
    ARGS_KIND_FLAG,            /* bool field → true when flag is seen */
    ARGS_KIND_FLAG_SET,        /* int  field → `set_value` when seen */
    ARGS_KIND_STRING,          /* const char * field → next token */
    ARGS_KIND_APPEND,          /* char ** + size_t → appends one */
    ARGS_KIND_INT,             /* long field → typed int in [min,max] */
    ARGS_KIND_POSITIONAL,      /* Positional → APPEND tgt (class_accept) */
    ARGS_KIND_POSITIONAL_ARG,  /* Positional → STRING tgt (class_accept) */
    ARGS_KIND_POSITIONAL_RAW   /* Fallback bucket for post_parse */
} args_kind_t;

/**
 * Positional classification ID — opaque integer the engine compares
 * by equality, nothing more. Each command that needs polymorphic
 * positionals declares a command-local enum and returns those values
 * from `classify()`. The engine has no interest in the value space
 * beyond `class_accept == classify(tok)`, so domain vocabulary
 * (profiles, files, git refs, ...) stays out of this header.
 *
 * Commands without polymorphic positionals don't touch this field at
 * all — they use `ARGS_POSITIONAL_ANY` / `ARGS_POSITIONAL_ANY_ARG`
 * and the zero-initialized `class_accept` matches the engine's zero
 * default (cls=0 when no classifier is configured).
 */
typedef int args_class_t;

/**
 * Outcome of `args_parse()`.
 */
typedef enum args_outcome {
    ARGS_OK,                   /* Parse succeeded; proceed to dispatch */
    ARGS_HELP_REQUESTED,       /* `-h`/`--help` was seen */
    ARGS_FAILED                /* Errors recorded; inspect `errors` */
} args_outcome_t;

/**
 * Outcome of `args_resolve_root()`.
 *
 * One value per distinct dispatcher response. The caller branches on
 * this to render help, print version, dispatch a matched command, or
 * report an unknown token — keeping the root-layer decision table in
 * the caller rather than the parser.
 */
typedef enum args_root_outcome {
    ARGS_ROOT_NONE,            /* argc < 2 — no command typed */
    ARGS_ROOT_HELP,            /* `-h`/`--help` at argv[1] */
    ARGS_ROOT_VERSION,         /* `-v`/`--version` at argv[1] */
    ARGS_ROOT_COMMAND,         /* Matched name or root_aliases token */
    ARGS_ROOT_UNKNOWN          /* argv[1] matched nothing in the registry */
} args_root_outcome_t;

/* ══════════════════════════════════════════════════════════════════
 * Function pointer types
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Classifier: inspect a positional token and return its class ID.
 *
 * Called for every positional token when the command defines it. The
 * returned value is matched against `class_accept` on each POSITIONAL
 * / POSITIONAL_ARG row; the first row with equal value wins. A token
 * whose class matches no row falls back to the POSITIONAL_RAW bucket
 * (if present) or reports an "unexpected argument" error.
 *
 * Return values are defined by the command itself via a local enum
 * starting at 1 — see `args_class_t`.
 */
typedef args_class_t (*args_classify)(const char *token);

/**
 * Seed non-zero defaults on the options struct before parsing begins.
 *
 * Called exactly once after the struct is zero-initialized and before
 * any tokens are processed. Use for flags whose default is `true` or
 * for tri-state enums with a non-zero neutral value.
 */
typedef void (*args_defaults)(void *opts);

/**
 * Post-parse hook: interpret positional buckets, do secondary parsing.
 *
 * Called after all tokens have been consumed without recorded parse
 * errors and after POSITIONAL_RAW min/max counts are validated. Use
 * for refspec parsing, N-positional reinterpretation, mode inference,
 * etc. Allocations may use `arena`. Returning a non-NULL error aborts
 * dispatch; the error is wrapped into the error collector and freed.
 */
typedef error_t *(*args_postparse)(
    void *opts, arena_t *arena,
    const args_command_t *command
);

/**
 * Cross-field invariant check. Runs after post_parse. Fail the same way.
 */
typedef error_t *(*args_validate)(
    void *opts,
    const args_command_t *command
);

/**
 * Command entry point. Called by the dispatcher after successful parse.
 *
 * `ctx` is opaque to the engine — it is whatever the caller wants to
 * thread through to the command (typically a domain-specific dispatch
 * bundle holding repo handle, config, output stream, arena, etc.).
 * Each command's dispatch wrapper casts `ctx` to its expected type on
 * the first line. `opts` points to the parsed options struct.
 */
typedef error_t *(*args_dispatch)(const void *ctx, void *opts);

/* ══════════════════════════════════════════════════════════════════
 * Core structures
 * ══════════════════════════════════════════════════════════════════ */

/**
 * One row in an opts[] table.
 *
 * All fields beyond `kind` are optional per kind; unused bytes stay
 * zero. A single struct (not a union) is used because it lets tables
 * be declared as `static const args_opt_t opts[] = { ... }` at file
 * scope and keeps rows trivially copyable.
 */
struct args_opt {
    args_kind_t kind;

    /* Vocabulary */
    const char *flags;          /* "force f" or "yes y no-confirm"; GROUP/END rows: unused */
    const char *value_label;    /* "<name>", "<pattern>", "<N>" — shown after last flag in help */
    const char *help;           /* Description text, or GROUP title */

    /* Target offsets (set via offsetof in macros) */
    size_t offset;              /* Primary field in the options struct */
    size_t count_offset;        /* APPEND/POSITIONAL/POSITIONAL_RAW: offset of size_t count field */

    /* Per-kind details */
    args_class_t class_accept;  /* POSITIONAL[_ONE]: command-local class ID; 0 = unclassified */
    int set_value;              /* FLAG_SET: value assigned to the int field */
    long int_min;               /* INT: inclusive lower bound */
    long int_max;               /* INT: inclusive upper bound */
    size_t positional_min;      /* POSITIONAL_RAW: minimum count */
    size_t positional_max;      /* POSITIONAL_RAW: maximum count 0 = unlimited */

    /* Display */
    bool hidden;                /* Suppress from help rendering */
};

/**
 * Subcommand entry in a tree.
 *
 * `name` is a space-separated alias list; the first token is the
 * canonical form shown in help output. Every subcommand in a tree
 * must share the parent's options struct type (same opts_size), since
 * the dispatcher allocates opts based on the top-level command.
 */
struct args_subcommand {
    const char *name;               /* "remove rm" — space-separated */
    const args_command_t *command;  /* Subcommand specification */
    bool hidden;                    /* Hide from help output */
};

/**
 * A command as a first-class value.
 *
 * All projections (parser, help renderer, completion exporter,
 * dispatcher) consume this struct. Registry entries are
 * `const args_command_t` at file scope with static storage duration.
 */
struct args_command {
    /* Identity */
    const char *name;            /* Fully qualified: "apply", "profile enable" */
    const char *summary;         /* One-line description for root-level help */

    /* Help text (printf-style: `%s` is substituted for program name) */
    const char *usage;           /* Usage line, e.g. "%s apply [opts] ..." */
    const char *description;     /* Paragraph shown AFTER summary, BEFORE opts */
    const char *notes;           /* Paragraph shown AFTER opts, BEFORE examples */
    const char *examples;        /* Free-form body under an "Examples:" header  */
    const char *epilogue;        /* Paragraph shown last */

    /* Parsing */
    size_t opts_size;            /* sizeof(cmd_X_options_t), or 0 */
    const args_opt_t *opts;      /* Terminated by ARGS_END */

    /* Subcommand tree */
    const args_subcommand_t *subcommands;      /* Terminated by name NULL */
    const args_command_t *default_subcommand;  /* Dispatched when the user passes no positional */

    /* Behavior hooks (all optional) */
    args_classify classify;      /* Classify positional token into command-local class ID */
    args_defaults init_defaults; /* Seed opts with non-zero defaults before parsing */
    args_postparse post_parse;   /* Populate derived fields; non-NULL return aborts dispatch */
    args_validate validate;      /* Cross-field invariant check; runs after post_parse */

    /* Execution  */
    const void *payload;       /* Domain-extension payload (opaque to engine) */
    args_dispatch dispatch;    /* Command entry point */

    /* Root-level flag aliases */
    const char *root_aliases;    /* argv[1] match dispatches command; NULL = none */

    /* Bits */
    bool passthrough;            /* Skip parsing, hand argv to dispatch as-is */
    bool silent_failure;         /* Suppress stderr on error */
    bool hidden;                 /* Hide from root help listing */
};

/**
 * One parse error.
 */
struct args_error {
    const char *message;         /* Arena-allocated; NUL-terminated */
    const args_opt_t *opt;       /* Offending opt, or NULL */
    int token_index;             /* argv index, or -1 if no token */
};

/**
 * Fixed-capacity error collector.
 *
 * Eight slots hold every realistic typo-heavy parse. Overflow sets the
 * flag; later errors are dropped silently and the renderer shows a
 * "more errors suppressed" trailer.
 */
#define ARGS_ERRORS_CAP 8
struct args_errors {
    args_error_t items[ARGS_ERRORS_CAP];
    size_t count;
    bool overflowed;
};

/* ══════════════════════════════════════════════════════════════════
 * Root dispatcher
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Resolve argv[1] against a root command registry in a single pass.
 *
 * Pure function: no allocations, no I/O, no global state. The caller
 * branches on the returned outcome — rendering help, printing version,
 * dispatching the matched spec, or reporting an unknown token. The
 * dispatcher sits above the parser: once a command is resolved here,
 * `args_parse()` handles argv[2..] under the spec's own rules.
 *
 * Resolution order:
 *   1. argc < 2                              → ARGS_ROOT_NONE
 *   2. argv[1] ∈ {-h, --help}                → ARGS_ROOT_HELP
 *   3. argv[1] ∈ {-v, --version}             → ARGS_ROOT_VERSION
 *   4. bare word matching `cmd->name`        → ARGS_ROOT_COMMAND
 *   5. flag form (`-X` / `--XXX`) matching
 *      `cmd->root_aliases`                   → ARGS_ROOT_COMMAND
 *   6. anything else                         → ARGS_ROOT_UNKNOWN
 *
 * Built-ins win over `root_aliases` — a command that declares
 * `root_aliases = "help h"` is shadowed silently. Universal CLI
 * conventions cannot be overridden from user data.
 *
 * @param commands    NULL-terminated registry of top-level commands.
 * @param argc        Process argc.
 * @param argv        Process argv.
 * @param command_out On ARGS_ROOT_COMMAND, populated with the matched
 *                    spec; unchanged otherwise. NULL is allowed.
 * @return            One of `args_root_outcome_t`.
 */
args_root_outcome_t args_resolve_root(
    const args_command_t *const *commands, int argc, char **argv,
    const args_command_t **command_out
);

/* ══════════════════════════════════════════════════════════════════
 * Parse entry point
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Parse argv[start_idx..argc) against a command's spec.
 *
 * Pre-conditions:
 *   - command != NULL;
 *   - arena != NULL (used for error messages and positional arrays);
 *   - opts_out != NULL, zero-initialized, of size `command->opts_size`;
 *   - errors_out != NULL (will be initialized; stack-declared is fine).
 *
 * Behavior:
 *   - Seeds defaults via `init_defaults` if set.
 *   - For subcommand trees: recurses into the matching child, or into
 *     `default_subcommand` when the user passes no positional.
 *   - Otherwise walks the token stream applying opts, collecting parse
 *     errors up to ARGS_ERRORS_CAP.
 *   - Runs `post_parse` then `validate` if no errors so far.
 *
 * Help wins over errors: if `-h`/`--help` appears in the token stream
 * the parser returns ARGS_HELP_REQUESTED immediately, discarding any
 * errors already recorded AND any tokens still to read. `dotta add
 * --bogus -h` prints help and exits 0 — the user asked for help, so
 * the typo is a secondary concern. Rule of thumb for spec authors:
 * don't rely on post_parse or validate firing when -h is on the line.
 *
 * Side effects: none on stdio; none on global state; no exit(). Every
 * allocation comes from `arena`.
 *
 * @param command      Command spec (must not be NULL).
 * @param argc         Argument count.
 * @param argv         Argument vector.
 * @param start_idx    First index to parse (1 at root, 2 after command).
 * @param arena        Arena for error messages / positional arrays.
 * @param opts_out     Zero-initialized options struct; populated in place.
 * @param errors_out   Caller-provided; populated with parse errors.
 * @param resolved_out If non-NULL, set to the leaf command actually
 *                     reached after subcommand resolution. The caller
 *                     uses this to render help/errors against the
 *                     correct command and to invoke the leaf's
 *                     dispatch. For a non-tree command this is just
 *                     `command`. NULL is allowed for callers that do
 *                     not care (test fixtures, etc.).
 * @return Outcome enum (`-v`/`--version` is handled at root, not here).
 */
args_outcome_t args_parse(
    const args_command_t *command, int argc, char **argv, int start_idx,
    arena_t *arena, void *opts_out, args_errors_t *errors_out,
    const args_command_t **resolved_out
);

/* ══════════════════════════════════════════════════════════════════
 * Rendering (all callers decide when, where, and to which stream)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Render the root-level usage banner and command summary list.
 *
 * Hidden commands are skipped. The commands array is terminated by
 * a NULL entry.
 */
void args_render_root_usage(
    FILE *out,
    const args_command_t *const *commands,
    const char *prog
);

/**
 * Render a single `Usage: ...` line from `command->usage`.
 */
void args_render_usage_line(
    FILE *out,
    const args_command_t *command,
    const char *prog
);

/**
 * Render full help for a command:
 *   1) usage line,
 *   2) summary,
 *   3) description (before options),
 *   4) options table (sectioned by ARGS_GROUP rows),
 *   5) subcommand list,
 *   6) notes (after options),
 *   7) examples,
 *   8) epilogue.
 *
 * Empty fields are silently skipped. `%s` substitutes to `prog` in any
 * free-form block.
 */
void args_render_help(
    FILE *out,
    const args_command_t *command,
    const char *prog
);

/**
 * Render collected parse errors followed by the usage line and
 * "Try '<prog> <cmd> --help'" hint. Safe to call with errors->count == 0
 * (it will still emit the usage/help hint).
 */
void args_render_errors(
    FILE *out,
    const args_errors_t *errors,
    const args_command_t *command,
    const char *prog
);

/* ══════════════════════════════════════════════════════════════════
 * Completion export (build-time)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Emit a fish-shell completion script body for the command registry.
 *
 * The generated output is plain fish script lines (`complete -c <prog>
 * ...`) — consumable via `source` or concatenation into a checked-in
 * file. The emitter handles:
 *
 *   - top-level built-ins (`-h`, `-v`),
 *   - one root-alias entry per command with `root_aliases` set,
 *   - one command row per non-hidden command,
 *   - one option row per non-hidden flag/string/int/append,
 *   - one subcommand row per non-hidden subcommand,
 *   - one option row per subcommand's own flags,
 *   - a `__<prog>_value_flags` variable listing all value-taking flags
 *     across the entire registry (used by fish's positional-arg scan).
 *
 * Dynamic completions (profile names, file names, commit SHAs) are
 * NOT emitted here — they depend on runtime repository state and live
 * in a hand-maintained `<prog>.fish` entry point that sources this
 * output.
 *
 * Positional-class hints are NOT emitted either; fish offers a union
 * (profiles ∪ files) for polymorphic positionals and filters by prefix.
 *
 * @param out      Output stream (fully buffered writes are fine).
 * @param arena    Borrowed scratch arena for token storage and dedup set.
 *                 All allocations live until the caller destroys the
 *                 arena; callers typically pass their command-scoped
 *                 arena. Must not be NULL.
 * @param commands NULL-terminated registry of top-level commands.
 * @param prog     Program name used for `complete -c <prog>` lines and
 *                 `__<prog>_*` helper-function references. Must match
 *                 the prefix used in the hand-maintained fish entry
 *                 point that sources the generated script.
 */
void args_export_completion_fish(
    FILE *out,
    arena_t *arena,
    const args_command_t *const *commands,
    const char *prog
);

/* ══════════════════════════════════════════════════════════════════
 * Utilities exposed for hooks
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Parse a bounded decimal long. Used internally by ARGS_KIND_INT and
 * exposed for post_parse hooks that need identical semantics.
 *
 * Fails on: NULL, empty, non-numeric trailing chars, value outside
 * [min, max], or ERANGE from strtol.
 *
 * @return NULL on success; `error_t *` (caller frees) on failure.
 */
error_t *args_parse_long(const char *text, long min, long max, long *out);

/* ══════════════════════════════════════════════════════════════════
 * Spec-writing macros
 *
 * Naming rule for `flags`:
 *   - Space-separated. No dashes. Single-char = short (-x),
 *     multi-char = long (--xxx). Author controls display order.
 * ══════════════════════════════════════════════════════════════════ */

#define ARGS_END \
    { .kind = ARGS_KIND_END }

#define ARGS_GROUP(title_s) \
    { .kind = ARGS_KIND_GROUP, .help = (title_s) }

/**
 * Flag → bool field is set to true when any listed name is seen.
 * Field type: bool.
 */
#define ARGS_FLAG(flags_s, type, field, help_s) \
    { .kind   = ARGS_KIND_FLAG, \
      .flags  = (flags_s), \
      .help   = (help_s), \
      .offset = offsetof(type, field) }

/**
 * Flag → int field is set to `value` when any listed name is seen.
 * Use for tri-state enums where multiple flags write distinct values
 * into the same field (e.g., `--encrypt` sets 1, `--no-encrypt` sets 2).
 * Field type: int.
 */
#define ARGS_FLAG_SET(flags_s, type, field, value, help_s) \
    { .kind      = ARGS_KIND_FLAG_SET, \
      .flags     = (flags_s), \
      .help      = (help_s), \
      .offset    = offsetof(type, field), \
      .set_value = (value) }

/**
 * String option: `--name VALUE` or `--name=VALUE`. Field type: const char *.
 * The stored pointer borrows from argv (lives as long as argv).
 */
#define ARGS_STRING(flags_s, label_s, type, field, help_s) \
    { .kind        = ARGS_KIND_STRING, \
      .flags       = (flags_s), \
      .value_label = (label_s), \
      .help        = (help_s), \
      .offset      = offsetof(type, field) }

/**
 * Repeatable option: each occurrence appends to a char** array.
 * Field types: `char **field; size_t count_field;`. Both borrow argv.
 * An ARGS_POSITIONAL row may target the same field/count pair to
 * merge bare positionals into the same array (argv-order preserved).
 */
#define ARGS_APPEND(flags_s, label_s, type, field, count_field, help_s) \
    { .kind         = ARGS_KIND_APPEND, \
      .flags        = (flags_s), \
      .value_label  = (label_s), \
      .help         = (help_s), \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Typed integer: parsed via strtol, range-checked [min, max].
 * Field type: long.
 */
#define ARGS_INT(flags_s, label_s, type, field, min_v, max_v, help_s) \
    { .kind        = ARGS_KIND_INT, \
      .flags       = (flags_s), \
      .value_label = (label_s), \
      .help        = (help_s), \
      .offset      = offsetof(type, field), \
      .int_min     = (min_v), \
      .int_max     = (max_v) }

/**
 * Classified positional → append to a char** array.
 * The command's classify() routes each positional to the row whose
 * class_accept matches. Field types: `char **field; size_t count;`.
 */
#define ARGS_POSITIONAL(cls, type, field, count_field) \
    { .kind         = ARGS_KIND_POSITIONAL, \
      .class_accept = (cls), \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Classified documented positional: single-value target with an inline
 * label + help string (rendered under "Arguments:"). The `cls` routes
 * tokens from classify() to this row; multiple matches silently
 * overwrite, so pair with a classifier that returns a unique class
 * for single-value semantics.
 */
#define ARGS_POSITIONAL_ARG(cls, label_s, type, field, help_s) \
    { .kind         = ARGS_KIND_POSITIONAL_ARG, \
      .class_accept = (cls), \
      .value_label  = (label_s), \
      .help         = (help_s), \
      .offset       = offsetof(type, field) }

/**
 * Unclassified positional bucket — all positionals append here. Use
 * for commands that don't need a classify() function (single-bucket
 * positionals). `class_accept` is left at zero-init, matching the
 * engine's zero default for cls when no classifier runs.
 * Field types: `char **field; size_t count;`.
 */
#define ARGS_POSITIONAL_ANY(type, field, count_field) \
    { .kind         = ARGS_KIND_POSITIONAL, \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Unclassified documented positional: single-value target with an
 * inline label + help (rendered under "Arguments:"). Companion to
 * ANY for commands that take at most one positional and want to
 * document it.
 */
#define ARGS_POSITIONAL_ANY_ARG(label_s, type, field, help_s) \
    { .kind        = ARGS_KIND_POSITIONAL_ARG, \
      .value_label = (label_s), \
      .help        = (help_s), \
      .offset      = offsetof(type, field) }

/**
 * Unclassified raw positional bucket: every positional that does not
 * match a POSITIONAL / POSITIONAL_ARG row lands here. Enforced min/max
 * bounds are reported as parse errors. The command's post_parse hook
 * is responsible for interpreting the bucket.
 */
#define ARGS_POSITIONAL_RAW(type, field, count_field, min_c, max_c) \
    { .kind           = ARGS_KIND_POSITIONAL_RAW, \
      .offset         = offsetof(type, field), \
      .count_offset   = offsetof(type, count_field), \
      .positional_min = (min_c), \
      .positional_max = (max_c) }

#endif /* DOTTA_ARGS_H */
