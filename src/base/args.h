/**
 * args.h - Declarative argument-parser engine
 *
 * A command's argument signature is data, not imperative code. The `args_command_t`
 * struct is the single source of truth: parser, help, completion, and dispatch
 * are all projections of the same row.
 *
 * A command is declared as:
 *   - an options-struct typedef owned by `src/cmds/<name>.h`;
 *   - a `static const args_opt_t opts[]` table terminated by ARGS_END;
 *   - a `const args_command_t` static value exposing name, summary, usage, help
 *     text, the opts table, hooks, and a dispatch function.
 *
 * The engine:
 *   - never writes to stdio (rendering is caller-driven);
 *   - never calls exit();
 *   - holds no global state;
 *   - uses a caller-supplied arena for every allocation (error messages, positional
 *     arrays, post-parse strings).
 *
 * Key design points
 * -----------------
 *   `flags`                Space-separated list of names. Single-char names
 *                          are short forms (emitted with a single dash);
 *                          multi-char names are long forms (double dash). Display
 *                          order follows write order — no "canonical" vs "alias"
 *                          distinction in the renderer.
 *
 *   Positional model       Three shapes: classified (engine routes token
 *                          by `classify(token)` to the matching POSITIONAL /
 *                          POSITIONAL_ARG row), unclassified (POSITIONAL_ANY /
 *                          POSITIONAL_ANY_ARG — no classify; every token is of
 *                          the one class), and raw bucket (POSITIONAL_RAW —
 *                          commands interpret in post_parse). An ARG row takes
 *                          one token and is then passed over, so ARG rows take
 *                          the positionals of their class in declaration order
 *                          (`<url> [path]` is two rows) and may be required. A
 *                          grammar the order of rows cannot state — a verb read
 *                          from the first positional, a refspec whose shape decides
 *                          the next — uses POSITIONAL_RAW.
 *
 *   Tri-state flags        One `int` field and one `ARGS_FLAG_SET` row per
 *                          value it can take, 0 reserved for "no flag given".
 *                          The zeroed opts struct is that sentinel, so
 *                          `init_defaults` leaves the field alone and `post_parse`
 *                          resolves unset to the default — which is what lets a
 *                          command tell "the user asked for the default" from
 *                          "the user asked for nothing". Two rows of one group
 *                          naming different values is a contradiction in the
 *                          grammar, and the engine refuses it.
 *
 *   Subcommand trees       Parent has `subcommands`. Every subcommand in a
 *                          tree MUST share the parent's options struct type (so
 *                          `opts_size` allocates enough for any sub). Each sub's
 *                          `init_defaults` sets the discriminator. At the slot,
 *                          nothing or a flag name is the `default_subcommand`'s
 *                          line.
 *
 *   Root-level dispatch    `args_resolve_root` classifies argv[1] into a
 *                          built-in flag (`-h`/`--help`, `-v`/`--version`), a
 *                          command (by name), a shortcut — a subcommand whose
 *                          aliases stand at the root too, `<prog> enable` for
 *                          `<prog> profile enable` (`args_subcommand_t::
 *                          shortcut`), resolved to the subcommand's own spec —
 *                          or a root alias (`args_command_t::root_aliases`).
 *
 *   Completion             Flags and subcommands complete from the rows, as
 *                          rules the fish exporter writes. What can stand at a
 *                          positional, or as a flag's value, is the command's
 *                          `complete` hook, asked at runtime with the buckets a
 *                          partial parse filled (`args_complete_candidates`);
 *                          the exported wrapper is how the shell asks.
 *
 *   Cleanup chain          The engine is signal-safe and key-zero-safe: no
 *                          `exit()`, no libc-free in the error path, no
 *                          process-level state. The dispatcher owns the arena
 *                          and destroys it after dispatch returns.
 *
 * Picking a subcommand pattern
 * ----------------------------
 * Three patterns coexist because real CLIs vary. Pick by shape, not by taste:
 *
 *   Subcommand tree        Use when the first word is a verb: each sub is an
 *   (.subcommands)         action with rows of its own. Subs may repeat a
 *                          flag — `-v` on each of `key {set|clear|status}` is
 *                          three rows, not a reason for a router. A bare `<prog>
 *                          <cmd>` runs the `default_subcommand`. Example: `dotta
 *                          profile {list|enable|...}`.
 *
 *   POSITIONAL_RAW         Use when what a positional means is decided by
 *   + post_parse           its shape or by what follows it — `[profile:]file
 *                          [@commit]`, a `<file> <commit>` told from a `<profile>
 *                          <file>` by the tokens themselves — which no order of
 *                          rows can state. Example: `dotta show`, `dotta revert`.
 *
 *   Classify + POSITIONAL  Use for a SINGLE action whose positionals
 *   (multiple class rows)  are polymorphic by shape. The classifier
 *                          maps each token to a class; matching rows route to
 *                          distinct fields. Example: `dotta apply
 *                          [profile|file]...` — both kinds can appear in any order.
 *
 * If two or more fit, prefer the tree: it gives per-sub `--help` for free, the
 * sub names and their summaries in the completion rules, and no hand-rolled
 * dispatch switch.
 */

#ifndef DOTTA_ARGS_H
#define DOTTA_ARGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Local forward declarations of base-layer types. Defined as typedefs in <types.h>;
 * we re-declare here (compatible since the struct tags match) so args.h has zero
 * domain dependencies and can compile as a standalone parser engine. */
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
    ARGS_KIND_FLAG_SET,        /* int  field → `set_value`; 0 = no flag given */
    ARGS_KIND_STRING,          /* const char * field → next token */
    ARGS_KIND_APPEND,          /* char ** + size_t → appends one */
    ARGS_KIND_INT,             /* long field → typed int in [min,max] */
    ARGS_KIND_POSITIONAL,      /* Positional → APPEND tgt (class_accept) */
    ARGS_KIND_POSITIONAL_ARG,  /* Positional → STRING tgt (class_accept) */
    ARGS_KIND_POSITIONAL_RAW   /* Fallback bucket for post_parse */
} args_kind_t;

/**
 * Positional classification ID — opaque integer the engine compares by equality,
 * nothing more. Each command that needs polymorphic positionals declares a
 * command-local enum and returns those values from `classify()`. The engine has
 * no interest in the value space beyond `class_accept == classify(tok)`, so domain
 * vocabulary (profiles, files, git refs, ...) stays out of this header.
 *
 * Commands without polymorphic positionals don't touch this field at all — they
 * use `ARGS_POSITIONAL_ANY` / `ARGS_POSITIONAL_ANY_ARG` and the zero-initialized
 * `class_accept` matches the engine's zero default (cls=0 when no classifier is
 * configured).
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
 * One value per distinct dispatcher response. The caller branches on this to
 * render help, print version, dispatch a matched command, or report an unknown
 * token — keeping the root-layer decision table in the caller rather than the
 * parser.
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
 * Called for every positional token when the command defines it. The returned
 * value is matched against `class_accept` on each POSITIONAL / POSITIONAL_ARG
 * row; the first row with equal value wins. A token whose class matches no row
 * falls back to the POSITIONAL_RAW bucket (if present) or reports an "unexpected
 * argument" error.
 *
 * Return values are defined by the command itself via a local enum starting at
 * 1 — see `args_class_t`.
 */
typedef args_class_t (*args_classify)(const char *token);

/**
 * Seed non-zero defaults on the options struct before parsing begins.
 *
 * Called exactly once after the struct is zero-initialized and before any tokens
 * are processed. Use for flags whose default is `true` or for tri-state enums
 * with a non-zero neutral value.
 */
typedef void (*args_defaults)(void *opts);

/**
 * Post-parse hook: interpret positional buckets, do secondary parsing, and reject
 * what the rows cannot express.
 *
 * Called after all tokens have been consumed without recorded parse errors and
 * after the positional rows' counts are validated. Use for refspec parsing,
 * N-positional reinterpretation, mode inference, and cross-field invariants
 * (mutually exclusive flags, a value one mode requires and another forbids).
 * Allocations may use `arena`. Returning a non-NULL error aborts dispatch; the
 * error is wrapped into the error collector and freed.
 */
typedef error_t *(*args_postparse)(
    void *opts, arena_t *arena,
    const args_command_t *command
);

/**
 * Where the cursor stands, for the completion hook.
 *
 * The hook reads the command's options struct as the tokens before the cursor
 * left it — every flag applied, every positional routed to its bucket — without
 * the settle: no count check, no post_parse, which are written for a complete
 * line. It re-derives only what the position decides; where the grammar needs
 * the next token to know (show's second positional is a file or a commit), it
 * offers the union.
 */
typedef struct args_completion {
    const args_opt_t *value_of;  /* Non-NULL: the cursor is this option's value */
    const char *current;         /* What is being typed: the token, or the text after
                                  * `=` of an inline `--name=text`; "" when nothing */
} args_completion_t;

/**
 * What the hook may ask the shell to add beside its candidates: its own completion
 * of `current` as a path — every path, or directories only. One thing at most;
 * a path completion includes the directories.
 */
typedef enum args_want {
    ARGS_WANT_NONE,    /* Nothing beyond the candidates printed */
    ARGS_WANT_FILES,   /* Native path completion of `current` */
    ARGS_WANT_DIRS     /* Native directory completion of `current` */
} args_want_t;

/**
 * Completion hook: what can stand at the cursor.
 *
 * Prints candidates to `out`, one per line as `token` or `token<TAB>description`
 * — the sources are the application's, the engine never reads them — and returns
 * what the shell should add. `ctx` is the same opaque payload `dispatch` receives.
 * A command without a hook offers nothing beyond its flags and subcommands, which
 * the exported rules carry.
 */
typedef args_want_t (*args_complete)(
    const void *ctx, const void *opts,
    const args_completion_t *at, FILE *out
);

/**
 * Command entry point. Called by the dispatcher after successful parse.
 *
 * `ctx` is opaque to the engine — it is whatever the caller wants to thread through
 * to the command (typically a domain-specific dispatch bundle holding repo handle,
 * config, output stream, arena, etc.). Each command's dispatch wrapper casts
 * `ctx` to its expected type on the first line. `opts` points to the parsed options
 * struct.
 */
typedef error_t *(*args_dispatch)(const void *ctx, void *opts);

/* ══════════════════════════════════════════════════════════════════
 * Core structures
 * ══════════════════════════════════════════════════════════════════ */

/**
 * One row in an opts[] table.
 *
 * All fields beyond `kind` are optional per kind; unused bytes stay zero. A single
 * struct (not a union) is used because it lets tables be declared as `static
 * const args_opt_t opts[] = { ... }` at file scope and keeps rows trivially
 * copyable.
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
    int set_value;              /* FLAG_SET: value assigned to the int field (non-zero) */
    long int_min;               /* INT: inclusive lower bound */
    long int_max;               /* INT: inclusive upper bound */
    size_t positional_min;      /* Positional rows: minimum count; an ARG row's 1 = required */
    size_t positional_max;      /* POSITIONAL_RAW: maximum count 0 = unlimited */

    /* Display */
    bool hidden;                /* Suppress from help rendering */
};

/**
 * Subcommand entry in a tree.
 *
 * `name` is a space-separated alias list; the first name is the canonical form
 * shown in help output. Every subcommand in a tree must share the parent's options
 * struct type (same opts_size), since the dispatcher allocates opts based on
 * the top-level command.
 *
 * A `shortcut` — read on the subcommands of a top-level command — also stands
 * at the root by its aliases: `<prog> enable <name>` for `<prog> profile enable
 * <name>`. The root resolver answers it with the subcommand's own spec, so parse,
 * help and dispatch are the subcommand's as if its parent had been typed; the
 * root usage lists it under "Shortcuts:" as the word and the subcommand it stands
 * for, and the completion export gives it a command's rows. A command's name
 * wins over a shortcut's alias.
 */
struct args_subcommand {
    const char *name;               /* "remove rm" — space-separated */
    const args_command_t *command;  /* Subcommand specification */
    bool hidden;                    /* Hide from help output */
    bool shortcut;                  /* Its aliases stand at the root too */
};

/**
 * A command as a first-class value.
 *
 * All projections (parser, help renderer, completion exporter, dispatcher) consume
 * this struct. Registry entries are `const args_command_t` at file scope with
 * static storage duration.
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
    const args_command_t *default_subcommand;  /* Reached by no positional, or a flag at the slot */

    /* Behavior hooks (all optional) */
    args_classify classify;      /* Classify positional token into command-local class ID */
    args_defaults init_defaults; /* Seed opts with non-zero defaults before parsing */
    args_postparse post_parse;   /* Populate derived fields, reject invariants; non-NULL return aborts dispatch */
    args_complete complete;      /* What can stand at the cursor; NULL = nothing */

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
 * Eight slots hold every realistic typo-heavy parse. Overflow sets the flag;
 * later errors are dropped silently and the renderer shows a "more errors
 * suppressed" trailer.
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
 * Pure function: no allocations, no I/O, no global state. The caller branches
 * on the returned outcome — rendering help, printing version, dispatching the
 * matched spec, or reporting an unknown token. The dispatcher sits above the
 * parser: once a command is resolved here, `args_parse()` handles argv[2..] under
 * the spec's own rules.
 *
 * Resolution order:
 *   1. argc < 2                              → ARGS_ROOT_NONE
 *   2. argv[1] ∈ {-h, --help}                → ARGS_ROOT_HELP
 *   3. argv[1] ∈ {-v, --version}             → ARGS_ROOT_VERSION
 *   4. bare word matching `cmd->name`        → ARGS_ROOT_COMMAND
 *   5. bare word matching an alias of a
 *      `shortcut` subcommand of a command    → ARGS_ROOT_COMMAND, the
 *                                              subcommand's own spec
 *   6. flag form (`-X` / `--XXX`) matching
 *      `cmd->root_aliases`                   → ARGS_ROOT_COMMAND
 *   7. anything else                         → ARGS_ROOT_UNKNOWN
 *
 * Built-ins win over `root_aliases` — a command that declares `root_aliases =
 * "help h"` is shadowed silently. Universal CLI conventions cannot be overridden
 * from user data. Likewise a command's name wins over a shortcut's alias, and
 * the first shortcut in registry order over a later one spelled the same: the
 * shadowed one is unreachable, and the root usage shows both.
 *
 * @param commands    NULL-terminated registry of top-level commands.
 * @param argc        Process argc.
 * @param argv        Process argv.
 * @param command_out On ARGS_ROOT_COMMAND, populated with the matched spec — a
 *                    shortcut's is the subcommand's own, which `args_parse()`
 *                    reads from argv[2] like any command's; unchanged otherwise.
 *                    NULL is allowed.
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
 *     `default_subcommand` when the user passes no positional, or a flag at the
 *     slot.
 *   - Otherwise walks the token stream applying opts, collecting parse errors
 *     up to ARGS_ERRORS_CAP.
 *   - Runs `post_parse` if no errors so far.
 *
 * Help wins over errors: if `-h`/`--help` appears in the token stream the parser
 * returns ARGS_HELP_REQUESTED immediately, discarding any errors already recorded
 * AND any tokens still to read. `dotta add --bogus -h` prints help and exits 0
 * — the user asked for help, so the typo is a secondary concern. Rule of thumb
 * for spec authors: don't rely on post_parse firing when -h is on the line.
 *
 * Side effects: none on stdio; none on global state; no exit(). Every allocation
 * comes from `arena`.
 *
 * @param command      Command spec (must not be NULL).
 * @param argc         Argument count.
 * @param argv         Argument vector.
 * @param start_idx    First index to parse (1 at root, 2 after command).
 * @param arena        Arena for error messages / positional arrays.
 * @param opts_out     Zero-initialized options struct; populated in place.
 * @param errors_out   Caller-provided; populated with parse errors.
 * @param resolved_out If non-NULL, set to the leaf command actually reached after
 *                     subcommand resolution. The caller uses this to render
 *                     help/errors against the correct command and to invoke the
 *                     leaf's dispatch. For a non-tree command this is just
 *                     `command`. NULL is allowed for callers that do not care
 *                     (test fixtures, etc.).
 * @return Outcome enum (`-v`/`--version` is handled at root, not here).
 */
args_outcome_t args_parse(
    const args_command_t *command, int argc, char **argv, int start_idx,
    arena_t *arena, void *opts_out, args_errors_t *errors_out,
    const args_command_t **resolved_out
);

/* ══════════════════════════════════════════════════════════════════
 * Completion (runtime)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Answer the shell: what can stand at the cursor of a command line.
 *
 * `argv[1..argc)` are the complete tokens of the line, argv[0] the program as
 * at dispatch; `current` is the token being typed — possibly empty, never routed
 * to a bucket. The line is resolved and consumed exactly as `args_parse` would
 * — the registry for argv[1], the subcommand tree, the option loop — except that
 * it stops where the tokens stop: a trailing value flag names the value being
 * typed instead of recording an error, and a line the command would reject (an
 * unknown flag, one positional too many) still has a next token, so the loop's
 * errors are recorded and ignored. Then the command's `complete` hook answers
 * with the buckets as they stand.
 *
 * Nothing is printed and no hook is called where the exported rules already answer
 * or nothing can: the root slot (the command names), a tree's subcommand slot
 * (the subcommand names), the name of a flag being typed (`-x`, `--name`, `--`),
 * `-h` anywhere on the line, a passthrough command, a command without a hook.
 *
 * Output — the candidates protocol the exported wrapper reads:
 *
 *   token<TAB>description, or token     one candidate per line;
 *   <TAB>files<TAB>current              the shell completes paths natively;
 *   <TAB>dirs<TAB>current               the shell completes directories.
 *
 * A token is never empty, so a line beginning with a tab is a request — and there
 * is at most one, printed after the hook has returned: the last line. The wrapper
 * reads it there and passes every line before it through untouched, so a large
 * answer costs the shell nothing per line.
 *
 * @param commands NULL-terminated root registry.
 * @param argc     Count of `argv`.
 * @param argv     The program name, then the complete tokens of the line.
 * @param current  The token being typed; "" when none.
 * @param arena    Arena for the options struct and its buckets.
 * @param ctx      Opaque payload handed to the hook, as `dispatch`'s.
 * @param out      Output stream for the candidates.
 */
void args_complete_candidates(
    const args_command_t *const *commands, int argc, char **argv,
    const char *current, arena_t *arena, const void *ctx, FILE *out
);

/* ══════════════════════════════════════════════════════════════════
 * Rendering (all callers decide when, where, and to which stream)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Render the root-level usage banner and command summary list, then the shortcuts
 * — each as the word and the subcommand it stands for — and the root options.
 *
 * Hidden commands and subcommands are skipped. The commands array is terminated
 * by a NULL entry.
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
 * Empty fields are silently skipped. `%s` substitutes to `prog` in any free-form
 * block.
 */
void args_render_help(
    FILE *out,
    const args_command_t *command,
    const char *prog
);

/**
 * Render collected parse errors followed by the usage line and "Try '<prog> <cmd>
 * --help'" hint. Safe to call with errors->count == 0 (it will still emit the
 * usage/help hint).
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
 * Emit the fish-shell completion script for the command registry — the whole of
 * it, ready to be installed as `<prog>.fish`:
 *
 *   - the condition helpers the rules are guarded by (`__<prog>_needs_command`,
 *     `__<prog>_using_command`, `__<prog>_needs_subcommand`,
 *     `__<prog>_using_default_subcommand`, `__<prog>_using_subcommand`,
 *     `__<prog>_positional`), reading the line as the engine does;
 *   - the wrapper `__<prog>_candidates`, which runs `<prog> <candidates>` with
 *     the line's tokens and reads the candidates protocol back
 *     (`args_complete_candidates`): the candidates pass through, a path request
 *     — the last line, when there is one — goes to the shell's own path completion;
 *   - one positional rule, under any command, that asks the wrapper — unless
 *     the token being typed is a flag name, which the flag rows answer;
 *   - top-level built-ins (`-h`, `-v`),
 *   - one root-alias entry per command with `root_aliases` set,
 *   - one command row per non-hidden command, and one per shortcut subcommand,
 *     whose rules then stand under its aliases as a command's do,
 *   - one option row per non-hidden flag/string/int/append, a value-taking one
 *     asking the wrapper for its value; a single-char name is declared as fish's
 *     old-style option (`-o X`) — exactly `-X`, never bundled, its value the
 *     next token — which is how the parser reads it,
 *   - one subcommand row per non-hidden subcommand, at the open slot,
 *   - one option row per subcommand's own flags; the default subcommand's also
 *     at the open slot and after a flag there, where the parser reads them.
 *
 * What can stand at a positional or as a value — profile names, file names, commit
 * SHAs, paths — is never in the script: it depends on the line and the
 * application's state, and the binary answers at runtime.
 *
 * Every name the script carries as a bare fish word — the program, each command
 * name and root alias, each subcommand alias, each flag name, hidden ones too —
 * must be one: letters, digits, `_` and `-`. A name outside that grammar is not
 * quoted away but refused, before anything is written: fish would read a space
 * as two candidates, `$` and globs as expansions, a quote or `/` as a script
 * that does not load. Descriptions are free text and are escaped.
 *
 * @param out        Output stream (fully buffered writes are fine).
 * @param commands   NULL-terminated registry of top-level commands.
 * @param prog       Program name used for `complete -c <prog>` lines and the
 *                   `__<prog>_*` helper-function names.
 * @param candidates The arguments after `prog` that run the candidates driver,
 *                   e.g. "__complete": the wrapper appends `--current=<token>
 *                   -- <tokens…>`. Fish source, written verbatim.
 * @return           NULL when the script was written; else, nothing written,
 *                   an error naming the first name that cannot stand as a fish
 *                   word (caller frees).
 */
error_t *args_export_completion_fish(
    FILE *out,
    const args_command_t *const *commands,
    const char *prog,
    const char *candidates
);

/* ══════════════════════════════════════════════════════════════════
 * Utilities exposed for hooks
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Parse a bounded decimal long. Used internally by ARGS_KIND_INT and exposed
 * for post_parse hooks that need identical semantics.
 *
 * Fails on: NULL, empty, non-numeric trailing chars, value outside [min, max],
 * or ERANGE from strtol.
 *
 * @return NULL on success; `error_t *` (caller frees) on failure.
 */
error_t *args_parse_long(const char *text, long min, long max, long *out);

/**
 * For a completion hook: true when the cursor is the value of the option row
 * that targets `field` of the options struct `type`. A row's identity is the
 * field it writes — no two value-taking rows of one command share one.
 */
#define ARGS_VALUE_IS(at, type, field) \
    ((at)->value_of != NULL && (at)->value_of->offset == offsetof(type, field))

/* ══════════════════════════════════════════════════════════════════
 * Spec-writing macros
 *
 * Naming rule for `flags`:
 *   - Space-separated. No dashes. Single-char = short (-x), multi-char = long
 *     (--xxx). Author controls display order.
 * ══════════════════════════════════════════════════════════════════ */

#define ARGS_END \
    { .kind = ARGS_KIND_END }

#define ARGS_GROUP(title_s) \
    { .kind = ARGS_KIND_GROUP, .help = (title_s) }

/**
 * Flag → bool field is set to true when any listed name is seen. Field type: bool.
 */
#define ARGS_FLAG(flags_s, type, field, help_s) \
    { .kind   = ARGS_KIND_FLAG, \
      .flags  = (flags_s), \
      .help   = (help_s), \
      .offset = offsetof(type, field) }

/**
 * Flag → int field is set to `value` when any listed name is seen. Use for
 * tri-state enums where multiple flags write distinct values into the same field
 * (e.g., `--encrypt` sets 1, `--no-encrypt` sets 2). Field type: int.
 *
 * `value` must be non-zero and distinct within the group: zero is the field's
 * "no flag given" sentinel, so a row writing it would be inert, and the engine
 * reads the field back to tell one spelling of the group from a second. The engine
 * is that field's only writer — nothing else in a spec may seed it.
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
 * Repeatable option: each occurrence appends to a char** array. Field types:
 * `char **field; size_t count_field;`. Both borrow argv. An ARGS_POSITIONAL row
 * may target the same field/count pair to merge bare positionals into the same
 * array (argv-order preserved).
 */
#define ARGS_APPEND(flags_s, label_s, type, field, count_field, help_s) \
    { .kind         = ARGS_KIND_APPEND, \
      .flags        = (flags_s), \
      .value_label  = (label_s), \
      .help         = (help_s), \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Typed integer: parsed via strtol, range-checked [min, max]. Field type: long.
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
 * Classified positional → append to a char** array. The command's classify()
 * routes each positional to the row whose class_accept matches. Field types:
 * `char **field; size_t count;`.
 */
#define ARGS_POSITIONAL(cls, type, field, count_field) \
    { .kind         = ARGS_KIND_POSITIONAL, \
      .class_accept = (cls), \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Classified documented positional: single-value target with an inline label +
 * help string (rendered under "Arguments:"). The row takes the first token of
 * class `cls` and is then passed over — a token whose class has no row left to
 * take it falls to the RAW bucket, or is an "unexpected argument" — so several
 * rows of one class take its tokens in declaration order. `min_c` 1 makes the
 * row required, 0 optional.
 */
#define ARGS_POSITIONAL_ARG(cls, label_s, type, field, min_c, help_s) \
    { .kind           = ARGS_KIND_POSITIONAL_ARG, \
      .class_accept   = (cls), \
      .value_label    = (label_s), \
      .help           = (help_s), \
      .offset         = offsetof(type, field), \
      .positional_min = (min_c) }

/**
 * Unclassified positional bucket — all positionals append here. Use for commands
 * that don't need a classify() function (single-bucket positionals). `class_accept`
 * is left at zero-init, matching the engine's zero default for cls when no
 * classifier runs. Field types: `char **field; size_t count;`.
 */
#define ARGS_POSITIONAL_ANY(type, field, count_field) \
    { .kind         = ARGS_KIND_POSITIONAL, \
      .offset       = offsetof(type, field), \
      .count_offset = offsetof(type, count_field) }

/**
 * Unclassified documented positional: single-value target with an inline label
 * + help (rendered under "Arguments:"). Companion to ANY: the rows take the
 * positionals in declaration order — `<url> [path]` is two rows — and `min_c` 1
 * makes a row required. A row whose field a flag has already written (a `-p <name>`
 * beside a `[name]` positional) is passed over the same way, and the positional
 * it would have taken is unexpected.
 */
#define ARGS_POSITIONAL_ANY_ARG(label_s, type, field, min_c, help_s) \
    { .kind           = ARGS_KIND_POSITIONAL_ARG, \
      .value_label    = (label_s), \
      .help           = (help_s), \
      .offset         = offsetof(type, field), \
      .positional_min = (min_c) }

/**
 * Unclassified raw positional bucket: every positional that does not match a
 * POSITIONAL / POSITIONAL_ARG row lands here. Enforced min/max bounds are reported
 * as parse errors. The command's post_parse hook is responsible for interpreting
 * the bucket.
 */
#define ARGS_POSITIONAL_RAW(type, field, count_field, min_c, max_c) \
    { .kind           = ARGS_KIND_POSITIONAL_RAW, \
      .offset         = offsetof(type, field), \
      .count_offset   = offsetof(type, count_field), \
      .positional_min = (min_c), \
      .positional_max = (max_c) }

#endif /* DOTTA_ARGS_H */
