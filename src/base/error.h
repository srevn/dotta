/**
 * error.h - Error handling for dotta
 *
 * Centralized error handling with context tracking and propagation helpers.
 *
 * ERR_PERMISSION
 * --------------
 * The one code a consumer acts on rather than prints, so its meaning is fixed
 * here and not per producer: a refusal an identity met. The kernel's — EACCES
 * or EPERM, through error_from_errno below — and libgit2's owner check on the
 * repository, which spells its own because GIT_EOWNER carries no errno. An answer
 * dotta looked up is never one, whatever the answer is about: a hook's mode, a
 * claim's ids, a policy's verdict. Every reader turns the code straight into a
 * remedy only a refusal has — cmds/add and cmds/update close with the sudo line,
 * core/workspace classes the failed look UNREADABLE and its readers name root,
 * utils/repo offers to reclaim the repository — and none of them can see which
 * producer it came from, which is what makes the class load-bearing rather than
 * descriptive.
 *
 * sys/identity's drop is outside the rule and out of reach of it: its two refusals
 * say the run cannot *become* an identity, they are coded by subsystem because
 * a setuid-family EAGAIN is not ERR_FS, and identity_init returns to main() before
 * there is a command to read them.
 *
 * core/state's refusals are outside it by subsystem too: SQLite opens the store's
 * database as the invoker on every run, and no second try spans a call into it
 * (sys/filesystem), so a refusal there is a broken installation to report, never
 * a reach a root run would have. They are ERR_STATE_INVALID; an ERR_PERMISSION
 * would send add's and update's tails to offer a sudo that changes nothing.
 */

#ifndef DOTTA_ERROR_H
#define DOTTA_ERROR_H

#include <stdarg.h>
#include <stdio.h>
#include <types.h>

/**
 * Error structure (opaque)
 *
 * Contains error code, message, and optional cause.
 */
struct error {
    error_code_t code;
    char *message;
    error_t *cause;  /* Wrapped error (can be NULL) */
};

/**
 * Create a new error with formatted message
 *
 * @param code Error code
 * @param fmt Format string (printf-style)
 * @param ... Format arguments
 * @return Newly allocated error (must be freed with error_free)
 */
error_t *error_create(error_code_t code, const char *fmt, ...);

/**
 * Wrap an existing error with additional context
 *
 * Ownership of cause is always consumed: on success, cause becomes the new error's
 * cause chain; on OOM, cause is returned directly (no leak).
 *
 * @param cause Original error (ownership transferred)
 * @param fmt Context message format
 * @param ... Format arguments
 * @return New error wrapping the original, or cause itself on OOM
 */
error_t *error_wrap(error_t *cause, const char *fmt, ...);

/**
 * Create error from libgit2 error
 *
 * @param git_error_code Git error code (from libgit2)
 * @return Newly allocated error
 */
error_t *error_from_git(int git_error_code);

/**
 * The error code an errno names
 *
 * One mapping, for every site that turns a kernel refusal into an error a caller
 * can act on: EACCES and EPERM are ERR_PERMISSION; ENOENT and ENOTDIR — nothing
 * can stand beneath a non-directory — are ERR_NOT_FOUND; anything else is ERR_FS.
 *
 * @param errno_val errno value
 * @return The code
 */
error_code_t error_code_from_errno(int errno_val);

/**
 * Create an error from a kernel refusal
 *
 * The one producer for every site that turns an errno into an error: the code
 * is error_code_from_errno's, the message the caller's prose, then ": " and
 * strerror's word — exactly what a site would spell by hand, so a reader can
 * act on the code (ERR_PERMISSION, ERR_NOT_FOUND) without matching prose. Read
 * errno into the argument before anything that could move it (a close, a free).
 * A site that codes its refusal by subsystem rather than by errno (a session
 * file's ERR_CRYPTO, the drop's ERR_PERMISSION, the store database's
 * ERR_STATE_INVALID) keeps its own spelling; every ERR_FS born from a refusal
 * reads through here.
 *
 * @param errno_val errno value
 * @param fmt Format string (printf-style) for the caller's part of the message
 * @param ... Format arguments
 * @return Newly allocated error
 */
error_t *error_from_errno(int errno_val, const char *fmt, ...);

/**
 * Free error and all chained causes
 *
 * @param err Error to free (can be NULL)
 */
void error_free(error_t *err);

/**
 * Get error message
 *
 * @param err Error
 * @return Error message (valid until error is freed)
 */
const char *error_message(const error_t *err);

/**
 * Get error code
 *
 * @param err Error
 * @return Error code
 */
error_code_t error_code(const error_t *err);

/**
 * Get the root cause — the deepest error in the chain
 *
 * The error that started it: the mechanism's own refusal, verbatim, beneath
 * whatever context the layers above wrapped around it. A consumer that already
 * names its subject (a receipt line built around the path) renders the root's
 * message, where the refusal speaks for itself; error_print renders the whole
 * chain instead.
 *
 * @param err Error
 * @return The deepest cause — err itself when nothing is wrapped (valid until
 *         the error is freed)
 */
const error_t *error_root(const error_t *err);

/**
 * Print error to stream
 *
 * Prints error message and all causes in chain.
 *
 * @param err Error
 * @param stream Output stream (e.g., stderr)
 */
void error_print(const error_t *err, FILE *stream);

/**
 * End the run: the report flushed, the terminal given back, one line, abort(3)
 *
 * The one way dotta ends a run of itself, for what no caller could answer, and
 * its two reporters each spell their own line: a contract broken (CHECK_ARG below)
 * and exhaustion (base/heap.h heap_die). The line is formatted on the stack and
 * written with write(2), so nothing on the way to the death allocates — exhaustion
 * may be why the run is dying — and a line past 1 KiB is cut. It lands after
 * what the run printed — stdout is flushed first, and main.c line-buffers it —
 * and on the terminal the user lent: the settings dotta armed are put back first,
 * and a hidden cursor shown (base/terminal.h terminal_restore_armed). abort(3)
 * raises SIGABRT, a terminating signal (sys/process.h PROCESS_TERMINATING_SIGNALS),
 * so a hook dies with the run, and the run's status is 134.
 *
 * @param fmt Format string (printf-style) for the line, without its newline
 * @param ... Format arguments
 */
_Noreturn void error_die(const char *fmt, ...)
__attribute__((format(printf, 1, 2)));

/**
 * Convenience macros
 */

/* Create error (error_create) */
#define ERROR(code, ...) \
    error_create(code, __VA_ARGS__)

/* Return if expression produces error */
#define RETURN_IF_ERROR(expr) do { \
    error_t *_err = (expr); \
    if (_err != NULL) return _err; \
} while(0)

/*
 * A condition the caller owed, checked where it is relied on: broken, it is a
 * bug, and the run dies at the check's site (error_die). What only a caller's
 * bug can falsify — a pointer it handed, a shape it built — is checked here.
 * What a user's word or data can falsify — a name typed, a file read, a
 * configuration — is a refusal, returned as an error the user can act on, and
 * never checked here: a contract a user can reach is a crash they can cause.
 */
#define CHECK_ARG(cond, msg) do { \
    if (!(cond)) error_die("BUG: %s:%d: %s", __FILE__, __LINE__, (msg)); \
} while (0)

/* A pointer the caller owed */
#define CHECK_NULL(ptr) \
    CHECK_ARG((ptr) != NULL, #ptr " cannot be NULL")

#endif /* DOTTA_ERROR_H */
