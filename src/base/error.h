/**
 * error.h - Error handling for dotta
 *
 * Centralized error handling with context tracking and propagation helpers.
 */

#ifndef DOTTA_ERROR_H
#define DOTTA_ERROR_H

#include <stdarg.h>
#include <stdio.h>
#include <types.h>

/**
 * Error structure (opaque)
 *
 * Contains error code, message, source location, and optional cause.
 */
struct error {
    error_code_t code;
    char *message;
    const char *file;
    int line;
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
 * Create error with source location
 *
 * @param code Error code
 * @param file Source file
 * @param line Line number
 * @param fmt Format string
 * @param ... Format arguments
 * @return Newly allocated error
 */
error_t *error_create_with_location(
    error_code_t code,
    const char *file,
    int line,
    const char *fmt,
    ...
);

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
 * file's ERR_CRYPTO, the drop's ERR_PERMISSION) keeps its own spelling; every
 * ERR_FS born from a refusal reads through here.
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
 * Convenience macros
 */

/* Create error with source location */
#define ERROR(code, ...) \
    error_create_with_location(code, __FILE__, __LINE__, __VA_ARGS__)

/* Return if expression produces error */
#define RETURN_IF_ERROR(expr) do { \
    error_t *_err = (expr); \
    if (_err != NULL) return _err; \
} while(0)

/* Check argument condition */
#define CHECK_ARG(cond, msg) do { \
    if (!(cond)) return ERROR(ERR_INVALID_ARG, msg); \
} while(0)

/* Check for NULL pointer */
#define CHECK_NULL(ptr) \
    CHECK_ARG((ptr) != NULL, #ptr " cannot be NULL")

#endif /* DOTTA_ERROR_H */
