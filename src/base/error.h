/**
 * error.h - Error handling for dotta
 *
 * Centralized error handling with context tracking and propagation helpers.
 */

#ifndef DOTTA_ERROR_H
#define DOTTA_ERROR_H

#include <stdarg.h>
#include <stdio.h>

#include "dotta/types.h"

/**
 * Error structure (opaque)
 *
 * Contains error code, message, source location, and optional cause.
 */
struct dotta_error {
    dotta_error_code_t code;
    char *message;
    const char *file;
    int line;
    dotta_error_t *cause;  /* Wrapped error (can be NULL) */
};

/**
 * Create a new error with formatted message
 *
 * @param code Error code
 * @param fmt Format string (printf-style)
 * @param ... Format arguments
 * @return Newly allocated error (must be freed with error_free)
 */
dotta_error_t *error_create(dotta_error_code_t code, const char *fmt, ...);

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
dotta_error_t *error_create_with_location(
    dotta_error_code_t code,
    const char *file,
    int line,
    const char *fmt,
    ...
);

/**
 * Wrap an existing error with additional context
 *
 * @param cause Original error (ownership transferred)
 * @param fmt Context message format
 * @param ... Format arguments
 * @return New error wrapping the original
 */
dotta_error_t *error_wrap(dotta_error_t *cause, const char *fmt, ...);

/**
 * Create error from libgit2 error
 *
 * @param git_error_code Git error code (from libgit2)
 * @return Newly allocated error
 */
dotta_error_t *error_from_git(int git_error_code);

/**
 * Create error from errno
 *
 * @param errno_val errno value
 * @return Newly allocated error
 */
dotta_error_t *error_from_errno(int errno_val);

/**
 * Free error and all chained causes
 *
 * @param err Error to free (can be NULL)
 */
void error_free(dotta_error_t *err);

/**
 * Get error message
 *
 * @param err Error
 * @return Error message (valid until error is freed)
 */
const char *error_message(const dotta_error_t *err);

/**
 * Get error code
 *
 * @param err Error
 * @return Error code
 */
dotta_error_code_t error_code(const dotta_error_t *err);

/**
 * Print error to stream
 *
 * Prints error message and all causes in chain.
 *
 * @param err Error
 * @param stream Output stream (e.g., stderr)
 */
void error_print(const dotta_error_t *err, FILE *stream);

/**
 * Print error with full context (includes source location)
 *
 * @param err Error
 * @param stream Output stream
 */
void error_print_full(const dotta_error_t *err, FILE *stream);

/**
 * Convenience macros
 */

/* Create error with source location */
#define ERROR(code, ...) \
    error_create_with_location(code, __FILE__, __LINE__, __VA_ARGS__)

/* Return if expression produces error */
#define RETURN_IF_ERROR(expr) do { \
    dotta_error_t *_err = (expr); \
    if (_err != NULL) return _err; \
} while(0)

/* Check argument condition */
#define CHECK_ARG(cond, msg) do { \
    if (!(cond)) return ERROR(DOTTA_ERR_INVALID_ARG, msg); \
} while(0)

/* Check argument and provide formatted message */
#define CHECK_ARG_FMT(cond, fmt, ...) do { \
    if (!(cond)) return ERROR(DOTTA_ERR_INVALID_ARG, fmt, __VA_ARGS__); \
} while(0)

/* Check for NULL pointer */
#define CHECK_NULL(ptr) \
    CHECK_ARG((ptr) != NULL, #ptr " cannot be NULL")

#endif /* DOTTA_ERROR_H */
