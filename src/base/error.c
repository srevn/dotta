/**
 * error.c - Error handling implementation
 */

#include "error.h"

#include <errno.h>
#include <git2/errors.h>
#include <stdlib.h>
#include <string.h>

/**
 * Create error with variable arguments (internal helper)
 */
static error_t *error_vcreate(
    error_code_t code,
    const char *file,
    int line,
    const char *fmt,
    va_list args
) {
    error_t *err = calloc(1, sizeof(error_t));
    if (!err) {
        return NULL;  /* Out of memory - can't allocate error */
    }

    err->code = code;
    err->file = file;
    err->line = line;
    err->cause = NULL;

    /* Format message */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (len < 0) {
        free(err);
        return NULL;
    }

    err->message = malloc(len + 1);
    if (!err->message) {
        free(err);
        return NULL;
    }

    vsnprintf(err->message, len + 1, fmt, args);

    return err;
}

error_t *error_create(error_code_t code, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(code, NULL, 0, fmt, args);
    va_end(args);
    return err;
}

error_t *error_create_with_location(
    error_code_t code,
    const char *file,
    int line,
    const char *fmt,
    ...
) {
    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(code, file, line, fmt, args);
    va_end(args);
    return err;
}

error_t *error_wrap(error_t *cause, const char *fmt, ...) {
    if (!cause) {
        return NULL;
    }

    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(
        cause->code,
        cause->file,
        cause->line,
        fmt,
        args
    );
    va_end(args);

    if (err) {
        err->cause = cause;
    }

    return err;
}

error_t *error_from_git(int git_error_code) {
    const git_error *e = git_error_last();
    const char *msg = e ? e->message : "Unknown git error";

    return error_create(
        ERR_GIT,
        "Git error (%d): %s",
        git_error_code,
        msg
    );
}

error_t *error_from_errno(int errno_val) {
    return error_create(
        ERR_FS,
        "System error: %s",
        strerror(errno_val)
    );
}

void error_free(error_t *err) {
    if (!err) {
        return;
    }

    /* Free cause chain */
    if (err->cause) {
        error_free(err->cause);
    }

    free(err->message);
    free(err);
}

const char *error_message(const error_t *err) {
    if (!err) {
        return NULL;
    }
    return err->message;
}

error_code_t error_code(const error_t *err) {
    if (!err) {
        return OK;
    }
    return err->code;
}

void error_print(const error_t *err, FILE *stream) {
    if (!err) {
        return;
    }

    fprintf(stream, "Error: %s\n", err->message);

    /* Print cause chain */
    const error_t *cause = err->cause;
    while (cause) {
        fprintf(stream, "  Caused by: %s\n", cause->message);
        cause = cause->cause;
    }
}

void error_print_full(const error_t *err, FILE *stream) {
    if (!err) {
        return;
    }

    fprintf(stream, "Error: %s\n", err->message);

    if (err->file) {
        fprintf(stream, "  at %s:%d\n", err->file, err->line);
    }

    /* Print cause chain with locations */
    const error_t *cause = err->cause;
    while (cause) {
        fprintf(stream, "  Caused by: %s\n", cause->message);
        if (cause->file) {
            fprintf(stream, "    at %s:%d\n", cause->file, cause->line);
        }
        cause = cause->cause;
    }
}
