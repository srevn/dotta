/**
 * error.c - Error handling implementation
 */

#include "base/error.h"

#include <errno.h>
#include <git2/errors.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/heap.h"
#include "base/terminal.h"

/**
 * Create error with variable arguments (internal helper)
 */
static error_t *error_vcreate(
    error_code_t code,
    const char *fmt,
    va_list args
) {
    /* Size the message. The format is its writer's: one that cannot be formatted
     * is a caller's bug, never an error to report. */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    CHECK_ARG(len >= 0, "fmt cannot be formatted");

    /* The error and its message, from the heap that cannot fail. */
    error_t *err = heap_calloc(1, sizeof(error_t));
    err->code = code;
    err->message = heap_alloc((size_t) len + 1);
    vsnprintf(err->message, (size_t) len + 1, fmt, args);

    return err;
}

error_t *error_create(error_code_t code, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(code, fmt, args);
    va_end(args);
    return err;
}

error_t *error_wrap(error_t *cause, const char *fmt, ...) {
    if (!cause) {
        return NULL;
    }

    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(cause->code, fmt, args);
    va_end(args);

    err->cause = cause;
    return err;
}

error_t *error_from_git(int git_error_code) {
    const git_error *e = git_error_last();
    const char *msg = e ? e->message : "Unknown git error";

    return error_create(
        ERR_GIT, "Git error (%d): %s",
        git_error_code, msg
    );
}

error_code_t error_code_from_errno(int errno_val) {
    switch (errno_val) {
        case EACCES:
        case EPERM:
            return ERR_PERMISSION;
        case ENOENT:
        case ENOTDIR:
            return ERR_NOT_FOUND;
        default:
            return ERR_FS;
    }
}

error_t *error_from_errno(int errno_val, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    error_t *err = error_vcreate(error_code_from_errno(errno_val), fmt, args);
    va_end(args);

    /* The caller's prose, then ": " and strerror's word. */
    const char *why = strerror(errno_val);
    size_t len = strlen(err->message);
    err->message = heap_realloc(err->message, len + 2 + strlen(why) + 1);
    memcpy(err->message + len, ": ", 2);
    strcpy(err->message + len + 2, why);

    return err;
}

void error_free(error_t *err) {
    while (err) {
        error_t *cause = err->cause;
        free(err->message);
        free(err);
        err = cause;
    }
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

const error_t *error_root(const error_t *err) {
    if (!err) {
        return NULL;
    }
    while (err->cause) {
        err = err->cause;
    }
    return err;
}

void error_print(const error_t *err, FILE *stream) {
    if (!err) {
        return;
    }

    fprintf(
        stream, "Error: %s\n",
        err->message
    );

    /* Print cause chain */
    const error_t *cause = err->cause;
    while (cause) {
        fprintf(
            stream, "  Caused by: %s\n",
            cause->message
        );
        cause = cause->cause;
    }
}

_Noreturn void error_die(const char *fmt, ...) {
    /* What the run printed, first: the bytes stdout still holds. */
    fflush(stdout);

    /* The terminal the user lent, before the line: raw mode would draw it as a
     * staircase, and a cursor the editor hid would stay hidden past the run. */
    terminal_restore_armed();

    /* The line, formatted on the stack into all but the byte its newline takes:
     * a death allocates nothing, and a line past the buffer is cut. A format
     * that failed leaves the newline alone, which is still a death. */
    char line[1024];
    va_list args;
    va_start(args, fmt);
    int formatted = vsnprintf(line, sizeof(line) - 1, fmt, args);
    va_end(args);

    size_t len = formatted < 0 ? 0 : strlen(line);
    line[len++] = '\n';
    (void) write(STDERR_FILENO, line, len);

    abort();
}
