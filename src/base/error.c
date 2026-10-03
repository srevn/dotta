/**
 * error.c - Error handling implementation
 */

#include "base/error.h"

#include <errno.h>
#include <git2/errors.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/terminal.h"

/* The node, this file's alone: a reader asks for its code, its message, its line,
 * its cause or its root, and never reads a field. Made whole and never edited:
 * a wrap holds its cause and edits nothing of it, its line made once from its
 * own message and the cause's line. A root carries the code; a wrap carries none,
 * error_code reading the root's. */
struct error {
    error_code_t code;    /* A root's; OK on a wrap */
    const char *message;  /* The fact's words, one line */
    const char *line;     /* The facts from here down, joined by ": "; the message at a root */
    error_t cause;        /* The fact beneath; NULL at the root */
};

/**
 * Every error the process makes, in one arena of this module's own (the header's
 * "Lifetime"): made at the first error, never reset and never freed. Not the
 * command's — errors are made before it and rendered after it (main.c run_spec)
 * — and not main's, which base cannot see: a fact of the process kept where it
 * is asked for, as sys/identity keeps its own.
 */
static arena_t *error_arena(void) {
    static arena_t *errors;
    if (!errors) errors = arena_create(0);

    return errors;
}

/**
 * The node, made whole in the arena from its value, its message already there
 *
 * A root's line is its message, the one string: only a wrap arrives with a line
 * of its own (error_wrap).
 */
static error_t error_node(struct error value) {
    struct error *node = arena_alloc(error_arena(), sizeof(*node));
    *node = value;
    if (!node->line) node->line = node->message;

    return node;
}

error_t error_create(error_code_t code, const char *fmt, ...) {
    /* The format is its writer's: one that cannot be formatted is a caller's
     * bug, and dies in the arena's formatter, never an error to report. */
    va_list args;
    va_start(args, fmt);
    const char *message = arena_str_vformat(error_arena(), fmt, args);
    va_end(args);

    return error_node((struct error){ .code = code, .message = message });
}

error_t error_wrap(error_t cause, const char *fmt, ...) {
    if (!cause) return NULL;

    va_list args;
    va_start(args, fmt);
    const char *message = arena_str_vformat(error_arena(), fmt, args);
    va_end(args);

    /* The line the facts make from here down, made once with the node: every
     * reader that carries the failure in a line of its own borrows it */
    const char *line = arena_str_format(error_arena(), "%s: %s", message, cause->line);

    /* No code: the root beneath carries it (error_code) */
    return error_node((struct error){ .message = message, .line = line, .cause = cause });
}

error_t error_git(int git_error_code, const char *fmt, ...) {
    CHECK_NULL(fmt);

    /* libgit2's sentence for the call that failed — or, where it set none, the
     * static "no error", the one error of class GIT_ERROR_NONE (util/errors.c
     * git_error_last), which a search libgit2 ended with the error cleared answers
     * (revparse.c walk_and_search). There, and only there, the code is the one
     * fact there is: a code says nothing a user reads, an EACCES on a ref file
     * being -14, GIT_ELOCKED. A sentence an earlier call left standing reads as
     * the failing call's — libgit2 words a callback's return only where none
     * stands (util/errors.h git_error_set_after_callback_function) — so a callback
     * words its own refusal (sys/transfer.c transfer_credentials_callback). */
    const git_error *last = git_error_last();
    char code[32];
    snprintf(code, sizeof(code), "Git error %d", git_error_code);
    const char *why = last->klass == GIT_ERROR_NONE ? code : last->message;

    /* The caller's prose, then ": " and that word: one message, sized before
     * the arena is asked, so it is one allocation as every other's is. */
    va_list args;
    va_start(args, fmt);
    va_list sized;
    va_copy(sized, args);
    int len = vsnprintf(NULL, 0, fmt, sized);
    va_end(sized);
    CHECK_ARG(len >= 0, "fmt cannot be formatted");

    const size_t prose = (size_t) len;
    const size_t total = prose + 2 + strlen(why);
    char *message = arena_alloc(error_arena(), total + 1);
    vsnprintf(message, prose + 1, fmt, args);
    va_end(args);
    snprintf(message + prose, total - prose + 1, ": %s", why);

    return error_node((struct error){ .code = ERR_GIT, .message = message });
}

error_code_t error_errno_code(int errno_val) {
    switch (errno_val) {
        /* The bits, an ACL among them, refused the identity the call ran as:
         * the one refusal another identity may not meet (sys/filesystem.h
         * fs_denied). EPERM is a flag's, a policy's or an owner rule's, which
         * nothing here can tell apart, and root meets the first two as flatly:
         * it falls to the default. */
        case EACCES:
            return ERR_PERMISSION;
        case ENOENT:
        case ENOTDIR:
            return ERR_NOT_FOUND;
        default:
            return ERR_FS;
    }
}

error_t error_errno(int errno_val, const char *fmt, ...) {
    CHECK_NULL(fmt);

    /* The caller's prose, then ": " and strerror's word: one message, sized before
     * the arena is asked, so it is one allocation as every other's is. */
    const char *why = strerror(errno_val);

    va_list args;
    va_start(args, fmt);
    va_list sized;
    va_copy(sized, args);
    int len = vsnprintf(NULL, 0, fmt, sized);
    va_end(sized);
    CHECK_ARG(len >= 0, "fmt cannot be formatted");

    const size_t prose = (size_t) len;
    const size_t total = prose + 2 + strlen(why);
    char *message = arena_alloc(error_arena(), total + 1);
    vsnprintf(message, prose + 1, fmt, args);
    va_end(args);
    snprintf(message + prose, total - prose + 1, ": %s", why);

    return error_node(
        (struct error){ .code = error_errno_code(errno_val), .message = message }
    );
}

const char *error_message(error_t err) {
    return err ? err->message : NULL;
}

const char *error_line(error_t err) {
    return err ? err->line : NULL;
}

error_code_t error_code(error_t err) {
    err = error_root(err);
    return err ? err->code : OK;
}

error_t error_cause(error_t err) {
    return err ? err->cause : NULL;
}

error_t error_root(error_t err) {
    if (!err) return NULL;
    while (err->cause) {
        err = err->cause;
    }
    return err;
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
