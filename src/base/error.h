/**
 * error.h - Error handling for dotta
 *
 * Centralized error handling with context tracking.
 *
 * Lifetime
 * --------
 * An error is a fact of the process: made whole, never edited, never freed, and
 * borrowed by every reader until the process ends. Its reader is not known where
 * it is made — rendered at once, kept in a receipt's row, rendered by main after
 * the command's arena is gone, or made before that arena exists (identity_init,
 * gitops_init, config_load) — and the process is the one scope that encloses
 * them all. So every error lives in one arena of this module's own, made at the
 * first error; a wrap holds its cause, two of them over one cause share it, and
 * no reader can reach back into one.
 *
 * The handle is const, so nothing a reader holds can edit one, and must-check
 * (include/types.h): an error dropped on purpose is `(void) f()`, and one dropped
 * by accident does not compile.
 *
 * What that costs is the pressure the shape is for: an error is minted on a failure
 * path only, and a loop that goes on is where the cost shows, since every error
 * it makes stays for the run. Two kinds meet such a loop. An answer spelled as
 * an error is data instead (a key opens a ciphertext or it does not,
 * crypto/cipher.h cipher_opens; a claim's names resolve or say which did not,
 * core/metadata.h metadata_ownership). A genuine failure the loop goes on past
 * is minted once per cause and answered again — an immutable error is safe to
 * hand every reader — so what the run keeps is counted by the causes, never by
 * the loop (sys/source.h: a repository whose configuration does not parse is
 * one error for every entry beneath it; the keymgr's standing refusal, one for
 * every row after it). A loop that still mints per row says its bound where it
 * does.
 *
 * Propagation
 * -----------
 * A failure passed on returns where it is met, in plain sight. The first step
 * declares `err` and each later one assigns it — one taken under a condition
 * answering NULL where it is not — and the last returns the call:
 *
 *     error_t err = f(…);
 *     if (err) return err;
 *     err = c ? g(…) : NULL;
 *     if (err) return err;
 *     return h(…);
 *
 * A run of steps whose every outcome meets one tail — a release, a wrap they
 * share — chains, and reads `err` once after the run; an optional lookup asks
 * its answer beside the failure:
 *
 *     if (!err) err = h(…);
 *     if (err || !x) return err;
 *
 * A failure in hand is `err`, and an int a call answers is `rc`: a second failure
 * held in one body is a second job.
 *
 * Messages
 * --------
 * A message is one line, and a fact: what could not be done, or what is so, about
 * what — and why, where the cause beneath does not already say it. The renderer
 * owns every break (base/output.h output_error), and a datum goes into a message
 * as the bytes it is, never escaped by its writer. A way out is a clause of the
 * fact, after ';', and only where the fact does not imply it: the flag, key or
 * spelling the user could not guess, and what it does (base/gitignore.c
 * validate_pattern's escape), true for every caller of the site — a template
 * the user must fill in is none. A wrap says where its cause stands — a file, a
 * key, a profile or a role the cause cannot name — or it is not written. A re-mint
 * — a new error spelled from another's error_message — keeps one fact's words,
 * never its causes. A message opening on a word opens capitalised; none closes
 * with a period; a datum is quoted '%s'.
 *
 * ERR_PERMISSION
 * --------------
 * The one code a consumer acts on rather than prints, so its meaning is fixed
 * here and not per producer: a refusal an identity met. The kernel's — EACCES,
 * through error_from_errno below: the bits refused the identity the call ran
 * as, where an EPERM may be a flag's or a policy's that root meets as flatly
 * (ERR_FS) — and libgit2's owner check on the repository, which spells its own
 * because GIT_EOWNER carries no errno. An answer dotta looked up is never one,
 * whatever the answer is about: a hook's mode, a claim's ids, a policy's verdict.
 * Every reader turns the code straight into a remedy only a refusal has —
 * core/workspace classes the failed look UNREADABLE and its readers offer root,
 * utils/repo offers to reclaim the repository — and none of them can see which
 * producer it came from, which is what makes the class load-bearing rather than
 * descriptive. The code is the one the kernel's refusal was made with (error_code),
 * whatever wraps stand above it.
 *
 * sys/identity's drop is outside the rule and out of reach of it: its two refusals
 * say the run cannot *become* an identity, they are coded by subsystem because
 * a setuid-family EAGAIN is not ERR_FS, and identity_init returns to main() before
 * there is a command to read them.
 *
 * A refusal met where no second try spans the call is outside it too, and is
 * coded by its subsystem: no identity a run can take reads through it. core/state's
 * — SQLite opens the store's database as the invoker on every run (sys/filesystem)
 * — are ERR_STATE_INVALID, a broken installation to report; sys/source's reads
 * of a source repository — its layout raw, its configuration through libgit2,
 * both as the invoker under every identity (sys/source.h) — are ERR_GIT, the
 * repository's failure, as git's own is.
 */

#ifndef DOTTA_ERROR_H
#define DOTTA_ERROR_H

#include <stdarg.h>
#include <types.h>

/**
 * Create a new error with formatted message
 *
 * An error is this module's arena's ("Lifetime" above), so it is made or the
 * run dies of exhaustion (base/arena.h): no answer here is NULL. The format is
 * its writer's, checked by the compiler at every site, and one that still cannot
 * be formatted is a caller's bug.
 *
 * @param code Error code
 * @param fmt Format string (printf-style)
 * @param ... Format arguments
 * @return The error, the process's
 */
error_t error_create(error_code_t code, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Wrap an existing error with additional context
 *
 * The new node holds its cause; two wraps of one cause share it, and neither
 * edits it. Its code is its root's (error_code).
 *
 * @param cause Original error (NULL wraps nothing)
 * @param fmt Context message format
 * @param ... Format arguments
 * @return New error wrapping the original, or NULL for a NULL cause
 */
error_t error_wrap(error_t cause, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Create error from libgit2 error
 *
 * @param git_error_code Git error code (from libgit2)
 * @return The error, the process's
 */
error_t error_from_git(int git_error_code);

/**
 * The error code an errno names
 *
 * One mapping, for every site that turns a kernel refusal into an error a caller
 * can act on: EACCES is ERR_PERMISSION; ENOENT and ENOTDIR — nothing can stand
 * beneath a non-directory — are ERR_NOT_FOUND; anything else is ERR_FS, EPERM
 * among it, a flag's or a policy's as often as an owner rule's.
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
 * ERR_STATE_INVALID, a source repository's ERR_GIT) keeps its own spelling; every
 * ERR_FS born from a refusal reads through here.
 *
 * @param errno_val errno value
 * @param fmt Format string (printf-style) for the caller's part of the message
 * @param ... Format arguments
 * @return The error, the process's
 */
error_t error_from_errno(int errno_val, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Get error message
 *
 * The outermost fact's.
 *
 * @param err Error
 * @return Error message, or NULL for NULL
 */
const char *error_message(error_t err);

/**
 * The facts of a failure as one line
 *
 * Each message, the outermost first, joined by ": " — for a line that carries a
 * failure inside it (a warning, a failed row), where base/output.h output_error's
 * block would break the line. A root's line is its message; a wrap's is its
 * message, ": " and its cause's line, made with the node. Borrowed by every reader,
 * as the message is ("Lifetime" above).
 *
 * @param err The failure
 * @return The line, the process's; NULL for NULL
 */
const char *error_line(error_t err);

/**
 * Get error code
 *
 * The root's (error_root), whatever wraps stand above it, so a reader that acts
 * on the code acts on the mechanism's refusal.
 *
 * @param err Error
 * @return Error code, or OK for NULL
 */
error_code_t error_code(error_t err);

/**
 * Get the cause — the fact this one wraps
 *
 * One link down the chain, for a reader that walks it: error_root is the walk
 * taken to its end, base/output.h output_error the walk rendered.
 *
 * @param err Error
 * @return The wrapped fact, or NULL at the root and for NULL
 */
error_t error_cause(error_t err);

/**
 * Get the root cause — the deepest error in the chain
 *
 * The error that started it: the mechanism's own refusal, verbatim, beneath
 * whatever context the layers above wrapped around it. A consumer that already
 * names its subject (a receipt line built around the path) renders the root's
 * message, where the refusal speaks for itself; base/output.h output_error renders
 * the whole chain as a block instead, and error_line as one line.
 *
 * @param err Error
 * @return The deepest cause — err itself when nothing is wrapped
 */
error_t error_root(error_t err);

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

/*
 * A condition the caller owed, checked where it is relied on: broken, it is a
 * bug, and the run dies at the check's site (error_die). What only a caller's
 * bug can falsify — a pointer it handed, a shape it built — is checked here.
 * What a user's word or data can falsify — a name typed, a file read, a
 * configuration — is a refusal, returned as an error the user can act on, and
 * never checked here: a contract a user can reach is a crash they can cause.
 *
 * The tail past a switch that names every value of its enum is the same kind of
 * condition: -Wswitch fails the build the day a value is added, so what reaches
 * the tail is a value no enumerator names, which only a caller's cast can make.
 * It dies, CHECK_ARG(false, "…"), unless the function has an answer that makes
 * its caller do nothing — a predicate's false over an action it would skip, a
 * NULL for no text — which it may give instead. Never a default arm, which hides
 * the next value from -Wswitch, and never a made-up answer — a name, a decision,
 * a success — which the caller would act on.
 */
#define CHECK_ARG(cond, msg) do { \
    if (!(cond)) error_die("BUG: %s:%d: %s", __FILE__, __LINE__, (msg)); \
} while (0)

/* A pointer the caller owed */
#define CHECK_NULL(ptr) \
    CHECK_ARG((ptr) != NULL, #ptr " cannot be NULL")

#endif /* DOTTA_ERROR_H */
