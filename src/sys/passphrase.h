/**
 * passphrase.h — Secure passphrase acquisition
 *
 * Two orthogonal sources for user passphrases, each returning a right-sized
 * `secure_alloc` mapping (base/secure.h) that the caller releases with secure_free:
 *
 *   passphrase_prompt    — interactive TTY prompt with echo disabled,
 *                          or piped stdin read for scripts and tests.
 *   passphrase_from_env  — DOTTA_ENCRYPTION_PASSPHRASE fallback, for
 *                          automation contexts. This function only returns the
 *                          bytes.
 *
 * Cleanup contract:
 *
 *     secure_free(passphrase, passphrase_len + 1);
 *
 * The +1 covers the NUL terminator that is guaranteed to be present. The mapping
 * is the passphrase's own — locked against swap best-effort, wiped and unmapped
 * by secure_free — and is not the allocator's: callers MUST NOT free it.
 *
 * Terminal safety (passphrase_prompt only):
 *   During the echo-disabled window the function installs short-lived signal
 *   handlers for SIGINT, SIGTERM, SIGHUP, and SIGQUIT — the four terminating
 *   signals whose default action would leave the terminal with echo off if they
 *   fired while the prompt was active. The handler restores the saved terminal
 *   attributes and re-raises the signal with its default disposition, so the
 *   process terminates normally and the user's shell sees the standard 128+N
 *   exit status.
 *
 *   Signals that the parent process had set to SIG_IGN are honored (not hooked).
 *   This preserves the "inherit parent's discipline" convention for backgrounded
 *   dotta and shell pipelines.
 *
 * Non-reentrant: the terminal-restoration state lives at file scope, so a single
 * process must not call passphrase_prompt concurrently (from multiple threads
 * or recursively). Dotta is single-threaded.
 */

#ifndef DOTTA_PASSPHRASE_H
#define DOTTA_PASSPHRASE_H

#include <stddef.h>

#include <types.h>

/**
 * Read a passphrase from the user with terminal echo disabled.
 *
 * Modes:
 *   - TTY input: echo is disabled for the read window and restored on every return
 *     path, including signal-induced exits.
 *   - Non-TTY input: echo handling is skipped. Reading still works normally,
 *     which is what scripts and integration tests rely on.
 *
 * Input validation:
 *   - Empty input → ERR_INVALID_ARG.
 *   - Truncated input (length >= internal cap without a newline) → ERR_INVALID_ARG.
 *     A silent truncation would hand the caller a different passphrase than what
 *     the user intended to type.
 *
 * EINTR retry: fgets is retried on non-terminating signal interrupts (SIGWINCH
 * during terminal resize, SIGCHLD, etc.) so transient signals do not force the
 * user to re-enter. The terminating signals we install handlers for re-raise
 * with default disposition instead of returning.
 *
 * @param prompt          Prompt string written to stderr (must not be NULL).
 * @param out_passphrase  The passphrase's own mapping. Caller owns; release
 *                        with secure_free(p, *out_len + 1).
 * @param out_len         Passphrase length, excluding the NUL terminator.
 * @return NULL on success. ERR_FS on tty manipulation or read I/O failure.
 *         ERR_MEMORY when the mapping fails. ERR_INVALID_ARG on empty or truncated
 *         input.
 */
error_t *passphrase_prompt(
    const char *prompt,
    char **out_passphrase,
    size_t *out_len
);

/**
 * Read the passphrase from DOTTA_ENCRYPTION_PASSPHRASE.
 *
 * Intended for automation contexts where an interactive prompt is unacceptable.
 * The returned mapping is NUL-terminated. The variable is unset once read, so a
 * child of the run does not inherit it; the trade-off the variable makes (it is
 * visible to ps(1) until then) is the user's to accept, and this function prints
 * nothing about it.
 *
 * @param out_passphrase  The passphrase's own mapping. Caller owns; release
 *                        with secure_free(p, *out_len + 1).
 * @param out_len         Passphrase length, excluding the NUL terminator.
 * @return NULL on success. ERR_NOT_FOUND if the env var is unset or empty.
 *         ERR_MEMORY when the mapping fails.
 */
error_t *passphrase_from_env(
    char **out_passphrase,
    size_t *out_len
);

#endif /* DOTTA_PASSPHRASE_H */
