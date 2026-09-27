/**
 * passphrase.c - Secure passphrase acquisition implementation
 */

#include "sys/passphrase.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "base/error.h"
#include "base/secure.h"
#include "base/terminal.h"

/* Maximum passphrase length — a defensive cap against runaway stdin redirects.
 * Well beyond any human-typed passphrase; trips only on pathological input.
 * File-local because no caller needs to know the number; they see a rejection
 * error if they exceed it. */
#define MAX_PASSPHRASE_LENGTH 4096

/**
 * Read a passphrase from the user with terminal echo disabled.
 *
 * The contract is the header's. Setup order — save termios → arm them → disable
 * echo — and teardown order — restore echo → disarm — keep a terminating signal
 * in either window harmless: armed, it puts back settings that are already back.
 */
error_t *passphrase_prompt(
    const char *prompt,
    char **out_passphrase,
    size_t *out_len
) {
    CHECK_NULL(prompt);
    CHECK_NULL(out_passphrase);
    CHECK_NULL(out_len);

    const bool is_tty = isatty(STDIN_FILENO);
    struct termios old_term, new_term;
    bool echo_disabled = false;

    /* The settings armed BEFORE echo goes off: a terminating signal from here
     * puts them back (base/terminal.h terminal_arm, main.c's handler). */
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return ERROR(ERR_FS, "Failed to get terminal attributes");
        }

        terminal_arm(&old_term);

        new_term = old_term;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            terminal_disarm();   /* echo was never disabled */
            return ERROR(ERR_FS, "Failed to disable echo");
        }

        echo_disabled = true;
    }

    /* Display the prompt — at a terminal, where somebody reads it; a pipe has
     * its answer ready and its transcript is not the place for a question. fflush
     * ensures it is visible before fgets blocks on stdin, even when stderr is
     * line-buffered. */
    if (is_tty) {
        fprintf(stderr, "%s", prompt);
        fflush(stderr);
    }

    /* Fixed-size read buffer caps the damage if a pathological stdin redirect
     * streams megabytes into the prompt. A mapping of its own (base/secure.h):
     * locked best-effort, wiped and unmapped when it goes. */
    char *passphrase = secure_alloc(MAX_PASSPHRASE_LENGTH + 1);
    if (!passphrase) {
        if (echo_disabled) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            terminal_disarm();
        }
        return ERROR(ERR_MEMORY, "Failed to map passphrase buffer");
    }

    /* EINTR retry: a signal whose handler returns interrupts fgets, and the read
     * is asked again. None does today — the terminating signals end the process
     * in their handler, and the default-ignored ones (SIGWINCH, SIGCHLD) never
     * interrupt — so the loop is the read's own robustness. The stream's error
     * indicator is sticky, so each attempt starts it clean and the indicator
     * after the loop is the last attempt's. */
    char *result = NULL;
    do {
        clearerr(stdin);
        errno = 0;
        result = fgets(passphrase, MAX_PASSPHRASE_LENGTH + 1, stdin);
    } while (result == NULL && errno == EINTR);
    const bool read_failed = ferror(stdin);
    const int read_errno = errno;  /* before the teardown's own calls move it */

    /* Teardown order: restore echo → disarm. */
    if (echo_disabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\n");  /* the Enter keypress echo was suppressed */
        terminal_disarm();
    }

    /* Nothing read: end of input (a closed stdin, a pipe that ran out of lines)
     * or a failed read. The stream's indicators tell them apart — errno does
     * not: stdio's first use of a stream probes it with isatty, which leaves
     * ENOTTY behind on a clean end of input. */
    if (result == NULL) {
        secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return read_failed
            ? error_from_errno(read_errno, "Read failed")
            : ERROR(ERR_FS, "End of input");
    }

    /* Calculate length */
    size_t len = strlen(passphrase);

    /* Truncation check BEFORE trimming the newline. If fgets filled the buffer
     * without seeing a newline, the user's input was cut mid-stream — reject
     * rather than hand the caller a prefix of the intended passphrase. */
    const bool has_newline = (len > 0 && passphrase[len - 1] == '\n');
    if (len == MAX_PASSPHRASE_LENGTH && !has_newline) {
        secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(
            ERR_INVALID_ARG,
            "Passphrase too long (maximum %d characters)",
            MAX_PASSPHRASE_LENGTH - 1
        );
    }

    /* Trim trailing newline */
    if (has_newline) {
        passphrase[len - 1] = '\0';
        len--;
    }

    /* Check for empty passphrase */
    if (len == 0) {
        secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Return a right-sized copy so the caller's cleanup length (len + 1) matches
     * the actual allocation. Returning the oversized read buffer directly would
     * force the caller to know — and pass — MAX_PASSPHRASE_LENGTH at cleanup
     * time. */
    char *tight = secure_alloc(len + 1);
    if (!tight) {
        secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_MEMORY, "Failed to map passphrase buffer");
    }

    memcpy(tight, passphrase, len + 1);

    /* Wipe and unmap the oversized read buffer */
    secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);

    *out_passphrase = tight;
    *out_len = len;

    return NULL;
}

/**
 * Get passphrase from environment variable
 *
 * Reads from DOTTA_ENCRYPTION_PASSPHRASE if set.
 *
 * After copying the passphrase into its own mapping, the env var is unset via
 * `unsetenv`, so nothing this run execs afterwards inherits it — the header has
 * the rest: a run answered from a cache never reads it and so never unsets it,
 * and the children that run scripts never see it either way. The original `getenv`
 * string is libc-owned and cannot be wiped — `unsetenv` is the closest available
 * approximation to scrubbing it (the libc may relink the environ entry, but recent
 * glibc/macOS leave only a small residue and the visible env loses the variable).
 * The underlying "env-var passphrases are visible to ps(1)" trade-off is the
 * user's choice to accept.
 *
 * @param out_passphrase Passphrase (caller must free and zero)
 * @param out_len Passphrase length
 */
error_t *passphrase_from_env(
    char **out_passphrase,
    size_t *out_len
) {
    CHECK_NULL(out_passphrase);
    CHECK_NULL(out_len);

    const char *env_passphrase = getenv("DOTTA_ENCRYPTION_PASSPHRASE");
    if (!env_passphrase || env_passphrase[0] == '\0') {
        return ERROR(ERR_NOT_FOUND, "DOTTA_ENCRYPTION_PASSPHRASE not set");
    }

    /* Copy the passphrase into a mapping of its own (base/secure.h). */
    const size_t len = strlen(env_passphrase);
    char *passphrase = secure_alloc(len + 1);
    if (!passphrase) {
        return ERROR(ERR_MEMORY, "Failed to map passphrase buffer");
    }

    memcpy(passphrase, env_passphrase, len + 1);

    /* Drop the env-var so nothing this run execs afterwards inherits it. The
     * `getenv` pointer is invalidated by `unsetenv` per POSIX, so we MUST have
     * completed `memcpy` above before this call. Failure is non-fatal — the copy
     * in `passphrase` is what we hand back to the caller; the env-var residue
     * is a defense-in-depth concern (the user already accepted the env-var
     * trade-off). */
    (void) unsetenv("DOTTA_ENCRYPTION_PASSPHRASE");

    *out_passphrase = passphrase;
    *out_len = len;

    return NULL;
}
