/**
 * passphrase.c — Secure passphrase acquisition implementation
 */

#include "crypto/passphrase.h"

#include <errno.h>
#include <hydrogen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"

/* Maximum passphrase length — a defensive cap against runaway stdin
 * redirects. Well beyond any human-typed passphrase; trips only on
 * pathological input. File-local because no caller needs to know the
 * number; they see a rejection error if they exceed it. */
#define MAX_PASSPHRASE_LENGTH 4096

/* Signal-handler state (terminal restoration)
 *
 * During the echo-disabled window we catch the four terminating
 * signals whose default action would leave the terminal with echo
 * off if they fired:
 *
 *   SIGINT  (ctrl-c)
 *   SIGTERM (kill)
 *   SIGHUP  (controlling terminal hangup)
 *   SIGQUIT (ctrl-\)
 *
 * The handler runs in an async-signal-safe context — only sig_atomic_t
 * loads/stores and the narrow POSIX-defined async-safe syscalls
 * (tcsetattr, signal, raise) are permitted. We park the saved
 * terminal attributes at file scope so the handler can read them
 * without a stack frame lookup; access is gated by a sig_atomic_t
 * flag that is set before the handler is installed and cleared
 * before it is uninstalled.
 *
 * Ordering invariants (violation leaves the terminal or signal
 * table in an inconsistent state):
 *
 *   Setup:     save termios → set flag = 1 → install handlers →
 *              disable echo
 *
 *     A signal between "set flag" and "install handlers"
 *     terminates by default — echo has not yet been disabled, so
 *     the terminal is already in a good state.
 *
 *     A signal between "install handlers" and "disable echo"
 *     enters the handler, restores to saved_term_for_handler
 *     (which is the current state — a no-op), re-raises with
 *     default disposition, terminates normally.
 *
 *   Teardown:  restore echo → clear flag → uninstall handlers
 *
 *     A signal between "clear flag" and "uninstall handlers"
 *     enters the handler, sees flag == 0, does not call tcsetattr
 *     (echo is already restored), re-raises with default
 *     disposition. Terminal and exit status both correct.
 *
 * Non-reentrant. A second caller in the same process would
 * overwrite saved_term_for_handler mid-window. Dotta is
 * single-threaded and never prompts twice concurrently, so this
 * is a latent invariant rather than an active constraint.
 * ====================================================================== */

static struct termios saved_term_for_handler;
static volatile sig_atomic_t saved_term_active = 0;

/* Signals we catch for terminal restoration. All four default to
 * terminate-the-process, which is exactly the scenario where
 * restoration matters. */
static const int HANDLED_SIGNALS[] = {
    SIGINT,
    SIGTERM,
    SIGHUP,
    SIGQUIT,
};
#define HANDLED_SIGNALS_COUNT \
    (sizeof(HANDLED_SIGNALS) / sizeof(HANDLED_SIGNALS[0]))

/* Per-signal prior dispositions captured at install time. Parallel
 * indexed with HANDLED_SIGNALS. `handler_installed[i] == true` iff
 * we actually installed our handler for HANDLED_SIGNALS[i] (false
 * means the parent had SIG_IGN set and we respected that). */
static struct sigaction saved_dispositions[HANDLED_SIGNALS_COUNT];
static bool handler_installed[HANDLED_SIGNALS_COUNT];

/**
 * Signal handler — restore the terminal and re-raise with default
 * disposition.
 *
 * Must use only async-signal-safe operations. tcsetattr, signal,
 * and raise are listed as async-signal-safe by POSIX.1-2008.
 *
 * The flag gate handles the brief window between teardown
 * "clear flag" and "uninstall handlers": a signal there enters the
 * handler, sees flag == 0, skips the (already-done) restoration,
 * and falls through to default-raise. Exit status and terminal
 * are both correct.
 */
static void passphrase_cleanup_on_signal(int sig) {
    if (saved_term_active) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_term_for_handler);
        saved_term_active = 0;
    }
    /* Reinstall default disposition and re-raise. Using raise()
     * preserves the standard "killed by signal N" exit status
     * (128 + N) so parent processes see the true termination
     * cause rather than a synthesized exit(0) or _exit(N). */
    signal(sig, SIG_DFL);
    raise(sig);
}

/**
 * Install the cleanup handler for each signal in HANDLED_SIGNALS.
 *
 * Skips any signal whose current disposition is SIG_IGN — the
 * parent deliberately chose to ignore it (backgrounded dotta,
 * shell pipeline discipline), and we must not start catching what
 * they asked to be ignored.
 *
 * Preconditions (caller enforces):
 *   - saved_term_for_handler has been populated with the current
 *     (pre-echo-disabled) terminal attributes.
 *   - saved_term_active has already been set to 1, so the
 *     handler's flag check sees an armed state even if the signal
 *     fires mid-install.
 *
 * Any partial install (some handlers up, some not) is safe because
 * passphrase_restore_signal_handlers walks handler_installed[] and
 * unwinds only what we actually installed.
 */
static void passphrase_install_signal_handlers(void) {
    struct sigaction sa = { 0 };
    sa.sa_handler = passphrase_cleanup_on_signal;
    sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: non-terminating signals (SIGWINCH, SIGCHLD)
     * interrupt fgets with EINTR, and the EINTR retry loop in
     * passphrase_prompt takes over. The four signals we catch
     * never return from fgets at all — they default-raise and
     * terminate inside the handler. */
    sa.sa_flags = 0;

    for (size_t i = 0; i < HANDLED_SIGNALS_COUNT; i++) {
        handler_installed[i] = false;
        memset(&saved_dispositions[i], 0, sizeof(saved_dispositions[i]));

        struct sigaction current;
        if (sigaction(HANDLED_SIGNALS[i], NULL, &current) != 0) {
            /* Query failed — leave this signal alone. Non-fatal:
             * worst case, a fatal signal of this kind during the
             * prompt leaves echo off, which is the pre-existing
             * behavior we are improving but not guaranteeing in
             * every edge case. */
            continue;
        }

        /* Respect parent-set SIG_IGN. The POSIX-correct check is
         * on sa_handler even for sa_sigaction-style handlers,
         * because SIG_IGN is a sa_handler value defined to be
         * mutually exclusive with sa_sigaction. */
        if (current.sa_handler == SIG_IGN) {
            continue;
        }

        if (sigaction(HANDLED_SIGNALS[i], &sa, &saved_dispositions[i]) == 0) {
            handler_installed[i] = true;
        }
    }
}

/**
 * Restore the signal dispositions captured by
 * passphrase_install_signal_handlers.
 *
 * Must be called AFTER saved_term_active has been cleared, so any
 * straggler signal between flag-clear and sigaction-restore is a
 * handler no-op followed by default-disposition re-raise (correct
 * terminal state, correct exit status).
 */
static void passphrase_restore_signal_handlers(void) {
    for (size_t i = 0; i < HANDLED_SIGNALS_COUNT; i++) {
        if (handler_installed[i]) {
            sigaction(HANDLED_SIGNALS[i], &saved_dispositions[i], NULL);
            handler_installed[i] = false;
        }
    }
}

/**
 * Read a passphrase from the user with terminal echo disabled.
 *
 *
 * @param prompt Prompt string written to stderr (must not be NULL).
 * @param out_passphrase Heap-allocated passphrase buffer
 * @param out_len Passphrase length, excluding the NUL terminator.
 * @return NULL on success.
 *         ERR_FS on tty manipulation or read I/O failure.
 *         ERR_MEMORY on allocation failure.
 *         ERR_INVALID_ARG on empty or truncated input.
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

    /* Arm the terminal-restoration machinery BEFORE disabling
     * echo. Order: save termios → set flag → install handlers →
     * disable echo. See the "Setup" ordering comment at the top of
     * this file for why. */
    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return ERROR(ERR_FS, "Failed to get terminal attributes");
        }

        memcpy(&saved_term_for_handler, &old_term, sizeof(old_term));
        saved_term_active = 1;
        passphrase_install_signal_handlers();

        new_term = old_term;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
            /* Echo was never disabled. Disarm in teardown order
             * (flag first, then handlers) so a racing signal
             * during sigaction-restore is a no-op + default-raise. */
            saved_term_active = 0;
            passphrase_restore_signal_handlers();
            return ERROR(ERR_FS, "Failed to disable echo");
        }

        echo_disabled = true;
    }

    /* Display the prompt. fflush ensures it is visible before
     * fgets blocks on stdin, even when stderr is line-buffered. */
    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    /* Fixed-size read buffer caps the damage if a pathological
     * stdin redirect streams megabytes into the prompt. */
    char *passphrase = malloc(MAX_PASSPHRASE_LENGTH + 1);
    if (!passphrase) {
        if (echo_disabled) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            saved_term_active = 0;
            passphrase_restore_signal_handlers();
        }
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
    }

    /* Best-effort mlock. Non-fatal on failure (the process may
     * lack RLIMIT_MEMLOCK headroom); the bytes still live in the
     * caller's memory and are wiped before free. */
    if (mlock(passphrase, MAX_PASSPHRASE_LENGTH + 1) != 0) {
        /* no-op */
    }

    /* EINTR retry: non-terminating signals interrupt fgets
     * because we deliberately did not set SA_RESTART. */
    char *result = NULL;
    do {
        errno = 0;
        result = fgets(passphrase, MAX_PASSPHRASE_LENGTH + 1, stdin);
    } while (result == NULL && errno == EINTR);

    /* Teardown order: restore echo → clear flag → uninstall
     * handlers. See "Teardown" comment at the top of this file. */
    if (echo_disabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\n");  /* the Enter keypress echo was suppressed */
        saved_term_active = 0;
        passphrase_restore_signal_handlers();
        echo_disabled = false;
    }

    /* Check read result */
    if (result == NULL) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_FS, "Failed to read passphrase");
    }

    /* Calculate length */
    size_t len = strlen(passphrase);

    /* Truncation check BEFORE trimming the newline. If fgets
     * filled the buffer without seeing a newline, the user's
     * input was cut mid-stream — reject rather than hand the
     * caller a prefix of the intended passphrase. */
    const bool has_newline = (len > 0 && passphrase[len - 1] == '\n');
    if (len == MAX_PASSPHRASE_LENGTH && !has_newline) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
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
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Return a right-sized copy so the caller's cleanup length
     * (len + 1) matches the actual allocation. Returning the
     * oversized read buffer directly would force the caller to
     * know — and pass — MAX_PASSPHRASE_LENGTH at cleanup time. */
    char *tight = malloc(len + 1);
    if (!tight) {
        buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
    }

    if (mlock(tight, len + 1) != 0) {
        /* Best-effort; non-fatal. */
    }

    memcpy(tight, passphrase, len + 1);

    /* Zero and free the oversized read buffer */
    buffer_secure_free(passphrase, MAX_PASSPHRASE_LENGTH + 1);

    *out_passphrase = tight;
    *out_len = len;

    return NULL;
}

/**
 * Get passphrase from environment variable
 *
 * Reads from DOTTA_ENCRYPTION_PASSPHRASE if set.
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

    /* Duplicate passphrase */
    const size_t len = strlen(env_passphrase);
    char *passphrase = malloc(len + 1);
    if (!passphrase) {
        return ERROR(ERR_MEMORY, "Failed to allocate passphrase buffer");
    }

    /* Lock memory to prevent swapping */
    if (mlock(passphrase, len + 1) != 0) {
        /* Best-effort; non-fatal. Process isolation still applies. */
    }

    memcpy(passphrase, env_passphrase, len + 1);

    *out_passphrase = passphrase;
    *out_len = len;

    return NULL;
}
