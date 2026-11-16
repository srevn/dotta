/**
 * terminal.h - Terminal control utilities
 *
 * Provides low-level terminal control for building inline TUIs. Handles raw mode,
 * ANSI escape sequences, and input reading.
 *
 * Design principles:
 * - Clean abstraction over termios and ANSI codes
 * - Proper cleanup on errors (RAII pattern)
 * - No assumptions about UI structure
 * - Compatible with POSIX terminals
 */

#ifndef DOTTA_TERMINAL_H
#define DOTTA_TERMINAL_H

#include <stdbool.h>
#include <stddef.h>
#include <termios.h>
#include <types.h>

/**
 * ANSI escape codes
 */
#define ANSI_CURSOR_HIDE "\033[?25l"
#define ANSI_CURSOR_SHOW "\033[?25h"
#define ANSI_CURSOR_POSITION "\033[%d;%dH"
#define ANSI_CURSOR_UP "\033[%dA"
#define ANSI_CURSOR_DOWN "\033[%dB"
#define ANSI_CURSOR_TO_START "\033[1G"
#define ANSI_CURSOR_SAVE "\033[s"
#define ANSI_CURSOR_RESTORE "\033[u"
#define ANSI_CLEAR_SCREEN "\033[2J"
#define ANSI_CLEAR_TO_END "\033[0J"
#define ANSI_CLEAR_LINE "\033[2K"
#define ANSI_CLEAR_LINE_TO_END "\033[0K"

/**
 * Terminal state (opaque)
 *
 * Stores original terminal settings for restoration on cleanup.
 */
typedef struct terminal terminal_t;

/**
 * Terminal dimensions
 */
typedef struct {
    int rows;
    int cols;
} terminal_size_t;

/**
 * Special key codes
 *
 * Regular ASCII characters (a-z, 0-9, etc.) are returned as-is. These codes
 * represent special keys that need multi-byte sequences.
 *
 * The sign says whether there is a key at all: zero and up is one, negative is
 * none. A key the reader cannot name is still a key — the user pressed something
 * — and belongs in the 1000+ band with the rest; the two negatives are what a
 * read that gave nothing leaves behind, and neither clears, so a loop over
 * terminal_read_key ends on one instead of asking again forever.
 *
 * Every enumerator carries an explicit value so the split stays audit-friendly:
 * inserting a new synthetic key cannot silently shift neighbours into another
 * enumerator's slot, and the ASCII band cannot accidentally collide with the
 * 1000+ band.
 */
typedef enum {
    TERM_KEY_EOF       = -1,     /* No key: the input stream ended */
    TERM_KEY_ERROR     = -2,     /* No key: the read failed */
    TERM_KEY_UP        = 1000,
    TERM_KEY_DOWN      = 1001,
    TERM_KEY_LEFT      = 1002,
    TERM_KEY_RIGHT     = 1003,
    TERM_KEY_HOME      = 1004,
    TERM_KEY_END       = 1005,
    TERM_KEY_PAGE_UP   = 1006,
    TERM_KEY_PAGE_DOWN = 1007,
    TERM_KEY_DELETE    = 1008,
    TERM_KEY_UNKNOWN   = 1009,   /* A key press whose sequence has no name */
    TERM_KEY_BACKSPACE = 127,
    TERM_KEY_ENTER     = '\r',
    TERM_KEY_ESCAPE    = 27,
    TERM_KEY_TAB       = '\t',
    TERM_KEY_SPACE     = ' ',
    TERM_KEY_CTRL_C    = 3,
    TERM_KEY_CTRL_D    = 4
} term_key_t;

/**
 * Initialize terminal for raw mode
 *
 * Saves current terminal state and enables raw mode:
 * - Disable line buffering
 * - Disable echo
 * - Disable signals (Ctrl+C, Ctrl+Z)
 * - Read input byte-by-byte
 *
 * The saved settings are armed with stdin before raw mode goes on (terminal_arm),
 * so a terminating signal puts them back.
 *
 * Always call terminal_restore() when done, even on errors.
 *
 * @param out Terminal state, released by terminal_restore (must not be NULL)
 * @return Error or NULL on success
 */
error_t terminal_init(terminal_t **out);

/**
 * Restore terminal to original state
 *
 * Restores settings saved by terminal_init(), and disarms them once they are
 * back, then releases the state: once per terminal_init, and a NULL state is a
 * no-op.
 *
 * @param term Terminal state (can be NULL)
 */
void terminal_restore(terminal_t *term);

/**
 * Arm the settings a terminating signal puts back
 *
 * Whoever changes a terminal's settings arms the ones to restore, before the
 * change, with the descriptor the change is made through — the editor's raw mode
 * (terminal_init) and a hidden echo's (terminal_echo_off) — and disarms once
 * they are back. They go back through that descriptor, which stays open until
 * the disarm: the terminal changed is the one it names, whatever stdin is. One
 * slot: dotta changes one terminal at a time, and an arm while one is armed is
 * a caller's bug (CHECK_ARG). Read by main.c's handler, terminating_signal, and
 * by the death, base/error.c error_die, through terminal_restore_armed.
 *
 * @param fd The terminal's descriptor, open until the disarm
 * @param settings The settings to put back (must not be NULL; copied)
 */
void terminal_arm(int fd, const struct termios *settings);

/**
 * Disarm the settings terminal_arm armed: they are back, and a terminating signal
 * has nothing to restore
 */
void terminal_disarm(void);

/**
 * Put back what dotta changed of the terminal: the armed settings, and the cursor
 * terminal_cursor_hide hid — on a line of its own, past the UI that hid it, as
 * that UI's own exit leaves it
 *
 * For a signal handler and for the death (main.c terminating_signal, base/error.c
 * error_die): tcsetattr(3) and write(2) alone, both async-signal-safe, and every
 * flag it reads a volatile sig_atomic_t. Disarms, and forgets the cursor, so a
 * second call is a no-op.
 */
void terminal_restore_armed(void);

/**
 * Hide what is typed at a terminal: its settings read into *saved and armed
 * (terminal_arm), then its echo turned off
 *
 * Armed before the echo goes off, so a terminating signal inside the window puts
 * the settings back through `fd`. The change is git's (lib/git/compat/terminal.c
 * disable_bits), made once the terminal's output has drained and with its unread
 * input dropped (TCSAFLUSH): what was typed before the question, echoed while
 * the echo was still on, is never read as its answer.
 *
 * Readers: sys/passphrase.c passphrase_prompt; terminal_ask, where the answer
 * is unseen.
 *
 * @param fd The terminal's descriptor, open until terminal_echo_on
 * @param saved The settings as they stood, for terminal_echo_on (must not be NULL)
 * @return Error or NULL on success; refused, nothing is armed and nothing changed
 */
error_t terminal_echo_off(int fd, struct termios *saved);

/**
 * Show what is typed again: the settings terminal_echo_off saved put back, then
 * disarmed
 *
 * Put back as git puts them back (lib/git/compat/terminal.c restore_term), with
 * the terminal's unread input dropped (TCSAFLUSH): what was typed past the answer
 * read is never read as the next.
 *
 * @param fd The descriptor terminal_echo_off was handed
 * @param saved The settings it saved (must not be NULL)
 */
void terminal_echo_on(int fd, const struct termios *saved);

/**
 * Ask a question on the controlling terminal, as git asks one
 * (lib/git/compat/terminal.c git_terminal_prompt)
 *
 * The terminal is /dev/tty, opened for the question and closed after it, whatever
 * the process's own streams are: a run whose stdin and stdout are led away still
 * asks the person, and one with no terminal has nobody to ask. The question is
 * written as it stands, and the answer is the line typed after it, to its newline
 * — an empty line is an answer — or to the terminal's end of input where a line
 * was begun. With `echo` false the answer is unseen: the echo off before the
 * question is written (terminal_echo_off), and once the answer is read, the newline
 * the terminal did not echo, then the settings back.
 *
 * What is typed may be a secret: it is read off the descriptor, never through a
 * stdio buffer, into memory wiped before the call returns, and handed over as a
 * heap string its caller ends with secure_free_string (base/secure.h). No terminal
 * hands a longer line whole than the one read here — a canonical line ends at
 * 1,024 bytes on macOS and at 4,096 on Linux — so a longer answer cannot be typed,
 * at git's own question either; one a terminal with no line discipline hands
 * past that is refused, never taken in part.
 *
 * Refused: no terminal, and a read that failed, each in its errno's words alone,
 * as git says them (lib/git/prompt.c git_prompt) — the caller says what was asked;
 * the terminal's settings (terminal_echo_off); a question the terminal would
 * not take; the terminal's end of input before any byte, "End of input"; an answer
 * past the bound.
 *
 * @param question The question, written as it stands (must not be NULL)
 * @param echo Whether the answer shows as it is typed
 * @param out The answer, the heap's (must not be NULL); NULL on a refusal
 * @return Error or NULL on success
 */
error_t terminal_ask(const char *question, bool echo, char **out);

/**
 * Get terminal size
 *
 * Queries current terminal dimensions via ioctl, of stdout's terminal, where a
 * screen is drawn — never stdin's, where its keys are read (terminal_is_tty,
 * terminal_init): a screen led away from the terminal has no size, and is refused
 * here, ENOTTY, whatever stdin is.
 *
 * @param out Size (must not be NULL)
 * @return Error or NULL on success
 */
error_t terminal_get_size(terminal_size_t *out);

/**
 * Check if stdin is a TTY
 *
 * @return true if stdin is connected to a terminal
 */
bool terminal_is_tty(void);

/**
 * Hide cursor
 *
 * Until terminal_cursor_show, a terminating signal shows it again
 * (terminal_restore_armed).
 */
void terminal_cursor_hide(void);

/**
 * Show cursor
 */
void terminal_cursor_show(void);

/**
 * Move cursor to position (1-indexed)
 *
 * @param row Row (1 = top)
 * @param col Column (1 = left)
 */
void terminal_cursor_move(int row, int col);

/**
 * Move cursor up N lines
 *
 * @param n Number of lines
 */
void terminal_cursor_up(int n);

/**
 * Move cursor down N lines
 *
 * @param n Number of lines
 */
void terminal_cursor_down(int n);

/**
 * Move cursor to column 1 (start of line)
 */
void terminal_cursor_to_start(void);

/**
 * Save cursor position
 */
void terminal_cursor_save(void);

/**
 * Restore cursor position
 */
void terminal_cursor_restore(void);

/**
 * Clear entire screen
 */
void terminal_clear_screen(void);

/**
 * Clear from cursor to end of screen
 */
void terminal_clear_to_end(void);

/**
 * Clear current line
 */
void terminal_clear_line(void);

/**
 * Clear from cursor to end of line
 */
void terminal_clear_line_to_end(void);

/**
 * Read single key press
 *
 * Blocks until a key is pressed. Handles multi-byte sequences for arrow keys,
 * function keys, etc.
 *
 * Returns:
 * - Regular ASCII (0-127) for printable chars
 * - TERM_KEY_* codes for special keys
 * - TERM_KEY_UNKNOWN for unrecognized sequences
 * - TERM_KEY_EOF or TERM_KEY_ERROR for no key at all: the input stream ended,
 *   or the read failed. Which of the two a vanished terminal gives is the system's
 *   — a pty whose master closed reads as end-of-input on one and as an error on
 *   another — so they are one answer to a caller, and neither clears: the next
 *   ask gives it again. A loop over this function ends on a negative rather than
 *   taking it for a key it does not know (cmds/interactive.c view_handle_key,
 *   the one reader, takes it as the quit Ctrl-D spells).
 *
 * @return A key code, or a negative answer that is no key
 */
int terminal_read_key(void);

/**
 * Check if input is available (non-blocking)
 *
 * Uses select() with 0 timeout to check stdin.
 *
 * @return true if data available on stdin
 */
bool terminal_has_input(void);

/**
 * Cleanup function for __attribute__((cleanup))
 */
static inline void terminal_cleanup(terminal_t **term) {
    if (term && *term) {
        terminal_restore(*term);
        *term = NULL;
    }
}

#define TERMINAL_CLEANUP __attribute__((cleanup(terminal_cleanup)))

#endif /* DOTTA_TERMINAL_H */
