/**
 * terminal.h - Terminal control utilities
 *
 * Provides low-level terminal control for building inline TUIs.
 * Handles raw mode, ANSI escape sequences, and input reading.
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
 * Regular ASCII characters (a-z, 0-9, etc.) are returned as-is.
 * These codes represent special keys that need multi-byte sequences.
 */
typedef enum {
    TERM_KEY_UNKNOWN = -1,
    TERM_KEY_UP = 1000,
    TERM_KEY_DOWN,
    TERM_KEY_LEFT,
    TERM_KEY_RIGHT,
    TERM_KEY_HOME,
    TERM_KEY_END,
    TERM_KEY_PAGE_UP,
    TERM_KEY_PAGE_DOWN,
    TERM_KEY_DELETE,
    TERM_KEY_BACKSPACE = 127,
    TERM_KEY_ENTER = '\r',
    TERM_KEY_ESCAPE = 27,
    TERM_KEY_TAB = '\t',
    TERM_KEY_SPACE = ' ',
    TERM_KEY_CTRL_C = 3,
    TERM_KEY_CTRL_D = 4
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
 * Always call terminal_restore() when done, even on errors.
 *
 * @param out Terminal state (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *terminal_init(terminal_t **out);

/**
 * Restore terminal to original state
 *
 * Restores settings saved by terminal_init().
 * Safe to call multiple times.
 *
 * @param term Terminal state (can be NULL)
 */
void terminal_restore(terminal_t *term);

/**
 * Get terminal size
 *
 * Queries current terminal dimensions via ioctl.
 *
 * @param out Size (must not be NULL)
 * @return Error or NULL on success
 */
error_t *terminal_get_size(terminal_size_t *out);

/**
 * Check if stdin is a TTY
 *
 * @return true if stdin is connected to a terminal
 */
bool terminal_is_tty(void);

/**
 * Hide cursor
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
 * Blocks until a key is pressed. Handles multi-byte sequences
 * for arrow keys, function keys, etc.
 *
 * Returns:
 * - Regular ASCII (0-127) for printable chars
 * - TERM_KEY_* codes for special keys
 * - TERM_KEY_UNKNOWN for unrecognized sequences
 *
 * @return Key code
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
