/**
 * terminal.c - Terminal control implementation
 *
 * Provides POSIX-compliant terminal control for building inline TUIs.
 */

#include "base/terminal.h"

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include "base/error.h"
#include "base/heap.h"

/* Terminal Initialization & Cleanup  */

/**
 * Terminal state structure
 */
struct terminal {
    struct termios orig_termios;  /* Original terminal settings */
    bool raw_mode_enabled;        /* Track if raw mode is active */
};

error_t terminal_init(terminal_t **out) {
    CHECK_NULL(out);

    /* Check if stdin is a TTY */
    if (!isatty(STDIN_FILENO)) {
        return error_create(
            ERR_INVALID_ARG, "stdin is not a terminal"
        );
    }

    /* Save original terminal settings */
    struct termios orig;
    if (tcgetattr(STDIN_FILENO, &orig) < 0) {
        return error_from_errno(errno, "failed to get terminal attributes");
    }

    /* Configure raw mode */
    struct termios raw = orig;

    /* Input flags:
     * - BRKINT: disable break conditions
     * - ICRNL: disable CR to NL translation
     * - INPCK: disable parity checking
     * - ISTRIP: disable 8th bit stripping
     * - IXON: disable software flow control (Ctrl+S/Ctrl+Q)
     */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    /* Output flags - OPOST: disable output processing */
    raw.c_oflag &= ~(OPOST);

    /* Control flags - CS8: set 8 bits per byte */
    raw.c_cflag |= (CS8);

    /* Local flags:
     * - ECHO: disable echo
     * - ICANON: disable canonical mode (line buffering)
     * - IEXTEN: disable extended input processing (Ctrl+V)
     * - ISIG: disable signals (Ctrl+C, Ctrl+Z)
     */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

    /* Control characters:
     * - VMIN: minimum bytes for read (1 = return after 1 byte)
     * - VTIME: timeout in deciseconds (0 = blocking read)
     */
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    /* Armed before raw mode goes on: a terminating signal from here puts the
     * original settings back (terminal_arm, which keeps a copy). */
    terminal_arm(&orig);

    /* Apply raw mode settings. A refusal disarms, which moves no errno. */
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        terminal_disarm();
        return error_from_errno(errno, "failed to enable raw mode");
    }

    /* The state, made once raw mode is on: nothing before it had to be undone */
    terminal_t *term = heap_calloc(1, sizeof(terminal_t));
    term->orig_termios = orig;
    term->raw_mode_enabled = true;
    *out = term;
    return NULL;
}

void terminal_restore(terminal_t *term) {
    if (!term) return;

    /* Restore original terminal settings, and disarm them once they are back */
    if (term->raw_mode_enabled) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term->orig_termios);
        term->raw_mode_enabled = false;
        terminal_disarm();
    }

    /* Show cursor in case it was hidden */
    terminal_cursor_show();

    free(term);
}

/* The Armed Settings */

/* What a terminating signal puts back: the settings armed, and whether the cursor
 * is hidden. Written by the code that changes the terminal and read by a signal
 * handler, so every flag is a volatile sig_atomic_t and the settings are whole
 * before the flag that says so (terminal_arm). */
static struct termios armed_settings;
static volatile sig_atomic_t armed = 0;
static volatile sig_atomic_t cursor_hidden = 0;

void terminal_arm(const struct termios *settings) {
    CHECK_ARG(!armed, "the terminal is armed already");

    /* The flag down while the copy is made, and up only once it is whole: a signal
     * between the two finds nothing armed rather than half a copy. The fences
     * keep the compiler from moving the copy across either store. */
    armed = 0;
    atomic_signal_fence(memory_order_seq_cst);
    armed_settings = *settings;
    atomic_signal_fence(memory_order_seq_cst);
    armed = 1;
}

void terminal_disarm(void) {
    armed = 0;
}

void terminal_restore_armed(void) {
    /* TCSANOW, never a drain: a handler must not wait on output a stopped terminal
     * may never take. */
    if (armed) {
        (void) tcsetattr(STDIN_FILENO, TCSANOW, &armed_settings);
        armed = 0;
    }

    /* A hidden cursor is an inline UI drawing (cmds/interactive.c): its line
     * ended first, as the UI's own exit ends it, so the shell's prompt starts
     * clear — then the cursor. Straight to the descriptor: stdio is not
     * async-signal-safe, and what it holds unflushed dies with the process. */
    if (cursor_hidden) {
        static const char back[] = "\r\n" ANSI_CURSOR_SHOW;
        (void) write(STDOUT_FILENO, back, sizeof(back) - 1);
        cursor_hidden = 0;
    }
}

/* Terminal Capabilities */

error_t terminal_get_size(terminal_size_t *out) {
    CHECK_NULL(out);

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) {
        return error_from_errno(errno, "failed to get terminal size");
    }

    /* Validate terminal size */
    if (ws.ws_row == 0 || ws.ws_col == 0) {
        return error_create(
            ERR_FS, "invalid terminal size: %ux%u rows x cols",
            ws.ws_row, ws.ws_col
        );
    }

    out->rows = ws.ws_row;
    out->cols = ws.ws_col;
    return NULL;
}

bool terminal_is_tty(void) {
    return isatty(STDIN_FILENO);
}

/* Cursor Control */

void terminal_cursor_hide(void) {
    /* Marked before it is hidden: a signal between the two shows a cursor that
     * was never hidden, which is harmless. */
    cursor_hidden = 1;
    fprintf(stdout, ANSI_CURSOR_HIDE);
    fflush(stdout);
}

void terminal_cursor_show(void) {
    fprintf(stdout, ANSI_CURSOR_SHOW);
    fflush(stdout);
    cursor_hidden = 0;   /* after: a signal before it shows the cursor twice */
}

void terminal_cursor_move(int row, int col) {
    fprintf(stdout, ANSI_CURSOR_POSITION, row, col);
    fflush(stdout);
}

void terminal_cursor_up(int n) {
    if (n > 0) {
        fprintf(stdout, ANSI_CURSOR_UP, n);
        fflush(stdout);
    }
}

void terminal_cursor_down(int n) {
    if (n > 0) {
        fprintf(stdout, ANSI_CURSOR_DOWN, n);
        fflush(stdout);
    }
}

void terminal_cursor_to_start(void) {
    fprintf(stdout, ANSI_CURSOR_TO_START);
    fflush(stdout);
}

void terminal_cursor_save(void) {
    fprintf(stdout, ANSI_CURSOR_SAVE);
    fflush(stdout);
}

void terminal_cursor_restore(void) {
    fprintf(stdout, ANSI_CURSOR_RESTORE);
    fflush(stdout);
}

/* Screen Control */

void terminal_clear_screen(void) {
    fprintf(stdout, ANSI_CLEAR_SCREEN);
    terminal_cursor_move(1, 1);
    fflush(stdout);
}

void terminal_clear_to_end(void) {
    fprintf(stdout, ANSI_CLEAR_TO_END);
    fflush(stdout);
}

void terminal_clear_line(void) {
    fprintf(stdout, ANSI_CLEAR_LINE);
    fflush(stdout);
}

void terminal_clear_line_to_end(void) {
    fprintf(stdout, ANSI_CLEAR_LINE_TO_END);
    fflush(stdout);
}

/* Input Reading */

/**
 * Read single byte from stdin
 *
 * Returns:
 * - Byte value (0-255) on success
 * - TERM_KEY_EOF when the stream ended, TERM_KEY_ERROR when the read failed —
 *   the two answers terminal_read_key hands its own caller, named here so the
 *   negatives travel out of the module under one name (base/terminal.h)
 */
static int read_byte(void) {
    unsigned char c;
    ssize_t n = read(STDIN_FILENO, &c, 1);

    if (n < 0) {
        return TERM_KEY_ERROR;
    } else if (n == 0) {
        return TERM_KEY_EOF;
    }

    return c;
}

/**
 * Read escape sequence
 *
 * Called after reading ESC (0x1B). Reads the following bytes and maps them to
 * TERM_KEY_* codes.
 *
 * Common sequences:
 * - ESC [ A -> Up
 * - ESC [ B -> Down
 * - ESC [ C -> Right
 * - ESC [ D -> Left
 * - ESC [ H -> Home
 * - ESC [ F -> End
 * - ESC [ 3 ~ -> Delete
 *
 * A read that gives nothing part-way through a sequence answers as a key here —
 * ESC alone, or one with no name — because the bytes already read were a key
 * press. The end of input is met again at the next terminal_read_key, which is
 * where it is answered as itself.
 */
static int read_escape_sequence(void) {
    /* Check if more input is available without blocking. If not, this was just
     * a standalone ESC key press. */
    if (!terminal_has_input()) {
        return TERM_KEY_ESCAPE;
    }

    int c1 = read_byte();
    if (c1 < 0) {
        return TERM_KEY_ESCAPE; /* Just ESC */
    }

    /* Check for CSI sequence (ESC [) */
    if (c1 != '[') {
        /* Not a CSI sequence, could be Alt+key or other */
        return TERM_KEY_UNKNOWN;
    }

    int c2 = read_byte();
    if (c2 < 0) {
        return TERM_KEY_UNKNOWN;
    }

    /* Single character sequences */
    switch (c2) {
        case 'A':
            return TERM_KEY_UP;
        case 'B':
            return TERM_KEY_DOWN;
        case 'C':
            return TERM_KEY_RIGHT;
        case 'D':
            return TERM_KEY_LEFT;
        case 'H':
            return TERM_KEY_HOME;
        case 'F':
            return TERM_KEY_END;
        default:
            break;
    }

    /* Multi-character sequences (e.g., ESC [ 3 ~) */
    if (c2 >= '0' && c2 <= '9') {
        int c3 = read_byte();
        if (c3 == '~') {
            switch (c2) {
                case '1':
                    return TERM_KEY_HOME;
                case '3':
                    return TERM_KEY_DELETE;
                case '4':
                    return TERM_KEY_END;
                case '5':
                    return TERM_KEY_PAGE_UP;
                case '6':
                    return TERM_KEY_PAGE_DOWN;
                case '7':
                    return TERM_KEY_HOME;
                case '8':
                    return TERM_KEY_END;
                default:
                    break;
            }
        }
    }

    return TERM_KEY_UNKNOWN;
}

int terminal_read_key(void) {
    int c = read_byte();

    if (c < 0) {
        return c; /* No key: TERM_KEY_EOF or TERM_KEY_ERROR, as read_byte named it */
    }

    /* Handle escape sequences */
    if (c == TERM_KEY_ESCAPE) {
        return read_escape_sequence();
    }

    /* Map special keys */
    switch (c) {
        case 127:  /* Backspace (sometimes DEL) */
        case '\b': /* Backspace (sometimes ^H) */
            return TERM_KEY_BACKSPACE;

        case '\r': /* Enter */
        case '\n': /* Newline */
            return TERM_KEY_ENTER;

        default:
            return c;
    }
}

bool terminal_has_input(void) {
    fd_set readfds;
    struct timeval timeout;

    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    /* Zero timeout = non-blocking check */
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int result;
    do {
        result = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);
        /* Retry on EINTR (interrupted by signal) */
    } while (result < 0 && errno == EINTR);

    /* Return true only if input is available. Other errors are treated as "no
     * input" (conservative). */
    return result > 0;
}
