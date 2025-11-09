/**
 * terminal.c - Terminal control implementation
 *
 * Provides POSIX-compliant terminal control for building inline TUIs.
 */

#include "terminal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include "base/error.h"

/* Terminal Initialization & Cleanup  */

/**
 * Terminal state structure
 */
struct terminal {
    struct termios orig_termios;  /* Original terminal settings */
    bool raw_mode_enabled;        /* Track if raw mode is active */
};

error_t *terminal_init(terminal_t **out) {
    if (!out) {
        return error_create(ERR_INVALID_ARG, "out cannot be NULL");
    }

    /* Check if stdin is a TTY */
    if (!isatty(STDIN_FILENO)) {
        return error_create(ERR_INVALID_ARG, "stdin is not a terminal");
    }

    /* Allocate terminal state */
    terminal_t *term = calloc(1, sizeof(terminal_t));
    if (!term) {
        return error_create(ERR_MEMORY, "failed to allocate terminal state");
    }

    /* Save original terminal settings */
    if (tcgetattr(STDIN_FILENO, &term->orig_termios) < 0) {
        free(term);
        return error_create(ERR_FS, "failed to get terminal attributes: %s",
                          strerror(errno));
    }

    /* Configure raw mode */
    struct termios raw = term->orig_termios;

    /* Input flags:
     * - BRKINT: disable break conditions
     * - ICRNL: disable CR to NL translation
     * - INPCK: disable parity checking
     * - ISTRIP: disable 8th bit stripping
     * - IXON: disable software flow control (Ctrl+S/Ctrl+Q)
     */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    /* Output flags:
     * - OPOST: disable output processing
     */
    raw.c_oflag &= ~(OPOST);

    /* Control flags:
     * - CS8: set 8 bits per byte
     */
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

    /* Apply raw mode settings */
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        free(term);
        return error_create(ERR_FS, "failed to enable raw mode: %s",
                          strerror(errno));
    }

    term->raw_mode_enabled = true;
    *out = term;
    return NULL;
}

void terminal_restore(terminal_t *term) {
    if (!term) {
        return;
    }

    /* Restore original terminal settings */
    if (term->raw_mode_enabled) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term->orig_termios);
        term->raw_mode_enabled = false;
    }

    /* Show cursor in case it was hidden */
    terminal_cursor_show();

    free(term);
}

/* Terminal Capabilities */

error_t *terminal_get_size(terminal_size_t *out) {
    if (!out) {
        return error_create(ERR_INVALID_ARG, "out cannot be NULL");
    }

    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) {
        return error_create(ERR_FS, "failed to get terminal size: %s",
                          strerror(errno));
    }

    /* Validate terminal size */
    if (ws.ws_row == 0 || ws.ws_col == 0) {
        return error_create(ERR_FS, "invalid terminal size: %ux%u rows x cols",
                          ws.ws_row, ws.ws_col);
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
    fprintf(stdout, ANSI_CURSOR_HIDE);
    fflush(stdout);
}

void terminal_cursor_show(void) {
    fprintf(stdout, ANSI_CURSOR_SHOW);
    fflush(stdout);
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
 * - -1 on EOF
 * - -2 on error
 */
static int read_byte(void) {
    unsigned char c;
    ssize_t n = read(STDIN_FILENO, &c, 1);

    if (n < 0) {
        return -2; /* Error */
    } else if (n == 0) {
        return -1; /* EOF */
    }

    return c;
}

/**
 * Read escape sequence
 *
 * Called after reading ESC (0x1B). Reads the following bytes
 * and maps them to TERM_KEY_* codes.
 *
 * Common sequences:
 * - ESC [ A -> Up
 * - ESC [ B -> Down
 * - ESC [ C -> Right
 * - ESC [ D -> Left
 * - ESC [ H -> Home
 * - ESC [ F -> End
 * - ESC [ 3 ~ -> Delete
 */
static int read_escape_sequence(void) {
    /* Check if more input is available without blocking.
     * If not, this was just a standalone ESC key press. */
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
            }
        }
    }

    return TERM_KEY_UNKNOWN;
}

int terminal_read_key(void) {
    int c = read_byte();

    if (c < 0) {
        return c; /* EOF or error */
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

    /* Return true only if input is available.
     * Other errors are treated as "no input" (conservative). */
    return result > 0;
}
