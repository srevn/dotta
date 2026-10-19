/**
 * process.c - Unified subprocess primitive implementation
 *
 * Single linear procedure: validate spec → open what the child reads and where
 * it writes (process_stdin_open, process_output_open) and the exec's pipe → fork
 * → the child sets up its environment and execs (process_child) → the parent
 * drains a pipe's output by poll() to the limit's deadline (process_drain), keeping
 * what a capture asks for (process_capture_t) → parent reaps the child by the
 * same deadline (process_reap), escalating SIGTERM→SIGKILL where the limit came
 * first (process_kill) → parent reports the reaped child into the result struct
 * (process_report), and reads a file's output (process_read_file).
 *
 * One cleanup label handles all error paths. Every resource (descriptors, capture
 * buffer, stray child) is initialized to a sentinel so cleanup is unconditional
 * and order-independent.
 */

#include "sys/process.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/heap.h"
#include "base/secure.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

/* Initial capture buffer size; doubles on demand up to the bound
 * (PROCESS_CAPTURE_MAX, and its NUL). */
#define PROCESS_CAPTURE_INITIAL 4096

/* Read chunk size for the child's output: a pipe's drain, a file's read. */
#define PROCESS_READ_CHUNK 4096

/* The bound of the child's close loop (process_child): the descriptor limit, at
 * most git's 4096 (lib/git/run-command.c start_command), so a limit raised to a
 * million costs no million close()s a spawn, and one sysconf cannot tell reads
 * as the cap. A descriptor at or past it stands only in a run already holding
 * thousands — libgit2's pack files, each close-on-exec
 * (lib/libgit2/src/util/posix.c p_open) — and reaches the exec only where it is
 * not. */
#define PROCESS_FD_CAP 4096

/* The reap's cadence (process_reap): a look at once, then a sleep of a millisecond,
 * doubling to 50 ms — a child that exits at once is reaped at once, and one that
 * runs on costs a wakeup every 50 ms. */
#define PROCESS_REAP_FIRST_NS (1000L * 1000L)
#define PROCESS_REAP_MAX_NS (50L * 1000L * 1000L)

#define PROCESS_NS_PER_SECOND (1000L * 1000L * 1000L)
#define PROCESS_NS_PER_MS (1000L * 1000L)

/* Grace periods for the timeout escalation. SIGTERM gets the longer window; SIGKILL
 * is essentially instantaneous but we still bound the wait so a stuck reap doesn't
 * block forever. */
#define PROCESS_GRACE_TERM_SECONDS 5
#define PROCESS_GRACE_KILL_SECONDS 3

/* Best-effort orphan reap window during cleanup. Short — if the child won't die
 * in this time, we abandon and let init reap. */
#define PROCESS_GRACE_ORPHAN_SECONDS 1

/* The pgid of the PROCESS_PGRP_NEW child process_run() is running, zero otherwise:
 * published once the child's group is set, the terminating signals held across
 * the fork until then, and cleared on every exit path below. The host program's
 * terminating-signal handler reads it through the declaration in process.h and
 * forwards the signal to the group, so a Ctrl+C kills dotta and the spawned hook
 * atomically rather than orphaning the hook. PROCESS_PGRP_SHARED children leave
 * it at zero — the kernel already delivers terminal signals to the whole foreground
 * group. */
volatile sig_atomic_t active_child_pgid = 0;

/**
 * Write all `n` bytes of `buf` to `fd`, retrying on partial writes and EINTR,
 * until done or refused. A refusal costs the bytes alone, whoever the caller: a
 * payload whose child is gone, a copy whose reader went away (EPIPE, SIGPIPE
 * ignored: the header), a child's errno, whose exit code (126, 127) then reports
 * the failure alone.
 */
static void process_write(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        p += w;
        n -= (size_t) w;
    }
}

/* The monotonic instant `seconds` from now, immune to wall-clock jumps */
static struct timespec process_deadline(int seconds) {
    struct timespec deadline = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += seconds;

    return deadline;
}

/* Nanoseconds from now until `deadline`, 0 once it has passed: a limit counted
 * in the time that passed, never in the seconds the clock turned */
static int64_t process_remaining(const struct timespec *deadline) {
    struct timespec now = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t left = (int64_t) (deadline->tv_sec - now.tv_sec) *
        PROCESS_NS_PER_SECOND + (deadline->tv_nsec - now.tv_nsec);

    return left > 0 ? left : 0;
}

/**
 * waitpid by a deadline: `pid` once reaped, its status in *status; 0 where the
 * deadline came first; -1 with errno where the wait failed. With no deadline
 * (NULL) it waits as long as the child runs. Polls at once, then after a sleep
 * from PROCESS_REAP_FIRST_NS doubling to PROCESS_REAP_MAX_NS, never past the
 * deadline.
 */
static pid_t process_reap(pid_t pid, const struct timespec *deadline, int *status) {
    if (!deadline) {
        pid_t reaped;
        do {
            reaped = waitpid(pid, status, 0);
        } while (reaped < 0 && errno == EINTR);
        return reaped;
    }

    int64_t interval = PROCESS_REAP_FIRST_NS;
    for (;;) {
        pid_t reaped = waitpid(pid, status, WNOHANG);
        if (reaped == pid) return pid;
        if (reaped < 0 && errno != EINTR) return -1;

        int64_t left = process_remaining(deadline);
        if (left == 0) return 0;

        int64_t nap = interval < left ? interval : left;
        struct timespec delay = {
            .tv_sec  = (time_t) (nap / PROCESS_NS_PER_SECOND),
            .tv_nsec = (long) (nap % PROCESS_NS_PER_SECOND),
        };
        (void) nanosleep(&delay, NULL);
        interval = interval * 2 <
            PROCESS_REAP_MAX_NS ? interval * 2 : PROCESS_REAP_MAX_NS;
    }
}

/**
 * End a child its limit outlived: SIGTERM to `target` (the child, or its group's
 * negated pgid), SIGKILL once the grace has passed. True once reaped, its status
 * in *status. The single source of the SIGTERM/SIGKILL escalation.
 */
static bool process_kill(pid_t pid, pid_t target, int *status) {
    /* kill() failure is non-fatal — the target may already be gone, in which
     * case the reap tells. */
    (void) kill(target, SIGTERM);
    struct timespec grace = process_deadline(PROCESS_GRACE_TERM_SECONDS);
    if (process_reap(pid, &grace, status) == pid) return true;

    (void) kill(target, SIGKILL);
    grace = process_deadline(PROCESS_GRACE_KILL_SECONDS);
    return process_reap(pid, &grace, status) == pid;
}

/**
 * A pipe for `program`'s spawn, both ends closed at an exec; its refusal names
 * the program
 *
 * For the exec's pipe the mark is the protocol: its write end, closed by the
 * exec, tells the parent the exec happened. For the others it is a second guard
 * beside the child's close loop (process_child). F_SETFD fails only for a
 * descriptor that is not open, and pipe() has just opened both.
 */
static error_t process_pipe(int fds[2], const char *program) {
    if (pipe(fds) != 0) {
        return error_errno(errno, "Failed to create a pipe for '%s'", program);
    }
    (void) fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void) fcntl(fds[1], F_SETFD, FD_CLOEXEC);

    return NULL;
}

/**
 * A file for `program`'s output, its two descriptors a pipe's two ends, both
 * closed at an exec; its refusal names the directory and the program
 *
 * fds[0] is the parent's to read, fds[1] the child's own to write — a duplicate,
 * which the parent closes once the child holds it, as it closes a pipe's end.
 * The two share one offset, which the child's writes move, so the parent reads
 * by position (process_read_file). In the temporary directory (sys/filesystem.h
 * fs_tmpdir) and unlinked at once: nothing names it, and it is gone at its last
 * close — the parent's, or that of a task the child left writing on.
 */
static error_t process_file(int fds[2], const char *program) {
    /* A template mkstemp could not create is no file of this run's, whatever
     * name it tried last, so nothing is unlinked */
    const char *dir = fs_tmpdir();
    char *path = heap_str_format("%s/dotta-output-XXXXXX", dir);
    fds[0] = mkstemp(path);
    if (fds[0] < 0) {
        error_t err = error_errno(
            errno, "Failed to create a temporary file in '%s' for '%s'", dir, program
        );
        free(path);
        return err;
    }
    (void) unlink(path);
    free(path);
    (void) fcntl(fds[0], F_SETFD, FD_CLOEXEC);

    fds[1] = fcntl(fds[0], F_DUPFD_CLOEXEC, 0);
    if (fds[1] < 0) {
        error_t err = error_errno(
            errno, "Failed to create a temporary file in '%s' for '%s'", dir, program
        );
        close(fds[0]);
        return err;
    }

    return NULL;
}

/**
 * The descriptors a stdin policy needs before the fork: what the child reads,
 * `*child`, and the end the parent writes its payload into, `*parent` — a pipe's
 * two ends (BUFFER), /dev/null for the child alone (DEVNULL), neither (INHERIT).
 * Each -1 where the policy has none, and both on a refusal, which names the
 * program.
 */
static error_t process_stdin_open(
    const process_spec_t *spec, int *parent, int *child
) {
    *parent = -1;
    *child = -1;

    switch (spec->stdin_policy) {
        case PROCESS_STDIN_INHERIT:
            return NULL;

        case PROCESS_STDIN_DEVNULL:
            /* Opened here, where its failure is a refusal: the child could only
             * keep dotta's stdin in its place */
            *child = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (*child < 0) {
                return error_errno(
                    errno, "Failed to open /dev/null for '%s'",
                    spec->argv[0]
                );
            }
            return NULL;

        case PROCESS_STDIN_BUFFER: {
            int fds[2];
            error_t err = process_pipe(fds, spec->argv[0]);
            if (err) return err;

            *child = fds[0];
            *parent = fds[1];
            return NULL;
        }
    }

    CHECK_ARG(false, "a stdin policy no enumerator names");
}

/**
 * The descriptors an output policy needs before the fork: where the child writes,
 * `*child`, and what the parent reads, `*parent` — a pipe's two ends (CAPTURE,
 * STREAM), a file's (FILE), /dev/null for the child alone (DEVNULL). Each -1
 * where the policy has none, and both on a refusal, which names the program.
 */
static error_t process_output_open(
    const process_spec_t *spec, int *parent, int *child
) {
    *parent = -1;
    *child = -1;

    switch (spec->output_policy) {
        case PROCESS_OUTPUT_DEVNULL:
            /* Opened here, where its failure is a refusal: the child could only
             * keep dotta's output in its place */
            *child = open("/dev/null", O_WRONLY | O_CLOEXEC);
            if (*child < 0) {
                return error_errno(
                    errno, "Failed to open /dev/null for '%s'",
                    spec->argv[0]
                );
            }
            return NULL;

        case PROCESS_OUTPUT_CAPTURE:
        case PROCESS_OUTPUT_STREAM: {
            int fds[2];
            error_t err = process_pipe(fds, spec->argv[0]);
            if (err) return err;

            *parent = fds[0];
            *child = fds[1];
            return NULL;
        }

        case PROCESS_OUTPUT_FILE: {
            int fds[2];
            error_t err = process_file(fds, spec->argv[0]);
            if (err) return err;

            *parent = fds[0];
            *child = fds[1];
            return NULL;
        }
    }

    CHECK_ARG(false, "an output policy no enumerator names");
}

/**
 * A child's signals, made its own before exec — both primitives' children
 *
 * No handler of the parent's runs between fork and exec: execve() resets a caught
 * signal to SIG_DFL itself, and this covers the window before it the way execve()
 * would — a terminating signal the parent catches goes back to its default, and
 * one it inherited ignored stays ignored. SIGPIPE is dotta's own ignore (main.c),
 * never the child's, and the mask is cleared — both parents block signals across
 * the fork (process_run the terminating ones, process_foreground the keyboard's),
 * and one that arrived since lands here, on its default. Called in the child
 * alone: no error_t, no malloc.
 */
static void process_child_signals(void) {
    static const int terminating[] = PROCESS_TERMINATING_SIGNALS;
    for (size_t i = 0; i < sizeof(terminating) / sizeof(*terminating); i++) {
        struct sigaction current;
        if (sigaction(terminating[i], NULL, &current) == 0 &&
            current.sa_handler != SIG_IGN) {
            signal(terminating[i], SIG_DFL);
        }
    }
    signal(SIGPIPE, SIG_DFL);

    sigset_t empty;
    sigemptyset(&empty);
    (void) sigprocmask(SIG_SETMASK, &empty, NULL);
}

/**
 * A child's failure before its exec, or its exec's: the errno over the exec's
 * pipe, which the parent reads into the result (exec_failed, exec_errno), then
 * the exit — 126 for a step of the setup, 127 for the exec. Both primitives'
 * children.
 */
static _Noreturn void process_child_fail(int errfd, int code) {
    int e = errno;
    process_write(errfd, &e, sizeof(e));
    _exit(code);
}

/**
 * The child, from the fork to its exec: its signals and its group, the invoker's
 * identity, its stdin and its output, every other descriptor closed, its working
 * directory — then the exec
 *
 * `in` is what the stdin policy opened for the child, -1 for dotta's own
 * (process_stdin_open), `out` what the output policy opened for it
 * (process_output_open), `errfd` the exec's pipe's write end: each above 2
 * (main.c), so no dup2 here overwrites another's source. No error_t, no malloc,
 * no return: a failure is its errno over the exec's pipe (process_child_fail).
 */
static _Noreturn void process_child(
    const process_spec_t *spec, int in, int out, int errfd
) {
    /* The child's signals, its own before exec (process_child_signals). */
    process_child_signals();

    if (spec->pgrp_policy == PROCESS_PGRP_NEW) {
        (void) setpgid(0, 0);
    }

    /* The invoker's child, for good (sys/identity), before anything the child
     * does — the chdir, the exec, the script. Reported as an exec failure is:
     * errno over the self-pipe, 126. */
    if (identity_drop_child() != 0) process_child_fail(errfd, 126);

    if (in >= 0 && dup2(in, STDIN_FILENO) < 0) process_child_fail(errfd, 126);
    if (dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0) {
        process_child_fail(errfd, 126);
    }

    /* Close every other inherited fd below the cap (PROCESS_FD_CAP): the parent's
     * ends — so the child never holds its own stdin's write end, nor what the
     * parent reads its output from — the originals of what it was handed, and
     * libgit2's and SQLite's handles, which must not leak into the script: a
     * socket of libgit2's is close-on-exec only where the platform has SOCK_CLOEXEC
     * (lib/libgit2/src/util/posix.h). errfd must survive — it carries any
     * exec-failure errno back to the parent. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > PROCESS_FD_CAP) {
        maxfd = PROCESS_FD_CAP;
    }
    for (int fd = STDERR_FILENO + 1; fd < (int) maxfd; fd++) {
        if (fd != errfd) {
            close(fd);
        }
    }

    if (spec->work_dir && chdir(spec->work_dir) != 0 &&
        (!spec->work_dir_fallback || chdir(spec->work_dir_fallback) != 0)) {
        process_child_fail(errfd, 126);
    }

    execve(spec->argv[0], spec->argv, spec->envp);
    process_child_fail(errfd, 127);
}

/**
 * A reaped child, reported into its result: the errno its exec's pipe holds,
 * where the child wrote one before its exit (process_child_fail), and its wait
 * status — the code it exited with, or the signal that ended it and 128 past
 * it. Both primitives' children.
 *
 * Read once the child is reaped, so the read never waits: the pipe's write end
 * closed at the exec (FD_CLOEXEC) or at the child's exit, and the child forks
 * nothing before its exec — where a read before the reap would wait out a child
 * held before its exec, past any limit.
 */
static void process_report(int errfd, int status, process_result_t *result) {
    int exec_errno = 0;
    ssize_t got;
    do {
        got = read(errfd, &exec_errno, sizeof(exec_errno));
    } while (got < 0 && errno == EINTR);

    if (got == (ssize_t) sizeof(exec_errno)) {
        result->exec_failed = true;
        result->exec_errno = exec_errno;
    }

    /* exec_failed is independent — exit_code reflects what the wait returned
     * (126 or 127 for a child that failed before its exec or at it), which is
     * still useful information for the caller. */
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->signal_num = WTERMSIG(status);
        result->exit_code = 128 + result->signal_num;
    } else {
        /* WIFSTOPPED or other unexpected wait state — should not occur because
         * we do not pass WUNTRACED. Map to a generic failure so callers do not
         * see uninitialized fields. */
        result->exit_code = 1;
    }
}

/**
 * What a capture keeps of the child's output: its first PROCESS_CAPTURE_MAX bytes,
 * terminated, and the count of the rest. Kept as a secret is (process_output_t):
 * every allocation that held a byte of it is wiped before the allocator has it
 * back.
 */
typedef struct {
    char *bytes;                  /* the kept bytes, NUL-terminated */
    size_t len;                   /* bytes kept, the NUL not counted */
    size_t capacity;              /* bytes' allocation, the NUL's byte among it */
    size_t dropped;               /* bytes past the bound, never kept */
} process_capture_t;

/* A capture's first buffer, PROCESS_CAPTURE_INITIAL bytes, empty and terminated */
static void process_capture_init(process_capture_t *capture) {
    *capture = (process_capture_t) {
        .bytes = heap_alloc(PROCESS_CAPTURE_INITIAL),
        .capacity = PROCESS_CAPTURE_INITIAL,
    };

    capture->bytes[0] = '\0';
}

/**
 * Keep a chunk of the child's output: as much of it as the bound has room for,
 * the rest counted — the child's volume never sizes the capture (the header).
 *
 * The buffer doubles to fit, never past the bound and its NUL, which no chunk
 * needs more than, so the doubling cannot overflow. It grows by malloc → memcpy
 * → wipe → free, the old allocation wiped whole: a realloc may move the bytes
 * and leave the old ones on the freelist unwiped. The cost is a copy and a wipe
 * per doubling, nine at most to the bound, and none for an output that fits the
 * first buffer.
 */
static void process_capture_add(
    process_capture_t *capture, const char *chunk, size_t n
) {
    size_t room = PROCESS_CAPTURE_MAX - capture->len;
    size_t keep = n < room ? n : room;
    capture->dropped += n - keep;

    size_t need = capture->len + keep + 1;
    if (need > capture->capacity) {
        size_t capacity = capture->capacity;
        while (capacity < need) capacity *= 2;
        if (capacity > PROCESS_CAPTURE_MAX + 1) capacity = PROCESS_CAPTURE_MAX + 1;

        char *grown = heap_alloc(capacity);
        memcpy(grown, capture->bytes, capture->len);
        secure_wipe(capture->bytes, capture->capacity);
        free(capture->bytes);
        capture->bytes = grown;
        capture->capacity = capacity;
    }

    memcpy(capture->bytes + capture->len, chunk, keep);
    capture->len += keep;
    capture->bytes[capture->len] = '\0';
}

/* A capture never handed to the result, wiped and freed, so partial-read bytes
 * do not linger after a mid-capture failure */
static void process_capture_deinit(process_capture_t *capture) {
    secure_wipe(capture->bytes, capture->capacity);
    free(capture->bytes);
    *capture = (process_capture_t) { 0 };
}

/**
 * Read a pipe's output to its end or to the deadline (none where NULL), whichever
 * comes first — *timed_out says which. CAPTURE keeps it (process_capture_add);
 * STREAM copies it to dotta's stdout as it comes, a copy its reader refused lost
 * alone. Kept or copied, every chunk is read, so a child past the bound or past
 * its reader never blocks on a full pipe and runs to its own end.
 */
static error_t process_drain(
    const process_spec_t *spec, int fd, const struct timespec *deadline,
    process_capture_t *capture, bool *timed_out
) {
    char chunk[PROCESS_READ_CHUNK];
    error_t err = NULL;

    /* Not blocking, so a read the poll woke for never waits past the deadline */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    *timed_out = false;
    for (;;) {
        /* The wait, by the deadline where there is one: its remaining milliseconds
         * rounded up, so the poll never wakes short of it */
        int wait_ms = -1;
        if (deadline) {
            int64_t left = process_remaining(deadline);
            if (left == 0) {
                *timed_out = true;
                break;
            }
            int64_t ms = (left + PROCESS_NS_PER_MS - 1) / PROCESS_NS_PER_MS;
            wait_ms = ms < INT_MAX ? (int) ms : INT_MAX;
        }

        /* poll(2), never select(2): an fd_set holds no descriptor at or past
         * FD_SETSIZE, and the pipe's is the lowest one free at the spawn — past
         * every pack descriptor libgit2 holds for the run
         * (lib/libgit2/src/libgit2/mwindow.c git_mwindow_file_register) */
        struct pollfd ready = { .fd = fd, .events = POLLIN };
        int rs = poll(&ready, 1, wait_ms);
        if (rs < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = error_errno(errno, "Failed to read the output of '%s'", spec->argv[0]);
            break;
        }
        if (rs == 0) {
            /* The deadline's turn: the loop's top asks it again. */
            continue;
        }

        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            err = error_errno(errno, "Failed to read the output of '%s'", spec->argv[0]);
            break;
        }
        if (n == 0) {
            break;  /* child closed its end of the pipe */
        }

        if (spec->output_policy == PROCESS_OUTPUT_CAPTURE) {
            process_capture_add(capture, chunk, (size_t) n);
        } else {
            process_write(STDOUT_FILENO, chunk, (size_t) n);
        }
    }

    /* The chunk last held the tail of what the child wrote, its bytes past the
     * bound among them — wiped as every buffer that held one is
     * (process_output_t) */
    secure_wipe(chunk, sizeof(chunk));

    return err;
}

/**
 * Read a file's output once its child is reaped: the file as it stands then,
 * its first PROCESS_CAPTURE_MAX bytes kept (process_capture_add) and the rest
 * counted, never read. By position, never through the offset the child's writes
 * move (process_file), so what a task the child left writes on lands past what
 * is read.
 */
static error_t process_read_file(
    const process_spec_t *spec, int fd, process_capture_t *capture
) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return error_errno(errno, "Failed to read the output of '%s'", spec->argv[0]);
    }

    char chunk[PROCESS_READ_CHUNK];
    error_t err = NULL;
    off_t offset = 0;
    while (offset < st.st_size && capture->len < PROCESS_CAPTURE_MAX) {
        ssize_t n = pread(fd, chunk, sizeof(chunk), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = error_errno(errno, "Failed to read the output of '%s'", spec->argv[0]);
            break;
        }
        if (n == 0) {
            break;  /* the file ends short of the size it stood at */
        }

        process_capture_add(capture, chunk, (size_t) n);
        offset += n;
    }
    if (offset < st.st_size) {
        capture->dropped += (size_t) (st.st_size - offset);
    }

    /* The chunk held what the child wrote: wiped as the drain's is */
    secure_wipe(chunk, sizeof(chunk));

    return err;
}

error_t process_run(const process_spec_t *spec, process_result_t *result) {
    CHECK_NULL(spec);
    CHECK_NULL(result);
    CHECK_NULL(spec->argv);
    CHECK_NULL(spec->envp);

    /* The spec's shape is its caller's to keep (process_spec_t): a stdin payload
     * is load-bearing only for BUFFER, so one set under INHERIT or DEVNULL is a
     * payload the caller expected and the child would never read */
    CHECK_ARG(
        spec->argv[0] != NULL && spec->argv[0][0] != '\0',
        "argv[0] names no program"
    );
    CHECK_ARG(
        spec->timeout_seconds >= 0,
        "a time limit below zero"
    );
    CHECK_ARG(
        spec->stdin_policy == PROCESS_STDIN_BUFFER ||
        (spec->stdin_content == NULL && spec->stdin_content_len == 0),
        "a payload the stdin policy never delivers"
    );
    CHECK_ARG(
        spec->stdin_content != NULL || spec->stdin_content_len == 0,
        "a payload length with no payload"
    );
    CHECK_ARG(
        spec->stdin_content_len <= PROCESS_STDIN_BUFFER_MAX,
        "a payload past PROCESS_STDIN_BUFFER_MAX"
    );
    CHECK_ARG(
        spec->stdin_policy != PROCESS_STDIN_INHERIT ||
        spec->pgrp_policy == PROCESS_PGRP_SHARED,
        "a child on dotta's stdin in a process group of its own"
    );

    /* Zero result so every path through cleanup leaves callers with a well-defined
     * struct. */
    *result = (process_result_t) { 0 };

    /* All resources initialized to safe sentinels. */
    const char *program = spec->argv[0];
    int stdin_parent = -1;
    int stdin_child = -1;
    int output_parent = -1;
    int output_child = -1;
    int errfd[2] = { -1, -1 };
    pid_t pid = -1;
    pid_t kill_target = -1;
    process_capture_t capture = { 0 };
    int status = 0;
    error_t err = NULL;

    /* What the child reads and where it writes, each opened before the fork
     * (process_stdin_open, process_output_open). */
    err = process_stdin_open(spec, &stdin_parent, &stdin_child);
    if (err) goto cleanup;

    err = process_output_open(spec, &output_parent, &output_child);
    if (err) goto cleanup;

    /* Exec-errno self-pipe (child writes errno+_exit on exec failure; on exec
     * success, FD_CLOEXEC closes the write end and parent reads EOF). */
    err = process_pipe(errfd, program);
    if (err) goto cleanup;

    /* The capture, made before the fork where the policy keeps the output. */
    if (spec->output_policy == PROCESS_OUTPUT_CAPTURE ||
        spec->output_policy == PROCESS_OUTPUT_FILE) {
        process_capture_init(&capture);
    }

    /* What dotta wrote lands ahead of anything the child writes: a line still
     * in a stdio buffer would follow the child's output wherever both go, so
     * every stream is flushed before the fork, as git flushes before every child
     * (lib/git/run-command.c start_command). */
    (void) fflush(NULL);

    /* The terminating signals held from before the fork until the child's group
     * is set and published: one that arrives in between lands once it is, and
     * is forwarded — never lost while a child of a group of its own runs on past
     * dotta. The child clears the mask with its signals (process_child_signals). */
    static const int signals[] = PROCESS_TERMINATING_SIGNALS;
    sigset_t terminating, before;
    sigemptyset(&terminating);
    for (size_t i = 0; i < sizeof(signals) / sizeof(*signals); i++) {
        sigaddset(&terminating, signals[i]);
    }
    (void) sigprocmask(SIG_BLOCK, &terminating, &before);

    pid = fork();
    if (pid == 0) {
        process_child(spec, stdin_child, output_child, errfd[1]);
    }

    /* ───── Parent ──────────────────────────────────────────────── */

    /* The fork's outcome, the signals still held: its refusal, or the child's
     * group set and published. Race-mitigate: the pgrp is set even if the child
     * has not yet executed setpgid(0,0) itself. setpgid() is idempotent with
     * respect to the (pid,pid) target; EACCES (child already exec'd) is acceptable
     * because the child's own setpgid ran before exec. */
    if (pid < 0) {
        err = error_errno(errno, "Failed to fork '%s'", program);
    } else if (spec->pgrp_policy == PROCESS_PGRP_NEW) {
        (void) setpgid(pid, pid);
        active_child_pgid = (sig_atomic_t) pid;
        kill_target = -pid;
    } else {
        kill_target = pid;
    }

    /* Let go on both outcomes, before anything else can fail: a signal held since
     * the fork lands now, and the handler forwards it to the group just published
     * (main.c terminating_signal). */
    (void) sigprocmask(SIG_SETMASK, &before, NULL);
    if (err) goto cleanup;

    /* Close the child's ends — what it reads, where it writes, the exec's pipe's
     * write end: the child holds its own of each. */
    if (stdin_child >= 0) {
        close(stdin_child);
        stdin_child = -1;
    }
    if (output_child >= 0) {
        close(output_child);
        output_child = -1;
    }
    close(errfd[1]);
    errfd[1] = -1;

    /* Deliver the stdin payload before the output is read. The spec-entry cap
     * on stdin_content_len keeps the payload within any POSIX-conformant pipe
     * buffer, so the write returns immediately even if the child has not yet
     * reached its consuming read. EPIPE (child exec failed or exited before
     * reading) is benign — the exec-errno drain and wait-status decode below
     * surface the real cause. */
    if (stdin_parent >= 0) {
        if (spec->stdin_content_len > 0) {
            process_write(stdin_parent, spec->stdin_content, spec->stdin_content_len);
        }
        close(stdin_parent);
        stdin_parent = -1;
    }

    /* The limit's deadline, monotonic (process_deadline), or none */
    struct timespec limit = process_deadline(spec->timeout_seconds);
    const struct timespec *deadline = spec->timeout_seconds > 0 ? &limit : NULL;

    /* A pipe is read to its end before its child is reaped, so a task the child
     * leaves holding it holds the wait; every other policy waits on the child
     * alone (process_output_t). */
    if (spec->output_policy == PROCESS_OUTPUT_CAPTURE ||
        spec->output_policy == PROCESS_OUTPUT_STREAM) {
        err = process_drain(spec, output_parent, deadline, &capture, &result->timed_out);
        if (err) goto cleanup;
    }

    /* The reap, by the deadline the drain did not meet: a child that closed its
     * output and runs on (`exec >&-; sleep 9999`) is waited on here, as is every
     * child whose output is no pipe */
    if (!result->timed_out) {
        pid_t reaped = process_reap(pid, deadline, &status);
        if (reaped < 0) {
            err = error_errno(errno, "Failed to wait for '%s'", program);
            goto cleanup;
        }
        result->timed_out = reaped == 0;
    }

    /* A child its limit outlived, ended (process_kill) */
    if (result->timed_out && !process_kill(pid, kill_target, &status)) {
        err = error_create(
            ERR_FS, "Failed to kill '%s' (pid %d), which outlived its time limit",
            program, (int) pid
        );
        goto cleanup;
    }
    pid = -1;

    /* The child reaped, reported (process_report) */
    process_report(errfd[0], status, result);

    /* A file's output, read once its child is reaped (process_read_file) */
    if (spec->output_policy == PROCESS_OUTPUT_FILE) {
        err = process_read_file(spec, output_parent, &capture);
        if (err) goto cleanup;
    }

    /* The capture handed to the result — none where the policy keeps none — and
     * wiped at its deinit (process_result_deinit) */
    result->output = capture.bytes;
    result->output_len = capture.len;
    result->output_dropped = capture.dropped;
    capture.bytes = NULL;

cleanup:
    /* Stop the async signal handler from chasing this pgid before the synchronous
     * orphan reap below fires its own kill(). Two scopes, one source of truth:
     * the global is for the handler; kill_target is for in-function cleanup.
     * Pre-fork failure paths write 0-over-0 — harmless. */
    active_child_pgid = 0;

    if (stdin_parent >= 0) close(stdin_parent);
    if (stdin_child >= 0) close(stdin_child);
    if (output_parent >= 0) close(output_parent);
    if (output_child >= 0) close(output_child);
    if (errfd[0] >= 0) close(errfd[0]);
    if (errfd[1] >= 0) close(errfd[1]);

    /* Reap any stray child. We get here with pid > 0 only if a mid-execution
     * failure prevented the normal wait paths from running. Best-effort; if it
     * does not die in the orphan window, the kernel reaps when dotta exits. */
    if (pid > 0) {
        (void) kill(kill_target, SIGKILL);
        struct timespec grace = process_deadline(PROCESS_GRACE_ORPHAN_SECONDS);
        (void) process_reap(pid, &grace, &status);
    }

    /* The capture, where ownership was not transferred (process_capture_deinit) */
    process_capture_deinit(&capture);

    return err;
}

void process_result_deinit(process_result_t *result) {
    if (!result) {
        return;
    }
    secure_wipe(result->output, result->output_len);
    free(result->output);
    *result = (process_result_t) { 0 };
}

error_t process_foreground(char *const argv[], process_result_t *result) {
    CHECK_NULL(argv);
    CHECK_NULL(argv[0]);
    CHECK_NULL(result);

    *result = (process_result_t) { 0 };

    /* The exec's errno comes back over a self-pipe the exec closes, so a program
     * that could not be run is told from one that exited 127. */
    int errfd[2] = { -1, -1 };
    error_t err = process_pipe(errfd, argv[0]);
    if (err) return err;

    /* The keyboard's signals held across the fork, until the parent ignores them
     * below: a Ctrl-C in between is neither dotta's death nor lost to the child,
     * which clears its mask before exec and hears the terminal's own. */
    sigset_t keyboard, before;
    sigemptyset(&keyboard);
    sigaddset(&keyboard, SIGINT);
    sigaddset(&keyboard, SIGQUIT);
    (void) sigprocmask(SIG_BLOCK, &keyboard, &before);

    pid_t pid = fork();
    if (pid < 0) {
        err = error_errno(errno, "Failed to fork '%s'", argv[0]);
        (void) sigprocmask(SIG_SETMASK, &before, NULL);
        close(errfd[0]);
        close(errfd[1]);
        return err;
    }

    if (pid == 0) {
        /* ───── Child ─────────────────────────────────────────────
         *
         * As process_run's: no error_t / no malloc until exec, and a failure
         * writes its errno to the self-pipe and exits (process_child_fail). */
        close(errfd[0]);
        process_child_signals();

        /* The invoker's child, for good (sys/identity), before the exec. */
        if (identity_drop_child() != 0) process_child_fail(errfd[1], 126);

        execvp(argv[0], argv);
        process_child_fail(errfd[1], 127);
    }

    /* ───── Parent ──────────────────────────────────────────────── */

    /* The keyboard's signals are the child's until it is reaped (the header):
     * ignored here, and a pending one discarded with the ignore — it reached
     * the child too. */
    struct sigaction ignore = { 0 };
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    struct sigaction saved_int, saved_quit;
    (void) sigaction(SIGINT, &ignore, &saved_int);
    (void) sigaction(SIGQUIT, &ignore, &saved_quit);
    (void) sigprocmask(SIG_SETMASK, &before, NULL);

    /* The child's end closed: the exec, or the child's exit, closes the last. */
    close(errfd[1]);

    /* Reaped whatever it is doing, however long it takes: no timeout, for the
     * user is driving it. */
    int status = 0;
    if (process_reap(pid, NULL, &status) < 0) {
        err = error_errno(errno, "Failed to wait for '%s'", argv[0]);
    }

    /* dotta's own answer to the keyboard back, the child gone. */
    (void) sigaction(SIGINT, &saved_int, NULL);
    (void) sigaction(SIGQUIT, &saved_quit, NULL);

    /* Reported as process_run reports its child, once reaped (process_report) */
    if (!err) process_report(errfd[0], status, result);
    close(errfd[0]);
    return err;
}
