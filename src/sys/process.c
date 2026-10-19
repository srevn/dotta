/**
 * process.c - Unified subprocess primitive implementation
 *
 * Single linear procedure: validate spec → open the child's stdin
 * (process_stdin_open) and pipes (output + exec-errno) → fork → the child sets
 * up its environment and execs (process_child) → the parent drains output with
 * a monotonic-clock select() loop (process_drain), keeping what a capture asks
 * for (process_capture_t) → parent reaps the child (escalating SIGTERM→SIGKILL
 * on timeout) → parent decodes wait status into the result struct.
 *
 * One cleanup label handles all error paths. Every resource (pipe fds, capture
 * buffer, stray child) is initialized to a sentinel so cleanup is unconditional
 * and order-independent.
 */

#include "sys/process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/heap.h"
#include "base/secure.h"
#include "sys/identity.h"

/* Initial capture buffer size; doubles on demand up to the bound
 * (PROCESS_CAPTURE_MAX, and its NUL). */
#define PROCESS_CAPTURE_INITIAL 4096

/* Read chunk size for draining the child's output pipe. */
#define PROCESS_READ_CHUNK 4096

/* Cap for sysconf(_SC_OPEN_MAX) before the close-fds loop, so a pathological
 * RLIMIT_NOFILE doesn't cost millions of close() syscalls in the child. */
#define PROCESS_FD_CAP 65536
#define PROCESS_FD_FALLBACK 1024

/* Polling cadence for the post-EOF and post-kill waitpid loops. 50ms is a balance
 * between wake-up latency and CPU burn. */
#define PROCESS_POLL_INTERVAL_NS (50L * 1000L * 1000L)

/* Grace periods for the timeout escalation. SIGTERM gets the longer window; SIGKILL
 * is essentially instantaneous but we still bound the wait so a stuck reap doesn't
 * block forever. */
#define PROCESS_GRACE_TERM_SECONDS 5
#define PROCESS_GRACE_KILL_SECONDS 3

/* Best-effort orphan reap window during cleanup. Short — if the child won't die
 * in this time, we abandon and let init reap. */
#define PROCESS_GRACE_ORPHAN_SECONDS 1

/* The pgid of the PROCESS_PGRP_NEW child process_run() is running, zero otherwise:
 * published before the parent's own setpgid and cleared on every exit path below.
 * The host program's terminating-signal handler reads it through the declaration
 * in process.h and forwards the signal to the group, so a Ctrl+C kills dotta
 * and the spawned hook atomically rather than orphaning the hook.
 * PROCESS_PGRP_SHARED children leave it at zero — the kernel already delivers
 * terminal signals to the whole foreground group. */
volatile sig_atomic_t active_child_pgid = 0;

/**
 * Write all `n` bytes of `buf` to `fd`, retrying on partial writes and EINTR.
 * Returns the number of bytes written, or -1 if no progress was made before a
 * non-recoverable error.
 */
static ssize_t process_write(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t total = 0;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return total > 0 ? (ssize_t) total : -1;
        }
        p += w;
        total += (size_t) w;
        n -= (size_t) w;
    }
    return (ssize_t) total;
}

/**
 * Send `sig` to `kill_target` (a pid or negative pgid), then poll waitpid(pid)
 * for up to `grace_seconds`. On reap, *status is filled and true is returned.
 * On grace expiry or unrecoverable waitpid error, false is returned.
 *
 * Used in three places: timeout-during-read, timeout-during-wait, and orphan
 * reap during cleanup. Single source of truth for the SIGTERM/SIGKILL escalation.
 */
static bool process_kill_and_wait(
    pid_t pid,
    pid_t kill_target,
    int sig,
    int grace_seconds,
    int *status
) {
    /* kill() failure is non-fatal — the target may already be gone, in which
     * case waitpid() will tell us via reap or ECHILD. */
    (void) kill(kill_target, sig);

    struct timespec start = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &start);

    for ( ; ;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) {
            return true;
        }
        if (r < 0 && errno != EINTR) {
            return false;
        }

        struct timespec now = { 0, 0 };
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= (time_t) grace_seconds) {
            return false;
        }

        struct timespec delay = { 0, PROCESS_POLL_INTERVAL_NS };
        (void) nanosleep(&delay, NULL);
    }
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
 * A child's signals, made its own before exec — both primitives' children
 *
 * No handler of the parent's runs between fork and exec: execve() resets a caught
 * signal to SIG_DFL itself, and this covers the window before it the way execve()
 * would — a terminating signal the parent catches goes back to its default, and
 * one it inherited ignored stays ignored. SIGPIPE is dotta's own ignore (main.c),
 * never the child's; SIGALRM goes back too, and the mask is cleared — the
 * foreground child's parent blocks the keyboard's signals across the fork
 * (process_foreground). Called in the child alone: no error_t, no malloc.
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
    signal(SIGALRM, SIG_DFL);

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
    (void) process_write(errfd, &e, sizeof(e));
    _exit(code);
}

/**
 * The child, from the fork to its exec: its signals and its group, the invoker's
 * identity, its stdin and its output, every other descriptor closed, its working
 * directory — then the exec
 *
 * `in` is what the stdin policy opened for the child, -1 for dotta's own
 * (process_stdin_open), `out` the output pipe's write end, `errfd` the exec's
 * pipe's: each above 2 (main.c), so no dup2 here overwrites another's source.
 * No error_t, no malloc, no return: a failure is its errno over the exec's pipe
 * (process_child_fail).
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

    /* Close every other inherited fd: the pipes' other ends — so the child never
     * holds its own stdin's write end — and libgit2's and SQLite's handles, which
     * must not leak into the script. errfd must survive — it carries any
     * exec-failure errno back to the parent. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > PROCESS_FD_CAP) {
        maxfd = PROCESS_FD_FALLBACK;
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
 * Compute remaining seconds until deadline. Returns 0 if the deadline has passed.
 * Returns -1 if no timeout is set.
 */
static long process_remaining(
    const struct timespec *start,
    int timeout_seconds
) {
    if (timeout_seconds <= 0) {
        return -1;
    }
    struct timespec now = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed = (long) (now.tv_sec - start->tv_sec);
    long remaining = (long) timeout_seconds - elapsed;
    return remaining < 0 ? 0 : remaining;
}

/**
 * What a capture keeps of the child's output: its first PROCESS_CAPTURE_MAX bytes,
 * terminated, and the count of the rest. A secure capture holds a secret (a
 * credential helper's response): every buffer that held a byte of it is wiped
 * before the allocator has it back.
 */
typedef struct {
    char *bytes;                  /* the kept bytes, NUL-terminated */
    size_t len;                   /* bytes kept, the NUL not counted */
    size_t capacity;              /* bytes' allocation, the NUL's byte among it */
    size_t dropped;               /* bytes past the bound, drained and not kept */
    bool secure;                  /* every allocation wiped before its free */
} process_capture_t;

/* A capture's first buffer, PROCESS_CAPTURE_INITIAL bytes, empty and terminated */
static void process_capture_init(process_capture_t *capture, bool secure) {
    *capture = (process_capture_t) {
        .bytes = heap_alloc(PROCESS_CAPTURE_INITIAL),
        .capacity = PROCESS_CAPTURE_INITIAL,
        .secure = secure,
    };
    capture->bytes[0] = '\0';
}

/**
 * Keep a chunk of the child's output: as much of it as the bound has room for,
 * the rest counted — the child's volume never sizes the capture (the header).
 *
 * The buffer doubles to fit, never past the bound and its NUL, which no chunk
 * needs more than, so the doubling cannot overflow. A secure capture grows by
 * malloc → memcpy → wipe → free, the old allocation wiped whole: a realloc may
 * move the bytes and leave the old ones on the freelist unwiped. The cost is a
 * copy and a wipe per doubling, and a credential helper's response fits the first
 * buffer or one doubling of it.
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

        if (capture->secure) {
            char *grown = heap_alloc(capacity);
            memcpy(grown, capture->bytes, capture->len);
            secure_wipe(capture->bytes, capture->capacity);
            free(capture->bytes);
            capture->bytes = grown;
        } else {
            capture->bytes = heap_realloc(capture->bytes, capacity);
        }
        capture->capacity = capacity;
    }

    memcpy(capture->bytes + capture->len, chunk, keep);
    capture->len += keep;
    capture->bytes[capture->len] = '\0';
}

/* A capture never handed to the result, freed — wiped first where secure, so
 * partial-read bytes do not linger after a mid-capture failure */
static void process_capture_deinit(process_capture_t *capture) {
    if (capture->secure) secure_wipe(capture->bytes, capture->capacity);
    free(capture->bytes);
    *capture = (process_capture_t) { 0 };
}

/**
 * Read the child's output to the end of the pipe or to the limit, whichever comes
 * first — *timed_out says which. A capture keeps it (process_capture_add) and a
 * stream copies it to spec->stream_fd as it comes; kept or not, every chunk is
 * read, so a child past the bound never blocks on a full pipe and runs to its
 * own end.
 */
static error_t process_drain(
    const process_spec_t *spec, int fd, const struct timespec *start,
    process_capture_t *capture, bool *timed_out
) {
    char chunk[PROCESS_READ_CHUNK];
    bool stream_broken = false;
    error_t err = NULL;

    *timed_out = false;
    for (;;) {
        long remaining = process_remaining(start, spec->timeout_seconds);
        if (spec->timeout_seconds > 0 && remaining == 0) {
            *timed_out = true;
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        struct timeval *tvp = NULL;
        if (remaining >= 0) {
            tv.tv_sec = remaining;
            tv.tv_usec = 0;
            tvp = &tv;
        }

        int rs = select(fd + 1, &rfds, NULL, NULL, tvp);
        if (rs < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = error_errno(errno, "Failed to read the output of '%s'", spec->argv[0]);
            break;
        }
        if (rs == 0) {
            /* select timed out; loop iteration will reassess remaining. */
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

        if (spec->capture) {
            process_capture_add(capture, chunk, (size_t) n);
        }

        if (spec->stream_fd >= 0 && !stream_broken) {
            ssize_t w = process_write(spec->stream_fd, chunk, (size_t) n);
            if (w < 0) {
                /* Sink is broken (likely EPIPE because the consumer closed its
                 * end). Drop further chunks but keep draining so the child can
                 * finish naturally rather than blocking on a full pipe. */
                stream_broken = true;
            }
        }
    }

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
    int pipefd[2] = { -1, -1 };
    int errfd[2] = { -1, -1 };
    pid_t pid = -1;
    pid_t kill_target = -1;
    process_capture_t capture = { 0 };
    int status = 0;
    error_t err = NULL;

    /* The child's stdin, opened before the fork (process_stdin_open). */
    err = process_stdin_open(spec, &stdin_parent, &stdin_child);
    if (err) goto cleanup;

    /* Output pipe (child stdout/stderr → parent). */
    err = process_pipe(pipefd, program);
    if (err) goto cleanup;

    /* Exec-errno self-pipe (child writes errno+_exit on exec failure; on exec
     * success, FD_CLOEXEC closes the write end and parent reads EOF). */
    err = process_pipe(errfd, program);
    if (err) goto cleanup;

    /* The capture, made before the fork where one is asked for. */
    if (spec->capture) {
        process_capture_init(&capture, spec->secure_capture);
    }

    pid = fork();
    if (pid < 0) {
        err = error_errno(errno, "Failed to fork '%s'", program);
        goto cleanup;
    }

    if (pid == 0) {
        process_child(spec, stdin_child, pipefd[1], errfd[1]);
    }

    /* ───── Parent ──────────────────────────────────────────────── */

    /* Race-mitigate: ensure the child's pgrp is set even if it has not yet executed
     * setpgid(0,0) itself. setpgid() is idempotent with respect to the (pid,pid)
     * target; EACCES (child already exec'd) is acceptable because the child's
     * own setpgid ran before exec. */
    if (spec->pgrp_policy == PROCESS_PGRP_NEW) {
        /* Publish before our own setpgid so the signal handler can forward to
         * the child group during the sub-window where the child has setpgid'd
         * but the parent has not. If neither side has called setpgid yet, the
         * pgrp does not exist and kill(-pid) returns ESRCH — benign. */
        active_child_pgid = (sig_atomic_t) pid;
        (void) setpgid(pid, pid);
        kill_target = -pid;
    } else {
        kill_target = pid;
    }

    /* Close the child's ends: its stdin's, and both pipes'. */
    if (stdin_child >= 0) {
        close(stdin_child);
        stdin_child = -1;
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    close(errfd[1]);
    errfd[1] = -1;

    /* Deliver the stdin payload before entering the capture loop. The spec-entry
     * cap on stdin_content_len keeps the payload within any POSIX-conformant
     * pipe buffer, so the write returns immediately even if the child has not
     * yet reached its consuming read. EPIPE (child exec failed or exited before
     * reading) is benign — the exec-errno drain and wait-status decode below
     * surface the real cause. */
    if (stdin_parent >= 0) {
        if (spec->stdin_content_len > 0) {
            (void) process_write(
                stdin_parent, spec->stdin_content, spec->stdin_content_len
            );
        }
        close(stdin_parent);
        stdin_parent = -1;
    }

    /* Non-blocking output pipe so the select+read loop never blocks past the
     * timeout. */
    {
        int flags = fcntl(pipefd[0], F_GETFL, 0);
        if (flags >= 0) {
            (void) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
        }
    }

    /* Monotonic deadline. Immune to wall-clock jumps. */
    struct timespec start = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &start);

    err = process_drain(spec, pipefd[0], &start, &capture, &result->timed_out);
    if (err) goto cleanup;

    /* Drain the exec-errno channel: 0 bytes (EOF) means execve succeeded and
     * FD_CLOEXEC closed the write end; sizeof(int) bytes means the child wrote
     * an errno before _exit. */
    {
        int e_buf = 0;
        ssize_t er = read(errfd[0], &e_buf, sizeof(e_buf));
        if (er == (ssize_t) sizeof(e_buf)) {
            result->exec_failed = true;
            result->exec_errno = e_buf;
        }
    }

    close(pipefd[0]);
    pipefd[0] = -1;
    close(errfd[0]);
    errfd[0] = -1;

    if (result->timed_out) {
        if (!process_kill_and_wait(
            pid, kill_target, SIGTERM, PROCESS_GRACE_TERM_SECONDS, &status
            )) {
            if (!process_kill_and_wait(
                pid, kill_target, SIGKILL, PROCESS_GRACE_KILL_SECONDS, &status
                )) {
                err = error_create(
                    ERR_FS, "Failed to kill '%s' (pid %d), which outlived its "
                    "time limit", program, (int) pid
                );
                goto cleanup;
            }
        }
        pid = -1;
    } else {
        /* Pipe drained (read returned 0). Child usually exits in the same instant;
         * the loop's first WNOHANG catches that. The 50ms polling fallback handles
         * "child closed stdout but kept running" (e.g., `exec >&-; sleep 9999`). */
        for ( ; ;) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) {
                pid = -1;
                break;
            }
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                err = error_errno(errno, "Failed to wait for '%s'", program);
                goto cleanup;
            }

            long remaining = process_remaining(&start, spec->timeout_seconds);
            if (spec->timeout_seconds > 0 && remaining == 0) {
                result->timed_out = true;
                if (!process_kill_and_wait(
                    pid, kill_target, SIGTERM, PROCESS_GRACE_TERM_SECONDS, &status
                    )) {
                    (void) process_kill_and_wait(
                        pid, kill_target, SIGKILL,
                        PROCESS_GRACE_KILL_SECONDS, &status
                    );
                }
                pid = -1;
                break;
            }

            struct timespec delay = { 0, PROCESS_POLL_INTERVAL_NS };
            (void) nanosleep(&delay, NULL);
        }
    }

    /* Decode wait status. exec_failed (already set from the errno pipe) is
     * independent — exit_code reflects what the wait returned (typically 126/127
     * for our child-side _exit), which is still useful information for the
     * caller. */
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
        result->signal_num = 0;
    } else if (WIFSIGNALED(status)) {
        result->signal_num = WTERMSIG(status);
        result->exit_code = 128 + result->signal_num;
    } else {
        /* WIFSTOPPED or other unexpected wait state — should not occur because
         * we do not pass WUNTRACED. Map to a generic failure so callers do not
         * see uninitialized fields. */
        result->exit_code = 1;
        result->signal_num = 0;
    }

    /* Transfer capture ownership into the result. The secure flag mirrors the
     * capture's so process_result_deinit can scrub before free without re-deriving
     * intent. */
    if (spec->capture) {
        result->output = capture.bytes;
        result->output_len = capture.len;
        result->output_dropped = capture.dropped;
        result->secure = capture.secure;
        capture.bytes = NULL;
    }

cleanup:
    /* Stop the async signal handler from chasing this pgid before the synchronous
     * orphan reap below fires its own kill(). Two scopes, one source of truth:
     * the global is for the handler; kill_target is for in-function cleanup.
     * Pre-fork failure paths write 0-over-0 — harmless. */
    active_child_pgid = 0;

    if (stdin_parent >= 0) close(stdin_parent);
    if (stdin_child >= 0) close(stdin_child);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    if (errfd[0] >= 0) close(errfd[0]);
    if (errfd[1] >= 0) close(errfd[1]);

    /* Reap any stray child. We get here with pid > 0 only if a mid-execution
     * failure prevented the normal wait paths from running. Best-effort; if it
     * does not die in the orphan window, the kernel reaps when dotta exits. */
    if (pid > 0) {
        (void) process_kill_and_wait(
            pid, kill_target, SIGKILL,
            PROCESS_GRACE_ORPHAN_SECONDS, &status
        );
    }

    /* The capture, where ownership was not transferred (process_capture_deinit) */
    process_capture_deinit(&capture);

    return err;
}

void process_result_deinit(process_result_t *result) {
    if (!result) {
        return;
    }
    if (result->secure && result->output) {
        secure_wipe(result->output, result->output_len);
    }
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

    /* End of file at the exec, the child's errno where it could not run. */
    close(errfd[1]);
    int exec_errno = 0;
    ssize_t got;
    do {
        got = read(errfd[0], &exec_errno, sizeof(exec_errno));
    } while (got < 0 && errno == EINTR);
    close(errfd[0]);

    /* Reaped whatever it is doing, however long it takes: no timeout, for the
     * user is driving it. */
    int status = 0;
    pid_t reaped;
    do {
        reaped = waitpid(pid, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    int wait_errno = errno;

    /* dotta's own answer to the keyboard back, the child gone. */
    (void) sigaction(SIGINT, &saved_int, NULL);
    (void) sigaction(SIGQUIT, &saved_quit, NULL);

    if (reaped < 0) {
        return error_errno(wait_errno, "Failed to wait for '%s'", argv[0]);
    }

    /* The wait status decoded as process_run decodes it. */
    if (got == (ssize_t) sizeof(exec_errno)) {
        result->exec_failed = true;
        result->exec_errno = exec_errno;
    }
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->signal_num = WTERMSIG(status);
        result->exit_code = 128 + result->signal_num;
    } else {
        result->exit_code = 1;
    }

    return NULL;
}
