/**
 * process.c - Unified subprocess primitive implementation
 *
 * Single linear procedure: validate spec → open pipes (output +
 * exec-errno) → fork → child sets up its environment and execs →
 * parent drains output with a monotonic-clock select() loop →
 * parent reaps the child (escalating SIGTERM→SIGKILL on timeout) →
 * parent decodes wait status into the result struct.
 *
 * One cleanup label handles all error paths. Every resource
 * (pipe fds, capture buffer, stray child) is initialized to a
 * sentinel so cleanup is unconditional and order-independent.
 */

#include "sys/process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"

/* Defined in main.c. See sys/process.h "Threading and signal model"
 * for the host-program contract. Updated only by process_run() —
 * read by main.c's signal_cleanup_handler to forward terminating
 * signals to a PROCESS_PGRP_NEW child's group before dotta dies. */
extern volatile sig_atomic_t active_child_pgid;

/* Initial capture buffer size; doubles on demand up to SIZE_MAX/2. */
#define PROCESS_CAPTURE_INITIAL 4096

/* Read chunk size for draining the child's output pipe. */
#define PROCESS_READ_CHUNK 4096

/* Cap for sysconf(_SC_OPEN_MAX) before the close-fds loop, so a
 * pathological RLIMIT_NOFILE doesn't cost millions of close()
 * syscalls in the child. */
#define PROCESS_FD_CAP 65536
#define PROCESS_FD_FALLBACK 1024

/* Polling cadence for the post-EOF and post-kill waitpid loops.
 * 50ms is a balance between wake-up latency and CPU burn. */
#define PROCESS_POLL_INTERVAL_NS (50L * 1000L * 1000L)

/* Grace periods for the timeout escalation. SIGTERM gets the longer
 * window; SIGKILL is essentially instantaneous but we still bound
 * the wait so a stuck reap doesn't block forever. */
#define PROCESS_GRACE_TERM_SECONDS 5
#define PROCESS_GRACE_KILL_SECONDS 3

/* Best-effort orphan reap window during cleanup. Short — if the
 * child won't die in this time, we abandon and let init reap. */
#define PROCESS_GRACE_ORPHAN_SECONDS 1

/**
 * Write all `n` bytes of `buf` to `fd`, retrying on partial writes
 * and EINTR. Returns the number of bytes written, or -1 if no
 * progress was made before a non-recoverable error.
 */
static ssize_t write_full(int fd, const void *buf, size_t n) {
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
 * Send `sig` to `kill_target` (a pid or negative pgid), then poll
 * waitpid(pid) for up to `grace_seconds`. On reap, *status is
 * filled and true is returned. On grace expiry or unrecoverable
 * waitpid error, false is returned.
 *
 * Used in three places: timeout-during-read, timeout-during-wait,
 * and orphan reap during cleanup. Single source of truth for the
 * SIGTERM/SIGKILL escalation.
 */
static bool process_kill_and_wait(
    pid_t pid,
    pid_t kill_target,
    int sig,
    int grace_seconds,
    int *status
) {
    /* kill() failure is non-fatal — the target may already be gone,
     * in which case waitpid() will tell us via reap or ECHILD. */
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
 * Set FD_CLOEXEC on a pipe pair, ignoring failures (the explicit
 * close-loop in the child still handles fd cleanup; CLOEXEC is
 * defense-in-depth for any future code path that doesn't follow
 * the close-loop discipline).
 */
static void set_pipe_cloexec(int fds[2]) {
    (void) fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void) fcntl(fds[1], F_SETFD, FD_CLOEXEC);
}

/**
 * Compute remaining seconds until deadline. Returns 0 if the
 * deadline has passed. Returns -1 if no timeout is set.
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
 * Grow the capture buffer to fit `needed` bytes. Returns NULL on
 * allocation failure or arithmetic overflow; otherwise returns the
 * (possibly reallocated) buffer and updates *capacity_inout.
 */
static char *capture_grow(char *buf, size_t needed, size_t *capacity_inout) {
    size_t cap = *capacity_inout;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) {
            return NULL;
        }
        cap *= 2;
    }
    char *grown = realloc(buf, cap);
    if (!grown) {
        return NULL;
    }
    *capacity_inout = cap;
    return grown;
}

error_t *process_run(const process_spec_t *spec, process_result_t *result) {
    CHECK_NULL(spec);
    CHECK_NULL(result);
    CHECK_NULL(spec->argv);
    CHECK_NULL(spec->envp);

    if (spec->argv[0] == NULL || spec->argv[0][0] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "process_spec.argv[0] must be a non-empty path"
        );
    }
    if (spec->timeout_seconds < 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "process_spec.timeout_seconds must be >= 0 (got %d)",
            spec->timeout_seconds
        );
    }

    /* stdin_content / stdin_content_len are load-bearing only for
     * BUFFER; any stray setting under INHERIT/DEVNULL means the caller
     * expected a stdin payload that will not be delivered. Reject
     * rather than silently ignore. */
    if (spec->stdin_policy == PROCESS_STDIN_BUFFER) {
        if (spec->stdin_content_len > 0 && !spec->stdin_content) {
            return ERROR(
                ERR_INVALID_ARG,
                "stdin_content_len > 0 but stdin_content is NULL"
            );
        }
        if (spec->stdin_content_len > PROCESS_STDIN_BUFFER_MAX) {
            return ERROR(
                ERR_INVALID_ARG,
                "stdin_content_len %zu exceeds PROCESS_STDIN_BUFFER_MAX (%d)",
                spec->stdin_content_len, PROCESS_STDIN_BUFFER_MAX
            );
        }
    } else if (spec->stdin_content != NULL || spec->stdin_content_len > 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "stdin_content set but stdin_policy is not PROCESS_STDIN_BUFFER"
        );
    }

    /* Zero result so every path through cleanup leaves callers with
     * a well-defined struct. */
    *result = (process_result_t) { 0 };

    /* All resources initialized to safe sentinels. */
    int pipefd[2] = { -1, -1 };
    int errfd[2] = { -1, -1 };
    int stdin_pipe[2] = { -1, -1 };
    pid_t pid = -1;
    pid_t kill_target = -1;
    char *capture = NULL;
    size_t cap_len = 0;
    size_t cap_capacity = 0;
    int status = 0;
    bool timed_out = false;
    error_t *err = NULL;

    /* Output pipe (child stdout/stderr → parent). */
    if (pipe(pipefd) != 0) {
        return ERROR(
            ERR_FS, "Failed to create output pipe: %s",
            strerror(errno)
        );
    }
    set_pipe_cloexec(pipefd);

    /* Exec-errno self-pipe (child writes errno+_exit on exec failure;
     * on exec success, FD_CLOEXEC closes the write end and parent
     * reads EOF). */
    if (pipe(errfd) != 0) {
        err = ERROR(
            ERR_FS, "Failed to create exec-errno pipe: %s",
            strerror(errno)
        );
        goto cleanup;
    }
    set_pipe_cloexec(errfd);

    /* Stdin payload pipe (parent writes spec->stdin_content; child
     * reads from its stdin). Only created for BUFFER policy. */
    if (spec->stdin_policy == PROCESS_STDIN_BUFFER) {
        if (pipe(stdin_pipe) != 0) {
            err = ERROR(
                ERR_FS, "Failed to create stdin pipe: %s",
                strerror(errno)
            );
            goto cleanup;
        }
        set_pipe_cloexec(stdin_pipe);
    }

    /* Pre-allocate capture buffer if requested. Failure here is
     * surfaced as ERR_MEMORY rather than silently degrading. */
    if (spec->capture) {
        cap_capacity = PROCESS_CAPTURE_INITIAL;
        capture = malloc(cap_capacity);
        if (!capture) {
            err = ERROR(ERR_MEMORY, "Failed to allocate capture buffer");
            goto cleanup;
        }
    }

    pid = fork();
    if (pid < 0) {
        err = ERROR(ERR_FS, "Failed to fork: %s", strerror(errno));
        goto cleanup;
    }

    if (pid == 0) {
        /* ───── Child ─────────────────────────────────────────────
         *
         * From this point until execve(), no error_t / no malloc /
         * no goto-cleanup. Failures write errno to errfd[1] (which
         * the parent drains after our exit) and _exit(126|127).
         */

        /* Reset signal disposition so parent's SIGINT handler does
         * not run between fork and exec. execve() itself resets
         * non-ignored handlers to SIG_DFL, but we reset early to
         * cover the fork→exec window. */
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGALRM, SIG_DFL);
        sigset_t empty;
        sigemptyset(&empty);
        (void) sigprocmask(SIG_SETMASK, &empty, NULL);

        /* Belt-and-suspenders: cancel any inherited alarm. */
        alarm(0);

        if (spec->pgrp_policy == PROCESS_PGRP_NEW) {
            (void) setpgid(0, 0);
        }

        close(pipefd[0]);
        close(errfd[0]);

        if (spec->stdin_policy == PROCESS_STDIN_DEVNULL) {
            int dn = open("/dev/null", O_RDONLY);
            if (dn >= 0) {
                if (dn != STDIN_FILENO) {
                    (void) dup2(dn, STDIN_FILENO);
                    close(dn);
                }
                /* If dn == STDIN_FILENO (parent had stdin closed), it is
                 * already in the right slot — leave it open. */
            }
            /* If open failed, child inherits whatever stdin parent had.
             * No clean way to report from the child here; the worst case
             * is the script blocks on a terminal read and we time out. */
        } else if (spec->stdin_policy == PROCESS_STDIN_BUFFER) {
            /* Parent holds the write end; close it so the child cannot
             * see its own stdin source as writable. */
            close(stdin_pipe[1]);
            if (stdin_pipe[0] != STDIN_FILENO) {
                if (dup2(stdin_pipe[0], STDIN_FILENO) < 0) {
                    int e = errno;
                    (void) write_full(errfd[1], &e, sizeof(e));
                    _exit(126);
                }
                close(stdin_pipe[0]);
            }
            /* If stdin_pipe[0] == STDIN_FILENO already (parent's stdin was
             * closed pre-fork), it is in the right slot — leave it open.
             * The explicit closes above make stdin_pipe[0]/[1] invisible
             * to the close-fds loop below. */
        }

        if (dup2(pipefd[1], STDOUT_FILENO) < 0
            || dup2(pipefd[1], STDERR_FILENO) < 0) {
            int e = errno;
            (void) write_full(errfd[1], &e, sizeof(e));
            _exit(126);
        }
        close(pipefd[1]);

        /* Close every other inherited fd so libgit2/SQLite handles do
         * not leak into the script. errfd[1] must survive — it carries
         * any exec-failure errno back to the parent. */
        long maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0 || maxfd > PROCESS_FD_CAP) {
            maxfd = PROCESS_FD_FALLBACK;
        }
        for (int fd = STDERR_FILENO + 1; fd < (int) maxfd; fd++) {
            if (fd != errfd[1]) {
                close(fd);
            }
        }

        if (spec->work_dir) {
            if (chdir(spec->work_dir) != 0) {
                if (!spec->work_dir_fallback || chdir(spec->work_dir_fallback) != 0) {
                    int e = errno;
                    (void) write_full(errfd[1], &e, sizeof(e));
                    _exit(126);
                }
            }
        }

        execve(spec->argv[0], spec->argv, spec->envp);

        /* execve only returns on failure. */
        {
            int e = errno;
            (void) write_full(errfd[1], &e, sizeof(e));
        }
        _exit(127);
    }

    /* ───── Parent ──────────────────────────────────────────────── */

    /* Race-mitigate: ensure the child's pgrp is set even if it has
     * not yet executed setpgid(0,0) itself. setpgid() is idempotent
     * with respect to the (pid,pid) target; EACCES (child already
     * exec'd) is acceptable because the child's own setpgid ran
     * before exec. */
    if (spec->pgrp_policy == PROCESS_PGRP_NEW) {
        /* Publish before our own setpgid so the signal handler can
         * forward to the child group during the sub-window where
         * the child has setpgid'd but the parent has not. If neither
         * side has called setpgid yet, the pgrp does not exist and
         * kill(-pid) returns ESRCH — benign. */
        active_child_pgid = (sig_atomic_t) pid;
        (void) setpgid(pid, pid);
        kill_target = -pid;
    } else {
        kill_target = pid;
    }

    /* Close the child's ends of both pipes. */
    close(pipefd[1]);
    pipefd[1] = -1;
    close(errfd[1]);
    errfd[1] = -1;

    /* Deliver the stdin payload before entering the capture loop. The
     * spec-entry cap on stdin_content_len keeps the payload within any
     * POSIX-conformant pipe buffer, so the write returns immediately
     * even if the child has not yet reached its consuming read. EPIPE
     * (child exec failed or exited before reading) is benign — the
     * exec-errno drain and wait-status decode below surface the real
     * cause. */
    if (spec->stdin_policy == PROCESS_STDIN_BUFFER) {
        close(stdin_pipe[0]);
        stdin_pipe[0] = -1;
        if (spec->stdin_content_len > 0) {
            (void) write_full(
                stdin_pipe[1], spec->stdin_content, spec->stdin_content_len
            );
        }
        close(stdin_pipe[1]);
        stdin_pipe[1] = -1;
    }

    /* Non-blocking output pipe so the select+read loop never blocks
     * past the timeout. */
    {
        int flags = fcntl(pipefd[0], F_GETFL, 0);
        if (flags >= 0) {
            (void) fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
        }
    }

    /* Monotonic deadline. Immune to wall-clock jumps. */
    struct timespec start = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &start);

    char buf[PROCESS_READ_CHUNK];
    bool got_eof = false;
    bool stream_broken = false;

    while (!got_eof) {
        long remaining = process_remaining(&start, spec->timeout_seconds);
        if (spec->timeout_seconds > 0 && remaining == 0) {
            timed_out = true;
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pipefd[0], &rfds);

        struct timeval tv;
        struct timeval *tvp = NULL;
        if (remaining >= 0) {
            tv.tv_sec = remaining;
            tv.tv_usec = 0;
            tvp = &tv;
        }

        int rs = select(pipefd[0] + 1, &rfds, NULL, NULL, tvp);
        if (rs < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = ERROR(ERR_FS, "select on child pipe: %s", strerror(errno));
            goto cleanup;
        }
        if (rs == 0) {
            /* select timed out; loop iteration will reassess remaining. */
            continue;
        }

        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            err = ERROR(ERR_FS, "read child pipe: %s", strerror(errno));
            goto cleanup;
        }
        if (n == 0) {
            got_eof = true;
            break;
        }

        if (spec->capture) {
            size_t need = cap_len + (size_t) n + 1;
            if (need < cap_len) {
                err = ERROR(ERR_MEMORY, "Capture buffer size overflow");
                goto cleanup;
            }
            if (need > cap_capacity) {
                char *grown = capture_grow(capture, need, &cap_capacity);
                if (!grown) {
                    err = ERROR(
                        ERR_MEMORY,
                        "Failed to grow capture buffer (need %zu bytes)",
                        need
                    );
                    goto cleanup;
                }
                capture = grown;
            }
            memcpy(capture + cap_len, buf, (size_t) n);
            cap_len += (size_t) n;
        }

        if (spec->stream_fd >= 0 && !stream_broken) {
            ssize_t w = write_full(spec->stream_fd, buf, (size_t) n);
            if (w < 0) {
                /* Sink is broken (likely EPIPE because the consumer
                 * closed its end). Drop further chunks but keep
                 * draining so the child can finish naturally rather
                 * than blocking on a full pipe. */
                stream_broken = true;
            }
        }
    }

    if (spec->capture && capture) {
        capture[cap_len] = '\0';
    }

    /* Drain the exec-errno channel: 0 bytes (EOF) means execve
     * succeeded and FD_CLOEXEC closed the write end; sizeof(int)
     * bytes means the child wrote an errno before _exit. */
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

    if (timed_out) {
        if (!process_kill_and_wait(
            pid, kill_target, SIGTERM, PROCESS_GRACE_TERM_SECONDS, &status
            )) {
            if (!process_kill_and_wait(
                pid, kill_target, SIGKILL, PROCESS_GRACE_KILL_SECONDS, &status
                )) {
                err = ERROR(
                    ERR_FS, "Child PID %d failed to terminate after SIGKILL",
                    (int) pid
                );
                goto cleanup;
            }
        }
        pid = -1;
    } else {
        /* Pipe drained (got_eof). Child usually exits in the same
         * instant; the loop's first WNOHANG catches that. The 50ms
         * polling fallback handles "child closed stdout but kept
         * running" (e.g., `exec >&-; sleep 9999`). */
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
                err = ERROR(ERR_FS, "waitpid: %s", strerror(errno));
                goto cleanup;
            }

            long remaining = process_remaining(&start, spec->timeout_seconds);
            if (spec->timeout_seconds > 0 && remaining == 0) {
                timed_out = true;
                if (!process_kill_and_wait(
                    pid, kill_target, SIGTERM,
                    PROCESS_GRACE_TERM_SECONDS, &status
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

    /* Decode wait status. exec_failed (already set from the errno
     * pipe) is independent — exit_code reflects what the wait
     * returned (typically 126/127 for our child-side _exit), which
     * is still useful information for the caller. */
    result->timed_out = timed_out;
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
        result->signal_num = 0;
    } else if (WIFSIGNALED(status)) {
        result->signal_num = WTERMSIG(status);
        result->exit_code = 128 + result->signal_num;
    } else {
        /* WIFSTOPPED or other unexpected wait state — should not
         * occur because we do not pass WUNTRACED. Map to a generic
         * failure so callers do not see uninitialized fields. */
        result->exit_code = 1;
        result->signal_num = 0;
    }

    /* Transfer capture ownership into the result. */
    if (spec->capture) {
        result->output = capture;
        result->output_len = cap_len;
        capture = NULL;
    }

cleanup:
    /* Stop the async signal handler from chasing this pgid before
     * the synchronous orphan reap below fires its own kill(). Two
     * scopes, one source of truth: the global is for the handler;
     * kill_target is for in-function cleanup. Pre-fork failure paths
     * write 0-over-0 — harmless. */
    active_child_pgid = 0;

    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    if (errfd[0] >= 0) close(errfd[0]);
    if (errfd[1] >= 0) close(errfd[1]);
    if (stdin_pipe[0] >= 0) close(stdin_pipe[0]);
    if (stdin_pipe[1] >= 0) close(stdin_pipe[1]);

    /* Reap any stray child. We get here with pid > 0 only if a
     * mid-execution failure prevented the normal wait paths from
     * running. Best-effort; if it does not die in the orphan
     * window, the kernel reaps when dotta exits. */
    if (pid > 0) {
        (void) process_kill_and_wait(
            pid, kill_target, SIGKILL,
            PROCESS_GRACE_ORPHAN_SECONDS, &status
        );
    }

    /* Free capture buffer only if ownership was not transferred. */
    free(capture);

    return err;
}

void process_result_dispose(process_result_t *result) {
    if (!result) {
        return;
    }
    free(result->output);
    *result = (process_result_t) { 0 };
}
