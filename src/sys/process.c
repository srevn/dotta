/**
 * process.c - A child: its program found as git finds one, and three ways to
 * wait for it: implementation
 *
 * Every child is made one way: its program found before anything is opened
 * (process_find), then spawned (process_spawn) — the exec's pipe, every stdio
 * stream flushed, the fork — and in the child its signals, the invoker's identity,
 * the setup its wait places it in, or none (process_setup_t), and the exec
 * (process_child, process_exec). The waits differ in what they open before the
 * spawn and how they wait after it.
 *
 * process_run is one linear procedure: validate spec → find the program → open
 * what the child reads and where it writes (process_stdin_open,
 * process_output_open) → spawn → the parent drains a pipe's output by poll() to
 * the limit's deadline (process_drain), keeping what a capture asks for
 * (process_capture_t) → parent reaps the child by the same deadline (process_reap),
 * escalating SIGTERM→SIGKILL where the limit came first (process_kill) → parent
 * reports the reaped child into the result struct (process_report), and reads a
 * file's output (process_read_file). One cleanup label handles all its error
 * paths. Every resource (descriptors, capture buffer, stray child) is initialized
 * to a sentinel so cleanup is unconditional and order-independent.
 *
 * process_foreground spawns a child placed nowhere, the keyboard's signals held
 * across the spawn and ignored until the child is reaped.
 *
 * process_start spawns a child placed on two pipes, reads the exec's pipe before
 * it answers (process_exec_errno), and hands its caller the pipes' other ends
 * (process_t); process_finish closes them and reaps it with no limit.
 */

#include "sys/process.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
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

/* The shell a file the kernel will not execute is handed to (process_exec), and
 * a command line's (process_shell): POSIX's, git's SHELL_PATH by default */
#define PROCESS_SHELL "/bin/sh"

/**
 * Write all `n` bytes of `buf` to `fd`, retrying on partial writes and EINTR,
 * until done or refused: 0, or -1 with errno. A started child's refusal is its
 * write's (process_write); every other caller's costs the bytes alone: a payload
 * whose child is gone, a copy whose reader went away (EPIPE, SIGPIPE ignored:
 * the header), a child's errno, whose exit code (126, 127) then reports the failure
 * alone.
 */
static int process_write_fd(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += w;
        n -= (size_t) w;
    }

    return 0;
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
 * End a child its limit outlived: SIGTERM, SIGKILL once the grace has passed.
 * True once reaped, its status in *status. The single source of the SIGTERM/SIGKILL
 * escalation. The child alone: what it started shares dotta's process group,
 * which no kill of dotta's may reach (the header).
 */
static bool process_kill(pid_t pid, int *status) {
    /* kill() failure is non-fatal — the target may already be gone, in which
     * case the reap tells. */
    (void) kill(pid, SIGTERM);
    struct timespec grace = process_deadline(PROCESS_GRACE_TERM_SECONDS);
    if (process_reap(pid, &grace, status) == pid) return true;

    (void) kill(pid, SIGKILL);
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
 * STREAM), a file's (FILE), /dev/null for the child alone (DEVNULL), neither
 * (INHERIT). Each -1 where the policy has none, and both on a refusal, which
 * names the program.
 */
static error_t process_output_open(
    const process_spec_t *spec, int *parent, int *child
) {
    *parent = -1;
    *child = -1;

    switch (spec->output_policy) {
        case PROCESS_OUTPUT_INHERIT:
            return NULL;

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
 * The exec's vector over argv's program, found as git finds one (the header):
 * PROCESS_SHELL, the program's path, then argv's arguments — from its second
 * element the program's own, its path its argv[0], and whole the shell's, for a
 * file the kernel will not execute (process_exec). NULL where no PATH entry holds
 * the program.
 *
 * One allocation, freed by the caller: the pointers, then room for the longest
 * path the lookup builds, each built in place; argv's strings borrowed. Called
 * before the fork, since the child allocates nothing.
 */
static char **process_find(char *const argv[]) {
    size_t argc = 0;
    while (argv[argc]) argc++;

    /* dotta's own PATH, never the child's, and where it is unset the system's
     * default, which git sets at its start (lib/git/exec-cmd.c setup_path) */
    const char *search_path = getenv("PATH");
    if (!search_path) search_path = _PATH_DEFPATH;

    const char *name = argv[0];
    size_t room = strlen(search_path) + strlen(name) + 2;
    char **shell_argv = heap_alloc((argc + 2) * sizeof(*shell_argv) + room);
    shell_argv[0] = PROCESS_SHELL;
    memcpy(shell_argv + 1, argv, (argc + 1) * sizeof(*shell_argv));

    /* A name holding a '/' is run as given */
    if (strchr(name, '/')) return shell_argv;

    /* Any other is the first "<entry>/<name>" along PATH, ':' apart, that is a
     * regular file its owner may execute — the mode's owner bit, never access(2)
     * (lib/git/run-command.c locate_in_PATH, is_executable). An empty entry is
     * the working directory, the name alone (POSIX), and so is an empty PATH,
     * as git's own reads: its exec path, a ':', then PATH (setup_path). */
    char *candidate = (char *) (shell_argv + argc + 2);
    for (const char *entry = search_path, *end;; entry = end + 1) {
        end = entry + strcspn(entry, ":");
        snprintf(
            candidate, room, "%.*s%s%s", (int) (end - entry), entry,
            end > entry ? "/" : "", name
        );

        struct stat st;
        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR)) {
            shell_argv[1] = candidate;
            return shell_argv;
        }

        if (*end == '\0') break;
    }

    free(shell_argv);
    return NULL;
}

/**
 * A child's signals, made its own before exec — every child's
 *
 * No handler of the parent's runs between fork and exec: execve() resets a caught
 * signal to SIG_DFL itself, and this covers the window before it the way execve()
 * would — a terminating signal the parent catches goes back to its default, and
 * one it inherited ignored stays ignored. SIGPIPE is dotta's own ignore (main.c),
 * never the child's, and the mask is cleared — process_foreground blocks the
 * keyboard's signals across its fork, and one that arrived since lands here, on
 * its default. Called in the child alone: no error_t, no malloc.
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
 * the exit — 126 for a step of the setup, 127 for the exec. Every child's.
 */
static _Noreturn void process_child_fail(int errfd, int code) {
    int e = errno;
    (void) process_write_fd(errfd, &e, sizeof(e));
    _exit(code);
}

/**
 * The child's exec, its last step: the program found, by its path, handed the
 * vector past the shell (process_find) — every child's. A failure is its errno
 * over the exec's pipe and the exit 127 (process_child_fail). No error_t, no
 * malloc, no return.
 */
static _Noreturn void process_exec(
    char *const shell_argv[], char *const envp[], int errfd
) {
    execve(shell_argv[1], shell_argv + 1, envp);

    /* A file the kernel will not execute — a script with no #! line — is read
     * by the shell, its path the shell's first argument, as git runs every command
     * (lib/git/run-command.c prepare_cmd, start_command). Where the shell cannot
     * run either, the file's own errno is the one reported. */
    if (errno == ENOEXEC) {
        execve(shell_argv[0], shell_argv, envp);
        errno = ENOEXEC;
    }
    process_child_fail(errfd, 127);
}

/**
 * Where a wait places its child (process_child): the descriptor each of its three
 * streams is set from, and the directory it enters
 *
 * Each descriptor is one its wait opened before the spawn — above 2 (main.c),
 * so no dup2 overwrites another's source — or -1 for dotta's own stream. A placed
 * child closes every other descriptor before its exec. A child placed nowhere
 * (NULL: process_foreground's) keeps every descriptor dotta holds and dotta's
 * working directory.
 */
typedef struct {
    int streams[3];                 /* stdin, stdout, stderr: from this, -1 for dotta's own */
    const char *work_dir;           /* NULL: dotta's own */
    const char *work_dir_fallback;  /* entered where work_dir is not; NULL: none */
} process_setup_t;

/**
 * The child, from the fork to its exec — every child's: its signals, the invoker's
 * identity, then where `setup` places it its three streams, every other descriptor
 * closed and its working directory (process_setup_t) — then the exec (process_exec)
 *
 * `shell_argv` is the exec's vector over the program found (process_find), `errfd`
 * the exec's pipe's write end. No error_t, no malloc, no return: a failure is
 * its errno over the exec's pipe (process_child_fail).
 */
static _Noreturn void process_child(
    char *const shell_argv[], char *const envp[], const process_setup_t *setup, int errfd
) {
    /* The child's signals, its own before exec (process_child_signals). */
    process_child_signals();

    /* The invoker's child, for good (sys/identity), before anything the child
     * does — the chdir, the exec, the script. Reported as an exec failure is:
     * errno over the self-pipe, 126. */
    if (identity_drop_child() != 0) process_child_fail(errfd, 126);

    /* A child placed nowhere keeps dotta's own: its streams, its working directory
     * and every other descriptor, one the shell handed dotta among them */
    if (!setup) process_exec(shell_argv, envp, errfd);

    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
        if (setup->streams[fd] >= 0 && dup2(setup->streams[fd], fd) < 0) {
            process_child_fail(errfd, 126);
        }
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

    if (setup->work_dir && chdir(setup->work_dir) != 0 &&
        (!setup->work_dir_fallback || chdir(setup->work_dir_fallback) != 0)) {
        process_child_fail(errfd, 126);
    }

    process_exec(shell_argv, envp, errfd);
}

/**
 * A child made — every wait's: the exec's pipe, every stdio stream flushed, the
 * fork, and the child placed by `setup`, or nowhere where NULL (process_child)
 *
 * *pid is the child, *exec_fd the exec's pipe's read end, the wait's to read
 * and close (process_exec_errno): the exec closes the write end, or the child's
 * failure writes its errno there first. A refusal — the pipe, the fork — makes
 * no child, names `program` as its wait was handed it, and leaves both -1.
 */
static error_t process_spawn(
    const char *program, char *const shell_argv[], char *const envp[],
    const process_setup_t *setup, pid_t *pid, int *exec_fd
) {
    *pid = -1;
    *exec_fd = -1;

    /* Exec-errno self-pipe (child writes errno+_exit on exec failure; on exec
     * success, FD_CLOEXEC closes the write end and parent reads EOF), so a program
     * that could not be run is told from one that exited 127. */
    int errfd[2];
    error_t err = process_pipe(errfd, program);
    if (err) return err;

    /* What dotta wrote lands ahead of anything the child writes: a line still
     * in a stdio buffer would follow the child's output wherever both go, so
     * every stream is flushed before the fork, as git flushes before every child
     * (lib/git/run-command.c start_command). */
    (void) fflush(NULL);

    pid_t child = fork();
    if (child < 0) {
        err = error_errno(errno, "Failed to fork '%s'", program);
        close(errfd[0]);
        close(errfd[1]);
        return err;
    }

    if (child == 0) {
        process_child(shell_argv, envp, setup, errfd[1]);
    }

    /* The write end is the child's: its exec, or its exit, closes the last. */
    close(errfd[1]);

    *pid = child;
    *exec_fd = errfd[0];
    return NULL;
}

/**
 * The errno a child's exec failed with, read off the exec's pipe (process_spawn)
 * to its end: 0 where the exec closed it. Every step that fails at the exec or
 * before it sets errno, so a child that could not run writes none that is 0
 * (process_child_fail). The read waits for the exec or the child's exit:
 * process_run and the foreground read it once the child is reaped, the start
 * before it answers. Every child's.
 */
static int process_exec_errno(int fd) {
    int exec_errno = 0;
    ssize_t got;
    do {
        got = read(fd, &exec_errno, sizeof(exec_errno));
    } while (got < 0 && errno == EINTR);

    return got == (ssize_t) sizeof(exec_errno) ? exec_errno : 0;
}

/**
 * A reaped child, reported into its result: the errno its exec failed with, 0
 * where it ran (process_exec_errno), and its wait status — the code it exited
 * with, or the signal that ended it and 128 past it. Every child's.
 */
static void process_report(int exec_errno, int status, process_result_t *result) {
    if (exec_errno != 0) {
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
            (void) process_write_fd(STDOUT_FILENO, chunk, (size_t) n);
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
    CHECK_NULL(spec->argv[0]);
    CHECK_NULL(spec->envp);

    /* The spec's shape is its caller's to keep (process_spec_t): a stdin payload
     * is load-bearing only for BUFFER, so one set under INHERIT or DEVNULL is a
     * payload the caller expected and the child would never read */
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

    /* The program, found before anything is opened (process_find). One no PATH
     * entry holds reads as an exec that failed — ENOENT, and 127, the status a
     * shell gives a command it cannot find — with no child made */
    char **shell_argv = process_find(spec->argv);
    if (!shell_argv) {
        *result = (process_result_t) {
            .exit_code = 127, .exec_failed = true, .exec_errno = ENOENT
        };
        return NULL;
    }

    /* Zero result so every path through cleanup leaves callers with a well-defined
     * struct. */
    *result = (process_result_t) { 0 };

    /* All resources initialized to safe sentinels. */
    const char *program = spec->argv[0];
    int stdin_parent = -1;
    int stdin_child = -1;
    int output_parent = -1;
    int output_child = -1;
    int exec_fd = -1;
    pid_t pid = -1;
    process_capture_t capture = { 0 };
    int status = 0;
    error_t err = NULL;

    /* What the child reads and where it writes, each opened before the spawn
     * (process_stdin_open, process_output_open). */
    err = process_stdin_open(spec, &stdin_parent, &stdin_child);
    if (err) goto cleanup;

    err = process_output_open(spec, &output_parent, &output_child);
    if (err) goto cleanup;

    /* The capture, made before the spawn where the policy keeps the output. */
    if (spec->output_policy == PROCESS_OUTPUT_CAPTURE ||
        spec->output_policy == PROCESS_OUTPUT_FILE) {
        process_capture_init(&capture);
    }

    /* The child placed where its policies opened its stdin and its output — stderr
     * with stdout — dotta's own where they opened nothing, in its directory
     * (process_spawn) */
    process_setup_t setup = {
        .streams           = { stdin_child, output_child, output_child },
        .work_dir          = spec->work_dir,
        .work_dir_fallback = spec->work_dir_fallback,
    };
    err = process_spawn(program, shell_argv, spec->envp, &setup, &pid, &exec_fd);
    if (err) goto cleanup;

    /* Close the child's ends — what it reads, where it writes: the child holds
     * its own of each. */
    if (stdin_child >= 0) {
        close(stdin_child);
        stdin_child = -1;
    }
    if (output_child >= 0) {
        close(output_child);
        output_child = -1;
    }

    /* Deliver the stdin payload before the output is read. The spec-entry cap
     * on stdin_content_len keeps the payload within any POSIX-conformant pipe
     * buffer, so the write returns immediately even if the child has not yet
     * reached its consuming read. EPIPE (child exec failed or exited before
     * reading) is benign — the exec-errno drain and wait-status decode below
     * surface the real cause. */
    if (stdin_parent >= 0) {
        if (spec->stdin_content_len > 0) {
            (void) process_write_fd(stdin_parent, spec->stdin_content, spec->stdin_content_len);
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
    if (result->timed_out && !process_kill(pid, &status)) {
        err = error_create(
            ERR_FS, "Failed to kill '%s' (pid %d), which outlived its time limit",
            program, (int) pid
        );
        goto cleanup;
    }
    pid = -1;

    /* The child reaped, reported (process_report): its exec's pipe read once it
     * is reaped, so the read never waits — the write end closed at the exec or
     * at the child's exit, and the child forks nothing before its exec — where
     * a read before the reap would wait out a child held before its exec, past
     * any limit */
    process_report(process_exec_errno(exec_fd), status, result);

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
    if (stdin_parent >= 0) close(stdin_parent);
    if (stdin_child >= 0) close(stdin_child);
    if (output_parent >= 0) close(output_parent);
    if (output_child >= 0) close(output_child);
    if (exec_fd >= 0) close(exec_fd);

    /* Reap any stray child. We get here with pid > 0 only if a mid-execution
     * failure prevented the normal wait paths from running. Best-effort; if it
     * does not die in the orphan window, the kernel reaps when dotta exits. */
    if (pid > 0) {
        (void) kill(pid, SIGKILL);
        struct timespec grace = process_deadline(PROCESS_GRACE_ORPHAN_SECONDS);
        (void) process_reap(pid, &grace, &status);
    }

    /* The capture, where ownership was not transferred (process_capture_deinit) */
    process_capture_deinit(&capture);
    free(shell_argv);

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
    extern char **environ;

    CHECK_NULL(argv);
    CHECK_NULL(argv[0]);
    CHECK_NULL(result);

    /* The program, found and missed as process_run's is, before anything is opened
     * (process_find) */
    char **shell_argv = process_find(argv);
    if (!shell_argv) {
        *result = (process_result_t) {
            .exit_code = 127, .exec_failed = true, .exec_errno = ENOENT
        };
        return NULL;
    }

    *result = (process_result_t) { 0 };

    /* The keyboard's signals held across the spawn, until the parent ignores
     * them below: a Ctrl-C once the child is made is neither dotta's death nor
     * lost to the child, which clears its mask before exec and hears the terminal's
     * own. One sent before the fork, while the spawn flushes, is held and
     * dropped. */
    sigset_t keyboard, before;
    sigemptyset(&keyboard);
    sigaddset(&keyboard, SIGINT);
    sigaddset(&keyboard, SIGQUIT);
    (void) sigprocmask(SIG_BLOCK, &keyboard, &before);

    /* The child placed nowhere: dotta's own streams, descriptors and directory,
     * in dotta's own environment (process_spawn). It holds its own copy of the
     * vector. */
    pid_t pid = -1;
    int exec_fd = -1;
    error_t err = process_spawn(argv[0], shell_argv, environ, NULL, &pid, &exec_fd);
    free(shell_argv);
    if (err) {
        (void) sigprocmask(SIG_SETMASK, &before, NULL);
        return err;
    }

    /* The keyboard's signals are the child's until it is reaped (the header):
     * ignored here, and a pending one sent since the fork discarded with the
     * ignore — it reached the child too. */
    struct sigaction ignore = { 0 };
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    struct sigaction saved_int, saved_quit;
    (void) sigaction(SIGINT, &ignore, &saved_int);
    (void) sigaction(SIGQUIT, &ignore, &saved_quit);
    (void) sigprocmask(SIG_SETMASK, &before, NULL);

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
    if (!err) process_report(process_exec_errno(exec_fd), status, result);
    close(exec_fd);
    return err;
}

/* A started child (process_t): its pid, the parent's ends of its two pipes, each
 * close-on-exec (process_pipe), and its program as its caller named it, which
 * each refusal names */
struct process {
    pid_t pid;
    int in;                         /* its stdin's write end */
    int out;                        /* its stdout's read end */
    char program[];                 /* argv[0], as handed to the start */
};

error_t process_start(char *const argv[], char *const envp[], process_t **out) {
    CHECK_NULL(argv);
    CHECK_NULL(argv[0]);
    CHECK_NULL(envp);
    CHECK_NULL(out);

    *out = NULL;

    /* The program, found before anything is opened (process_find): one no PATH
     * entry holds is the start's refusal, as an exec that failed is, with no
     * child made */
    const char *program = argv[0];
    char **shell_argv = process_find(argv);
    if (!shell_argv) {
        return error_errno(ENOENT, "Cannot run '%s'", program);
    }

    int stdin_pipe[2] = { -1, -1 };
    int stdout_pipe[2] = { -1, -1 };
    int exec_fd = -1;
    pid_t pid = -1;
    error_t err = NULL;

    /* Its stdin and its stdout, each a pipe whose parent end is close-on-exec
     * (process_pipe): a child spawned while this one stands never holds them,
     * so its finish ends it */
    err = process_pipe(stdin_pipe, program);
    if (err) goto cleanup;

    err = process_pipe(stdout_pipe, program);
    if (err) goto cleanup;

    /* The child placed on the pipes' far ends, its stderr dotta's own — what it
     * says to a person reaches the person, as git leaves ssh's (lib/git/connect.c
     * git_connect) — in dotta's working directory (process_spawn) */
    process_setup_t setup = { .streams = { stdin_pipe[0], stdout_pipe[1], -1 } };
    err = process_spawn(program, shell_argv, envp, &setup, &pid, &exec_fd);
    if (err) goto cleanup;

    /* Close the child's ends — what it reads, where it writes: the child holds
     * its own of each, so a write to it once it is gone is EPIPE, and a read at
     * its end of output is 0. */
    close(stdin_pipe[0]);
    stdin_pipe[0] = -1;
    close(stdout_pipe[1]);
    stdout_pipe[1] = -1;

    /* The exec's pipe read to its end before the start answers, as git's
     * start_command reads it: the exec closes it, or the child writes its errno
     * and exits, so neither waits. A program that could not be run is the start's
     * refusal, its child reaped. */
    int exec_errno = process_exec_errno(exec_fd);
    if (exec_errno != 0) {
        int status = 0;
        (void) process_reap(pid, NULL, &status);
        err = error_errno(exec_errno, "Cannot run '%s'", program);
        goto cleanup;
    }

    /* The started child, its ends handed to it, and its program's name copied
     * for each refusal */
    size_t size = strlen(program) + 1;
    process_t *child = heap_alloc(sizeof(*child) + size);
    child->pid = pid;
    child->in = stdin_pipe[1];
    child->out = stdout_pipe[0];
    memcpy(child->program, program, size);
    stdin_pipe[1] = -1;
    stdout_pipe[0] = -1;
    *out = child;

cleanup:
    if (stdin_pipe[0] >= 0) close(stdin_pipe[0]);
    if (stdin_pipe[1] >= 0) close(stdin_pipe[1]);
    if (stdout_pipe[0] >= 0) close(stdout_pipe[0]);
    if (stdout_pipe[1] >= 0) close(stdout_pipe[1]);
    if (exec_fd >= 0) close(exec_fd);
    free(shell_argv);

    return err;
}

error_t process_write(process_t *child, const void *data, size_t size) {
    CHECK_NULL(child);
    CHECK_ARG(data != NULL || size == 0, "data cannot be NULL with a size");

    if (process_write_fd(child->in, data, size) < 0) {
        return error_errno(errno, "Failed to write to '%s'", child->program);
    }

    return NULL;
}

error_t process_read(process_t *child, void *data, size_t size, size_t *out_len) {
    CHECK_NULL(child);
    CHECK_NULL(data);
    CHECK_NULL(out_len);
    CHECK_ARG(size > 0, "a read of no bytes, which cannot tell the child's end");

    *out_len = 0;

    /* One read, whatever it gives: the bytes the child wrote, or 0 at its end */
    ssize_t got;
    do {
        got = read(child->out, data, size);
    } while (got < 0 && errno == EINTR);

    if (got < 0) {
        return error_errno(errno, "Failed to read the output of '%s'", child->program);
    }

    *out_len = (size_t) got;
    return NULL;
}

error_t process_finish(process_t *child, process_result_t *result) {
    CHECK_NULL(result);

    *result = (process_result_t) { 0 };
    if (!child) return NULL;

    /* Its stdin closed, then its stdout: a child that reads its stdin to its
     * end exits, and one still writing meets its reader gone (SIGPIPE) */
    close(child->in);
    close(child->out);

    /* Reaped however long it takes: no limit, as git's finish_command waits. */
    int status = 0;
    error_t err = NULL;
    if (process_reap(child->pid, NULL, &status) < 0) {
        err = error_errno(errno, "Failed to wait for '%s'", child->program);
    }

    /* Reported as every child is, once reaped (process_report): its exec the
     * start's to answer for, so no errno of its own */
    if (!err) process_report(0, status, result);
    free(child);
    return err;
}

char **process_shell(char *const argv[]) {
    CHECK_NULL(argv);
    CHECK_NULL(argv[0]);

    size_t argc = 0;
    while (argv[argc]) argc++;

    /* A line holding no character the shell reads — git's set — is a program,
     * run as named: argv's own vector */
    const char *line = argv[0];
    if (line[strcspn(line, "|&;<>()$`\\\"' \t\n*?[#~=%")] == '\0') {
        char **copy = heap_alloc((argc + 1) * sizeof(*copy));
        memcpy(copy, argv, (argc + 1) * sizeof(*copy));
        return copy;
    }

    /* Any other is the shell's: the line its $0, and its script — the line, then
     * "$@" where arguments follow, so each reaches the program as one word —
     * built past the pointers */
    size_t room = strlen(line) + sizeof(" \"$@\"");
    char **shell = heap_alloc((argc + 4) * sizeof(*shell) + room);
    char *script = (char *) (shell + argc + 4);
    snprintf(script, room, argc > 1 ? "%s \"$@\"" : "%s", line);
    shell[0] = PROCESS_SHELL;
    shell[1] = "-c";
    shell[2] = script;
    memcpy(shell + 3, argv, (argc + 1) * sizeof(*shell));
    return shell;
}
