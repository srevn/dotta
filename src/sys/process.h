/**
 * process.h - Unified subprocess primitive
 *
 * One linear procedure for "fork, build env, capture or stream output,
 * enforce timeout, reap" — replacing the parallel implementations
 * previously in utils/hooks.c and sys/bootstrap.c.
 *
 * Design principles:
 * - Monotonic-clock timeout via select() — no SIGALRM mutation, no
 *   global signal-handler state, no prev_alarm restoration dance.
 * - Caller chooses the load-bearing knobs (stdin policy, output
 *   handling, working directory, process-group policy); the primitive
 *   does not homogenize behavior that callers genuinely need to
 *   differ on.
 * - Child reports execve() failure to the parent over a CLOEXEC
 *   self-pipe carrying errno, so the parent can distinguish "exec
 *   failed" from "the script exited 127" — letting callers report
 *   the specific reason ("ENOEXEC: bad shebang") instead of a
 *   misleading proxy.
 * - Result struct is stack-allocated by the caller and populated on
 *   every code path. Allocation failure is always surfaced as an
 *   error_t, never silently dropped.
 *
 * Threading and signal model:
 * - Single-threaded: must not be called concurrently from multiple
 *   threads. The implementation does not synchronize.
 * - SIGPIPE: caller must have SIGPIPE ignored (typically via
 *   signal(SIGPIPE, SIG_IGN) at process startup). The streaming
 *   code path will otherwise terminate the parent on a broken sink.
 * - SIGCHLD: caller must NOT install a SIGCHLD handler. The
 *   implementation uses waitpid() with default disposition.
 * - The child resets SIGINT/SIGTERM/SIGPIPE/SIGALRM to SIG_DFL and
 *   clears its signal mask before exec — parent handlers do not
 *   leak into the new program image.
 * - Terminating-signal forwarding (PROCESS_PGRP_NEW only): the
 *   primitive publishes the child's pgid into the volatile
 *   sig_atomic_t global `active_child_pgid` (defined in main.c)
 *   for the duration of the child's lifetime, and clears it on
 *   every exit path. The host program's SIGINT/SIGTERM handler
 *   must read this and forward via kill(-pgid, signum) before its
 *   own cleanup, so terminal Ctrl+C kills the parent and the spawned
 *   child group atomically. PROCESS_PGRP_SHARED children leave the
 *   global at zero — the kernel delivers terminal signals to the
 *   entire foreground process group directly.
 */

#ifndef DOTTA_PROCESS_H
#define DOTTA_PROCESS_H

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * Pgid of the currently running PROCESS_PGRP_NEW child, or 0 when no
 * such child is active. Defined in main.c and read by the host
 * program's SIGINT/SIGTERM handler — see the "Threading and signal
 * model" comment above for the contract. Declared here so the
 * cross-TU type contract is enforced at compile time rather than
 * tracked by hand in a bare `extern` inside process.c.
 *
 * Volatile sig_atomic_t for async-signal-safe access from a handler
 * (POSIX requirement).
 */
extern volatile sig_atomic_t active_child_pgid;

/**
 * Stdin policy for the spawned child.
 *
 * INHERIT — child inherits parent's STDIN_FILENO (typically the
 *           controlling terminal). Use for interactive scripts that
 *           need to prompt the user (read -p, etc.).
 * DEVNULL — child's STDIN_FILENO is redirected to /dev/null. Use for
 *           non-interactive children that must never block on a
 *           terminal read.
 * BUFFER  — child's STDIN_FILENO reads from a pipe the primitive
 *           fills with spec->stdin_content (stdin_content_len bytes)
 *           and closes. Use for subprocesses that consume a small
 *           fixed payload on stdin (e.g., `git credential fill`
 *           reading a protocol request). Payload is capped at
 *           PROCESS_STDIN_BUFFER_MAX so the single synchronous write
 *           performed before the capture loop never blocks on a
 *           pipe-buffer shortage.
 */
typedef enum {
    PROCESS_STDIN_INHERIT,
    PROCESS_STDIN_DEVNULL,
    PROCESS_STDIN_BUFFER,
} process_stdin_t;

/**
 * Upper bound on stdin_content_len for PROCESS_STDIN_BUFFER.
 *
 * The primitive writes the entire payload synchronously before the
 * stdout capture loop starts. For that write to be non-blocking even
 * when the child has not yet reached its consuming read, the payload
 * must fit in the pipe buffer. POSIX guarantees PIPE_BUF-sized writes
 * are atomic, and the minimum PIPE_BUF (_POSIX_PIPE_BUF) is 512 bytes;
 * Linux's default pipe capacity is 65536 and macOS's is 16384, with
 * PIPE_BUF itself at 4096 / 512 respectively. Picking 4096 is a
 * comfortable ceiling across realistic targets — larger payloads need
 * a future extension that interleaves stdin writes with the stdout
 * select loop.
 */
#define PROCESS_STDIN_BUFFER_MAX 4096

/**
 * Process-group policy for the spawned child.
 *
 * SHARED — child stays in the parent's process group. Ctrl+C from
 *          the controlling terminal is delivered to both. Use when
 *          dotta and the child should die together on user
 *          interrupt (e.g., long-running interactive scripts).
 * NEW    — child is placed in its own process group (pgid = pid)
 *          via setpgid(). Timeout kills target the whole group via
 *          kill(-pid, ...), so sub-processes the child spawns are
 *          reaped along with it. Trade-off: terminal-driven SIGINT
 *          no longer reaches the child group; only the parent dies.
 */
typedef enum {
    PROCESS_PGRP_SHARED,
    PROCESS_PGRP_NEW,
} process_pgrp_t;

/**
 * Subprocess specification.
 *
 * Value type built by the caller — typically with designated
 * initializers — and passed to process_run() once. All pointer
 * fields are borrowed; the caller must keep the underlying storage
 * (argv strings, envp strings, work_dir strings) valid for the
 * duration of the process_run() call.
 *
 * Invariants (validated at entry):
 * - argv non-NULL; argv[0] non-NULL and non-empty. The primitive
 *   does NOT perform PATH lookup — argv[0] should be an absolute
 *   path the caller has already resolved.
 * - envp non-NULL. Use { NULL } for an empty environment.
 * - timeout_seconds >= 0. Zero means no timeout (wait forever).
 * - stream_fd is -1 (no streaming) or a writable fd the caller
 *   owns. The primitive does not close it.
 * - work_dir / work_dir_fallback NULL means "inherit". If both are
 *   set, the child tries work_dir first; on chdir failure, falls
 *   back to work_dir_fallback. If both fail, child exits with
 *   exec_failed=true and exec_errno=<chdir errno>.
 * - stdin_content / stdin_content_len: both zero (NULL / 0) unless
 *   stdin_policy == PROCESS_STDIN_BUFFER. When BUFFER, stdin_content
 *   must be non-NULL if stdin_content_len > 0, and stdin_content_len
 *   must not exceed PROCESS_STDIN_BUFFER_MAX. The primitive writes
 *   the full buffer once before entering the capture loop; if the
 *   child exits before consuming it (EPIPE on the write), that is
 *   not a primitive-level error — exec_failed / exit_code carry the
 *   real cause.
 */
typedef struct {
    char *const *argv;              /* argv[0] = absolute path; NULL-terminated */
    char *const *envp;              /* environment, NULL-terminated */
    process_stdin_t stdin_policy;
    const char *stdin_content;      /* non-NULL iff stdin_policy == BUFFER */
    size_t stdin_content_len;       /* bytes in stdin_content (≤ MAX) */
    bool capture;                   /* true = collect stdout+stderr into result */
    bool secure_capture;            /* scrub the capture buffer before any allocator hand-back */
    int stream_fd;                  /* -1 = no streaming; else write each chunk */
    const char *work_dir;           /* NULL = inherit parent's CWD */
    const char *work_dir_fallback;  /* NULL = no fallback */
    int timeout_seconds;            /* 0 = no timeout */
    process_pgrp_t pgrp_policy;
} process_spec_t;

/**
 * Subprocess execution result.
 *
 * The caller stack-allocates and zero-initializes:
 *
 *     process_result_t result = {0};
 *     error_t *err = process_run(&spec, &result);
 *     // ... inspect result.exit_code / result.timed_out / result.output ...
 *     process_result_dispose(&result);
 *
 * Field semantics:
 * - exit_code   : WEXITSTATUS for normal termination, 128+signal_num
 *                 for signal termination. Reflects what the wait
 *                 status actually said — never overloaded with a
 *                 timeout sentinel (use timed_out for that).
 * - signal_num  : 0 if normal exit; signal that killed the child
 *                 otherwise. When a timeout fires, this is SIGTERM
 *                 or SIGKILL (whichever finally reaped the child).
 * - timed_out   : true if the primitive killed the child for
 *                 exceeding spec.timeout_seconds. Independent of
 *                 exit_code/signal_num — caller checks this first.
 * - exec_failed : true if the child reached execve() and execve
 *                 returned, OR a child-side setup step (dup2,
 *                 chdir) failed before exec. exec_errno carries
 *                 the errno from the failure.
 * - exec_errno  : errno value reported by the child via the
 *                 self-pipe. Zero when exec_failed is false.
 * - output      : capture buffer, NUL-terminated. Non-NULL only if
 *                 spec.capture was true AND something was read
 *                 before failure. Caller may take ownership by
 *                 setting result.output = NULL before dispose;
 *                 otherwise dispose frees it.
 * - output_len  : number of bytes in output, excluding the
 *                 terminating NUL. Zero when output is NULL.
 * - secure      : mirrors spec.secure_capture. When true,
 *                 process_result_dispose scrubs the capture buffer
 *                 before free. Ownership-transfer (output = NULL
 *                 before dispose) bypasses this scrub — the caller
 *                 then owns scrubbing.
 */
typedef struct {
    int exit_code;
    int signal_num;
    bool timed_out;
    bool exec_failed;
    int exec_errno;
    char *output;
    size_t output_len;
    bool secure;
} process_result_t;

/**
 * Run a child process, wait for it, and report the outcome.
 *
 * Always populates *result before returning, on every path. Returns
 * NULL — meaning "the primitive succeeded mechanically" — even when:
 *   - the child exited non-zero (caller checks result->exit_code),
 *   - the child timed out and was killed (result->timed_out is true),
 *   - exec failed in the child (result->exec_failed + exec_errno).
 *
 * Returns a non-NULL error_t* only for failures the primitive itself
 * encountered:
 *   - invalid spec (argv NULL, argv[0] missing, etc.)         → ERR_INVALID_ARG
 *   - pipe(), fork(), or clock_gettime() failed                → ERR_FS
 *   - capture buffer allocation or growth failed               → ERR_MEMORY
 *   - select()/read()/waitpid() returned an unrecoverable error → ERR_FS
 *   - "we tried to kill a timed-out child but it never reaped"  → ERR_FS
 *
 * Caller composes the user-facing error message from result fields
 * plus its own context (script name, hook name, etc.).
 */
error_t *process_run(const process_spec_t *spec, process_result_t *result);

/**
 * Release any heap-allocated fields in result and zero the struct.
 *
 * Safe on a zero-initialized result. Idempotent — calling twice is a
 * no-op. To take ownership of the capture buffer before disposing,
 * read result->output (and result->output_len), then set
 * result->output = NULL before calling.
 *
 * When result->secure is true (mirrored from spec.secure_capture),
 * the capture buffer is wiped before free so secrets do not linger
 * on the freelist. Ownership-transfer (output = NULL before dispose)
 * bypasses the scrub — the caller owns it from that point on.
 */
void process_result_dispose(process_result_t *result);

#endif /* DOTTA_PROCESS_H */
