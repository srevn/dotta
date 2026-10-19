/**
 * process.h - Unified subprocess primitive
 *
 * One linear procedure for "fork, build env, send the output where the caller
 * says, enforce timeout, reap" — replacing the parallel implementations previously
 * in utils/hooks.c and sys/bootstrap.c — and its one sibling for a child in the
 * foreground, which takes the terminal while dotta waits (process_foreground:
 * the editor, `dotta git`). Both children make their signals their own the same
 * way before exec, and report into one result.
 *
 * Design principles:
 * - The time limit is one deadline on the monotonic clock, counted in the time
 *   that passed: the drain's poll() and the reap's waits both end by it — no
 *   SIGALRM mutation, no global signal-handler state, no prev_alarm restoration
 *   dance.
 * - Caller chooses the load-bearing knobs (stdin policy, output policy, working
 *   directory, time limit); the primitive does not homogenize behavior that callers
 *   genuinely need to differ on.
 * - What dotta wrote lands ahead of anything the child writes: every stdio stream
 *   is flushed before the fork, as git flushes before every child
 *   (lib/git/run-command.c start_command).
 * - Child reports execve() failure to the parent over a CLOEXEC self-pipe carrying
 *   errno, so the parent can distinguish "exec failed" from "the script exited
 *   127" — letting callers report the specific reason ("ENOEXEC: bad shebang")
 *   instead of a misleading proxy.
 * - Result struct is stack-allocated by the caller and populated on every code
 *   path.
 *
 * Threading, descriptor and signal model:
 * - Single-threaded: must not be called concurrently from multiple threads. The
 *   implementation does not synchronize.
 * - The standard descriptors: the host program has 0, 1 and 2 open from its start
 *   (main.c main, its first lines), so no descriptor the primitive opens sits
 *   at one of them for a child's dup2 to overwrite.
 * - SIGPIPE: caller must have SIGPIPE ignored (typically via signal(SIGPIPE,
 *   SIG_IGN) at process startup), so a payload written to a child that is gone,
 *   or a copy to a reader that went away (PROCESS_OUTPUT_STREAM), is EPIPE and
 *   never dotta's death.
 * - SIGCHLD: caller must NOT install a SIGCHLD handler. The implementation uses
 *   waitpid() with default disposition.
 * - The child resets each terminating signal it finds caught
 *   (PROCESS_TERMINATING_SIGNALS) to SIG_DFL — one the parent inherited ignored
 *   stays ignored, as execve keeps it — resets SIGPIPE, dotta's own ignore, and
 *   clears its signal mask before exec, so no handler of the parent's runs between
 *   fork and exec.
 * - The child becomes the invoker for good before exec (identity_drop_child,
 *   sys/identity): under sudo a hook or a script never runs as root. A failure
 *   there is reported like an exec failure, errno over the self-pipe.
 * - Every child runs in dotta's process group, part of the job the user started,
 *   as git runs every child it starts (lib/git/run-command.c start_command sets
 *   no group). The terminal's signals — Ctrl+C, Ctrl+\, a hangup — reach it as
 *   they reach dotta, and the terminal is its as dotta's: a write to /dev/tty,
 *   an answer read from it, tostop or not, where from a group of its own the
 *   read would stop it (SIGTTIN) and under tostop the write (SIGTTOU). So the
 *   time limit's kill ends the child alone, never what it started, and a signal
 *   sent to dotta alone — kill(1), a supervisor — reaches no child: one writing
 *   into dotta's pipe dies at its next write once dotta is gone (SIGPIPE), one
 *   writing to a file, the terminal or /dev/null runs on.
 */

#ifndef DOTTA_PROCESS_H
#define DOTTA_PROCESS_H

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * The terminating signals: those whose default action ends dotta, which a changed
 * terminal must not survive
 *
 * An initializer for an int array. The host program catches each (main.c
 * terminating_signal: the armed terminal put back, then re-raised), and the child
 * resets each it finds caught before exec. A signal the host inherited ignored
 * stays ignored in both — a backgrounded dotta, nohup. SIGABRT is one: the death's
 * abort(3) raises it (base/error.h error_die), so a run that broke a contract
 * puts the terminal back as one a user ended does, and a sanitizer that aborts
 * has said its report first. SIGSEGV and SIGBUS are not here: the debug build's
 * AddressSanitizer reports them, and a handler of dotta's would swallow the report.
 */
#define PROCESS_TERMINATING_SIGNALS { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGABRT }

/**
 * Stdin policy for the spawned child.
 *
 * INHERIT — child inherits parent's STDIN_FILENO (typically the controlling
 *           terminal). Use for interactive scripts that need to prompt the user
 *           (read -p, etc.).
 * DEVNULL — child's STDIN_FILENO is redirected to /dev/null. Use for
 *           non-interactive children that must never block on a terminal read.
 *           Opened before the fork: one that cannot be opened refuses the run,
 *           never leaves the child dotta's stdin.
 * BUFFER  — child's STDIN_FILENO reads from a pipe the primitive
 *           fills with spec->stdin_content (stdin_content_len bytes) and closes.
 *           Use for subprocesses that consume a small fixed payload on stdin
 *           (e.g., `git credential fill` reading a protocol request). Payload
 *           is capped at PROCESS_STDIN_BUFFER_MAX so the single synchronous write
 *           performed before the output is read never blocks on a pipe-buffer
 *           shortage.
 */
typedef enum {
    PROCESS_STDIN_INHERIT,
    PROCESS_STDIN_DEVNULL,
    PROCESS_STDIN_BUFFER,
} process_stdin_t;

/**
 * Upper bound on stdin_content_len for PROCESS_STDIN_BUFFER.
 *
 * The primitive writes the entire payload synchronously before the child's output
 * is read. For that write to be non-blocking even when the child has not yet
 * reached its consuming read, the payload must fit in the pipe buffer. POSIX
 * guarantees PIPE_BUF-sized writes are atomic, and the minimum PIPE_BUF
 * (_POSIX_PIPE_BUF) is 512 bytes; Linux's default pipe capacity is 65536 and
 * macOS's is 16384, with PIPE_BUF itself at 4096 / 512 respectively. Picking
 * 4096 is a comfortable ceiling across realistic targets — larger payloads need
 * a future extension that interleaves the payload's writes with the output's reads.
 *
 * The caller's contract, checked at entry: a payload a user's data sizes is bounded
 * where it is built, in the words of what it carries — sys/credentials.c
 * credential_helper_run, whose request holds the credential, so a credential
 * past the bound is never handed to a helper (approve and reject warn, a fill
 * finds nothing).
 */
#define PROCESS_STDIN_BUFFER_MAX 4096

/**
 * Output policy for the spawned child: where its stdout and stderr go, together
 * — and so what the wait on it ends at.
 *
 * A pipe (CAPTURE, STREAM) is read to its end: the wait ends once it is drained
 * and the child reaped, so a task the child leaves holding the pipe holds the
 * wait. Every other policy waits on the child alone: the wait ends at its exit,
 * and a task it leaves runs on, writing where the child wrote.
 *
 * INHERIT — dotta's own stdout and stderr: what the user watches live, between
 *           dotta's own lines, as the child writes it — a hook under -v
 *           (utils/hooks) — nothing of it kept. A reader that goes away ends
 *           the child at its next write (SIGPIPE).
 * DEVNULL — /dev/null: output nobody reads, a credential helper's to approve or
 *           reject (sys/credentials). Opened before the fork: one that cannot
 *           be opened refuses the run, never leaves the child dotta's output.
 * CAPTURE — onto a pipe read into memory as the child writes, kept to the bound
 *           and counted past it (PROCESS_CAPTURE_MAX): a response the caller
 *           parses (sys/credentials). Nothing of it touches a disk — the policy
 *           for an output that holds a secret.
 * STREAM  — onto a pipe copied to dotta's stdout as it comes, and drained to the
 *           child's end whatever the reader does: a reader that went away costs
 *           the copy, never the child — a bootstrap script (utils/bootstrap).
 * FILE    — into an unlinked file in the temporary directory (sys/filesystem.h
 *           fs_tmpdir), read once the child is reaped, kept to the bound and
 *           counted past it: a hook's run (utils/hooks). A temporary directory
 *           where no file can be created refuses the run; a child writing without
 *           bound fills it while it runs, and what it writes stands there until
 *           the file's last close — its own, or that of a task it left writing on.
 *
 * What a policy keeps (CAPTURE, FILE) is kept as a secret is, whatever wrote it
 * — no policy can tell an output that holds one from one that does not: every
 * buffer that held a byte of it is wiped before the allocator has it back, the
 * result's by process_result_deinit.
 */
typedef enum {
    PROCESS_OUTPUT_INHERIT,
    PROCESS_OUTPUT_DEVNULL,
    PROCESS_OUTPUT_CAPTURE,
    PROCESS_OUTPUT_STREAM,
    PROCESS_OUTPUT_FILE,
} process_output_t;

/**
 * The most a policy that keeps a child's output keeps of it (CAPTURE, FILE),
 * stdout and stderr together.
 *
 * What a child writes is the child's to size, never the memory dotta holds for
 * it: past the bound the capture keeps nothing more and counts the rest
 * (result.output_dropped), and the child runs to its own end, never killed for
 * its volume. What a short capture means is the caller's to say — a credential
 * response read in part is refused (sys/credentials), a failed hook's output is
 * shown as far as it was kept (utils/hooks).
 */
#define PROCESS_CAPTURE_MAX ((size_t) 1024 * 1024)

/**
 * Subprocess specification.
 *
 * Value type built by the caller — typically with designated initializers — and
 * passed to process_run() once. All pointer fields are borrowed; the caller must
 * keep the underlying storage (argv strings, envp strings, work_dir strings)
 * valid for the duration of the process_run() call.
 *
 * Its shape is the caller's contract, checked at entry (base/error.h CHECK_ARG):
 * a spec is built by code, never read from a user, so one that breaks it is a
 * bug and dies there — and a caller whose payload a user's data sizes bounds it
 * first (PROCESS_STDIN_BUFFER_MAX).
 * - argv non-NULL; argv[0] non-NULL and non-empty. The primitive does NOT perform
 *   PATH lookup — argv[0] should be an absolute path the caller has already
 *   resolved.
 * - envp non-NULL. Use { NULL } for an empty environment.
 * - timeout_seconds >= 0. Zero means no timeout (wait forever).
 * - work_dir / work_dir_fallback NULL means "inherit". If both are set, the child
 *   tries work_dir first; on chdir failure, falls back to work_dir_fallback. If
 *   both fail, child exits with exec_failed=true and exec_errno=<chdir errno>.
 * - stdin_content / stdin_content_len: both zero (NULL / 0) unless stdin_policy
 *   == PROCESS_STDIN_BUFFER. When BUFFER, stdin_content must be non-NULL if
 *   stdin_content_len > 0, and stdin_content_len must not exceed
 *   PROCESS_STDIN_BUFFER_MAX. The primitive writes the full buffer once before
 *   the output is read; if the child exits before consuming it (EPIPE on the
 *   write), that is not a primitive-level error — exec_failed / exit_code carry
 *   the real cause.
 */
typedef struct {
    char *const *argv;              /* argv[0] = absolute path; NULL-terminated */
    char *const *envp;              /* environment, NULL-terminated */
    process_stdin_t stdin_policy;
    const char *stdin_content;      /* non-NULL iff stdin_policy == BUFFER */
    size_t stdin_content_len;       /* bytes in stdin_content (≤ MAX) */
    process_output_t output_policy;
    const char *work_dir;           /* NULL = inherit parent's CWD */
    const char *work_dir_fallback;  /* NULL = no fallback */
    int timeout_seconds;            /* 0 = no timeout */
} process_spec_t;

/**
 * Subprocess execution result.
 *
 * The caller stack-allocates and zero-initializes:
 *
 *     process_result_t result = {0};
 *     error_t err = process_run(&spec, &result);
 *     // ... inspect result.exit_code / result.timed_out / result.output ...
 *     process_result_deinit(&result);
 *
 * Field semantics:
 * - exit_code      : WEXITSTATUS for normal termination, 128+signal_num
 *                    for signal termination. Reflects what the wait status actually
 *                    said — never overloaded with a timeout sentinel (use timed_out
 *                    for that).
 * - signal_num     : 0 if normal exit; signal that killed the child
 *                    otherwise. When a timeout fires, this is SIGTERM or SIGKILL
 *                    (whichever finally reaped the child).
 * - timed_out      : true if the primitive killed the child for
 *                    exceeding spec.timeout_seconds. Independent of
 *                    exit_code/signal_num — caller checks this first.
 * - exec_failed    : true if the child reached execve() and execve returned, OR a
 *                    child-side setup step (dup2, chdir) failed before exec.
 *                    exec_errno carries the errno from the failure.
 * - exec_errno     : errno value reported by the child via the
 *                    self-pipe. Zero when exec_failed is false.
 * - output         : capture buffer, NUL-terminated. Non-NULL whenever the
 *                    output policy keeps the output (PROCESS_OUTPUT_CAPTURE,
 *                    FILE) and the run returned no error — "" for a child that
 *                    wrote nothing. Caller may take ownership by setting
 *                    result.output = NULL before dispose; otherwise dispose wipes
 *                    and frees it.
 * - output_len     : number of bytes in output, excluding the
 *                    terminating NUL. Zero when output is NULL. At most
 *                    PROCESS_CAPTURE_MAX.
 * - output_dropped : bytes the child wrote past PROCESS_CAPTURE_MAX, never kept
 *                    — output holds the first PROCESS_CAPTURE_MAX and the rest
 *                    is gone. Zero for a capture that kept everything.
 */
typedef struct {
    int exit_code;
    int signal_num;
    bool timed_out;
    bool exec_failed;
    int exec_errno;
    char *output;
    size_t output_len;
    size_t output_dropped;
} process_result_t;

/**
 * Run a child process, wait for it, and report the outcome.
 *
 * Always populates *result before returning, on every path. Returns NULL — meaning
 * "the primitive succeeded mechanically" — even when:
 *   - the child exited non-zero (caller checks result->exit_code),
 *   - the child timed out and was killed (result->timed_out is true),
 *   - exec failed in the child (result->exec_failed + exec_errno).
 *
 * Returns non-NULL only for a failure of the primitive itself, each naming the
 * program it was handed (argv[0]), so no caller names it again: what a policy
 * needs that it could not open — a pipe, /dev/null, the temporary file, which
 * the refusal names too — or the fork it could not make, the child's output it
 * could not read, a wait that failed — the errno's code (base/error.h error_errno)
 * — or a child its time limit outlived that SIGKILL did not end, ERR_FS. A spec
 * that breaks its contract dies at the check (process_spec_t).
 *
 * Caller composes the user-facing error message from result fields plus its own
 * context (script name, hook name, etc.).
 */
error_t process_run(const process_spec_t *spec, process_result_t *result);

/**
 * Release any heap-allocated fields in result and zero the struct.
 *
 * Safe on a zero-initialized result. Idempotent — calling twice is a no-op. To
 * take ownership of the capture buffer before disposing, read result->output
 * (and result->output_len), then set result->output = NULL before calling.
 *
 * The capture buffer is wiped before it is freed, as every buffer that held a
 * child's output is (process_output_t), so no secret lingers on the freelist.
 * Ownership-transfer (output = NULL before dispose) bypasses the wipe — the caller
 * owns it from that point on.
 */
void process_result_deinit(process_result_t *result);

/**
 * Run a child in the foreground, and wait for it.
 *
 * The child takes the terminal: dotta's stdin, stdout and stderr, in dotta's
 * process group — for a program the user drives, the editor (sys/editor) and
 * `dotta git` with the pager git starts. argv[0] is looked up on PATH, the
 * environment is dotta's own, and the child is the invoker's (sys/identity) with
 * its signals made its own before exec, as process_run's child's are.
 *
 * The keyboard's signals are the child's to answer while it runs: a terminal
 * sends SIGINT and SIGQUIT to dotta's whole group, so dotta ignores both until
 * the child is reaped — an editor reads Ctrl-C as a key, a pager as "stop" —
 * and never dies first with the child still holding the terminal. What a child
 * that died of one means is the caller's to decide (git's rule: re-raise it, so
 * the caller dies as its child did); a terminal's hangup and any other signal
 * still end dotta, the child hearing the terminal's own.
 *
 * Populates *result on every path, as process_run does: exit_code and signal_num
 * from the wait status, exec_failed and exec_errno when the program could not
 * be run (the child's errno, over a self-pipe); no capture, no timeout. Returns
 * non-NULL only for a failure of the primitive itself — the pipe, the fork or
 * the wait — naming argv[0], as process_run's do.
 *
 * @param argv NULL-terminated; argv[0] a program name or path (must not be NULL)
 * @param result Outcome (must not be NULL)
 * @return Error or NULL on success
 */
error_t process_foreground(char *const argv[], process_result_t *result);

#endif /* DOTTA_PROCESS_H */
