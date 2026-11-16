/**
 * process.h - A child: its program found as git finds one, and three ways to
 * wait for it
 *
 * A child's program is found before its fork and exec'd by its path, one way
 * for every child, as git runs a command (lib/git/run-command.c prepare_cmd,
 * start_command). A name holding a '/' is run as given; any other is the first
 * regular file of that name along PATH whose owner may execute it — dotta's own
 * PATH, never the environment a caller builds for the child, and the system's
 * default where it is unset, as git makes it (locate_in_PATH; exec-cmd.c
 * setup_path). A name no PATH entry holds — the empty one among them, as git
 * reads it — is an exec that failed, ENOENT, and no child is made. The program
 * is handed its path as argv[0], as git hands it.
 *
 * Three ways to wait for it, each reporting into one result:
 *   process_run         to its end, by a time limit, its output where the caller
 *                       says: a hook, a bootstrap script
 *   process_foreground  in the foreground, the terminal its own while dotta
 *                       waits: the editor, `dotta git`
 *   process_start       in conversation, its caller writing what it reads and
 *                       reading what it writes, then waiting at process_finish
 *                       with no limit, as git waits for its ssh
 *                       (lib/git/run-command.c finish_command): ssh, carrying
 *                       libgit2's protocol on its stdin and stdout (sys/ssh)
 *   process_exchange    the same for one exchange: its request written whole
 *                       where there is one, then its answer read to its end where
 *                       one is wanted, as git runs a credential helper and an
 *                       askpass (lib/git/credential.c run_credential_helper,
 *                       prompt.c do_askpass): each of them (sys/credentials)
 *
 * A command line a person configured — an editor, an ssh command, a credential
 * helper — becomes an argv by git's rule, which its caller applies (process_shell):
 * never a wait, so never to a path a caller made.
 *
 * Design principles:
 * - The time limit is one deadline on the monotonic clock, counted in the time
 *   that passed: the drain's poll() and the reap's waits both end by it — no
 *   SIGALRM mutation, no global signal-handler state, no prev_alarm restoration
 *   dance.
 * - Caller chooses the load-bearing knobs (process_run's stdin policy, output
 *   policy, working directory and time limit; an exchange's request and result);
 *   the primitive does not homogenize behavior that callers genuinely need to
 *   differ on.
 * - A child's stderr is placed by its wait: process_run's with its stdout, wherever
 *   its output policy sends it; dotta's own where the child's stdout is a program's
 *   to read or nobody's (process_start, process_exchange), so what it says to a
 *   person reaches the person, as git leaves ssh's and a helper's.
 * - What dotta wrote lands ahead of anything the child writes: every stdio stream
 *   is flushed before the fork, as git flushes before every child
 *   (lib/git/run-command.c start_command).
 * - Child reports execve() failure to the parent over a CLOEXEC self-pipe carrying
 *   errno, so the parent can distinguish "exec failed" from "the script exited
 *   127" — letting callers report the specific reason (a missing interpreter's
 *   ENOENT) instead of a misleading proxy. The start reads it before it answers
 *   and the exchange before it writes, so a started child is a program that runs
 *   and a request is never written to one that could not.
 * - A file the kernel will not execute (ENOEXEC: a script with no #! line) is
 *   read by /bin/sh, its path the shell's first argument — git's retry for every
 *   command it runs (lib/git/run-command.c prepare_cmd, start_command), made by
 *   the one exec every child takes, never a libc's: musl's execvp makes none.
 * - Result struct is stack-allocated by the caller and populated on every code
 *   path.
 *
 * Threading, descriptor and signal model:
 * - Single-threaded: must not be called concurrently from multiple threads. The
 *   implementation does not synchronize.
 * - The standard descriptors: the host program has 0, 1 and 2 open from its start
 *   (main.c main, its first lines), so no descriptor the primitive opens sits
 *   at one of them for a child's dup2 to overwrite.
 * - Every other descriptor: a child process_run, process_start or process_exchange
 *   places, its streams where its wait says, has every descriptor past them closed
 *   before its exec, so no handle of libgit2's or SQLite's reaches it, and a
 *   child spawned while a started one stands never holds that one's stdin; the
 *   foreground's keeps every descriptor dotta holds, so one the shell handed
 *   dotta reaches the program (`GIT_TRACE=3 dotta git … 3>log`).
 * - SIGPIPE: caller must have SIGPIPE ignored (typically via signal(SIGPIPE,
 *   SIG_IGN) at process startup), so a request written to a child that is gone
 *   (process_exchange), a write to a started child that is gone (process_write),
 *   or a copy to a reader that went away (PROCESS_OUTPUT_STREAM), is EPIPE and
 *   never dotta's death.
 * - SIGCHLD: caller must NOT install a SIGCHLD handler. The implementation uses
 *   waitpid() with default disposition.
 * - The child resets each terminating signal it finds caught
 *   (PROCESS_TERMINATING_SIGNALS) to SIG_DFL — one the parent inherited ignored
 *   stays ignored, as execve keeps it — resets SIGPIPE, dotta's own ignore, and
 *   clears its signal mask before exec, so no handler of the parent's runs between
 *   fork and exec.
 * - Every child becomes the invoker for good before exec (identity_drop_child,
 *   sys/identity): under sudo no child runs as root. A failure there is reported
 *   like an exec failure, errno over the self-pipe.
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
 */
typedef enum {
    PROCESS_STDIN_INHERIT,
    PROCESS_STDIN_DEVNULL,
} process_stdin_t;

/**
 * Output policy for the spawned child: where its stdout and stderr go, together
 * — and so what the wait on it ends at.
 *
 * A pipe (STREAM) is read to its end: the wait ends once it is drained and the
 * child reaped, so a task the child leaves holding the pipe holds the wait. Every
 * other policy waits on the child alone: the wait ends at its exit, and a task
 * it leaves runs on, writing where the child wrote.
 *
 * INHERIT — dotta's own stdout and stderr: what the user watches live, between
 *           dotta's own lines, as the child writes it — a hook under -v
 *           (utils/hooks) — nothing of it kept. A reader that goes away ends
 *           the child at its next write (SIGPIPE).
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
 * A child's output is held as a secret is, whatever wrote it — no policy can
 * tell an output that holds one from one that does not: every buffer that held
 * a byte of it, the chunk STREAM copies it through and what FILE keeps alike,
 * is wiped before it is let go, the result's by process_result_deinit.
 */
typedef enum {
    PROCESS_OUTPUT_INHERIT,
    PROCESS_OUTPUT_STREAM,
    PROCESS_OUTPUT_FILE,
} process_output_t;

/**
 * The most FILE keeps of a child's output, stdout and stderr together, and an
 * exchange of its answer, its stdout alone (process_exchange).
 *
 * What a child writes is the child's to size, never the memory dotta holds for
 * it: past the bound the capture keeps nothing more and counts the rest
 * (result.output_dropped), and the child runs to its own end, never killed for
 * its volume. What a short capture means is the caller's to say — a helper's
 * answer read in part is none (sys/credentials), a failed hook's output is shown
 * as far as it was kept (utils/hooks).
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
 * bug and dies there.
 * - argv non-NULL; argv[0] non-NULL: a name, found as git finds one, or a path,
 *   run as given (the header).
 * - envp non-NULL. Use { NULL } for an empty environment.
 * - timeout_seconds >= 0. Zero means no timeout (wait forever).
 * - work_dir / work_dir_fallback NULL means "inherit". If both are set, the child
 *   tries work_dir first; on chdir failure, falls back to work_dir_fallback. If
 *   both fail, child exits with exec_failed=true and exec_errno=<chdir errno>.
 */
typedef struct {
    char *const *argv;              /* argv[0] a name or a path; NULL-terminated */
    char *const *envp;              /* environment, NULL-terminated */
    process_stdin_t stdin_policy;
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
 *                    for that) — and 127 where no child was made, the status a
 *                    shell gives a command it cannot find.
 * - signal_num     : 0 if normal exit; signal that killed the child
 *                    otherwise. When a timeout fires, this is SIGTERM or SIGKILL
 *                    (whichever finally reaped the child).
 * - timed_out      : true if the primitive killed the child for
 *                    exceeding spec.timeout_seconds. Independent of
 *                    exit_code/signal_num — caller checks this first.
 * - exec_failed    : true if no PATH entry holds the program, no child made; if
 *                    the child reached execve() and execve returned; OR if a
 *                    child-side setup step (dup2, chdir) failed before exec.
 *                    exec_errno carries the errno from the failure.
 * - exec_errno     : errno value reported by the child via the
 *                    self-pipe, ENOENT for a program not found. Zero when
 *                    exec_failed is false.
 * - output         : capture buffer, NUL-terminated. Non-NULL whenever the
 *                    output policy keeps the output (PROCESS_OUTPUT_FILE) or an
 *                    exchange wants its answer (process_exchange), a child was
 *                    made and the wait returned no error — "" for a child that
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
 *   - the program could not be run: no PATH entry holds it, or its exec failed
 *     in the child (result->exec_failed + exec_errno).
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
 * `dotta git` with the pager git starts. Its program is found as every child's
 * is (the header); its environment, its working directory and every descriptor
 * dotta holds are dotta's own (the header); and the child is the invoker's
 * (sys/identity) with its signals made its own before exec, as process_run's
 * child's are.
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
 * be run (not found, or the child's errno, over a self-pipe); no capture, no
 * timeout. Returns non-NULL only for a failure of the primitive itself — the
 * pipe, the fork or the wait — naming argv[0], as process_run's do.
 *
 * @param argv NULL-terminated; argv[0] a program name or path (must not be NULL)
 * @param result Outcome (must not be NULL)
 * @return Error or NULL on success
 */
error_t process_foreground(char *const argv[], process_result_t *result);

/**
 * A started child: its program running, its stdin and its stdout the caller's
 * to write and read, until its finish frees it (process_start … process_finish);
 * NULL is none
 */
typedef struct process process_t;

/**
 * Start a child its caller talks to, and leave it running.
 *
 * Its stdin is a pipe the caller writes (process_write), its stdout one the caller
 * reads (process_read), its stderr dotta's own — what it says to a person reaches
 * the person, as git leaves ssh's. Its program is found as every child's is (the
 * header), in the environment `envp`, every other descriptor closed, in dotta's
 * working directory.
 *
 * The start answers once the program runs, as git's start_command reads its exec's
 * pipe: one that could not be run — no PATH entry holds it, its exec or a step
 * before it failed — is the start's refusal in its errno's words, "Cannot run
 * '<argv[0]>'", with no child left. The pipe or the fork it could not make is a
 * refusal naming argv[0], as process_run's are.
 *
 * @param argv NULL-terminated; argv[0] a name or a path (must not be NULL)
 * @param envp The child's environment, NULL-terminated (must not be NULL)
 * @param out The started child, the caller's to finish; NULL on a refusal
 * @return Error or NULL on success
 */
error_t process_start(char *const argv[], char *const envp[], process_t **out);

/**
 * Write every byte of `data` to a started child's stdin, a short write resumed
 * and a signal's interruption asked again. A child that is gone — its stdin closed,
 * or its end — is the refusal EPIPE (SIGPIPE ignored: the header). Each refusal
 * names its program.
 *
 * @param child Started child (must not be NULL)
 * @param data The bytes (must not be NULL where size is above 0)
 * @param size Byte count
 * @return Error or NULL on success
 */
error_t process_write(process_t *child, const void *data, size_t size);

/**
 * Read what a started child wrote to its stdout: one read, of at most `size`
 * bytes, waiting until the child writes or ends — its count in *out_len, 0 at
 * the child's end of output. A signal's interruption is asked again; a failed
 * read is a refusal naming its program.
 *
 * @param child Started child (must not be NULL)
 * @param data Where the bytes land (must not be NULL)
 * @param size Room in data, above 0: a read of no bytes could not tell the end
 * @param out_len Bytes read (must not be NULL); 0 on a refusal
 * @return Error or NULL on success
 */
error_t process_read(process_t *child, void *data, size_t size, size_t *out_len);

/**
 * Finish a started child: end what its caller holds of it, wait for it, report
 * how it ended, and free it.
 *
 * Its stdin is closed, then its stdout — a child that reads its stdin to its
 * end exits, and one still writing meets its reader gone (SIGPIPE) — and it is
 * reaped with no limit, as git's finish_command waits: one that will not end
 * once its stdin closes holds the finish until it ends or is killed. *result is
 * its wait status, as process_run reports it: no exec failure, which the start
 * answered for, no capture, no timeout. The handle is freed on every path, the
 * refusal of a wait that failed among them, naming its program. NULL is none:
 * *result zeroed.
 *
 * @param child Started child, or NULL
 * @param result Outcome (must not be NULL)
 * @return Error or NULL on success
 */
error_t process_finish(process_t *child, process_result_t *result);

/**
 * Exchange a request and an answer with a child, once, and wait for it — as git
 * runs a credential helper and an askpass (lib/git/credential.c
 * run_credential_helper, prompt.c do_askpass).
 *
 * Its stdin is a pipe its request is written into whole, then ended — or, with
 * no request (NULL), dotta's own, as git leaves an askpass's. Its stdout is a
 * pipe its answer is read from to its end — or, with no result wanted (NULL),
 * /dev/null, git's no_stdout for a helper's store and erase, and how it ended
 * is nobody's. Its stderr is dotta's own — what it says to a person reaches the
 * person, as git leaves a helper's. Its program is found as every child's is
 * (the header), in dotta's own environment, as git hands a helper and an askpass
 * its own, every other descriptor closed, in dotta's working directory.
 *
 * The exchange answers once the program runs, as the start does: one that could
 * not be run — no PATH entry holds it, its exec or a step before it failed — is
 * its refusal in its errno's words, "Cannot run '<argv[0]>'", before anything
 * is written to it and with no child left. The request is written before the
 * answer is read, as git writes it: a child gone before it read it is no refusal
 * (EPIPE, SIGPIPE ignored: the header), and one that answers past a pipe's room
 * before it reads a request past one holds the exchange, as it holds git's. The
 * answer is read to its end and kept to PROCESS_CAPTURE_MAX, the rest counted,
 * as FILE keeps a child's output (process_output_t) — so a task the child leaves
 * holding its stdout holds the exchange until that task ends. The child is reaped
 * with no limit, as git's finish_command waits — a child whose answer could not
 * be read among them, its stdout closed first.
 *
 * *result, where wanted, is how it ended, as process_run reports it, and its
 * answer in output: no exec failure, which the exchange answered for, no timeout;
 * zeroed on a refusal. The pipe, /dev/null, the fork, the read or the wait it
 * could not make is a refusal naming argv[0], as process_run's are.
 *
 * Readers: sys/credentials.c credential_helper, each of a helper's operations —
 * a "get" with its answer, a "store" and an "erase" with none — and
 * credential_ask_one, an askpass, with no request.
 *
 * @param argv NULL-terminated; argv[0] a name or a path (must not be NULL)
 * @param request What the child reads on its stdin, or NULL for none
 * @param size The request's bytes (0 where there is none)
 * @param result How it ended and its answer, or NULL for neither
 * @return Error or NULL on success
 */
error_t process_exchange(
    char *const argv[], const void *request, size_t size, process_result_t *result
);

/**
 * A command line a person configured, as the argv a wait runs: git's rule
 * (lib/git/run-command.c prepare_shell_cmd)
 *
 * argv[0] is the line, the rest its arguments. A line holding a character the
 * shell reads — git's set: `code --wait`, `vim -u NONE` — is the shell's to run,
 * /bin/sh -c '<line> "$@"' with the line its $0 and the arguments after it, so
 * each reaches the program as one word the shell never splits or expands; with
 * no argument, the line alone. Any other line is a program, its name or its path,
 * run as named with no shell between: argv's own vector. Never applied to a path
 * a caller made, where a directory holding a space would read as a line.
 *
 * Readers: sys/editor.c editor_launch; sys/ssh.c ssh_start; sys/credentials.c
 * credential_helper.
 *
 * @param argv The line, then its arguments, NULL-terminated (must not be NULL,
 *             nor argv[0])
 * @return The vector, the heap's: the caller frees it; argv's strings borrowed
 */
char **process_shell(char *const argv[]);

#endif /* DOTTA_PROCESS_H */
