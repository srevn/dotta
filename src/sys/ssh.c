/**
 * ssh.c - An SSH remote, reached as git reaches one: implementation
 *
 * A connection is libgit2's subtransport and its one stream in one value (ssh_t),
 * the stream a member: it holds nothing of its own and lives exactly as long as
 * its subtransport, which libgit2 frees the stream before closing and closes
 * before freeing (lib/libgit2/src/libgit2/transports/smart.c
 * git_smart__reset_stream, git_smart__free). The listing's action starts the
 * child (ssh_start), the service that follows it on the connection is the same
 * stream, and the stream's end finishes the child (ssh_finish) — or the close
 * does, where one still stands.
 */

#include "sys/ssh.h"

#include <stdlib.h>
#include <string.h>

#include <git2/sys/errors.h>
#include <git2/sys/transport.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/url.h"
#include "sys/process.h"

/* One connection: libgit2's subtransport, its one stream, and the child that
 * carries it */
typedef struct {
    git_smart_subtransport parent;           /* What libgit2 asks of it: action, close, free */
    git_smart_subtransport_stream stream;    /* The one stream a connection is, its own */
    git_remote *owner;                       /* Borrowed: its name and its store's configuration */
    process_t *child;                        /* NULL: none stands */
} ssh_t;

/**
 * The environment the child is started with, a string array in `arena`: the
 * process's own, less the names git takes out of what it starts for a remote,
 * each locating a repository or its configuration (lib/git/environment.c
 * local_repo_env) — a line the person configured may run git, which must not
 * read this process's repository as its own. An envp as it stands: the process's
 * environment holds HOME from its start (sys/identity.h), which no name here
 * takes out, so its spine exists and is ended.
 */
static void ssh_env(arena_t *arena, string_array_t *env) {
    extern char **environ;
    static const char *const names[] = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_OBJECT_DIRECTORY",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
        "GIT_PREFIX",
        "GIT_SHALLOW_FILE",
        "GIT_COMMON_DIR",
    };
    const size_t count = sizeof(names) / sizeof(names[0]);

    string_array_init(env, arena, 0);
    for (char **entry = environ; *entry; entry++) {
        /* An entry's name is what stands before its '=', compared whole */
        size_t len = strcspn(*entry, "=");
        size_t i;
        for (i = 0; i < count; i++) {
            if (strncmp(*entry, names[i], len) == 0 && names[i][len] == '\0') break;
        }

        if (i == count) string_array_push(env, *entry);
    }
}

/**
 * A path quoted for the shell ssh starts on the far side, into `arena`: whole
 * in single quotes, each ' and ! outside them, escaped — git's rule
 * (lib/git/quote.c sq_quote_buf), which is not base/string.h str_shell_quote's:
 * that one leaves a plain word bare, for a line a person reads back
 */
static const char *ssh_quote(arena_t *arena, const char *path) {
    /* At most four bytes for each of the path's, and the two quotes and the NUL */
    char *quoted = arena_alloc(arena, 4 * strlen(path) + 3);
    char *at = quoted;

    *at++ = '\'';
    for (const char *byte = path; *byte; byte++) {
        /* A ' ends the quotes, and so does a ! — csh's history reads one inside
         * them — so each is spelled outside, escaped, and the quotes open again */
        if (*byte == '\'' || *byte == '!') {
            *at++ = '\'';
            *at++ = '\\';
            *at++ = *byte;
            *at++ = '\'';
        } else {
            *at++ = *byte;
        }
    }
    *at++ = '\'';
    *at = '\0';

    return quoted;
}

/**
 * A string of the store's configuration into *out, the snapshot's own while it
 * stands; *out left as it stood where the configuration holds none. A key given
 * no value reads as "" (lib/libgit2/src/libgit2/config.c git_config_get_string),
 * so a command line given none is the empty command, where git dies on it
 */
static error_t ssh_string(git_config *config, const char *key, const char **out) {
    const char *value = NULL;
    int rc = git_config_get_string(&value, config, key);
    if (rc == GIT_ENOTFOUND) return NULL;
    if (rc < 0) return error_git(rc, "Cannot read '%s'", key);

    *out = value;
    return NULL;
}

/**
 * How a child that failed ended, as its error; NULL for one that exited 0
 *
 * The subject is ssh, the role, whatever program the person named: what went
 * wrong is in the child's own words, on the terminal above the op's failure, as
 * git leaves them.
 */
static error_t ssh_failure(const process_result_t *result) {
    if (result->signal_num) {
        return error_create(
            ERR_INTERNAL, "ssh terminated by signal %d", result->signal_num
        );
    }
    if (result->exit_code != 0) {
        return error_create(
            ERR_INTERNAL, "ssh exited with code %d", result->exit_code
        );
    }

    return NULL;
}

/**
 * Start the connection's child at `url`, the URL the listing's action is handed
 * (transports/smart.c git_smart__connect): the line git starts at protocol version
 * 0 (lib/git/connect.c git_connect, fill_ssh_args), read off the URL, the
 * environment and the store's configuration here, once, nothing of it kept. `key`
 * is the service's key in the remote's configuration, `program` git's own program
 * for the service.
 */
static int ssh_start(ssh_t *ssh, const char *url, const char *key, const char *program) {
    arena_t *frame = arena_create(0);
    git_config *config = NULL;

    /* The remote — its host, its port, its repository's path — read off the URL
     * as git splits it. A path or a host opening with '-' would be an option —
     * to the far side's program, or to ssh — and starts nothing, the path asked
     * first, as git asks (connect.c git_connect, fill_ssh_args); each refusal
     * names the part and no datum, for a host carries the URL's user, and a
     * password with it where one is written */
    url_ssh_t remote;
    error_t err = url_ssh(url, frame, &remote);
    if (!err && remote.path[0] == '-') {
        err = error_create(
            ERR_INVALID_ARG, "The URL's path opens with '-', an option to the "
            "remote's program"
        );
    }
    if (!err && remote.host[0] == '-') {
        err = error_create(
            ERR_INVALID_ARG, "The URL's host opens with '-', an option to ssh"
        );
    }

    /* The store's configuration, its strings read off one snapshot of it */
    if (!err) {
        int rc = git_repository_config_snapshot(&config, git_remote_owner(ssh->owner));
        if (rc < 0) err = error_git(rc, "Cannot read the store's configuration");
    }

    /* The command: GIT_SSH_COMMAND, then core.sshCommand — a line the person
     * configured, the shell's by git's rule — else GIT_SSH, else ssh: a program
     * run as named, with no shell between, a path holding a space among them
     * (connect.c get_ssh_command, fill_ssh_args). A setting that is set and empty
     * is the command, a name no PATH entry holds, as git takes it. */
    const char *line = getenv("GIT_SSH_COMMAND");
    if (!err && !line) err = ssh_string(config, "core.sshcommand", &line);

    /* The far side's program: the remote's own for the service where its
     * configuration names one, else git's (transport.c transport_get); a handle
     * with no name has no configuration of its own */
    const char *name = git_remote_name(ssh->owner);
    if (!err && name) {
        err = ssh_string(config, arena_str_format(frame, "remote.%s.%s", name, key), &program);
    }
    if (err) goto done;

    /* The line: <command> [-p <port>] <host> "<program> '<path>'", the port's
     * flag OpenSSH's for every command, git's variants unread (the header) */
    const char *named = getenv("GIT_SSH");
    string_array_t args;
    string_array_init(&args, frame, 5);
    string_array_push(&args, line ? line : named ? named : "ssh");
    if (remote.port) {
        string_array_push(&args, "-p");
        string_array_push(&args, remote.port);
    }
    string_array_push(&args, remote.host);
    string_array_pushf(&args, "%s %s", program, ssh_quote(frame, remote.path));

    /* Started on its two pipes, its refusal the action's: a program nothing holds,
     * an exec that failed (sys/process.h process_start) */
    string_array_t env;
    ssh_env(frame, &env);

    char **shell = line ? process_shell(args.entries) : NULL;
    err = process_start(shell ? shell : args.entries, env.entries, &ssh->child);
    free(shell);

done:
    git_config_free(config);
    arena_free(frame);

    return error_to_git(err);
}

/**
 * The connection's end, met in its stream — a read's end of output, a write's
 * refusal: the child finished here, before libgit2 words the end
 *
 * How the child failed is the op's cause, outranking the read's or the write's
 * own refusal — a download whose child has gone says how it ended, where the
 * write alone would say "Broken pipe" — and a refusal outranks a clean end. A
 * child that exited 0 at its end of output is libgit2's to word: 0, and no byte
 * read.
 */
static int ssh_finish(ssh_t *ssh, error_t cause) {
    process_result_t result;
    error_t err = process_finish(ssh->child, &result);
    ssh->child = NULL;

    if (!err) err = ssh_failure(&result);
    if (!err) err = cause;

    return error_to_git(err);
}

/**
 * libgit2's read: the bytes the child wrote, or the stream's end
 *
 * libgit2 reads no more once a read gives 0 or fails (transports/smart_protocol.c
 * git_smart__store_refs, recv_pkt, no_sideband, parse_report), so no read meets
 * a connection whose child has ended: where one did, it would die at process_read's
 * check, the tree's answer to a broken contract.
 */
static int ssh_stream_read(
    git_smart_subtransport_stream *stream, char *buffer, size_t size, size_t *out_len
) {
    ssh_t *ssh = (ssh_t *) stream->subtransport;

    error_t err = process_read(ssh->child, buffer, size, out_len);
    if (!err && *out_len > 0) return 0;

    return ssh_finish(ssh, err);
}

/**
 * libgit2's write: every byte, or the stream's end
 *
 * libgit2 writes only after an action (transports/smart.c
 * git_smart__negotiation_step, git_smart__get_push_stream) and none once a write
 * failed, so no write meets a connection whose child has ended (ssh_stream_read).
 */
static int ssh_stream_write(
    git_smart_subtransport_stream *stream, const char *buffer, size_t len
) {
    ssh_t *ssh = (ssh_t *) stream->subtransport;

    error_t err = process_write(ssh->child, buffer, len);
    return err ? ssh_finish(ssh, err) : 0;
}

/* libgit2's free of the stream: nothing, the stream the connection's own, freed
 * with it (ssh_free) */
static void ssh_stream_free(git_smart_subtransport_stream *stream) {
    (void) stream;
}

/**
 * libgit2's action: a listing's starts the connection's child; the service that
 * follows the listing on the connection is the same stream
 */
static int ssh_action(
    git_smart_subtransport_stream **out, git_smart_subtransport *subtransport,
    const char *url, git_smart_service_t service
) {
    ssh_t *ssh = (ssh_t *) subtransport;

    *out = &ssh->stream;
    switch (service) {
        case GIT_SERVICE_UPLOADPACK_LS:
            return ssh_start(ssh, url, "uploadpack", "git-upload-pack");
        case GIT_SERVICE_RECEIVEPACK_LS:
            return ssh_start(ssh, url, "receivepack", "git-receive-pack");
        case GIT_SERVICE_UPLOADPACK:
        case GIT_SERVICE_RECEIVEPACK:
            /* The same stream while its child stands. With none — its stream
             * ended — refused: the close asks this before the goodbye flush it
             * writes (transports/smart.c git_smart__close), so no flush is written
             * to no child, and nothing reads the sentence */
            if (ssh->child) return 0;

            (void) git_error_set_str(GIT_ERROR_SSH, "the connection has ended");
            return GIT_ERROR;
    }

    CHECK_ARG(false, "a service no enumerator names");
}

/**
 * libgit2's close: a child still standing finished, its status unread (the header)
 * — one whose service completed, or that listed alone, as git's disconnect reads
 * none (lib/git/transport.c disconnect_git). libgit2 closes before each listing's
 * action, and again as it frees, so a close with no child does nothing.
 */
static int ssh_close(git_smart_subtransport *subtransport) {
    ssh_t *ssh = (ssh_t *) subtransport;

    process_result_t result;
    (void) process_finish(ssh->child, &result);
    ssh->child = NULL;

    return 0;
}

/* libgit2's free: the connection and its stream, closed before it
 * (transports/smart.c git_smart__free) */
static void ssh_free(git_smart_subtransport *subtransport) {
    free(subtransport);
}

/* The connection, made for libgit2's smart transport: its two faces wired, handed
 * the handle its transport was made for */
static int ssh_subtransport(
    git_smart_subtransport **out, git_transport *transport, void *owner
) {
    (void) transport;

    ssh_t *ssh = heap_alloc(sizeof(*ssh));
    *ssh = (ssh_t){
        .parent = { .action = ssh_action, .close = ssh_close, .free = ssh_free },
        .stream = {
            .subtransport = &ssh->parent,
            .read         = ssh_stream_read,
            .write        = ssh_stream_write,
            .free         = ssh_stream_free,
        },
        .owner = owner,
    };

    *out = &ssh->parent;
    return 0;
}

int ssh_transport(git_transport **out, git_remote *owner) {
    CHECK_NULL(out);
    CHECK_NULL(owner);

    /* libgit2's smart transport over the connection, stateful — one stream a
     * connection — the definition read within the call alone
     * (lib/libgit2/src/libgit2/transports/smart.c git_transport_smart) */
    return git_transport_smart(
        out, owner, &(git_smart_subtransport_definition){ ssh_subtransport, 0, owner }
    );
}
