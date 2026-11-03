/**
 * remote.c - The store's remote, met once a command: implementation
 *
 * See remote.h. Every op the session makes is one libgit2 network call — the
 * connect, the download, a push's connect and upload — wrapped in sys/transfer's
 * op and handed its options whole, as a connected remote takes the options each
 * op hands it in place of the last (lib/libgit2/src/libgit2/remote.c
 * connect_or_reset_options): transfer's callbacks for its direction, and the
 * proxy git's configuration names, no credential callback beside it, so the
 * remote's credential is never a proxy's answer. Its failure's sentence is read
 * before anything closes: a close may set libgit2's error over the op's
 * (transports/smart.c git_smart__close writes a flush to the connection). Every
 * ref written here, in the store or on the remote, is written from its writer's
 * read: a tracking ref through sys/gitops' writers (gitops_write_reference,
 * gitops_delete_reference) — the session's and the forget's — the remote's through
 * the push's compare.
 */

#include "sys/remote.h"

#include <fcntl.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

#define REMOTE_HEADS "refs/heads/"   /* a branch's ref, and its name past it */
#define REMOTE_KEPT  "dotta.remote"  /* the branch names an open listed, beside dotta.db */

struct remote {
    arena_t *arena;             /* The handle's own: itself, the listing it copies, the names it lends */
    git_repository *repo;       /* Borrowed */
    git_remote *git;            /* libgit2's, looked up once; connected from the open to its fetch or push */
    transfer_context_t *xfer;   /* What libgit2 calls back into during each op */
    const char *action;         /* The command's word, every reflog line's; borrowed */
    hashmap_t *advertised;      /* Every ref the open listed: its name, and its id (git_oid *) */
    string_array_t branches;    /* The names under refs/heads/, in the listing's order */
};

/*
 * Where the branch names an open listed are kept: beside the store's database,
 * in the directory libgit2 names for every repository it opened
 * (lib/libgit2/src/libgit2/repository.c git_repository_path), spelled with its
 * separator where libgit2's spelling lacks one. One spelling for the keep and
 * its reader (remote_keep_branches, remote_last_branches).
 */
static const char *remote_kept_path(git_repository *repo, arena_t *arena) {
    const char *git_dir = git_repository_path(repo);

    return arena_str_format(
        arena, "%s%s" REMOTE_KEPT, git_dir, str_ends_with(git_dir, "/") ? "" : "/"
    );
}

/*
 * What the kept names' file holds, into `out` (BUFFER_INIT): nothing where none
 * stands or it will not read whole — a regular file, opened waiting on nothing,
 * a FIFO refused at once (sys/filesystem.h fs_read_fd). dotta's own artifact,
 * read by a raw call (sys/filesystem.h): the invoker's by construction. One read
 * for the keep and its reader, so the two compare what one reading holds.
 */
static void remote_kept_read(const char *path, buffer_t *out) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return;

    /* The descriptor's own look, and the read of what it says, which leaves nothing
     * where it refuses (sys/filesystem.h fs_read_fd) */
    struct stat st;
    if (fstat(fd, &st) == 0) (void) fs_read_fd(fd, &st, out);
    close(fd);
}

/*
 * Keep the branch names the open listed (remote_last_branches reads them): each
 * on a line of its own, in the listing's order — names alone, which is all
 * completion asks, and an id the store may hold no object of would answer nothing
 * else. A branch name holds no newline (Git's reference rule).
 *
 * Written only where the file holds other bytes, into a temporary beside it that
 * is renamed over it, so a reader meets the old names or the new, whole. dotta's
 * own artifact, by raw calls (sys/filesystem.h): the invoker's by construction,
 * 0600 from mkstemp. A step that fails drops the keep and takes its temporary
 * back — completion alone reads the names, and the next open keeps them again;
 * a process killed between the temporary and the rename leaves the temporary
 * beside the file.
 */
static void remote_keep_branches(const remote_t *remote) {
    const char *path = remote_kept_path(remote->repo, remote->arena);

    buffer_t names = BUFFER_INIT;
    for (size_t i = 0; i < remote->branches.count; i++) {
        buffer_appendf(&names, "%s\n", remote->branches.entries[i]);
    }

    /* An empty listing's buffer holds no pointer, and memcmp is undefined over
     * a null one even across zero bytes (infra/compare.c judge) */
    buffer_t kept = BUFFER_INIT;
    remote_kept_read(path, &kept);
    if (kept.size != names.size ||
        (names.size > 0 && memcmp(kept.data, names.data, names.size) != 0)) {
        /* A failed mkstemp created no file, and its template may now name one
         * that is not ours: nothing below it runs, the unlink included */
        char *temp = arena_str_format(remote->arena, "%s.XXXXXX", path);
        int fd = mkstemp(temp);
        if (fd >= 0) {
            error_t err = fs_write_fd(fd, temp, names.data, names.size);
            if (close(fd) != 0 || err || rename(temp, path) != 0) unlink(temp);
        }
    }

    buffer_deinit(&kept);
    buffer_deinit(&names);
}

error_t remote_default(git_repository *repo, arena_t *arena, const char **out) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    git_strarray remotes = { 0 };
    int rc = git_remote_list(&remotes, repo);
    if (rc < 0) return error_git(rc, "Cannot list the remotes");

    if (remotes.count == 0) {
        git_strarray_dispose(&remotes);
        return error_create(ERR_NOT_FOUND, "No remotes configured");
    }

    /* Select: "origin" wins; otherwise sole remote; otherwise ambiguous. */
    const char *selected = NULL;
    for (size_t i = 0; i < remotes.count; i++) {
        if (strcmp(remotes.strings[i], "origin") == 0) {
            selected = "origin";
            break;
        }
    }
    if (!selected && remotes.count == 1) {
        selected = remotes.strings[0];
    }
    if (!selected) {
        git_strarray_dispose(&remotes);
        return error_create(
            ERR_INVALID_ARG, "Multiple remotes configured, but no 'origin' found"
        );
    }

    *out = arena_strdup(arena, selected);
    git_strarray_dispose(&remotes);

    return NULL;
}

error_t remote_open(
    git_repository *repo, const char *name, const char *action, output_t *output,
    remote_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(action);
    CHECK_NULL(output);
    CHECK_NULL(out);

    *out = NULL;

    /* The remote, looked up once: a name Git refuses, or none by it, refused in
     * Git's words */
    git_remote *git = NULL;
    int rc = git_remote_lookup(&git, repo, name);
    if (rc < 0) return error_git(rc, "Cannot reach remote '%s'", name);

    /* The handle in an arena of its own, made here and freed with it, beside
     * the listing it copies and the names it lends: from here every failure frees
     * through remote_free. The transfer is told no URL: each credential the helper
     * fills is kept under the URL that asked for it, the fetch URL's or the push
     * URL's (lib/libgit2/src/libgit2/remote.c git_remote__urlfordirection), and
     * judged there (sys/transfer.h). */
    arena_t *arena = arena_create(0);
    remote_t *remote = arena_calloc(arena, 1, sizeof(*remote));
    remote->arena = arena;
    remote->repo = repo;
    remote->git = git;
    remote->action = action;
    remote->xfer = transfer_context_create(output);

    /* The open's one op: the connect for upload-pack, which reads the remote's
     * advertisement — no byte of a pack moves, so no frame is drawn */
    git_remote_connect_options opts;
    git_remote_connect_options_init(&opts, GIT_REMOTE_CONNECT_OPTIONS_VERSION);
    transfer_configure_callbacks(&opts.callbacks, remote->xfer, GIT_DIRECTION_FETCH);
    opts.proxy_opts.type = GIT_PROXY_AUTO;

    transfer_op_begin(remote->xfer);
    rc = git_remote_connect_ext(git, GIT_DIRECTION_FETCH, &opts);
    transfer_op_end(remote->xfer, rc);

    const git_remote_head **heads = NULL;
    size_t count = 0;
    if (rc == 0) rc = git_remote_ls(&heads, &count, git);
    if (rc < 0) {
        /* The sentence before the free, which closes what the connect opened:
         * libgit2's cause, but where it read the URL as a path and found no
         * directory there. A URL with no ':' is a path to libgit2 only where a
         * directory stands, and otherwise names no transport at all, "unsupported
         * URL protocol" (lib/libgit2/src/libgit2/transport.c transport_find_fn),
         * so there the cause is what libgit2 found, looked at as it looks — a
         * stat through a link, as the invoker: a raw call (sys/filesystem.h) —
         * and the path is said, which carries no credential. The open's connect
         * alone chooses a transport: a push's reuses it (remote.c
         * git_remote_connect_ext), and a path gone since reads libgit2's words,
         * which name it. */
        const char *url = git_remote_url(git);
        struct stat st;
        error_t err;
        if (url && !strchr(url, ':') && (stat(url, &st) != 0 || !S_ISDIR(st.st_mode))) {
            err = error_create(
                ERR_NOT_FOUND, "Cannot reach remote '%s': no directory at '%s'", name, url
            );
        } else {
            err = error_git(rc, "Cannot reach remote '%s'", name);
        }
        remote_free(remote);
        return err;
    }

    /* What the remote advertises, copied: each ref's name and id, and the branches
     * among them in the listing's order. A name holding '^' is no ref — Git's
     * reference rule refuses the character: it is the line a listing adds beside
     * a ref that names a tag, `<ref>^{}` and the commit the tag peels to
     * (lib/git/upload-pack.c write_v0_ref, transports/local.c add_ref), and is
     * copied never, as git's fetch passes it over (lib/git/remote.c
     * get_expanded_map: "a dereference item") */
    remote->advertised = hashmap_create(arena, count);
    string_array_init(&remote->branches, arena, 0);
    for (size_t i = 0; i < count; i++) {
        if (strchr(heads[i]->name, '^')) continue;

        git_oid *id = arena_alloc(arena, sizeof(*id));
        git_oid_cpy(id, &heads[i]->oid);
        hashmap_set(remote->advertised, heads[i]->name, id);

        if (str_starts_with(heads[i]->name, REMOTE_HEADS)) {
            string_array_push(&remote->branches, heads[i]->name + strlen(REMOTE_HEADS));
        }
    }

    /* The branch names kept for completion, beside the store's database */
    remote_keep_branches(remote);

    *out = remote;
    return NULL;
}

void remote_advertised(const remote_t *remote, const char *refname, git_oid *out) {
    CHECK_NULL(remote);
    CHECK_NULL(refname);
    CHECK_NULL(out);

    const git_oid *id = hashmap_get(remote->advertised, refname);
    if (id) {
        git_oid_cpy(out, id);
    } else {
        memset(out, 0, sizeof(*out));
    }
}

const string_array_t *remote_branches(const remote_t *remote) {
    CHECK_NULL(remote);

    return &remote->branches;
}

string_array_t remote_last_branches(git_repository *repo, arena_t *arena) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);

    buffer_t kept = BUFFER_INIT;
    remote_kept_read(remote_kept_path(repo, arena), &kept);

    /* A name a line, as the open kept them: a line and its newline are one step */
    string_array_t names;
    string_array_init(&names, arena, 0);
    const char *line = kept.data;
    while (line && *line) {
        const size_t len = strcspn(line, "\n");
        string_array_pushf(&names, "%.*s", (int) len, line);
        line += len + (line[len] == '\n');
    }

    buffer_deinit(&kept);
    return names;
}

error_t remote_fetch(
    remote_t *remote, const string_array_t *branches, const char *refname,
    transfer_wire_t *received
) {
    CHECK_NULL(remote);
    CHECK_NULL(branches);
    CHECK_ARG(
        git_remote_connected(remote->git),
        "a session fetches once, on the connection its open listed"
    );

    git_repository *repo = remote->repo;
    const char *name = git_remote_name(remote->git);

    /* The fetched branches' refs and the tracking refs in their way, in a frame
     * of this call's own — its answer is no memory. The tracking refs are listed
     * whole first, complete or an error, for the ones in a fetched name's way
     * (the header). */
    arena_t *frame = arena_create(0);
    string_array_t fetched, blockers, tracking, refspecs;
    string_array_init(&fetched, frame, branches->count);
    string_array_init(&blockers, frame, 0);
    transfer_wire_t wire = { 0 };
    error_t err = gitops_list_remote_tracking(repo, name, frame, &tracking);
    if (err) goto done;

    for (size_t i = 0; i < branches->count; i++) {
        const char *branch = branches->entries[i];

        /* The branch's ref, spelled where every one is: one the remote does not
         * advertise is not fetched, and nothing is written for it */
        char ref[DOTTA_REFNAME_MAX];
        err = gitops_branch_refname(ref, sizeof(ref), branch);
        if (err) goto done;
        if (!hashmap_has(remote->advertised, ref)) continue;

        /* Barred where a tracking ref in its way (gitops_nested) stands beside
         * its own branch here: that branch's counterpart, never taken out, so
         * the name is not fetched (the header) */
        bool barred = false;
        for (size_t j = 0; j < tracking.count && !barred; j++) {
            if (!gitops_nested(tracking.entries[j], branch)) continue;
            err = gitops_branch_exists(repo, tracking.entries[j], &barred);
            if (err) goto done;
        }
        if (barred) continue;

        /* Otherwise each one in its way is taken out, once however many names
         * it stands in the way of */
        for (size_t j = 0; j < tracking.count; j++) {
            if (!gitops_nested(tracking.entries[j], branch)) continue;
            if (!string_array_contains(&blockers, tracking.entries[j])) {
                string_array_push(&blockers, tracking.entries[j]);
            }
        }
        string_array_push(&fetched, ref);
    }

    /* What the download asks for: each fetched branch's ref, then the caller's
     * where the remote advertises it — a source alone each, its objects wanted
     * and no ref named for them — in the one shape git_strarray reads: a string
     * array's entries are an argv as they stand */
    string_array_clone(&fetched, frame, &refspecs);
    if (refname && hashmap_has(remote->advertised, refname)) {
        string_array_push(&refspecs, refname);
    }

    /* The download, on the connection the open listed, and the download alone:
     * it writes no ref and no FETCH_HEAD and prunes nothing, the update of the
     * tips and the prune being git_remote_fetch's (remote.c git_remote_fetch) —
     * and no tag is followed, whatever remote.<remote>.tagOpt says (fetch.c
     * filter_wants): an option whose value would change what dotta's own fetch
     * answers is set here. A fetch of nothing asks nothing of the remote, where
     * an empty list would download its configured refspecs (remote.c
     * git_remote__download). */
    if (refspecs.count > 0) {
        git_fetch_options opts;
        git_fetch_options_init(&opts, GIT_FETCH_OPTIONS_VERSION);
        transfer_configure_callbacks(&opts.callbacks, remote->xfer, GIT_DIRECTION_FETCH);
        opts.proxy_opts.type = GIT_PROXY_AUTO;
        opts.download_tags = GIT_REMOTE_DOWNLOAD_TAGS_NONE;
        git_strarray refs = { refspecs.entries, refspecs.count };

        transfer_op_begin(remote->xfer);
        int rc = git_remote_download(remote->git, &refs, &opts);
        wire = transfer_op_end(remote->xfer, rc);
        if (rc < 0) {
            err = error_git(rc, "Cannot fetch from remote '%s'", name);
            goto done;
        }
    }

    /* Each one in the way taken out once the objects are here — a download that
     * failed takes nothing out — and from its read: one gone since the listing
     * leaves nothing to take, one moved since its read refuses (sys/gitops.h
     * gitops_delete_reference) */
    for (size_t i = 0; i < blockers.count; i++) {
        char ref[DOTTA_REFNAME_MAX];
        git_oid id;
        err = gitops_remote_branch_refname(ref, sizeof(ref), name, blockers.entries[i]);
        if (!err) err = gitops_reference_oid(repo, ref, &id);
        if (!err && !git_oid_is_zero(&id)) err = gitops_delete_reference(repo, ref, &id);
        if (err) goto done;
    }

    /* Each fetched branch's tracking ref, written after its objects — a ref must
     * name an object the store holds (lib/libgit2/src/libgit2/refs.c
     * reference__create) — from the head it read there, read and written in one
     * step a name: the listing's absence is its read, the null id, never looked
     * up again, as each name is written once, and a ref that names the advertised
     * head already is left alone */
    for (size_t i = 0; i < fetched.count; i++) {
        const char *ref = fetched.entries[i];
        const char *branch = ref + strlen(REMOTE_HEADS);

        char tracking_ref[DOTTA_REFNAME_MAX];
        err = gitops_remote_branch_refname(tracking_ref, sizeof(tracking_ref), name, branch);
        if (err) goto done;

        git_oid head;
        git_oid read = GIT_OID_SHA1_ZERO;
        remote_advertised(remote, ref, &head);
        if (string_array_contains(&tracking, branch)) {
            err = gitops_reference_oid(repo, tracking_ref, &read);
            if (err) goto done;
        }
        if (git_oid_equal(&read, &head)) continue;

        /* Forward alone: a ref that stands moves only where the advertised head
         * descends from it, its objects the download's; where the remote left
         * its line it stands, for the act that takes the remote's head (the
         * header) */
        if (!git_oid_is_zero(&read)) {
            int rc = git_graph_descendant_of(repo, &head, &read);
            if (rc < 0) {
                err = error_git(rc, "Cannot read '%s' against the remote's head", tracking_ref);
                goto done;
            }
            if (rc == 0) continue;
        }

        err = gitops_write_reference(
            repo, tracking_ref, &head, &read, remote->action, "fetched from %s", name
        );
        if (err) goto done;
    }

    if (received) *received = wire;

done:
    /* The listing's connection, closed whatever the fetch did: the fetch is its
     * last use, and the download's sentence is read above */
    git_remote_disconnect(remote->git);
    arena_free(frame);
    return err;
}

/*
 * A branch's tracking ref, moved after a push that landed: to the commit it pushed,
 * or deleted where it pushed the branch's deletion and the ref stands — from
 * the ref's read, as every write is (sys/gitops.h gitops_write_reference). A
 * follow that will not land — another writer's move since the read, a name in
 * its way in Git's namespace, a lock another process holds — is no push's failure,
 * the push having landed, and leaves the ref as it stands: the next fetch moves
 * it where the remote's head continues its line, else the next act on the branch
 * (remote_take).
 */
static void remote_follow(remote_t *remote, const char *branch, const git_oid *target) {
    const char *name = git_remote_name(remote->git);

    char ref[DOTTA_REFNAME_MAX];
    git_oid read;
    error_t err = gitops_remote_branch_refname(ref, sizeof(ref), name, branch);
    if (!err) err = gitops_reference_oid(remote->repo, ref, &read);
    if (err || git_oid_equal(&read, target)) return;

    if (git_oid_is_zero(target)) {
        (void) gitops_delete_reference(remote->repo, ref, &read);
    } else {
        (void) gitops_write_reference(
            remote->repo, ref, target, &read, remote->action, "pushed to %s", name
        );
    }
}

error_t remote_push(
    remote_t *remote, const char *refname, const git_oid *target, const git_oid *expected,
    transfer_wire_t *sent
) {
    CHECK_NULL(remote);
    CHECK_NULL(refname);
    CHECK_NULL(target);
    CHECK_NULL(expected);
    CHECK_ARG(
        !git_oid_is_zero(target) || !git_oid_is_zero(expected),
        "a push names the commit its ref is to name, or the one its deletion takes"
    );

    const char *name = git_remote_name(remote->git);

    /* The update: the commit itself, forced — libgit2's own fast-forward check
     * lifted (lib/libgit2/src/libgit2/push.c queue_objects), the compare below
     * the push's one rule — or nothing, a deletion; an argv of one, as the upload
     * reads it. A name and an id fit the refspec's buffer by its definition
     * (DOTTA_REFSPEC_MAX). */
    char refspec[DOTTA_REFSPEC_MAX];
    error_t err;
    if (git_oid_is_zero(target)) {
        err = gitops_build_refname(refspec, sizeof(refspec), ":%s", refname);
    } else {
        char hex[GIT_OID_SHA1_HEXSIZE + 1];
        git_oid_tostr(hex, sizeof(hex), target);
        err = gitops_build_refname(refspec, sizeof(refspec), "+%s:%s", hex, refname);
    }
    if (err) return err;
    char *refspecs[] = { refspec };
    git_strarray refs = { refspecs, 1 };

    /* The listing's connection closed first, where it stands: a path remote's
     * connect answers from the connection it holds (transports/local.c
     * local_connect), so the push would compare and negotiate against the open's
     * listing; and a smart one's close says goodbye (transports/smart.c
     * git_smart__close), where a connect over it drops it unsaid
     * (git_smart__connect) */
    git_remote_disconnect(remote->git);

    git_push_options opts;
    git_push_options_init(&opts, GIT_PUSH_OPTIONS_VERSION);
    transfer_configure_callbacks(&opts.callbacks, remote->xfer, GIT_DIRECTION_PUSH);
    opts.proxy_opts.type = GIT_PROXY_AUTO;

    /* The push's own connection, for receive-pack, its op the connect alone as
     * the open's is: its listing, read on it, names the ref as the remote holds
     * it now */
    transfer_op_begin(remote->xfer);
    int rc = git_remote_connect(
        remote->git, GIT_DIRECTION_PUSH, &opts.callbacks, &opts.proxy_opts, NULL
    );
    transfer_op_end(remote->xfer, rc);

    const git_remote_head **heads = NULL;
    size_t count = 0;
    if (rc == 0) rc = git_remote_ls(&heads, &count, remote->git);
    if (rc < 0) {
        /* The sentence before the close, which may set one of its own */
        err = error_git(rc, "Cannot push '%s' to remote '%s'", refname, name);
        git_remote_disconnect(remote->git);
        return err;
    }

    /* Sent only where that listing names what its writer read, the null id where
     * it names none — the listing libgit2's negotiation reads too (push.c
     * calculate_work) — so a refusal sends nothing */
    git_oid listed = GIT_OID_SHA1_ZERO;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(heads[i]->name, refname) == 0) {
            git_oid_cpy(&listed, &heads[i]->oid);
            break;
        }
    }
    if (!git_oid_equal(&listed, expected)) {
        git_remote_disconnect(remote->git);
        return error_create(
            ERR_CONFLICT, "Reference '%s' on remote '%s' was changed by another writer "
            "since this command read it", refname, name
        );
    }

    /* The upload, on that connection (remote.c connect_or_reset_options), an op
     * of its own: its sentence read before the close, the remote's words where
     * it refused the ref (sys/transfer.h transfer_push_status_callback) */
    transfer_op_begin(remote->xfer);
    rc = git_remote_upload(remote->git, &refs, &opts);
    const transfer_wire_t wire = transfer_op_end(remote->xfer, rc);
    err = rc < 0 ? error_git(rc, "Cannot push '%s' to remote '%s'", refname, name) : NULL;
    git_remote_disconnect(remote->git);
    if (err) return err;

    if (sent) *sent = wire;

    /* The branch's tracking ref follows it, or is the next fetch's or act's to
     * move */
    if (str_starts_with(refname, REMOTE_HEADS)) {
        remote_follow(remote, refname + strlen(REMOTE_HEADS), target);
    }

    return NULL;
}

void remote_take(remote_t *remote, const char *branch) {
    CHECK_NULL(remote);
    CHECK_NULL(branch);

    const char *name = git_remote_name(remote->git);

    /* The remote's head as the open listed it, under the branch's own ref: none
     * listed, nothing to take */
    char ref[DOTTA_REFNAME_MAX];
    git_oid head;
    error_t err = gitops_branch_refname(ref, sizeof(ref), branch);
    if (err) return;
    remote_advertised(remote, ref, &head);
    if (git_oid_is_zero(&head)) return;

    /* Its tracking ref from its read, left alone where it names that head, and
     * where the read or the write will not land (the header) */
    char tracking_ref[DOTTA_REFNAME_MAX];
    git_oid read;
    err = gitops_remote_branch_refname(tracking_ref, sizeof(tracking_ref), name, branch);
    if (!err) err = gitops_reference_oid(remote->repo, tracking_ref, &read);
    if (err || git_oid_equal(&read, &head)) return;

    (void) gitops_write_reference(
        remote->repo, tracking_ref, &head, &read, remote->action, "fetched from %s", name
    );
}

error_t remote_forget(git_repository *repo, const char *name, size_t *forgotten) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(forgotten);

    *forgotten = 0;

    /* The remote's tracking refs and the branches here, each listed whole, in a
     * frame of this call's own: its answer is a count */
    arena_t *frame = arena_create(0);
    string_array_t tracking, branches;
    error_t err = gitops_list_remote_tracking(repo, name, frame, &tracking);
    if (!err) err = gitops_list_branches(repo, frame, &branches);
    if (err) goto done;

    /* Each beside a branch here forgotten from its read: one gone since the listing
     * leaves nothing to forget, one moved since its read refuses (sys/gitops.h
     * gitops_delete_reference) */
    for (size_t i = 0; i < tracking.count; i++) {
        if (!string_array_contains(&branches, tracking.entries[i])) continue;

        char ref[DOTTA_REFNAME_MAX];
        git_oid id;
        err = gitops_remote_branch_refname(ref, sizeof(ref), name, tracking.entries[i]);
        if (!err) err = gitops_reference_oid(repo, ref, &id);
        if (err) goto done;
        if (git_oid_is_zero(&id)) continue;

        err = gitops_delete_reference(repo, ref, &id);
        if (err) goto done;
        (*forgotten)++;
    }

done:
    arena_free(frame);
    return err;
}

void remote_free(remote_t *remote) {
    if (!remote) return;

    /* What the arena does not hold first, read off the handle while it stands:
     * the remote, its listing's connection closed where it stands (remote.c
     * git_remote_free), then the transfer — each credential's verdict, told the
     * helper; then the arena, and the handle with it and every name it lent */
    git_remote_free(remote->git);
    transfer_context_free(remote->xfer);
    arena_free(remote->arena);
}

/*
 * The branch here and its tracking ref, read now, each Git's null id where none
 * stands (sys/gitops.h gitops_reference_oid): the branch at `ref`, which its
 * caller spells through the branch rule (gitops_branch_refname) and the remote's
 * listing holds it under too, and its tracking ref, of the name past refs/heads/.
 * One read for the session's reading and the last one (remote_relation,
 * remote_last_relation), so the two relate what one read holds.
 */
static error_t remote_read_heads(
    git_repository *repo, const char *name, const char *ref, git_oid *local,
    git_oid *tracking
) {
    char tracking_ref[DOTTA_REFNAME_MAX];
    error_t err = gitops_remote_branch_refname(
        tracking_ref, sizeof(tracking_ref), name, ref + strlen(REMOTE_HEADS)
    );
    if (!err) err = gitops_reference_oid(repo, ref, local);
    if (!err) err = gitops_reference_oid(repo, tracking_ref, tracking);

    return err;
}

/*
 * A head against the line it is read against, its counterpart (remote_counterpart):
 * the three answers a reading tells apart (remote.h remote_state_t)
 */
typedef enum {
    REMOTE_COUNTERPART_WITHIN,  /* Every commit of the head the line's: the two alike, or the head behind */
    REMOTE_COUNTERPART_BEYOND,  /* The head shares the line's history and holds commits it lacks */
    REMOTE_COUNTERPART_NONE     /* No counterpart: no commit shared, or no head or no line to read */
} remote_counterpart_t;

/*
 * `head` read against the line `line` names, its counterpart: within it, beyond
 * it, or none — and where beyond, the commits the head holds that the line lacks
 * counted into `ahead`, which nothing else writes
 */
static error_t remote_counterpart(
    git_repository *repo, const git_oid *head, const git_oid *line,
    remote_counterpart_t *out, size_t *ahead
) {
    /* No head or no line is no counterpart, and two heads alike are within: no
     * walk for either */
    if (git_oid_is_zero(head) || git_oid_is_zero(line)) {
        *out = REMOTE_COUNTERPART_NONE;
        return NULL;
    }
    if (git_oid_equal(head, line)) {
        *out = REMOTE_COUNTERPART_WITHIN;
        return NULL;
    }

    /* Their merge base tells the three apart (sys/gitops.h gitops_find_merge_base):
     * none, no commit shared; the head itself, within the line; any other, beyond
     * it */
    git_oid base;
    error_t err = gitops_find_merge_base(repo, head, line, &base);
    if (err) return err;

    *out = git_oid_is_zero(&base)
         ? REMOTE_COUNTERPART_NONE : git_oid_equal(&base, head)
         ? REMOTE_COUNTERPART_WITHIN : REMOTE_COUNTERPART_BEYOND;

    if (*out != REMOTE_COUNTERPART_BEYOND) return NULL;

    /* Beyond it: the commits the head holds that the line lacks, counted */
    size_t behind = 0;
    int rc = git_graph_ahead_behind(ahead, &behind, repo, head, line);
    if (rc < 0) return error_git(rc, "Cannot count the commits between two heads");

    return NULL;
}

/*
 * The reading of three heads, into `out` with them, each question of the history
 * asked where the reading turns on its answer: no branch here, no branch on the
 * remote, the two alike, a re-creation, then the branch against the remote's head
 */
static error_t remote_relate(
    git_repository *repo, const git_oid *local, const git_oid *tracking,
    const git_oid *remote, remote_relation_t *out
) {
    *out = (remote_relation_t){ .local = *local, .tracking = *tracking, .remote = *remote };

    /* No branch here: none on the remote either, its tracking ref telling a
     * deletion from a name the remote never held; else created where it comes
     * back from — the tracking ref where the remote's head is its counterpart
     * and it stands beyond it, the remote's head otherwise */
    if (git_oid_is_zero(local)) {
        if (git_oid_is_zero(remote)) {
            out->state = git_oid_is_zero(tracking)
                       ? REMOTE_STATE_NO_LOCAL_NO_REMOTE : REMOTE_STATE_NO_LOCAL_DELETED;
            return NULL;
        }

        remote_counterpart_t counterpart;
        error_t err = remote_counterpart(repo, tracking, remote, &counterpart, &out->ahead);
        if (err) return err;

        out->state = counterpart == REMOTE_COUNTERPART_BEYOND
                   ? REMOTE_STATE_NO_LOCAL_AHEAD : REMOTE_STATE_NO_LOCAL;

        out->from = counterpart == REMOTE_COUNTERPART_BEYOND ? *tracking : *remote;
        return NULL;
    }

    /* No branch on the remote: deleted there where its tracking ref is the branch's
     * counterpart — the branch within it, or beyond it — and never published
     * where it has none: no tracking ref, or one sharing nothing with the branch
     * (a profile recreated here) */
    if (git_oid_is_zero(remote)) {
        remote_counterpart_t counterpart;
        error_t err = remote_counterpart(repo, local, tracking, &counterpart, &out->ahead);
        if (err) return err;

        out->state = counterpart == REMOTE_COUNTERPART_WITHIN
                   ? REMOTE_STATE_DELETED : counterpart == REMOTE_COUNTERPART_BEYOND
                   ? REMOTE_STATE_DELETED_AHEAD : REMOTE_STATE_NO_REMOTE;
        return NULL;
    }

    if (git_oid_equal(local, remote)) {
        out->state = REMOTE_STATE_UP_TO_DATE;
        return NULL;
    }

    /* The remote's branch recreated apart from the line its tracking ref names
     * — the two share no commit — asked before the branch is counted against
     * the remote's head, which a re-creation shares nothing with either: the
     * branch read against the old line where that line is its counterpart, and
     * otherwise against the remote's head as every branch is */
    if (!git_oid_is_zero(tracking) && !git_oid_equal(tracking, remote)) {
        git_oid base;
        error_t err = gitops_find_merge_base(repo, tracking, remote, &base);
        if (err) return err;

        if (git_oid_is_zero(&base)) {
            remote_counterpart_t counterpart;
            err = remote_counterpart(repo, local, tracking, &counterpart, &out->ahead);
            if (err) return err;

            if (counterpart != REMOTE_COUNTERPART_NONE) {
                out->state = counterpart == REMOTE_COUNTERPART_WITHIN
                           ? REMOTE_STATE_RECREATED : REMOTE_STATE_RECREATED_AHEAD;
                return NULL;
            }
        }
    }

    /* The branch against the remote's head: two histories sharing no commit are
     * diverged too, each counted whole */
    int rc = git_graph_ahead_behind(&out->ahead, &out->behind, repo, local, remote);
    if (rc < 0) return error_git(rc, "Cannot count the commits between two heads");

    out->state = out->behind == 0
               ? REMOTE_STATE_AHEAD : out->ahead == 0
               ? REMOTE_STATE_BEHIND : REMOTE_STATE_DIVERGED;
    return NULL;
}

error_t remote_relation(const remote_t *remote, const char *branch, remote_relation_t *out) {
    CHECK_NULL(remote);
    CHECK_NULL(branch);
    CHECK_NULL(out);

    const char *name = git_remote_name(remote->git);

    /* The branch's two heads here, then the remote's as the open listed it, under
     * the branch's own ref */
    char ref[DOTTA_REFNAME_MAX];
    git_oid local, tracking, head;
    error_t err = gitops_branch_refname(ref, sizeof(ref), branch);
    if (!err) err = remote_read_heads(remote->repo, name, ref, &local, &tracking);
    if (err) return err;
    remote_advertised(remote, ref, &head);

    return remote_relate(remote->repo, &local, &tracking, &head, out);
}

error_t remote_last_relation(
    git_repository *repo, const char *name, const char *branch, remote_relation_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(branch);
    CHECK_NULL(out);

    /* The branch's two heads here, the tracking ref standing for the remote's */
    char ref[DOTTA_REFNAME_MAX];
    git_oid local, tracking;
    error_t err = gitops_branch_refname(ref, sizeof(ref), branch);
    if (!err) err = remote_read_heads(repo, name, ref, &local, &tracking);
    if (err) return err;

    return remote_relate(repo, &local, &tracking, &tracking, out);
}

const char *remote_state_symbol(remote_state_t state) {
    switch (state) {
        case REMOTE_STATE_UP_TO_DATE:         return "=";
        case REMOTE_STATE_AHEAD:              return "↑";
        case REMOTE_STATE_BEHIND:             return "↓";
        case REMOTE_STATE_DIVERGED:           return "↕";
        case REMOTE_STATE_RECREATED:
        case REMOTE_STATE_RECREATED_AHEAD:    return "↻";
        case REMOTE_STATE_NO_REMOTE:          return "•";
        case REMOTE_STATE_DELETED:
        case REMOTE_STATE_DELETED_AHEAD:      return "−";
        case REMOTE_STATE_NO_LOCAL:
        case REMOTE_STATE_NO_LOCAL_AHEAD:
        case REMOTE_STATE_NO_LOCAL_DELETED:
        case REMOTE_STATE_NO_LOCAL_NO_REMOTE: return "?";
    }

    CHECK_ARG(false, "a remote state no enumerator names");
}

output_color_t remote_state_color(remote_state_t state) {
    switch (state) {
        case REMOTE_STATE_UP_TO_DATE:         return OUTPUT_COLOR_GREEN;
        case REMOTE_STATE_AHEAD:              return OUTPUT_COLOR_YELLOW;
        case REMOTE_STATE_BEHIND:             return OUTPUT_COLOR_YELLOW;
        case REMOTE_STATE_DIVERGED:           return OUTPUT_COLOR_RED;
        case REMOTE_STATE_RECREATED:
        case REMOTE_STATE_RECREATED_AHEAD:    return OUTPUT_COLOR_YELLOW;
        case REMOTE_STATE_NO_REMOTE:          return OUTPUT_COLOR_CYAN;
        case REMOTE_STATE_DELETED:
        case REMOTE_STATE_DELETED_AHEAD:      return OUTPUT_COLOR_YELLOW;
        case REMOTE_STATE_NO_LOCAL:
        case REMOTE_STATE_NO_LOCAL_AHEAD:
        case REMOTE_STATE_NO_LOCAL_DELETED:
        case REMOTE_STATE_NO_LOCAL_NO_REMOTE: return OUTPUT_COLOR_DIM;
    }

    CHECK_ARG(false, "a remote state no enumerator names");
}

void remote_state_phrase(
    const remote_relation_t *relation, char *buffer, size_t buffer_size
) {
    CHECK_NULL(relation);
    CHECK_NULL(buffer);

    switch (relation->state) {
        case REMOTE_STATE_UP_TO_DATE:
            snprintf(buffer, buffer_size, "up-to-date");
            return;

        case REMOTE_STATE_AHEAD:
            snprintf(
                buffer, buffer_size, "%zu commit%s ahead",
                relation->ahead, relation->ahead == 1 ? "" : "s"
            );
            return;

        case REMOTE_STATE_BEHIND:
            snprintf(
                buffer, buffer_size, "%zu commit%s behind",
                relation->behind, relation->behind == 1 ? "" : "s"
            );
            return;

        case REMOTE_STATE_DIVERGED:
            snprintf(
                buffer, buffer_size, "diverged (%zu ahead, %zu behind)",
                relation->ahead, relation->behind
            );
            return;

        case REMOTE_STATE_RECREATED:
            snprintf(buffer, buffer_size, "recreated on the remote");
            return;

        case REMOTE_STATE_RECREATED_AHEAD:
            snprintf(
                buffer, buffer_size, "recreated on the remote, %zu commit%s ahead",
                relation->ahead, relation->ahead == 1 ? "" : "s"
            );
            return;

        case REMOTE_STATE_NO_REMOTE:
            snprintf(buffer, buffer_size, "no remote branch");
            return;

        case REMOTE_STATE_DELETED:
            snprintf(buffer, buffer_size, "deleted on the remote");
            return;

        case REMOTE_STATE_DELETED_AHEAD:
            snprintf(
                buffer, buffer_size, "deleted on the remote, %zu commit%s ahead",
                relation->ahead, relation->ahead == 1 ? "" : "s"
            );
            return;

        case REMOTE_STATE_NO_LOCAL:
            snprintf(buffer, buffer_size, "no local branch");
            return;

        case REMOTE_STATE_NO_LOCAL_AHEAD:
            snprintf(
                buffer, buffer_size, "no local branch, %zu commit%s ahead",
                relation->ahead, relation->ahead == 1 ? "" : "s"
            );
            return;

        case REMOTE_STATE_NO_LOCAL_DELETED:
            snprintf(buffer, buffer_size, "no local branch, deleted on the remote");
            return;

        case REMOTE_STATE_NO_LOCAL_NO_REMOTE:
            snprintf(buffer, buffer_size, "no local branch, no remote branch");
            return;
    }

    CHECK_ARG(false, "a remote state no enumerator names");
}
