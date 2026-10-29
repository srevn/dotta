/**
 * remote.h - The store's remote, met once a command
 *
 * One remote, met once by a command (remote_t). Its open looks the remote up
 * once, connects for upload-pack and copies what the remote advertises — every
 * ref by name and the id it names — into its own arena: the epoch's verdict,
 * each branch's head there, a selection and what the fetch asks for are one
 * listing, and the transport's own copy is gone at its next connection. The open
 * also keeps the branch names the listing held, beside the store's database,
 * written only where they changed: what completion offers of the remote, offline
 * (remote_last_branches); nothing reads them as the remote's present.
 *
 * A fetch — at most one, the listing connection's last use — downloads on that
 * connection, so what it brings are the objects of the ids the listing named:
 * each requested branch the remote advertises, and one ref besides where its
 * caller names one; no ref written, no tag followed, nothing pruned. On a path
 * remote libgit2's local transport packs every head it listed, less what this
 * store's refs reach, whatever the fetch asks for
 * (lib/libgit2/src/libgit2/transports/local.c local_download_pack): there the
 * objects of every branch arrive, unnamed. Then the fetch writes each fetched
 * branch's remote-tracking ref itself — the remote as this store last saw it —
 * from the head it read there, as git's own fetch does (lib/git/builtin/fetch.c
 * update_local_ref): a tracking ref in a fetched name's way taken out first,
 * from its read, and never one beside a branch that stands here, whose way-held
 * name is then not fetched. A branch the remote no longer advertises keeps its
 * tracking ref.
 *
 * A push is one update — a ref, the commit it is to name or Git's null id (a
 * deletion), and the head its writer read the remote naming or Git's null id (a
 * create) — on a connection of its own: connected for receive-pack and listed,
 * it is sent only where that listing names what the writer read, the commit itself
 * and never a ref read again, libgit2's fast-forward check lifted. A smart server
 * compares the old id the push names again under its lock
 * (lib/git/builtin/receive-pack.c update); a path remote compares only a create's
 * absence (transports/local.c local_push_update_remote_ref), and writes the
 * repository the fetch URL names whatever pushurl says (local_push). A branch's
 * push that lands moves its tracking ref after it, from its read; a tracking
 * ref that will not follow is left as it stands, the next fetch's to write.
 *
 * The callbacks libgit2 calls during each op are sys/transfer's, made at the
 * open and freed at the free, which commits the credential helper's one verdict.
 * Which remote: "origin", or the one configured (remote_default).
 *
 * Layer: sys/. Knows libgit2, sys/gitops and sys/transfer, nothing of dotta's
 * vocabulary: every ref it writes carries the command word its caller hands its
 * open in its reflog line, as it is.
 */

#ifndef DOTTA_REMOTE_H
#define DOTTA_REMOTE_H

#include <git2.h>
#include <types.h>

#include "base/output.h"
#include "sys/transfer.h"

/* The store's remote, met once a command (opaque) */
typedef struct remote remote_t;

/**
 * Which remote a command meets: "origin", or the only one configured
 *
 * Several without an "origin" is ERR_INVALID_ARG, naming the case; none is
 * ERR_NOT_FOUND, and nothing else is — a listing that fails is libgit2's error
 * (ERR_GIT). The code is read by cmds/remove.c remove_profile, as a profile that
 * is this repository's alone, and cmds/status.c status_remote, as no section to
 * print.
 *
 * The name is the configuration's, as git lists it, and nothing here judges it:
 * a name Git refuses — a hand-written `[remote ""]` among them — is refused by
 * the open's lookup, in Git's words (remote_open).
 *
 * Readers: cmds/sync.c cmd_sync, cmds/status.c status_remote, cmds/profile.c
 * profile_fetch and profile_list, cmds/remove.c remove_profile, cmds/list.c
 * list_profiles, cmds/completion.c completion_profiles.
 *
 * @param repo Repository (must not be NULL)
 * @param arena Arena the name lives in (must not be NULL)
 * @param out The remote's name (must not be NULL; left NULL on a failure)
 * @return Error or NULL on success
 */
error_t remote_default(git_repository *repo, arena_t *arena, const char **out);

/**
 * Meet the remote: looked up, connected for upload-pack, its advertisement copied
 *
 * The one op the open makes is the connect, its listing read on it (sys/transfer.h
 * transfer_op_begin), and every ref the remote advertises is copied into the
 * session's own arena — the transport's copy is gone at its next connection
 * (transports/smart_protocol.c git_smart__store_refs, transports/local.c
 * local_connect) — and never the line the listing adds beside a ref that names
 * a tag, `<ref>^{}`: the commit the tag peels to, which no ref names. The
 * connection stays for the fetch, its last use, or until the first push or the
 * free closes it. A session that opened has reached its remote.
 *
 * Every failure is the session's whole, nothing kept: a name Git refuses or no
 * remote by it, a remote with no URL, the connect and the listing, each "Cannot
 * reach remote '<name>'" over libgit2's cause, read before anything closes —
 * save a URL libgit2 reads as a path where no directory stands, whose cause is
 * "no directory at '<url>'" (ERR_NOT_FOUND), where libgit2's names a protocol.
 * The branch names the listing held are kept once it is copied
 * (remote_last_branches), and a keep that fails is no failure of the open's:
 * completion alone reads them, and the next open keeps them again.
 *
 * Readers: cmds/sync.c cmd_sync; cmds/status.c status_remote; cmds/profile.c
 * profile_fetch and profile_list; cmds/clone.c cmd_clone; cmds/remove.c
 * remove_profile.
 *
 * @param repo Repository (must not be NULL; borrowed for the session)
 * @param name The remote's name (must not be NULL)
 * @param action The command's word, every reflog line the session writes (must
 *               not be NULL; borrowed for the session)
 * @param output The run's output, borrowed for transfer's frames and the remote's
 *               words (must not be NULL)
 * @param out The session (must not be NULL; caller frees with remote_free)
 * @return Error or NULL on success
 */
error_t remote_open(
    git_repository *repo,
    const char *name,
    const char *action,
    output_t *output,
    remote_t **out
);

/**
 * The id the remote advertised at a ref, or Git's null id where it advertised none
 *
 * Read off the open's copy, so every reader asks the one listing: no advertised
 * ref names the null id — libgit2 drops an empty repository's `capabilities^{}`
 * (transports/smart.c git_smart__connect) — and absence is its answer, as a
 * reference that does not stand is gitops_reference_oid's.
 *
 * Readers: infra/epoch.c epoch_resolve (the epoch's verdict); cmds/sync.c sync_push
 * (a push's expectation); cmds/clone.c cmd_clone (its gate, through the epoch's
 * verdict); cmds/remove.c remove_profile (whether the remote holds the branch
 * its deletion would push).
 *
 * @param remote The session (must not be NULL)
 * @param refname Full reference name (must not be NULL)
 * @param out The id, or the null id (must not be NULL)
 */
void remote_advertised(const remote_t *remote, const char *refname, git_oid *out);

/**
 * The branches the remote advertised, by name, in its listing's order
 *
 * Every ref under refs/heads/ the open listed, the prefix dropped: what the remote
 * holds now. A name the branch rule refuses — a leading '-', HEAD, which git's
 * plumbing alone makes — is listed as the remote holds it, and refused where a
 * reader builds its ref (sys/gitops.h gitops_branch_refname); so is a branch at
 * a tag or a tree, which only a tool other than git makes, refused where a reader
 * reads its head (sys/upstream.h upstream_create_branch). Lent from the session:
 * valid until remote_free.
 *
 * Readers: cmds/profile.c profile_fetch (the selection and its pre-flight) and
 * profile_list (the remote's not fetched here); cmds/clone.c cmd_clone (its gate,
 * and the listing select_profiles selects off).
 *
 * @param remote The session (must not be NULL)
 * @return The names (never NULL)
 */
const string_array_t *remote_branches(const remote_t *remote);

/**
 * The branches the remote's last contact listed, by name, in its listing's order
 *
 * What a session's open kept beside the store's database (remote_open), read
 * with no network, and true of that contact alone: a branch created on the remote
 * since is not here, one deleted there since still is, and after `remote set-url`
 * they are the old remote's until the next contact; nothing reads them as the
 * remote's present. None before a first contact, and none where the file will
 * not read: no names is the one answer its reader takes from either.
 *
 * Reader: cmds/completion.c completion_profiles, its Remote profile offers.
 *
 * @param repo Repository (must not be NULL)
 * @param arena Arena the names live in (must not be NULL)
 * @return The names; empty where none are kept
 */
string_array_t remote_last_branches(git_repository *repo, arena_t *arena);

/**
 * Fetch: download what the open's listing names, then write the tracking refs
 *
 * At most once a session, on the connection the open listed — its last use, closed
 * whatever the fetch did; a second fetch, or one after a push, is a caller's
 * bug. Fetched: each of `branches` the remote advertises, and `refname` where
 * given and advertised — the download alone, which writes no ref, no FETCH_HEAD
 * and prunes nothing; no tag is followed, whatever the remote's configuration
 * says (GIT_REMOTE_DOWNLOAD_TAGS_NONE). A name the remote does not advertise is
 * not fetched and nothing is written for it. Where nothing is fetched, nothing
 * is asked of the remote.
 *
 * A tracking ref in a branch's way — at a name it continues, or beneath it —
 * would refuse its write in Git's namespace (lib/libgit2/src/libgit2/refdb_fs.c
 * reference_path_available), so the remote's tracking refs are listed whole first,
 * complete or an error (sys/gitops.h gitops_list_remote_tracking), and each in
 * a fetched name's way is taken out before any write, from its read, as git's
 * own fetch prunes first (lib/git/builtin/fetch.c do_fetch) — once the download
 * has brought the objects, where git's prunes before it: a download that fails
 * takes nothing out. One beside a branch that stands here is never taken out:
 * it is that branch's counterpart, and its branch holds the name's way here too
 * — so the name is barred, decided before the download: not fetched, nothing
 * written, as for a name the remote lacks.
 *
 * Then each fetched branch's tracking ref is written from the head it read there
 * — the listing's absence its null id, unread again — to the id the remote
 * advertised, wherever the remote moved the branch, a force push included, and
 * whatever fetch refspec the remote's configuration holds, or none; under `dotta
 * <action>: fetched from <remote>`, and left alone where the two agree; one another
 * writer moved since is refused, naming the ref. A branch the remote no longer
 * advertises keeps its tracking ref, whatever fetch.prune says: pruned, its branch
 * here would read as never pushed, which the next sync would push back — a prune
 * is a hand's, `dotta git fetch --prune`. `refname`'s objects stand in the store
 * for its caller to judge, and nothing names them.
 *
 * Readers: cmds/sync.c cmd_sync (every profile in the run's scope, and the epoch)
 * and cmds/status.c status_remote (every profile its section lists), each asking
 * for branches here, none nested with another, so neither meets a barred name;
 * cmds/profile.c profile_fetch (the remote's own names), whose names a branch
 * here may bar; cmds/clone.c cmd_clone (the profiles it selected off the listing,
 * and the epoch), into a store it just made, which holds no tracking ref.
 *
 * @param remote The session (must not be NULL)
 * @param branches Branch names, each once and through the branch rule (must not
 *                 be NULL; may be empty)
 * @param refname One ref besides whose objects come too, written nowhere: the
 *                epoch's (NULL: none)
 * @param received What the download moved, set where the fetch succeeds; zero
 *                 where nothing was fetched (NULL: not asked)
 * @return Error or NULL on success: "Cannot fetch from remote '<name>'" over
 *         the download's cause; a tracking ref the listing, a take-out or a write
 *         refused, naming the ref
 */
error_t remote_fetch(
    remote_t *remote,
    const string_array_t *branches,
    const char *refname,
    transfer_wire_t *received
);

/**
 * Push one update: `refname` to `target`, only where the remote names `expected`
 *
 * git's update-ref <ref> <new> <old> on the remote, receive-pack's own command:
 * `target` the commit the ref is to name, Git's null id to delete it; `expected`
 * the id its writer read the remote naming, Git's null id where it read none (a
 * create). Both null is a caller's bug.
 *
 * The listing's connection is closed first, and the push connects for receive-pack,
 * the connect an op of its own as the open's is: listed there, the ref is compared
 * with `expected` before anything is sent, and the upload, its own op on that
 * connection, is the commit itself, forced — `+<id>:<ref>`, or `:<ref>` — so
 * libgit2's own fast-forward check is lifted (lib/libgit2/src/libgit2/push.c
 * queue_objects) and the compare is the push's one rule. The '+' is libgit2's
 * alone: the command a server reads names the old head and the new
 * (transports/smart_protocol.c gen_pktline), so a server that refuses a
 * non-fast-forward (receive.denyNonFastForwards) refuses it still. A ref the
 * remote refuses is the push's failure in the remote's words (sys/transfer.h
 * transfer_push_status_callback). The connection is closed after.
 *
 * A branch's push that landed (refname under refs/heads/) moves its tracking
 * ref after it, from its read — to `target`, or deleted where the push deleted
 * and the ref stands — under `dotta <action>: pushed to <remote>`. One that will
 * not follow, moved by another writer or refused by Git's namespace, is left as
 * it stands: the push landed, and the next fetch writes the ref from the remote's
 * listing.
 *
 * Readers: cmds/sync.c sync_push (a profile's push, a resolution's) and
 * sync_reconcile_epoch (the epoch's establish); cmds/remove.c remove_profile (a
 * deletion's).
 *
 * @param remote The session (must not be NULL)
 * @param refname The remote's ref, in full (must not be NULL)
 * @param target The commit it is to name, or the null id (must not be NULL)
 * @param expected What its writer read there, or the null id (must not be NULL)
 * @param sent What the push moved, set where it lands (NULL: not asked)
 * @return Error or NULL on success: ERR_CONFLICT "Reference '<refname>' on remote
 *         '<name>' was changed by another writer since this command read it"
 *         where the compare refuses, nothing sent; "Cannot push '<refname>' to
 *         remote '<name>'" over the cause — the remote's words where it refused
 *         the ref
 */
error_t remote_push(
    remote_t *remote,
    const char *refname,
    const git_oid *target,
    const git_oid *expected,
    transfer_wire_t *sent
);

/**
 * Leave the remote: the listing's connection closed where it stands, the credential
 * helper told its one verdict (sys/transfer.h transfer_context_free), and the
 * session's arena with everything it lent
 *
 * NULL-safe.
 */
void remote_free(remote_t *remote);

#endif /* DOTTA_REMOTE_H */
