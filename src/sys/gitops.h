/**
 * gitops.h - The store, local: what dotta adds to Git
 *
 * What dotta holds the store to beyond what libgit2 does, each rule in the one
 * place it is kept. The library is configured once a process (gitops_init), and
 * a handle opened or created signs the reflog lines libgit2 writes with the
 * identity dotta's commits carry (gitops_open_repository). A branch name becomes
 * a ref here alone, under Git's branch rule (gitops_branch_refname). A reference
 * is read as one chain — found, its id, its commit, its tree — its absence proven
 * on a fresh read, never a lookup's word alone (gitops_reference_find), and a
 * listing is complete or an error (below). A reference is written and deleted
 * here only from the state its writer read, its reflog line naming the command
 * that moved it (gitops_write_reference, gitops_delete_reference), and a commit
 * object has one writer, the action that made it in its header
 * (gitops_create_commit). An option whose configured value would change what
 * dotta's own operation answers is dotta's, whatever the configuration says: a
 * merge's rename pairing and its driver in sys/stage, the fetch's tags and its
 * prune in sys/remote. Beside the rules stand the passes the layers above share
 * — a tree walked, a blob read in place, two trees diffed, a merge base — and
 * calls passed through, each failure in Git's words. Nothing here meets a remote
 * (sys/remote.h).
 *
 * Converting libgit2's errors includes its iterators, the ones easy to miss:
 * `git_reference_next_name` returns 0, GIT_ITEROVER at the end, or a negative
 * code, and a loop testing only for 0 cannot tell an enumeration that finished
 * from one that gave up. Every iteration here classifies all three.
 *
 * For a ref listing that is necessary and not sufficient: libgit2's filesystem
 * refdb reads `packed-refs` loudly the first time on a handle — a parse it refused
 * leaves an empty packed store it serves after — and the loose store as far as
 * it can — a ref file it cannot open or parse is skipped with the error cleared,
 * a directory it cannot open is an empty one, and its walk of a directory stops
 * at a link it cannot stat (refdb_fs.c `refdb_fs_backend__iterator_next`,
 * `iter_load_paths`; iterator.c `filesystem_iterator_frame_push`) — so an
 * unreadable `refs/heads` enumerates as nothing and ends GIT_ITEROVER. So every
 * listing here parses packed-refs afresh and reads the loose store itself, looking
 * each ref file up (gitops_list_refs). A LISTING IS COMPLETE OR AN ERROR — Git's
 * own words for the ref, the same a singular lookup says of it, or the walk's
 * for a directory it could not read — and a caller acting on an absence in one
 * (the census, the blocker, init's adoption test) holds no proof of its own. A
 * singular lookup that misses proves no absence either, and the one that must
 * says so (gitops_reference_find).
 */

#ifndef DOTTA_GITOPS_H
#define DOTTA_GITOPS_H

#include <git2.h>
#include <types.h>

/**
 * The buffer a reference name is built in: as long as libgit2 reads one
 *
 * Git bounds a reference name by nothing but memory, a loose ref's path by the
 * kernel; libgit2 normalizes every name it looks up or writes into git_refname_t,
 * char[1024] (lib/libgit2/src/libgit2/refs.h GIT_REFNAME_MAX), and refuses one
 * that does not fit ("the provided buffer is too short to hold the normalization").
 * So a name this buffer cannot hold is one no lookup could read, and the bound
 * is the library's, never one of dotta's own. A refspec joins a source and a
 * name, a ':' between them and the force's '+' before; a push's source is an
 * id, or nothing.
 */
#define DOTTA_REFNAME_MAX 1024                        /* a name, and its NUL */
#define DOTTA_REFSPEC_MAX (2 * DOTTA_REFNAME_MAX + 1) /* [+]<source>:<name>, and NUL */

/**
 * Initialize libgit2 for this process, and configure it
 *
 * One producer for a fact every binary linking this library shares: how dotta
 * configures libgit2. The library's options are process-wide, so a knob set in
 * a `main()` would be the shipped binary's alone and every unit suite would
 * exercise a differently configured library — a difference in speed for the object
 * cache's knobs, and in what a run can read at all for the bound on the packs
 * it holds open. Paired with gitops_shutdown so no caller writes half of the
 * lifecycle.
 *
 * @return Error or NULL on success
 */
error_t gitops_init(void);

/**
 * Release this process's libgit2
 *
 * Decrements the library's reference count, freeing its object cache with the
 * last reference. The other half of gitops_init's pair.
 */
void gitops_shutdown(void);

/**
 * The signature a commit dotta writes carries, stamped now
 *
 * user.name and user.email as the repository's configuration names them
 * (git_signature_default: its own file, the user's, the system's); where it lacks
 * either — a fresh machine before its dotfiles are deployed — the invoker at
 * this host (sys/identity.h), `<invoker> <invoker@host>`, "dotta" for an invoker
 * with no name and "localhost" for a host gethostname cannot name.
 *
 * Readers: the one writer of a commit object, the stage's commit (sys/stage.c
 * stage_commit), a merge's among them, and the handle's open and create, which
 * hand it to libgit2 as the ident of the reflog lines it signs itself
 * (gitops_open_repository, gitops_init_repository). Caller frees the returned
 * signature via `git_signature_free`.
 *
 * @param out  Output signature (caller frees with git_signature_free)
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_get_signature(git_signature **out, git_repository *repo);

/**
 * Open git repository at path
 *
 * The open is the presence test: there is no separate "is this a repository"
 * predicate, because answering it requires this call and discarding this call's
 * failure turns every unreadable repository into an absent one.
 *
 * The failure is classified so a caller can tell the cases apart:
 *   ERR_NOT_FOUND  — nothing stands at the path's two places, a working tree's
 *                    .git and a bare store's HEAD: looked at, and absent. libgit2
 *                    answers not found for a repository it could not read as
 *                    well, so the open asks both itself before it says so. Read
 *                    by utils/repo.c repo_open, as no store there, and by
 *                    cmds/init.c cmd_init, which creates a repository where it
 *                    reads the code.
 *   ERR_PERMISSION — the repository is owned by another user.
 *   ERR_GIT        — everything else, carrying libgit2's own message — a config
 *                    file that will not parse (the user's ~/.gitconfig is loaded
 *                    on open), a damaged object database — or the open's own: a
 *                    repository libgit2 would not open whose .git or HEAD stands,
 *                    and a look at either that could not answer.
 *
 * The handle opened signs the reflog lines libgit2 writes — every reference
 * write's, which no call of libgit2's hands a signature: dotta's own
 * (gitops_write_reference), a remote rename's (cmds/remote.c remote_rename) —
 * with the signature dotta's commits carry (gitops_get_signature), so a line
 * names whom a commit here names.
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_open_repository(git_repository **out, const char *path);

/**
 * Create a bare repository at path, or open the one that stands there
 *
 * `git init --bare`, the path created as needed. dotta's store is bare
 * (utils/repo.h): nothing is ever checked out, every write to a branch is a stage
 * committed in memory (sys/stage), and a working tree was the layer beneath an
 * anchor branch nothing reads any more. Over a repository that already stands
 * the call is git's re-init — refs and config kept, only what is missing written
 * back, HEAD among them — so a store a hand stripped of its HEAD is whole again;
 * it does not make a repository with a working tree bare, and a caller that must
 * know reads `git_repository_is_bare` on what it got.
 *
 * HEAD is written here once, `ref: refs/heads/<init.defaultBranch, else master>`,
 * unborn — git's own fresh state — and nothing in dotta reads or writes it after.
 * A symref a hand moves onto a profile makes that profile a GUI's current branch
 * and costs dotta nothing. Garbage in the file stops `dotta git` with git's own
 * words, and stops every commit too — libgit2 reads HEAD at each ref write to
 * decide whether the HEAD reflog gets the entry, and fails on what it finds,
 * naming the file — while every read runs; the file is the hand's to put back.
 *
 * The handle signs its reflog lines as an opened one does (gitops_open_repository).
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_init_repository(git_repository **out, const char *path);

/**
 * Close repository and free resources
 *
 * Safe to call with NULL.
 *
 * @param repo Repository handle (can be NULL)
 */
void gitops_close_repository(git_repository *repo);

/**
 * The reference at a full name, or NULL where none stands
 *
 * NULL is an absence proven on a fresh read of the store, never a lookup's word
 * alone: a lookup that misses has read packed-refs through two readers libgit2
 * does not keep sound, a search of the file and a cache of its parse. So a miss
 * is asked again of a reference database that has never read the file, whose
 * listing of the name parses it whole — a damaged file refuses there — and a
 * name that listing holds and no lookup reaches (records out of order, CRLF line
 * ends under the sorted trait) is the failure. The reference comes back as it
 * is stored: a symbolic one is not resolved. A lookup that fails names the
 * reference, above libgit2's sentence where it has one, so a reader that prints
 * the failure as one line has said which (cmds/sync.c sync_reconcile_epoch, over
 * infra/epoch.c epoch_resolve's read of the local epoch).
 *
 * A miss leaves the handle on that fresh reference database. A reference or an
 * iterator held from before keeps the database it came from — libgit2 counts it
 * — so nothing a caller holds is freed under it.
 *
 * One corner stays open: under `core.precomposeunicode` the lookup reads a name
 * in decomposed Unicode as its composed form and the listing does not, so in a
 * file whose order hides the composed name a decomposed spelling reads absent —
 * and a namespace spelled so lists none of the packed refs beneath it, in any
 * file (gitops_list_refs). The branch rule (gitops_branch_refname) passes a
 * decomposed name.
 *
 * Readers: gitops_reference_exists, and every presence question through it;
 * gitops_reference_oid, and every reader of what a reference names through it —
 * its id, its commit, its tree (their headers); gitops_delete_reference, which
 * deletes the reference it finds; gitops_verify_branch, the worktrees' question
 * of a branch.
 *
 * @param repo Repository (must not be NULL)
 * @param refname Full reference name (must not be NULL or empty)
 * @param out The reference (caller frees with git_reference_free), or NULL:
 *            none stands (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_reference_find(
    git_repository *repo, const char *refname, git_reference **out
);

/**
 * Check if a reference exists
 *
 * The singular: the ref resolves, or it is absent. Anything else — a loose ref
 * that will not open, one whose bytes are not an OID, a packed-refs that will
 * not parse — is the error, never an absence, and every caller propagates it: a
 * bool that read it as "no" once sent the user to fetch a profile that was here.
 * gitops_reference_find answers it for any ref (a branch, the epoch, the baseline),
 * its absence proven; a name outside refs/heads is the caller's to spell in full.
 *
 * @param repo Repository (must not be NULL)
 * @param refname Full reference name (must not be NULL or empty)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_reference_exists(
    git_repository *repo, const char *refname, bool *exists
);

/**
 * Check if branch exists
 *
 * gitops_reference_exists of refs/heads/<name>, the name through the branch rule
 * (gitops_branch_refname) on the way. A reader asking of many names whose misses
 * recur — a branch gone stays gone, asked again at every load — asks them together
 * (gitops_branches_exist), every miss proven at once.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_branch_exists(git_repository *repo, const char *name, bool *exists);

/**
 * Check which branches exist
 *
 * gitops_branch_exists of each name, the misses proven together: each name looked
 * up first, through the branch rule (gitops_branch_refname) — a lookup that finds,
 * or fails, is the answer, as it is the singular's (gitops_reference_find) —
 * and every name that missed proven by one listing of the branches, on a reference
 * database that has read nothing yet (gitops_list_branches): absent where the
 * listing lacks it, and where it holds it asked as the singular asks, a name
 * the listing holds and no lookup reaches being the failure. So however many of
 * the names miss, the store's packed refs are parsed once, and where none misses,
 * never — the singular parses them once a miss. The listing is complete or an
 * error, so a branch it cannot read refuses the answer for every name, where
 * the singular reads its own name alone; and the corner the singular leaves open
 * for a decomposed name stands here alike. Where any missed, the handle is left
 * on the listing's fresh reference database.
 *
 * Readers: core/manifest.c manifest_build (every enabled profile), core/scope.c
 * scope_resolve_enabled (the same rows, without the view) and core/workspace.c
 * workspace_ask_departures (each owned file orphan's disabled profile).
 *
 * @param repo Repository (must not be NULL)
 * @param names Branch names (must not be NULL where count > 0)
 * @param count How many
 * @param exists Whether each stands, parallel to `names` (must not be NULL); no
 *               answer beside an error
 * @return Error or NULL on success
 */
error_t gitops_branches_exist(
    git_repository *repo, const char *const *names, size_t count, bool *exists
);

/**
 * Find the existing branch that blocks a name
 *
 * Git's ref namespace is a directory tree: refs/heads/<n> is a name and
 * refs/heads/<n>/<v> is a folder of names, and one path cannot be both. So a
 * branch and any branch beneath it are mutually exclusive, in every ref backend
 * — packing the refs does not lift it, it only rewords the refusal ("path to
 * reference collides with existing one" instead of a failure to remove a
 * directory). Git refuses the second at creation; libgit2 refuses it too, and
 * neither of its wordings names both branches.
 *
 * Answers which existing branch stands in the way of `name`, so a caller can
 * refuse in its own vocabulary before doing any work. An exact match does not
 * block — that is `gitops_branch_exists`'s question, and its answer is a different
 * one. A name Git refuses is no candidate: the branch rule refuses it
 * (gitops_branch_refname) before any branch is read.
 *
 * The answer is the listed branch's own name, as long as Git made it, or NULL
 * when nothing blocks; it and the listing it is read from are `arena`'s.
 *
 * @param repo  Repository (must not be NULL)
 * @param name  Branch name to test (must not be NULL)
 * @param arena Arena the listing and the answer live in (must not be NULL)
 * @param out   The blocking branch's name, or NULL (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_branch_blocker(
    git_repository *repo, const char *name, arena_t *arena, const char **out
);

/**
 * Whether two reference names nest: one a folder the other lives in
 *
 * Git's namespace is a directory tree, and one path cannot be both a name and a
 * folder of names (lib/libgit2/src/libgit2/refdb_fs.c reference_path_available),
 * so of two nested names the namespace holds one, never both. Equal names are
 * not nested: that is a lookup's question, and its answer a different one.
 *
 * Readers: gitops_branch_blocker, a branch in a name's way; sys/remote.c
 * remote_fetch, a tracking ref in a fetched name's way.
 *
 * @param a A reference name, or a name beneath one namespace (must not be NULL)
 * @param b Another, spelled alike (must not be NULL)
 * @return Whether they nest
 */
bool gitops_nested(const char *a, const char *b);

/**
 * List the references under a namespace
 *
 * The names beneath `namespace` — "refs/heads" lists a branch as "p", "refs"
 * lists it as "heads/p" — complete or an error (the header). libgit2's enumeration
 * under the namespace first, on a reference database that has read nothing yet
 * — packed-refs parsed whole, so a damaged file refuses the listing every time
 * and never lists as a store without packed refs (gitops_reference_find says
 * why); then the loose store beneath it, read whole as the invoker, as libgit2
 * reads it, every ref file looked up: a refusal is the listing's, in Git's words,
 * and a ref the enumeration did not name is appended under the name libgit2 gives
 * it — one born since the enumeration read, one past a link the enumeration could
 * not stat, where libgit2's walk of the directory stops. A link to a directory
 * is a namespace, entered as Git's own listing enters one; what the kernel refuses
 * beneath it — a link that loops past its limit, a directory the invoker cannot
 * read — refuses the listing, naming the directory, where git lists past it: an
 * absence in this listing is acted on. Loose refs are named by their path, so a
 * namespace with no directory holds no loose refs (a remote never fetched, every
 * ref packed) and is not an error. Order is the enumeration's, the appended after
 * it.
 *
 * gitops_list_branches and gitops_list_remote_tracking are this under their
 * namespaces; init's adoption test asks it of "refs" whole.
 *
 * The listing is a value of `arena`; on a failure `out` is left as it was.
 *
 * @param repo Repository (must not be NULL)
 * @param namespace The namespace, no trailing slash (must not be NULL or empty)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The names beneath it (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_list_refs(
    git_repository *repo, const char *namespace, arena_t *arena, string_array_t *out
);

/**
 * List all local branches
 *
 * Every branch under refs/heads by name, complete or an error (gitops_list_refs).
 *
 * @param repo Repository (must not be NULL)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The branch names (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_list_branches(git_repository *repo, arena_t *arena, string_array_t *out);

/**
 * List all remote tracking branches
 *
 * Every ref under refs/remotes/<remote> by name, complete or an error
 * (gitops_list_refs), less the one that is not a branch of the remote: `HEAD`,
 * the remote's own symbolic HEAD, which `git clone` and `git remote set-head`
 * record there.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out The branch names (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_list_remote_tracking(
    git_repository *repo,
    const char *remote_name,
    arena_t *arena,
    string_array_t *out
);

/**
 * Create a branch at a commit, only where its name is free
 *
 * gitops_delete_branch's twin: its refusals first, then gitops_write_reference
 * of refs/heads/<name> from Git's null id — written only where no branch of the
 * name stands, so one created since its caller found none refuses, ERR_CONFLICT
 * in the writer's words — under `dotta <action>: <words>`, the words the caller's.
 * The refusals, in their order: a name the branch rule refuses
 * (gitops_branch_refname); a name Git's namespace cannot hold beside a branch
 * already here (gitops_branch_blocker), ERR_CONFLICT naming both — a failure
 * about the two names, which the write would report in libgit2's words naming
 * one — asked before the target is read, since a name a fetch passes over for
 * the branch in its way (sys/remote.h remote_fetch) has a head the store may
 * not hold; and a target that is no commit — a tag, a tree, a blob — naming the
 * id: a branch names a commit (gitops_reference_commit says why), so a remote's
 * branch at a tag, which only a tool other than git writes, is no branch here.
 *
 * Readers: cmds/clone.c land_profiles (each profile the clone selected, into a
 * store it just made, at the remote's head), and cmds/profile.c profile_fetch
 * and cmds/sync.c sync_execute (a profile with no branch here, at the head its
 * relation names: sys/remote.h remote_relation_t from).
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param target The commit it is to name (must not be NULL, nor Git's null id)
 * @param action The word of the command that creates it (must not be NULL)
 * @param format What it did, a printf format over the arguments after it (must
 *               not be NULL)
 * @return NULL; a name the branch rule refuses, in its words; ERR_CONFLICT naming
 *         both branches where the namespace cannot hold the name; ERR_GIT naming
 *         the target where it is no commit, in libgit2's words where it will
 *         not read; every other answer gitops_write_reference's
 */
error_t gitops_create_branch(
    git_repository *repo,
    const char *name,
    const git_oid *target,
    const char *action,
    const char *format,
    ...
) __attribute__((format(printf, 5, 6)));

/**
 * Verify that a branch's delete would land: its refusals, asked without it
 *
 * gitops_delete_branch's two refusals, git's update-ref verify <ref> <old-oid>
 * and the worktrees' question beside it, for a caller that must hear them before
 * an act it cannot take back: the branch, its name through the branch rule
 * (gitops_branch_refname), still names `expected`, read as the delete reads it
 * (gitops_delete_reference), and no linked worktree of the repository has it
 * checked out (gitops_delete_branch says why). Nothing is written, and the answer
 * holds until another writer moves the branch, which the delete then refuses
 * itself.
 *
 * Readers: gitops_delete_branch, before its delete; cmds/remove.c remove_profile,
 * before the remote's deletion it pushes first.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param expected The head its writer read (must not be NULL, nor Git's null id)
 * @return NULL; ERR_CONFLICT "Reference '<refname>' was changed by another writer
 *         since this command read it" where the branch names another id or none,
 *         and ERR_CONFLICT naming the branch where a linked worktree has it checked
 *         out; the read's own failure, gitops_reference_oid's; a name the branch
 *         rule refuses, in its words
 */
error_t gitops_verify_branch(
    git_repository *repo, const char *name, const git_oid *expected
);

/**
 * Delete a branch, only from the head its writer read
 *
 * Its refusals first (gitops_verify_branch), then gitops_delete_reference of
 * refs/heads/<name>: the ref and its reflog, only where the branch still names
 * `expected`. Refused, in dotta's words, when a linked worktree of the repository
 * has the branch checked out (`dotta git worktree add`): a bare store checks
 * nothing out itself, so a worktree is the one place a checkout of a profile
 * can stand, and `git_reference_delete` would take the branch from under it without
 * a word. Not refused for the branch HEAD names: HEAD is git's and unborn
 * (gitops_init_repository), a hand may have pointed it at a profile, and git
 * itself deletes that branch in a bare repository — `git_branch_delete` is the
 * stricter one and is not used. Per-branch config another tool wrote
 * (`branch.<name>.*`) is that tool's and stays; dotta writes none.
 *
 * Readers: cmds/remove.c remove_profile, from the head its preview read;
 * cmds/sync.c sync_execute, a deletion the remote's answer teaches, from the
 * head its relation read.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param expected The head its writer read (must not be NULL, nor Git's null id)
 * @return NULL; every refusal gitops_verify_branch's; every other answer
 *         gitops_delete_reference's
 */
error_t gitops_delete_branch(
    git_repository *repo, const char *name, const git_oid *expected
);

/**
 * The commit a reference names, or NULL where no reference stands
 *
 * gitops_reference_oid, and the object at that id, which must be a commit: a
 * branch names a commit — Git writes nothing else to one (lib/git/refs.c
 * ref_transaction_update refuses a "non-commit object") and dotta writes nothing
 * else anywhere — so a reference that stands at a tree, a blob or a tag is refused,
 * naming what it found. A tag is not peeled: the stage writes a branch only from
 * the id it read there (gitops_write_reference), so a head read through a tag
 * is one no commit could be written on. NULL is the reference's absence, proven.
 *
 * The one way a reference becomes a head. Readers: gitops_reference_tree, and
 * the readers of a tree through it (its header); gitops_branch_commit, and the
 * readers of a branch's head through it; gitops_load_reference_commit, which
 * refuses the absence; infra/epoch.c epoch_walk, the census, at each branch it
 * lists, one gone since the listing holding nothing, one that will not read passed
 * over.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (must not be NULL or empty)
 * @param out The commit (caller frees with git_commit_free), or NULL: none stands
 *            (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_reference_commit(
    git_repository *repo, const char *ref_name, git_commit **out
);

/**
 * The tree a reference names, or NULL where no reference stands
 *
 * gitops_reference_commit, and its tree: NULL is the reference's absence, proven;
 * one that stands and names no commit is refused there. For the readers that
 * act on the absence as an answer, in one read where a presence question and a
 * load were two: core/ignore.c ignore_ref_text (no .dottaignore yet), infra/epoch.c
 * epoch_load (no epoch) and gitops_branch_tree.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (must not be NULL or empty)
 * @param out The tree (caller frees with git_tree_free), or NULL: none stands
 *            (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_reference_tree(
    git_repository *repo, const char *ref_name, git_tree **out
);

/**
 * The commit a branch names, or NULL where the branch does not stand
 *
 * gitops_reference_commit of refs/heads/<name>, the name through the branch rule
 * (gitops_branch_refname) on the way: gitops_branch_tree's twin, for a reader
 * that needs the head itself — the history behind it, or its id beside its tree.
 * Readers: core/manifest.c manifest_build (each enabled profile whose branch it
 * found standing, its claims read from the head's tree and the head's id kept
 * beside them, a branch gone since contributing nothing), core/workspace.c
 * workspace_ask_departures (each owned file orphan's disabled profile whose branch
 * it found standing, one gone since answering every name GONE) and cmds/remove.c
 * remove_profile (the head a deletion takes, read once, before it says what it
 * takes; a branch gone, no profile to delete).
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out The head (caller frees with git_commit_free), or NULL: the branch
 *            does not stand (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_branch_commit(
    git_repository *repo, const char *branch_name, git_commit **out
);

/**
 * The tree a branch names, or NULL where the branch does not stand
 *
 * gitops_reference_tree of refs/heads/<name>, the name through the branch rule
 * (gitops_branch_refname) on the way. Readers: sys/bootstrap.c bootstrap_exists,
 * and gitops_load_branch_tree, which refuses the absence.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out The tree (caller frees with git_tree_free), or NULL: the branch
 *            does not stand (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_branch_tree(
    git_repository *repo, const char *branch_name, git_tree **out
);

/**
 * Load tree from a branch by name
 *
 * gitops_branch_tree for a reader that needs the branch: its absence, proven,
 * is refused (ERR_NOT_FOUND, naming the reference).
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out_tree Tree object (must not be NULL, caller must free with
 *                 git_tree_free)
 * @return Error or NULL on success
 */
error_t gitops_load_branch_tree(
    git_repository *repo,
    const char *branch_name,
    git_tree **out_tree
);

/**
 * What a tree walk does after the entry its visitor was shown
 *
 * The visitor says it through its last parameter, which the walk sets to CONTINUE
 * before each call, so a visitor with nothing to say leaves it.
 *
 * Readers: the walks over a profile's content, which SKIP machinery at their
 * gate — a name under no label, a tree of it with everything beneath (infra/label.h
 * label_prefixes) — core/profiles.c profile_step, which also STOPs where its
 * own visitor fails, and cmds/completion.c refspec_emit, which also STOPs at
 * its cap; and the ciphertext census, which SKIPs a binding it has met and a
 * subtree it cannot load, and STOPs where its asker has an answer (infra/epoch.c
 * epoch_present_blob).
 */
typedef enum {
    GITOPS_NEXT_CONTINUE,   /* on to the next entry: a tree's own entries first */
    GITOPS_NEXT_SKIP,       /* past this entry, and at a tree everything beneath it */
    GITOPS_NEXT_STOP        /* the walk has its answer: end it, no failure */
} gitops_next_t;

/**
 * A tree walk's visitor
 *
 * Shown each entry in pre-order with the entry's path within the walked tree
 * ("home", then "home/.bashrc"), joined by the walk and lent for the call, and
 * the caller's payload, untouched. Its failure is its return, whatever `next`
 * says; what the walk does next is `next`.
 */
typedef error_t (*gitops_visit_fn)(
    const char *path,
    const git_tree_entry *entry,
    void *payload,
    gitops_next_t *next
);

/**
 * Walk a tree, showing every entry to a visitor
 *
 * Pre-order: a tree is shown before its entries, so its visitor may skip them.
 * The path is joined here, once per entry, and nothing bounds it but memory —
 * Git's only bound on a name — so no visitor holds a buffer of its own or refuses
 * a name for its length.
 *
 * Answers NULL where the walk finished and where the visitor stopped it; the
 * visitor's failure, as the visitor made it; or the walk's own — a subtree that
 * will not load — in libgit2's words. What the visitor answered is read from
 * the walk's own state and never from libgit2, whose reply to a callback that
 * ended its walk may be a sentence an earlier call left standing (errors.h
 * git_error_set_after_callback_function sets one only where none stands).
 *
 * @param tree Tree to walk (must not be NULL)
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return Error or NULL on success
 */
error_t gitops_tree_walk(
    const git_tree *tree,
    gitops_visit_fn visit,
    void *payload
);

/**
 * The filemode a path's type stands as in a tree
 *
 * dotta's type (include/types.h path_type_t) in Git's words: a file 0100644, an
 * executable 0100755, a link 0120000, a directory a tree, 040000 — the filemode
 * the content layer and the comparisons read a claim's bytes under. The decode
 * reads the other way, a blob's filemode into its type (core/profiles.c
 * profile_decode_blob). A type no enumerator names is a caller's bug, and dies.
 *
 * Readers: core/workspace.c workspace_analyze_file, core/deploy.c deploy_file,
 * cmds/diff.c diff_print_item and diff_print_view, and cmds/show.c show_print_blob
 * (a decoded claim's type, which the profile read off one of a blob's three
 * filemodes).
 *
 * @param type Path type
 * @return Its filemode
 */
git_filemode_t gitops_type_filemode(path_type_t type);

/**
 * Zero-copy view into a git blob's raw bytes.
 *
 * Holds an open git_blob handle and exposes its raw content without copying.
 * The `data` pointer is owned by libgit2's object cache and is valid only between
 * gitops_blob_view_open() and gitops_blob_view_close(): a reader that keeps the
 * bytes past the close copies what it keeps.
 *
 * The `_handle` field is opaque; do not touch it directly.
 */
typedef struct {
    git_blob *_handle;
    const void *data;
    size_t size;
} gitops_blob_view_t;

/**
 * Open a zero-copy view onto a blob.
 *
 * On failure, `*out` is left in a safe state (NULL handle/data, zero size) so
 * gitops_blob_view_close() is a no-op.
 *
 * @param repo Repository (must not be NULL)
 * @param oid Blob OID (must not be NULL)
 * @param out View handle (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_blob_view_open(
    git_repository *repo,
    const git_oid *oid,
    gitops_blob_view_t *out
);

/**
 * Close a blob view and release its libgit2 handle.
 *
 * Safe to call with NULL, a zero-initialised view, or an already-closed view.
 * After close, all fields are zeroed so double-close is safe.
 *
 * @param view View to close (can be NULL)
 */
void gitops_blob_view_close(gitops_blob_view_t *view);

/**
 * Load the commit a reference names
 *
 * gitops_reference_commit for a reader that needs the reference: its absence,
 * proven, is refused (ERR_NOT_FOUND, naming the reference). Readers: sys/stage.c
 * stage_open and stage_merge (the parent-to-be, a merge's first), and
 * gitops_load_branch_commit.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (must not be NULL or empty)
 * @param out Commit object (must not be NULL, caller must free with
 *            git_commit_free)
 * @return Error or NULL on success
 */
error_t gitops_load_reference_commit(
    git_repository *repo,
    const char *ref_name,
    git_commit **out
);

/**
 * Load the commit at a branch's head
 *
 * gitops_load_reference_commit of refs/heads/<branch>, the name through the branch
 * rule (gitops_branch_refname) on the way, and every failure names the reference.
 * Readers: the revision's three askers, sys/revision.c revision_load and
 * core/scope.c scope_resolve_commit and scope_resolve_range, which read a branch's
 * head once and ask it; cmds/list.c list_profiles, list_files and
 * list_file_history, which read every fact a screen prints off it;
 * cmds/completion.c commits_walk, which walks back from it.
 *
 * @param repo Repository (must not be NULL)
 * @param branch Branch name (must not be NULL)
 * @param out The head (must not be NULL, caller must free with git_commit_free)
 * @return Error or NULL on success
 */
error_t gitops_load_branch_commit(
    git_repository *repo,
    const char *branch,
    git_commit **out
);

/**
 * Write a reference, only from the state its writer read
 *
 * `refname` comes to name `target` only where it still stands as `expected` says
 * — git's update-ref <ref> <new> <old>:
 *   - an id: the head it must still name — the stage's commit, sync's pull, a
 *     remote-tracking ref the session moves, the epoch's install over the ref
 *     its census judged;
 *   - Git's null id: nothing, the name free — the stage's root, a branch's create
 *     (gitops_create_branch), a remote-tracking ref the session writes first,
 *     the epoch's install where none stood.
 * libgit2 compares under the reference's own lock, and asks Git's namespace
 * whatever the compare says (lib/libgit2/src/libgit2/refdb_fs.c
 * refdb_fs_backend__write: reference_path_available, then cmp_old_ref), so a
 * reference another writer moved, deleted or made since its writer read it —
 * another dotta, `dotta git`, git — is refused, and so is a name Git's namespace
 * cannot hold beside another. Refused, nothing is written.
 *
 * A symbolic chain is walked to the name it ends at, a name nothing stands at
 * included, as git's update-ref writes through one: the compare is the end's,
 * and the symbolic references stand as they were. Five links at most, as many
 * as libgit2 follows resolving a name (refdb.c git_refdb_resolve).
 *
 * A create decides on what the store does not hold, so it reads a reference
 * database that has read nothing yet (gitops_reference_find says why). Its decision
 * is the compare's lookup, under the lock, as git's update-ref takes a zero <old>:
 * a sorted packed-refs whose records are out of order hides a name from that
 * lookup as from git's (lib/git/refs/packed-backend.c), and every reader ahead
 * of a create proves the name absent first (gitops_reference_find), which refuses
 * such a file — so only a file damaged between that proof and the write has a
 * loose reference written over a packed one.
 *
 * The reflog line names the command that moved the reference, then what it did:
 * `dotta <action>: <words>`, opened as a commit's action header is
 * (gitops_create_commit), so a commit's line and its header name one command.
 * Formatted here alone, so no writer spells a line of its own. It is signed with
 * the handle's ident (gitops_open_repository), HEAD's log takes it too where
 * HEAD names the reference written (refdb_fs.c maybe_append_head), and Git keeps
 * it where it keeps the reference's log — in dotta's store a branch's and a
 * remote-tracking ref's (utils/repo.h repo_declare_store), not the epoch's or
 * the baseline's (refdb.c git_refdb_should_write_reflog). Its clock is the write's.
 *
 * Readers: sys/stage.c stage_commit; cmds/sync.c sync_execute, a pull;
 * gitops_create_branch; sys/remote.c remote_fetch, remote_follow and remote_take,
 * a remote-tracking ref after a fetch, a push and an act; infra/epoch.c
 * epoch_adopt.
 *
 * @param repo Repository (must not be NULL)
 * @param refname Full reference name (must not be NULL)
 * @param target The id the reference is to name (must not be NULL; an object
 *               the repository holds)
 * @param expected What the writer read: an id, or Git's null id (must not be
 *                 NULL: every write is from a read)
 * @param action The word of the command that moves the reference (must not be
 *               NULL: every line names one)
 * @param format What it did, a printf format over the arguments after it (must
 *               not be NULL)
 * @return NULL; ERR_CONFLICT "Reference '<refname>' was changed by another writer
 *         since this command read it" where the compare refuses, and nowhere
 *         else; every other failure Git's, in Git's words — a head deleted since
 *         ("reference '<name>' not found"), a lock another writer holds, a name
 *         the namespace refuses, a HEAD libgit2 cannot read, a store a fresh
 *         read refuses; a chain link the reference rule refuses, in its words
 *         (gitops_build_refname); and a chain past the bound, ERR_GIT
 */
error_t gitops_write_reference(
    git_repository *repo,
    const char *refname,
    const git_oid *target,
    const git_oid *expected,
    const char *action,
    const char *format,
    ...
) __attribute__((format(printf, 6, 7)));

/**
 * Delete a reference, only from the state its writer read
 *
 * `refname` goes, and its reflog with it, only where it still names `expected`,
 * the id its writer read there — git's update-ref -d <ref> <old>. What it names
 * is read as gitops_reference_oid reads it — an absence proven, a damaged
 * packed-refs the read's own failure, a symbolic reference read through — off
 * the one reference the delete then takes, so libgit2 compares again under the
 * reference's lock against that read (lib/libgit2/src/libgit2/refs.c
 * git_reference_delete, refdb_fs.c refdb_fs_backend__delete_tail). A symbolic
 * reference is deleted itself, as git's branch -d deletes one
 * (lib/git/builtin/branch.c, REF_NO_DEREF), never what it names, which update-ref
 * -d without --no-deref would delete (lib/git/builtin/update-ref.c).
 *
 * One window stays: libgit2 takes the lock and deletes the reflog before it
 * compares (refdb_fs.c refdb_fs_backend__delete), so a write inside the
 * microseconds between this read and that lock is refused with the reflog gone,
 * the reference standing where its writer left it.
 *
 * Readers: gitops_delete_branch; sys/remote.c remote_fetch, each tracking ref
 * it takes out of a fetched name's way, and remote_follow, a branch's tracking
 * ref after its deletion's push, each from the id it read there.
 *
 * @param repo Repository (must not be NULL)
 * @param refname Full reference name (must not be NULL or empty)
 * @param expected The id its writer read there (must not be NULL, nor Git's null
 *                 id: a writer deletes what it read standing)
 * @return NULL; ERR_CONFLICT "Reference '<refname>' was changed by another writer
 *         since this command read it" where it names another id or none — moved
 *         or deleted since, met at this read or at libgit2's under the lock —
 *         and nowhere else; the read's own failure, gitops_reference_oid's; every
 *         other failure Git's, in Git's words — a lock another writer holds among
 *         them
 */
error_t gitops_delete_reference(
    git_repository *repo,
    const char *refname,
    const git_oid *expected
);

/**
 * The id a reference names, or Git's null id where none stands
 *
 * gitops_reference_find, read through a symbolic reference to the one it names:
 * the null id — all zeros, git_oid_is_zero, Git's own id for no object — only
 * where the absence is proven. A symbolic reference that names nothing is a
 * failure, not an absence, and so is a reference that stands at the null id:
 * git reads one as broken (lib/git/refs/files-backend.c), never as missing. The
 * delete reads the reference it takes so too (gitops_delete_reference). For the
 * readers that act on a reference's absence as an answer: infra/epoch.c
 * epoch_resolve (no local epoch), sys/remote.c remote_fetch (a tracking ref in
 * a fetched name's way gone since its listing, nothing to take out), remote_follow
 * and remote_take (a branch's tracking ref never written, a create) and
 * remote_read_heads (no branch here, no tracking ref: a branch against its remote),
 * cmds/remove.c remove_profile (no tracking ref its deletion's lease could name),
 * and gitops_reference_commit, which reads the commit at the id.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (must not be NULL or empty)
 * @param out The id, or the null id (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_reference_oid(
    git_repository *repo,
    const char *ref_name,
    git_oid *out
);

/**
 * Validate and build a Git reference name
 *
 * Builds a reference name — or a refspec, which holds two — using printf-style
 * formatting, and refuses one its buffer cannot hold rather than truncate it
 * into another name. The buffer is DOTTA_REFNAME_MAX, or DOTTA_REFSPEC_MAX for
 * a refspec: libgit2's own bound (that constant's header), so a name refused
 * here is longer than any libgit2 reads.
 *
 * A branch name goes through gitops_branch_refname, which carries Git's branch
 * rule, and a branch's remote-tracking name through gitops_remote_branch_refname;
 * this is for the other shapes.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer: DOTTA_REFNAME_MAX, DOTTA_REFSPEC_MAX
 * @param format Printf-style format string (must not be NULL)
 * @param ... Format arguments
 * @return Error or NULL on success
 */
error_t gitops_build_refname(
    char *buffer, size_t buffer_size, const char *format, ...
) __attribute__((format(printf, 3, 4)));

/**
 * A branch name to its reference, or Git's refusal
 *
 * The one place a branch name becomes `refs/heads/<name>`. An empty name first,
 * refused as empty; then Git's branch rule (git_branch_name_is_valid: the reference
 * rule on the joined name, plus the two shapes only the branch rule refuses — a
 * leading '-' and the word HEAD, valid references git itself will not make branches
 * of), then the join, sized to the buffer by gitops_build_refname, whose own
 * reference check the branch rule subsumes. Every lookup, creator and mover of
 * a branch a user names builds its ref here, and every transfer its refspec's
 * branch half, so a name Git refuses is refused wherever it first touches Git —
 * add's prepare, enable's loop, a filter's refusal path — and no branch git cannot
 * name is ever made (before this, `add -- -x` and `add HEAD` made two). No verb
 * refuses a name ahead of it, and no command either: a user's empty `-p ""` and
 * an empty positional read this one refusal. A branch a listing names is Git's
 * already, and is read back under the reference rule it was listed by
 * (infra/epoch.c epoch_walk): the branch rule refuses two shapes a reference
 * can hold.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer: DOTTA_REFNAME_MAX
 * @param name Branch name (must not be NULL)
 * @return NULL, or ERR_INVALID_ARG naming the name ("Branch name cannot be empty"
 *         for none); the builder's length refusal
 */
error_t gitops_branch_refname(
    char *buffer, size_t buffer_size, const char *name
);

/**
 * A branch's remote-tracking reference, or the reference rule's refusal
 *
 * The one place a remote and a branch become `refs/remotes/<remote>/<branch>`,
 * sized and checked by gitops_build_refname, whose refusals name the whole
 * reference. The branch half is the caller's: a profile's name, held to the branch
 * rule where its own ref is built (gitops_branch_refname).
 *
 * Readers: sys/remote.c remote_fetch, remote_follow, remote_take and
 * remote_read_heads; cmds/remove.c remove_profile, the tracking ref its deletion
 * is leased on.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer: DOTTA_REFNAME_MAX
 * @param remote Remote name (must not be NULL)
 * @param branch Branch name (must not be NULL)
 * @return NULL, or the builder's refusal naming the reference
 */
error_t gitops_remote_branch_refname(
    char *buffer, size_t buffer_size, const char *remote, const char *branch
);

/**
 * Get tree from commit OID
 *
 * Convenience function to extract tree from a commit.
 *
 * @param repo Repository (must not be NULL)
 * @param commit_oid Commit OID (must not be NULL)
 * @param out_tree Tree object (must not be NULL, caller must free with
 *                 git_tree_free)
 * @return Error or NULL on success
 */
error_t gitops_get_tree_from_commit(
    git_repository *repo,
    const git_oid *commit_oid,
    git_tree **out_tree
);

/**
 * Generate diff between two trees
 *
 * Thin wrapper around git_diff_tree_to_tree. NULL trees are allowed for
 * "added/deleted" semantics.
 *
 * @param repo Repository (must not be NULL)
 * @param old_tree Old tree (can be NULL for "added from nothing")
 * @param new_tree New tree (can be NULL for "deleted to nothing")
 * @param opts Diff options (can be NULL for defaults)
 * @param out_diff Output diff object (must not be NULL, caller must free with
 *                 git_diff_free)
 * @return Error or NULL on success
 */
error_t gitops_diff_trees(
    git_repository *repo,
    git_tree *old_tree,
    git_tree *new_tree,
    const git_diff_options *opts,
    git_diff **out_diff
);

/**
 * Get statistics from diff object
 *
 * Extracts files_changed, insertions, deletions counts.
 *
 * @param diff Diff object (must not be NULL)
 * @param out_stats Stats object (must not be NULL, caller must free with
 *                  git_diff_stats_free)
 * @return Error or NULL on success
 */
error_t gitops_diff_get_stats(
    git_diff *diff,
    git_diff_stats **out_stats
);

/**
 * The merge base of two commits, or Git's null id where they share none
 *
 * The best common ancestor for a three-way merge — the first of several, where
 * a criss-cross leaves more than one (lib/libgit2/src/libgit2/merge.c
 * git_merge_base). Two commits that share no history are an answer, never a
 * failure: the null id, where libgit2 answers GIT_ENOTFOUND, which it answers
 * for that alone — a commit it could not load being -1 (merge.c merge_bases) —
 * so a reader tests the id, as one reads a reference's absence
 * (gitops_reference_oid). Readers: sys/stage.c stage_merge_trees, which merges
 * two such histories over Git's empty tree; cmds/sync.c sync_disagreements, the
 * floor of the names a merge's two sides took, where none is no line; and
 * sys/remote.c remote_relate and remote_ahead, where a branch against its remote
 * reads two histories sharing none: the remote's branch recreated, or a tracking
 * ref no counterpart.
 *
 * @param repo Repository (must not be NULL)
 * @param one First commit OID (must not be NULL)
 * @param two Second commit OID (must not be NULL)
 * @param out_oid The merge base, or the null id: none shared (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_find_merge_base(
    git_repository *repo,
    const git_oid *one,
    const git_oid *two,
    git_oid *out_oid
);

/**
 * Write a commit object, moving no reference
 *
 * git_commit_create_buffer's whole contract — the author, the committer, the
 * message's encoding, the message, the tree and the parents, each written as
 * handed — and, where `action` names one, one header after the committer's lines:
 * the action that made the commit, in the word its writer names it by. libgit2
 * writes a header only through a writer that moves no reference
 * (lib/libgit2/src/libgit2/commit.c git_commit_create_with_signature). With no
 * action the object is the one git_commit_create writes from the same inputs,
 * byte for byte.
 *
 * The reference is its writer's to write, from the state it read
 * (gitops_write_reference). Reader: sys/stage.c stage_commit, with its writer's
 * action.
 *
 * @param repo Repository (must not be NULL)
 * @param author The author (must not be NULL)
 * @param committer The committer (must not be NULL)
 * @param message_encoding The message's encoding (NULL: none, UTF-8)
 * @param message The message (must not be NULL)
 * @param tree The tree (must not be NULL; the repository's)
 * @param parent_count How many parents (0: a root)
 * @param parents The parents, in order (must not be NULL where parent_count > 0)
 * @param action The word the action's header carries (NULL: no header)
 * @param out The commit's id (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_create_commit(
    git_repository *repo,
    const git_signature *author,
    const git_signature *committer,
    const char *message_encoding,
    const char *message,
    const git_tree *tree,
    size_t parent_count,
    const git_commit *parents[],
    const char *action,
    git_oid *out
);

/**
 * The action a commit's header names, or NULL where it names none
 *
 * The word gitops_create_commit writes after the committer's lines, read as libgit2
 * reads a header (lib/libgit2/src/libgit2/commit.c git_commit_header_field):
 * the key's first line, a value continued past a newline joined to its
 * continuation, so a word written is the word read. NULL is a commit with no
 * such line — a hand's, git's own. The word is opaque here: what each one means
 * is infra/commit's.
 *
 * Reader: sys/history.c history_read, the word of each commit that took a path
 * away.
 *
 * @param commit The commit (must not be NULL)
 * @param arena The arena the word lives in (must not be NULL)
 * @param out The word, the arena's, or NULL: the commit names none (must not be
 *            NULL)
 * @return Error or NULL on success
 */
error_t gitops_commit_action(
    const git_commit *commit,
    arena_t *arena,
    const char **out
);

#endif /* DOTTA_GITOPS_H */
