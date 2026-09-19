/**
 * gitops.h - Git operations wrapper
 *
 * Thin wrapper around libgit2 with error handling and resource management.
 *
 * Design principles:
 * - Validate all inputs
 * - Convert libgit2 errors to dotta errors
 * - Manage libgit2 object lifecycles
 * - No business logic (just git operations)
 *
 * Converting libgit2's errors includes its iterators, the ones easy to miss:
 * `git_reference_next_name`, `git_revwalk_next` and `git_rebase_next` each return
 * 0, GIT_ITEROVER at the end, or a negative code, and a loop testing only for 0
 * cannot tell an enumeration that finished from one that gave up. Every iteration
 * here classifies all three.
 *
 * For a ref listing that is necessary and not sufficient: libgit2's filesystem
 * refdb reads `packed-refs` loudly and the loose store as far as it can — a ref
 * file it cannot open or parse is skipped with the error cleared, a directory
 * it cannot open is an empty one, and its walk of a directory stops at a link it
 * cannot stat (refdb_fs.c `refdb_fs_backend__iterator_next`, `iter_load_paths`;
 * iterator.c `filesystem_iterator_frame_push`) — so an unreadable `refs/heads`
 * enumerates as nothing and ends GIT_ITEROVER. So every listing here reads the
 * loose store itself and looks each ref file up (gitops_list_refs). A LISTING
 * IS COMPLETE OR AN ERROR — Git's own words for the ref, the same a singular
 * lookup says of it, or the walk's for a directory it could not read — and a
 * caller acting on an absence in one (the census, the blocker, init's adoption
 * test) holds no proof of its own.
 */

#ifndef DOTTA_GITOPS_H
#define DOTTA_GITOPS_H

#include <git2.h>
#include <types.h>

/**
 * Common buffer size constants for Git operations
 *
 * These constants define standard buffer sizes used throughout dotta. Git allows
 * up to 255 chars per reference component, but we use conservative limits for
 * safety and to catch truncation early.
 */
#define DOTTA_REFNAME_MAX 256    /* For git reference names (refs/heads/...) */
#define DOTTA_REFSPEC_MAX 512    /* For git refspecs (refs/heads/foo:refs/remotes/origin/foo) */
#define DOTTA_MESSAGE_MAX 512    /* For commit messages and prompts */

/**
 * Initialize libgit2 for this process, and configure it
 *
 * One producer for a fact every binary linking this library shares: how dotta
 * configures libgit2. The library's options are process-wide, so a knob set in
 * a `main()` would be the shipped binary's alone and every unit suite would
 * exercise a differently configured library — a difference that costs only
 * performance today and would cost correctness the first time a knob is one of
 * the strict-object or owner-validation family. Paired with gitops_shutdown so
 * no caller writes half of the lifecycle.
 *
 * @return Error or NULL on success
 */
error_t *gitops_init(void);

/**
 * Release this process's libgit2
 *
 * Decrements the library's reference count, freeing its object cache with the
 * last reference. The other half of gitops_init's pair.
 */
void gitops_shutdown(void);

/**
 * Build a commit signature with fallback for missing git config.
 *
 * Tries git_signature_default first (reads user.name / user.email from .gitconfig);
 * on failure (common on fresh machines before dotfiles are deployed) falls back
 * to "$USER@$HOSTNAME" via getenv / gethostname, defaulting to "dotta@localhost"
 * when even those are unavailable.
 *
 * Used by every dotta path that creates a commit object — the stage's commit
 * (sys/stage), the merge commit and the rebase. Caller frees the returned signature
 * via `git_signature_free`.
 *
 * @param out  Output signature (caller frees with git_signature_free)
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_get_signature(git_signature **out, git_repository *repo);

/**
 * Open git repository at path
 *
 * The open is the presence test: there is no separate "is this a repository"
 * predicate, because answering it requires this call and discarding this call's
 * failure turns every unreadable repository into an absent one.
 *
 * The failure is classified so a caller can tell the cases apart:
 *   ERR_NOT_FOUND  — libgit2 found no repository here. It reports an
 *                    unreadable .git the same way and words both the same, so a
 *                    caller that needs the distinction asks the filesystem.
 *   ERR_PERMISSION — the repository is owned by another user.
 *   ERR_GIT        — everything else, carrying libgit2's own message: a
 *                    config file that will not parse (the user's ~/.gitconfig
 *                    is loaded on open), a damaged object database.
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_open_repository(git_repository **out, const char *path);

/**
 * Create a bare repository at path, or open the one that stands there
 *
 * `git init --bare`, the path made as needed. dotta's store is bare (utils/repo.h):
 * nothing is ever checked out, every write to a branch is a stage committed in
 * memory (sys/stage), and a working tree was the layer beneath an anchor branch
 * nothing reads any more. Over a repository that already stands the call is git's
 * re-init — refs and config kept, only what is missing written back, HEAD among
 * them — so a store a hand stripped of its HEAD is whole again; it does not make
 * a repository with a working tree bare, and a caller that must know reads
 * `git_repository_is_bare` on what it got.
 *
 * HEAD is written here once, `ref: refs/heads/<init.defaultBranch, else master>`,
 * unborn — git's own fresh state — and nothing in dotta reads or writes it after.
 * A symref a hand moves onto a profile makes that profile a GUI's current branch
 * and costs dotta nothing. Garbage in the file stops `dotta git` with git's own
 * words, and stops every commit too — libgit2 reads HEAD at each ref write to
 * decide whether the HEAD reflog gets the entry, and fails on what it finds,
 * naming the file — while every read runs; the file is the hand's to put back.
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_init_repository(git_repository **out, const char *path);

/**
 * Close repository and free resources
 *
 * Safe to call with NULL.
 *
 * @param repo Repository handle (can be NULL)
 */
void gitops_close_repository(git_repository *repo);

/**
 * Check if a reference exists
 *
 * The singular: the ref resolves, or it is absent. Anything else — a loose ref
 * that will not open, one whose bytes are not an OID — is the error, never an
 * absence, and every caller propagates it: a bool that read it as "no" once sent
 * the user to fetch a profile that was here. One lookup answers it for any ref
 * (a branch, the epoch, the baseline); a name outside refs/heads is the caller's
 * to spell in full.
 *
 * @param repo Repository (must not be NULL)
 * @param refname Full reference name (must not be NULL or empty)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_reference_exists(
    git_repository *repo, const char *refname, bool *exists
);

/**
 * Check if branch exists
 *
 * gitops_reference_exists of refs/heads/<name>, the name through the branch rule
 * (gitops_branch_refname) on the way.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_branch_exists(git_repository *repo, const char *name, bool *exists);

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
 * one.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name to test (must not be NULL)
 * @param out_blocker Receives the blocking branch's name (caller frees), or NULL
 *                    when nothing blocks (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_branch_blocker(
    git_repository *repo, const char *name, char **out_blocker
);

/**
 * List the references under a namespace
 *
 * The names beneath `namespace` — "refs/heads" lists a branch as "p", "refs"
 * lists it as "heads/p" — complete or an error (the header). libgit2's enumeration
 * under the namespace first; then the loose store beneath it, read whole, every
 * ref file looked up: a refusal is the listing's, in Git's words, and a ref the
 * enumeration did not name is appended under the name libgit2 gives it — one
 * born since the enumeration read, one behind a directory this run reads through
 * and libgit2 does not (a run that holds root), one past a dangling link, where
 * libgit2's walk of the directory stops. Loose refs are named by their path, so
 * a namespace with no directory holds no loose refs (a remote never fetched,
 * every ref packed) and is not an error. Order is the enumeration's, the appended
 * after it.
 *
 * gitops_list_branches and gitops_list_remote_tracking are this under their
 * namespaces; init's adoption test asks it of "refs" whole.
 *
 * @param repo Repository (must not be NULL)
 * @param namespace The namespace, no trailing slash (must not be NULL or empty)
 * @param out String array of names beneath it (must not be NULL, caller frees)
 * @return Error or NULL on success
 */
error_t *gitops_list_refs(
    git_repository *repo, const char *namespace, string_array_t **out
);

/**
 * List all local branches
 *
 * Every branch under refs/heads by name, complete or an error (gitops_list_refs).
 *
 * @param repo Repository (must not be NULL)
 * @param out String array of branch names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_list_branches(git_repository *repo, string_array_t **out);

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
 * @param out String array of branch names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_list_remote_tracking(
    git_repository *repo,
    const char *remote_name,
    string_array_t **out
);

/**
 * Delete a branch
 *
 * The ref and its reflog. Refused, in dotta's words, when a linked worktree of
 * the repository has the branch checked out (`dotta git worktree add`): a bare
 * store checks nothing out itself, so a worktree is the one place a checkout of
 * a profile can stand, and `git_reference_delete` would take the branch from
 * under it without a word. Not refused for the branch HEAD names: HEAD is git's
 * and unborn (gitops_init_repository), a hand may have pointed it at a profile,
 * and git itself deletes that branch in a bare repository — `git_branch_delete`
 * is the stricter one and is not used. Per-branch config another tool wrote
 * (`branch.<name>.*`) is that tool's and stays; dotta writes none.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_branch(git_repository *repo, const char *name);

/**
 * Load tree from reference
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Reference name (e.g., "refs/heads/main") (must not be NULL)
 * @param out Tree object (must not be NULL, caller must free with git_tree_free)
 * @return Error or NULL on success
 */
error_t *gitops_load_tree(git_repository *repo, const char *ref_name, git_tree **out);

/**
 * Load tree from a branch by name, optionally capturing the peeled HEAD OID
 *
 * Convenience wrapper: builds "refs/heads/<branch_name>" and resolves to tree.
 * When out_oid is non-NULL, atomically captures the peeled OID from the same
 * git_reference_peel that produces the tree — no separate ref lookup needed.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out_tree Tree object (must not be NULL, caller must free with
 *                 git_tree_free)
 * @param out_oid Peeled HEAD OID (can be NULL to skip)
 * @return Error or NULL on success
 */
error_t *gitops_load_branch_tree(
    git_repository *repo,
    const char *branch_name,
    git_tree **out_tree,
    git_oid *out_oid
);

/**
 * Walk tree with callback
 *
 * @param tree Tree to walk (must not be NULL)
 * @param callback Callback function (must not be NULL)
 * @param payload User data passed to callback
 * @return Error or NULL on success
 */
error_t *gitops_tree_walk(
    const git_tree *tree,
    git_treewalk_cb callback,
    void *payload
);

/**
 * Zero-copy view into a git blob's raw bytes.
 *
 * Holds an open git_blob handle and exposes its raw content without copying.
 * The `data` pointer is owned by libgit2's object cache and is valid only between
 * gitops_blob_view_open() and gitops_blob_view_close().
 *
 * Use this when you only need to inspect or stream the bytes through another
 * consumer (e.g. magic header check, decryption pipeline). Use
 * gitops_read_blob_content() when you need an owned, null-terminated copy for
 * parsing.
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
error_t *gitops_blob_view_open(
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
 * Read blob content by OID
 *
 * Looks up a blob by OID, copies its content into a caller-owned null-terminated
 * buffer. The returned size is the raw blob size (not including the null
 * terminator).
 *
 * For callers that only need to inspect or stream the bytes without owning a
 * copy, prefer gitops_blob_view_open() to avoid the extra allocation and memcpy.
 *
 * @param repo Repository (must not be NULL)
 * @param oid Blob OID (must not be NULL)
 * @param out_content Content buffer (must not be NULL, caller must free)
 * @param out_size Content size in bytes (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_read_blob_content(
    git_repository *repo,
    const git_oid *oid,
    void **out_content,
    size_t *out_size
);

/**
 * Get commit from reference
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Reference name (must not be NULL)
 * @param out Commit object (must not be NULL, caller must free with
 *            git_commit_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_commit(
    git_repository *repo,
    const char *ref_name,
    git_commit **out
);

/**
 * Resolve a commit reference reachable from a branch
 *
 * Resolves commit_ref to a commit OID and verifies that commit is reachable from
 * branch_name's tip — i.e. equals the tip or is one of its ancestors.
 *
 * Supported syntax:
 * - "HEAD"             — branch's tip
 * - "HEAD~N", "HEAD^N" — ancestry relative to the branch (not repo HEAD)
 * - Full or short SHA  — must point to a commit reachable from the branch
 * - Annotated/lightweight tags — peeled to commit, must be reachable
 *
 * Reachability invariant: git_revparse_single resolves repository-wide, so a
 * SHA from another branch would otherwise succeed and silently misattribute the
 * commit. This function enforces the constraint the name implies.
 *
 * Returns ERR_NOT_FOUND if commit_ref cannot be resolved or if it resolves to a
 * commit not reachable from branch_name's tip. Every other failure is a rung of
 * the resolution that could not be made — the branch unreadable, its tip
 * unreadable, a reference that peels to no commit, an ancestry the walk could
 * not decide — and each is ERR_GIT under a sentence naming both the rung and
 * the branch. A caller therefore adds nothing by restating the subject: a wrap
 * saying "not found" over one of them would name a fate this function did not
 * reach. Readers, none of which wraps: export.c cmd_export (the refspec's
 * @commit), revert.c cmd_revert (the commit reverted to), show.c show_source
 * and cmd_show (a file's tree, and a commit shown under a named profile), and
 * profiles.c profile_resolve_commit, which asks a whole set and is the one reader
 * that reads the code — ERR_NOT_FOUND meaning "not this branch's, ask the next"
 * and every other code ending its search.
 *
 * The commit is the whole answer, and its OID is read off it (git_commit_id):
 * nothing is handed back beside it, so no caller holds two views of one fact
 * and none looks the commit up a second time to reach its tree.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_commit Resolved commit object (must not be NULL, caller must free
 *                   with git_commit_free)
 * @return Error or NULL on success
 */
error_t *gitops_resolve_commit_in_branch(
    git_repository *repo,
    const char *branch_name,
    const char *commit_ref,
    git_commit **out_commit
);

/* Forward declaration for transfer context */
typedef struct transfer_context_s transfer_context_t;

/**
 * Fetch everything a remote has, under its own refspecs
 *
 * `git fetch <remote>`: the refspec the remote was created with — every branch
 * under refs/heads to refs/remotes/<remote>, for one `git_remote_create` made —
 * and nothing else. Every branch the remote has lands as a remote-tracking ref;
 * no local branch is made and HEAD is not touched; the refs under refs/dotta
 * are not under the refspec and do not come (the epoch has its own fetch,
 * infra/epoch). The clone's one round trip; a name the remote lacks is not an
 * error of the fetch, so what landed is read afterwards
 * (gitops_list_remote_tracking).
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_remote(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer
);

/**
 * Fetch branch from remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * Fetch multiple branches from remote in a single operation
 *
 * Performs a batched fetch of multiple branches, significantly reducing network
 * overhead compared to fetching each branch individually.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin") (must not be NULL)
 * @param branches Branch names to fetch (must not be NULL, count > 0)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_fetch_branches(
    git_repository *repo,
    const char *remote_name,
    const string_array_t *branches,
    transfer_context_t *xfer
);

/**
 * Push branch to remote
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * Force-push branch to remote (overwrites remote history).
 *
 * Identical to gitops_push_branch except the refspec is prefixed with '+', which
 * instructs the server to accept a non-fast-forward update. Used by sync's 'ours'
 * divergence strategy.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_force_push_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * Delete a branch from remote repository
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_remote_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    transfer_context_t *xfer
);

/**
 * List branches advertised by the remote server (network op).
 *
 * Connects to the remote and reads the advertised refs via git_remote_ls. Unlike
 * gitops_list_remote_tracking (which reads cached refs under
 * refs/remotes/<remote>/), this is authoritative — it sees branches added to
 * the server since the last fetch — but requires network and credentials.
 *
 * Filters results to refs under refs/heads/, excluding empty names.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param xfer Transfer context for credentials and op lifecycle (must not be NULL)
 * @param out_branches Branch names on remote (must not be NULL, caller frees)
 * @return Error or NULL on success
 */
error_t *gitops_list_remote_branches(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    string_array_t **out_branches
);

/**
 * Get URL for a remote
 *
 * Looks up a remote by name and returns a copy of its URL.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param out_url URL string (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_get_remote_url(
    git_repository *repo,
    const char *remote_name,
    char **out_url
);

/**
 * Resolve the default remote (name + optional URL) into arena.
 *
 * Selection strategy:
 *   1. Prefer "origin" if it exists.
 *   2. Otherwise use the only configured remote.
 *   3. Multiple remotes without "origin" → error (require explicit choice).
 *   4. No remotes → error with a hint to add one.
 *
 * When `out_url` is non-NULL, also looks up the remote's URL. A remote configured
 * without a URL yields `*out_url = NULL` and a successful return — credentialed
 * transfers tolerate a NULL URL (helper approve / reject become no-ops,
 * SSH/anonymous still works), so this stays a happy-path outcome rather than an
 * error.
 *
 * Outputs are arena-borrowed; the caller does not free them, and they remain
 * valid for the lifetime of the arena.
 *
 * @param repo     Repository (must not be NULL)
 * @param arena    Arena for output strings (must not be NULL)
 * @param out_name Remote name (must not be NULL; arena-borrowed on success)
 * @param out_url  Optional URL out-param (NULL skips URL lookup)
 * @return Error or NULL on success
 */
error_t *gitops_resolve_default_remote(
    git_repository *repo,
    arena_t *arena,
    const char **out_name,
    const char **out_url
);

/**
 * Create reference
 *
 * @param repo Repository (must not be NULL)
 * @param name Reference name (e.g., "refs/heads/mybranch") (must not be NULL)
 * @param oid Target OID (must not be NULL)
 * @param force Overwrite if exists
 * @return Error or NULL on success
 */
error_t *gitops_create_reference(
    git_repository *repo,
    const char *name,
    const git_oid *oid,
    bool force
);

/**
 * Resolve reference name to OID
 *
 * Convenience function that resolves a reference name directly to its target
 * OID without exposing the intermediate reference object. Handles symbolic
 * references transparently.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (e.g., "refs/heads/main") (must not be NULL)
 * @param out Target OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_resolve_reference_oid(
    git_repository *repo,
    const char *ref_name,
    git_oid *out
);

/**
 * Resolve a branch's current HEAD OID
 *
 * Convenience for `refs/heads/<branch_name>` resolution. Builds the full refname
 * and dispatches to gitops_resolve_reference_oid.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name without refs/heads/ prefix (must not be NULL)
 * @param out Target OID (must not be NULL)
 * @return Error or NULL on success (ERR_NOT_FOUND if branch missing)
 */
error_t *gitops_resolve_branch_head_oid(
    git_repository *repo,
    const char *branch_name,
    git_oid *out
);

/**
 * Resolve a remote-tracking branch's current OID
 *
 * Convenience for `refs/remotes/<remote_name>/<branch_name>` resolution. Builds
 * the full refname and dispatches to gitops_resolve_reference_oid.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name without refs/remotes/<remote>/ prefix (must
 *                    not be NULL)
 * @param out Target OID (must not be NULL)
 * @return Error or NULL on success (ERR_NOT_FOUND if remote branch missing)
 */
error_t *gitops_resolve_remote_branch_oid(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    git_oid *out
);

/**
 * Validate and build a Git reference name
 *
 * Builds a reference name using printf-style formatting and validates it fits
 * in the provided buffer without truncation.
 *
 * Git allows up to 255 chars per component, but we use conservative limits to
 * prevent silent failures with libgit2 operations.
 *
 * A branch name goes through gitops_branch_refname, which carries Git's branch
 * rule; this is for the other shapes.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer
 * @param format Printf-style format string (must not be NULL)
 * @param ... Format arguments
 * @return Error or NULL on success
 */
error_t *gitops_build_refname(
    char *buffer, size_t buffer_size, const char *format, ...
);

/**
 * A branch name to its reference, or Git's refusal
 *
 * The one place a branch name becomes `refs/heads/<name>`. Git's branch rule
 * first (git_branch_name_is_valid: the reference rule on the joined name, plus
 * the two shapes only the branch rule refuses — a leading '-' and the word HEAD,
 * valid references git itself will not make branches of), then the join, sized
 * to the buffer by gitops_build_refname, whose own reference check the branch
 * rule subsumes. Every lookup, creator and mover of a branch builds its ref here,
 * so a name Git refuses is refused wherever it first touches Git — add's prepare,
 * enable's loop, a filter's refusal path — and no branch git cannot name is ever
 * made (before this, `add -- -x` and `add HEAD` made two).
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer
 * @param name Branch name (must not be NULL)
 * @return NULL, or ERR_INVALID_ARG naming the name; the builder's length refusal
 */
error_t *gitops_branch_refname(
    char *buffer, size_t buffer_size, const char *name
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
error_t *gitops_get_tree_from_commit(
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
error_t *gitops_diff_trees(
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
error_t *gitops_diff_get_stats(
    git_diff *diff,
    git_diff_stats **out_stats
);

/**
 * Find merge base between two commits
 *
 * Finds the best common ancestor for a three-way merge.
 *
 * @param repo Repository (must not be NULL)
 * @param one First commit OID (must not be NULL)
 * @param two Second commit OID (must not be NULL)
 * @param out_oid Merge base commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_find_merge_base(
    git_repository *repo,
    const git_oid *one,
    const git_oid *two,
    git_oid *out_oid
);

/**
 * Merge trees without modifying HEAD or working directory
 *
 * Performs a three-way merge using common ancestor. This is a pure tree-level
 * operation that never touches HEAD.
 *
 * @param repo Repository (must not be NULL)
 * @param ancestor_oid Common ancestor commit (must not be NULL)
 * @param our_oid Our commit (local) (must not be NULL)
 * @param their_oid Their commit (remote) (must not be NULL)
 * @param out_index Resulting merge index (must not be NULL, caller must free
 *                  with git_index_free)
 * @return Error or NULL on success
 */
error_t *gitops_merge_trees_safe(
    git_repository *repo,
    const git_oid *ancestor_oid,
    const git_oid *our_oid,
    const git_oid *their_oid,
    git_index **out_index
);

/**
 * Create merge commit from index
 *
 * Creates a merge commit with two parents. Does not update any references.
 *
 * @param repo Repository (must not be NULL)
 * @param index Merged index (must not be NULL, must not have conflicts)
 * @param our_commit Our commit (local) (must not be NULL)
 * @param their_commit Their commit (remote) (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out_oid Created commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_create_merge_commit(
    git_repository *repo,
    git_index *index,
    git_commit *our_commit,
    git_commit *their_commit,
    const char *message,
    git_oid *out_oid
);

/**
 * Perform in-memory rebase without modifying HEAD
 *
 * Rebases branch_oid onto onto_oid using libgit2's in-memory mode. This never
 * touches HEAD or the working directory.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_oid Branch to rebase (must not be NULL)
 * @param onto_oid Target to rebase onto (must not be NULL)
 * @param out_oid Final rebased commit OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_rebase_inmemory_safe(
    git_repository *repo,
    const git_oid *branch_oid,
    const git_oid *onto_oid,
    git_oid *out_oid
);

/**
 * Update branch reference to new commit
 *
 * Updates a branch reference without modifying HEAD. Thread-safe with reflog.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param new_oid New commit OID (must not be NULL)
 * @param reflog_msg Reflog message (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_update_branch_reference(
    git_repository *repo,
    const char *branch_name,
    const git_oid *new_oid,
    const char *reflog_msg
);

#endif /* DOTTA_GITOPS_H */
