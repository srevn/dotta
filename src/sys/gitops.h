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
 * is the library's, never one of dotta's own. A refspec joins two names, a ':'
 * between them and the force's '+' before.
 */
#define DOTTA_REFNAME_MAX 1024                        /* a name, and its NUL */
#define DOTTA_REFSPEC_MAX (2 * DOTTA_REFNAME_MAX + 1) /* [+]<name>:<name>, and NUL */

#define DOTTA_MESSAGE_MAX 512                         /* For commit messages */

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
error_t gitops_init(void);

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
error_t gitops_get_signature(git_signature **out, git_repository *repo);

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
error_t gitops_open_repository(git_repository **out, const char *path);

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
 * is stored: a symbolic one is not resolved.
 *
 * A miss leaves the handle on that fresh reference database, so a create-only
 * write that follows a proven absence finds the name free on the store as the
 * proof read it (sys/stage.c stage_orphan's root commit, gitops_create_reference
 * without force). A reference or an iterator held from before keeps the database
 * it came from — libgit2 counts it — so nothing a caller holds is freed under it.
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
 * its id, its commit, its tree (their headers).
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
 * (gitops_branch_refname) on the way.
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_branch_exists(git_repository *repo, const char *name, bool *exists);

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
 * List the references under a namespace
 *
 * The names beneath `namespace` — "refs/heads" lists a branch as "p", "refs"
 * lists it as "heads/p" — complete or an error (the header). libgit2's enumeration
 * under the namespace first, on a reference database that has read nothing yet
 * — packed-refs parsed whole, so a damaged file refuses the listing every time and
 * never lists as a store without packed refs (gitops_reference_find says why);
 * then the loose store beneath it, read whole as the invoker, as libgit2 reads
 * it, every ref file looked up: a refusal is the listing's, in Git's words, and
 * a ref the enumeration did not name is appended under the name libgit2 gives
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
error_t gitops_delete_branch(git_repository *repo, const char *name);

/**
 * The commit a reference names, or NULL where no reference stands
 *
 * gitops_reference_oid, and the object at that id, which must be a commit: a
 * branch names a commit — Git writes nothing else to one (lib/git/refs.c
 * ref_transaction_update refuses a "non-commit object") and dotta writes nothing
 * else anywhere — so a reference that stands at a tree, a blob or a tag is refused,
 * naming what it found. A tag is not peeled: the stage commits on a branch only
 * from the target libgit2 reads there (commit.c validate_tree_and_parents), and
 * a tip read through a tag is one no commit can be made on. NULL is the reference's
 * absence, proven.
 *
 * The one way a reference becomes a tip. Readers: gitops_reference_tree, and
 * the readers of a tree through it (its header); gitops_load_reference_commit,
 * which refuses the absence; infra/epoch.c epoch_walk, the census, at each branch
 * it lists, one gone since the listing holding nothing.
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
 * load were two: core/ignore.c ignore_blob_read (no .dottaignore yet) and
 * gitops_branch_tree.
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
 * The tree a branch names, or NULL where the branch does not stand
 *
 * gitops_reference_tree of refs/heads/<name>, the name through the branch rule
 * (gitops_branch_refname) on the way. Readers: core/manifest.c manifest_build
 * (a profile whose branch is gone contributes nothing), core/workspace.c
 * workspace_orphan_authority (an orphan whose branch is gone is lost),
 * sys/bootstrap.c bootstrap_exists, and gitops_load_branch_tree, which refuses
 * the absence.
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
 * label_prefixes) — core/manifest.c manifest_claim_blob, core/profiles.c
 * profile_list_entry and profile_count_entry, cmds/export.c collect_entry, and
 * cmds/completion.c refspec_emit, which also STOPs at its cap; and the ciphertext
 * census, which SKIPs a binding it has met and STOPs where its asker has an answer
 * (infra/epoch.c epoch_present_blob).
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
error_t gitops_read_blob_content(
    git_repository *repo,
    const git_oid *oid,
    void **out_content,
    size_t *out_size
);

/**
 * Load the commit a reference names
 *
 * gitops_reference_commit for a reader that needs the reference: its absence,
 * proven, is refused (ERR_NOT_FOUND, naming the reference). Readers: sys/stage.c
 * stage_open (the parent-to-be), cmds/status.c status_print_remote (the
 * remote-tracking branch's tip), and gitops_load_branch_commit.
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
 * Load the commit at a branch's tip
 *
 * gitops_load_reference_commit of refs/heads/<branch>, the name through the branch
 * rule (gitops_branch_refname) on the way, and every failure names the reference.
 * Readers: the revision's three askers, gitops_resolve_commit_in_branch and
 * core/profiles.c profile_resolve_commit and profile_resolve_range, which read
 * a branch's tip once and ask it; cmds/list.c list_profiles, list_files and
 * list_file_history, which read every fact a screen prints off it; cmds/status.c
 * status_print_remote, which prints it; cmds/completion.c commits_walk, which
 * walks back from it.
 *
 * @param repo Repository (must not be NULL)
 * @param branch Branch name (must not be NULL)
 * @param out The tip (must not be NULL, caller must free with git_commit_free)
 * @return Error or NULL on success
 */
error_t gitops_load_branch_commit(
    git_repository *repo,
    const char *branch,
    git_commit **out
);

/**
 * A revision a user named, read before any branch is chosen
 *
 * Two kinds of spelling name a commit. HEAD's — `HEAD` or `@`, alone or with
 * its steps back, `~N` and `^N` in any chain (base/refspec.h refspec_ancestry)
 * — names a commit of a branch, and only once the branch is chosen: its tip,
 * and the steps back from it. Every other spelling is git's revision syntax and
 * names one commit whichever branch is asked after — an id, a short id, a tag
 * peeled to its commit, `<id>~N` — so it is resolved once, when the revision is
 * read.
 *
 * Nothing is held but the spelling and one commit's id, so the value needs no
 * release and is copied freely; it is valid while the spelling is.
 */
typedef struct {
    const char *spelling;   /* as typed, borrowed: what every refusal names */
    const char *ancestry;   /* HEAD's steps, borrowed ("" the tip); NULL: a commit */
    git_oid commit;         /* the commit the spelling names; unread where ancestry is */
} gitops_revision_t;

/**
 * Read a revision
 *
 * HEAD's steps are read whole, so one dotta does not walk — anything after HEAD
 * but `~N` and `^N`, `HEAD@{1}`, `@{1}` and `HEAD^{commit}` among them — refuses
 * here, before any branch is. A count too large for any history is read as it
 * is: the walk answers that it reaches past the root.
 *
 * Every other spelling is resolved now, and resolving it is required: one that
 * names no commit is the failure, in Git's words, whatever kept it from naming
 * one — a typo, an ambiguous short id, a commit or a tag object the store has
 * lost — and a spelling that names a tree or a blob refuses as naming no commit.
 * No branch is ever passed over for a spelling that does not resolve.
 *
 * @param repo Repository (must not be NULL)
 * @param spelling The revision as typed (must not be NULL; borrowed by `out`)
 * @param out The revision (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t gitops_revision_resolve(
    git_repository *repo,
    const char *spelling,
    gitops_revision_t *out
);

/**
 * The commit a revision names in a branch, or NULL where the branch has none
 *
 * A query, asked of a tip the caller read once (gitops_load_branch_commit) so
 * every revision asked of a branch is asked of one tip. HEAD's steps are walked
 * back from it, and NULL is the history shorter than they reach — proven by the
 * parent count each commit on the way was read with, never by a lookup that missed.
 * A commit is the branch's where the tip is that commit or reaches it through
 * its parents, and NULL is a history that does not hold it. A parent the walk
 * could not load and a history the query could not read are the failures, each
 * naming the revision and the branch — even where libgit2 answers GIT_ENOTFOUND,
 * which here is an object the store has lost and never an answer.
 *
 * @param repo Repository (must not be NULL)
 * @param rev The revision (must not be NULL)
 * @param branch The tip's branch, for what a failure names (must not be NULL)
 * @param tip The branch's tip (must not be NULL; borrowed)
 * @param out The commit (caller frees with git_commit_free), or NULL: none in
 *            the branch (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_revision_find(
    git_repository *repo,
    const gitops_revision_t *rev,
    const char *branch,
    git_commit *tip,
    git_commit **out
);

/**
 * The commit a revision names in a named branch, or a refusal
 *
 * The revision read (gitops_revision_resolve), the branch's tip read once
 * (gitops_load_branch_commit), and the one asked of the other
 * (gitops_revision_find); a revision the branch has no commit for is the refusal
 * that says so — HEAD's steps reaching past the branch's history, a commit its
 * history does not hold. Every failure names what failed, the revision or the
 * branch, so a caller adds nothing by restating the subject. Readers, none of
 * which wraps: export.c cmd_export (the refspec's @commit), revert.c cmd_revert
 * (the commit reverted to), show.c show_source and cmd_show (a file's tree, and
 * a commit shown under a named profile).
 *
 * The commit is the whole answer, and its OID is read off it (git_commit_id):
 * nothing is handed back beside it, so no caller holds two views of one fact
 * and none looks the commit up a second time to reach its tree.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param commit_ref The revision as typed (must not be NULL)
 * @param out_commit Resolved commit object (must not be NULL, caller must free
 *                   with git_commit_free)
 * @return Error or NULL on success
 */
error_t gitops_resolve_commit_in_branch(
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
error_t gitops_fetch_remote(
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
error_t gitops_fetch_branch(
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
error_t gitops_fetch_branches(
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
error_t gitops_push_branch(
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
error_t gitops_force_push_branch(
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
error_t gitops_delete_remote_branch(
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
 * @param arena Arena the listing lives in (must not be NULL)
 * @param out Branch names on remote (must not be NULL; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t gitops_list_remote_branches(
    git_repository *repo,
    const char *remote_name,
    transfer_context_t *xfer,
    arena_t *arena,
    string_array_t *out
);

/**
 * Get URL for a remote
 *
 * The remote's URL, copied into the arena, or NULL where it has none: a remote
 * configured without a URL is legal — credentialed transfers tolerate one
 * (gitops_resolve_default_remote) — so its absence is an answer, never an error.
 * A lookup that fails — no such remote, a name Git refuses — is the error, in
 * Git's words, and leaves `*out_url` as it was.
 *
 * Readers: gitops_resolve_default_remote's URL, and the completion's description
 * of each configured remote (cmds/completion.c completion_remotes).
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param arena Arena the URL lives in (must not be NULL)
 * @param out_url The URL, the arena's, or NULL (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_get_remote_url(
    git_repository *repo,
    const char *remote_name,
    arena_t *arena,
    const char **out_url
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
 * When `out_url` is non-NULL, also looks up the remote's URL
 * (gitops_get_remote_url). A remote configured without a URL yields `*out_url =
 * NULL` and a successful return — credentialed transfers tolerate a NULL URL
 * (helper approve / reject become no-ops, SSH/anonymous still works), so this
 * stays a happy-path outcome rather than an error.
 *
 * The name is the configuration's, as git lists it, and nothing here judges it:
 * a name Git refuses — a hand-written `[remote ""]` among them — is refused by
 * the lookup of whichever verb takes it, in Git's words. Every verb that takes
 * a remote name looks it up before any other use of it, and none refuses one
 * ahead of that lookup.
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
error_t gitops_resolve_default_remote(
    git_repository *repo,
    arena_t *arena,
    const char **out_name,
    const char **out_url
);

/**
 * Create reference
 *
 * Without `force` the name must be free, and that is decided on a fresh read of
 * the store (gitops_reference_find says why): a packed ref of the name refuses
 * the create, and a packed-refs that will not parse refuses it too.
 *
 * @param repo Repository (must not be NULL)
 * @param name Reference name (e.g., "refs/heads/mybranch") (must not be NULL)
 * @param oid Target OID (must not be NULL)
 * @param force Overwrite if exists
 * @return Error or NULL on success
 */
error_t gitops_create_reference(
    git_repository *repo,
    const char *name,
    const git_oid *oid,
    bool force
);

/**
 * The id a reference names, or Git's null id where none stands
 *
 * gitops_reference_find, read through a symbolic reference to the one it names:
 * the null id — all zeros, git_oid_is_zero, Git's own id for no object — only
 * where the absence is proven. A symbolic reference that names nothing is a
 * failure, not an absence, and so is a reference that stands at the null id:
 * git reads one as broken (lib/git/refs/files-backend.c), never as missing. For
 * the readers that act on a reference's absence as an answer: sys/upstream.c
 * upstream_analyze_profile (no branch, no remote branch), cmds/sync.c
 * pull_branch_ff (nothing fetched to fast-forward to), infra/epoch.c
 * epoch_inspect_remote (no local epoch), gitops_reference_commit, which reads
 * the commit at the id, and gitops_resolve_reference_oid, which refuses it.
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
 * Resolve reference name to OID
 *
 * gitops_reference_oid for a reader that needs the reference: its absence, proven,
 * is refused (ERR_NOT_FOUND, naming the reference), and every failure of the
 * read is its own — a symbolic reference that names nothing, in Git's words;
 * one at the null id, as broken.
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Full reference name (e.g., "refs/heads/main") (must not be NULL)
 * @param out Target OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t gitops_resolve_reference_oid(
    git_repository *repo,
    const char *ref_name,
    git_oid *out
);

/**
 * Resolve a branch's tip to its id
 *
 * gitops_resolve_reference_oid of `refs/heads/<branch_name>`, the name through
 * the branch rule (gitops_branch_refname) on the way.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name without refs/heads/ prefix (must not be NULL)
 * @param out Target OID (must not be NULL)
 * @return Error or NULL on success (ERR_NOT_FOUND if branch missing)
 */
error_t gitops_resolve_branch_oid(
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
error_t gitops_resolve_remote_branch_oid(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
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
 * rule; this is for the other shapes.
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
error_t gitops_find_merge_base(
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
error_t gitops_merge_trees_safe(
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
error_t gitops_create_merge_commit(
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
error_t gitops_rebase_inmemory_safe(
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
error_t gitops_update_branch_reference(
    git_repository *repo,
    const char *branch_name,
    const git_oid *new_oid,
    const char *reflog_msg
);

#endif /* DOTTA_GITOPS_H */
