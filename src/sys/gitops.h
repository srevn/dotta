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
 */

#ifndef DOTTA_GITOPS_H
#define DOTTA_GITOPS_H

#include <git2.h>
#include <types.h>

/**
 * Common buffer size constants for Git operations
 *
 * These constants define standard buffer sizes used throughout dotta.
 * Git allows up to 255 chars per reference component, but we use
 * conservative limits for safety and to catch truncation early.
 */
#define DOTTA_REFNAME_MAX 256    /* For git reference names (refs/heads/...) */
#define DOTTA_REFSPEC_MAX 512    /* For git refspecs (refs/heads/foo:refs/remotes/origin/foo) */
#define DOTTA_MESSAGE_MAX 512    /* For commit messages and prompts */

/**
  * Build a commit signature with fallback for missing git config.
  *
  * Tries git_signature_default first (reads user.name / user.email from
  * .gitconfig); on failure (common on fresh machines before dotfiles are
  * deployed) falls back to "$USER@$HOSTNAME" via getenv / gethostname,
  * defaulting to "dotta@localhost" when even those are unavailable.
  *
  * Used by every dotta path that creates a commit object — orphan-branch
  * creation, profile commits, and the repository config ref. Caller frees
  * the returned signature via `git_signature_free`.
  *
  * @param out  Output signature (caller frees with git_signature_free)
  * @param repo Repository (must not be NULL)
  * @return Error or NULL on success
  */
error_t *gitops_get_signature(git_signature **out, git_repository *repo);

/**
 * Open git repository at path
 *
 * @param out Repository handle (must not be NULL)
 * @param path Repository path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_open_repository(git_repository **out, const char *path);

/**
 * Close repository and free resources
 *
 * Safe to call with NULL.
 *
 * @param repo Repository handle (can be NULL)
 */
void gitops_close_repository(git_repository *repo);

/**
 * Discover repository starting from path
 *
 * Searches upward from start_path to find .git directory.
 *
 * @param out Repository path (must not be NULL, caller must free)
 * @param start_path Starting search path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_discover_repository(char **out, const char *start_path);

/**
 * Discover and open repository
 *
 * Convenience function combining discover + open.
 *
 * @param out Repository handle (must not be NULL)
 * @param start_path Starting search path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_discover_and_open(git_repository **out, const char *start_path);

/**
 * Check if path is a valid git repository
 *
 * @param path Path to check (must not be NULL)
 * @return true if path exists and is a valid git repository
 */
bool gitops_is_repository(const char *path);

/**
 * Check if branch exists
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @param exists Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_branch_exists(git_repository *repo, const char *name, bool *exists);

/**
 * Create orphan branch (no parent commits)
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_create_orphan_branch(git_repository *repo, const char *name);

/**
 * List all local branches
 *
 * @param repo Repository (must not be NULL)
 * @param out String array of branch names (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_list_branches(git_repository *repo, string_array_t **out);

/**
 * List all remote tracking branches
 *
 * Returns branch names (without <remote>/ prefix) for all remote tracking
 * references. Filters out special refs (HEAD, dotta-worktree).
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
 * Delete branch
 *
 * @param repo Repository (must not be NULL)
 * @param name Branch name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_delete_branch(git_repository *repo, const char *name);

/**
 * Get current branch name
 *
 * @param repo Repository (must not be NULL)
 * @param out Branch name (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_current_branch(git_repository *repo, char **out);

/**
 * Check if a branch is the currently checked-out branch (HEAD)
 *
 * Compares branch_name against the branch that HEAD references.
 * Returns false for detached HEAD state or bare repositories.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch to check (must not be NULL)
 * @param is_current Output: true if branch is current HEAD (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_is_current_branch(
    git_repository *repo,
    const char *branch_name,
    bool *is_current
);

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
 * @param out_tree Tree object (must not be NULL, caller must free with git_tree_free)
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
    git_tree *tree,
    git_treewalk_cb callback,
    void *payload
);

/**
 * Find file by exact path in tree
 *
 * Normalizes path (strips all leading slashes) before lookup.
 *
 * @param tree Tree to search (must not be NULL)
 * @param path File path (must not be NULL)
 * @param out Tree entry (must not be NULL, caller must free with git_tree_entry_free)
 * @return Error or NULL on success
 */
error_t *gitops_find_file_in_tree(
    git_tree *tree,
    const char *path,
    git_tree_entry **out
);

/**
 * Zero-copy view into a git blob's raw bytes.
 *
 * Holds an open git_blob handle and exposes its raw content without
 * copying. The `data` pointer is owned by libgit2's object cache and
 * is valid only between gitops_blob_view_open() and
 * gitops_blob_view_close().
 *
 * Use this when you only need to inspect or stream the bytes through
 * another consumer (e.g. magic header check, decryption pipeline).
 * Use gitops_read_blob_content() when you need an owned, null-terminated
 * copy for parsing.
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
 * On failure, `*out` is left in a safe state (NULL handle/data, zero
 * size) so gitops_blob_view_close() is a no-op.
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
 * Safe to call with NULL, a zero-initialised view, or an already-closed
 * view. After close, all fields are zeroed so double-close is safe.
 *
 * @param view View to close (can be NULL)
 */
void gitops_blob_view_close(gitops_blob_view_t *view);

/**
 * Read blob content by OID
 *
 * Looks up a blob by OID, copies its content into a caller-owned
 * null-terminated buffer. The returned size is the raw blob size
 * (not including the null terminator).
 *
 * For callers that only need to inspect or stream the bytes without
 * owning a copy, prefer gitops_blob_view_open() to avoid the extra
 * allocation and memcpy.
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
 * Create commit
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param tree Tree object (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out Commit OID (can be NULL if not needed)
 * @return Error or NULL on success
 */
error_t *gitops_create_commit(
    git_repository *repo,
    const char *branch_name,
    git_tree *tree,
    const char *message,
    git_oid *out
);

/**
 * Get commit from reference
 *
 * @param repo Repository (must not be NULL)
 * @param ref_name Reference name (must not be NULL)
 * @param out Commit object (must not be NULL, caller must free with git_commit_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_commit(
    git_repository *repo,
    const char *ref_name,
    git_commit **out
);

/**
 * Resolve commit reference within a branch
 *
 * Resolves commit references (HEAD, HEAD~N, SHA, etc.) relative to a branch.
 * Supports:
 * - "HEAD" (branch HEAD)
 * - "HEAD~N" or "HEAD^N" (ancestry)
 * - Full/short SHA
 * - Tags
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param commit_ref Commit reference (must not be NULL)
 * @param out_oid Resolved commit OID (must not be NULL)
 * @param out_commit Resolved commit object (can be NULL if not needed, caller must free)
 * @return Error or NULL on success
 */
error_t *gitops_resolve_commit_in_branch(
    git_repository *repo,
    const char *branch_name,
    const char *commit_ref,
    git_oid *out_oid,
    git_commit **out_commit
);

/**
 * Update or create a file in a Git branch with atomic commit
 *
 * This function provides atomic file updates to Git branches:
 * 1. Creates a blob from the provided content
 * 2. Updates the branch tree to reference the new blob
 * 3. Creates a commit with the specified message
 *
 * If the file already exists with identical content, no commit is created (no-op).
 * This avoids cluttering history with empty commits when nothing has changed.
 *
 * Path support:
 * - Supports files at any directory depth
 * - Creates intermediate directories as needed
 * - Preserves existing sibling entries at each level
 * - Detects file/directory conflicts (error if path component is a file)
 *
 * Path normalization:
 * - Leading slashes stripped: "/foo/bar" -> "foo/bar"
 * - Double slashes collapsed: "foo//bar" -> "foo/bar"
 * - Trailing slashes rejected (not a file path)
 *
 * Examples:
 * - Root level: "README.md", ".bootstrap"
 * - One level: ".dotta/metadata.json"
 * - Deep path: "home/.config/nvim/init.vim"
 *
 * File modes:
 * - GIT_FILEMODE_BLOB (0100644): Regular file
 * - GIT_FILEMODE_BLOB_EXECUTABLE (0100755): Executable file
 *
 * Index handling:
 * - When `branch_name` is NOT the currently-checked-out branch (the
 *   common case — dotta keeps HEAD on dotta-worktree while mutating
 *   profile branches), the repository's shared index is left alone
 *   on purpose. Touching it would corrupt the checked-out branch's
 *   staging area.
 * - When `branch_name` IS the current branch, the shared index is
 *   re-seeded from the new tree so a subsequent workdir sync (e.g.
 *   `gitops_sync_worktree` with GIT_CHECKOUT_SAFE) can proceed
 *   without seeing phantom modifications. The workdir itself is the
 *   caller's responsibility — this function does not write to disk.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param file_path File path within branch (must not be NULL or empty)
 * @param content File content (must not be NULL)
 * @param content_size Size of content in bytes
 * @param commit_message Commit message (must not be NULL)
 * @param file_mode Git file mode (GIT_FILEMODE_BLOB or GIT_FILEMODE_BLOB_EXECUTABLE)
 * @param was_modified Optional output: set to true if file was modified, false if no-op (can be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_update_file(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    const char *content,
    size_t content_size,
    const char *commit_message,
    git_filemode_t file_mode,
    bool *was_modified
);

/**
 * Describes one blob to set/replace in a tree update batch.
 *
 * The blob referenced by `blob_oid` MUST already exist in the
 * repository's ODB. Callers creating fresh content are responsible
 * for writing the blob (e.g. git_blob_create_from_buffer) before
 * passing it in.
 */
typedef struct {
    const char *path;          /* Path within the tree (must not be empty) */
    git_oid blob_oid;          /* Blob OID (must exist in repo ODB) */
    git_filemode_t mode;       /* BLOB, BLOB_EXECUTABLE, or LINK */
} gitops_tree_update_t;

/**
 * Atomic multi-file tree update on a branch (HEAD-safe)
 *
 * Loads the current tree of `branch_name`, applies the requested
 * `updates` (blob replacements/insertions) and `removals` (path
 * deletions), writes the resulting tree, and creates a single commit
 * with `message`.
 *
 * This operation is HEAD-safe: it never touches the repository's
 * shared index (.git/index), the worktree, or HEAD. Safe to call
 * regardless of which branch HEAD points at — in dotta this matters
 * because HEAD always tracks `dotta-worktree`, not the profile
 * branches we mutate here.
 *
 * Mechanism: builds a standalone in-memory git_index, seeds it from
 * the branch HEAD tree, applies updates/removals, writes the
 * resulting tree directly to the ODB via git_index_write_tree_to,
 * and delegates commit creation to gitops_create_commit.
 *
 * git_index_add replaces entries at the same path, so updates that
 * overlap existing paths are "upserts" without needing an explicit
 * remove-before-add.
 *
 * At least one update or removal is required. Supported modes are
 * GIT_FILEMODE_BLOB, GIT_FILEMODE_BLOB_EXECUTABLE, and
 * GIT_FILEMODE_LINK (symlinks).
 *
 * No-op detection is the caller's responsibility: if all updates
 * collapse to the current tree, an empty-diff commit is still
 * created.
 *
 * @param repo          Repository (must not be NULL)
 * @param branch_name   Target branch (must not be NULL, must exist)
 * @param updates       Update entries (may be NULL if update_count is 0)
 * @param update_count  Number of update entries
 * @param removals      Paths to remove (may be NULL if removal_count is 0)
 * @param removal_count Number of removal paths
 * @param message       Commit message (must not be NULL)
 * @param out_oid       New commit OID (may be NULL if not needed)
 * @return Error or NULL on success
 */
error_t *gitops_commit_tree_updates_safe(
    git_repository *repo,
    const char *branch_name,
    const gitops_tree_update_t *updates,
    size_t update_count,
    const char *const *removals,
    size_t removal_count,
    const char *message,
    git_oid *out_oid
);

/* Forward declaration for transfer context */
typedef struct transfer_context_s transfer_context_t;

/**
 * Clone repository from URL
 *
 * @param out Repository handle (must not be NULL)
 * @param url Remote URL (must not be NULL)
 * @param local_path Local path for clone (must not be NULL)
 * @param xfer Transfer context for credentials and progress (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_clone(
    git_repository **out,
    const char *url,
    const char *local_path,
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
 * Performs a batched fetch of multiple branches, significantly reducing
 * network overhead compared to fetching each branch individually.
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
 * Identical to gitops_push_branch except the refspec is prefixed with
 * '+', which instructs the server to accept a non-fast-forward update.
 * Used by sync's 'ours' divergence strategy.
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
 * Connects to the remote and reads the advertised refs via git_remote_ls.
 * Unlike gitops_list_remote_tracking (which reads cached refs under
 * refs/remotes/<remote>/), this is authoritative — it sees branches
 * added to the server since the last fetch — but requires network
 * and credentials.
 *
 * Filters results to refs under refs/heads/, excluding dotta-worktree
 * and empty names.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param xfer Transfer context for credentials and op lifecycle
 *             (must not be NULL)
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
 * When `out_url` is non-NULL, also looks up the remote's URL. A remote
 * configured without a URL yields `*out_url = NULL` and a successful
 * return — credentialed transfers tolerate a NULL URL (helper approve /
 * reject become no-ops, SSH/anonymous still works), so this stays a
 * happy-path outcome rather than an error.
 *
 * Outputs are arena-borrowed; the caller does not free them, and they
 * remain valid for the lifetime of the arena.
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
 * Lookup reference
 *
 * @param repo Repository (must not be NULL)
 * @param name Reference name (must not be NULL)
 * @param out Reference object (must not be NULL, caller must free with git_reference_free)
 * @return Error or NULL on success
 */
error_t *gitops_lookup_reference(
    git_repository *repo,
    const char *name,
    git_reference **out
);

/**
 * Resolve reference name to OID
 *
 * Convenience function that resolves a reference name directly to its
 * target OID without exposing the intermediate reference object. Handles
 * symbolic references transparently.
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
 * Convenience for `refs/heads/<branch_name>` resolution. Builds the full
 * refname and dispatches to gitops_resolve_reference_oid.
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
 * Convenience for `refs/remotes/<remote_name>/<branch_name>` resolution.
 * Builds the full refname and dispatches to gitops_resolve_reference_oid.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (must not be NULL)
 * @param branch_name Branch name without refs/remotes/<remote>/ prefix (must not be NULL)
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
 * Builds a reference name using printf-style formatting and validates
 * it fits in the provided buffer without truncation.
 *
 * Git allows up to 255 chars per component, but we use conservative limits
 * to prevent silent failures with libgit2 operations.
 *
 * @param buffer Output buffer for the reference name (must not be NULL)
 * @param buffer_size Size of output buffer
 * @param format Printf-style format string (must not be NULL)
 * @param ... Format arguments
 * @return Error or NULL on success
 *
 * Example:
 *   char refname[256];
 *   error_t *err = gitops_build_refname(refname, sizeof(refname), "refs/heads/%s", branch);
 */
error_t *gitops_build_refname(char *buffer, size_t buffer_size, const char *format, ...);

/**
 * Get repository index
 *
 * @param repo Repository (must not be NULL)
 * @param out Index object (must not be NULL, caller must free with git_index_free)
 * @return Error or NULL on success
 */
error_t *gitops_get_index(git_repository *repo, git_index **out);

/**
 * Add file to index
 *
 * @param index Index (must not be NULL)
 * @param path Path relative to repository root (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_index_add(git_index *index, const char *path);

/**
 * Write index to disk and create tree
 *
 * @param index Index (must not be NULL)
 * @param out Tree OID (must not be NULL)
 * @return Error or NULL on success
 */
error_t *gitops_index_write_tree(git_index *index, git_oid *out);

/**
 * Get tree from commit OID
 *
 * Convenience function to extract tree from a commit.
 *
 * @param repo Repository (must not be NULL)
 * @param commit_oid Commit OID (must not be NULL)
 * @param out_tree Tree object (must not be NULL, caller must free with git_tree_free)
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
 * Thin wrapper around git_diff_tree_to_tree.
 * NULL trees are allowed for "added/deleted" semantics.
 *
 * @param repo Repository (must not be NULL)
 * @param old_tree Old tree (can be NULL for "added from nothing")
 * @param new_tree New tree (can be NULL for "deleted to nothing")
 * @param opts Diff options (can be NULL for defaults)
 * @param out_diff Output diff object (must not be NULL, caller must free with git_diff_free)
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
 * @param out_stats Stats object (must not be NULL, caller must free with git_diff_stats_free)
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
 * Performs a three-way merge using common ancestor. This is a pure
 * tree-level operation that never touches HEAD.
 *
 * @param repo Repository (must not be NULL)
 * @param ancestor_oid Common ancestor commit (must not be NULL)
 * @param our_oid Our commit (local) (must not be NULL)
 * @param their_oid Their commit (remote) (must not be NULL)
 * @param out_index Resulting merge index (must not be NULL, caller must free with git_index_free)
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
 * Rebases branch_oid onto onto_oid using libgit2's in-memory mode.
 * This never touches HEAD or the working directory.
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

/**
 * Synchronize working directory with current HEAD
 *
 * Updates the working directory and index to match HEAD. Use after modifying
 * the currently checked-out branch to ensure consistency.
 *
 * Strategy options:
 * - GIT_CHECKOUT_SAFE: Abort if local modifications conflict (recommended)
 * - GIT_CHECKOUT_FORCE: Overwrite all local modifications (use with caution)
 *
 * IMPORTANT: GIT_CHECKOUT_FORCE will destroy uncommitted changes without
 * warning. Only use when certain no user data can exist (e.g., immediately
 * after creating a new branch, or during dotta init).
 *
 * @param repo Repository (must not be NULL, must not be bare)
 * @param strategy Checkout strategy (GIT_CHECKOUT_SAFE recommended)
 * @return Error or NULL on success
 */
error_t *gitops_sync_worktree(
    git_repository *repo,
    git_checkout_strategy_t strategy
);

#endif /* DOTTA_GITOPS_H */
