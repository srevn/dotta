/**
 * state.h - SQLite-based deployment state tracking
 *
 * Tracks which files have been deployed to enable cleanup,
 * conflict detection, and status reporting.
 *
 * Database location: .git/dotta.db
 *
 * Schema:
 *   - schema_meta: Schema versioning
 *   - enabled_profiles: User's profile management
 *   - virtual_manifest: Deployed file manifest
 *   - tracked_directories: Tracked directories from metadata
 *
 * Design principles:
 * - Binary format (fast, compact)
 * - WAL mode (concurrent access, atomic commits)
 * - Prepared statements (100x faster for bulk operations)
 * - Persistent indexes (O(1) lookups without rebuilding)
 * - Separate tables enforce authority model at storage level
 */

#ifndef DOTTA_STATE_H
#define DOTTA_STATE_H

#include <git2.h>
#include <sys/stat.h>
#include <time.h>
#include <types.h>

#include "core/metadata.h"

/**
 * File type in state
 */
typedef enum {
    STATE_FILE_REGULAR,
    STATE_FILE_SYMLINK,
    STATE_FILE_EXECUTABLE
} state_file_type_t;

/**
 * State lifecycle constants
 *
 * These constants define the lifecycle state of manifest entries.
 * The state field implements an explicit state machine for file management.
 */
#define STATE_ACTIVE "active"       /* Normal entry, file is in scope and should be managed */
#define STATE_INACTIVE "inactive"   /* Staged for removal, reversible (profile disable) */
#define STATE_DELETED "deleted"     /* Confirmed deletion, awaiting filesystem cleanup by apply */
#define STATE_RELEASED "released"   /* File removed from Git externally, loss of authority */

/**
 * Convert state file type to git filemode
 *
 * Maps the internal state file type enum to the corresponding git filemode.
 * This is the canonical conversion used by safety checks and workspace
 * divergence analysis.
 *
 * Mapping:
 *   STATE_FILE_SYMLINK    -> GIT_FILEMODE_LINK (0120000)
 *   STATE_FILE_EXECUTABLE -> GIT_FILEMODE_BLOB_EXECUTABLE (0100755)
 *   STATE_FILE_REGULAR    -> GIT_FILEMODE_BLOB (0100644)
 *
 * @param type State file type
 * @return Corresponding git filemode
 */
static inline git_filemode_t state_type_to_git_filemode(state_file_type_t type) {
    switch (type) {
        case STATE_FILE_SYMLINK:
            return GIT_FILEMODE_LINK;
        case STATE_FILE_EXECUTABLE:
            return GIT_FILEMODE_BLOB_EXECUTABLE;
        default:
            return GIT_FILEMODE_BLOB;
    }
}

/**
 * Stat cache — fast-path witness of a deployment anchor
 *
 * Witness field of a deployment_anchor_t: the (mtime, size, ino) triple
 * captured at the moment dotta confirmed disk content equals
 * anchor.blob_oid. If a later live stat matches all three fields, disk
 * is still equal to anchor.blob_oid without re-hashing — the same
 * approach Git uses with its index.
 *
 * Sentinel: All-zero state means unset — forces the slow path (safe default).
 * mtime == 0 acts as validity gate: a file with genuine mtime=0 (epoch)
 * simply never benefits from the fast path — correct, just not optimized.
 */
typedef struct {
    int64_t mtime;    /* st_mtime seconds at last known-good state (0 = unset) */
    int64_t size;     /* st_size at last known-good state */
    uint64_t ino;     /* st_ino at last known-good state */
} stat_cache_t;

#define STAT_CACHE_UNSET ((stat_cache_t){0})

/**
 * Populate stat cache from a struct stat
 *
 * Captures the three fields used for fast-path validation. Call this
 * immediately after a deploy, adoption, post-commit capture, or slow-path
 * CMP_EQUAL confirmation — the stat returned must correspond to the blob
 * the caller just confirmed disk matches.
 */
static inline stat_cache_t stat_cache_from_stat(const struct stat *st) {
    return (stat_cache_t){
        .mtime = (int64_t) st->st_mtime,
        .size = (int64_t) st->st_size,
        .ino = (uint64_t) st->st_ino,
    };
}

/**
 * Deployment anchor — dotta's record of "disk was confirmed to equal this"
 *
 * Three fields, one concept: the blob dotta last confirmed was present on
 * disk, when that confirmation happened, and the stat triple that proves
 * it is still there without re-hashing.
 *
 * Invariants:
 *   - blob_oid is non-zero iff dotta has at some point confirmed disk
 *     content matched that blob. Zero means "never confirmed" (e.g.,
 *     newly enabled profile whose files predate dotta).
 *   - stat matching live stat is a fast-path witness that disk still
 *     equals blob_oid.
 *   - blob_oid ≠ virtual_manifest.blob_oid iff the Git-expected value
 *     has advanced past the last disk confirmation — i.e., stale.
 *
 * Witness vs. ownership split:
 *   - (blob_oid, stat) is witness data — cheap, observational, updated
 *     whenever dotta confirms disk matches (including from status/diff/sync
 *     via workspace_flush_anchor_updates). Witness writes pass
 *     deployed_at = 0 to preserve the ownership flag.
 *   - deployed_at > 0 is the ownership flag — dotta actively committed to
 *     managing this file's disk presence. Written by explicit user acts:
 *     apply (deploy or adoption), add, update. Workspace classification
 *     reads deployed_at > 0 to separate DELETED (was owned, now missing)
 *     from UNDEPLOYED (never owned); consumers are analyze_file_divergence
 *     and analyze_encryption_policy_mismatch.
 *
 * The anchor is written only by state_update_anchor() — the sole writer
 * of deployed_blob_oid, deployed_at, and stat_*. Manifest-layer writes
 * (reconcile/sync/rebuild via sync_entry_to_state) leave every anchor
 * column untouched: the UPSERT's preserve-on-zero sentinel on
 * deployed_blob_oid and unconditional preserve on deployed_at + stat_*.
 */
typedef struct {
    git_oid blob_oid;         /* Blob whose on-disk presence dotta confirmed */
    time_t deployed_at;       /* When confirmation happened (0 = never) */
    stat_cache_t stat;        /* Fast-path witness for the confirmation */
} deployment_anchor_t;

#define DEPLOYMENT_ANCHOR_UNSET ((deployment_anchor_t){0})

/**
 * Build a deployment anchor by snapshotting disk stat
 *
 * Convenience wrapper around lstat() + stat_cache_from_stat(). Callers should
 * invoke this only after they have verified the file on disk matches
 * blob_oid — this is an anchor advance, not a probe.
 *
 * If lstat fails (rare: file removed in the small window between content
 * confirmation and anchor recording), the stat witness is left zeroed. The
 * blob_oid and deployed_at fields are still populated so the row's anchor
 * advances correctly; the fast path just can't short-circuit on next read
 * and will fall through to the slow path.
 */
static inline deployment_anchor_t capture_anchor_from_disk(
    const char *filesystem_path,
    const git_oid *blob_oid,
    time_t deployed_at
) {
    deployment_anchor_t anchor = {
        .blob_oid    = *blob_oid,
        .deployed_at = deployed_at,
        .stat        = STAT_CACHE_UNSET,
    };

    struct stat st;
    if (lstat(filesystem_path, &st) == 0) {
        anchor.stat = stat_cache_from_stat(&st);
    }
    return anchor;
}

/**
 * State file entry (virtual_manifest row)
 *
 * Carries two distinct domains that share a primary key (filesystem_path)
 * and 1:1 cardinality:
 *
 *   VWD cache         — git-derived expected state maintained by the
 *                       manifest layer (reconcile/sync/rebuild). Fields:
 *                       blob_oid, type, mode, owner, group, encrypted, state.
 *   Deployment anchor — dotta's record of "disk was confirmed to equal
 *                       this blob, at this time, with this stat." Advanced
 *                       only by state_update_anchor() after a disk-matches-
 *                       blob confirmation (deploy, adoption, workspace flush
 *                       on CMP_EQUAL, post-commit capture).
 *
 * The two domains differ on anchor.blob_oid vs blob_oid iff Git-expected has
 * advanced past the last disk confirmation — i.e., the row is stale.
 *
 * SCOPE-BASED ARCHITECTURE:
 * - manifest existence = file should be managed
 * - state (lifecycle string) tracks active/inactive/deleted/released
 * - anchor.deployed_at is the lifecycle timestamp (0 = never confirmed)
 */
typedef struct {
    /* Identity */
    char *storage_path;         /* Path in profile (home/.bashrc) */
    char *filesystem_path;      /* Deployed path (/home/user/.bashrc) */
    char *profile;              /* Source profile name */
    char *old_profile;          /* Previous profile if reassigned, NULL otherwise */

    /* VWD cache (git-derived, reconcile-maintained) */
    state_file_type_t type;     /* File type (REGULAR, SYMLINK, EXECUTABLE) */
    git_oid blob_oid;           /* Blob the composed profile layer expects on disk */
    mode_t mode;                /* Permission mode (e.g., 0644), 0 if no metadata tracked */
    char *owner;                /* Owner username (root/ files only, can be NULL) */
    char *group;                /* Group name (root/ files only, can be NULL) */
    bool encrypted;             /* Encryption flag */
    char *state;                /* Lifecycle state (STATE_ACTIVE/STATE_INACTIVE/...) */

    /* Deployment anchor (dotta-authored, advances only via state_update_anchor) */
    deployment_anchor_t anchor;
} state_file_entry_t;

/**
 * Enabled profile entry
 *
 * One row from the enabled_profiles table, materialized as an in-memory record.
 * The state handle holds a cached array of these entries that is populated lazily
 * on first peek and invalidated whenever the table is mutated.
 *
 * Ownership: state handle owns the strings; callers that peek receive borrowed
 * pointers valid until the next mutation (see state_peek_profiles).
 */
typedef struct {
    char *name;              /* Profile name (owned) */
    char *custom_prefix;     /* Custom deployment prefix (owned); NULL when unset */
    git_oid commit_oid;      /* Last-synced HEAD OID (zero OID if never synced) */
} state_profile_entry_t;

/**
 * State directory entry
 */
typedef struct {
    char *filesystem_path;    /* Deployed path (PRIMARY KEY, e.g., /home/user/.config/fish) */
    char *storage_path;       /* Portable path (e.g., home/.config/fish) */
    char *profile;            /* Source profile */
    mode_t mode;              /* Permissions */
    char *owner;              /* Owner (optional, root/ prefix only) */
    char *group;              /* Group (optional, root/ prefix only) */

    /* Lifecycle tracking */
    char *state;              /* Lifecycle state (STATE_ACTIVE/STATE_INACTIVE etc.) */
    time_t deployed_at;       /* Lifecycle timestamp (0 = never deployed, >0 = known) */
} state_directory_entry_t;

/**
 * State structure (opaque)
 */
typedef struct state state_t;

/**
 * Load state from repository (read-only)
 *
 * If database doesn't exist, returns empty state.
 * If database is corrupt or wrong version, returns error.
 *
 * Use this function for read-only operations (status, list).
 * For operations that will modify and save state, use state_open().
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out);

/**
 * Load state for update (with transaction)
 *
 * Opens database with write lock (BEGIN IMMEDIATE transaction).
 * The transaction is automatically committed when state_save() is called
 * or rolled back when state_free() is called (cleanup on error paths).
 *
 * Use this function for operations that will modify state (add, apply, remove, etc.).
 * For read-only operations, use state_load().
 *
 * If another process holds the write lock, waits up to 3 seconds (SQLITE_BUSY).
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_open(git_repository *repo, state_t **out);

/**
 * Save state to repository
 *
 * Commits the transaction started by state_open().
 * All modifications made since load are atomically committed.
 *
 * @param repo Repository (must not be NULL)
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(git_repository *repo, state_t *state);

/**
 * Begin an explicit transaction on a read-only state handle
 *
 * Acquires a write lock (BEGIN IMMEDIATE). Used by batch operations
 * that need atomicity on a state opened via state_load() (no inherent
 * transaction). Must be paired with state_commit() or
 * state_rollback().
 *
 * @param state State (must not be NULL, must have open database, must not be in transaction)
 * @return Error or NULL on success
 */
error_t *state_begin(state_t *state);

/**
 * Commit a transaction started by state_begin()
 *
 * @param state State (must not be NULL, must be in transaction)
 * @return Error or NULL on success
 */
error_t *state_commit(state_t *state);

/**
 * Roll back a transaction started by state_begin()
 *
 * Safe to call on error paths. Silently succeeds if no transaction active.
 *
 * @param state State (must not be NULL)
 */
void state_rollback(state_t *state);

/**
 * Check if state has an active transaction
 *
 * Returns true if BEGIN IMMEDIATE has been executed and not yet
 * committed or rolled back. Used by workspace_flush_anchor_updates()
 * to decide whether to manage its own transaction.
 *
 * @param state State handle (must not be NULL)
 * @return true if transaction is active
 */
bool state_locked(const state_t *state);

/**
 * Create empty state
 *
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_empty(state_t **out);

/**
 * Free state structure
 *
 * Automatically rolls back transaction if not committed (error path cleanup).
 * Closes database connection and frees all memory.
 *
 * @param state State to free (can be NULL)
 */
void state_free(state_t *state);

/**
 * Add file entry to state
 *
 * Uses prepared statement for performance (critical for bulk operations).
 * Can be called 1000+ times in a loop during apply.
 *
 * @param state State (must not be NULL)
 * @param entry File entry to add (must not be NULL, copied into database)
 * @return Error or NULL on success
 */
error_t *state_add_file(state_t *state, const state_file_entry_t *entry);

/**
 * Remove file entry from state
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to remove (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_remove_file(state_t *state, const char *filesystem_path);

/**
 * Check if file exists in state
 *
 * Uses PRIMARY KEY index for O(1) lookup.
 * Hot path - called frequently during status checks.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to check (must not be NULL)
 * @return true if file exists in state
 */
bool state_file_exists(const state_t *state, const char *filesystem_path);

/**
 * Get file entry from state
 *
 * IMPORTANT: Memory ownership changed from original API.
 * Caller owns the returned entry and must free it with state_free_entry().
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to lookup (must not be NULL)
 * @param out File entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_get_file(
    const state_t *state,
    const char *filesystem_path,
    state_file_entry_t **out
);

/**
 * Get file entry by storage path
 *
 * Like state_get_file() but keyed on storage_path instead of filesystem_path.
 * Only returns active entries (state = 'active'). Uses idx_manifest_storage
 * index for O(1) lookup.
 *
 * Since the manifest resolves precedence, each active storage_path maps to
 * exactly one entry for home/ and root/ paths. For custom/ paths with
 * different prefixes, multiple active entries may exist — returns the
 * first match.
 *
 * @param state State (must not be NULL)
 * @param storage_path Storage path to lookup (e.g., "home/.bashrc")
 * @param out File entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success (ERR_NOT_FOUND if not in manifest)
 */
error_t *state_get_file_by_storage(
    const state_t *state,
    const char *storage_path,
    state_file_entry_t **out
);

/**
 * Get all file entries
 *
 * When arena is NULL, returns heap-allocated array that caller must free
 * with state_free_all_files(). When arena is non-NULL, all allocations
 * (entries array + string fields) use the arena — caller must NOT call
 * state_free_all_files() (arena_destroy handles everything).
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (NULL = heap with state_free_all_files)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_files(
    const state_t *state,
    arena_t *arena,
    state_file_entry_t **out,
    size_t *count
);

/**
 * Free array returned by state_get_all_files()
 *
 * @param entries Array to free (can be NULL)
 * @param count Number of entries in array
 */
void state_free_all_files(state_file_entry_t *entries, size_t count);

/**
 * Enable profile with optional custom prefix
 *
 * If profile already enabled, updates its custom_prefix (UPSERT behavior).
 * Position assigned automatically as MAX(position) + 1 for new profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - profile MUST NOT be NULL or empty
 *
 * Postconditions:
 *   - Profile added to enabled_profiles or existing entry updated
 *   - custom_prefix column set to prefix (or NULL if not provided)
 *   - enabled_at timestamp updated to current time
 *   - Transaction remains open (caller commits)
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile Profile name (must not be NULL)
 * @param custom_prefix Custom prefix or NULL for home/root profiles
 * @return Error or NULL on success
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile,
    const char *custom_prefix
);

/**
 * Disable profile
 *
 * Removes profile from enabled_profiles table.
 *
 * Preconditions:
 *   - state MUST have active transaction
 *
 * Postconditions:
 *   - Profile removed from enabled_profiles (if exists)
 *   - Transaction remains open (caller commits)
 *   - Not an error if profile wasn't enabled
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile Profile name (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_disable_profile(
    state_t *state,
    const char *profile
);

/**
 * Set enabled profiles (bulk operation)
 *
 * BULK API: For atomic profile list replacement (clone, reorder, interactive).
 * For individual profile enable/disable, prefer state_enable_profile() and
 * state_disable_profile() which provide explicit custom prefix management.
 *
 * Custom Prefix Preservation:
 *   Automatically preserves custom_prefix values for profiles that remain
 *   enabled after the operation. This enables safe profile reordering without
 *   losing custom prefix associations.
 *
 * Use Cases:
 *   - Clone: Initial profile list setup (no custom prefixes exist yet)
 *   - Reorder: Change precedence order while preserving custom_prefix values
 *   - Interactive: Bulk enable/disable selection with prefix preservation
 *
 * Position Assignment:
 *   Profiles are assigned sequential positions starting from 0.
 *   Any gaps in position numbering from previous operations are eliminated.
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies enabled_profiles table (virtual_manifest table untouched).
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *
 * Postconditions:
 *   - enabled_profiles table replaced with new profile list
 *   - Positions assigned as 0, 1, 2, ... (n-1)
 *   - custom_prefix values preserved for matching profile names
 *   - enabled_at timestamp updated to current time for all profiles
 *   - Transaction remains open (caller commits)
 *
 * @param state State (must not be NULL)
 * @param profiles Profile names (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_set_profiles(state_t *state, const string_array_t *profiles);

/**
 * Get enabled profiles
 *
 * Returns copy that caller must free.
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out);

/**
 * Check if a profile is enabled
 *
 * Fast O(n) check where n = number of enabled profiles (typically < 10).
 * Useful for commands that need to conditionally update manifest based on
 * whether a profile is enabled.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_has_profile(const state_t *state, const char *profile);

/**
 * Get last deployed timestamp for a profile
 *
 * Returns the most recent deployment timestamp for files from the specified profile.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @return Timestamp (0 if profile has no deployed files)
 */
time_t state_get_profile_timestamp(const state_t *state, const char *profile);

/**
 * Helper: Create file entry
 *
 * Allocates a state_file_entry_t and populates its identity and VWD-cache
 * fields from the arguments. The deployment anchor is zero-initialized;
 * hydration callers populate entry->anchor afterward from their row data.
 *
 * The blob_oid parameter is named explicitly (not `git_oid`) because C treats
 * a prior parameter name as in scope for subsequent parameters.
 *
 * @param storage_path Storage path (must not be NULL)
 * @param filesystem_path Filesystem path (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param old_profile Previous profile (can be NULL)
 * @param type File type
 * @param blob_oid Blob OID for content identity (must not be NULL, copied)
 * @param mode Permission mode (0 if no metadata tracked)
 * @param owner Owner username (can be NULL)
 * @param group Group name (can be NULL)
 * @param encrypted Encryption flag
 * @param state Lifecycle state (can be NULL for default)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    const char *old_profile,
    state_file_type_t type,
    const git_oid *blob_oid,
    mode_t mode,
    const char *owner,
    const char *group,
    bool encrypted,
    const char *state,
    state_file_entry_t **out
);

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_file_entry_t *entry);

/**
 * Advance a manifest entry's deployment anchor
 *
 * The sole writer of the deployment columns (deployed_blob_oid, deployed_at,
 * stat_*). Call after confirming disk content matches anchor->blob_oid.
 *
 * Semantics:
 *   - anchor->blob_oid must be non-zero. A zero blob_oid is only valid as
 *     the "never confirmed" initial row state written by the UPSERT on
 *     first INSERT; it is never a legal advance target.
 *   - anchor->deployed_at == 0 → preserve the existing timestamp
 *     (add/update/workspace-flush case — first observation advances
 *     the anchor witness without claiming a new deployment event).
 *   - anchor->deployed_at != 0 → write the new value
 *     (apply post-deploy/adoption case — stamps the deployment event).
 *   - anchor->stat is always written.
 *
 * Not-found is not an error: the entry may not exist if the profile is
 * disabled or the file was filtered by precedence. Callers do not need
 * to check existence before calling.
 *
 * @param state State (must not be NULL, must have open database)
 * @param filesystem_path File path to update (must not be NULL)
 * @param anchor Deployment anchor to write (must not be NULL, blob_oid non-zero)
 * @return Error or NULL on success
 */
error_t *state_update_anchor(
    state_t *state,
    const char *filesystem_path,
    const deployment_anchor_t *anchor
);

/**
 * Clear old_profile for a manifest entry
 *
 * Acknowledges profile reassignment after successful deployment.
 * Used by apply to clear the reassignment flag once the user has
 * been informed about the change via preflight.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path File path (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_clear_old_profile(
    state_t *state,
    const char *filesystem_path
);

/**
 * Set file entry state (active/inactive/deleted)
 *
 * Updates the state column for a manifest entry. Used by manifest layer
 * to mark files as inactive when they become orphaned (removed with no fallback).
 *
 * Valid states:
 *   - STATE_ACTIVE   - Normal entry, file is in scope
 *   - STATE_INACTIVE - Staged for removal, reversible (profile disable)
 *   - STATE_DELETED  - Confirmed deletion via remove command
 *   - STATE_RELEASED    - File removed from Git externally, loss of authority
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - filesystem_path MUST exist in virtual_manifest
 *   - new_state MUST be STATE_ACTIVE, STATE_INACTIVE, STATE_DELETED, or STATE_RELEASED
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path File to update (must not be NULL)
 * @param new_state New state value (must not be NULL)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *state_set_file_state(
    state_t *state,
    const char *filesystem_path,
    const char *new_state
);

/**
 * Set commit_oid for a profile in enabled_profiles
 *
 * Writes the profile's current branch HEAD to the per-profile commit_oid
 * column. Single-row UPDATE on enabled_profiles.
 *
 * Called after operations that move a profile's branch HEAD:
 * - manifest_sync_diff (after pull/merge)
 * - manifest_add_files (after commit)
 * - manifest_update_files (after commit)
 * - manifest_remove_files (after commit)
 * - manifest_enable_profile (after initial population)
 * - manifest_populate (after clone-time population)
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile Profile name (must not be NULL)
 * @param commit_oid New commit OID for profile HEAD (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_set_profile_commit_oid(
    state_t *state,
    const char *profile,
    const git_oid *commit_oid
);

/**
 * Peek the cached enabled_profiles rows
 *
 * Returns borrowed pointers to the in-memory row cache. Iteration order
 * matches enabled_profiles.position (the user's precedence order).
 *
 * Lifetime — pointers into the row array and the strings it references
 * (name, custom_prefix) remain valid until the next shape mutation on
 * enabled_profiles:
 *   - state_enable_profile
 *   - state_disable_profile
 *   - state_set_profiles
 *   - state_rollback (any mutation could have happened in the transaction)
 *   - state_free
 *
 * state_set_profile_commit_oid does NOT invalidate these borrows — it
 * patches the commit_oid field of the matching row in place. The
 * commit_oid *value* under a previously returned pointer may change as a
 * result, but the pointer itself (and all name / custom_prefix pointers)
 * stays valid.
 *
 * When the state has no database (state_empty), returns *out_entries = NULL,
 * *out_count = 0.
 *
 * @param state State (must not be NULL)
 * @param out_entries Output: borrowed pointer to row array (must not be NULL)
 * @param out_count Output: number of rows (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_peek_profiles(
    const state_t *state,
    const state_profile_entry_t **out_entries,
    size_t *out_count
);

/**
 * Peek a single profile's custom prefix
 *
 * Returns a borrowed pointer into the row cache. Same lifetime rules as
 * state_peek_profiles.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to look up (must not be NULL)
 * @return Borrowed custom prefix string, or NULL when the profile has no
 *         custom prefix, is not enabled, or the state has no database.
 */
const char *state_peek_profile_prefix(
    const state_t *state,
    const char *profile
);

/**
 * Peek a single profile's stored commit_oid
 *
 * Returns a borrowed pointer into the row cache. Same lifetime rules as
 * state_peek_profiles.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to look up (must not be NULL)
 * @return Borrowed commit OID, or NULL when the profile is not enabled or
 *         the state has no database.
 */
const git_oid *state_peek_profile_commit_oid(
    const state_t *state,
    const char *profile
);

/**
 * Get entries by profile
 *
 * Returns all manifest entries from the specified profile.
 * Used by profile disable to determine impact of disabling a profile.
 *
 * When arena is NULL, returns heap-allocated array (free with state_free_all_files).
 * When arena is non-NULL, all allocations use the arena.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param arena Arena for allocations (NULL = heap with state_free_all_files)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_entries_by_profile(
    const state_t *state,
    const char *profile,
    arena_t *arena,
    state_file_entry_t **out,
    size_t *count
);

/**
 * Create state directory entry from metadata item
 *
 * Converts portable metadata (storage_path) to state entry (both paths).
 * Derives filesystem_path from metadata's storage_path using path_from_storage().
 *
 * @param meta_item Metadata item (must not be NULL, must be DIRECTORY kind)
 * @param profile Source profile name (must not be NULL)
 * @param custom_prefix Custom prefix for this profile (NULL for home/root)
 * @param out State directory entry (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_directory_entry_create_from_metadata(
    const metadata_item_t *meta_item,
    const char *profile,
    const char *custom_prefix,
    arena_t *arena,
    state_directory_entry_t **out
);

/**
 * Add directory entry to state
 *
 * @param state State (must not be NULL)
 * @param entry Directory entry (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_directory(
    state_t *state,
    const state_directory_entry_t *entry
);

/**
 * Get all tracked directories
 *
 * When arena is NULL, returns heap-allocated array that caller must free
 * with state_free_all_directories(). When arena is non-NULL, all allocations
 * (entries array + string fields) use the arena — caller must NOT call
 * state_free_all_directories() (arena_destroy handles everything).
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (NULL = heap with state_free_all_directories)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_directories(
    const state_t *state,
    arena_t *arena,
    state_directory_entry_t **out,
    size_t *count
);

/**
 * Get directories by profile
 *
 * Returns all directory entries from the specified profile.
 * Used by profile disable to determine impact on directories.
 *
 * When arena is NULL, returns heap-allocated array (free with state_free_all_directories).
 * When arena is non-NULL, all allocations use the arena.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param arena Arena for allocations (NULL = heap with state_free_all_directories)
 * @param out Output array (must not be NULL, caller must free)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_directories_by_profile(
    const state_t *state,
    const char *profile,
    arena_t *arena,
    state_directory_entry_t **out,
    size_t *count
);

/**
 * Update directory entry
 *
 * Updates all fields except filesystem_path (primary key) and deployed_at.
 * The deployed_at field is preserved to maintain lifecycle tracking.
 *
 * Updated fields: storage_path, profile, mode, owner, group
 * Preserved fields: filesystem_path (WHERE clause), deployed_at (lifecycle)
 *
 * This is used during profile disable to update directory entries to their
 * fallback profiles while preserving the original deployment timestamp.
 *
 * @param state State (must not be NULL)
 * @param entry Entry to update (must not be NULL, filesystem_path must exist)
 * @return Error or NULL on success
 */
error_t *state_update_directory(
    state_t *state,
    const state_directory_entry_t *entry
);

/**
 * Remove directory entry by path
 *
 * Deletes directory entry from state. Used during orphan cleanup after
 * the directory has been removed from the filesystem.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path Filesystem path (PRIMARY KEY, must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_remove_directory(state_t *state, const char *filesystem_path);

/**
 * Clear all tracked directories
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_directories(state_t *state);

/**
 * Get directory entry from state
 *
 * Retrieves single directory entry by filesystem path.
 * Caller owns the returned entry and must free it with state_free_directory_entry().
 *
 * @param state State (must not be NULL)
 * @param filesystem_path Directory path to lookup (must not be NULL)
 * @param out Directory entry (must not be NULL, caller must free with state_free_directory_entry)
 * @return Error or NULL on success (ERR_NOT_FOUND if doesn't exist)
 */
error_t *state_get_directory(
    const state_t *state,
    const char *filesystem_path,
    state_directory_entry_t **out
);

/**
 * Set directory lifecycle state
 *
 * Updates the state column for a directory entry.
 * Used by manifest operations to mark directories as active/inactive/deleted.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path Directory path (must not be NULL)
 * @param new_state Lifecycle state (STATE_ACTIVE/STATE_INACTIVE/STATE_DELETED)
 * @return Error or NULL on success
 */
error_t *state_set_directory_state(
    state_t *state,
    const char *filesystem_path,
    const char *new_state
);

/**
 * Mark all directories as inactive
 *
 * Bulk operation for manifest_sync_directories to prepare for rebuild.
 * Replaces the nuclear state_clear_directories() approach with mark-and-reactivate pattern.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_mark_all_directories_inactive(state_t *state);

/**
 * Free single directory entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_directory_entry(state_directory_entry_t *entry);

/**
 * Free array of directory entries
 *
 * @param entries Array to free (can be NULL)
 * @param count Number of entries in array
 */
void state_free_all_directories(
    state_directory_entry_t *entries,
    size_t count
);

#endif /* DOTTA_STATE_H */
