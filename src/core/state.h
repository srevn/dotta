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
 *   - anchors: The record — what dotta last reconciled each managed path
 *     against, and what it confirmed there (both kinds, one row per path)
 *   - virtual_manifest: Deployed file manifest
 *   - tracked_directories: Tracked directories from metadata
 *
 * Design principles:
 * - Binary format (fast, compact)
 * - WAL mode (concurrent access, atomic commits)
 * - Prepared statements (100x faster for bulk operations)
 * - Persistent indexes (O(1) lookups without rebuilding)
 * - Separate tables enforce authority model at storage level: the record
 *   (anchors) is dotta's own and never derivable; the expected side is
 *   Git's and keyed apart from it
 */

#ifndef DOTTA_STATE_H
#define DOTTA_STATE_H

#include <git2.h>
#include <sys/stat.h>
#include <time.h>
#include <types.h>

#include "core/row.h"

/**
 * Lifecycle phase of a manifest row
 *
 * Persistent finite-state machine attached to every virtual_manifest and
 * tracked_directories row. Distinct from `workspace_state_t` (types.h),
 * which classifies *where* an item exists at runtime — this enum records
 * the row's *phase* across commands.
 *
 * LIFECYCLE_ACTIVE = 0 by design: zero-init from arena_calloc / memset
 * yields the default phase, matching the SQL schema's `DEFAULT 'active'`.
 *
 * Vocabulary asymmetry: tracked_directories' CHECK constraint excludes
 * 'released' — directories cannot lose authority externally because they
 * have no blob-level identity in Git. state_transition_directories_by_profile
 * rejects LIFECYCLE_RELEASED at its boundary; the SQL CHECK is
 * defense-in-depth.
 *
 * Writers, by intent:
 *   LIFECYCLE_INACTIVE and LIFECYCLE_DELETED are written only by a local,
 *   explicit verb — profile disable/reorder, remove --delete-profile,
 *   clone and interactive save (INACTIVE, through manifest_apply_scope's
 *   leftover); remove --delete-files (DELETED, through
 *   manifest_remove_files' fate overlay). Every departure dotta
 *   *discovers* in Git — an external commit, a pulled removal, a branch
 *   that no longer resolves — is LIFECYCLE_RELEASED: the deployed copy
 *   is left alone and the row retires. manifest_apply_scope takes the
 *   distinction as its `leftover` argument; no engine code reasons about
 *   who moved Git. A verb that knows better overlays its answer on the
 *   rows it named after the engine ran (remove's DELETED, or the purge
 *   of a row released by a removal the user asked for).
 *
 * Column: virtual_manifest.state / tracked_directories.state.
 */
typedef enum {
    LIFECYCLE_ACTIVE = 0,    /* Normal entry, file is in scope and should be managed */
    LIFECYCLE_INACTIVE,      /* Staged for removal, reversible (profile disable) */
    LIFECYCLE_DELETED,       /* Confirmed deletion, awaiting filesystem cleanup by apply */
    LIFECYCLE_RELEASED       /* Departure discovered in Git, loss of authority (file-only) */
} state_lifecycle_t;

/**
 * Stat cache — fast-path field of an anchor
 *
 * Field of an anchor_t: the (mtime, size, ino) triple captured at the
 * moment dotta confirmed disk content equals anchor.blob_oid. If a later
 * live stat matches all three fields, disk is still equal to
 * anchor.blob_oid without re-hashing — the same approach Git uses with
 * its index.
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
 * Capture a stat triple from disk
 *
 * lstat() + stat_cache_from_stat(). Callers invoke this only after they
 * have verified the file on disk matches the blob they are about to
 * anchor — this feeds an anchor write, not a probe.
 *
 * If lstat fails (rare: file removed in the small window between content
 * confirmation and anchor recording), the triple is left zeroed. The
 * anchor still advances to the blob; the fast path just can't
 * short-circuit on next read and will fall through to the slow path.
 */
static inline stat_cache_t stat_cache_from_path(const char *filesystem_path) {
    struct stat st;
    if (lstat(filesystem_path, &st) != 0) {
        return STAT_CACHE_UNSET;
    }
    return stat_cache_from_stat(&st);
}

/**
 * Anchor — the record dotta keeps of a managed path (anchors row)
 *
 * The row dotta last reconciled this path against — what it deployed, or,
 * when deployed_at is 0, what it was looking at when it first observed
 * the path — and what it confirmed there. One row per filesystem path,
 * both kinds. A row exists iff dotta has observed the path on disk while
 * it was managed: there is no "never observed" row, and observed_at is
 * never zero.
 *
 * Three signals, three write rules:
 *   - blob_oid + stat : content-verified pair. Advanced only after
 *     disk-matches-blob verification (slow-path CMP_EQUAL, apply deploy,
 *     adoption, add, update). Zero blob_oid is no content confirmation —
 *     a directory, whose whole confirmed-disk record is that it was
 *     observed (a directory has no content confirmation, schema-enforced),
 *     or a file observed but never confirmed.
 *   - deployed_at     : active-ownership timestamp. Advances to now on
 *     apply deploy, apply adoption, add, update (state_anchor with
 *     own = true); kept by every confirmation (own = false). 0 = dotta
 *     never put this here.
 *   - observed_at     : first-observation timestamp. Written once, by
 *     whichever write creates the row (state_observe, or state_anchor's
 *     INSERT arm), and never again: the first caller wins because no
 *     later write names the column.
 *
 * Invariants:
 *   - blob_oid is non-zero iff dotta has at some point confirmed disk
 *     content matched that blob. Zero means "never confirmed."
 *   - stat matching live stat is fast-path proof that disk still
 *     equals blob_oid.
 *   - blob_oid ≠ the manifest row's blob_oid iff the Git-expected value
 *     has advanced past the last disk confirmation — i.e., stale.
 *   - deployed_at > 0 on a file implies a non-zero blob_oid: the write
 *     that owned it confirmed it (schema-enforced). A row with a blob
 *     and deployed_at = 0 is a confirmation, not a deployment.
 *
 * The identity and metadata fields (storage_path, profile, type, mode,
 * owner, group) are those of the row the record was written from — who
 * deployed what, under which claim. They are what an orphan (a record
 * whose path no active row names) is measured against, and
 * profile ≠ the active row's profile is a reassignment apply has not
 * acknowledged.
 *
 * prune_ordered is the one persisted intent: remove --delete-files
 * ordered the deployed copy pruned at the next apply. Meaningful only
 * for an orphan; cleared by state_anchor, which every route back under
 * an active row takes.
 */
typedef struct {
    /* Identity — the row's, at the last write */
    char *filesystem_path;    /* Deployed path (PRIMARY KEY) */
    char *storage_path;       /* Path in profile (home/.bashrc) */
    char *profile;            /* Profile whose row dotta reconciled the path against */

    /* What dotta set there */
    path_type_t type;         /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    mode_t mode;              /* Recorded mode claim (0 = none) */
    char *owner;              /* Recorded owner (can be NULL) */
    char *group;              /* Recorded group (can be NULL) */

    /* What dotta confirmed */
    git_oid blob_oid;         /* Content-confirmed blob (zero = never confirmed: a directory, or observed only) */
    stat_cache_t stat;        /* Fast-path stat triple, bound to blob_oid (all-zero = unusable) */
    time_t observed_at;       /* First sighting on disk in scope (> 0 always: a row exists iff observed) */
    time_t deployed_at;       /* Last active-ownership event (advances; 0 = never owned) */
    bool prune_ordered;       /* remove --delete-files: prune the deployed copy at next apply */
} anchor_t;

/**
 * State entry — a virtual_manifest or tracked_directories row
 *
 * TRANSITIONAL — dies with the two tables. The expected side as the
 * database still stores it: a manifest row plus the two columns that
 * cache an answer the view would give — the lifecycle phase, and the
 * profile the row was reassigned from. A tracked_directories row
 * hydrates with type = PATH_TYPE_DIRECTORY and old_profile = NULL (the
 * table has no such column). Consumers that outlive the tables read
 * `&entry->row`; only the workspace's partition, the engine and the
 * verb overlays read the other two.
 */
typedef struct {
    manifest_row_t row;          /* Expected state (Git-derived, engine-maintained) */
    state_lifecycle_t lifecycle; /* Lifecycle phase (default LIFECYCLE_ACTIVE on zero-init) */
    char *old_profile;           /* Previous profile if reassigned, NULL otherwise (files only) */
} state_entry_t;

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
    char *target;            /* Deployment target for custom/ files (owned); NULL when unset */
    git_oid commit_oid;      /* Last-synced HEAD OID (zero OID if never synced) */
} state_profile_entry_t;

/**
 * State structure (opaque)
 */
typedef struct state state_t;

/**
 * Load state from repository (read-only, scoped-mutation capable)
 *
 * If .git/dotta.db doesn't exist, returns a usable handle whose
 * state->db is NULL (lazy promotion by state_begin happens on first
 * write). If the file exists but is corrupt or wrong version,
 * returns an error. Use for the READ acquisition shape — see the
 * "Transaction model" section above.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out);

/**
 * Load state for update (whole-dispatch transaction held)
 *
 * Opens (creating if necessary) .git/dotta.db with the write lock
 * already held (BEGIN IMMEDIATE). The transaction is committed by
 * state_save() or rolled back by state_free() (cleanup on error
 * paths). Use for the WRITE acquisition shape — see the "Transaction
 * model" section above. If another process holds the write lock,
 * waits up to 3 seconds (SQLITE_BUSY).
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
 * Begin an explicit transaction on a state handle
 *
 * Acquires a write lock (BEGIN IMMEDIATE). Used by batch operations
 * that need atomicity on a state opened via state_load() (no inherent
 * transaction). On a handle whose underlying DB does not yet exist on
 * disk (state_load() on a repository never touched by `dotta init`),
 * this lazily creates .git/dotta.db before taking the lock — mirroring
 * state_open()'s create semantics, deferred to the moment of actual
 * write intent. Must be paired with state_commit() or state_rollback().
 *
 * @param state State (must not be NULL, must not be in transaction)
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
 * committed or rolled back. Used by code paths that may run under
 * either acquisition shape (manifest_reconcile,
 * workspace_flush_updates, ...) to decide whether to start
 * their own scoped transaction or piggyback on the caller's.
 *
 * @param state State handle (must not be NULL)
 * @return true if transaction is active
 */
bool state_locked(const state_t *state);

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
 * Project a file row into virtual_manifest (projection writer)
 *
 * True UPSERT, the sole caller being the projection engine: the row is
 * written ACTIVE on both arms (projection means in-scope), its
 * old_profile is captured by SQL when the winning profile changes, and
 * nothing else about the path is touched — the record lives in its own
 * table. Uses a prepared statement for performance (critical for bulk
 * operations; called once per row that moved).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param row File row to project (must not be NULL; type != DIRECTORY)
 * @return Error or NULL on success
 */
error_t *state_add_file(state_t *state, const manifest_row_t *row);

/**
 * Remove file entry from state
 *
 * Retires the expected row only. The record, if any, is retired
 * separately by state_retire_anchor — the two tables are keyed apart
 * and nothing cascades.
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
    state_entry_t **out
);

/**
 * Get file entry by storage path
 *
 * Like state_get_file() but keyed on storage_path instead of filesystem_path.
 * Only returns active entries (lifecycle = LIFECYCLE_ACTIVE). Uses
 * idx_manifest_storage index for O(1) lookup.
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
    state_entry_t **out
);

/**
 * Get all file entries
 *
 * Allocates the entries array and every string field from the caller's
 * arena. Lifetime is tied to the arena: caller controls cleanup by
 * destroying the arena.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_files(
    const state_t *state,
    arena_t *arena,
    state_entry_t **out,
    size_t *count
);

/**
 * Count manifest entries belonging to a profile
 *
 * Pure SQL aggregate (SELECT COUNT(*) WHERE profile = ?), backed by the
 * idx_manifest_profile index. Avoids materializing rows just to count
 * them. All lifecycle states are counted (active, inactive, deleted,
 * released) — callers that want only one state must filter at a higher
 * layer.
 *
 * On empty state (no DB), returns *out_count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param out_count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_count_files_by_profile(
    const state_t *state,
    const char *profile,
    size_t *out_count
);

/**
 * Return the set of distinct profile names referenced in virtual_manifest
 *
 * Pure SQL aggregate (SELECT DISTINCT profile FROM virtual_manifest),
 * backed by idx_manifest_profile. Used by profile_validate's orphan
 * check to deduplicate profile names before probing Git for branch
 * existence — turning F per-row probes (where F = manifest entry count)
 * into P probes (where P = distinct profile count, typically <10).
 *
 * The output is heap-allocated; caller frees with string_array_free.
 * Order is unspecified.
 *
 * On empty state (no DB), returns an empty array (count == 0) with no
 * error.
 *
 * @param state State (must not be NULL)
 * @param out Output: distinct profile names (must not be NULL,
 *            caller frees with string_array_free)
 * @return Error or NULL on success
 */
error_t *state_get_distinct_file_profiles(
    const state_t *state,
    string_array_t **out
);

/**
 * Count active encrypted manifest entries
 *
 * Pure SQL aggregate (SELECT COUNT(*) WHERE encrypted = 1 AND state =
 * 'active'). Used by the key command to summarize how many files the
 * cached passphrase will decrypt. Non-active rows are excluded — they
 * are not part of the live working set.
 *
 * On empty state (no DB), returns *out_count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param out_count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_count_encrypted_files(
    const state_t *state,
    size_t *out_count
);

/**
 * Enable profile with optional deployment target
 *
 * If profile already enabled, updates its target (UPSERT behavior).
 * Position assigned automatically as MAX(position) + 1 for new profiles.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - profile MUST NOT be NULL or empty
 *
 * Postconditions:
 *   - Profile added to enabled_profiles or existing entry updated
 *   - target column set to the supplied value (or NULL if not provided)
 *   - enabled_at timestamp updated to current time
 *   - Transaction remains open (caller commits)
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile Profile name (must not be NULL)
 * @param target Deployment target or NULL for home/root profiles
 * @return Error or NULL on success
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile,
    const char *target
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
 * Reorder enabled profiles to match a new precedence order
 *
 * Atomically deletes and re-inserts every row in enabled_profiles so the
 * position column reflects the order of `profiles`. Per-row state (target,
 * commit_oid) is preserved across the rewrite — only precedence changes.
 *
 * REORDER-ONLY CONTRACT:
 *   Reorder permutes membership; it does not add or remove rows. Every
 *   name in `profiles` MUST already be a row in enabled_profiles, and the
 *   set of names MUST equal the current enabled set (any caller passing a
 *   different set is a bug — the function rejects unknown names at the
 *   boundary but does not synthesize the inverse "rows you forgot to
 *   include" check; that's the caller's responsibility).
 *
 *   Additions belong to state_enable_profile. Removals belong to
 *   state_disable_profile. A name not currently enabled returns
 *   ERR_INVALID_ARG and leaves the table untouched — closing the
 *   silent (custom-profile, NULL-target) trap at the write boundary.
 *
 * Direct callers:
 *   - profile reorder: user-driven precedence change.
 *   - interactive save: persists the new order after the TUI's own diff
 *                       has already applied additions/removals via the
 *                       membership primitives.
 *
 * Preconditions:
 *   - state MUST have an active write transaction.
 *   - profiles MUST NOT be NULL. profiles->count may be 0 (vacuous reorder).
 *   - Every name in profiles MUST already be in the row cache.
 *
 * Postconditions:
 *   - enabled_profiles rows hold positions 0..N-1 in the order given.
 *   - target and commit_oid preserved on every retained row.
 *   - enabled_at timestamp refreshed for every row.
 *   - Row cache invalidated; next peek reloads.
 *   - Transaction remains open (caller commits).
 *
 * @param state State (must not be NULL)
 * @param profiles Profile names in desired order (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_reorder_profiles(state_t *state, const string_array_t *profiles);

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
 * Helper: Create file entry
 *
 * Allocates a state_entry_t and populates its row and lifecycle fields
 * from the arguments.
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
 * @param lifecycle Lifecycle phase (pass LIFECYCLE_ACTIVE for the default)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    const char *old_profile,
    path_type_t type,
    const git_oid *blob_oid,
    mode_t mode,
    const char *owner,
    const char *group,
    bool encrypted,
    state_lifecycle_t lifecycle,
    state_entry_t **out
);

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_entry_t *entry);

/**
 * Get every anchor, in filesystem_path order
 *
 * The one read of the anchors table. Allocates the array and every
 * string field from the caller's arena; lifetime is tied to the arena.
 * A NULL blob column hydrates to a zero OID, a NULL mode to 0. The
 * workspace loads it once per run and indexes it by path; the
 * projection engine reads it to tell a departed row with a record from
 * one without.
 *
 * On empty state (no DB), returns *out = NULL, *count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_anchors(
    const state_t *state,
    arena_t *arena,
    anchor_t **out,
    size_t *count
);

/**
 * Observe a managed path: record its first sighting on disk
 *
 * Presence only, idempotent. INSERT OR IGNORE creates the record with the
 * row's identity and metadata, no blob, no stat, observed_at = now, and
 * never touches an existing row. The workspace calls it (through
 * workspace_observe) for an active row it found on disk with no record;
 * apply calls it for a directory it fixed rather than made. The record's
 * existence is what the absence classifier reads (workspace.c
 * classify_absent): a path once observed that is now missing was
 * deleted, not never deployed.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path was observed under (must not be NULL)
 * @param now Observation timestamp (must be > 0)
 * @return Error or NULL on success
 */
error_t *state_observe(state_t *state, const manifest_row_t *row, time_t now);

/**
 * Anchor a managed path: record the row dotta reconciled it against
 *
 * The sole writer of the record's content, metadata and ownership
 * columns. Call after confirming disk content matches row->blob_oid
 * (or, for a DIRECTORY row, after creating or confirming the directory).
 * One statement, an UPSERT on anchors: the INSERT arm creates the row
 * with observed_at = now; the UPDATE arm rewrites everything the row and
 * the confirmation supply and leaves observed_at alone.
 *
 * ROUTING INVARIANT — this is load-bearing:
 *   - If a workspace is live for this transaction, anchor writes MUST
 *     route through workspace_anchor (workspace.h). That wrapper calls
 *     this function with resolved_out pointing at a record it then
 *     patches into its snapshot — or creates there, when the path had no
 *     record at load — so every later reader in the run sees the
 *     canonical post-write value the SQL produced. Calling state_anchor
 *     directly while a workspace is live silently desyncs the snapshot.
 *   - If no workspace is live (the anchor overlays of manifest_add_files
 *     and manifest_update_files), this function is the legitimate direct
 *     caller. There is no snapshot to patch, so callers pass
 *     resolved_out=NULL and the next workspace_load reads SQL fresh.
 *
 * Semantics (encoded in the SQL — single source of truth):
 *   - row->blob_oid must be non-zero for a file row: a zero blob would
 *     record "never confirmed" for a path this call claims to have
 *     confirmed. Rejected here, before the schema's CHECK would reject
 *     it. A DIRECTORY row binds NULL — a directory has no content
 *     confirmation.
 *   - own = true  → deployed_at = now: an ownership event (apply deploy,
 *     adoption, add, update).
 *   - own = false → deployed_at is kept: a confirmation (the slow-path
 *     CMP_EQUAL flush). On the INSERT arm it is 0 — a row with a blob
 *     and deployed_at = 0 is a confirmation, not a deployment.
 *   - observed_at is the INSERT arm's alone: now for a new row, untouched
 *     for an existing one.
 *   - stat may be NULL (a directory, or lstat failed after the write):
 *     the triple is written as zeros and the next read takes the slow
 *     path.
 *   - prune_ordered resets to 0: the path is back under a live row.
 *
 * resolved_out semantics:
 *   - If non-NULL, populated with the post-write record: every field the
 *     caller supplied — the row's identity and metadata (borrowed: the
 *     string pointers are the row's, not copies), the blob, the stat —
 *     plus the two columns the SQL decided, observed_at and deployed_at,
 *     read back through RETURNING. Snapshot mirrors assign it directly;
 *     no C-side rule logic is needed because the DB already applied the
 *     rules.
 *   - May be NULL when the caller does not maintain an in-memory snapshot.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path is anchored to (must not be NULL; non-zero
 *            blob for a file row)
 * @param stat Stat triple captured after the confirmation (may be NULL)
 * @param now Timestamp of the write (must be > 0)
 * @param own true for an ownership event, false for a confirmation
 * @param resolved_out Optional out-param for the post-write record
 *                     (may be NULL; see semantics above)
 * @return Error or NULL on success
 */
error_t *state_anchor(
    state_t *state,
    const manifest_row_t *row,
    const stat_cache_t *stat,
    time_t now,
    bool own,
    anchor_t *resolved_out
);

/**
 * Retire a managed path's record
 *
 * DELETE by filesystem_path. A missing row is success: the callers name
 * paths that may have no record — never seen here, nothing to retire.
 * Called by apply's record step for every pruned, reclaimed or released
 * orphan, by update's purge of a deleted path, and by remove's release.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose record retires (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_retire_anchor(state_t *state, const char *filesystem_path);

/**
 * Order a managed path's deployed copy pruned
 *
 * Sets prune_ordered on the record: remove --delete-files chose the fate
 * of a deployed copy nothing backs any more, and apply is to prune it —
 * a clean copy; cleanup's skip reasons still protect a modified one. A
 * missing row is success: nothing was ever observed at the path, so
 * there is nothing to prune.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose deployed copy is to be pruned (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_order_prune(state_t *state, const char *filesystem_path);

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
 * Set file entry lifecycle phase
 *
 * Updates the state column for a manifest entry. Used by manifest layer
 * to mark files as inactive when they become orphaned (removed with no fallback).
 *
 * The vocabulary is the full file CHECK set: LIFECYCLE_ACTIVE,
 * LIFECYCLE_INACTIVE, LIFECYCLE_DELETED, LIFECYCLE_RELEASED. The type
 * system enforces vocabulary validity — no runtime check is needed.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - filesystem_path MUST exist in virtual_manifest
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path File to update (must not be NULL)
 * @param new_lifecycle Target lifecycle phase
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *state_set_file_state(
    state_t *state,
    const char *filesystem_path,
    state_lifecycle_t new_lifecycle
);

/**
 * Bulk DELETE: virtual_manifest entries by (profile, lifecycle-set)
 *
 * Single SQL statement: DELETE FROM virtual_manifest
 *                       WHERE profile = ? AND state IN (?, ?, ...)
 *
 * Replaces fetch-all-by-profile + per-row filter + per-row state_remove_file.
 * Atomic: a failure aborts the operation (no partial-cleanup foot-gun); a
 * success purges every matching row in one round-trip to SQLite.
 *
 * Edge cases:
 *   - state->db == NULL (no DB file)         → no-op success, *out_purged = 0
 *   - lifecycle_count == 0                   → ERR_INVALID_ARG (caller bug;
 *                                              empty IN-set is meaningless)
 *   - profile name unknown                   → zero rows affected (success)
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile Profile name to filter on (must not be NULL)
 * @param lifecycles Array of lifecycle phases to match (must not be NULL)
 * @param lifecycle_count Number of entries in lifecycles (must be > 0)
 * @param out_purged Output: rows deleted (optional, may be NULL)
 * @return Error or NULL on success
 */
error_t *state_purge_files_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *lifecycles,
    size_t lifecycle_count,
    size_t *out_purged
);

/**
 * Bulk UPDATE: virtual_manifest entries' lifecycle by (profile, from-set)
 *
 * Single SQL statement: UPDATE virtual_manifest SET state = ?
 *                       WHERE profile = ? AND state IN (?, ?, ...)
 *
 * Replaces fetch-all-by-profile + per-row filter + per-row state_set_file_state.
 * Atomic: a failure aborts the operation; a success transitions every matching
 * row in one round-trip.
 *
 * Vocabulary is enforced by the type system — no runtime validation needed.
 *
 * Edge cases:
 *   - state->db == NULL              → no-op success, *out_changed = 0
 *   - from_count == 0                → ERR_INVALID_ARG
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile Profile name to filter on (must not be NULL)
 * @param from_lifecycles Array of source lifecycle phases (must not be NULL)
 * @param from_count Number of entries in from_lifecycles (must be > 0)
 * @param new_lifecycle Target lifecycle phase
 * @param out_changed Output: rows updated (optional, may be NULL)
 * @return Error or NULL on success
 */
error_t *state_transition_files_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *from_lifecycles,
    size_t from_count,
    state_lifecycle_t new_lifecycle,
    size_t *out_changed
);

/**
 * Set commit_oid for a profile in enabled_profiles
 *
 * Writes the profile's current branch HEAD to the per-profile commit_oid
 * column. Single-row UPDATE on enabled_profiles.
 *
 * One caller: manifest_apply_scope, which writes the OID of the tree it
 * just projected for every enabled profile whose branch resolved. Every
 * command that moves an enabled branch runs the engine afterwards, so
 * no other writer exists.
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
 * (name, target) remain valid until the next shape mutation on
 * enabled_profiles:
 *   - state_enable_profile
 *   - state_disable_profile
 *   - state_reorder_profiles
 *   - state_rollback (any mutation could have happened in the transaction)
 *   - state_free
 *
 * state_set_profile_commit_oid does NOT invalidate these borrows — it
 * patches the commit_oid field of the matching row in place. The
 * commit_oid *value* under a previously returned pointer may change as a
 * result, but the pointer itself (and all name / target pointers)
 * stays valid.
 *
 * When the state has no database (state_load on a repository without
 * .git/dotta.db, never promoted via state_begin), returns
 * *out_entries = NULL, *out_count = 0.
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
 * Peek a single profile's deployment target
 *
 * Returns a borrowed pointer into the row cache. Same lifetime rules as
 * state_peek_profiles.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to look up (must not be NULL)
 * @return Borrowed deployment target string, or NULL when the profile has no
 *         deployment target, is not enabled, or the state has no database.
 */
const char *state_peek_profile_target(
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
 * Add or refresh a tracked directory (projection writer)
 *
 * True UPSERT — the directory mirror of state_add_file. The sole caller
 * is the manifest layer's projection loop, and projection means in-scope:
 * the row's state is set to 'active' unconditionally (INSERT and UPDATE
 * alike), reactivating rows the sweep just downgraded. Nothing else about
 * the path is touched — the record lives in its own table.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param row Directory row to project (must not be NULL; type == DIRECTORY)
 * @return Error or NULL on success
 */
error_t *state_add_directory(state_t *state, const manifest_row_t *row);

/**
 * Retire file rows that left scope without ever being materialized
 *
 * No record means "no filesystem obligation": dotta never observed the
 * path on disk while the row was in scope, so there is nothing to delete
 * and nothing downstream would ever retire it — every other deletion
 * path is driven by a filesystem effect the row does not have.
 *
 *   DELETE FROM virtual_manifest
 *    WHERE state != 'active'
 *      AND filesystem_path NOT IN (SELECT filesystem_path FROM anchors);
 *
 * Called by manifest_apply_scope after its leftover pass, inside the
 * same transaction: the demoter terminates its own demotions. On empty
 * state (no DB), no-op success. Attribution does not read counts from
 * here — the leftover pass counts ghosts per-profile from the anchors
 * snapshot it already holds (files_reclaimed). The purge in
 * manifest_update_files' and manifest_remove_files' fate overlays is a
 * different decision (terminal state for a deletion the user asked for,
 * observed or not) and does not overlap this one.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_reclaim_unmaterialized_files(state_t *state);

/**
 * Retire directory rows that left scope without ever being materialized
 *
 * Directory mirror of state_reclaim_unmaterialized_files — same predicate,
 * same "no filesystem obligation" semantics:
 *
 *   DELETE FROM tracked_directories
 *    WHERE state != 'active'
 *      AND filesystem_path NOT IN (SELECT filesystem_path FROM anchors);
 *
 * Called only by manifest_sync_directories, as the last step of its
 * rebuild. The sweep (state_mark_all_directories_inactive) is what demotes
 * directory rows, so the re-projection must re-activate every row
 * re-entering scope before this predicate runs — that ordering is the
 * reason this belongs inside the rebuild rather than at its call sites.
 * On empty state (no DB), no-op success.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_reclaim_unmaterialized_directories(state_t *state);

/**
 * Get all tracked directories
 *
 * Allocates the entries array and every string field from the caller's
 * arena. Lifetime is tied to the arena: caller controls cleanup by
 * destroying the arena. Every entry hydrates with type =
 * PATH_TYPE_DIRECTORY and old_profile = NULL.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_directories(
    const state_t *state,
    arena_t *arena,
    state_entry_t **out,
    size_t *count
);

/**
 * Remove directory entry by path
 *
 * Deletes directory entry from state. Used during orphan cleanup after
 * the directory has been removed from the filesystem. Retires the
 * expected row only; the record is retired separately by
 * state_retire_anchor.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path Filesystem path (PRIMARY KEY, must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_remove_directory(state_t *state, const char *filesystem_path);

/**
 * Mark all ACTIVE directories as inactive
 *
 * Bulk operation for manifest_sync_directories to prepare for rebuild.
 *
 * Only LIFECYCLE_ACTIVE rows are downgraded to LIFECYCLE_INACTIVE.
 * LIFECYCLE_DELETED is preserved (it represents downstream intent that must
 * survive a reconciliation sweep). Directory rows do not carry
 * LIFECYCLE_RELEASED — see the state_lifecycle_t vocabulary note.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_mark_all_directories_inactive(state_t *state);

/**
 * Bulk DELETE: tracked_directories entries by (profile, lifecycle-set)
 *
 * Single SQL statement: DELETE FROM tracked_directories
 *                       WHERE profile = ? AND state IN (?, ?, ...)
 *
 * Mirror of state_purge_files_by_profile for the tracked_directories table.
 * See that function's docstring for atomicity / edge-case semantics.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile Profile name to filter on (must not be NULL)
 * @param lifecycles Array of lifecycle phases to match (must not be NULL)
 * @param lifecycle_count Number of entries in lifecycles (must be > 0)
 * @param out_purged Output: rows deleted (optional, may be NULL)
 * @return Error or NULL on success
 */
error_t *state_purge_directories_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *lifecycles,
    size_t lifecycle_count,
    size_t *out_purged
);

/**
 * Bulk UPDATE: tracked_directories entries' lifecycle by (profile, from-set)
 *
 * Single SQL statement: UPDATE tracked_directories SET state = ?
 *                       WHERE profile = ? AND state IN (?, ?, ...)
 *
 * Mirror of state_transition_files_by_profile for the tracked_directories
 * table. new_lifecycle must not be LIFECYCLE_RELEASED — directory rows do
 * not carry that phase (see the state_lifecycle_t vocabulary note); this
 * boundary rejects it with ERR_INVALID_ARG.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile Profile name to filter on (must not be NULL)
 * @param from_lifecycles Array of source lifecycle phases (must not be NULL)
 * @param from_count Number of entries in from_lifecycles (must be > 0)
 * @param new_lifecycle Target lifecycle phase (must not be LIFECYCLE_RELEASED)
 * @param out_changed Output: rows updated (optional, may be NULL)
 * @return Error or NULL on success
 */
error_t *state_transition_directories_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *from_lifecycles,
    size_t from_count,
    state_lifecycle_t new_lifecycle,
    size_t *out_changed
);

#endif /* DOTTA_STATE_H */
