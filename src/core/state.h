/**
 * state.h - The enabled profiles and the record (SQLite)
 *
 * Persists the two things dotta cannot recompute: which profiles the user enabled
 * here (and in what order, with what targets), and the record of what dotta did
 * to each managed path. Everything else — what should stand at a path, from whom
 * — is computed from Git at every load (core/manifest.h) and never stored.
 *
 * Database location: .git/dotta.db
 *
 * Schema:
 *   - schema_meta: Schema versioning
 *   - enabled_profiles: User's profile management
 *   - path_anchors: The record — what dotta last reconciled each managed path
 *     against, and what it confirmed there (both kinds, one row per path)
 *
 * Design principles:
 * - Binary format (fast, compact)
 * - WAL mode (concurrent access, atomic commits)
 * - Prepared statements (100x faster for bulk operations)
 * - Persistent indexes (O(1) lookups without rebuilding)
 * - Nothing derivable is stored: the record is dotta's own and never derivable;
 *   the expected side is Git's and lives in Git
 */

#ifndef DOTTA_STATE_H
#define DOTTA_STATE_H

#include <git2.h>
#include <sys/stat.h>
#include <time.h>
#include <types.h>

/* The record is written from a row of the view (core/manifest.h); the writers
 * take it by pointer, so the row is named here and defined there. */
typedef struct manifest_row manifest_row_t;

/**
 * Stat cache — fast-path field of an anchor
 *
 * Field of an anchor_t: the (mtime, size, ino) triple captured at the moment
 * dotta confirmed disk content equals anchor.blob_oid. If a later live stat matches
 * all three fields, disk is still equal to anchor.blob_oid without re-hashing —
 * the same approach Git uses with its index.
 *
 * Sentinel: All-zero state means unset — forces the slow path (safe default).
 * mtime == 0 acts as validity gate: a file with genuine mtime=0 (epoch) simply
 * never benefits from the fast path — correct, just not optimized.
 *
 * Lineage: this is Git's cache_entry stat data serving ce_match_stat, with the
 * same blind spot and the same cure. A triple whose mtime second had not closed
 * when the stat was taken cannot distinguish the bytes the caller verified from
 * a same-second, same-size, in-place rewrite — so the constructor refuses to
 * build that proof (mtime >= now ⇒ UNSET, Git's "racily clean" smudge, write-side).
 * The record then advances blob-only and the next load's slow path confirms once,
 * in a closed second. Consequence, deliberate: a deploy can never bind a usable
 * triple (its file's second is its own), and a capture of a file edited this
 * second defers its fast path one load.
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
 * The one constructor: a triple is born only from a struct stat the caller already
 * holds at the moment of its look — a post-commit capture's fstat, or the slow-path
 * CMP_EQUAL confirmation's lstat — so the triple and the bytes the caller verified
 * describe the same moment. There is deliberately no from-path variant: a fresh
 * look taken at record-write time would bind whatever stands at the path then
 * to a verdict from earlier.
 *
 * A stat whose mtime second has not closed (mtime >= now: written this very second,
 * or carrying a future mtime) demotes to UNSET — no proof is built where a
 * same-second, same-size, in-place rewrite could stand behind it (the Lineage
 * note above). Residue, accepted: a rewrite landing between the caller's look
 * and this call, with the call crossing the second boundary in that sub-millisecond
 * gap — the same order of window Git accepts between hashing a file and writing
 * its index entry.
 */
static inline stat_cache_t stat_cache_from_stat(const struct stat *st) {
    if ((int64_t) st->st_mtime >= (int64_t) time(NULL)) {
        return STAT_CACHE_UNSET;
    }
    return (stat_cache_t){
        .mtime = (int64_t) st->st_mtime,
        .size = (int64_t) st->st_size,
        .ino = (uint64_t) st->st_ino,
    };
}

/**
 * Anchor — the record dotta keeps of a managed path (path_anchors row)
 *
 * The row dotta last reconciled this path against — what it deployed, or, when
 * deployed_at is 0, what it was looking at when it first observed the path —
 * and what it confirmed there. One row per filesystem path, both kinds. A row
 * exists iff dotta has observed the path on disk while it was managed: there is
 * no "never observed" row, and observed_at is never zero.
 *
 * Three signals, three write rules — one verb each (below):
 *   - blob_oid + stat : content-verified pair. Advanced only after
 *     disk-matches-blob verification — state_confirm (the slow-path CMP_EQUAL)
 *     and state_anchor (apply deploy, adoption, add, update). Zero blob_oid is
 *     no content confirmation — a directory, whose whole confirmed-disk record
 *     is that it was observed (a directory has no content confirmation,
 *     schema-enforced), or a file observed but never confirmed.
 *   - deployed_at     : active-ownership timestamp. Advances to now on
 *     every state_anchor (apply deploy, adoption, acknowledgement, add, update);
 *     untouched by a confirmation. 0 = dotta never put this here.
 *   - observed_at     : first-observation timestamp. Written once, by
 *     whichever write creates the row (state_observe, or state_anchor's INSERT
 *     arm), and never again: the first caller wins because no later write names
 *     the column.
 *
 * Invariants:
 *   - blob_oid is non-zero iff dotta has at some point confirmed disk content
 *     matched that blob. Zero means "never confirmed."
 *   - stat matching live stat is fast-path proof that disk still equals blob_oid.
 *   - blob_oid ≠ the manifest row's blob_oid iff the Git-expected value has
 *     advanced past the last disk confirmation — i.e., stale.
 *   - deployed_at > 0 on a file implies a non-zero blob_oid: the write that owned
 *     it confirmed it (schema-enforced). A row with a blob and deployed_at = 0
 *     is a confirmation, not a deployment.
 *
 * The identity and metadata fields (storage_path, profile, type, mode, owner,
 * group) are those of the row the record was written from — who deployed what,
 * under which claim. A confirmation rewrites only what it confirmed (type, blob,
 * stat); the claim — profile, storage path, mode, owner, group — is an ownership
 * event's to change. They are what an orphan (a record whose path no active row
 * names) is measured against, and an owned record whose profile ≠ the active
 * row's profile is a reassignment apply has not acknowledged.
 *
 * prune_ordered is the one persisted intent: remove --delete-files ordered the
 * deployed copy pruned at the next apply. Meaningful only for an orphan; cleared
 * by state_confirm and state_anchor, one of which every route back under an active
 * row takes once disk matches the row (a clean fast-path hit on an ordered record
 * queues the confirmation for exactly this). While the copy is edited or gone
 * the order stands, and the divergence it is measured against keeps it from pruning
 * the edit.
 */
typedef struct anchor {
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
} state_profile_entry_t;

/**
 * State structure (opaque)
 */
typedef struct state state_t;

/**
 * Load state from repository (read-only, scoped-mutation capable)
 *
 * If .git/dotta.db doesn't exist, returns a usable handle whose state->db is
 * NULL (lazy promotion by state_begin happens on first write). If the file exists
 * but is corrupt or wrong version, returns an error. Use for the READ acquisition
 * shape — see runtime.h's dotta_state_mode_t.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out);

/**
 * Load state for update (whole-dispatch transaction held)
 *
 * Opens (creating if necessary) .git/dotta.db with the write lock already held
 * (BEGIN IMMEDIATE). The transaction is committed by state_save() or rolled back
 * by state_free() (cleanup on error paths). Use for the WRITE acquisition shape
 * — see runtime.h's dotta_state_mode_t. If another process holds the write lock,
 * waits up to 3 seconds (SQLITE_BUSY).
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_open(git_repository *repo, state_t **out);

/**
 * Save state
 *
 * Commits the open transaction — the one state_open() started, or the one
 * state_begin() started after an earlier save. All modifications made since the
 * transaction began are atomically committed; a handle with no open transaction
 * saves nothing and succeeds.
 *
 * A command whose writes have two lifetimes saves at the boundary between them
 * and begins again (state_begin): apply commits what the load established —
 * observations, confirmations, adoptions — before the first exit it can take
 * without executing, then holds a second transaction for the record of what it
 * executed. Each save is one lifetime's commit.
 *
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(state_t *state);

/**
 * Begin an explicit transaction on a state handle
 *
 * Acquires a write lock (BEGIN IMMEDIATE). Used by batch operations that need
 * atomicity on a state opened via state_load() (no inherent transaction), and
 * by a state_open() handle that has saved once and has more to write (see
 * state_save). On a handle whose underlying DB does not yet exist on disk
 * (state_load() on a repository never touched by `dotta init`), this lazily creates
 * .git/dotta.db before taking the lock — mirroring state_open()'s create semantics,
 * deferred to the moment of actual write intent. Must be paired with
 * state_commit(), state_save() or state_rollback().
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
 * Returns true if BEGIN IMMEDIATE has been executed and not yet committed or
 * rolled back. Used by code paths that may run under either acquisition shape
 * (workspace_flush_updates, ...) to decide whether to start their own scoped
 * transaction or piggyback on the caller's.
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
 * Enable profile with optional deployment target
 *
 * If profile already enabled, updates its target (UPSERT behavior). Position
 * assigned automatically as MAX(position) + 1 for new profiles.
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
 * Atomically deletes and re-inserts every row in enabled_profiles so the position
 * column reflects the order of `profiles`. Per-row state (the target) is preserved
 * across the rewrite — only precedence changes.
 *
 * REORDER-ONLY CONTRACT:
 *   Reorder permutes membership; it does not add or remove rows. Every name in
 *   `profiles` MUST already be a row in enabled_profiles, and the set of names
 *   MUST equal the current enabled set (any caller passing a different set is a
 *   bug — the function rejects unknown names at the boundary but does not
 *   synthesize the inverse "rows you forgot to include" check; that's the caller's
 *   responsibility).
 *
 *   Additions belong to state_enable_profile. Removals belong to
 *   state_disable_profile. A name not currently enabled returns ERR_INVALID_ARG
 *   and leaves the table untouched — closing the silent (custom-profile,
 *   NULL-target) trap at the write boundary.
 *
 * Direct callers:
 *   - profile reorder: user-driven precedence change.
 *   - interactive save: persists the new order after the TUI's own diff has already
 *                       applied additions/removals via the membership primitives.
 *
 * Preconditions:
 *   - state MUST have an active write transaction.
 *   - profiles MUST NOT be NULL. profiles->count may be 0 (vacuous reorder).
 *   - Every name in profiles MUST already be in the row cache.
 *
 * Postconditions:
 *   - enabled_profiles rows hold positions 0..N-1 in the order given.
 *   - target preserved on every retained row.
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
 * Fast O(n) check where n = number of enabled profiles (typically < 10). Useful
 * for commands that need to conditionally write the record based on whether a
 * profile is enabled.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_has_profile(const state_t *state, const char *profile);

/**
 * Peek the cached enabled_profiles rows
 *
 * Returns borrowed pointers to the in-memory row cache. Iteration order matches
 * enabled_profiles.position (the user's precedence order).
 *
 * Lifetime — pointers into the row array and the strings it references (name,
 * target) remain valid until the next shape mutation on enabled_profiles:
 *   - state_enable_profile
 *   - state_disable_profile
 *   - state_reorder_profiles
 *   - state_rollback (any mutation could have happened in the transaction)
 *   - state_free
 *
 * When the state has no database (state_load on a repository without .git/dotta.db,
 * never promoted via state_begin), returns *out_entries = NULL, *out_count = 0.
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
 * Get every anchor, in filesystem_path order
 *
 * The one read of the path_anchors table. Allocates the array and every string
 * field from the caller's arena; lifetime is tied to the arena. A NULL blob column
 * hydrates to a zero OID, a NULL mode to 0. The workspace loads it once per run
 * and indexes it by path; the verbs that need one record by path (remove) load
 * it the same way and index it themselves rather than growing a point read for
 * one caller; manifest_diff reads it to tell a departed row with a record from
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
 * Presence only, idempotent. INSERT OR IGNORE creates the record with the row's
 * identity and metadata, no blob, no stat, observed_at = now, and never touches
 * an existing row. The workspace calls it (through
 * workspace_observe) for an active row it found on disk with no record;
 * apply calls it for a directory it fixed rather than made. The record's existence
 * is what the absence classifier reads (workspace.c classify_absent): a path
 * once observed that is now missing was deleted, not never deployed.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path was observed under (must not be NULL)
 * @param now Observation timestamp (must be > 0)
 * @return Error or NULL on success
 */
error_t *state_observe(state_t *state, const manifest_row_t *row, time_t now);

/**
 * Confirm a managed path: record that disk content equals the row's blob
 *
 * The slow path's CMP_EQUAL, persisted: rewrites what the comparison established
 * — the kind (type), the content (blob_oid) and the stat triple captured with
 * it — and nothing of the claim the record carries (profile, storage_path, mode,
 * owner, group), which only an ownership event changes. prune_ordered resets:
 * the path is back under a live row. One UPDATE by filesystem_path; the record
 * must exist — one cannot confirm what one has not seen, and the flush observes
 * first. File rows only: a directory has no content to confirm, and row->blob_oid
 * must be non-zero (a zero blob would record "never confirmed" for a path this
 * call claims to have confirmed — rejected here, where the schema's CHECK would
 * only refuse the zeroblob).
 *
 * Why a confirmation leaves the claim alone: the claim says who deployed the
 * content on disk and under which row. A confirmation against a different profile's
 * row does not change that — the file still holds what profile A put there, it
 * merely also satisfies B's row — and the workspace reads A ≠ B as a reassignment
 * apply has yet to acknowledge (workspace.c analyze_file_divergence). Were the
 * confirmation to rewrite the profile, the slow path would acknowledge
 * reassignments silently while the fast path, which writes nothing, showed them.
 *
 * No snapshot mirror is taken here: the caller that keeps one (the workspace's
 * flush) patches exactly the columns this statement names on the record it already
 * holds.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Active row whose blob disk was found equal to (must not be NULL; a
 *            file row with a non-zero blob)
 * @param stat Stat triple captured by the comparison (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_confirm(
    state_t *state,
    const manifest_row_t *row,
    const stat_cache_t *stat
);

/**
 * Anchor a managed path: record the row dotta reconciled it against
 *
 * The ownership event — apply deploy, adoption, acknowledgement, add, update.
 * Call after confirming disk content matches row->blob_oid (or, for a DIRECTORY
 * row, after creating or confirming the directory). One statement, an UPSERT on
 * path_anchors: the INSERT arm creates the row with observed_at = now; the UPDATE
 * arm rewrites everything the row and the confirmation supply and leaves
 * observed_at alone. deployed_at = now on both arms.
 *
 * ROUTING INVARIANT — this is load-bearing:
 *   - If a workspace is live for this transaction, anchor writes MUST route through
 *     workspace_anchor (workspace.h). That wrapper calls this function with
 *     resolved_out pointing at a record it then patches into its snapshot — or
 *     creates there, when the path had no record at load — so every later reader
 *     in the run sees the canonical post-write value the SQL produced. Calling
 *     state_anchor directly while a workspace is live silently desyncs the
 *     snapshot.
 *   - If no workspace is live (add's and update's capture loops), this function
 *     is the legitimate direct caller. There is no snapshot to patch, so callers
 *     pass resolved_out=NULL and the next workspace_load reads SQL fresh.
 *
 * Semantics (encoded in the SQL — single source of truth):
 *   - row->blob_oid must be non-zero for a file row: a zero blob would record
 *     "never confirmed" for a path this call claims to have confirmed. Rejected
 *     here, before the schema's CHECK would reject it. A DIRECTORY row binds
 *     NULL — a directory has no content confirmation.
 *   - deployed_at = now: an ownership event, always. A confirmation is
 *     state_confirm's.
 *   - observed_at is the INSERT arm's alone: now for a new row, untouched for
 *     an existing one.
 *   - stat may be NULL (a directory; a deployed file — no triple survives the
 *     write's own open second; or the caller's establishment did not reach it):
 *     the triple is written as zeros and the next read takes the slow path.
 *   - prune_ordered resets to 0: the path is back under a live row.
 *
 * resolved_out semantics:
 *   - If non-NULL, populated with the post-write record: every field the caller
 *     supplied — the row's identity and metadata (borrowed: the string pointers
 *     are the row's, not copies), the blob, the stat, deployed_at = now — plus
 *     the one column the SQL decided, observed_at, read back through RETURNING.
 *     Snapshot mirrors assign it directly; no C-side rule logic is needed because
 *     the DB already applied the rule.
 *   - May be NULL when the caller does not maintain an in-memory snapshot.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path is anchored to (must not be NULL; non-zero blob for a
 *            file row)
 * @param stat Stat triple of the caller's establishing look (may be NULL; see
 *             semantics above)
 * @param now Timestamp of the write (must be > 0)
 * @param resolved_out Optional out-param for the post-write record (may be NULL;
 *                     see semantics above)
 * @return Error or NULL on success
 */
error_t *state_anchor(
    state_t *state,
    const manifest_row_t *row,
    const stat_cache_t *stat,
    time_t now,
    anchor_t *resolved_out
);

/**
 * Retire a managed path's record
 *
 * DELETE by filesystem_path. A missing row is success: the callers name paths
 * that may have no record — never seen here, nothing to retire. Called by apply's
 * record step for every pruned, reclaimed or released orphan, by update's purge
 * of a deleted path, and by remove's release.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose record retires (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_retire_anchor(state_t *state, const char *filesystem_path);

/**
 * Order a managed path's deployed copy pruned
 *
 * Sets prune_ordered on the record: remove --delete-files chose the fate of a
 * deployed copy nothing backs any more, and apply is to prune it — a clean copy;
 * cleanup's skip reasons still protect a modified one. A missing row is success:
 * nothing was ever observed at the path, so there is nothing to prune.
 *
 * Read in exactly one place — the workspace's orphan analysis — and honoured
 * only for a record whose path is not in the view; cleared by state_confirm and
 * state_anchor, one of which every route back into "active" eventually takes
 * (add, update, deploy, the CMP_EQUAL flush).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose deployed copy is to be pruned (must not be
 *                        NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_order_prune(state_t *state, const char *filesystem_path);

#endif /* DOTTA_STATE_H */
