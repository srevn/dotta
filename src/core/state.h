/**
 * state.h - The enabled profiles, the record, and the path-keyed facts (SQLite)
 *
 * Persists what dotta cannot recompute: which profiles the user enabled here
 * (and in what order, with what targets), the record of what dotta did to each
 * managed path, and the two facts keyed beside it — the prune order (a deferred
 * intent) and the released copy (a fact that outlives its record). Each carrier
 * has a one-sentence lifetime rule:
 *   - the enabled set lives until the user changes it;
 *   - a record lives from first observation to explicit retire;
 *   - an order lives only while its path is out of the view — it dies when the
 *     path re-enters (the flush's join), when its record retires (the retire's
 *     sibling delete), or when apply executes it;
 *   - a released copy lives only while its fact can still be true — the read
 *     verifies it against live disk before trusting it, the flush's join forgets
 *     it once its path's record again carries a confirmed blob, and apply's sweep
 *     retires it when disk provably left it.
 * Everything else — what should stand at a path, from whom — is computed from
 * Git at every load (core/manifest.h) and never stored.
 *
 * The enabled set is this machine's mount table, one line of fstab per row: the
 * name is what is mounted (the branch — the repository is the device, and knows
 * nothing of where any machine mounts it), the position is the mount order (later
 * mounts stack on top: later wins), and the target is where the profile's own
 * tree — its custom/ paths — stands here. The target is part of the enablement,
 * not of the branch: bound by `enable --target` and `add --target`, moved in
 * place by `enable --target`, kept by an enable that names none, and gone with
 * the row when the profile is disabled. A profile with custom/ paths is enabled
 * only with a target; the one row without one that can exist is the profile a
 * sync brought custom/ paths into after it was enabled here, and the build holds
 * that tree's claims until it is bound (manifest_unbound).
 *
 * Database location: the store's dotta.db, beside its refs (utils/repo.h)
 *
 * Schema:
 *   - schema_meta: Schema versioning
 *   - enabled_profiles: User's profile management
 *   - path_anchors: The record — what dotta last reconciled each managed path
 *     against, and what it confirmed there (both kinds, one row per path)
 *   - prune_orders: The one deferred intent — remove --delete-files ordered the
 *     deployed copy pruned at the next apply (row existence is the fact)
 *   - released_copies: The content-proof half of a record that released — disk
 *     still held dotta's last confirmation when dotta let go of the path
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
 * a same-second, same-size, in-place rewrite — so the read-derived constructor
 * refuses to build that proof (mtime >= now ⇒ UNSET, Git's "racily clean" smudge,
 * write-side); the record then advances blob-only and the next load's slow path
 * confirms once, in a closed second. A capture of a file edited this second
 * therefore defers its fast path one load. A triple born from the write itself
 * (stat_cache_from_write) is exempt: authorship, not a read, is its proof.
 */
typedef struct {
    int64_t mtime;    /* st_mtime seconds at last known-good state (0 = unset) */
    int64_t size;     /* st_size at last known-good state */
    uint64_t ino;     /* st_ino at last known-good state */
} stat_cache_t;

#define STAT_CACHE_UNSET ((stat_cache_t){0})

/**
 * Populate stat cache from a struct stat the caller read
 *
 * The read-derived constructor: a triple is born only from a struct stat the
 * caller already holds at the moment of its look — a post-commit capture's fstat,
 * or the slow-path CMP_EQUAL confirmation's lstat — so the triple and the bytes
 * the caller verified describe the same moment. There is deliberately no from-path
 * variant: a fresh look taken at record-write time would bind whatever stands
 * at the path then to a verdict from earlier.
 *
 * A stat whose mtime second has not closed (mtime >= now: written this very second,
 * or carrying a future mtime) demotes to UNSET — a read can only infer the bytes
 * behind a stat, and no proof is built where a same-second, same-size, in-place
 * rewrite could stand behind it (the Lineage note above). Residue, accepted: a
 * rewrite landing between the caller's look and this call, with the call crossing
 * the second boundary in that sub-millisecond gap — the same order of window
 * Git accepts between hashing a file and writing its index entry.
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
 * Populate stat cache from the write that authored the bytes
 *
 * The write-derived constructor: the caller holds the fstat of a descriptor it
 * wrote itself — deploy's executor, taken after the last byte and before the
 * rename that publishes the file — so the triple describes dotta's own bytes by
 * authorship, not by a read's inference. There is no open second to smudge, because
 * there is nothing to mis-infer: the record says "dotta put (mtime, size, ino)
 * there", true the instant the write lands.
 *
 * What the smudge would have bought is narrower here and waived deliberately: a
 * foreign same-second, same-size, in-place rewrite of the just-deployed file
 * reads clean until its stat moves — the race Git accepts for every file checkout
 * writes into its index. The alternative was worse than the race: a deploy could
 * never arm a proof, every deployed path paid one redundant content read on its
 * next load, and a deployed 0000 claim — whose read the mode itself forbids —
 * stood [unreadable] forever.
 */
static inline stat_cache_t stat_cache_from_write(const struct stat *st) {
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
 *   - the blob a record carries is the blob of the claim the record names. The
 *     pair (profile, storage_path) is the binding that blob was confirmed under,
 *     and an encrypted blob is readable under no other (infra/content) — so the
 *     record's own pair, not the row's, is what a later load decrypts its base
 *     with (core/workspace.c analyze_file_divergence, compute_orphan_divergence).
 *     Kept by the two writers between them: state_anchor writes the claim beside
 *     the blob, and state_confirm advances the blob only for the claim the record
 *     already names (its precondition below).
 *
 * The identity and metadata fields (storage_path, profile, type, mode, owner,
 * group) are those of the row the record was written from — who deployed what,
 * under which claim. A confirmation rewrites only what it confirmed (type, blob,
 * stat); the claim — profile, storage path, mode, owner, group — is an ownership
 * event's to change. They are what an orphan (a record whose path no active row
 * names) is measured against, and an owned record whose profile ≠ the active
 * row's profile is a reassignment apply has not acknowledged — on a file row
 * and on a directory the profile manages, never on a derived ancestor claim nobody
 * made (core/workspace.h workspace_reassigned).
 */
typedef struct anchor {
    /* Identity — the row's, at the last write */
    char *filesystem_path;    /* Deployed path (PRIMARY KEY): the physical spelling */
    char *storage_path;       /* Path in profile (home/.bashrc) */
    char *profile;            /* Profile whose row dotta reconciled the path against */

    /* What dotta set there */
    path_type_t type;         /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    mode_t mode;              /* Recorded mode; meaningful iff type != SYMLINK */
    char *owner;              /* Recorded owner (can be NULL) */
    char *group;              /* Recorded group (can be NULL) */

    /* What dotta confirmed */
    git_oid blob_oid;         /* Content-confirmed blob (zero = never confirmed: a directory, or observed only) */
    stat_cache_t stat;        /* Fast-path stat triple, bound to blob_oid (all-zero = unusable) */
    time_t observed_at;       /* First sighting on disk in scope (> 0 always: a row exists iff observed) */
    time_t deployed_at;       /* Last active-ownership event (advances; 0 = never owned) */
} anchor_t;

/**
 * Released copy — a fact that outlives its record (released_copies row)
 *
 * One row says: at this filesystem path, dotta's last content confirmation —
 * this blob, this kind, under this claim pair — was still standing when dotta
 * let go of the path. Exactly the content-proof half of the record it descends
 * from (identity + confirmed pair, verbatim), claim-free: the claim and lifecycle
 * halves died with the record, so a released fact never fabricates a record, a
 * reassignment, or a DELETED absence. File kinds only — a directory has no content
 * confirmation to outlive its record.
 *
 * The row is a claim about the past, verified against the present at every use:
 * the analyzer reads it as the base of the three-way content question only when
 * the path's record carries no confirmed blob, and never trusts it without the
 * live stat or content check it performs for any base. The storage_path and profile
 * are the blob's own binding — an encrypted blob decrypts under its writer's
 * subkey (profile name → KDF) with its tree path as AAD — so a released base
 * stays verifiable even after the branch that wrote it is gone. The type routes
 * the TYPE arm's second question by the base's own kind, keeping the fast and
 * slow paths in agreement.
 */
typedef struct {
    /* Identity — the record's, at release */
    char *filesystem_path;    /* Released path (PRIMARY KEY) */
    char *storage_path;       /* Path in profile — AAD of an encrypted blob */
    char *profile;            /* Subkey of an encrypted blob */

    /* The confirmed pair, copied verbatim from the record */
    path_type_t type;         /* FILE, SYMLINK or EXECUTABLE — never DIRECTORY */
    git_oid blob_oid;         /* Content-confirmed blob (never zero: the write guard filters) */
    stat_cache_t stat;        /* Fast-path stat triple, bound to blob_oid (all-zero = unusable) */
} released_copy_t;

/**
 * Enabled profile entry
 *
 * One row from the enabled_profiles table, materialized as an in-memory record.
 * The handle holds the whole table as an array of these — read when the handle
 * opens the database, and again at every boundary that makes the table the handle's
 * own (a transaction taken, a row written, a rollback) — so the array has one
 * state and every reader of it is a plain read.
 *
 * Ownership: state handle owns the strings; callers that peek receive borrowed
 * pointers valid until the next boundary (see state_peek_profiles).
 */
typedef struct {
    char *name;              /* Profile name (owned) */
    char *target;            /* Where the profile's custom/ tree stands here (owned); NULL when unbound */
} state_profile_entry_t;

/**
 * State structure (opaque)
 */
typedef struct state state_t;

/**
 * Load state from repository (read-only, scoped-mutation capable)
 *
 * Nothing at the store's dotta.db — the filesystem's answer, never one inferred
 * from an open that failed — is a store never written: a usable handle with no
 * connection and no rows, promoted by state_begin at the first write intent.
 * Anything else standing there is opened as dotta's store at this schema version
 * or refused, the refusal naming the file: a file this identity cannot open, a
 * directory, a link to nowhere, a file that is not a database, a database that
 * holds no dotta schema (an empty one included: dotta never leaves one, see
 * state_begin), another version's, or one missing a table. Use for the READ
 * acquisition shape — see runtime.h's dotta_state_mode_t.
 *
 * The refusals are ERR_STATE_INVALID, never ERR_PERMISSION: SQLite opens the
 * file as the invoker on every run, outside sys/filesystem's second try, so the
 * remedy that code carries (base/error.h) would be false here.
 *
 * A load writes nothing of dotta's — no row, no schema, no journal mode, and no
 * database where none was. What SQLite does on any read is its own: its shared
 * locks, its -wal and -shm files, and the PASSIVE checkpoint state_free asks
 * for at the close, which moves frames a writer committed into the file.
 *
 * Reads the enabled_profiles rows into the handle's cache: the boundary where
 * that table becomes this handle's, so every later reader of it is a plain read
 * (state_peek_profiles). A handle with no database reads zero rows; a table that
 * cannot be read is this call's failure, not a later peek's silent "nothing
 * enabled".
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out);

/**
 * Load state for update (whole-dispatch transaction held)
 *
 * state_load, promoted by state_begin: WRITE is READ promoted at dispatch, through
 * the one door and the one creation, with the write lock already held (BEGIN
 * IMMEDIATE) when it returns. The transaction is committed by state_save() or
 * rolled back by state_free() (cleanup on error paths). Use for the WRITE
 * acquisition shape — see runtime.h's dotta_state_mode_t. If another process
 * holds the write lock, waits up to 3 seconds (SQLITE_BUSY). The row cache is
 * read inside the lock, so the rows this handle answers from are the transaction's
 * own snapshot. *out is set only once the lock is held: a refusal leaves it NULL.
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
 * state_save). Must be paired with state_commit(), state_save() or
 * state_rollback().
 *
 * On a handle whose load found nothing at the path, this first brings the store's
 * database into being — the first write intent, never a read. It is built where
 * no other process can see it and published whole, only where nothing stands:
 * no process ever meets one half-made, a store another process published since
 * this handle's load is opened and never replaced, and something else found
 * standing there is refused as the load refuses it, with nothing written into
 * it. A filesystem that holds no hard links refuses the publication.
 *
 * The lock is SQLite's to grant: a failure to take it names another process only
 * when one holds it (SQLITE_BUSY, after the busy timeout). A database this identity
 * cannot write is opened read-only, granted the lock, and refuses its first write.
 *
 * Re-reads the row cache inside the new lock: a handle that has been open since
 * before the lock was taken holds rows another process may have committed since,
 * and the transaction's own snapshot is what its readers must see.
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
 * Re-reads the row cache from the rolled-back table — a mutation inside the
 * transaction left it holding rows the database no longer has. This is the one
 * place a read of that table has no channel: a read that fails here empties the
 * cache, and every caller of rollback is already unwinding the command (workspace's
 * flush, add's, remove's and update's record phases, profile's and interactive's
 * cleanup), none of which reads the state again.
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
 * Enable, or re-enable with a binding
 *
 * A new name appends a row at the end of the order; an enabled name keeps its
 * position (UPSERT). `target` binds the profile's custom/ tree here; NULL (or
 * empty) names no target and keeps the one the row has — the only way a row loses
 * its target is state_disable_profile. The callers validate a target before it
 * reaches this write (mount_validate_target, at the binders).
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - profile MUST NOT be NULL or empty
 *
 * Postconditions:
 *   - Profile added to enabled_profiles or existing entry updated
 *   - target column set when one is given; otherwise unchanged (NULL on a new row)
 *   - enabled_at timestamp updated to current time
 *   - Transaction remains open (caller commits)
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param profile Profile name (must not be NULL)
 * @param target The binding to write, or NULL to keep the row's
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
 * Removes profile from enabled_profiles table — the line whole, target included:
 * nothing remembers a disabled profile's binding, and the caller that wants to
 * say what was forgotten reads it before this call.
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
 * `profiles` is the enabled set, permuted — every enabled name once, and nothing
 * else — and the boundary refuses anything less: a name that is not a row
 * (ERR_INVALID_ARG) and a list shorter than the table (ERR_INVALID_ARG), because
 * the rewrite re-inserts exactly the names given and a shorter list would delete
 * the rows it left out; a name twice fails the re-insert on UNIQUE(name). Additions
 * belong to state_enable_profile, removals to state_disable_profile. The table
 * is untouched on every refusal.
 *
 * Direct callers:
 *   - profile reorder: the user's whole order, validated there — every enabled
 *                      name once.
 *   - interactive save: persists the new order after the TUI's own diff has already
 *                       applied additions/removals via the membership primitives.
 *
 * Preconditions:
 *   - state MUST have an active write transaction.
 *   - profiles MUST NOT be NULL. profiles->count may be 0 (vacuous reorder of
 *     an empty table).
 *
 * Postconditions:
 *   - enabled_profiles rows hold positions 0..N-1 in the order given.
 *   - target preserved on every row.
 *   - enabled_at timestamp refreshed for every row.
 *   - Row cache re-read from the rewritten table.
 *   - Transaction remains open (caller commits).
 *
 * @param state State (must not be NULL)
 * @param profiles The enabled names in the desired order (must not be NULL)
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
 * Answers from the row cache, which is the table (state_peek_profiles): a plain
 * read, with no load to fail underneath it.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_has_profile(const state_t *state, const char *profile);

/**
 * Bound carrier for the enabled_profiles rows, the manifest_rows_t idiom.
 */
typedef struct {
    const state_profile_entry_t *entries;
    size_t count;
} state_profiles_t;

/**
 * The enabled_profiles rows, in position order (the user's precedence order)
 *
 * Pure value return — no allocation, no error path. The slice aliases the row
 * cache, which the handle reads with the database and re-reads at every boundary
 * where the table becomes the handle's again, so between boundaries the slice
 * IS the table. A repository with no database (state_load before any state_begin
 * promoted it) holds a load of zero rows, which is the correct view of it: an
 * empty slice, not a failure.
 *
 * Lifetime — the rows and the strings they reference (name, target) stand until
 * the next boundary replaces the cache:
 *   - state_begin
 *   - state_enable_profile
 *   - state_disable_profile
 *   - state_reorder_profiles
 *   - state_rollback
 *   - state_free
 *
 * A caller that must outlive one of those copies what it needs, and says so:
 * cmds/profile.c's disable receipt the targets it is about to forget, and
 * cmds/add.c's pre-flight the binding its receipt names after the record phase.
 *
 * @param state State (NULL returns an empty slice)
 * @return Borrowed slice over the rows
 */
state_profiles_t state_peek_profiles(const state_t *state);

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
 * one without; and sync's apply hint walks it against the view the Git phase
 * produced, with no workspace and no disk (cmds/sync.c).
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
 * owner, group), which only an ownership event changes. One UPDATE by
 * filesystem_path; the record must exist — one cannot confirm what one has not
 * seen, and the flush observes first. File rows only: a directory has no content
 * to confirm, and row->blob_oid must be non-zero (a zero blob would record "never
 * confirmed" for a path this call claims to have confirmed — rejected here, where
 * the schema's CHECK would only refuse the zeroblob).
 *
 * Why a confirmation leaves the claim alone: the claim says who deployed the
 * content on disk and under which row. A confirmation against a different profile's
 * row does not change that — the file still holds what profile A put there, it
 * merely also satisfies B's row — and the workspace reads A ≠ B as a reassignment
 * apply has yet to acknowledge (workspace.c analyze_file_divergence). Were the
 * confirmation to rewrite the profile, the slow path would acknowledge
 * reassignments silently while the fast path, which writes nothing, showed them.
 *
 * And why a confirmation of another claim is not written at all — the precondition:
 * `row` must be the claim the record names (manifest_is_claim on the record's
 * profile and storage path). Advancing the blob from any other row would leave
 * the record naming one claim and carrying another's bytes, which is not merely
 * untidy: an encrypted blob opens under one (profile, storage path) pair and no
 * other, so the pair the record does name would no longer decrypt what it holds,
 * and the base every later load measures disk against would be unreadable. Enforced
 * by the one place confirmations are queued from — core/workspace.c's
 * workspace_record_confirmation, which holds the record and asks before it queues
 * — so this statement trusts what it is handed and the flush is its only caller.
 * A row that is not the record's claim is a pending handover: apply's
 * acknowledgement moves the record onto it (cmds/apply.c), and until it does
 * the path takes the slow path on every load.
 *
 * No snapshot mirror is taken here: the caller that keeps one (the workspace's
 * flush) patches exactly the columns this statement names on the record it already
 * holds.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Active row whose blob disk was found equal to, and the claim the
 *            record names (must not be NULL; a file row with a non-zero blob)
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
 * DELETE by filesystem_path — the record and, in the same breath, its order: an
 * order cannot outlive its record, and the rule is kept by this explicit sibling
 * delete, never a constraint (nothing is a parent, nothing cascades). A missing
 * row is success: the callers name paths that may have no record — never seen
 * here, nothing to retire. Called by apply's record step for every pruned or
 * reclaimed orphan (the copy is gone — there is no fact), by update's purge of
 * a deleted path, by add's settle of the ancestor claims its own commit dropped,
 * and — composed inside state_release — for every release.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose record retires (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_retire_anchor(state_t *state, const char *filesystem_path);

/**
 * Order a managed path's deployed copy pruned
 *
 * Inserts the path into prune_orders: remove --delete-files chose the fate of a
 * copy nothing backs any more — one the removal named, or one dotta deployed;
 * never a copy dotta merely found under an unnamed path (the gate the one settle
 * loop enforces, cmds/remove settle_let_go) — and apply is to prune it — a clean
 * copy; cleanup's skip reasons still protect a modified one. The insert is guarded
 * by the record's existence (an order cannot exist without a record), so a missing
 * record is a no-op success: nothing was ever observed at the path, so there is
 * nothing to prune. At birth an ordered path is out of the view by construction
 * — the settle loop runs only over paths the post-commit view lacks, whichever
 * remove route called it.
 *
 * An order lives only while its path is out of the view. Read in exactly one
 * place — the workspace's orphan analysis — and voided by the flush's join when
 * the path re-enters the view, by the retire's sibling delete when the record
 * goes, or by apply executing the prune (the retire of the pruned record takes
 * the order with it).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose deployed copy is to be pruned (must not be
 *                        NULL)
 * @return Error or NULL on success (no record is OK)
 */
error_t *state_order_prune(state_t *state, const char *filesystem_path);

/**
 * Get every ordered path, in filesystem_path order
 *
 * The one read of the prune_orders table, the shape of state_get_all_anchors:
 * the array and its strings are the caller's arena's. The workspace loads it
 * once per run, unconditionally — the honour arm reads membership, and the flush's
 * join must see the orders even when no orphan stands for them (the path back
 * in the view is exactly the case with no orphan).
 *
 * On empty state (no DB), returns *out = NULL, *count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array of paths (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_prune_orders(
    const state_t *state,
    arena_t *arena,
    char ***out,
    size_t *count
);

/**
 * Void one prune order
 *
 * DELETE by filesystem_path; a missing row is success. Two callers, each an end
 * of the order's lifetime rule: the flush's join (the path re-entered the view
 * — the removal the order answered was reverted) and state_retire_anchor's sibling
 * delete (the record died; executed orders retire this way too).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose order is void (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_void_prune_order(state_t *state, const char *filesystem_path);

/**
 * Release a managed path: keep the record's content-proof, retire the record
 *
 * The record's death when the copy stays on disk. The INSERT arm moves the
 * content-proof half (identity + confirmed pair) into released_copies; it inserts
 * nothing for a directory or a never-confirmed record (blob IS NULL) — for those
 * this IS state_retire_anchor, so callers never branch on kind. OR REPLACE: a
 * path can release more than once across its life, and the latest fact is what
 * disk holds — while a proof-less re-release leaves an older, still-true row
 * standing. Then the retire, composed: the same call state_retire_anchor's callers
 * make, both its deletes included.
 *
 * The write is blind — remove and apply's release sites never lstat first. A
 * row false at birth (the user edited before releasing) degrades safely: the
 * read verifies against live disk before trusting it, and the sweep retires what
 * disk provably left. A rekey'd repository leaves old released rows permanently
 * UNVERIFIED at the read; they die by the same sweep or the flush's join when
 * the path is re-owned.
 *
 * A missing record is success: nothing observed, nothing to remember.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path being released (must not be NULL)
 * @return Error or NULL on success (no record is OK)
 */
error_t *state_release(state_t *state, const char *filesystem_path);

/**
 * Get every released copy, in filesystem_path order
 *
 * The released_copies read, the shape of state_get_all_anchors: the array and
 * its strings are the caller's arena's. The workspace loads it once per run,
 * unconditionally, beside the record; apply's sweep takes a fresh read inside
 * its own transaction so the run's release writes are included.
 *
 * On empty state (no DB), returns *out = NULL, *count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_released_copies(
    const state_t *state,
    arena_t *arena,
    released_copy_t **out,
    size_t *count
);

/**
 * Forget one released copy
 *
 * DELETE by filesystem_path; a missing row is success. Two callers, each an end
 * of the fact's lifetime rule: the flush's join (the path's record again carries
 * a confirmed blob — the fresher confirmation subsumes the fact) and apply's
 * sweep (disk provably left the copy: the path is absent, or its live size differs
 * from the recorded triple's). Never a compare-result consumer: a failed look
 * retires no fact.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose released copy is forgotten (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_forget_released(state_t *state, const char *filesystem_path);

#endif /* DOTTA_STATE_H */
