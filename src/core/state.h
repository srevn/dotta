/**
 * state.h - The enabled profiles and the record (SQLite)
 *
 * Persists what dotta cannot recompute: which profiles the user enabled here
 * (and in what order, with what targets), and the record of what dotta did to
 * each managed path — the one deferred intent, the prune order the user gave
 * for it, a column of it. Each carrier has a one-sentence lifetime rule:
 *   - the enabled set lives until the user changes it;
 *   - a record lives from first observation to explicit retire;
 *   - an order lives while its path is out of the view: a column of its record,
 *     it goes with the row (a retire; apply executing it is one), an ownership
 *     event writes it away, and the flush voids it where the view holds the path
 *     again.
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
 * the row when the profile is disabled. The column holds an absolute, folded
 * target or NULL and nothing else — the schema refuses the rest, the binders'
 * own rule (infra/mount.h mount_validate_target) in the store's language — so a
 * hand edit is refused at the hand edit, and every reader of the row cache reads
 * a key or none. A profile with custom/ paths is enabled only with a target;
 * the one row without one that can exist is the profile a sync brought custom/
 * paths into after it was enabled here, and the build holds that tree's claims
 * until it is bound (manifest_unbound).
 *
 * Database location: the store's dotta.db, beside its refs (utils/repo.h)
 *
 * Schema:
 *   - the header: application_id marks the file dotta's, user_version names the
 *     schema it holds
 *   - enabled_profiles: User's profile management
 *   - path_records: The record — what dotta last reconciled each managed path
 *     against, and what it confirmed there (both kinds, one row per path), the
 *     prune order among its columns
 *
 * Design principles:
 * - Binary format (fast, compact)
 * - WAL mode (concurrent access, atomic commits)
 * - Prepared statements kept for the connection's life, for the writes a run
 *   repeats
 * - A path-keyed table holds keys alone — absolute and folded, the shape
 *   mount_resolve spells every key in (sys/filesystem.h fs_is_folded), and whole
 *   — and refuses any other where a hand makes the edit (key_spelling). The shape
 *   and never the length: a key longer than PATH_MAX is the kernel's to refuse,
 *   at the call that meets it
 * - A path-keyed table is stored sorted by its key and read in key order: the
 *   key is TEXT under BINARY — memcmp over UTF-8 — and holds no NUL (key_spelling),
 *   which is where BINARY and strcmp meet, so a read comes back in strcmp order:
 *   a parent before everything beneath it, and every key found by a binary search
 *   by strcmp. The getters' ORDER BY is the promise; the storage makes the read
 *   a walk of the table.
 * - Nothing derivable is stored, and nothing no read asks for: the record is
 *   dotta's own and never derivable; the expected side is Git's and lives in Git
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
 * The stat — the record's fast path
 *
 * Field of a state_record_t: the (mtime, size, ino) triple captured at the moment
 * dotta confirmed disk content equals record.blob_oid. If a later live stat matches
 * all three fields, disk is still equal to record.blob_oid without re-hashing —
 * the same approach Git uses with its index.
 *
 * Sentinel: All-zero state means unset — forces the slow path (safe default).
 * mtime == 0 acts as validity gate: a file with genuine mtime=0 (epoch) simply
 * never benefits from the fast path — correct, just not optimized.
 *
 * Lineage: this is Git's cache_entry stat data serving ce_match_stat, with the
 * same cure for the same race. A triple whose mtime second had not closed when
 * the stat was taken cannot distinguish the bytes the caller verified from a
 * same-second, same-size, in-place rewrite — so the read-derived constructor
 * refuses to build one (mtime >= now ⇒ UNSET, Git's "racily clean" smudge,
 * write-side); the record then advances blob-only and the next load's slow path
 * confirms once, in a closed second. A capture of a file edited this second
 * therefore defers its fast path one load. A triple born from the write itself
 * (state_stat_from_write) is exempt: authorship, not a read, vouches for it.
 * And as ce_match_stat reads the entry's mode beside its stat data, the kind is
 * read beside the triple, never stored in it: the record carries it already,
 * the type every writer of a triple writes with it (state_stat_matches).
 *
 * Narrower than Git's, and what that leaves, accepted: Git's stat data carries
 * ctime, and these three fields do not. So a stat misses two same-size edits —
 * one whose mtime is then restored to the recorded second (touch -r or -t, cp
 * -p from a same-size source carrying that second: a deliberate act, since a
 * restore from a copy of the deployed version brings its bytes too), and a rewrite
 * inside the second of deploy's own write, which the write-derived constructor
 * waives. ctime would close the first alone, at a price this model does not pay:
 * deploy takes its fstat before the rename that publishes the file, and the rename
 * moves ctime, so every deployed file's stat would miss; and chmod, extended
 * attributes and hard links move it too, a read each on every load — which is
 * why Git grew core.trustctime. Sub-second times close neither: a restore carries
 * them, and they narrow deploy's second only to the filesystem clock's tick.
 */
typedef struct {
    int64_t mtime;    /* st_mtime seconds at last known-good state (0 = unset) */
    int64_t size;     /* st_size at last known-good state */
    uint64_t ino;     /* st_ino at last known-good state */
} state_stat_t;

#define STATE_STAT_UNSET ((state_stat_t){0})

/**
 * Build a stat from a struct stat the caller read
 *
 * The read-derived constructor: a triple is born only from a struct stat the
 * caller already holds at the moment of its look — a post-commit capture's fstat,
 * or the lstat of a slow path that found disk the row's content — so the triple
 * and the bytes the caller verified describe the same moment. There is deliberately
 * no from-path variant: a fresh look taken at record-write time would bind whatever
 * stands at the path then to a verdict from earlier.
 *
 * A stat whose mtime second has not closed (mtime >= now: written this very second,
 * or carrying a future mtime) demotes to UNSET — a read can only infer the bytes
 * behind a stat, and none is built where a same-second, same-size, in-place rewrite
 * could stand behind it (the Lineage note above). Residue, accepted: a rewrite
 * landing between the caller's look and this call, with the call crossing the
 * second boundary in that sub-millisecond gap — the same order of window Git
 * accepts between hashing a file and writing its index entry.
 */
static inline state_stat_t state_stat_from_read(const struct stat *st) {
    if ((int64_t) st->st_mtime >= (int64_t) time(NULL)) {
        return STATE_STAT_UNSET;
    }
    return (state_stat_t){
        .mtime = (int64_t) st->st_mtime,
        .size = (int64_t) st->st_size,
        .ino = (uint64_t) st->st_ino,
    };
}

/**
 * Build a stat from the write that authored the bytes
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
 * never arm the fast path, every deployed path paid one redundant content read
 * on its next load, and a deployed 0000 claim — whose read the mode itself forbids
 * — stood [unreadable] forever.
 */
static inline state_stat_t state_stat_from_write(const struct stat *st) {
    return (state_stat_t){
        .mtime = (int64_t) st->st_mtime,
        .size = (int64_t) st->st_size,
        .ino = (uint64_t) st->st_ino,
    };
}

/**
 * The record dotta keeps of a managed path (a path_records row)
 *
 * The row dotta last reconciled this path against — what it deployed, or, when
 * deployed_at is 0, what it was looking at when it first observed the path —
 * and what it confirmed there. One row per filesystem path, both kinds. A row
 * exists iff dotta has observed the node its kind names at the path while it
 * was active — seen standing there, or put there: there is no "never observed"
 * row — the row's existence is the observation (core/workspace.c classify_absent
 * reads it, of the kind the record names), and no column restates it.
 *
 * Four groups of columns, one write rule each (the verbs below):
 *   - the binding (profile, storage_path): the row the record follows — who
 *     deployed what — and the pair its blob was confirmed under. Written from
 *     one row, at the first observation (state_observe) and at every ownership
 *     event (state_anchor: apply deploy, adoption, acknowledgement, add, update);
 *     a confirmation never moves it.
 *   - the content (type, blob_oid, stat): the kind the record describes, and
 *     the blob dotta last verified disk against, with the stat of that moment.
 *     The first observation writes the kind alone; the blob and the stat advance
 *     only after disk-matches-blob verification, the kind with them — state_confirm
 *     (the slow-path CMP_EQUAL) and state_anchor. Zero blob_oid is no content
 *     confirmation — a directory, whose whole confirmed-disk record is that it
 *     was observed (a directory has no content confirmation, schema-enforced),
 *     or a file observed but never confirmed.
 *   - the claim (mode, owner, group): the claim dotta last reconciled the path
 *     against — the row's at the first observation and at every ownership event,
 *     and on each axis a look found disk standing on, or a fix made it stand
 *     on, the row's since (state_confirm_claim). It is the base a claim Git moved
 *     is measured from (core/workspace.h workspace_claims_moved), and an orphan's
 *     reference on disk. The executable half of the type is copied from the row
 *     beside it and no verdict reads it: the kind rung takes FILE and EXECUTABLE
 *     for one kind (core/workspace.h workspace_compare_confirmed), and the mode
 *     carries the bit.
 *   - the lifecycle (deployed_at, ordered_at): the two acts the record remembers.
 *     deployed_at advances to now on every ownership event and is untouched by
 *     a confirmation, 0 = dotta never put this here. ordered_at is when remove
 *     --delete-files ordered the copy pruned (state_order_prune, which re-stamps),
 *     0 = no order standing: an ownership event writes it away with the rest of
 *     the record, the flush voids it where the view holds the path again
 *     (state_void_prune), and it goes with the row.
 *
 * Invariants:
 *   - blob_oid is non-zero iff dotta has at some point confirmed disk content
 *     matched that blob. Zero means "never confirmed."
 *   - a stat matching a live look of the record's kind proves, on the fast path,
 *     that disk still equals blob_oid (state_stat_matches).
 *   - the confirmed pair (type, blob_oid) is not the manifest row's content iff
 *     the Git-expected value has advanced past the last disk confirmation — i.e.,
 *     stale. The pair, not the blob alone: Git hashes a link's target exactly
 *     as it hashes a file's bytes, so one id stands behind both, and the kind
 *     is what tells them apart (core/workspace.h workspace_stale, which is also
 *     where the executable bit is ruled out of it).
 *   - deployed_at > 0 on a file implies a non-zero blob_oid: the write that owned
 *     it confirmed it (schema-enforced). A row with a blob and deployed_at = 0
 *     is a confirmation, not a deployment.
 *   - the blob a record carries is the blob of the row its binding names. An
 *     encrypted blob is readable under no other binding (infra/content) — so
 *     the record's own binding, not the row's, is what a later load decrypts
 *     its base with (core/workspace.c workspace_analyze_file,
 *     workspace_compare_orphan). Kept by each writer on its own: state_anchor
 *     writes the binding beside the blob from one row, and state_confirm's
 *     statement matches only a record whose binding is the one its row's blob
 *     opens under.
 *
 * The binding and the claim are what an orphan (a record whose path the view
 * lacks) is measured against — the claim is its reference on disk, and the binding
 * names the branch asked whether it still holds the path — and an owned record
 * whose profile ≠ the profile of the row at its path is a reassignment apply
 * has not acknowledged: on a file row and on a directory the profile tracks,
 * never on a derived ancestor claim nobody made, and across kinds only while a
 * look finds the record's own node still standing (core/workspace.h
 * workspace_reassigned).
 */
typedef struct state_record {
    const char *filesystem_path; /* Deployed path (PRIMARY KEY), as spelled */

    /* The binding */
    const char *storage_path; /* Path in profile (home/.bashrc) */
    const char *profile;      /* Profile whose row the record follows */

    /* The content */
    path_type_t type;         /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    git_oid blob_oid;         /* Content-confirmed blob (zero = never confirmed: a directory, or observed only) */
    state_stat_t stat;        /* Fast-path stat triple, bound to blob_oid (all-zero = unusable) */

    /* The claim */
    mode_t mode;              /* Meaningful iff type != SYMLINK */
    const char *owner;        /* The claimed owner, or NULL */
    const char *group;        /* The claimed group, or NULL */

    /* The lifecycle */
    time_t deployed_at;       /* Last ownership event (advances; 0 = never owned) */
    time_t ordered_at;        /* When remove --delete-files ordered the copy pruned (0 = no order standing) */
} state_record_t;

/**
 * Does a live look still stand behind the record's stat? — the fast path, spelled
 * once
 *
 * True iff the record's triple is set, the look is a node of the kind the triple
 * was taken of, and the look's own (mtime, size, ino) are the triple — safety-grade
 * rather than a guess because of the two constructors above: a set triple is
 * born only beside bytes dotta had verified or had itself written, and only the
 * verbs that verify advance it (state_confirm, state_anchor), so a look that
 * matches it is the same node unwritten since — disk still holds the record's
 * blob, with nothing loaded and nothing hashed. An UNSET triple (mtime 0 — never
 * confirmed, or the read-derived constructor's smudge) matches no look, which
 * is the slow path by default.
 *
 * The kind is the stat's own: the record's type, which every verb that writes
 * the triple writes with it, of the node the triple was taken of. A node's kind
 * is fixed for the life of its inode, and the inode is the filesystem's to hand
 * out again: a node of another kind reusing it at the stat's size within the
 * stat's second is not the node the stat was taken of, and taken for it, a link
 * the user made reads as dotta's file — clean, or pruned as an orphan. Git's
 * ce_match_stat asks the entry's mode before its stat data for the same reason.
 * Asked in the ladder's division, a link for a link and a regular file for either
 * blob mode (core/workspace.h workspace_type_occupant); never of a directory,
 * which confirms no content and so carries no stat.
 *
 * Whether there is a stat to ask about is the asker's question, not this one's.
 *
 * Readers: core/workspace.c workspace_analyze_file, of the base, and
 * workspace_compare_orphan, of the orphan's record — the two fast paths, which
 * must not disagree about what a stat proves, and cannot: each hands in a record
 * whole, and the triple is never asked under a kind not its own.
 */
static inline bool state_stat_matches(const state_record_t *record, const struct stat *st) {
    return record->stat.mtime != 0
           && (record->type == PATH_TYPE_SYMLINK ? S_ISLNK(st->st_mode) : S_ISREG(st->st_mode))
           && record->stat.mtime == (int64_t) st->st_mtime
           && record->stat.size == (int64_t) st->st_size
           && record->stat.ino == (uint64_t) st->st_ino;
}

/**
 * Enabled profile entry
 *
 * One row from the enabled_profiles table, copied into memory. The handle holds
 * the whole table as an array of these — read when the handle opens the database,
 * and again at every boundary that makes the table the handle's own (a transaction
 * taken, a row written), and put back by a rollback — so the array has one state
 * and every reader of it is a plain read.
 *
 * Ownership: the state handle owns the strings; a caller of state_profiles or
 * state_target borrows them, valid until the next boundary (see state_profiles).
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
 * Anything else standing there is opened as dotta's store at this schema or
 * refused, the refusal naming the file: a file this identity cannot open, a
 * directory, a link to nowhere, a file that is not a database, a database whose
 * header does not mark it dotta's (an empty one included: dotta never leaves
 * one, see state_begin), another schema's, or one missing a table. Use for the
 * READ acquisition shape — see runtime.h's dotta_state_mode_t.
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
 * (state_profiles). A handle with no database reads zero rows; a table that cannot
 * be read is this call's failure, not a later reader's silent "nothing enabled".
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
 * the one admission and the one creation, with the write lock already held (BEGIN
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
 * state_begin() or state_resume() started after an earlier save. All modifications
 * made since the transaction began are atomically committed; a handle with no
 * open transaction by its own account (state_locked) saves nothing and succeeds.
 *
 * A command whose writes have two lifetimes saves at the boundary between them
 * and takes the lock back (state_resume): apply commits the present — the
 * observations and confirmations its load owes, the adoptions and acknowledgements
 * of the rows it found clean — before the first exit it can take without executing,
 * then holds a second transaction for the record of what it executed. Each save
 * is one lifetime's commit.
 *
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(state_t *state);

/**
 * Begin an explicit transaction on a state handle
 *
 * Acquires a write lock (BEGIN IMMEDIATE). Used by batch operations that need
 * atomicity on a state opened via state_load() (no inherent transaction). Must
 * be paired with state_commit(), state_save() or state_rollback().
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
 * and the transaction's own snapshot is what its readers must see. A read that
 * fails is the call's failure: the lock is released, and the handle keeps the
 * rows it held.
 *
 * What the transaction writes is decided from what it reads inside the lock,
 * for the same reason: a read made before it is of a store another process may
 * have moved since, and a write the lock covers is blind to that move. A caller
 * that must act on what it decided under an earlier lock of its own takes the
 * lock back with state_resume instead, which refuses where the store moved.
 *
 * @param state State (must not be NULL, must not be in transaction)
 * @return Error or NULL on success
 */
error_t *state_begin(state_t *state);

/**
 * Commit a transaction started by state_begin()
 *
 * Keeps where the commit leaves the store — SQLite's data_version, read under
 * the lock before the COMMIT and kept only once the COMMIT lands — for the resume
 * that asks the store against it (state_resume). Before, because the version
 * counts other connections' commits as this one has seen them: this commit does
 * not move it, and a read after the COMMIT would take in a writer landing between
 * the two, the one the resume is there to see. A version that cannot be read
 * fails the commit and leaves the transaction the caller's, as a row cache that
 * cannot be read fails the begin: a boundary establishes what it keeps, or is
 * not crossed.
 *
 * @param state State (must not be NULL, must be in transaction)
 * @return Error or NULL on success
 */
error_t *state_commit(state_t *state);

/**
 * Take the write lock back where this handle's last commit left the store
 *
 * state_begin, and one question asked under the lock: has another connection
 * committed since this handle's last commit (state_commit)? Where one has, the
 * transaction is rolled back and the answer is ERR_CONFLICT; where the version
 * cannot be read, rolled back, with the read's error. The question is the store's
 * alone — Git's refs and the disk are no part of it — and it is the whole of
 * it: any commit moves the version, a learning's as much as a move, so a caller
 * that resumes is one that would rather refuse than act on what another writer
 * did. The version is connection-local by SQLite's contract, so the question is
 * this handle's, asked of a handle that has committed.
 *
 * Reader: cmds/apply.c cmd_apply, after the present's checkpoint (state_save):
 * its plan is the load's, which a run cannot read again without a present of
 * its own to commit and say, and the lock was let go to say this one. A caller
 * that decides under the lock it takes — update's record phase, remove's settle,
 * interactive's save — reads the store as it stands, and owes the question nothing
 * (state_begin).
 *
 * @param state State (must not be NULL, must not be in transaction)
 * @return Error or NULL on success
 */
error_t *state_resume(state_t *state);

/**
 * Roll back a transaction started by state_begin()
 *
 * Safe to call on error paths. Silently succeeds if no transaction active.
 *
 * The row cache goes back with the table, to the rows the transaction began with:
 * a write inside it had replaced them, and they are the table again, since no
 * other connection can move it while the lock is held. Nothing is read, so nothing
 * can fail, and a reader after a rollback reads the table it returned to: status's
 * header and sync's post-pull view after a flush's (cmds/status.c
 * status_print_profiles, cmds/sync.c cmd_sync), and add's receipt after its record
 * phase's (cmds/add.c cmd_add). The handle's account decides it (state_locked):
 * after a transaction SQLite ended itself the ROLLBACK finds none, and the rows
 * still go back — the table as it stood when the transaction began, which a writer
 * may have moved since the lock was lost.
 *
 * @param state State (must not be NULL)
 */
void state_rollback(state_t *state);

/**
 * Check if state has an active transaction
 *
 * Returns true if BEGIN IMMEDIATE has been executed and not yet committed or
 * rolled back. Read by a code path that may run under either acquisition shape,
 * to decide whether to start its own scoped transaction or write in the caller's:
 * core/workspace.c workspace_flush, at its first write, the one reader.
 *
 * The handle's own account, not SQLite's: where SQLite ends a transaction itself
 * — on a full disk or an I/O error, at a write or at the COMMIT — this answers
 * true until the handle's commit or rollback. No decision reads it there, since
 * every writer stops at its first refused write, and the account is what both
 * verbs that end a transaction need: the rollback puts back the rows the
 * transaction began with, and a save of the writes SQLite discarded fails, its
 * COMMIT finding no transaction, where asking SQLite would find none open and
 * save nothing in silence.
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
 * position (UPSERT). `target` binds the profile's custom/ tree here; NULL names
 * no target and keeps the one the row has — the only way a row loses its target
 * is state_disable_profile. The callers validate a target before it reaches this
 * write (mount_validate_target, at the binders), and the schema refuses what
 * they would not have written (the target_spelling constraint), an empty string
 * among them: NULL is the one spelling of no target.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - profile MUST NOT be NULL or empty
 *
 * Postconditions:
 *   - Profile added to enabled_profiles or existing entry updated
 *   - target column set when one is given; otherwise unchanged (NULL on a new row)
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
 *   - Row cache re-read from the rewritten table.
 *   - Transaction remains open (caller commits).
 *
 * @param state State (must not be NULL)
 * @param profiles The enabled names in the desired order (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_reorder_profiles(state_t *state, const string_array_t *profiles);

/**
 * Check if a profile is enabled
 *
 * Fast O(n) check where n = number of enabled profiles (typically < 10). Useful
 * for commands that need to conditionally write the record based on whether a
 * profile is enabled.
 *
 * Answers from the row cache, the table as the handle last read it
 * (state_profiles): a plain read, with no load to fail underneath it.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_enabled(const state_t *state, const char *profile);

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
 * is the table as the handle last read it — under the lock, the table itself;
 * on a handle that holds none, what another process commits since is not in it.
 * A repository with no database (state_load before any state_begin promoted it)
 * holds a read of zero rows, which is the correct answer for it: an empty slice,
 * not a failure.
 *
 * Lifetime — the rows and the strings they reference (name, target) stand until
 * the next boundary replaces the cache:
 *   - state_begin, and state_resume through it
 *   - state_enable_profile
 *   - state_disable_profile
 *   - state_reorder_profiles
 *   - state_rollback
 *   - state_free
 *
 * A caller that must outlive one of those copies what it needs, and says so:
 * cmds/profile.c profile_disable the names it disables and the targets they forget,
 * and cmds/add.c cmd_add the binding its receipt names after the record phase.
 * Every other reader reads the rows between two boundaries and keeps nothing
 * past them.
 *
 * @param state State (NULL returns an empty slice)
 * @return Borrowed slice over the rows
 */
state_profiles_t state_profiles(const state_t *state);

/**
 * A single profile's deployment target
 *
 * Returns a borrowed pointer into the row cache. Same lifetime rules as
 * state_profiles. The answer is a key or NULL, the column holding nothing else
 * (the table's paragraph above).
 *
 * Readers, each asking of one profile by its name: the binders that hold a --target
 * to the row's binding — cmds/add.c cmd_add, whose receipt names it after the
 * record phase, and cmds/profile.c profile_enable, where another directory is a
 * move; cmds/profile.c profile_disable, whose receipt names the one it forgets;
 * cmds/status.c status_print_profiles, which prints a binding beside its profile;
 * cmds/interactive.c read_targets, the editor's seed; and add's path completion,
 * which asks outside a repository too (cmds/completion.c completion_paths_under).
 * A reader walking the rows reads each one's target where it stands (cmds/profile.c
 * profile_list).
 *
 * @param state State (NULL answers NULL: a run with no database holds no row)
 * @param profile Profile name to look up (must not be NULL)
 * @return Borrowed deployment target string, or NULL when the profile has no
 *         deployment target, is not enabled, or the state has no database.
 */
const char *state_target(
    const state_t *state,
    const char *profile
);

/**
 * Every record, in filesystem_path order
 *
 * The one read of the path_records table. Allocates the array and every string
 * field from the caller's arena; lifetime is tied to the arena. A NULL blob column
 * hydrates to a zero OID, a NULL mode to 0.
 *
 * In strcmp order (the principle above). Readers, and what each takes from it:
 *   - core/workspace.c workspace_partition: pairs each record with the active
 *     item at its path by the items' own search (workspace_find_active); the
 *     orphans keep strcmp order, which workspace_look_orphans' parents-first
 *     walk, their search (workspace_find_item: workspace_find's and the scan's)
 *     and the diverged items' orphan listing (workspace_list, which the screens
 *     print) rest on
 *   - cmds/profile.c profile_validate: the deleted profiles in first-seen order,
 *     so the report is reproducible
 *   - cmds/add.c write_record (the takeover note), cmds/remove.c
 *     remove_paths_candidates (the settle's candidates, read before the lock
 *     and under it), and core/manifest.c manifest_diff (a departed row's orphan
 *     split, handed the array by cmds/profile.c profile_enable, profile_disable
 *     and cmds/sync.c cmd_sync): by path, through state_find_record, which rests
 *     on strcmp order
 *   - cmds/remove.c remove_profile_candidates (every record naming the profile,
 *     read before the prompt and under the lock) and cmds/sync.c cmd_sync's apply
 *     hint (every record against the view the Git phase produced, with no workspace
 *     and no disk): walks, key order unread
 *
 * On empty state (no DB), returns *out = NULL, *count = 0 with no error.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_records(
    const state_t *state,
    arena_t *arena,
    state_record_t **out,
    size_t *count
);

/**
 * The record at a path, in a snapshot state_records read — or NULL
 *
 * A binary search by strcmp, which is the read's own order (the principle above):
 * the array must be the getter's, in the order it came back, and a hand-built
 * one in another order misses what it holds. The empty snapshot — NULL, count 0
 * — holds nothing.
 *
 * Readers: cmds/add.c write_record (the takeover note), cmds/remove.c
 * remove_paths_candidates (the settle's candidates), core/manifest.c manifest_diff
 * (a departed row's orphan split).
 *
 * @param records The snapshot (NULL when count is 0)
 * @param count Records in it
 * @param filesystem_path The key (NULL returns NULL)
 * @return Borrowed record, or NULL where the snapshot holds none at the key
 */
const state_record_t *state_find_record(
    const state_record_t *records,
    size_t count,
    const char *filesystem_path
);

/**
 * Observe an active path: write the record of its first observation on disk
 *
 * Presence only, idempotent. One INSERT creates the record with the row's binding,
 * kind and claim — no blob, no stat, never owned — and never touches an existing
 * row: ON CONFLICT DO NOTHING absorbs the key's conflict and no other, so every
 * constraint on what it writes still refuses (key_spelling among them). Two
 * callers, both the load's, since the load is where presence is established:
 * the workspace's flush (core/workspace.c workspace_flush), for an active row
 * its load found standing as its own kind with no record — so a directory apply
 * fixes rather than makes was present there and is observed by that flush — and
 * workspace_observe_retyped, for a directory its load found standing where the
 * record describes another kind of node, a record that call retires first so
 * the INSERT lands. The record's existence is what the absence classifier reads
 * (workspace.c classify_absent): a path once observed that is now missing was
 * deleted, not never deployed.
 *
 * *record is the observation's record, written last, so a failure leaves it as
 * it was: the row's binding, kind and claim (borrowed — the string pointers are
 * the row's), and nothing else. Written whether the INSERT landed or met a row
 * another writer made since the caller's read — still the INSERT's own values,
 * never that row, and never read back: a confirmation of the path binds this
 * record as the pair it replaces (state_confirm), so, with no blob and no stat,
 * it matches nothing but an identical observation, where landing is right. Read
 * back, it would lend the confirmation another writer's newer pair to overwrite.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path was observed under (must not be NULL)
 * @param record The record the observation is written into (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_observe(state_t *state, const manifest_row_t *row, state_record_t *record);

/**
 * Confirm an active path: advance its record to what the comparison established
 *
 * The slow path's CMP_EQUAL, persisted: rewrites what the comparison established
 * — the content: the kind (type), the blob (blob_oid) and the stat triple captured
 * with it — and neither the binding the record carries, which only an ownership
 * event changes, nor its claim, which is state_confirm_claim's to confirm beside
 * it. The record must exist — one cannot confirm what one has not seen, and the
 * flush observes first. File rows only: a directory has no content to confirm,
 * and row->blob_oid must be non-zero (a zero blob would say "never confirmed"
 * for a path this call claims to have confirmed — rejected here, where the schema's
 * CHECK would only refuse the zeroblob).
 *
 * One UPDATE, a compare-and-swap on the record the caller read: it matches iff
 * the database still holds the binding the row's blob opens under and the content
 * *record holds — its kind, blob and triple. What the fact depends on and what
 * it overwrites are bound, and nothing else, so an ownership event that moved
 * neither (an adoption's stamp) lets it land, while a record another writer moved
 * — another binding, a newer blob, a fresher stat — matches nothing, and nothing
 * is written. *record follows the statement: advanced on the three columns it
 * names when it wrote, and last, so a failure leaves it as read; left as read
 * when it did not — memory behind the database, the direction the next load
 * corrects.
 *
 * The binding bound is the row's, never the record's: a blob is written only
 * onto a record whose binding it opens under, so state_record_t's rule holds at
 * the write, whoever noted the confirmation. The one place a load notes a content
 * confirmation asks the same of its record first (core/workspace.c
 * workspace_analyze_file), so one that cannot land never opens the flush's
 * transaction. A row the record's binding does not name is one the record has
 * yet to follow: apply's acknowledgement moves the record onto it (cmds/apply.c),
 * and until it does the path takes the slow path on every load.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row The row whose blob disk was found equal to (must not be NULL; a
 *            file row with a non-zero blob)
 * @param stat Stat triple captured by the comparison (must not be NULL)
 * @param record The path's record as the caller read it — the content this
 *               confirmation replaces (must not be NULL; its binding is not read,
 *               the row's is the one bound); advanced iff the statement wrote
 * @return Error or NULL on success — a record moved since the read is no error
 */
error_t *state_confirm(
    state_t *state,
    const manifest_row_t *row,
    const state_stat_t *stat,
    state_record_t *record
);

/**
 * Confirm an active path's claim: advance its record to the claim disk was found,
 * or made, to stand on
 *
 * The claim's confirmation, beside state_confirm's content: mode, owner and group
 * are the claim established — the row's on each axis the caller found or made
 * disk agree with, the record's own on the rest — and `record` is the record as
 * the caller read it. One UPDATE, a compare-and-swap on the record's kind and
 * claim as read: it rewrites the three claim columns iff the database still holds
 * exactly those, so a record another writer moved since — an ownership event,
 * another confirmation — matches nothing and nothing is written. The kind is
 * bound because the claim was measured against one: a record another writer retyped
 * takes no claim measured under the other kind. *record follows the statement
 * on the three columns when it wrote, borrowing the caller's strings, and last,
 * so a failure leaves it as read.
 *
 * No binding is bound: a claim opens nothing, so the record learns it whichever
 * row's it is — the content's confirmation is bound to the row's binding because
 * an encrypted blob opens under one, and a mode or an owner opens nothing. Nothing
 * else is written — not the binding, not the content, not the lifecycle — so
 * this is never an ownership event.
 *
 * Both kinds. A link's mode binds NULL on both sides, the rule its row's binds
 * by (state_observe, state_anchor), whatever `mode` says.
 *
 * @param state State (must not be NULL, must have open database)
 * @param mode The mode established (read for a record that is no link)
 * @param owner The owner established, or NULL (borrowed by *record when written)
 * @param group The group established, or NULL (borrowed by *record when written)
 * @param record The path's record as the caller read it — the claim this
 *               confirmation replaces (must not be NULL); advanced iff the
 *               statement wrote
 * @return Error or NULL on success — a record moved since the read is no error
 */
error_t *state_confirm_claim(
    state_t *state,
    mode_t mode,
    const char *owner,
    const char *group,
    state_record_t *record
);

/**
 * Anchor an active path: write its record from the row dotta reconciled it against
 *
 * The ownership event — apply deploy, adoption, acknowledgement, add, update.
 * Call after confirming disk content matches row->blob_oid (or, for a DIRECTORY
 * row, after creating or confirming the directory). One statement, INSERT OR
 * REPLACE on path_records: the event writes the record whole — the row's binding,
 * kind and claim, the blob and the stat of the confirmation, deployed_at = now
 * — and a column it does not name takes its default, so nothing of the record
 * before the event survives it.
 *
 * ROUTING INVARIANT — this is load-bearing:
 *   - If a workspace live for this transaction is read after the write, ownership
 *     events MUST route through workspace_anchor (workspace.h). That wrapper
 *     hands this function a record allocated for the event, and points the path's
 *     item at it once the statement lands, so every later reader in the run sees
 *     the record the statement wrote. Calling state_anchor directly there silently
 *     desyncs the snapshot.
 *   - If no workspace is read after the write — add's capture loop, which loads
 *     none, and update's, whose workspace nothing reads after its record write
 *     (core/workspace.h's exception) — this function is the legitimate direct
 *     caller. There is no snapshot to patch, so callers pass NULL and the next
 *     workspace_load reads SQL fresh.
 *
 * Semantics (encoded in the SQL — single source of truth):
 *   - row->blob_oid must be non-zero for a file row: a zero blob would say "never
 *     confirmed" for a path this call claims to have confirmed. Rejected here,
 *     before the schema's CHECK would reject it. A DIRECTORY row binds NULL — a
 *     directory has no content confirmation.
 *   - deployed_at = now: an ownership event, always. A confirmation is
 *     state_confirm's.
 *   - stat may be NULL or UNSET, which say the same thing here (a directory; a
 *     symlink deploy made by path, with no descriptor whose fstat could describe
 *     it; or a caller whose establishment did not reach a triple): the triple
 *     is written as zeros and the next read takes the slow path. A deployed file's
 *     is the write's own (state_stat_from_write).
 *   - the path's order ends: an ownership event takes the path into the view,
 *     where no order stands (the column's default).
 *
 * *record is set last, to the record the statement wrote — so a failure leaves
 * it untouched: whole — the row's binding, kind and claim (borrowed: the string
 * pointers are the row's, not copies), the blob, the triple, deployed_at = now,
 * no order — with no column the SQL's to decide, so the record set is the inputs.
 * It is written, never read: the one caller that keeps it hands one allocated
 * for the event (core/workspace.h workspace_anchor), never a record a reader holds.
 *
 * @param state State (must not be NULL, must have open database)
 * @param row Row the path is anchored to (must not be NULL; non-zero blob for a
 *            file row)
 * @param stat Stat triple of the caller's establishing look (may be NULL; see
 *             semantics above)
 * @param now Timestamp of the write (must be > 0)
 * @param record Where the record the statement wrote is set, or NULL where the
 *               caller keeps none (add's and update's capture loops)
 * @return Error or NULL on success
 */
error_t *state_anchor(
    state_t *state,
    const manifest_row_t *row,
    const state_stat_t *stat,
    time_t now,
    state_record_t *record
);

/**
 * Retire a managed path's record
 *
 * The record goes — DELETE by filesystem_path — and with it the order it carries,
 * a column of the row that cannot outlive it. Whatever ended the record — a prune,
 * a reclaim, an absence, a let-go, a deletion committed — and whatever stands
 * at the path, the path is forgotten: a claim that later returns to it starts
 * from its first look, as at a path dotta never saw. So the write is blind and
 * needs no look at disk first, which is what lets add and update retire the records
 * their commits let go without asking whether anything still stands.
 *
 * A missing record is success: the callers name paths that may have no record —
 * never seen here, nothing to retire. Callers: apply's record phase (cmds/apply.c
 * apply_write_record), for every orphan it settles; remove's settle and update's
 * purge, for what their commits let go; add's settle, for the ancestor claims
 * its own commit dropped; and apply's load, through core/workspace.c
 * workspace_observe_retyped, for a directory's record of another kind of node,
 * which the directory's observation replaces.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose record retires (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t *state_retire(state_t *state, const char *filesystem_path);

/**
 * Order a managed path's deployed copy pruned
 *
 * Stamps the record's order (ordered_at = now): remove --delete-files chose the
 * fate of a copy nothing backs any more — one the removal named, or one dotta
 * deployed; never a copy dotta merely found under an unnamed path (the gate the
 * one settle loop enforces, cmds/remove remove_settle) — and apply is to prune
 * it — a clean copy; cleanup's skip reasons still protect a modified one. A missing
 * record is a no-op success: the UPDATE matches no row, since nothing was ever
 * observed at the path. At birth an ordered path is out of the view by construction
 * — the settle loop runs only over paths the post-commit view lacks, whichever
 * remove route called it. A repeated order re-stamps: the order standing is the
 * latest, which is what lets the void tell it from one it read.
 *
 * An order lives only while its path is out of the view. Read in exactly one
 * place — the workspace's orphan analysis — voided by the flush when the path
 * re-enters the view (state_void_prune), written away by an ownership event
 * (state_anchor), and gone with its record (a retire; apply executing the prune
 * is one).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose deployed copy is to be pruned (must not be
 *                        NULL)
 * @param now The order's moment (must be > 0)
 * @return Error or NULL on success (no record is OK)
 */
error_t *state_order_prune(state_t *state, const char *filesystem_path, time_t now);

/**
 * Void a record's prune order, as read
 *
 * The order's view end: the flush's (core/workspace.c workspace_flush), for a
 * record the load read whose path the view holds again — the removal the order
 * answered was reverted. One UPDATE, a compare-and-swap on the stamp *record
 * holds: it clears the order iff the database still holds that one, so an order
 * placed again since the read — a second removal, answering what the reader's
 * view predates — stands. *record follows the statement, last: ordered_at 0 when
 * it wrote, as read when it did not.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param record The record as the caller read it (must not be NULL); advanced
 *               iff the statement wrote
 * @return Error or NULL on success — an order moved since the read is no error
 */
error_t *state_void_prune(state_t *state, state_record_t *record);

#endif /* DOTTA_STATE_H */
