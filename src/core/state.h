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
 * - Prepared statements kept for the connection's life, for every write that
 *   binds a value
 * - A path-keyed table holds keys alone — absolute and folded, the shape
 *   mount_resolve spells every key in (base/string.h str_path_folded), and whole
 *   — and refuses any other where a hand makes the edit (key_spelling). The shape
 *   and never the length: a key longer than PATH_MAX is the kernel's to refuse,
 *   at the call that meets it
 * - Every name the store keeps is held the same way to what its readers assume
 *   of it: a storage name stands under its label (storage_spelling), as label_of
 *   and label_tail check of every record's; a profile's name is never empty
 *   (profile_spelling); and an owner or a group is a name, whole and never empty
 *   — so no reader meets a name that would abort it, print as no one, or read
 *   as another
 * - A stamp is a moment or 0, never negative, so a reader asking `== 0` and one
 *   asking `> 0` ask one question
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
 * the node every triple it holds was taken of (state_stat_matches).
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
 * Four groups of columns, one rule each. The store writes a record whole and
 * asks nothing of it (state_write), so each rule is kept where a record is built:
 * a first observation and apply's ownership events from the row the path is
 * reconciled against (core/workspace.h workspace_observation), add's and update's
 * from what their capture committed (cmds/add.c add_path_t, cmds/update.c
 * update_commit_t), a learning from the record the load read (core/workspace.c
 * workspace_learning).
 *   - the binding (profile, storage_path): the row the record follows — who
 *     deployed what — and the pair its blob was confirmed under. The row's at
 *     the first observation — a gone node's record's replacement among them —
 *     and at every ownership event (apply deploy, adoption, acknowledgement,
 *     add, update); a learning keeps the one it read. A storage name in the grammar
 *     and a profile never empty, each whole (schema-enforced).
 *   - the content (kind, blob_oid, stat): the node the record describes — a regular
 *     file, a link or a directory, in a look's own words (fs_occupant_t) — and
 *     the blob dotta last verified it holds, with the stat of that moment. The
 *     first observation writes the node alone, the row's; the blob and the stat
 *     advance only after disk-matches-blob verification — an ownership event,
 *     which writes all three from what it established (apply's from the row it
 *     deployed or found standing, a capture's from what it read and committed:
 *     the one blob the stage wrote, never a later head's), and a learning of
 *     the content (the slow-path CMP_EQUAL), which keeps the node: it is made
 *     only onto a record of the row's kind, since a record of another node, the
 *     look having found the row's in its place, gives way to the row's first
 *     observation before anything is learned onto it (core/workspace.c
 *     workspace_flush) — a whole write, never a learning onto the gone node's
 *     record. No node is executable: the bit is the claim's mode, and Git's
 *     filemode the row's alone. Zero blob_oid is no content confirmation — a
 *     directory, whose whole confirmed-disk record is that it was observed (a
 *     directory has no content confirmation, schema-enforced), or a file observed
 *     but never confirmed.
 *   - the claim (mode, owner, group): the claim dotta last reconciled the path
 *     against, and so the base a difference on a claim axis is read from — disk
 *     off it the user's move, the row off it Git's claim still to bring
 *     (core/workspace.h workspace_claims_moved). The row's at the first observation
 *     and at apply's ownership events, the one a capture authored at add's and
 *     update's (the claim its capture answered, core/profiles.h
 *     profile_stage_capture_file, profile_stage_capture_directory), and on each
 *     axis a look found disk standing on, or a fix made it stand on, the row's
 *     since (a learning of the claim) — and on the mode, where a run left a
 *     directory at the working mode it could not narrow, that mode, which no
 *     claim made (core/deploy.h deploy_hold_t), so the row's reads as Git's still
 *     to bring. It is a file orphan's reference on disk too; a directory orphan
 *     is judged by its emptiness, never its claim. A link claims no mode: its
 *     column is NULL, and every other node's is permission bits, 0000–0777; an
 *     owner and a group are names, whole and never empty, NULL where the claim
 *     names none (each schema-enforced).
 *   - the lifecycle (deployed_at, ordered_at): the two acts the record remembers,
 *     each a moment or 0 (schema-enforced). deployed_at advances to now on every
 *     ownership event and a learning keeps it, 0 = dotta never put this here.
 *     ordered_at is when remove --delete-files ordered the copy pruned
 *     (state_order_prune, which re-stamps), 0 = no order standing: no record
 *     written whole carries one (state_write) — an ownership event writes it
 *     away, the flush's learning voids it where the view holds the path again —
 *     and it goes with the row.
 *
 * Invariants:
 *   - blob_oid is non-zero iff dotta has at some point confirmed disk content
 *     matched that blob. Zero means "never confirmed."
 *   - a stat matching a live look of the record's kind proves, on the fast path,
 *     that disk still equals blob_oid (state_stat_matches).
 *   - the confirmed pair (kind, blob_oid) is not the manifest row's content iff
 *     the Git-expected value has advanced past the last disk confirmation — i.e.,
 *     stale. The pair, not the blob alone: Git hashes a link's target exactly
 *     as it hashes a file's bytes, so one id stands behind both, and the kind
 *     is what tells them apart (core/workspace.h workspace_stale).
 *   - deployed_at > 0 on a file implies a non-zero blob_oid: the write that owned
 *     it confirmed it (schema-enforced). A row with a blob and deployed_at = 0
 *     is a confirmation, not a deployment.
 *   - the blob a record carries was committed under its binding — the name, in
 *     the profile, that the record keeps — whatever that binding's row holds
 *     since. An encrypted blob is readable under no other binding (infra/content)
 *     — so the record's own binding, not the row's, is what a later load decrypts
 *     its base with (core/workspace.c workspace_compare_base). Kept where the
 *     record is built, since the store writes what it is handed: a first
 *     observation and apply's ownership events take the binding and the blob
 *     from one row, add's and update's from one capture — the name it committed
 *     under and the blob the stage wrote there — and a learning, which keeps
 *     the binding it read, learns a blob only where the row is that binding's
 *     claim (core/workspace.c workspace_analyze_file, the content's note) — or
 *     onto the row's first observation, whose binding is the row's
 *     (workspace_flush).
 *
 * The binding and the claim are what an orphan (a record whose path the view
 * lacks) is measured against — the claim is a file orphan's reference on disk,
 * and the binding names the profile asked whether it still holds the path — and
 * an owned record whose profile ≠ the profile of the row at its path is a
 * reassignment apply has not acknowledged: on a file row and on a directory the
 * profile tracks, never on a derived ancestor claim nobody made, and across kinds
 * only while a look finds the record's own node still standing (core/workspace.h
 * workspace_reassigned).
 */
typedef struct state_record {
    const char *filesystem_path; /* Deployed path (PRIMARY KEY), as spelled */

    /* The binding */
    const char *storage_path; /* Path in profile (home/.bashrc) */
    const char *profile;      /* Profile whose row the record follows */

    /* The content */
    fs_occupant_t kind;       /* The node: REGULAR, SYMLINK or DIRECTORY */
    git_oid blob_oid;         /* Content-confirmed blob (zero = never confirmed: a directory, or observed only) */
    state_stat_t stat;        /* Fast-path stat triple, bound to blob_oid (all-zero = unusable) */

    /* The claim */
    mode_t mode;              /* Meaningful iff kind != SYMLINK */
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
 * writes that verify advance it (a learning of the content, an ownership event),
 * so a look that matches it is the same node unwritten since — disk still holds
 * the record's blob, with nothing loaded and nothing hashed. An UNSET triple
 * (mtime 0 — never confirmed, or the read-derived constructor's smudge) matches
 * no look, which is the slow path by default.
 *
 * The kind is the stat's own: the record's, the node the triple was taken of. A
 * node's kind is fixed for the life of its inode, and the inode is the filesystem's
 * to hand out again: a node of another kind reusing it at the stat's size within
 * the stat's second is not the node the stat was taken of, and taken for it, a
 * link the user made reads as dotta's file — clean, or pruned as an orphan. Git's
 * ce_match_stat asks the entry's mode before its stat data for the same reason.
 * A link for a link and a regular file for a regular file, the record's kind
 * being a look's word already; never of a directory, which confirms no content
 * and so carries no stat.
 *
 * Whether there is a stat to ask about is the asker's question, not this one's.
 *
 * Readers: core/workspace.c workspace_analyze_file, of the base, and
 * workspace_compare_base, of the base or an orphan's record — the two fast paths,
 * which must not disagree about what a stat proves, and cannot: each hands in a
 * record whole, and the triple is never asked under a kind not its own.
 */
static inline bool state_stat_matches(const state_record_t *record, const struct stat *st) {
    return record->stat.mtime != 0
           && (record->kind == FS_OCCUPANT_SYMLINK ? S_ISLNK(st->st_mode) : S_ISREG(st->st_mode))
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
 * Before the rows, it keeps where the store stands as the handle first reads
 * it: the store a resume asks against until the handle's first commit
 * (state_resume).
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t state_load(git_repository *repo, state_t **out);

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
error_t state_open(git_repository *repo, state_t **out);

/**
 * Save state
 *
 * Commits the open transaction — the one state_open() started, or the one
 * state_begin() or state_resume() started after an earlier save. All modifications
 * made since the transaction began are atomically committed; a handle with no
 * open transaction by its own account (state_locked) saves nothing and succeeds.
 * A refused save is state_commit's, and so is what its callers owe it: nothing
 * said of the writes before it returns.
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
error_t state_save(state_t *state);

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
 * that must act on what it decided before the lock — from its load, or under an
 * earlier lock of its own — takes it with state_resume instead, which refuses
 * where the store moved.
 *
 * @param state State (must not be NULL, must not be in transaction)
 * @return Error or NULL on success
 */
error_t state_begin(state_t *state);

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
 * The COMMIT is itself a write the store can refuse, apart from every statement
 * before it: in WAL mode the transaction's pages reach the log here, so a full
 * disk refuses the COMMIT and never the statements. What a caller says of its
 * transaction's writes is therefore said once this has returned, never before
 * it: a line above a refused COMMIT names writes the rollback took back
 * (tests/test-runtime.sh refuses one through a file-size limit).
 *
 * @param state State (must not be NULL, must be in transaction)
 * @return Error or NULL on success
 */
error_t state_commit(state_t *state);

/**
 * Take the write lock only where the store stands as this handle last knew it
 *
 * state_begin, and one question asked under the lock: has another connection
 * committed since this handle last stood on the store — its last commit
 * (state_commit), or its admission where it has made none (state_load)? Where
 * one has, the transaction is rolled back and the answer is ERR_CONFLICT; where
 * the version cannot be read, rolled back, with the read's error. The question
 * is the store's alone — Git's refs and the disk are no part of it — and it is
 * the whole of it: any commit moves the version, a learning's as much as a move,
 * so a caller that resumes is one that would rather refuse than act on what another
 * writer did. The version is connection-local by SQLite's contract, so the question
 * is this handle's.
 *
 * Readers, each writing what it decided from reads made before the lock:
 *   - cmds/apply.c cmd_apply, after the present's checkpoint (state_save): its
 *     plan is the load's, which a run cannot read again without a present of
 *     its own to commit and say, and the lock was let go to say this one;
 *   - core/workspace.c workspace_flush, where the caller holds no lock: what a
 *     load owes the record is decided from its view and its record read, both
 *     taken before any lock, so it is written only where the store is still the
 *     one they read.
 * A caller that decides under the lock it takes — update's record phase, remove's
 * settle, interactive's save — reads the store as it stands, and owes the question
 * nothing (state_begin).
 *
 * @param state State (must not be NULL, must not be in transaction)
 * @return Error or NULL on success
 */
error_t state_resume(state_t *state);

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
 * core/workspace.c workspace_flush, before its writes, the one reader.
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
 * write (infra/path.h path_input_target, at the binders), and the schema refuses
 * what they would not have written (the target_spelling constraint), an empty
 * string among them: NULL is the one spelling of no target. The name is one Git's
 * branch rule admitted — a branch the caller listed or asked for (sys/gitops.h
 * gitops_branch_refname) — and the schema refuses the names no reader of the
 * row could read (the profile_spelling constraint), the empty one among them.
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - profile MUST NOT be NULL
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
error_t state_enable_profile(
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
error_t state_disable_profile(
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
error_t state_reorder_profiles(state_t *state, const string_array_t *profiles);

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
 * hydrates to a zero OID, a link's NULL mode to 0. Every column is read exactly
 * or the read fails: a conversion SQLite cannot allocate is ERR_MEMORY, never a
 * NULL taken for a value the column holds — an owner the path has, read as none.
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
 *   - cmds/add.c add_write_record (the takeover note), cmds/remove.c
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
error_t state_records(
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
 * Readers: cmds/add.c add_write_record (the takeover note), cmds/remove.c
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
 * Write a record whole
 *
 * Every column the record carries, over whatever stood at its key — one INSERT
 * OR REPLACE — so nothing of the record before the write survives it: the prune
 * order among it, which no record written whole carries, since an order lives
 * only while its path is out of the view and every record written is an active
 * path's. The store asks nothing of the record beyond what the schema holds (its
 * CHECKs, key_spelling): what the record says is its builder's, each rule kept
 * where the record is built (state_record_t). And the write is blind, decided
 * against the store it lands in: under a lock the writer holds while it reads
 * what it decides from — the run's, taken at dispatch (apply, add), or one taken
 * for the phase (update's record phase: its own captures, and the view it builds
 * under the lock) — or under a lock taken only where the store still stands as
 * the caller's reads left it (state_resume: a read command's flush, apply's record
 * phase).
 *
 * The store's own spelling of a record, the one a read gives back (state_records):
 * a zero blob, an absent owner or group bind NULL, and so does a link's mode,
 * which the kind makes a don't-care whatever the record says of it. A kind no
 * record describes — UNKNOWN, NONE, OTHER: a record built without its node —
 * has no spelling, and the store refuses it (the column's NOT NULL) rather than
 * write it as a file.
 *
 * ROUTING INVARIANT — this is load-bearing:
 *   - Where a workspace live for this transaction is read after the write, its
 *     writes go through the workspace's writers — the flush, workspace_anchor,
 *     workspace_learn, workspace_learn_mode (core/workspace.h) — each of which
 *     points the path's item at the record this wrote. Called directly there,
 *     the item goes on holding what the load read.
 *   - Where no workspace is read after the write — add's record phase, which
 *     loads none, and update's, whose workspace nothing reads after it
 *     (core/workspace.h's exception) — this is the legitimate direct caller.
 *
 * @param state State (must not be NULL, must have open database)
 * @param record The record to write (must not be NULL); read, never written
 * @return Error or NULL on success; a refusal names the path
 */
error_t state_write(state_t *state, const state_record_t *record);

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
 * purge, for what their commits let go; and add's settle, for the ancestor claims
 * its own commit dropped.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose record retires (must not be NULL)
 * @return Error or NULL on success (not found is OK)
 */
error_t state_retire(state_t *state, const char *filesystem_path);

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
 * latest.
 *
 * An order lives only while its path is out of the view. Read in exactly one
 * place — the workspace's orphan analysis — and ended by every record written
 * whole (state_write): the flush's, where the path has re-entered the view, and
 * an ownership event's; and gone with its record (a retire; apply executing the
 * prune is one).
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path Path whose deployed copy is to be pruned (must not be
 *                        NULL)
 * @param now The order's moment (must be > 0)
 * @return Error or NULL on success (no record is OK)
 */
error_t state_order_prune(state_t *state, const char *filesystem_path, time_t now);

#endif /* DOTTA_STATE_H */
