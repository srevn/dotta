/**
 * state.c - The enabled profiles and the record (SQLite) — implementation
 *
 * Uses SQLite for performance and scalability.
 *
 * Key optimizations:
 * - Prepared statements kept for the connection's life: every write the store
 *   binds a value into — the record's, per path, and the enabled set's
 * - WAL mode for concurrent access
 * - Enabled-profile rows cached in memory (tiny, read frequently)
 * - The record read in one pass per run (state_records)
 * - The record stored sorted by its key: a read in key order walks the table
 *   (core/state.h)
 *
 * Every refusal the store's connection meets is made where it is met, in the
 * shape error_errno gives a kernel refusal (base/error.h): the prose of what
 * could not be done, then ": " and SQLite's own words, read off the connection
 * (sqlite3_errmsg) as an argument of the error made once the call has failed,
 * with no call that succeeds between them — SQLite leaves its words undefined
 * after one, a bind's among them, where the failed statement's own finalize says
 * its failure again (lib/sqlite3/sqlite3.c sqlite3VdbeReset) — and answers "out
 * of memory" for a connection never made. An exec is read the same way and handed
 * no out-parameter: the message it would copy out is the connection's
 * (lib/sqlite3/sqlite3.c sqlite3_exec). Coded by the store's subsystem
 * (ERR_STATE_INVALID), save a lock another process holds (ERR_CONFLICT,
 * state_begin); SQLite's number says nothing its words do not.
 */

#include "core/state.h"

#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "sys/filesystem.h"

/* The database header's two fields that are the application's (SQLite's file
 * format, offsets 68 and 60): whose file this is — "dott", the id's four bytes
 * — and the schema it holds. SQL literals, since a PRAGMA takes its value in
 * its own text and never as a bound parameter: state_initialize writes the header
 * with them, and state_verify asks the header against them, SQLite comparing
 * the integers. The id is a signed 32-bit field: a value at or above 0x80000000
 * is stored as 0, which no admission would take. */
#define STATE_APPLICATION_ID "0x646f7474"
#define STATE_SCHEMA_VERSION "30"

/* Database file name */
#define STATE_DB_NAME "dotta.db"

/**
 * The prepared statements — every write the store binds a value into, each declared
 * here once: its SQL is state_sql's case, its handle a slot of state->statements
 */
typedef enum {
    /* The enabled set's verbs */
    STATEMENT_ENABLE_PROFILE,  /* INSERT … ON CONFLICT (name) DO UPDATE (the row, its target given or kept) */
    STATEMENT_DISABLE_PROFILE, /* DELETE FROM enabled_profiles (the row, its target with it) */
    STATEMENT_INSERT_PROFILE,  /* INSERT INTO enabled_profiles (the reorder's, per profile) */

    /* The record's verbs */
    STATEMENT_WRITE,           /* INSERT OR REPLACE path_records (the record, whole) */
    STATEMENT_RETIRE,          /* DELETE FROM path_records (the record, and the order it carries) */
    STATEMENT_ORDER_PRUNE,     /* UPDATE path_records SET ordered_at (the order, stamped) */
} statement_t;

/* The statements' arity, for the handle's array and the two walks over it. A
 * macro, not an enumerator, for the reason LABEL_COUNT is one (infra/label.h):
 * the type holds no sentinel, so every statement_t subscripts the array in range
 * and state_sql's switch is total over the type as it stands. */
#define STATEMENT_COUNT (STATEMENT_ORDER_PRUNE + 1)

/**
 * One read of the enabled_profiles table, whole: its rows in position order,
 * each string the read's own — the rows state_profiles lends, owned
 */
typedef struct {
    state_profile_entry_t *entries;         /* NULL when the read found zero rows */
    size_t count;                           /* Rows in entries */
} profiles_t;

/**
 * State structure
 *
 * Maintains minimal in-memory cache for performance:
 * - Enabled-profile rows cached (tiny, read frequently)
 * - The record read on demand, whole (one pass per run)
 * - Prepared statements cached, all of them while db is open and none while it
 *   is not: state_admit prepares every one or closes, so a verb that finds db
 *   open takes its statement unchecked (state_statement)
 *
 * Row cache invariant:
 *   The cache is the enabled_profiles table as this handle last read it, and it
 *   has one state: loaded. state_read_profiles() reads it whole where the table
 *   becomes this handle's — the handle's open, a transaction taken — and again
 *   after each of the handle's own writes to it; a read is whole before it replaces
 *   anything, so one that fails leaves the cache as it was, and every reader of
 *   the cache is a plain read. Writes re-read rather than patch the in-memory
 *   layout: the table's rules — the position an UPSERT gives, the target it keeps
 *   — are SQL's, spelled once.
 *
 *   A transaction keeps the rows it began with until it ends: its writes replace
 *   the cache and leave them standing, its commit releases them, and its rollback
 *   puts them back. The table a rollback returns to is the one the transaction
 *   began with, which no other connection can move while the lock is held, so a
 *   rollback reads nothing and has nothing to fail. The two slots share one read
 *   until a write replaces the cache: "the transaction wrote the table" is the
 *   two pointers differing, the one test that decides which read is released,
 *   and it holds over a table of no rows, whose read is NULL in both.
 */
struct state {
    /* Database connection */
    sqlite3 *db;                            /* NULL while nothing stands at db_path; state_begin publishes one */
    char *db_path;                          /* The store's dotta.db; owned, freed by state_free */

    /* The transaction: a COMMIT or ROLLBACK owed, and the rows it began with */
    bool in_transaction;                    /* The handle's BEGIN, until its COMMIT or ROLLBACK (state_locked) */
    profiles_t begun;                       /* The rows it began with, its rollback's; none outside one */

    /* Where this handle last stood on the store, which a resume asks against */
    int64_t data_version;                   /* SQLite's, as its admission read it, then each commit (state_commit) */

    /* The enabled_profiles rows (see the invariant above) */
    profiles_t profiles;                    /* The table as this handle last read it */

    /* The prepared statements (see the cache above) */
    sqlite3_stmt *statements[STATEMENT_COUNT]; /* Indexed by statement_t */
};

/**
 * Get database file path
 *
 * The store's database beside its objects, in the directory libgit2 names. The
 * handle's own string, freed by state_free: no arena is in reach of a handle.
 * libgit2 spells every directory it keeps with its separator, but its header
 * promises no such thing, so one is written where the spelling lacks it.
 *
 * @param repo Repository (must not be NULL)
 * @param out Output path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t get_db_path(git_repository *repo, char **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    const char *git_dir = git_repository_path(repo);
    if (!git_dir) {
        return error_create(ERR_GIT, "Failed to get repository path");
    }

    *out = heap_str_format(
        "%s%s" STATE_DB_NAME, git_dir, str_ends_with(git_dir, "/") ? "" : "/"
    );
    return NULL;
}

/**
 * A record's node as the text the kind column holds
 *
 * The one boundary where a kind becomes a column, as state_kind_from_text is
 * where the column becomes a kind again. The three nodes a record describes,
 * each a literal, so SQLITE_STATIC holds at the bind. The rest name no node a
 * record keeps — an absence, a look not taken, a device — and have no text: a
 * record built without its kind binds NULL, which the column's NOT NULL refuses
 * at the step, so the store refuses it rather than write it as a file. Total
 * over fs_occupant_t, so a new occupant is a build error here.
 */
static const char *state_kind_to_text(fs_occupant_t kind) {
    switch (kind) {
        case FS_OCCUPANT_REGULAR:   return "file";
        case FS_OCCUPANT_SYMLINK:   return "symlink";
        case FS_OCCUPANT_DIRECTORY: return "directory";
        case FS_OCCUPANT_UNKNOWN:
        case FS_OCCUPANT_NONE:
        case FS_OCCUPANT_OTHER:     return NULL;
    }

    /* Unreachable once every enum value is handled */
    return NULL;
}

/**
 * The node a kind column's text names — state_kind_to_text read back
 *
 * The column's CHECK admits the three texts and nothing else, so 'file' is the
 * one left when the other two are not.
 */
static fs_occupant_t state_kind_from_text(const char *text) {
    if (strcmp(text, "symlink") == 0) return FS_OCCUPANT_SYMLINK;
    if (strcmp(text, "directory") == 0) return FS_OCCUPANT_DIRECTORY;
    return FS_OCCUPANT_REGULAR;
}

/**
 * The spelling every path the store keeps is held to: absolute and folded, "/"
 * included — the rule base/string.h str_path_folded holds in C, which the binders
 * validate a target by (infra/mount.h mount_validate_target) and mount_resolve
 * spells every key in — and whole: no NUL, so the string C reads is the one SQLite
 * stores, and every clause judges all of it. Two constraints compose it,
 * target_spelling and key_spelling, and tests/test-state.c drives one list of
 * shapes through both.
 */
#define FOLDED_SPELLING(column) \
    "(instr(" column ", char(0)) = 0 AND (" column " = '/' OR (" \
    column " GLOB '/?*' AND " column " NOT GLOB '*/[/]*' AND " column " NOT GLOB '*/' AND " \
    column " NOT GLOB '*/.' AND " column " NOT GLOB '*/.[/]*' AND " \
    column " NOT GLOB '*/..' AND " column " NOT GLOB '*/..[/]*')))"

/**
 * The spelling every storage name the store keeps is held to: a name in the grammar
 * — a label's word alone, or the word, its separator and a tail whose every
 * component is a name, never empty, "." or "..", with no separator trailing —
 * the rule infra/label.h label_validate_storage holds in C where a tree, a sheet
 * or an argument becomes a name, and whole. A record's name is read back by readers
 * that assert it stands under a label (label_of, label_tail: an orphan's absent
 * claim, cleanup's exclude), so one standing under none would abort the load
 * that met it. The words are label_words', spelled once more in the store's
 * language; storage_spelling composes it, and tests/test-state.c drives label_words
 * and one list of shapes through it and through the grammar's own check.
 */
#define STORAGE_SPELLING(column) \
    "(instr(" column ", char(0)) = 0 AND (" column " = 'home' OR " column " = 'root' OR " \
    column " = 'custom' OR ((" column " GLOB 'home/?*' OR " column " GLOB 'root/?*' OR " \
    column " GLOB 'custom/?*') AND " column " NOT GLOB '*/[/]*' AND " column " NOT GLOB '*/' AND " \
    column " NOT GLOB '*/.' AND " column " NOT GLOB '*/.[/]*' AND " \
    column " NOT GLOB '*/..' AND " column " NOT GLOB '*/..[/]*')))"

/**
 * The spelling every profile's name the store keeps is held to: never empty,
 * and whole. The rest of a branch name's rule is Git's (sys/gitops.h
 * gitops_branch_refname), asked of every name the store keeps where it meets
 * Git — the view's build, an orphan's probe — and refused there by the name.
 * The store keeps out the two spellings no reader meets as Git's refusal: a NUL,
 * which C reads past, so two names UNIQUE holds apart would be one to the row
 * cache; and the empty name, which every screen prints as no one. profile_spelling
 * composes it, on the enabled set's name and on the record's profile.
 */
#define PROFILE_SPELLING(column) \
    "(" column " != '' AND instr(" column ", char(0)) = 0)"

/**
 * Write the schema into a new database, whole
 *
 * The database is state_create's private file, which no other process can open
 * until it is published, so nothing else has written into it: every object is
 * created plainly, and one already there is a defect to report, not a race to
 * absorb. One transaction, one commit — the header's two fields among what it
 * commits — and a failure leaves the transaction open, and state_create discards
 * the file whole.
 *
 * A CHECK runs at every write of its row, so a set of words is spelled with `=`
 * and never `IN (…)`: SQLite compiles a constant list in a CHECK into a table
 * it builds anew at every evaluation, where a statement's own list is built once.
 * Measured at 0.152.3: 60,000 record writes in one transaction took 355 ms with
 * the kind a list and 196 ms with it three comparisons. And a CHECK a macro
 * composes is named, so the refusal a hand meets names its rule ("CHECK constraint
 * failed: key_spelling"), where one whose expression is its own sentence — the
 * record's kind, its mode — is not.
 *
 * - the header: dotta's id and the schema's number (STATE_APPLICATION_ID,
 *   STATE_SCHEMA_VERSION)
 * - enabled_profiles: User's profile management (position, name, target)
 * - path_records: The record dotta keeps of every managed path
 *
 * @param db Connection to the private file (must not be NULL)
 * @return Error or NULL on success
 */
static error_t state_initialize(sqlite3 *db) {
    CHECK_NULL(db);

    const char *schema_sql =
        "BEGIN;"

        /* The header: whose file this is, and the schema it holds */
        "PRAGMA application_id = " STATE_APPLICATION_ID ";"
        "PRAGMA user_version = " STATE_SCHEMA_VERSION ";"

        /* Enabled profiles table (authority: profile commands).
         *
         * Held by the schema:
         *   - a name is never empty, and whole (profile_spelling: PROFILE_SPELLING
         *     above): UNIQUE holds apart exactly the names the row cache reads
         *     apart, and no row's name prints as no one
         *   - a target is NULL — bound nowhere — or a spelling FOLDED_SPELLING
         *     admits: the rule the binders validate before they write
         *     (infra/mount.h mount_validate_target) and the mount table takes
         *     as its precondition (mount_table_build), spelled once more in the
         *     store's own language so a hand edit is refused where it is made:
         *     no reader meets a spelling no binder wrote, and the row cache is
         *     the table with no rule of its own. */
        "CREATE TABLE enabled_profiles ("
        "    position INTEGER PRIMARY KEY,"
        "    name TEXT NOT NULL UNIQUE CONSTRAINT profile_spelling CHECK "
        "        " PROFILE_SPELLING("name") ","
        "    target TEXT CONSTRAINT target_spelling CHECK ("
        "        target IS NULL OR " FOLDED_SPELLING("target") ")"
        ") STRICT;"

        /* The record: what dotta last reconciled each managed path against, and
         * what it confirmed there. A row exists iff dotta has observed the path
         * on disk while it was active, and its existence is the whole of that
         * fact: no column restates it. One path, one node, one record — the PRIMARY
         * KEY, and the node's kind a column of it. No foreign key in either
         * direction: nothing is a parent, nothing cascades.
         *
         * The one deferred intent is the record's own column (ordered_at): remove
         * --delete-files ordered the deployed copy at this path pruned at the
         * next apply, at that moment, and 0 is no order. It lives only while
         * its path is out of the view: born after the fallback short-circuit
         * (the post-commit view lacks the path), ended by every write of the
         * record whole — the flush's when the path re-enters, an ownership event's
         * — and gone with the row.
         *
         * Held by the schema:
         *   - the node is a regular file, a link or a directory
         *     (state_kind_to_text's three texts): the executable bit is no kind,
         *     and no record describes an absence, a look not taken or a device
         *   - a link claims no mode and every other node does: (kind = 'symlink')
         *     = (mode IS NULL), an expression that is never NULL — a CHECK that
         *     evaluates to NULL passes — and the one spelling of a link's
         *     don't-care, so a claim read back is the claim a writer bound
         *   - a mode is permission bits alone, 0000–0777 (511): the claim sheet's
         *     bound (core/metadata.h), which every compare meets as st_mode &
         *     0777, so a mode beyond it — a sticky or setuid bit, MODE_UNCLAIMED
         *     leaking out of the sheet — would read as moved for ever. A link's
         *     NULL passes it
         *   - a directory has no content confirmation (blob_oid IS NULL)
         *   - ownership implies confirmation for a file (deployed_at > 0 ⇒ blob_oid
         *     set); a row with a blob and deployed_at = 0 is a confirmation,
         *     not a deployment
         *   - a stamp is a moment or 0, never negative: the readers of one ask
         *     it both ways — the orphan's ownership gate deployed_at == 0
         *     (core/workspace.c workspace_analyze_orphans), the disable's receipt
         *     deployed_at > 0 (core/manifest.c manifest_diff) — which agree on
         *     these values alone, where a negative stamp would be pruned as dotta's
         *     by the one and said to be left alone by the other
         *   - a stored blob is a real OID (20 bytes, never zeroblob)
         *   - the key is one a writer spells and C reads whole (key_spelling:
         *     FOLDED_SPELLING above — absolute and folded, the shape mount_resolve
         *     spells every key in, and free of NUL). C reads a string to its
         *     first NUL, so a key holding one would be another key's string to
         *     C: two rows, one key. With BINARY's memcmp over UTF-8, this is
         *     what makes a read in key order strcmp order (core/state.h)
         *   - the binding is one a writer spells, and C reads whole: the storage
         *     name one in the grammar (storage_spelling: STORAGE_SPELLING above
         *     — the precondition label_of and label_tail assert of every name
         *     they are handed), the profile never empty (profile_spelling, the
         *     enabled set's name's)
         *   - an owner or a group is a name, whole and never empty, so the name
         *     C reads is the name the claim stored and one a resolver can ask
         *     for; NULL is no claim, its one spelling — the claim sheet's parser
         *     refuses the empty name too (core/metadata.c metadata_from_json),
         *     so no writer is handed one
         *   - the table is stored sorted by its key (WITHOUT ROWID): a read in
         *     key order walks the table, with no sort step and no index between */
        "CREATE TABLE path_records ("
        "    filesystem_path TEXT PRIMARY KEY CONSTRAINT key_spelling CHECK "
        "        " FOLDED_SPELLING("filesystem_path") ","
        "    storage_path TEXT NOT NULL CONSTRAINT storage_spelling CHECK "
        "        " STORAGE_SPELLING("storage_path") ","
        "    profile TEXT NOT NULL CONSTRAINT profile_spelling CHECK "
        "        " PROFILE_SPELLING("profile") ","
        "    kind TEXT NOT NULL CHECK(kind = 'file' OR kind = 'symlink' OR kind = 'directory'),"
        "    mode INTEGER CHECK(mode BETWEEN 0 AND 511),"
        "    owner TEXT CHECK(instr(owner, char(0)) = 0 AND owner <> ''),"
        "    \"group\" TEXT CHECK(instr(\"group\", char(0)) = 0 AND \"group\" <> ''),"
        "    "
        "    blob_oid BLOB CHECK(blob_oid IS NULL"
        "        OR (length(blob_oid) = 20 AND blob_oid != zeroblob(20))),"
        "    stat_mtime INTEGER NOT NULL DEFAULT 0,"
        "    stat_size  INTEGER NOT NULL DEFAULT 0,"
        "    stat_ino   INTEGER NOT NULL DEFAULT 0,"
        "    "
        "    deployed_at INTEGER NOT NULL DEFAULT 0 CHECK(deployed_at >= 0),"
        "    ordered_at  INTEGER NOT NULL DEFAULT 0 CHECK(ordered_at >= 0),"
        "    "
        "    CHECK ((kind = 'symlink') = (mode IS NULL)),"
        "    CHECK (kind != 'directory' OR blob_oid IS NULL),"
        "    CHECK (deployed_at = 0 OR kind = 'directory' OR blob_oid IS NOT NULL)"
        ") STRICT, WITHOUT ROWID;"

        "COMMIT;";

    /* Execute schema SQL */
    if (sqlite3_exec(db, schema_sql, NULL, NULL, NULL) != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to initialize schema: %s", sqlite3_errmsg(db)
        );
    }

    return NULL;
}

/**
 * Verify that the database's header marks it dotta's store, at this schema
 *
 * The admission's first question about the file. A header that does not mark
 * the file dotta's is no store this code can read — an empty database, another
 * program's, a store whose header lacks the mark (made before it, or restored
 * from a text dump) — and one marking another schema was written by another dotta;
 * both are refused. Both fields are integers every database carries, 0 where
 * nothing set them, so a header is never missing one.
 *
 * @param db Database connection (must not be NULL)
 * @return Error or NULL on success
 */
static error_t state_verify(sqlite3 *db) {
    CHECK_NULL(db);

    /* Whether the header marks the file dotta's, whether it marks this schema,
     * and which schema it marks: SQLite compares the header's integers against
     * the literals state_initialize wrote it with. */
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        db,
        "SELECT application_id = " STATE_APPLICATION_ID ", "
        "user_version = " STATE_SCHEMA_VERSION ", user_version "
        "FROM pragma_application_id, pragma_user_version;",
        -1, &stmt, NULL
    );
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);

    /* A read that could not happen keeps SQLite's own cause — a file that is
     * not a database is refused here, by it — and is no verdict about the
     * header. */
    error_t err = NULL;
    if (rc != SQLITE_ROW) {
        err = error_create(
            ERR_STATE_INVALID, "Failed to read the database's header: %s", sqlite3_errmsg(db)
        );
    } else if (!sqlite3_column_int(stmt, 0)) {
        err = error_create(ERR_STATE_INVALID, "The database is not marked as dotta's");
    } else if (!sqlite3_column_int(stmt, 1)) {
        err = error_create(
            ERR_STATE_INVALID, "Unsupported schema version: %d (this build reads %s)",
            sqlite3_column_int(stmt, 2), STATE_SCHEMA_VERSION
        );
    }

    sqlite3_finalize(stmt);
    return err;
}

/**
 * Configure the connection
 *
 * The connection's own settings, sent on every admission once the header is read;
 * none of them is the file's:
 * - synchronous=NORMAL: Fast but safe
 * - cache_size: up to 10000 pages (about 40 MB at 4096-byte pages), grown only
 *   as pages are read
 * - persistent WAL off: the -wal and -shm files go with the last connection
 *
 * Not the lock wait: that is the admission's, set before its first statement.
 * Not the journal mode: that is the file's own, written into it where the file
 * is made (state_create), and a connection that never sends the pragma reads
 * the mode the file carries. Not the temp store: no statement the store runs
 * builds a temporary structure — every read walks a key and every write searches
 * one — so there is nothing for it to place.
 *
 * foreign_keys is deliberately absent: the schema declares no FK constraints
 * (path_records.profile outlives enabled_profiles rows by design), so nothing
 * cascades — records leave only through explicit retires.
 *
 * @param db Database connection (must not be NULL)
 * @return Error or NULL on success
 */
static error_t state_configure(sqlite3 *db) {
    CHECK_NULL(db);

    /* 1. Fast synchronization (safe on crash, fast on commit) */
    if (sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL) != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to set synchronous mode: %s", sqlite3_errmsg(db)
        );
    }

    /* 2. A larger page cache: 10000 pages, where the default is 2000 KiB (about
     * 500 pages, a store of about 13,000 records). The cache grows only with
     * the pages a run reads, so a store inside the default pays nothing for the
     * limit; past it, a transaction that writes thousands of records re-reads
     * and spills fewer pages. Measured at 0.151.26: 12,000 keyed writes in one
     * transaction over 60,000 records took 102 ms under the default and 68 ms
     * under this. */
    if (sqlite3_exec(db, "PRAGMA cache_size=10000;", NULL, NULL, NULL) != SQLITE_OK) {
        return error_create(ERR_STATE_INVALID, "Failed to set cache size: %s", sqlite3_errmsg(db));
    }

    /* 3. Disable persistent WAL */
    int persist_wal = 0;
    sqlite3_file_control(db, NULL, SQLITE_FCNTL_PERSIST_WAL, &persist_wal);

    return NULL;
}

/**
 * The SQL of a prepared statement
 *
 * Total over statement_t, so a statement declared without its SQL is a build
 * error here, never a prepare refused at the open.
 */
static const char *state_sql(statement_t statement) {
    switch (statement) {
        /* Enable: an UPSERT. Position is `COALESCE(MAX(position) + 1, 0)`: on
         * an empty table MAX returns NULL and the COALESCE drops to 0, matching
         * the 0-based position assignment used by state_reorder_profiles. On
         * conflict (the profile already enabled) the position is kept, and the
         * target moves only when one is given — `COALESCE(?2, target)` keeps
         * the row's own for a NULL, so no enable can unbind, and the one way a
         * row loses its target is the disable's DELETE.
         *
         * Bind order (numbered placeholders): ?1 name  ?2 target — NULL keeps the
         * row's */
        case STATEMENT_ENABLE_PROFILE:
            return
                "INSERT INTO enabled_profiles (name, target, position) "
                "VALUES (?1, ?2, "
                "  (SELECT COALESCE(MAX(position) + 1, 0) FROM enabled_profiles)) "
                "ON CONFLICT(name) DO UPDATE SET "
                "  target = COALESCE(?2, target);";

        /* Disable: the row goes, its target with it. A name with no row matches
         * nothing — no error. */
        case STATEMENT_DISABLE_PROFILE:
            return "DELETE FROM enabled_profiles WHERE name = ?1;";

        /* Insert profile (used in state_reorder_profiles) */
        case STATEMENT_INSERT_PROFILE:
            return
                "INSERT INTO enabled_profiles (position, name, target) "
                "VALUES (?, ?, ?);";

        /* Write: the record, whole. Every column is the record's, bound as the
         * caller built it, and OR REPLACE writes them over whatever stood at
         * the path: a column this statement does not name takes its default, so
         * nothing of the record before the write survives it — the order least
         * of all, which no record written whole carries (state_write). A column
         * that must survive a write cannot live beside these.
         *
         * Bind order (numbered placeholders):
         *   ?1 filesystem_path  ?2 storage_path  ?3 profile  ?4 kind
         *   ?5 mode — NULL for a link  ?6 owner  ?7 group — NULL where absent
         *   ?8 blob_oid — NULL where zero
         *   ?9 stat_mtime  ?10 stat_size  ?11 stat_ino
         *   ?12 deployed_at */
        case STATEMENT_WRITE:
            return
                "INSERT OR REPLACE INTO path_records "
                "(filesystem_path, storage_path, profile, kind, mode, owner, \"group\", "
                " blob_oid, stat_mtime, stat_size, stat_ino, deployed_at) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);";

        /* Retire: the record goes, and the order it carries with it. Nothing
         * cascades — there is no parent. */
        case STATEMENT_RETIRE:
            return "DELETE FROM path_records WHERE filesystem_path = ?1;";

        /* Order prune: the one deferred intent (remove --delete-files), stamped
         * on the record. A missing record matches nothing — the documented no-op
         * — and a repeated order re-stamps: the order standing is the latest. */
        case STATEMENT_ORDER_PRUNE:
            return "UPDATE path_records SET ordered_at = ?2 WHERE filesystem_path = ?1;";
    }

    CHECK_ARG(false, "a statement no enumerator names");
}

/**
 * Prepare every statement on the handle's connection
 *
 * Called once per connection, by state_admit. Each statement lives as long as
 * the connection, so it is prepared persistent: SQLite's hint for a statement
 * kept and run many times. A prepare SQLite refuses keeps SQLite's own cause —
 * a table this schema's statements read, missing, is named by it — and returns
 * at once: state_admit finalizes what was prepared, so a handle never carries
 * half its statements.
 *
 * @param state State (must not be NULL, its db open)
 * @return Error or NULL on success
 */
static error_t state_prepare(state_t *state) {
    for (statement_t statement = 0; statement < STATEMENT_COUNT; statement++) {
        int rc = sqlite3_prepare_v3(
            state->db, state_sql(statement), -1, SQLITE_PREPARE_PERSISTENT,
            &state->statements[statement], NULL
        );
        if (rc != SQLITE_OK) {
            return error_create(
                ERR_STATE_INVALID, "Failed to prepare the store's statements: %s",
                sqlite3_errmsg(state->db)
            );
        }
    }

    return NULL;
}

/**
 * Finalize every prepared statement
 *
 * Called by state_free before the connection closes, and by state_admit on a
 * refusal: a statement not yet prepared is NULL, which sqlite3_finalize takes
 * as a harmless no-op, so the walk is safe at any point. The walk is the array,
 * whole, so the close that follows finds none of the handle's statements left
 * open — an open one would keep the connection from closing (SQLITE_BUSY).
 *
 * @param state State (must not be NULL)
 */
static void state_finalize(state_t *state) {
    for (statement_t statement = 0; statement < STATEMENT_COUNT; statement++) {
        sqlite3_finalize(state->statements[statement]);
        state->statements[statement] = NULL;
    }
}

/**
 * A prepared statement, ready for its run
 *
 * Every verb takes its statement here. A run leaves its statement halted, and a
 * halted statement takes no binding (SQLITE_MISUSE), so it is reset; its
 * placeholders are cleared, so one this run leaves unbound is NULL, never the
 * last run's value.
 *
 * @param state State (must not be NULL, its db open: every statement prepared)
 * @param statement The statement to run
 * @return The statement, reset and unbound
 */
static sqlite3_stmt *state_statement(state_t *state, statement_t statement) {
    sqlite3_stmt *stmt = state->statements[statement];
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    return stmt;
}

/**
 * Release one read of the rows
 *
 * Every row of the read's allocation, whether or not the read finished building
 * it: the allocation is zeroed, so a row the read never reached frees two NULLs.
 * Leaves the read empty, as a read of no rows is.
 */
static void state_deinit_profiles(profiles_t *profiles) {
    for (size_t i = 0; i < profiles->count; i++) {
        free(profiles->entries[i].name);
        free(profiles->entries[i].target);
    }
    free(profiles->entries);
    *profiles = (profiles_t){ 0 };
}

/**
 * Read the enabled_profiles rows into the cache
 *
 * One SELECT over enabled_profiles, every row (name, target) copied out, ordered
 * by position to match the user's precedence order. Called where the table becomes
 * this handle's (the first is the admission, state_admit) and after each of its
 * own writes, and answering every per-profile question thereafter as a linear
 * search of the cache — no per-question SQL. A handle with no database has nothing
 * to read: its rows are the empty cache its load left, which is the answer for
 * a store never written (state_load).
 *
 * The read is allocated at the statement's own count: the table's size rides in
 * the last column, counted by the statement that reads the rows it sizes, so
 * the two are one snapshot and nothing another connection commits while this
 * one steps can make them disagree.
 *
 * Read whole before it replaces anything: a read that fails releases its own,
 * leaves the cache as it was, and says so to its caller. The rows it replaces
 * are released, unless the open transaction began with them — those are its
 * rollback's (state_rollback).
 */
static error_t state_read_profiles(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    /* Every row in position order, and the table's size beside each: the first
     * row sizes the allocation. */
    const char *sql =
        "SELECT name, target, (SELECT count(*) FROM enabled_profiles) "
        "FROM enabled_profiles ORDER BY position ASC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to prepare profile query: %s", sqlite3_errmsg(state->db)
        );
    }

    rc = sqlite3_step(stmt);
    profiles_t rows = {
        .count = rc == SQLITE_ROW ? (size_t) sqlite3_column_int64(stmt, 2) : 0,
    };
    if (rows.count > 0) {
        rows.entries = heap_calloc(rows.count, sizeof(*rows.entries));
    }

    error_t err = NULL;
    size_t i = 0;
    while (rc == SQLITE_ROW && i < rows.count) {
        /* The name is NOT NULL, so a NULL is its conversion failing to allocate.
         * The target is asked its type before it is converted, the one moment
         * SQLite answers it, so a NULL the conversion returns for a value is
         * that failure too — never a row bound nowhere. */
        const char *name = (const char *) sqlite3_column_text(stmt, 0);
        int target_type = sqlite3_column_type(stmt, 1);
        const char *target = (const char *) sqlite3_column_text(stmt, 1);

        /* Each copied as it comes, a NULL as NULL, so the arm reads a failed
         * conversion off its copy; the row it stops is left half-built for the
         * release below, which walks the whole allocation. */
        state_profile_entry_t *row = &rows.entries[i];
        row->name = heap_strdup(name);
        row->target = heap_strdup(target);
        if (!row->name || (target_type != SQLITE_NULL && !row->target)) {
            err = error_create(ERR_MEMORY, "Failed to read an enabled profile row");
            break;
        }

        i++;
        rc = sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);

    if (!err && rc != SQLITE_DONE) {
        err = error_create(
            ERR_STATE_INVALID, "Failed to query profiles: %s", sqlite3_errmsg(state->db)
        );
    }

    if (err) {
        state_deinit_profiles(&rows);
        return err;
    }

    /* The rows replaced are released, unless the open transaction began with
     * them: those its rollback puts back. */
    if (state->profiles.entries != state->begun.entries) {
        state_deinit_profiles(&state->profiles);
    }
    state->profiles = (profiles_t){ .entries = rows.entries, .count = i };

    return NULL;
}

/**
 * Linear lookup into the row cache
 *
 * Row count is bounded by the user's enabled-profile list (typically < 10), so
 * the linear scan is faster than a hash lookup and fits comfortably in L1.
 */
static const state_profile_entry_t *state_find_profile(
    const state_t *state,
    const char *profile
) {
    for (size_t i = 0; i < state->profiles.count; i++) {
        if (strcmp(state->profiles.entries[i].name, profile) == 0) {
            return &state->profiles.entries[i];
        }
    }
    return NULL;
}

/**
 * The enabled_profiles rows, in position order
 */
state_profiles_t state_profiles(const state_t *state) {
    if (!state) return (state_profiles_t){ 0 };

    return (state_profiles_t){
        .entries = state->profiles.entries,
        .count = state->profiles.count,
    };
}

/**
 * A single profile's deployment target
 */
const char *state_target(
    const state_t *state,
    const char *profile
) {
    if (!state || !profile) return NULL;

    const state_profile_entry_t *entry = state_find_profile(state, profile);
    return entry ? entry->target : NULL;
}

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
bool state_enabled(const state_t *state, const char *profile) {
    if (!state || !profile) return false;

    return state_find_profile(state, profile) != NULL;
}

/**
 * Enable profile with optional deployment target
 */
error_t state_enable_profile(
    state_t *state,
    const char *profile,
    const char *target
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(state->db);

    sqlite3_stmt *stmt = state_statement(state, STATEMENT_ENABLE_PROFILE);

    /* 1. the name, the column's to admit or refuse (profile_spelling), an empty
     * one among them  2. the target as given — a NULL pointer binds NULL, which
     * keeps the row's, and a string is the column's to admit or refuse
     * (target_spelling), an empty one among them. A bind SQLite refuses ends
     * the enable before its step, which would run with that parameter NULL: a
     * new row unbound. */
    int rc = sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 2, target, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to enable profile: %s", sqlite3_errmsg(state->db)
        );
    }

    return state_read_profiles(state);
}

/**
 * Disable profile
 */
error_t state_disable_profile(
    state_t *state,
    const char *profile
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(state->db);

    sqlite3_stmt *stmt = state_statement(state, STATEMENT_DISABLE_PROFILE);

    /* 1. the name. A bind SQLite refuses ends the disable before its step, which
     * would match no row and answer as a name never enabled. */
    int rc = sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to disable profile: %s", sqlite3_errmsg(state->db)
        );
    }

    /* Not an error if profile wasn't enabled (DELETE with 0 rows affected is OK) */
    return state_read_profiles(state);
}

/**
 * Reorder enabled profiles to match a new precedence order
 *
 * `profiles` is the enabled set, permuted: every name must be a row, and the
 * list must be as long as the table — the rewrite below re-inserts exactly the
 * names given, so a shorter list would delete the rows it left out. Additions
 * and removals belong to the membership primitives (state_enable_profile /
 * state_disable_profile). Both refusals leave the table untouched.
 *
 * Per-row state (the target) is read from the row cache and preserved across
 * the DELETE + re-INSERT rewrite. Only the position changes: the name and the
 * target are re-inserted as the cache holds them.
 *
 * Hot path - must be fast even with 10,000 deployed files. Only modifies
 * enabled_profiles (the record untouched).
 *
 * @param state State (must not be NULL)
 * @param profiles Profile names in desired order (must not be NULL)
 * @return Error or NULL on success
 */
error_t state_reorder_profiles(
    state_t *state,
    const string_array_t *profiles
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(state->db);

    /* Transaction is a precondition — the DELETE below would auto-commit on an
     * unguarded connection and leave no recovery path for errors in the INSERT
     * loop. The caller must hold BEGIN IMMEDIATE (state_open or state_begin). */
    if (!state->in_transaction) {
        return error_create(
            ERR_STATE_INVALID, "state_reorder_profiles requires an active transaction"
        );
    }

    /* Precondition: every name in `profiles` must already be enabled. Reorder
     * permutes membership; it never adds or removes rows. A name missing from
     * the cache means the caller wants to add a profile — they should call
     * state_enable_profile first. */
    for (size_t i = 0; i < profiles->count; i++) {
        if (!state_find_profile(state, profiles->entries[i])) {
            return error_create(
                ERR_INVALID_ARG,
                "state_reorder_profiles: profile '%s' is not currently enabled "
                "(use state_enable_profile to add a profile)",
                profiles->entries[i]
            );
        }
    }

    /* ...and every row must be named: the rewrite re-inserts exactly the names
     * given, so a shorter list would delete the rows it left out. Every name a
     * row, the counts equal, and UNIQUE(name) refusing a name twice at the
     * re-insert make the list the enabled set, permuted. */
    if (profiles->count != state->profiles.count) {
        return error_create(
            ERR_INVALID_ARG,
            "state_reorder_profiles: %zu names for %zu enabled profiles "
            "(reorder permutes the enabled set; use state_disable_profile to "
            "remove a profile)", profiles->count, state->profiles.count
        );
    }

    /* Delete all existing rows under the caller's transaction. On failure, SQL
     * is unchanged and the cache still matches — safe to return. */
    if (sqlite3_exec(state->db, "DELETE FROM enabled_profiles;", NULL, NULL, NULL) != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to clear profiles: %s", sqlite3_errmsg(state->db)
        );
    }

    /* Insert rows. SQLITE_TRANSIENT on every binding means SQLite copies the
     * value at bind time, so the cache pointers we pass below do not need to
     * outlive sqlite3_step — future refactors that mutate the cache mid-loop
     * stay safe. Cost is <100 bytes of memcpy per row; the table tops out around
     * ten rows in practice. */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *name = profiles->entries[i];
        const state_profile_entry_t *preserved = state_find_profile(state, name);

        /* The precondition loop above guarantees preserved is non-NULL. A profile
         * with no deployment target (home/root) legitimately has preserved->target
         * == NULL, which binds NULL. */

        sqlite3_stmt *stmt = state_statement(state, STATEMENT_INSERT_PROFILE);

        /* Bind parameters: position, name, target. SQLITE_TRANSIENT: SQLite copies
         * immediately; source lifetimes are ours. A bind SQLite refuses ends
         * the reorder before its step, which would re-insert the row with that
         * parameter NULL: a target lost. */
        int rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64) i);
        if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(stmt, 3, preserved->target, -1, SQLITE_TRANSIENT);
        }
        if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            return error_create(
                ERR_STATE_INVALID, "Failed to insert profile: %s", sqlite3_errmsg(state->db)
            );
        }
    }

    /* SQL now reflects the new order; re-read so the cache does too. */
    return state_read_profiles(state);
}

/**
 * The store's data_version, as this connection reads it
 *
 * SQLite's count of the commits other connections made, as this connection has
 * seen them: its own commits leave it where it was, so two reads differ iff another
 * connection committed between them. Read under the write lock, it names the
 * store the transaction stands on, since no other connection can commit while
 * the lock is held. Readers: state_admit, before the handle's first read of the
 * rows; state_commit, before its COMMIT; and state_resume, once the lock is taken
 * back.
 */
static error_t state_data_version(state_t *state, int64_t *out) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, "PRAGMA data_version;", -1, &stmt, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);

    error_t err = NULL;
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(stmt, 0);
    } else {
        err = error_create(
            ERR_STATE_INVALID, "Failed to read the database's version: %s",
            sqlite3_errmsg(state->db)
        );
    }

    sqlite3_finalize(stmt);
    return err;
}

/**
 * Admit the database standing at the handle's path as the store's, or refuse it
 *
 * A load admits through here wherever something stands at the path, and the
 * promotion does once state_create has made sure something does. What stands
 * there is dotta's store at this schema and is opened — its header read, the
 * connection configured, the statements prepared, where the store stands kept
 * for a resume (state_resume), the rows read (the row cache's first boundary,
 * so every reader of it downstream is a plain read) — or it is refused here,
 * with the file named: one this identity cannot open, a directory, a link to
 * nowhere (SQLite's CANTOPEN, with the OS's reason beside it), a file that is
 * not a database, a database not marked as dotta's, another schema's, or one
 * missing the tables this schema's statements read. An empty database is among
 * them and no special case: dotta never leaves one (state_create publishes whole),
 * and reading one as a store never written would read a truncated store as empty.
 *
 * READWRITE and never CREATE: the connection is the one state_begin takes its
 * lock on, and SQLite's CREATE follows a link to nowhere and makes its target.
 * Nothing here writes to the file. On a refusal the handle holds no connection
 * and no prepared statement, as it did before the call.
 *
 * @param state Handle whose db_path names the file (must not be NULL)
 * @return Error or NULL on success
 */
static error_t state_admit(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db_path);

    error_t err = NULL;
    int rc = sqlite3_open_v2(state->db_path, &state->db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        /* CANTOPEN says only that the open failed; the OS's errno says why, where
         * the failure had one (sqlite3_system_errno is 0 otherwise). */
        int os_errno = sqlite3_system_errno(state->db);
        if (os_errno) {
            err = error_create(
                ERR_STATE_INVALID, "%s: %s", sqlite3_errmsg(state->db),
                strerror(os_errno)
            );
        } else {
            err = error_create(
                ERR_STATE_INVALID, "%s", sqlite3_errmsg(state->db)
            );
        }
        goto fail;
    }

    /* The lock wait, before the first statement: each one reads the file, and a
     * read can meet a lock like any other. Up to 3s, for a lock another process
     * holds for an instant. */
    sqlite3_busy_timeout(state->db, 3000);

    /* The header first — a database at all, marked dotta's, at this schema — so
     * a file the admission will not keep is refused by that question, before
     * anything is configured or prepared for it. */
    err = state_verify(state->db);
    if (err) goto fail;

    err = state_configure(state->db);
    if (err) goto fail;

    err = state_prepare(state);
    if (err) goto fail;

    /* Where the store stands as the handle first reads it, the store a resume
     * asks against until the handle's first commit. Before the rows: a commit
     * landing between the two reads is then one the resume refuses, where read
     * after them it would be one the resume admits over rows that predate it. */
    err = state_data_version(state, &state->data_version);
    if (err) goto fail;

    err = state_read_profiles(state);
    if (err) goto fail;

    return NULL;

fail:
    state_finalize(state);
    sqlite3_close(state->db);
    state->db = NULL;
    return error_wrap(
        err, "Cannot open the store's database at: %s", state->db_path
    );
}

/**
 * Bring the store's database into being where nothing stands
 *
 * Built where no other process can see it, and published whole. The schema is
 * written into a private file beside the path (mkstemp, so publishing it is one
 * link within one directory), and the file takes its journal mode there, before
 * anyone can open it. link(2) then publishes it only where nothing stands: the
 * one create-if-absent POSIX gives a file with content, and one that never follows
 * a link standing at the name. So the first moment anything stands at the path
 * it is a store at this version in WAL mode — no process meets one half-made,
 * and no creator writes into a file that is not its own.
 *
 * EEXIST is not a failure. Something stands at the path now — most often a store
 * another process published since this handle's load — and the caller admits it
 * like any other (state_admit): a store is never replaced, and what cannot be
 * admitted is refused there, by name. A filesystem with no hard links refuses
 * the publication, naming the file; a replacing rename would publish over a store
 * another process made.
 *
 * The raw calls are those of one of dotta's own artifacts (sys/filesystem.h):
 * the file is the invoker's by construction, created 0600 as the session cache
 * is, and a second try as root would leave a database only root can open. The
 * refusals are coded by subsystem (base/error.h).
 *
 * @param db_path Where the store's database stands (must not be NULL)
 * @return Error or NULL on success — something stands at the path either way
 */
static error_t state_create(const char *db_path) {
    CHECK_NULL(db_path);

    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.XXXXXX", db_path);
    if (n < 0 || (size_t) n >= sizeof(temp)) {
        return error_wrap(
            error_create(ERR_STATE_INVALID, "The path is too long"),
            "Cannot create the store's database at: %s", db_path
        );
    }

    /* A failed mkstemp made no file, and its template may now name one that is
     * not ours: nothing below runs, the unlink included. */
    int fd = mkstemp(temp);
    if (fd < 0) {
        return error_wrap(
            error_create(ERR_STATE_INVALID, "%s", strerror(errno)),
            "Cannot create the store's database at: %s", db_path
        );
    }
    close(fd);

    error_t err = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_open_v2(temp, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        err = error_create(
            ERR_STATE_INVALID, "Failed to open the new database: %s", sqlite3_errmsg(db)
        );
        goto done;
    }

    err = state_initialize(db);
    if (err) goto done;

    /* The file's mode is the pragma's answer, not its return code: SQLite answers
     * with the old mode where it cannot change it, and a store outside WAL would
     * hold its readers behind its writers. */
    rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL;", -1, &stmt, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        err = error_create(ERR_STATE_INVALID, "Failed to set WAL mode: %s", sqlite3_errmsg(db));
        goto done;
    }
    const char *mode = (const char *) sqlite3_column_text(stmt, 0);
    if (!mode || strcmp(mode, "wal") != 0) {
        err = error_create(
            ERR_STATE_INVALID, "The filesystem refused WAL mode (the journal is '%s')",
            mode ? mode : "unknown"
        );
        goto done;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    /* Closed before it is published: SQLite names a database's -wal and -shm
     * after the path it opened it by, and the store's are dotta.db's. */
    sqlite3_close(db);
    db = NULL;

    if (link(temp, db_path) != 0 && errno != EEXIST) {
        err = error_create(ERR_STATE_INVALID, "%s", strerror(errno));
    }

done:
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    unlink(temp);
    return error_wrap(err, "Cannot create the store's database at: %s", db_path);
}

/**
 * Load state from repository (read-only)
 *
 * The handle, whether or not a store was ever written: the path is kept for
 * state_begin, and the connection is the admission's to open (state_admit) wherever
 * something stands there. No transaction is started — safe for concurrent reads.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t state_load(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    *out = NULL;

    state_t *state = heap_calloc(1, sizeof(*state));

    error_t err = get_db_path(repo, &state->db_path);
    if (err) {
        state_free(state);
        return err;
    }

    /* Nothing at the path is a store never written, and it is the filesystem's
     * answer alone: a failure to look is never nothing (sys/filesystem.h), so
     * UNKNOWN is the admission's to open or refuse. The handle then holds no
     * connection and the cache calloc left empty — the answer for a store never
     * written, not a read skipped — and state_begin brings one into being at
     * the first write intent (the READ → scoped-write contract, runtime.h's
     * dotta_state_mode_t). */
    if (fs_lstat_occupant(state->db_path, NULL) != FS_OCCUPANT_NONE) {
        err = state_admit(state);
        if (err) {
            state_free(state);
            return err;
        }
    }

    *out = state;
    return NULL;
}

/**
 * Load state for update (with transaction)
 *
 * state_load, promoted by state_begin: WRITE is READ promoted, through the one
 * admission and the one creation, and the handle is published only once its lock
 * is held — the row cache read inside it, so the rows this handle answers from
 * are the transaction's own snapshot.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t state_open(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    *out = NULL;

    state_t *state = NULL;
    error_t err = state_load(repo, &state);
    if (err) return err;

    /* A promotion that fails disposes of the handle the one way a handle is
     * disposed of — state_free finalizes, checkpoints, closes and frees whatever
     * got built — and publishes nothing: close_run frees what *out names. */
    err = state_begin(state);
    if (err) {
        state_free(state);
        return err;
    }

    *out = state;
    return NULL;
}

/**
 * Save state to repository
 *
 * The commit, on any handle shape: a handle that holds a transaction commits it
 * through state_commit, the one COMMIT a handle runs, and one that holds none —
 * a state_load() handle never promoted, with a connection or over a store never
 * written — saves nothing.
 *
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t state_save(state_t *state) {
    CHECK_NULL(state);

    return state->in_transaction ? state_commit(state) : NULL;
}

/**
 * Begin an explicit transaction on a state handle
 *
 * Post-condition on success: state->db is open and write-locked (BEGIN IMMEDIATE
 * held). A handle whose load found nothing at the path is promoted first — the
 * store published (state_create) and admitted (state_admit) — which is what makes
 * state_open this call over a fresh load.
 */
error_t state_begin(state_t *state) {
    CHECK_NULL(state);

    if (state->in_transaction) {
        return error_create(ERR_STATE_INVALID, "Transaction already active");
    }

    /* The promotion. A handle whose load found nothing at the path holds no
     * connection (state_load), and the first write intent is what brings a store
     * into being: state_create publishes one where nothing stands, or finds that
     * something does — most often a store another process published since this
     * handle's load — and either way what stands there is admitted or refused. */
    if (!state->db) {
        error_t err = state_create(state->db_path);
        if (err) return err;

        err = state_admit(state);
        if (err) return err;
    }

    /* The lock. BUSY is another connection holding it past the busy timeout,
     * and the one failure the second line is true of: a directory that cannot
     * take the -wal file answers READONLY here, and an I/O error is its own. */
    int rc = sqlite3_exec(state->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc == SQLITE_BUSY) {
        return error_create(
            ERR_CONFLICT, "Failed to acquire write lock: %s; another process holds it",
            sqlite3_errmsg(state->db)
        );
    }
    if (rc != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to acquire write lock: %s", sqlite3_errmsg(state->db)
        );
    }

    /* Re-read inside the new lock: a handle open since before the lock was taken
     * holds rows another process may have committed since, and this transaction's
     * readers must see its own snapshot. A read that fails releases the lock
     * the caller never got, and is returned: the read replaced nothing, so the
     * handle keeps the rows it held. */
    error_t err = state_read_profiles(state);
    if (err) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        return err;
    }

    /* The transaction is the handle's once its rows are read, and these are the
     * rows it begins with: the table for as long as the lock is held, and what
     * its rollback puts back. */
    state->in_transaction = true;
    state->begun = state->profiles;

    return NULL;
}

/**
 * Commit a transaction started by state_begin()
 */
error_t state_commit(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    if (!state->in_transaction) {
        return error_create(ERR_STATE_INVALID, "No active transaction to commit");
    }

    /* Where this commit leaves the store, read while the lock still holds it
     * there: the handle's own COMMIT leaves the version as it is, and a read
     * after it would take in whatever another connection lands once the lock is
     * let go — the one commit the resume is there to see. */
    int64_t data_version = 0;
    error_t err = state_data_version(state, &data_version);
    if (err) return err;

    if (sqlite3_exec(state->db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to commit transaction: %s", sqlite3_errmsg(state->db)
        );
    }

    /* Kept once the COMMIT landed: a refused one left the store where the handle's
     * last commit did. */
    state->in_transaction = false;
    state->data_version = data_version;

    /* The transaction's rows are the table's now: the ones it began with are
     * released, where a write replaced them. */
    if (state->begun.entries != state->profiles.entries) {
        state_deinit_profiles(&state->begun);
    }
    state->begun = (profiles_t){ 0 };

    return NULL;
}

/**
 * Take the write lock back where this handle's last commit left the store
 */
error_t state_resume(state_t *state) {
    CHECK_NULL(state);

    error_t err = state_begin(state);
    if (err) return err;

    /* The question the lock was taken back to ask, under it: another connection's
     * commit since this handle's last one moved the version off the one that
     * commit kept. */
    int64_t data_version = 0;
    err = state_data_version(state, &data_version);
    if (!err && data_version != state->data_version) {
        err = error_create(
            ERR_CONFLICT, "Another process wrote to the database since this one last did"
        );
    }

    /* Refused — the store moved, or the question had no answer — the lock goes
     * back with the transaction it began */
    if (err) state_rollback(state);
    return err;
}

/**
 * Roll back a transaction started by state_begin()
 */
void state_rollback(state_t *state) {
    if (!state || !state->db || !state->in_transaction) return;

    /* The handle's account decides it, not SQLite's: after a transaction SQLite
     * ended itself this ROLLBACK finds none, and what follows still runs. */
    sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
    state->in_transaction = false;

    /* The rows go back with the table: a write inside the transaction replaced
     * the ones it began with, and those are the table again (the invariant
     * above). */
    if (state->profiles.entries != state->begun.entries) {
        state_deinit_profiles(&state->profiles);
    }
    state->profiles = state->begun;
    state->begun = (profiles_t){ 0 };
}

/**
 * Check if state has an active transaction
 */
bool state_locked(const state_t *state) {
    return state && state->in_transaction;
}

/**
 * Free state structure
 *
 * Automatically rolls back transaction if not committed. Closes database and
 * frees all memory.
 *
 * @param state State to free (can be NULL)
 */
void state_free(state_t *state) {
    if (!state) return;

    /* A transaction still open (error path cleanup) is rolled back as any other
     * is, its rows going back with it, so the one read left is the handle's */
    state_rollback(state);

    /* Finalize prepared statements */
    state_finalize(state);

    /* Checkpoint WAL before close (non-blocking, best effort) */
    if (state->db) {
        /* PASSIVE checkpoint: merge WAL into main db */
        sqlite3_wal_checkpoint_v2(
            state->db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL
        );
        sqlite3_close(state->db);
        state->db = NULL;
    }

    free(state->db_path);
    state_deinit_profiles(&state->profiles);
    free(state);
}

/**
 * Every record, in filesystem_path order
 *
 * One full-table SELECT — a local prepare+finalize: a single-pass scan run once
 * per command gains nothing from a cached statement — whose last column is the
 * table's size, so the arena allocation is exact and the count and the rows are
 * one snapshot (state_read_profiles).
 */
error_t state_records(
    const state_t *state,
    arena_t *arena,
    state_record_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Empty state (no DB file) — return empty results */
    if (!state->db) return NULL;

    /* The one read (13 columns: the key, the binding, the kind, the claim, the
     * blob and its stat, the lifecycle), and the table's size in a 14th: the
     * first row sizes the allocation */
    const char *sql =
        "SELECT filesystem_path, storage_path, profile, kind, mode, owner, \"group\", "
        "blob_oid, stat_mtime, stat_size, stat_ino, deployed_at, ordered_at, "
        "(SELECT count(*) FROM path_records) "
        "FROM path_records ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return error_create(
            ERR_STATE_INVALID, "Failed to prepare the record's read: %s", sqlite3_errmsg(state->db)
        );
    }

    rc = sqlite3_step(stmt);
    size_t record_count = rc == SQLITE_ROW ? (size_t) sqlite3_column_int64(stmt, 13) : 0;

    /* Allocate array */
    state_record_t *records = NULL;
    if (record_count > 0) {
        records = arena_calloc(arena, record_count, sizeof(state_record_t));
    }

    size_t i = 0;
    while (rc == SQLITE_ROW && i < record_count) {
        /* Column layout matches the SELECT above:
         *   0:     the key (filesystem_path)
         *   1-2:   the binding (storage_path, profile)
         *   3:     the content's node (kind)
         *   4-6:   the claim (mode, owner, group)
         *   7-10:  the content's blob and stat (blob_oid, stat_mtime, stat_size,
         *          stat_ino)
         *   11-12: the lifecycle (deployed_at, ordered_at) */
        state_record_t *record = &records[i];

        /* Every column read whole, or the read fails. The four text columns the
         * schema holds NOT NULL come back NULL only where their conversion failed
         * to allocate. A nullable one is asked its type before it is converted,
         * the one moment SQLite answers it, so a NULL its conversion returns
         * for a value is that failure too — never an owner the path has for none
         * — and so is no pointer for a stored blob. Each string is copied into
         * the arena as it comes, a NULL as NULL, and one arm takes every conversion
         * that failed: SQLite's own exhaustion, a refusal in its own words. */
        int owner_type = sqlite3_column_type(stmt, 5);
        int group_type = sqlite3_column_type(stmt, 6);
        int blob_type = sqlite3_column_type(stmt, 7);
        const char *kind = (const char *) sqlite3_column_text(stmt, 3);
        const void *blob = blob_type != SQLITE_NULL ? sqlite3_column_blob(stmt, 7) : NULL;

        record->filesystem_path = arena_strdup(arena, (const char *) sqlite3_column_text(stmt, 0));
        record->storage_path = arena_strdup(arena, (const char *) sqlite3_column_text(stmt, 1));
        record->profile = arena_strdup(arena, (const char *) sqlite3_column_text(stmt, 2));
        record->owner = arena_strdup(arena, (const char *) sqlite3_column_text(stmt, 5));
        record->group = arena_strdup(arena, (const char *) sqlite3_column_text(stmt, 6));

        if (!record->filesystem_path || !record->storage_path || !record->profile || !kind ||
            (owner_type != SQLITE_NULL && !record->owner) ||
            (group_type != SQLITE_NULL && !record->group) ||
            (blob_type != SQLITE_NULL && !blob)) {
            sqlite3_finalize(stmt);
            return error_create(ERR_MEMORY, "Failed to read the record's columns");
        }

        /* A NULL blob (a directory, or observed only) is the zero OID calloc
         * left; a stored one is 20 bytes by CHECK. A NULL mode — a link's, by
         * CHECK — reads 0, SQLite's integer for NULL, read only under the kind. */
        if (blob) memcpy(record->blob_oid.id, blob, GIT_OID_RAWSZ);
        record->kind = state_kind_from_text(kind);
        record->mode = (mode_t) sqlite3_column_int(stmt, 4);
        record->stat = (state_stat_t){
            .mtime = sqlite3_column_int64(stmt, 8),
            .size = sqlite3_column_int64(stmt, 9),
            .ino = (uint64_t) sqlite3_column_int64(stmt, 10),
        };
        record->deployed_at = (time_t) sqlite3_column_int64(stmt, 11);
        record->ordered_at = (time_t) sqlite3_column_int64(stmt, 12);

        i++;
        rc = sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to read the record: %s", sqlite3_errmsg(state->db)
        );
    }

    *out = records;
    *count = i;

    return NULL;
}

/* bsearch's: a key against a record's (strcmp — the read's own order) */
static int state_path_order(const void *key, const void *elem) {
    return strcmp(key, ((const state_record_t *) elem)->filesystem_path);
}

/**
 * The record at a path, in a snapshot state_records read — or NULL
 */
const state_record_t *state_find_record(
    const state_record_t *records,
    size_t count,
    const char *filesystem_path
) {
    /* No search of nothing: bsearch's base must be valid even for zero elements
     * (C11 7.22.5), and the empty snapshot's is NULL. */
    if (count == 0 || !filesystem_path) return NULL;

    return bsearch(filesystem_path, records, count, sizeof(*records), state_path_order);
}

/**
 * Write a record whole
 *
 * One statement, every column bound from the record in the store's own spelling
 * (see the SQL comment on STATEMENT_WRITE and the header contract), each bind
 * checked before the next: one SQLite refuses — a value past its length limit,
 * an allocation it could not make — ends the write before the step, which would
 * run with that parameter NULL and write an owner the record names as none. A
 * NULL pointer binds NULL (SQLite's contract), so each nullable column is one call.
 */
error_t state_write(state_t *state, const state_record_t *record) {
    CHECK_NULL(state);
    CHECK_NULL(record);
    CHECK_NULL(state->db);

    sqlite3_stmt *stmt = state_statement(state, STATEMENT_WRITE);

    /* 1-4. the key, the binding and the node: a kind with no text binds NULL,
     * which the column refuses (state_kind_to_text) */
    int rc = sqlite3_bind_text(stmt, 1, record->filesystem_path, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, record->storage_path, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 3, record->profile, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 4, state_kind_to_text(record->kind), -1, SQLITE_STATIC);
    }

    /* 5-7. the claim: a link's mode a don't-care, bound NULL by the kind; an
     * absent owner or group NULL */
    if (rc == SQLITE_OK) {
        rc = record->kind == FS_OCCUPANT_SYMLINK ? sqlite3_bind_null(stmt, 5)
                                                 : sqlite3_bind_int(stmt, 5, record->mode);
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 6, record->owner, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 7, record->group, -1, SQLITE_TRANSIENT);

    /* 8-11. the content: a zero blob NULL, a confirmation of none; the stat bound
     * to it */
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_blob(
            stmt, 8, git_oid_is_zero(&record->blob_oid) ? NULL : record->blob_oid.id,
            GIT_OID_RAWSZ, SQLITE_TRANSIENT
        );
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(stmt, 9, record->stat.mtime);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(stmt, 10, record->stat.size);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(stmt, 11, (sqlite3_int64) record->stat.ino);

    /* 12. the stamp: the last ownership event's, 0 where dotta never put the
     * path there */
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(stmt, 12, (sqlite3_int64) record->deployed_at);

    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to write the record at '%s': %s",
            record->filesystem_path, sqlite3_errmsg(state->db)
        );
    }

    return NULL;
}

/**
 * Retire a managed path's record
 *
 * DELETE of the record, and with it the order it carries (see the SQL comment
 * on STATEMENT_RETIRE and the header contract); a missing record matches nothing
 * and is success.
 */
error_t state_retire(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);

    sqlite3_stmt *stmt = state_statement(state, STATEMENT_RETIRE);

    /* 1. the record's key */
    int rc = sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to retire the record at '%s': %s",
            filesystem_path, sqlite3_errmsg(state->db)
        );
    }

    return NULL;
}

/**
 * Order a managed path's deployed copy pruned
 *
 * UPDATE of the record's order (see the SQL comment on STATEMENT_ORDER_PRUNE
 * and the header contract); a missing record matches nothing and is success.
 */
error_t state_order_prune(state_t *state, const char *filesystem_path, time_t now) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);

    if (now <= 0) {
        return error_create(ERR_INVALID_ARG, "Order timestamp must be > 0");
    }

    sqlite3_stmt *stmt = state_statement(state, STATEMENT_ORDER_PRUNE);

    /* 1. the record's key  2. the order's moment */
    int rc = sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int64(stmt, 2, (sqlite3_int64) now);
    if (rc == SQLITE_OK) rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return error_create(
            ERR_STATE_INVALID, "Failed to order '%s' pruned: %s",
            filesystem_path, sqlite3_errmsg(state->db)
        );
    }

    return NULL;
}
