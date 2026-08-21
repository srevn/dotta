/**
 * state.c - SQLite-based deployment state tracking implementation
 *
 * Uses SQLite for performance and scalability.
 *
 * Key optimizations:
 * - Prepared statements cached for bulk operations
 * - WAL mode for concurrent access
 * - Enabled-profile rows cached in memory (tiny, read frequently)
 * - Files queried on-demand (large, read occasionally)
 * - Persistent B-tree indexes (no hashmap rebuilding)
 */

#include "core/state.h"

#include <git2.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "sys/filesystem.h"

/* Schema version - must match database */
#define STATE_SCHEMA_VERSION "14"

/* Database file name */
#define STATE_DB_NAME "dotta.db"

/**
 * State structure
 *
 * Maintains minimal in-memory cache for performance:
 * - Enabled-profile rows cached (tiny, read frequently)
 * - Files queried on-demand (large, read occasionally)
 * - Prepared statements cached (eliminate preparation overhead)
 *
 * Row cache invariant:
 *   The cache is the materialized view of enabled_profiles. It is populated
 *   ONLY by lazy load_profile_entries(). Shape mutations (add / remove / bulk
 *   replace) call invalidate_profile_entries() — never optimistically update
 *   the in-memory layout — so that a subsequent rollback cannot leave the
 *   cache out of sync with the DB. The one exception is commit_oid, which is
 *   a fixed-width value column: state_set_profile_commit_oid() patches it in
 *   place after a successful UPDATE. Rollback still invalidates defensively,
 *   so the optimistic patch cannot outlive the transaction that produced it.
 */
struct state {
    /* Database connection */
    sqlite3 *db;
    char *db_path;

    /* Transaction state */
    bool in_transaction;                    /* BEGIN IMMEDIATE executed */

    /* Cached enabled_profiles rows (loaded lazily, position-ordered) */
    state_profile_entry_t *profile_entries;
    size_t profile_entry_count;
    bool profile_entries_loaded;

    /* Prepared statements (initialized once, reused) */
    sqlite3_stmt *stmt_insert_file;         /* UPSERT virtual_manifest (projection writer) */
    sqlite3_stmt *stmt_remove_file;         /* DELETE FROM virtual_manifest */
    sqlite3_stmt *stmt_file_exists;         /* SELECT 1 FROM virtual_manifest */
    sqlite3_stmt *stmt_get_file;            /* SELECT * FROM virtual_manifest */
    sqlite3_stmt *stmt_get_file_by_storage; /* SELECT * WHERE storage_path = ? */
    sqlite3_stmt *stmt_insert_profile;      /* INSERT INTO enabled_profiles */

    /* Directory prepared statements */
    sqlite3_stmt *stmt_insert_directory;        /* UPSERT tracked_directories (projection writer) */
    sqlite3_stmt *stmt_remove_directory;        /* DELETE FROM tracked_directories */
    sqlite3_stmt *stmt_mark_all_directories_inactive; /* UPDATE tracked_directories SET state = 'inactive' */

    /* Anchor prepared statements (the record's four verbs) */
    sqlite3_stmt *stmt_observe;             /* INSERT OR IGNORE anchors (presence only) */
    sqlite3_stmt *stmt_anchor;              /* UPSERT anchors … RETURNING observed_at, deployed_at */
    sqlite3_stmt *stmt_retire_anchor;       /* DELETE FROM anchors */
    sqlite3_stmt *stmt_order_prune;         /* UPDATE anchors SET prune_ordered = 1 */
};

/**
 * Get database file path
 *
 * @param repo Repository (must not be NULL)
 * @param out Output path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *get_db_path(git_repository *repo, char **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    const char *git_dir = git_repository_path(repo);
    if (!git_dir) {
        return ERROR(ERR_GIT, "Failed to get repository path");
    }

    return fs_path_join(git_dir, STATE_DB_NAME, out);
}

/**
 * Wrap SQLite error with context
 *
 * Extracts error message from database connection and creates
 * descriptive error with context.
 *
 * @param db Database connection (can be NULL)
 * @param context Error context message
 * @return Error object
 */
static error_t *sqlite_error(sqlite3 *db, const char *context) {
    const char *errmsg = db ? sqlite3_errmsg(db) : "unknown error";
    int errcode = db ? sqlite3_errcode(db) : SQLITE_ERROR;

    return ERROR(
        ERR_STATE_INVALID, "%s: %s (SQLite error %d)",
        context, errmsg, errcode
    );
}

/**
 * Lifecycle ↔ SQL text — the single boundary between the in-memory enum
 * and the on-disk text representation. The strings are file-scope literals
 * so SQLITE_STATIC is valid at every bind site.
 *
 * lifecycle_from_sql_text canonicalizes NULL and unknown text to
 * LIFECYCLE_ACTIVE. The CHECK constraint at the SQL level rejects unknown
 * values on write; this read-side fallback exists only as graceful
 * degradation against a manually edited DB.
 */
static const char *lifecycle_to_sql_text(state_lifecycle_t lc) {
    switch (lc) {
        case LIFECYCLE_INACTIVE: return "inactive";
        case LIFECYCLE_DELETED:  return "deleted";
        case LIFECYCLE_RELEASED: return "released";
        case LIFECYCLE_ACTIVE:
        default:                 return "active";
    }
}

static state_lifecycle_t lifecycle_from_sql_text(const char *s) {
    if (!s)                         return LIFECYCLE_ACTIVE;
    if (strcmp(s, "inactive") == 0) return LIFECYCLE_INACTIVE;
    if (strcmp(s, "deleted") == 0)  return LIFECYCLE_DELETED;
    if (strcmp(s, "released") == 0) return LIFECYCLE_RELEASED;
    return LIFECYCLE_ACTIVE;
}

/**
 * Path type ↔ SQL text — the same boundary for the type column, shared by
 * virtual_manifest (files only) and anchors (both kinds). Both tables'
 * CHECK constraints reject unknown text on write; the read-side fallback
 * to PATH_TYPE_FILE is the same graceful degradation as above.
 */
static const char *path_type_to_sql_text(path_type_t type) {
    switch (type) {
        case PATH_TYPE_SYMLINK:    return "symlink";
        case PATH_TYPE_EXECUTABLE: return "executable";
        case PATH_TYPE_DIRECTORY:  return "directory";
        case PATH_TYPE_FILE:
        default:                   return "file";
    }
}

static path_type_t path_type_from_sql_text(const char *s) {
    if (!s)                           return PATH_TYPE_FILE;
    if (strcmp(s, "symlink") == 0)    return PATH_TYPE_SYMLINK;
    if (strcmp(s, "executable") == 0) return PATH_TYPE_EXECUTABLE;
    if (strcmp(s, "directory") == 0)  return PATH_TYPE_DIRECTORY;
    return PATH_TYPE_FILE;
}

/**
 * Initialize database schema
 *
 * Creates tables if they don't exist:
 * - schema_meta: Schema versioning
 * - enabled_profiles: User's profile management (with indexes)
 * - anchors: The record dotta keeps of every managed path (with index)
 * - virtual_manifest: Deployed file manifest (with indexes)
 * - tracked_directories: Tracked directories from metadata (with index)
 *
 * @param db Database connection (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *initialize_schema(sqlite3 *db) {
    CHECK_NULL(db);

    char *errmsg = NULL;
    int rc;

    /* Schema definition (idempotent - safe to run multiple times) */
    const char *schema_sql =
        /* Schema versioning table */
        "CREATE TABLE IF NOT EXISTS schema_meta ("
        "    key TEXT PRIMARY KEY,"
        "    value TEXT NOT NULL"
        ") STRICT;"

        /* Insert version (fails silently if already exists) */
        "INSERT OR IGNORE INTO schema_meta (key, value) "
        "VALUES ('version', '" STATE_SCHEMA_VERSION "');"

        /* Enabled profiles table (authority: profile commands) */
        "CREATE TABLE IF NOT EXISTS enabled_profiles ("
        "    position INTEGER PRIMARY KEY,"
        "    name TEXT NOT NULL UNIQUE,"
        "    enabled_at INTEGER NOT NULL,"
        "    commit_oid BLOB NOT NULL,"
        "    target TEXT"
        ") STRICT;"

        /* Index for existence checks */
        "CREATE INDEX IF NOT EXISTS idx_enabled_name "
        "ON enabled_profiles(name);"

        /* The record: what dotta last reconciled each managed path against,
         * and what it confirmed there. A row exists iff dotta has observed
         * the path on disk while it was managed. One path, one kind, one
         * record — the PRIMARY KEY; the kind is `type`. No foreign key in
         * either direction: nothing is a parent, nothing cascades.
         *
         * Held by the schema:
         *   - observed_at > 0 always (observed ⇔ row exists; no zero sentinel)
         *   - a directory has no content confirmation (blob_oid IS NULL)
         *   - ownership implies confirmation for a file (deployed_at > 0 ⇒
         *     blob_oid set); a row with a blob and deployed_at = 0 is a
         *     confirmation, not a deployment
         *   - a stored blob is a real OID (20 bytes, never zeroblob) */
        "CREATE TABLE IF NOT EXISTS anchors ("
        "    filesystem_path TEXT PRIMARY KEY,"
        "    storage_path TEXT NOT NULL,"
        "    profile TEXT NOT NULL,"
        "    type TEXT NOT NULL CHECK(type IN ('file', 'symlink', 'executable', 'directory')),"
        "    mode INTEGER,"
        "    owner TEXT,"
        "    \"group\" TEXT,"
        "    "
        "    blob_oid BLOB CHECK(blob_oid IS NULL"
        "                        OR (length(blob_oid) = 20 AND blob_oid != zeroblob(20))),"
        "    stat_mtime INTEGER NOT NULL DEFAULT 0,"
        "    stat_size  INTEGER NOT NULL DEFAULT 0,"
        "    stat_ino   INTEGER NOT NULL DEFAULT 0,"
        "    "
        "    observed_at INTEGER NOT NULL CHECK(observed_at > 0),"
        "    deployed_at INTEGER NOT NULL DEFAULT 0,"
        "    prune_ordered INTEGER NOT NULL DEFAULT 0 CHECK(prune_ordered IN (0, 1)),"
        "    "
        "    CHECK (type != 'directory' OR blob_oid IS NULL),"
        "    CHECK (deployed_at = 0 OR type = 'directory' OR blob_oid IS NOT NULL)"
        ") STRICT;"

        "CREATE INDEX IF NOT EXISTS idx_anchors_profile "
        "ON anchors(profile);"

        /* Virtual manifest table (scope definition) */
        "CREATE TABLE IF NOT EXISTS virtual_manifest ("
        "    filesystem_path TEXT PRIMARY KEY,"
        "    storage_path TEXT NOT NULL,"
        "    profile TEXT NOT NULL,"
        "    old_profile TEXT,"
        "    "
        "    blob_oid BLOB NOT NULL,"
        "    "
        "    type TEXT NOT NULL CHECK(type IN ('file', 'symlink', 'executable')),"
        "    mode INTEGER,"
        "    owner TEXT,"
        "    \"group\" TEXT,"
        "    encrypted INTEGER NOT NULL DEFAULT 0,"
        "    "
        "    state TEXT NOT NULL DEFAULT 'active'"
        "      CHECK(state IN ('active', 'inactive', 'deleted', 'released'))"
        ") STRICT;"

        /* Indexes for common queries (hot paths) */
        "CREATE INDEX IF NOT EXISTS idx_manifest_profile "
        "ON virtual_manifest(profile);"

        "CREATE INDEX IF NOT EXISTS idx_manifest_storage "
        "ON virtual_manifest(storage_path);"

        /* Tracked directories table */
        "CREATE TABLE IF NOT EXISTS tracked_directories ("
        "    filesystem_path TEXT PRIMARY KEY,"
        "    storage_path TEXT NOT NULL,"
        "    profile TEXT NOT NULL,"
        "    mode INTEGER,"
        "    owner TEXT,"
        "    \"group\" TEXT,"
        "    state TEXT NOT NULL DEFAULT 'active'"
        "      CHECK(state IN ('active', 'inactive', 'deleted'))"
        ") STRICT;"

        "CREATE INDEX IF NOT EXISTS idx_tracked_directories_profile "
        "ON tracked_directories(profile);";

    /* Execute schema SQL */
    rc = sqlite3_exec(db, schema_sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to initialize schema: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
}

/**
 * Verify schema version
 *
 * Checks that database schema matches the version expected by this code.
 * This prevents incompatibilities when database was created by a different
 * version of dotta.
 *
 * @param db Database connection (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *verify_schema_version(sqlite3 *db) {
    CHECK_NULL(db);

    const char *sql = "SELECT value FROM schema_meta WHERE key = 'version';";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return ERROR(
            ERR_STATE_INVALID,
            "Database missing schema_meta table - corrupted or wrong format"
        );
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return ERROR(ERR_STATE_INVALID, "Database missing schema version");
    }

    const char *db_version = (const char *) sqlite3_column_text(stmt, 0);
    if (!db_version) {
        sqlite3_finalize(stmt);
        return ERROR(ERR_STATE_INVALID, "Schema version is NULL");
    }

    /* Must match exactly */
    if (strcmp(db_version, STATE_SCHEMA_VERSION) != 0) {
        error_t *err = ERROR(
            ERR_STATE_INVALID,
            "Schema version mismatch: database has version %s, code expects %s\n"
            "Database was created by different version of dotta",
            db_version, STATE_SCHEMA_VERSION
        );
        sqlite3_finalize(stmt);
        return err;
    }

    sqlite3_finalize(stmt);
    return NULL;
}

/**
 * Configure database for optimal performance
 *
 * Sets critical pragmas:
 * - WAL mode: Concurrent access, 2-10x faster
 * - synchronous=NORMAL: Fast but safe
 * - cache_size: 10MB for large deployments
 * - temp_store=MEMORY: Temp operations in RAM
 * - busy_timeout: Wait up to 3s for lock
 *
 * @param db Database connection (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *configure_db(sqlite3 *db) {
    CHECK_NULL(db);

    char *errmsg = NULL;
    int rc;

    /* 1. Enable WAL mode (critical for performance) */
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to enable WAL mode: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    /* 2. Fast synchronization (safe on crash, fast on commit) */
    rc = sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to set synchronous mode: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    /* 3. Larger cache (10MB instead of default 2MB) */
    rc = sqlite3_exec(db, "PRAGMA cache_size=10000;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to set cache size: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    /* 4. Store temp tables in memory (faster) */
    rc = sqlite3_exec(db, "PRAGMA temp_store=MEMORY;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to set temp store: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    /* 5. Short busy timeout to handle transient locks gracefully */
    sqlite3_busy_timeout(db, 3000);

    /* 6. Disable persistent WAL */
    int persist_wal = 0;
    sqlite3_file_control(db, NULL, SQLITE_FCNTL_PERSIST_WAL, &persist_wal);

    return NULL;
}

/**
 * Open database connection
 *
 * Opens or creates database, initializes schema, and configures pragmas.
 * Does NOT start a transaction - use state_open() for that.
 *
 * @param db_path Path to database file (must not be NULL)
 * @param create_if_missing Create database if it doesn't exist
 * @param out Database connection (must not be NULL, caller must close)
 * @return Error or NULL on success
 */
static error_t *open_db(const char *db_path, bool create_if_missing, sqlite3 **out) {
    CHECK_NULL(db_path);
    CHECK_NULL(out);

    sqlite3 *db = NULL;
    error_t *err = NULL;
    int flags = SQLITE_OPEN_READWRITE;

    /* Add create flag if requested */
    if (create_if_missing) {
        flags |= SQLITE_OPEN_CREATE;
    }

    /* Open database */
    int rc = sqlite3_open_v2(db_path, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        if (rc == SQLITE_CANTOPEN && !create_if_missing) {
            /* Database doesn't exist - return NULL (not an error for read-only) */
            *out = NULL;
            return NULL;
        }

        err = ERROR(
            ERR_FS, "Failed to open database: %s",
            db ? sqlite3_errmsg(db) : sqlite3_errstr(rc)
        );

        if (db) sqlite3_close(db);
        return err;
    }

    /* Configure database */
    err = configure_db(db);
    if (err) {
        sqlite3_close(db);
        return err;
    }

    /* Initialize or verify schema */
    bool db_is_new = false;
    sqlite3_stmt *check_stmt = NULL;
    rc = sqlite3_prepare_v2(
        db, "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta';",
        -1, &check_stmt, NULL
    );

    if (rc == SQLITE_OK) {
        rc = sqlite3_step(check_stmt);
        db_is_new = (rc != SQLITE_ROW);
        sqlite3_finalize(check_stmt);
    }

    if (db_is_new) {
        /* New database - initialize schema */
        err = initialize_schema(db);
        if (err) {
            sqlite3_close(db);
            return err;
        }
    } else {
        /* Existing database - verify schema version */
        err = verify_schema_version(db);
        if (err) {
            sqlite3_close(db);
            return err;
        }
    }

    *out = db;
    return NULL;
}

/**
 * Finalize all prepared statements
 *
 * Called from state_free() before closing database, and by
 * prepare_statements on any failure: every slot is NULL until its
 * statement is prepared, so finalizing the roster is safe at any point.
 *
 * @param state State (can be NULL)
 */
static void finalize_statements(state_t *state) {
    if (!state) return;

    sqlite3_stmt **roster[] = {
        /* Manifest statements */
        &state->stmt_insert_file,
        &state->stmt_file_exists,
        &state->stmt_get_file,
        &state->stmt_get_file_by_storage,
        &state->stmt_remove_file,
        /* Profile statements */
        &state->stmt_insert_profile,
        /* Directory statements */
        &state->stmt_insert_directory,
        &state->stmt_remove_directory,
        &state->stmt_mark_all_directories_inactive,
        /* Anchor statements */
        &state->stmt_observe,
        &state->stmt_anchor,
        &state->stmt_retire_anchor,
        &state->stmt_order_prune,
    };

    for (size_t i = 0; i < sizeof(roster) / sizeof(roster[0]); i++) {
        if (*roster[i]) {
            sqlite3_finalize(*roster[i]);
            *roster[i] = NULL;
        }
    }
}

/**
 * Prepare all statements for state operations
 *
 * Called once per database connection. Statements are reused for all
 * operations, providing 100x speedup for bulk operations. On any failure
 * the statements already prepared are finalized before returning, so a
 * handle never carries a half-prepared roster.
 *
 * @param state State (must not be NULL, db must be open)
 * @return Error or NULL on success
 */
static error_t *prepare_statements(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    int rc;

    /* Project a file row (the projection engine's per-row write — hot path)
     *
     * Column order mirrors the virtual_manifest layout:
     *   identity (1-3) | VWD cache (4-9) | state
     *
     * UPDATE-path field preservation (ON CONFLICT clause):
     *
     * VWD cache (storage_path, profile, blob_oid, type, mode, owner, group,
     * encrypted): always replaced from excluded — the engine is the
     * authoritative writer of this domain.
     *
     * state: 'active' on both arms. The sole caller is the projection
     * loop, and projection means in-scope — a path that re-entered the
     * projection is ACTIVE whatever lifecycle it carried.
     *
     * old_profile: NULL on INSERT (no reassignment yet). On UPDATE, a
     * two-branch CASE: the profile is changing → auto-capture the current
     * profile from the existing row (eliminates read-before-write for
     * reassignment); unchanged → preserve. Clearing is done separately via
     * state_clear_old_profile().
     *
     * Nothing else about the path is touched: the record (content
     * confirmation, ownership, observation) lives in anchors, keyed
     * apart, and this statement never names it. */
    const char *sql_insert =
        "INSERT INTO virtual_manifest "
        "(filesystem_path, storage_path, profile, "
        " blob_oid, type, mode, owner, \"group\", encrypted, state) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active') "
        "ON CONFLICT(filesystem_path) DO UPDATE SET "
        "  storage_path = excluded.storage_path, "
        "  profile      = excluded.profile, "
        "  old_profile  = CASE "
        "                   WHEN excluded.profile != virtual_manifest.profile "
        "                        THEN virtual_manifest.profile "
        "                   ELSE virtual_manifest.old_profile "
        "                 END, "
        "  blob_oid     = excluded.blob_oid, "
        "  type         = excluded.type, "
        "  mode         = excluded.mode, "
        "  owner        = excluded.owner, "
        "  \"group\"    = excluded.\"group\", "
        "  encrypted    = excluded.encrypted, "
        "  state        = 'active';";

    rc = sqlite3_prepare_v2(state->db, sql_insert, -1, &state->stmt_insert_file, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare insert statement");
    }

    /* File exists check (used in status - hot path) */
    const char *sql_exists =
        "SELECT 1 FROM virtual_manifest WHERE filesystem_path = ? LIMIT 1;";

    rc = sqlite3_prepare_v2(state->db, sql_exists, -1, &state->stmt_file_exists, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare exists statement");
    }

    /* Get file (used by the verb overlays and remove's conflict analysis) */
    const char *sql_get =
        "SELECT storage_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state "
        "FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_get, -1, &state->stmt_get_file, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare get statement");
    }

    /* Get file by storage path (used by profile discovery) */
    const char *sql_get_by_storage =
        "SELECT filesystem_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state "
        "FROM virtual_manifest WHERE storage_path = ? AND state = 'active' LIMIT 1;";

    rc = sqlite3_prepare_v2(
        state->db, sql_get_by_storage, -1, &state->stmt_get_file_by_storage, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare get by storage statement");
    }

    /* Remove file (used in revert and cleanup) */
    const char *sql_remove =
        "DELETE FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_remove, -1, &state->stmt_remove_file, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare remove statement");
    }

    /* Insert profile (used in state_reorder_profiles) */
    const char *sql_profile =
        "INSERT INTO enabled_profiles (position, name, enabled_at, commit_oid, target) "
        "VALUES (?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_profile, -1, &state->stmt_insert_profile, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare profile statement");
    }

    /* Tracked-directory projection UPSERT (per-row in the manifest sync loop)
     *
     * The directory mirror of sql_insert. state = 'active' is hardcoded on
     * both arms: the sole caller is the projection loop, and projection
     * means in-scope — the sweep's INACTIVE downgrade is undone here for
     * rows still covered by an enabled profile's metadata. */
    const char *sql_insert_dir =
        "INSERT INTO tracked_directories "
        "(filesystem_path, storage_path, profile, mode, owner, \"group\", state) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active') "
        "ON CONFLICT(filesystem_path) DO UPDATE SET "
        "  storage_path = excluded.storage_path, "
        "  profile      = excluded.profile, "
        "  mode         = excluded.mode, "
        "  owner        = excluded.owner, "
        "  \"group\"    = excluded.\"group\", "
        "  state        = 'active';";

    rc = sqlite3_prepare_v2(
        state->db, sql_insert_dir, -1, &state->stmt_insert_directory, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare insert directory statement");
    }

    /* Remove tracked directory (per-removed-dir loop in apply cleanup) */
    const char *sql_remove_dir =
        "DELETE FROM tracked_directories WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(
        state->db, sql_remove_dir, -1, &state->stmt_remove_directory, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare remove directory statement");
    }

    /* Mark all active directories inactive (1× per directory sync sweep) */
    const char *sql_mark_dirs_inactive =
        "UPDATE tracked_directories SET state = 'inactive' WHERE state = 'active';";

    rc = sqlite3_prepare_v2(
        state->db, sql_mark_dirs_inactive, -1,
        &state->stmt_mark_all_directories_inactive, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare mark directories inactive statement");
    }

    /* Observe: presence only, idempotent. Creates the record with the row's
     * identity and metadata and observed_at = now; no blob, no stat. Never
     * touches an existing row — OR IGNORE is what makes the first observer
     * win without a CASE.
     *
     * Bind order (numbered placeholders):
     *   ?1 filesystem_path  ?2 storage_path  ?3 profile  ?4 type
     *   ?5 mode  ?6 owner  ?7 group  ?8 observed_at */
    const char *sql_observe =
        "INSERT OR IGNORE INTO anchors "
        "(filesystem_path, storage_path, profile, type, mode, owner, \"group\", observed_at) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);";

    rc = sqlite3_prepare_v2(state->db, sql_observe, -1, &state->stmt_observe, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare observe statement");
    }

    /* Anchor: the recorded row, the confirmation, the ownership event —
     * the sole writer of every record column but observed_at's existing
     * value.
     *
     * Bind order (numbered placeholders):
     *   ?1 filesystem_path  ?2 storage_path  ?3 profile  ?4 type
     *   ?5 mode  ?6 owner  ?7 group
     *   ?8 blob_oid — NULL for a directory
     *   ?9 stat_mtime  ?10 stat_size  ?11 stat_ino
     *   ?12 observed_at — the INSERT arm's alone; the UPDATE arm does not
     *                     name the column, so an existing stamp is never
     *                     rewritten and the first writer wins
     *   ?13 deployed_at — reused on both sides of its CASE so the
     *                     sentinel test and the replacement value cannot
     *                     drift apart: 0 keeps the existing timestamp
     *                     (a confirmation), anything else is written (an
     *                     ownership event)
     *
     * prune_ordered resets to 0 on the UPDATE arm: the path is back under
     * a live row, and any order predating that is void.
     *
     * RETURNING projects the two columns the statement decided rather than
     * took — observed_at (INSERT arm: now; UPDATE arm: the existing stamp)
     * and deployed_at (after the CASE) — so a caller mirroring an
     * in-memory snapshot (workspace_anchor) can assign the canonical
     * record without re-deriving either rule in C. Every other column is
     * what the caller bound. */
    const char *sql_anchor =
        "INSERT INTO anchors "
        "(filesystem_path, storage_path, profile, type, mode, owner, \"group\", "
        " blob_oid, stat_mtime, stat_size, stat_ino, observed_at, deployed_at) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) "
        "ON CONFLICT(filesystem_path) DO UPDATE SET "
        "  storage_path  = excluded.storage_path, "
        "  profile       = excluded.profile, "
        "  type          = excluded.type, "
        "  mode          = excluded.mode, "
        "  owner         = excluded.owner, "
        "  \"group\"     = excluded.\"group\", "
        "  blob_oid      = excluded.blob_oid, "
        "  stat_mtime    = excluded.stat_mtime, "
        "  stat_size     = excluded.stat_size, "
        "  stat_ino      = excluded.stat_ino, "
        "  deployed_at   = CASE WHEN excluded.deployed_at = 0 THEN anchors.deployed_at "
        "                       ELSE excluded.deployed_at END, "
        "  prune_ordered = 0 "
        "RETURNING observed_at, deployed_at;";

    rc = sqlite3_prepare_v2(state->db, sql_anchor, -1, &state->stmt_anchor, NULL);
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare anchor statement");
    }

    /* Retire: the record goes. Nothing cascades — there is no parent. */
    const char *sql_retire_anchor =
        "DELETE FROM anchors WHERE filesystem_path = ?1;";

    rc = sqlite3_prepare_v2(
        state->db, sql_retire_anchor, -1, &state->stmt_retire_anchor, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare retire anchor statement");
    }

    /* Order prune: the one persisted intent (remove --delete-files) */
    const char *sql_order_prune =
        "UPDATE anchors SET prune_ordered = 1 WHERE filesystem_path = ?1;";

    rc = sqlite3_prepare_v2(
        state->db, sql_order_prune, -1, &state->stmt_order_prune, NULL
    );
    if (rc != SQLITE_OK) {
        finalize_statements(state);
        return sqlite_error(state->db, "Failed to prepare order prune statement");
    }

    return NULL;
}

/**
 * Free the row cache and mark it unloaded
 *
 * Safe to call repeatedly. Invoked by shape-mutating paths
 * (state_enable_profile, state_disable_profile, state_reorder_profiles) and by
 * state_rollback / state_free. state_set_profile_commit_oid does NOT call
 * this helper — it patches the cached row in place because only a single
 * fixed-width value field changes. The cache must never outlive the last
 * committed DB state it was built from.
 */
static void invalidate_profile_entries(state_t *state) {
    if (!state || !state->profile_entries) {
        state->profile_entries_loaded = false;
        state->profile_entry_count = 0;
        return;
    }

    for (size_t i = 0; i < state->profile_entry_count; i++) {
        free(state->profile_entries[i].name);
        free(state->profile_entries[i].target);
    }
    free(state->profile_entries);
    state->profile_entries = NULL;
    state->profile_entry_count = 0;
    state->profile_entries_loaded = false;
}

/**
 * Load the enabled_profiles row cache
 *
 * Lazy loader: performs one SELECT over enabled_profiles and materializes
 * every row (name, target, commit_oid) into the cache. Rows are
 * ordered by position to match the user's precedence order.
 *
 * The cache replaces four previous query-shape functions (get_prefix_map,
 * get_profile_prefix, get_profile_commit_oid, load_commit_oid_map) with a
 * single lazy load + linear peek.
 */
static error_t *load_profile_entries(state_t *state) {
    CHECK_NULL(state);

    /* Already loaded — return immediately.
     * Must precede the db check: state_load() on a repository without
     * .git/dotta.db allocates a handle with db==NULL and pre-marks the
     * cache as loaded (zero rows), a valid view of "no enabled profiles".
     * Lazy promotion via state_begin() opens the DB without disturbing
     * this cached view; mutations invalidate it on their own. */
    if (state->profile_entries_loaded) return NULL;

    CHECK_NULL(state->db);

    /* Probe the row count first so we can allocate exactly once. */
    sqlite3_stmt *count_stmt = NULL;
    int rc = sqlite3_prepare_v2(
        state->db, "SELECT COUNT(*) FROM enabled_profiles;", -1, &count_stmt, NULL
    );
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare profile count query");
    }
    size_t row_count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        sqlite3_int64 n = sqlite3_column_int64(count_stmt, 0);
        if (n > 0) row_count = (size_t) n;
    }
    sqlite3_finalize(count_stmt);

    state_profile_entry_t *entries = NULL;
    if (row_count > 0) {
        entries = calloc(row_count, sizeof(*entries));
        if (!entries) {
            return ERROR(ERR_MEMORY, "Failed to allocate profile row cache");
        }
    }

    /* Read all rows in position order. */
    const char *sql =
        "SELECT name, target, commit_oid FROM enabled_profiles "
        "ORDER BY position ASC;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(entries);
        return sqlite_error(state->db, "Failed to prepare profile query");
    }

    error_t *err = NULL;
    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (i >= row_count) {
            /* Concurrent INSERT between COUNT and SELECT would be unusual
             * under our write-lock discipline, but guard anyway. */
            err = ERROR(ERR_STATE_INVALID, "Profile row count changed during load");
            break;
        }

        const char *name_db = (const char *) sqlite3_column_text(stmt, 0);
        const char *prefix_db = (const char *) sqlite3_column_text(stmt, 1);
        const void *oid_blob = sqlite3_column_blob(stmt, 2);

        if (!name_db) {
            err = ERROR(ERR_STATE_INVALID, "Profile name is NULL");
            break;
        }

        /* Allocate the row's owned strings atomically. If either strdup
         * fails, free whatever succeeded right here before breaking — the
         * outer cleanup loop only walks rows [0, i), so a half-built row
         * at index i would otherwise leak its successful allocations. */
        state_profile_entry_t *row = &entries[i];
        row->name = strdup(name_db);
        row->target = prefix_db ? strdup(prefix_db) : NULL;
        if (oid_blob) memcpy(row->commit_oid.id, oid_blob, GIT_OID_RAWSZ);

        if (!row->name || (prefix_db && !row->target)) {
            free(row->name);
            free(row->target);
            err = ERROR(ERR_MEMORY, "Failed to copy enabled profile row");
            break;
        }

        i++;
    }

    sqlite3_finalize(stmt);

    if (!err && rc != SQLITE_DONE) {
        err = sqlite_error(state->db, "Failed to query profiles");
    }

    if (err) {
        for (size_t j = 0; j < i; j++) {
            free(entries[j].name);
            free(entries[j].target);
        }
        free(entries);
        return err;
    }

    state->profile_entries = entries;
    state->profile_entry_count = i;
    state->profile_entries_loaded = true;

    return NULL;
}

/**
 * Linear lookup into the row cache (caller guarantees load)
 *
 * Row count is bounded by the user's enabled-profile list (typically < 10),
 * so the linear scan is faster than a hash lookup and fits comfortably in L1.
 */
static const state_profile_entry_t *find_profile_entry(
    const state_t *state,
    const char *profile
) {
    for (size_t i = 0; i < state->profile_entry_count; i++) {
        if (strcmp(state->profile_entries[i].name, profile) == 0) {
            return &state->profile_entries[i];
        }
    }
    return NULL;
}

/**
 * Peek the cached enabled_profiles rows
 */
error_t *state_peek_profiles(
    const state_t *state,
    const state_profile_entry_t **out_entries,
    size_t *out_count
) {
    CHECK_NULL(state);
    CHECK_NULL(out_entries);
    CHECK_NULL(out_count);

    error_t *err = load_profile_entries((state_t *) state);
    if (err) return err;

    *out_entries = state->profile_entries;
    *out_count = state->profile_entry_count;
    return NULL;
}

/**
 * Peek a single profile's deployment target
 */
const char *state_peek_profile_target(
    const state_t *state,
    const char *profile
) {
    if (!state || !profile) return NULL;

    error_t *err = load_profile_entries((state_t *) state);
    if (err) {
        error_free(err);
        return NULL;
    }

    const state_profile_entry_t *entry = find_profile_entry(state, profile);
    return entry ? entry->target : NULL;
}

/**
 * Peek a single profile's stored commit_oid
 */
const git_oid *state_peek_profile_commit_oid(
    const state_t *state,
    const char *profile
) {
    if (!state || !profile) return NULL;

    error_t *err = load_profile_entries((state_t *) state);
    if (err) {
        error_free(err);
        return NULL;
    }

    const state_profile_entry_t *entry = find_profile_entry(state, profile);
    return entry ? &entry->commit_oid : NULL;
}

/**
 * Get enabled profiles
 *
 * Returns copy that caller must free. Built from the row cache.
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    error_t *err = load_profile_entries((state_t *) state);
    if (err) return err;

    string_array_t *copy = string_array_new(0);
    if (!copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    for (size_t i = 0; i < state->profile_entry_count; i++) {
        err = string_array_push(copy, state->profile_entries[i].name);
        if (err) {
            string_array_free(copy);
            return err;
        }
    }

    *out = copy;
    return NULL;
}

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
bool state_has_profile(const state_t *state, const char *profile) {
    if (!state || !profile) {
        return false;
    }

    error_t *err = load_profile_entries((state_t *) state);
    if (err) {
        error_free(err);
        return false;
    }

    return find_profile_entry(state, profile) != NULL;
}

/**
 * Enable profile with optional deployment target
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile,
    const char *target
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(state->db);

    if (profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    /* UPSERT: Insert or update on conflict.
     *
     * commit_oid is zeroblob(20) on fresh INSERT — a sentinel that
     * manifest_apply_scope replaces, in the same transaction, with the HEAD
     * it projected the profile from. On UPSERT conflict (profile already
     * enabled), commit_oid is preserved — it represents the last-projected
     * HEAD and must not be clobbered by a target update.
     *
     * Position is `COALESCE(MAX(position) + 1, 0)`: on an empty table
     * MAX returns NULL and the COALESCE drops to 0, matching the 0-based
     * position assignment used by state_reorder_profiles. */
    const char *sql =
        "INSERT INTO enabled_profiles (name, target, enabled_at, commit_oid, position) "
        "VALUES (?1, ?2, ?3, zeroblob(20), "
        "  (SELECT COALESCE(MAX(position) + 1, 0) FROM enabled_profiles)) "
        "ON CONFLICT(name) DO UPDATE SET target = ?2, enabled_at = ?3";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare enable profile statement");
    }

    /* Bind parameters */
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_STATIC);
    if (target && target[0] != '\0') {
        sqlite3_bind_text(stmt, 2, target, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    sqlite3_bind_int64(stmt, 3, time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to enable profile");
    }

    invalidate_profile_entries(state);
    return NULL;
}

/**
 * Disable profile
 */
error_t *state_disable_profile(
    state_t *state,
    const char *profile
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(state->db);

    const char *sql = "DELETE FROM enabled_profiles WHERE name = ?1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare disable profile statement");
    }

    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to disable profile");
    }

    invalidate_profile_entries(state);
    /* Not an error if profile wasn't enabled (DELETE with 0 rows affected is OK) */
    return NULL;
}

/**
 * Reorder enabled profiles to match a new precedence order
 *
 * Reorder-only contract: every name in `profiles` must already be a row
 * in enabled_profiles. Additions and removals belong to the membership
 * primitives (state_enable_profile / state_disable_profile). A name not
 * currently enabled returns ERR_INVALID_ARG and leaves the table
 * untouched — closing the silent (custom-profile, NULL-target) trap at
 * the write boundary.
 *
 * Per-row state (target, commit_oid) is read from the row cache and
 * preserved across the DELETE + re-INSERT rewrite. Only the position
 * column changes meaning per call; everything else is byte-for-byte
 * preserved.
 *
 * Hot path - must be fast even with 10,000 deployed files. Only modifies
 * enabled_profiles (virtual_manifest untouched).
 *
 * @param state State (must not be NULL)
 * @param profiles Profile names in desired order (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_reorder_profiles(
    state_t *state,
    const string_array_t *profiles
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(state->db);

    /* Transaction is a precondition — the DELETE below would auto-commit
     * on an unguarded connection and leave no recovery path for errors
     * in the INSERT loop. The caller must hold BEGIN IMMEDIATE (state_open
     * or state_begin). */
    if (!state->in_transaction) {
        return ERROR(
            ERR_STATE_INVALID, "state_reorder_profiles requires an active transaction"
        );
    }

    /* Ensure the row cache is populated — we read every row from it to
     * verify the in-cache precondition and to preserve target + commit_oid
     * across DELETE + re-INSERT. */
    error_t *err = load_profile_entries(state);
    if (err) {
        return error_wrap(err, "Failed to load profile row cache");
    }

    /* Precondition: every name in `profiles` must already be enabled.
     * Reorder permutes membership; it never adds or removes rows. A name
     * missing from the cache means the caller wants to add a profile —
     * they should call state_enable_profile first, which is the only
     * primitive that can record a target for custom/-bearing profiles. */
    for (size_t i = 0; i < profiles->count; i++) {
        if (!find_profile_entry(state, profiles->items[i])) {
            return ERROR(
                ERR_INVALID_ARG,
                "state_reorder_profiles: profile '%s' is not currently enabled "
                "(use state_enable_profile to add a profile)",
                profiles->items[i]
            );
        }
    }

    /* Delete all existing rows under the caller's transaction. On failure,
     * SQL is unchanged and the cache still matches — safe to return. */
    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM enabled_profiles;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        err = ERROR(
            ERR_STATE_INVALID, "Failed to clear profiles: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    /* Insert rows. SQLITE_TRANSIENT on every binding means SQLite copies the
     * value at bind time, so the cache pointers we pass below do not need to
     * outlive sqlite3_step — future refactors that mutate the cache mid-loop
     * stay safe. Cost is <100 bytes of memcpy per row; the table tops out
     * around ten rows in practice. */
    time_t now = time(NULL);
    for (size_t i = 0; i < profiles->count; i++) {
        const char *name = profiles->items[i];
        const state_profile_entry_t *preserved = find_profile_entry(state, name);

        /* The precondition loop above guarantees preserved is non-NULL.
         * No NULL branch on target either: a profile with no deployment
         * target (home/root) legitimately has preserved->target == NULL,
         * which sqlite3_bind_null handles explicitly. */

        /* Reset and bind statement */
        sqlite3_reset(state->stmt_insert_profile);
        sqlite3_clear_bindings(state->stmt_insert_profile);

        /* Bind parameters: position, name, enabled_at, commit_oid, target.
         * SQLITE_TRANSIENT: SQLite copies immediately; source lifetimes are ours. */
        sqlite3_bind_int64(state->stmt_insert_profile, 1, (sqlite3_int64) i);
        sqlite3_bind_text(
            state->stmt_insert_profile, 2, name, -1, SQLITE_TRANSIENT
        );
        sqlite3_bind_int64(state->stmt_insert_profile, 3, (sqlite3_int64) now);
        sqlite3_bind_blob(
            state->stmt_insert_profile, 4,
            preserved->commit_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT
        );
        if (preserved->target) {
            sqlite3_bind_text(
                state->stmt_insert_profile, 5, preserved->target, -1, SQLITE_TRANSIENT
            );
        } else {
            sqlite3_bind_null(state->stmt_insert_profile, 5);
        }

        rc = sqlite3_step(state->stmt_insert_profile);
        if (rc != SQLITE_DONE) {
            return sqlite_error(state->db, "Failed to insert profile");
        }
    }

    /* SQL now reflects the new order. Invalidate so the next peek reloads
     * fresh rows in the new position order. */
    invalidate_profile_entries(state);
    return NULL;
}

/**
 * Project a file row into virtual_manifest
 *
 * HOT PATH: called once per row the projection engine writes.
 * Uses prepared statement for 100x speedup.
 *
 * @param state State (must not be NULL)
 * @param row File row to project (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_file(state_t *state, const manifest_row_t *row) {
    CHECK_NULL(state);
    CHECK_NULL(row);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_insert_file);

    /* Reset statement (clear previous bindings) */
    sqlite3_reset(state->stmt_insert_file);
    sqlite3_clear_bindings(state->stmt_insert_file);

    /* Bind parameters */
    /* 1-3. filesystem_path, storage_path, profile */
    sqlite3_bind_text(state->stmt_insert_file, 1, row->filesystem_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 2, row->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 3, row->profile, -1, SQLITE_TRANSIENT);

    /* 4. blob_oid — bound as 20-byte BLOB. Using row->blob_oid.id (the backing
     * byte array) rather than &row->blob_oid keeps the intent explicit: we
     * are writing the raw hash bytes, not a struct snapshot whose layout happens
     * to start with them. SQLITE_TRANSIENT lets SQLite copy before we modify. */
    sqlite3_bind_blob(
        state->stmt_insert_file, 4, row->blob_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT
    );

    /* 5. type */
    sqlite3_bind_text(
        state->stmt_insert_file, 5, path_type_to_sql_text(row->type), -1, SQLITE_STATIC
    );

    /* 6. mode */
    if (row->mode > 0) {
        sqlite3_bind_int(state->stmt_insert_file, 6, row->mode);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 6);
    }

    /* 7. owner */
    if (row->owner) {
        sqlite3_bind_text(state->stmt_insert_file, 7, row->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 7);
    }

    /* 8. group */
    if (row->group) {
        sqlite3_bind_text(state->stmt_insert_file, 8, row->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 8);
    }

    /* 9. encrypted. state is not bound: 'active' is hardcoded in the SQL
     * (projection means in-scope), and old_profile is the CASE's. */
    sqlite3_bind_int(state->stmt_insert_file, 9, row->encrypted ? 1 : 0);

    /* Execute (don't finalize - statement is reused) */
    int rc = sqlite3_step(state->stmt_insert_file);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to insert file entry");
    }

    return NULL;
}

/**
 * Remove file entry from state
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to remove (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_remove_file(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_remove_file);

    /* Reset and bind */
    sqlite3_reset(state->stmt_remove_file);
    sqlite3_clear_bindings(state->stmt_remove_file);

    sqlite3_bind_text(state->stmt_remove_file, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(state->stmt_remove_file);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to remove file entry");
    }

    /* Check if row was actually deleted */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in state", filesystem_path);
    }

    return NULL;
}

/**
 * Check if file exists in state
 *
 * HOT PATH: Called frequently during status checks.
 * Uses PRIMARY KEY index for O(1) lookup.
 *
 * @param state State (must not be NULL)
 * @param filesystem_path File path to check (must not be NULL)
 * @return true if file exists in state
 */
bool state_file_exists(const state_t *state, const char *filesystem_path) {
    if (!state || !filesystem_path || !state->db || !state->stmt_file_exists) {
        return false;
    }

    sqlite3_stmt *stmt = state->stmt_file_exists;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    /* Return true if row found */
    return (rc == SQLITE_ROW);
}

/**
 * Get file entry from state
 *
 * Returns owned memory (caller must free).
 * Original API returned borrowed reference.
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
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_get_file);

    sqlite3_stmt *stmt = state->stmt_get_file;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            return ERROR(
                ERR_NOT_FOUND, "File not found in state: %s",
                filesystem_path
            );
        }
        return sqlite_error(state->db, "Failed to query file");
    }

    /* Extract columns. Layout matches sql_get:
     *   0-2:  storage_path, profile, old_profile   (identity; filesystem_path is WHERE)
     *   3-9:  blob_oid, type, mode, owner, group, encrypted, state  (VWD cache) */
    const char *storage_path = (const char *) sqlite3_column_text(stmt, 0);
    const char *profile = (const char *) sqlite3_column_text(stmt, 1);
    const char *old_profile = (const char *) sqlite3_column_text(stmt, 2);

    /* Read path trusts sqlite3's schema enforcement: BLOB NOT NULL means non-NULL,
     * and our own bind path is the only writer so length is always GIT_OID_RAWSZ. */
    git_oid blob_oid;
    memcpy(blob_oid.id, sqlite3_column_blob(stmt, 3), GIT_OID_RAWSZ);

    const char *type_str = (const char *) sqlite3_column_text(stmt, 4);

    /* Read mode as integer (0 if NULL) */
    mode_t mode = 0;
    if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
        mode = (mode_t) sqlite3_column_int(stmt, 5);
    }

    const char *owner = (const char *) sqlite3_column_text(stmt, 6);
    const char *group = (const char *) sqlite3_column_text(stmt, 7);
    int encrypted = sqlite3_column_int(stmt, 8);
    state_lifecycle_t lifecycle = lifecycle_from_sql_text(
        (const char *) sqlite3_column_text(stmt, 9)
    );

    /* Validate required string columns */
    if (!storage_path || !profile || !type_str) {
        return ERROR(
            ERR_STATE_INVALID, "NULL value in required column for file: %s",
            filesystem_path
        );
    }

    /* Create entry (caller owns) */
    state_entry_t *entry = NULL;
    error_t *err = state_create_entry(
        storage_path, filesystem_path, profile, old_profile,
        path_type_from_sql_text(type_str), &blob_oid,
        mode, owner, group, encrypted != 0, lifecycle, &entry
    );

    if (err) return err;

    *out = entry;
    return NULL;
}

error_t *state_get_file_by_storage(
    const state_t *state,
    const char *storage_path,
    state_entry_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_get_file_by_storage);

    sqlite3_stmt *stmt = state->stmt_get_file_by_storage;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, storage_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            return ERROR(
                ERR_NOT_FOUND, "File not found in manifest: %s", storage_path
            );
        }
        return sqlite_error(state->db, "Failed to query file by storage path");
    }

    /* Extract columns. Layout matches sql_get_by_storage (same shape as
     * state_get_file but column 0 is filesystem_path, not storage_path):
     *   0-2:  filesystem_path, profile, old_profile  (identity; storage_path is WHERE)
     *   3-9:  blob_oid, type, mode, owner, group, encrypted, state */
    const char *filesystem_path = (const char *) sqlite3_column_text(stmt, 0);
    const char *profile = (const char *) sqlite3_column_text(stmt, 1);
    const char *old_profile = (const char *) sqlite3_column_text(stmt, 2);

    /* Read path trusts sqlite3's schema enforcement: BLOB NOT NULL means non-NULL,
     * and our own bind path is the only writer so length is always GIT_OID_RAWSZ. */
    git_oid blob_oid;
    memcpy(blob_oid.id, sqlite3_column_blob(stmt, 3), GIT_OID_RAWSZ);

    const char *type_str = (const char *) sqlite3_column_text(stmt, 4);

    mode_t mode = 0;
    if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
        mode = (mode_t) sqlite3_column_int(stmt, 5);
    }

    const char *owner = (const char *) sqlite3_column_text(stmt, 6);
    const char *group = (const char *) sqlite3_column_text(stmt, 7);
    int encrypted = sqlite3_column_int(stmt, 8);
    state_lifecycle_t lifecycle = lifecycle_from_sql_text(
        (const char *) sqlite3_column_text(stmt, 9)
    );

    if (!filesystem_path || !profile || !type_str) {
        return ERROR(
            ERR_STATE_INVALID,
            "NULL value in required column for storage path: %s", storage_path
        );
    }

    state_entry_t *entry = NULL;
    error_t *err = state_create_entry(
        storage_path, filesystem_path, profile, old_profile,
        path_type_from_sql_text(type_str), &blob_oid,
        mode, owner, group, encrypted != 0, lifecycle, &entry
    );

    if (err) return err;

    *out = entry;
    return NULL;
}

/**
 * Count manifest entries belonging to a profile
 *
 * Pure SQL aggregate; index-backed by idx_manifest_profile. Counts every
 * lifecycle state — callers needing a sub-state count must run their own
 * query.
 */
error_t *state_count_files_by_profile(
    const state_t *state,
    const char *profile,
    size_t *out_count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(out_count);

    *out_count = 0;

    /* Empty state (no DB file) — zero rows by definition. */
    if (!state->db) return NULL;

    const char *sql =
        "SELECT COUNT(*) FROM virtual_manifest WHERE profile = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare profile-count query");
    }

    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_STATIC);

    error_t *err = NULL;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_count = (size_t) sqlite3_column_int64(stmt, 0);
    } else {
        err = sqlite_error(state->db, "Failed to count files for profile");
    }

    sqlite3_finalize(stmt);
    return err;
}

error_t *state_get_distinct_file_profiles(
    const state_t *state,
    string_array_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    *out = NULL;

    string_array_t *profiles = string_array_new(0);
    if (!profiles) {
        return ERROR(ERR_MEMORY, "Failed to allocate distinct-profiles array");
    }

    /* Empty state (no DB file) — no profiles, success with empty array. */
    if (!state->db) {
        *out = profiles;
        return NULL;
    }

    const char *sql =
        "SELECT DISTINCT profile FROM virtual_manifest;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        string_array_free(profiles);
        return sqlite_error(state->db, "Failed to prepare distinct-profiles query");
    }

    error_t *err = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char *) sqlite3_column_text(stmt, 0);
        if (!name) continue;  /* defensive: profile is NOT NULL in schema */

        err = string_array_push(profiles, name);
        if (err) {
            err = error_wrap(err, "Failed to record distinct profile");
            break;
        }
    }

    if (!err && rc != SQLITE_DONE) {
        err = sqlite_error(state->db, "Failed to enumerate distinct profiles");
    }

    sqlite3_finalize(stmt);

    if (err) {
        string_array_free(profiles);
        return err;
    }

    *out = profiles;
    return NULL;
}

/**
 * Count active encrypted manifest entries
 *
 * The state literal 'active' is inlined to match the schema's CHECK
 * constraint vocabulary and the equivalent literal at the
 * state_get_file_by_storage query.
 */
error_t *state_count_encrypted_files(
    const state_t *state,
    size_t *out_count
) {
    CHECK_NULL(state);
    CHECK_NULL(out_count);

    *out_count = 0;

    if (!state->db) return NULL;

    const char *sql =
        "SELECT COUNT(*) FROM virtual_manifest "
        "WHERE encrypted = 1 AND state = 'active';";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare encrypted-count query");
    }

    error_t *err = NULL;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_count = (size_t) sqlite3_column_int64(stmt, 0);
    } else {
        err = sqlite_error(state->db, "Failed to count encrypted files");
    }

    sqlite3_finalize(stmt);
    return err;
}

/**
 * Get all file entries
 *
 * Returns allocated array via the caller's arena. Lifetime is tied to the
 * arena: caller controls cleanup by destroying the arena.
 *
 * This change is necessary because SQLite implementation doesn't keep
 * all files in memory.
 *
 * @param state State (must not be NULL)
 * @param arena Arena for allocations (must not be NULL)
 * @param out Output array (must not be NULL, lifetime tied to arena)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_files(
    const state_t *state,
    arena_t *arena,
    state_entry_t **out,
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

    /* Count files first (avoid double iteration) */
    const char *sql_count = "SELECT COUNT(*) FROM virtual_manifest;";
    sqlite3_stmt *stmt_count = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql_count, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare count query");
    }

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count files");
    }

    size_t file_count = (size_t) sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (file_count == 0) {
        return NULL;  /* Success, no files */
    }

    /* Allocate array */
    state_entry_t *entries = arena_calloc(arena, file_count, sizeof(state_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate file array");
    }

    /* Helper macros: route allocations through arena */
    #define DUP(s)      arena_strdup(arena, (s))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Query all files (11 columns: 4 identity + 7 VWD cache) */
    const char *sql_files =
        "SELECT filesystem_path, storage_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state "
        "FROM virtual_manifest ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_files, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare select query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < file_count) {
        /* Column layout matches sql_files:
         *   0-3:  identity (filesystem_path, storage_path, profile, old_profile)
         *   4-10: VWD cache (blob_oid, type, mode, owner, group, encrypted, state) */
        manifest_row_t *row = &entries[i].row;

        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile = (const char *) sqlite3_column_text(stmt, 2);
        const char *old_profile = (const char *) sqlite3_column_text(stmt, 3);

        /* Read binary blob_oid directly into the row (no intermediate allocation). */
        memcpy(row->blob_oid.id, sqlite3_column_blob(stmt, 4), GIT_OID_RAWSZ);

        const char *type_str = (const char *) sqlite3_column_text(stmt, 5);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            mode = (mode_t) sqlite3_column_int(stmt, 6);
        }

        const char *owner = (const char *) sqlite3_column_text(stmt, 7);
        const char *group = (const char *) sqlite3_column_text(stmt, 8);
        int encrypted = sqlite3_column_int(stmt, 9);
        const char *state_str = (const char *) sqlite3_column_text(stmt, 10);

        /* Validate non-nullable string columns (OIDs already validated above) */
        if (!fs_path || !storage_path || !profile || !type_str) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings into arena */
        row->filesystem_path = DUP(fs_path);
        row->storage_path = DUP(storage_path);
        row->profile = DUP(profile);
        row->mode = mode;
        row->owner = DUP_OPT(owner);
        row->group = DUP_OPT(group);
        row->type = path_type_from_sql_text(type_str);
        row->encrypted = (encrypted != 0);

        /* The two cached answers beside the row */
        entries[i].lifecycle = lifecycle_from_sql_text(state_str);
        entries[i].old_profile = DUP_OPT(old_profile);

        /* Check allocation success */
        if (!row->filesystem_path || !row->storage_path || !row->profile) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_MEMORY, "Failed to copy entry strings");
        }

        i++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to query files");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

/**
 * Add or refresh a tracked directory (projection writer)
 *
 * UPSERT: activates the row — see the SQL comment on sql_insert_dir and
 * the header contract for semantics.
 *
 * @param state State (must not be NULL)
 * @param row Directory row (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_directory(state_t *state, const manifest_row_t *row) {
    CHECK_NULL(state);
    CHECK_NULL(row);
    CHECK_NULL(row->filesystem_path);
    CHECK_NULL(row->storage_path);
    CHECK_NULL(row->profile);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_insert_directory);

    sqlite3_stmt *stmt = state->stmt_insert_directory;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind parameters. state is not bound: 'active' is hardcoded in the
     * SQL (projection means in-scope). */
    sqlite3_bind_text(stmt, 1, row->filesystem_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, row->storage_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, row->profile, -1, SQLITE_STATIC);

    /* Mode (optional) */
    if (row->mode > 0) {
        sqlite3_bind_int(stmt, 4, row->mode);
    } else {
        sqlite3_bind_null(stmt, 4);
    }

    /* Owner (optional) */
    if (row->owner) {
        sqlite3_bind_text(stmt, 5, row->owner, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    /* Group (optional) */
    if (row->group) {
        sqlite3_bind_text(stmt, 6, row->group, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to insert directory");
    }

    return NULL;
}

/**
 * Get all tracked directories
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
error_t *state_get_all_directories(
    const state_t *state,
    arena_t *arena,
    state_entry_t **out,
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

    /* Count directories first (avoid realloc, required for arena allocation) */
    const char *sql_count = "SELECT COUNT(*) FROM tracked_directories;";
    sqlite3_stmt *stmt_count = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql_count, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare directory count query");
    }

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count directories");
    }

    size_t dir_count = (size_t) sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (dir_count == 0) {
        return NULL;  /* Success, no directories */
    }

    /* Allocate array */
    state_entry_t *entries = arena_calloc(arena, dir_count, sizeof(state_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate directories array");
    }

    /* Helper macros: route allocations through arena */
    #define DUP(s)      arena_strdup(arena, (s))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Local prepare+finalize: this is a single-pass, full-table scan run once
     * per workspace_load. Caching the statement on the handle would buy nothing
     * — see state_get_all_files for the same pattern. */
    const char *sql_dirs =
        "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state "
        "FROM tracked_directories ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_dirs, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare directory query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < dir_count) {
        manifest_row_t *row = &entries[i].row;

        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile = (const char *) sqlite3_column_text(stmt, 2);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            mode = (mode_t) sqlite3_column_int(stmt, 3);
        }

        const char *owner = (const char *) sqlite3_column_text(stmt, 4);
        const char *group = (const char *) sqlite3_column_text(stmt, 5);
        const char *state_str = (const char *) sqlite3_column_text(stmt, 6);

        /* Validate non-nullable columns */
        if (!fs_path || !storage || !profile) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings into arena. A directory row has no blob (zero by
         * calloc), no encryption flag, no old_profile. */
        row->filesystem_path = DUP(fs_path);
        row->storage_path = DUP(storage);
        row->profile = DUP(profile);
        row->type = PATH_TYPE_DIRECTORY;
        row->mode = mode;
        row->owner = DUP_OPT(owner);
        row->group = DUP_OPT(group);
        entries[i].lifecycle = lifecycle_from_sql_text(state_str);

        /* Check allocation success */
        if (!row->filesystem_path || !row->storage_path || !row->profile) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_MEMORY, "Failed to copy directory entry strings");
        }

        i++;
    }

    sqlite3_finalize(stmt);

    /* Strict post-loop check: the dir_count guard plus our locking discipline
     * (single connection, no concurrent writer between COUNT and SELECT) makes
     * SQLITE_ROW unreachable here. Mirrors state_get_all_files. */
    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to query directories");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

/* Ghost reclaim, one table each. Cold path (one call per scope transition):
 * a one-shot exec beats a prepared-statement roster entry, and the literal
 * statement is worth more than de-duplicating one WHERE clause. "Never
 * observed" is the absence of a record: the subquery is the same fact the
 * engine's attribution reads from its anchors snapshot. */
error_t *state_reclaim_unmaterialized_files(state_t *state) {
    CHECK_NULL(state);

    /* Empty state (no DB file) — nothing to reclaim, success. */
    if (!state->db) return NULL;

    char *errmsg = NULL;
    int rc = sqlite3_exec(
        state->db,
        "DELETE FROM virtual_manifest WHERE state != 'active' "
        "AND filesystem_path NOT IN (SELECT filesystem_path FROM anchors);",
        NULL, NULL, &errmsg
    );
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to reclaim unmaterialized file rows: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
}

error_t *state_reclaim_unmaterialized_directories(state_t *state) {
    CHECK_NULL(state);

    /* Empty state (no DB file) — nothing to reclaim, success. */
    if (!state->db) return NULL;

    char *errmsg = NULL;
    int rc = sqlite3_exec(
        state->db,
        "DELETE FROM tracked_directories WHERE state != 'active' "
        "AND filesystem_path NOT IN (SELECT filesystem_path FROM anchors);",
        NULL, NULL, &errmsg
    );
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to reclaim unmaterialized directory rows: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
}

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
error_t *state_remove_directory(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_remove_directory);

    sqlite3_stmt *stmt = state->stmt_remove_directory;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to remove directory");
    }

    return NULL;
}

/**
 * Mark all ACTIVE directories as inactive
 *
 * Bulk operation for the manifest layer's directory sweep.
 *
 * Only LIFECYCLE_ACTIVE rows are downgraded to LIFECYCLE_INACTIVE.
 * LIFECYCLE_DELETED is preserved: it records a deletion dotta itself
 * ordered (remove --delete-files), intent that must survive a sweep the
 * rebuild runs on every projection. Directory rows carry no
 * LIFECYCLE_RELEASED — see the state_lifecycle_t vocabulary note.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_mark_all_directories_inactive(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_mark_all_directories_inactive);

    sqlite3_stmt *stmt = state->stmt_mark_all_directories_inactive;
    sqlite3_reset(stmt);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to mark all directories as inactive");
    }

    return NULL;
}

/* Build a "?,?,...,?" placeholder list for SQL IN clauses.
 *
 * Writes the placeholder string into buf (null-terminated) and returns its
 * length. Returns -1 on overflow or on n == 0. Each placeholder consumes
 * 2 bytes (',?') except the first (1 byte '?'). For state-set IN clauses the
 * bound is small (at most 4 lifecycle values), so a 64-byte buffer is ample */
static int build_in_placeholders(char *buf, size_t bufsz, size_t n) {
    if (n == 0 || bufsz == 0) return -1;
    size_t pos = 0;
    for (size_t i = 0; i < n; i++) {
        size_t need = (i == 0) ? 1 : 2;
        if (pos + need + 1 > bufsz) return -1;
        if (i > 0) buf[pos++] = ',';
        buf[pos++] = '?';
    }
    buf[pos] = '\0';
    return (int) pos;
}

/* Bulk DELETE on a per-profile lifecycle-set, shared by file and directory
 * primitives. Uses an index-backed query (idx_manifest_profile or
 * idx_tracked_directories_profile). The table parameter is a code-controlled
 * constant — never user input — so SQL injection is not a concern.
 *
 * The records of the rows about to go retire with them, by the same
 * predicate as a subquery, ahead of the row delete: a purge is a release
 * ("the deployed copy is left where it is") and a released path keeps no
 * record. Without it the anchors of a deleted profile's released files
 * would outlive every row that could name them.
 *
 * Returns rows-affected via *out_purged when provided. Empty DB and unknown
 * profile both yield zero rows-affected with no error. Empty lifecycle-set
 * is a caller bug (ERR_INVALID_ARG). */
static error_t *bulk_purge_by_profile(
    state_t *state,
    const char *table,
    const char *profile,
    const state_lifecycle_t *lifecycles,
    size_t lifecycle_count,
    size_t *out_purged
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(lifecycles);

    if (out_purged) *out_purged = 0;

    /* Empty state (no DB file) — nothing to delete, success. */
    if (!state->db) return NULL;

    if (lifecycle_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "bulk purge requires at least one lifecycle value"
        );
    }

    char placeholders[64];
    if (build_in_placeholders(placeholders, sizeof(placeholders), lifecycle_count) < 0) {
        return ERROR(
            ERR_INTERNAL,
            "Too many lifecycle values for bulk purge (got %zu)", lifecycle_count
        );
    }

    /* Two statements, one WHERE: the records first (a subquery over the
     * rows the second statement deletes), then the rows. */
    char sql_retire[320];
    int n = snprintf(
        sql_retire, sizeof(sql_retire),
        "DELETE FROM anchors WHERE filesystem_path IN "
        "(SELECT filesystem_path FROM %s WHERE profile = ? AND state IN (%s));",
        table, placeholders
    );
    if (n < 0 || (size_t) n >= sizeof(sql_retire)) {
        return ERROR(ERR_INTERNAL, "SQL buffer overflow building bulk purge");
    }

    char sql[256];
    n = snprintf(
        sql, sizeof(sql), "DELETE FROM %s WHERE profile = ? AND state IN (%s);",
        table, placeholders
    );
    if (n < 0 || (size_t) n >= sizeof(sql)) {
        return ERROR(ERR_INTERNAL, "SQL buffer overflow building bulk purge");
    }

    const char *statements[] = { sql_retire, sql };
    int changes = 0;

    for (size_t k = 0; k < 2; k++) {
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(state->db, statements[k], -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(state->db, "Failed to prepare bulk purge");
        }

        sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);
        for (size_t i = 0; i < lifecycle_count; i++) {
            sqlite3_bind_text(
                stmt, (int) (i + 2), lifecycle_to_sql_text(lifecycles[i]), -1, SQLITE_STATIC
            );
        }

        rc = sqlite3_step(stmt);
        changes = sqlite3_changes(state->db);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            return sqlite_error(state->db, "Failed to execute bulk purge");
        }
    }

    /* The count reported is the rows', from the second statement. */
    if (out_purged) *out_purged = (size_t) changes;

    return NULL;
}

/* Bulk UPDATE on a per-profile lifecycle-set, shared by file and directory
 * primitives. Vocabulary correctness is enforced by the type system; the
 * directory-only LIFECYCLE_RELEASED rejection lives at the public-facing
 * directory wrapper (state_transition_directories_by_profile). */
static error_t *bulk_transition_by_profile(
    state_t *state,
    const char *table,
    const char *profile,
    const state_lifecycle_t *from_lifecycles,
    size_t from_count,
    state_lifecycle_t new_lifecycle,
    size_t *out_changed
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(from_lifecycles);

    if (out_changed) *out_changed = 0;

    if (!state->db) return NULL;

    if (from_count == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "bulk transition requires at least one source lifecycle value"
        );
    }

    char placeholders[64];
    if (build_in_placeholders(placeholders, sizeof(placeholders), from_count) < 0) {
        return ERROR(
            ERR_INTERNAL,
            "Too many lifecycle values for bulk transition (got %zu)", from_count
        );
    }

    char sql[256];
    int n = snprintf(
        sql, sizeof(sql), "UPDATE %s SET state = ? WHERE profile = ? AND state IN (%s);",
        table, placeholders
    );
    if (n < 0 || (size_t) n >= sizeof(sql)) {
        return ERROR(ERR_INTERNAL, "SQL buffer overflow building bulk transition");
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare bulk transition");
    }

    sqlite3_bind_text(stmt, 1, lifecycle_to_sql_text(new_lifecycle), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, profile, -1, SQLITE_TRANSIENT);
    for (size_t i = 0; i < from_count; i++) {
        sqlite3_bind_text(
            stmt, (int) (i + 3), lifecycle_to_sql_text(from_lifecycles[i]), -1, SQLITE_STATIC
        );
    }

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(state->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to execute bulk transition");
    }

    if (out_changed) *out_changed = (size_t) changes;

    return NULL;
}

error_t *state_purge_directories_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *lifecycles,
    size_t lifecycle_count,
    size_t *out_purged
) {
    return bulk_purge_by_profile(
        state, "tracked_directories", profile,
        lifecycles, lifecycle_count, out_purged
    );
}

error_t *state_transition_directories_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *from_lifecycles,
    size_t from_count,
    state_lifecycle_t new_lifecycle,
    size_t *out_changed
) {
    /* Directory rows do not carry LIFECYCLE_RELEASED (no Git blob identity);
     * this is the sole write boundary that rejects it. */
    if (new_lifecycle == LIFECYCLE_RELEASED) {
        return ERROR(
            ERR_INVALID_ARG,
            "LIFECYCLE_RELEASED is not valid for directory entries"
        );
    }

    return bulk_transition_by_profile(
        state, "tracked_directories", profile,
        from_lifecycles, from_count, new_lifecycle, out_changed
    );
}

/**
 * Load state from repository (read-only)
 *
 * If database doesn't exist, returns empty state.
 * No transaction started - safe for concurrent reads.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_load(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *state = NULL;
    sqlite3 *db = NULL;

    /* Get database path */
    char *db_path = NULL;
    err = get_db_path(repo, &db_path);
    if (err) return err;

    /* Open database (don't create if missing) */
    err = open_db(db_path, false, &db);
    if (err) {
        free(db_path);
        return err;
    }

    /* Allocate the handle whether or not the DB exists. When the file is
     * absent, state->db stays NULL while state->db_path is retained so a
     * later state_begin() can lazily create the DB — honoring the
     * READ → scoped-write contract advertised by dotta_state_mode
     * (runtime.h::dotta_state_mode_t). Reads short-circuit through
     * load_profile_entries on the profile_entries_loaded flag set below;
     * zero rows is the correct view of a never-initialized state. */
    state = calloc(1, sizeof(state_t));
    if (!state) {
        if (db) sqlite3_close(db);
        free(db_path);
        return ERROR(ERR_MEMORY, "Failed to allocate state");
    }

    state->db = db;                        /* may be NULL */
    state->db_path = db_path;              /* owned; freed by state_free */
    state->in_transaction = false;
    state->profile_entries = NULL;
    state->profile_entry_count = 0;
    state->profile_entries_loaded = (db == NULL);

    if (db) {
        /* Prepare statements only when a live connection exists. On lazy
         * promotion, state_begin() runs the same prepare_statements() call
         * before taking BEGIN IMMEDIATE. */
        err = prepare_statements(state);
        if (err) {
            sqlite3_close(state->db);
            state->db = NULL;
            free(state->db_path);
            free(state);
            return err;
        }
    }

    *out = state;
    return NULL;
}

/**
 * Load state for update (with transaction)
 *
 * Opens database with write lock (BEGIN IMMEDIATE transaction).
 * Creates database if it doesn't exist.
 *
 * @param repo Repository (must not be NULL)
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_open(git_repository *repo, state_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *state = NULL;
    sqlite3 *db = NULL;

    /* Get database path */
    char *db_path = NULL;
    err = get_db_path(repo, &db_path);
    if (err) return err;

    /* Open database (create if missing) */
    err = open_db(db_path, true, &db);
    if (err) {
        free(db_path);
        return err;
    }

    /* Allocate state */
    state = calloc(1, sizeof(state_t));
    if (!state) {
        sqlite3_close(db);
        free(db_path);
        return ERROR(ERR_MEMORY, "Failed to allocate state");
    }

    state->db = db;
    state->db_path = db_path;
    state->in_transaction = false;
    state->profile_entries = NULL;
    state->profile_entry_count = 0;
    state->profile_entries_loaded = false;

    /* Prepare statements */
    err = prepare_statements(state);
    if (err) {
        sqlite3_close(db);
        free(db_path);
        free(state);
        return err;
    }

    /* Begin transaction - acquire write lock NOW */
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        err = ERROR(
            ERR_CONFLICT, "Failed to acquire write lock: %s\n"
            "Another process may be writing to the database",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        finalize_statements(state);
        sqlite3_close(db);
        free(db_path);
        free(state);
        return err;
    }

    state->in_transaction = true;

    *out = state;
    return NULL;
}

/**
 * Save state to repository
 *
 * Commits the transaction started by state_open() if one is active.
 * Safe on any handle shape: a state_load() handle for a repository
 * without .git/dotta.db that was never promoted via state_begin
 * holds no connection (state->db == NULL), and the guard below makes
 * save a no-op for it.
 *
 * @param repo Repository (must not be NULL)
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(git_repository *repo, state_t *state) {
    CHECK_NULL(repo);
    CHECK_NULL(state);

    if (state->db && state->in_transaction) {
        char *errmsg = NULL;
        int rc = sqlite3_exec(state->db, "COMMIT;", NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            error_t *err = ERROR(
                ERR_STATE_INVALID, "Failed to commit transaction: %s",
                errmsg ? errmsg : sqlite3_errstr(rc)
            );
            sqlite3_free(errmsg);
            return err;
        }

        state->in_transaction = false;
    }

    return NULL;
}

/**
 * Begin an explicit transaction on a state handle
 *
 * Post-condition on success: state->db is open and write-locked
 * (BEGIN IMMEDIATE held). Mirrors state_open()'s create semantics,
 * deferred to the moment of actual write intent — see the lazy
 * promotion block below.
 */
error_t *state_begin(state_t *state) {
    CHECK_NULL(state);

    if (state->in_transaction) {
        return ERROR(ERR_STATE_INVALID, "Transaction already active");
    }

    /* Lazy promotion: a state_load() on a repository with no
     * .git/dotta.db leaves this handle with state->db == NULL but
     * state->db_path populated. Create the DB on first write attempt
     * to honor the READ → scoped-write contract documented in
     * runtime.h::dotta_state_mode_t — matching state_open()'s create
     * semantics, just deferred to the moment of actual mutation.
     *
     * The profile_entries_loaded=true cached zero-row view (set by
     * state_load's empty branch) remains accurate against the
     * freshly-created empty schema; the first mutating call
     * (state_reorder_profiles / state_enable_profile / state_disable_profile)
     * invalidates the cache on its own per the existing discipline. */
    if (!state->db) {
        if (!state->db_path) {
            return ERROR(
                ERR_STATE_INVALID,
                "Cannot begin transaction: state has no database path"
            );
        }

        sqlite3 *db = NULL;
        error_t *err = open_db(state->db_path, true, &db);
        if (err) return err;
        state->db = db;

        err = prepare_statements(state);
        if (err) {
            sqlite3_close(state->db);
            state->db = NULL;
            return err;
        }
    }

    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_CONFLICT, "Failed to acquire write lock: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    state->in_transaction = true;
    return NULL;
}

/**
 * Commit a transaction started by state_begin()
 */
error_t *state_commit(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    if (!state->in_transaction) {
        return ERROR(ERR_STATE_INVALID, "No active transaction to commit");
    }

    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "COMMIT;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to commit transaction: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    state->in_transaction = false;
    return NULL;
}

/**
 * Roll back a transaction started by state_begin()
 *
 * Invalidates the row cache defensively: mutation paths already invalidate
 * before returning, so the cache should be consistent with the DB heading
 * into rollback — but any future author who forgets the discipline would
 * otherwise leave a stale cache behind. Invalidation is O(row_count) and
 * the next peek repopulates from the rolled-back DB state.
 */
void state_rollback(state_t *state) {
    if (!state || !state->db || !state->in_transaction) {
        return;
    }

    sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
    state->in_transaction = false;
    invalidate_profile_entries(state);
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
 * Automatically rolls back transaction if not committed.
 * Closes database and frees all memory.
 *
 * @param state State to free (can be NULL)
 */
void state_free(state_t *state) {
    if (!state) {
        return;
    }

    /* Rollback if transaction still active (error path cleanup) */
    if (state->in_transaction && state->db) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        state->in_transaction = false;
    }

    /* Finalize prepared statements */
    finalize_statements(state);

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
    invalidate_profile_entries(state);
    free(state);
}

/**
 * Create file entry
 *
 * Helper function to allocate and initialize a file entry: the row from
 * the identity and VWD-cache arguments, the lifecycle and old_profile
 * beside it.
 *
 * @param storage_path Storage path (must not be NULL)
 * @param filesystem_path Filesystem path (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param old_profile Previous profile (can be NULL)
 * @param type File type
 * @param blob_oid Blob OID for content identity (must not be NULL, copied)
 * @param mode Permission mode (can be NULL)
 * @param owner Owner username (can be NULL)
 * @param group Group name (can be NULL)
 * @param encrypted Encryption flag
 * @param state_value Lifecycle state (can be NULL for STATE_ACTIVE default)
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
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    state_entry_t *entry = calloc(1, sizeof(state_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate entry");
    }

    manifest_row_t *row = &entry->row;

    /* Copy required string fields */
    row->storage_path = strdup(storage_path);
    row->filesystem_path = strdup(filesystem_path);
    row->profile = strdup(profile);

    /* Copy binary blob OID (20 bytes, no allocation) */
    git_oid_cpy(&row->blob_oid, blob_oid);

    /* Copy optional string fields */
    entry->old_profile = old_profile ? strdup(old_profile) : NULL;
    row->owner = owner ? strdup(owner) : NULL;
    row->group = group ? strdup(group) : NULL;

    /* Set non-string fields */
    row->mode = mode;
    row->type = type;
    row->encrypted = encrypted;
    entry->lifecycle = lifecycle;

    /* Validate required allocations */
    if (!row->storage_path || !row->filesystem_path || !row->profile) {
        state_free_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Get every anchor, in filesystem_path order
 *
 * Count, allocate, one full-table SELECT — the same local prepare+finalize
 * shape as state_get_all_files, for the same reason: a single-pass scan
 * run once per workspace_load gains nothing from a cached statement.
 */
error_t *state_get_all_anchors(
    const state_t *state,
    arena_t *arena,
    anchor_t **out,
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

    /* Count first (arena allocation wants the size up front) */
    const char *sql_count = "SELECT COUNT(*) FROM anchors;";
    sqlite3_stmt *stmt_count = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql_count, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare anchor count query");
    }

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count anchors");
    }

    size_t anchor_count = (size_t) sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (anchor_count == 0) {
        return NULL;  /* Success, no anchors */
    }

    /* Allocate array */
    anchor_t *anchors = arena_calloc(arena, anchor_count, sizeof(anchor_t));
    if (!anchors) {
        return ERROR(ERR_MEMORY, "Failed to allocate anchors array");
    }

    /* Helper macros: route allocations through arena */
    #define DUP(s)      arena_strdup(arena, (s))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* The one read (14 columns: 3 identity + 4 metadata + 7 record) */
    const char *sql_anchors =
        "SELECT filesystem_path, storage_path, profile, type, mode, owner, \"group\", "
        "blob_oid, stat_mtime, stat_size, stat_ino, observed_at, deployed_at, prune_ordered "
        "FROM anchors ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_anchors, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare anchors query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < anchor_count) {
        /* Column layout matches sql_anchors:
         *   0-2:  identity (filesystem_path, storage_path, profile)
         *   3-6:  what dotta set (type, mode, owner, group)
         *   7-13: what dotta confirmed (blob_oid, stat_mtime, stat_size,
         *         stat_ino, observed_at, deployed_at, prune_ordered) */
        anchor_t *anchor = &anchors[i];

        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile = (const char *) sqlite3_column_text(stmt, 2);
        const char *type_str = (const char *) sqlite3_column_text(stmt, 3);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
            mode = (mode_t) sqlite3_column_int(stmt, 4);
        }

        const char *owner = (const char *) sqlite3_column_text(stmt, 5);
        const char *group = (const char *) sqlite3_column_text(stmt, 6);

        /* A NULL blob (a directory, or observed only) hydrates to the zero
         * OID calloc left; a stored blob is 20 bytes by CHECK. */
        if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
            memcpy(anchor->blob_oid.id, sqlite3_column_blob(stmt, 7), GIT_OID_RAWSZ);
        }

        /* Validate non-nullable string columns */
        if (!fs_path || !storage_path || !profile || !type_str) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at anchor %zu", i);
        }

        /* Copy strings into arena */
        anchor->filesystem_path = DUP(fs_path);
        anchor->storage_path = DUP(storage_path);
        anchor->profile = DUP(profile);
        anchor->type = path_type_from_sql_text(type_str);
        anchor->mode = mode;
        anchor->owner = DUP_OPT(owner);
        anchor->group = DUP_OPT(group);
        anchor->stat = (stat_cache_t){
            .mtime = sqlite3_column_int64(stmt, 8),
            .size = sqlite3_column_int64(stmt, 9),
            .ino = (uint64_t) sqlite3_column_int64(stmt, 10),
        };
        anchor->observed_at = (time_t) sqlite3_column_int64(stmt, 11);
        anchor->deployed_at = (time_t) sqlite3_column_int64(stmt, 12);
        anchor->prune_ordered = (sqlite3_column_int(stmt, 13) != 0);

        /* Check allocation success */
        if (!anchor->filesystem_path || !anchor->storage_path || !anchor->profile) {
            sqlite3_finalize(stmt);
            return ERROR(ERR_MEMORY, "Failed to copy anchor strings");
        }

        i++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to query anchors");
    }

    #undef DUP
    #undef DUP_OPT

    *out = anchors;
    *count = i;

    return NULL;
}

/**
 * Bind a row's identity and metadata as placeholders ?1-?7
 *
 * The shared prefix of sql_observe and sql_anchor: filesystem_path,
 * storage_path, profile, type, mode, owner, group — the columns a record
 * takes from the row it is written from. Both statements lay their
 * placeholders out to start this way so one bind sequence serves both.
 */
static void bind_row(sqlite3_stmt *stmt, const manifest_row_t *row) {
    /* 1-3. filesystem_path, storage_path, profile */
    sqlite3_bind_text(stmt, 1, row->filesystem_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, row->profile, -1, SQLITE_TRANSIENT);

    /* 4. type */
    sqlite3_bind_text(stmt, 4, path_type_to_sql_text(row->type), -1, SQLITE_STATIC);

    /* 5. mode (optional) */
    if (row->mode > 0) {
        sqlite3_bind_int(stmt, 5, row->mode);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    /* 6. owner (optional) */
    if (row->owner) {
        sqlite3_bind_text(stmt, 6, row->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    /* 7. group (optional) */
    if (row->group) {
        sqlite3_bind_text(stmt, 7, row->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 7);
    }
}

/**
 * Observe a managed path: record its first sighting on disk
 *
 * INSERT OR IGNORE — see the SQL comment on sql_observe and the header
 * contract. Binds the row's identity and metadata plus the stamp; the
 * blob and stat columns take their NULL / zero defaults, and an existing
 * row is left exactly as it was.
 */
error_t *state_observe(state_t *state, const manifest_row_t *row, time_t now) {
    CHECK_NULL(state);
    CHECK_NULL(row);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_observe);

    if (now <= 0) {
        return ERROR(ERR_INVALID_ARG, "Observation timestamp must be > 0");
    }

    sqlite3_stmt *stmt = state->stmt_observe;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    bind_row(stmt, row);

    /* 8. observed_at */
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64) now);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to record observation");
    }

    return NULL;
}

/**
 * Anchor a managed path: record the row dotta reconciled it against
 *
 * The sole writer of the record's content, metadata and ownership
 * columns. See state.h for the full contract. In brief:
 *   - row->blob_oid must be non-zero for a file row; a DIRECTORY row
 *     binds NULL.
 *   - own = true writes deployed_at = now; own = false keeps the
 *     existing timestamp (0 on a fresh row).
 *   - observed_at is the INSERT arm's alone.
 *   - stat is always written (zeros when NULL).
 *   - prune_ordered resets to 0.
 *
 * The SQL UPSERT encodes those rules and RETURNING projects the two
 * columns it decided. Callers that mirror an in-memory snapshot pass a
 * non-NULL resolved_out and assign it directly — the SQL is the single
 * specification, no C-side mirror of the rules exists.
 */
error_t *state_anchor(
    state_t *state,
    const manifest_row_t *row,
    const stat_cache_t *stat,
    time_t now,
    bool own,
    anchor_t *resolved_out
) {
    CHECK_NULL(state);
    CHECK_NULL(row);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_anchor);

    if (now <= 0) {
        return ERROR(ERR_INVALID_ARG, "Anchor timestamp must be > 0");
    }

    bool directory = (row->type == PATH_TYPE_DIRECTORY);

    /* A zero blob_oid on a file row would record "never confirmed" for a
     * path this call claims to have confirmed, and strand it in the stale
     * path. Reject rather than silently poison — and name the bug, where
     * the schema's CHECK would only refuse the zeroblob. */
    if (!directory && git_oid_is_zero(&row->blob_oid)) {
        return ERROR(
            ERR_STATE_INVALID,
            "state_anchor called with zero blob_oid for '%s'",
            row->filesystem_path
        );
    }

    sqlite3_stmt *stmt = state->stmt_anchor;

    /* Reset and bind */
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    bind_row(stmt, row);

    /* 8. blob_oid — 20 bytes for a file, NULL for a directory (no content
     * confirmation; the schema forbids a blob on a directory row). */
    if (directory) {
        sqlite3_bind_null(stmt, 8);
    } else {
        sqlite3_bind_blob(stmt, 8, row->blob_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT);
    }

    /* 9-11. stat triple (fast-path proof, bound to blob_oid; zeros when the
     * caller had none — the next read takes the slow path). */
    stat_cache_t triple = stat ? *stat : STAT_CACHE_UNSET;
    sqlite3_bind_int64(stmt, 9, triple.mtime);
    sqlite3_bind_int64(stmt, 10, triple.size);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64) triple.ino);

    /* 12. observed_at — consumed by the INSERT arm only.
     * 13. deployed_at — 0 keeps the existing stamp (a confirmation),
     *     now writes it (an ownership event). */
    sqlite3_bind_int64(stmt, 12, (sqlite3_int64) now);
    sqlite3_bind_int64(stmt, 13, (sqlite3_int64) (own ? now : 0));

    /* RETURNING yields exactly one row — an UPSERT always writes one — and
     * a single follow-up step drains to SQLITE_DONE. */
    int rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        if (resolved_out) {
            /* Every field the caller supplied, borrowed, plus the two
             * columns the SQL decided. Column layout matches the RETURNING
             * list: observed_at, deployed_at. */
            *resolved_out = (anchor_t){
                .filesystem_path = row->filesystem_path,
                .storage_path = row->storage_path,
                .profile = row->profile,
                .type = row->type,
                .mode = row->mode,
                .owner = row->owner,
                .group = row->group,
                .blob_oid = row->blob_oid,
                .stat = triple,
                .observed_at = (time_t) sqlite3_column_int64(stmt, 0),
                .deployed_at = (time_t) sqlite3_column_int64(stmt, 1),
                .prune_ordered = false,
            };
        }
        rc = sqlite3_step(stmt);
    }

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to anchor path");
    }

    return NULL;
}

/**
 * Retire a managed path's record
 *
 * DELETE by filesystem_path; a missing row is success (see the header
 * contract).
 */
error_t *state_retire_anchor(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_retire_anchor);

    sqlite3_stmt *stmt = state->stmt_retire_anchor;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to retire anchor");
    }

    return NULL;
}

/**
 * Order a managed path's deployed copy pruned
 *
 * UPDATE by filesystem_path; a missing row is success (see the header
 * contract).
 */
error_t *state_order_prune(state_t *state, const char *filesystem_path) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_order_prune);

    sqlite3_stmt *stmt = state->stmt_order_prune;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to order prune");
    }

    return NULL;
}

/**
 * Clear old_profile for a manifest entry
 *
 * Acknowledges profile reassignment after successful deployment.
 * Sets old_profile to NULL to clear the reassignment flag.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path File path (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_clear_old_profile(
    state_t *state,
    const char *filesystem_path
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);

    const char *sql = "UPDATE virtual_manifest SET old_profile = NULL WHERE filesystem_path = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare clear old_profile statement");
    }

    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to clear old_profile");
    }

    /* Check if row was actually updated */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in manifest", filesystem_path);
    }

    return NULL;
}

/**
 * Set file entry state (active/inactive/deleted/released)
 *
 * Updates the state column for a manifest entry. Used by manifest layer
 * to mark files for removal (inactive for staging, deleted for confirmed removal).
 *
 * Valid states:
 *   - LIFECYCLE_ACTIVE   - Normal entry, file is in scope
 *   - LIFECYCLE_INACTIVE - Staged for removal, reversible (profile disable)
 *   - LIFECYCLE_DELETED  - Confirmed deletion via remove command
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - filesystem_path MUST exist in virtual_manifest
 *   - new_state MUST be LIFECYCLE_ACTIVE, LIFECYCLE_INACTIVE, LIFECYCLE_DELETED, etc
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path File to update (must not be NULL)
 * @param new_state New state value (must not be NULL)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *state_set_file_state(
    state_t *state,
    const char *filesystem_path,
    state_lifecycle_t new_lifecycle
) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(filesystem_path);

    const char *sql = "UPDATE virtual_manifest SET state = ? WHERE filesystem_path = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare state update");
    }

    sqlite3_bind_text(stmt, 1, lifecycle_to_sql_text(new_lifecycle), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, filesystem_path, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update file state");
    }

    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in manifest", filesystem_path);
    }

    return NULL;
}

error_t *state_purge_files_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *lifecycles,
    size_t lifecycle_count,
    size_t *out_purged
) {
    return bulk_purge_by_profile(
        state, "virtual_manifest", profile,
        lifecycles, lifecycle_count, out_purged
    );
}

error_t *state_transition_files_by_profile(
    state_t *state,
    const char *profile,
    const state_lifecycle_t *from_lifecycles,
    size_t from_count,
    state_lifecycle_t new_lifecycle,
    size_t *out_changed
) {
    return bulk_transition_by_profile(
        state, "virtual_manifest", profile,
        from_lifecycles, from_count, new_lifecycle, out_changed
    );
}

/**
 * Set commit_oid for a profile in enabled_profiles
 *
 * Single-row UPDATE on enabled_profiles. Records the profile's current
 * branch HEAD as the last-synced commit.
 *
 * One caller: manifest_apply_scope, which writes the OID of the tree it
 * just projected for every enabled profile whose branch resolved.
 *
 * Cache discipline: this mutation patches the row cache *in place* rather
 * than invalidating it. Only the commit_oid field of the matching row
 * changes; name and target allocations are preserved. Callers
 * holding borrows obtained via state_peek_profile_target() or iterating
 * state_peek_profiles()[i].name survive this call without reloading —
 * see the lifetime contract in state.h. state_rollback remains the safety
 * net: a rolled-back transaction discards the optimistic patch along with
 * the uncommitted row.
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
) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(profile);
    CHECK_NULL(commit_oid);

    const char *sql = "UPDATE enabled_profiles SET commit_oid = ?1 WHERE name = ?2";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return ERROR(
            ERR_STATE_INVALID, "Failed to prepare commit_oid update: %s",
            sqlite3_errmsg(state->db)
        );
    }

    /* Bind parameters (20-byte BLOB for the OID column) */
    sqlite3_bind_blob(stmt, 1, commit_oid->id, GIT_OID_RAWSZ, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, profile, -1, SQLITE_TRANSIENT);

    /* Execute */
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return ERROR(
            ERR_STATE_INVALID, "Failed to set commit_oid for profile '%s': %s",
            profile, sqlite3_errmsg(state->db)
        );
    }

    /* In-place cache patch. Skipped when the cache isn't loaded yet — the
     * next peek will read the updated row from the DB. Skipped when the
     * profile is absent from the cache — the UPDATE matched zero rows, and
     * cache and DB already agree (both have no entry for this name). */
    if (state->profile_entries_loaded) {
        for (size_t i = 0; i < state->profile_entry_count; i++) {
            if (strcmp(state->profile_entries[i].name, profile) == 0) {
                git_oid_cpy(&state->profile_entries[i].commit_oid, commit_oid);
                break;
            }
        }
    }

    return NULL;
}

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->row.storage_path);
    free(entry->row.filesystem_path);
    free(entry->row.profile);
    free(entry->row.owner);
    free(entry->row.group);
    free(entry->old_profile);
    free(entry);
}
