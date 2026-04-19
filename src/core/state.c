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
#include "infra/path.h"
#include "sys/filesystem.h"

/* Schema version - must match database */
#define STATE_SCHEMA_VERSION "10"

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
    sqlite3_stmt *stmt_insert_file;         /* INSERT OR REPLACE virtual_manifest */
    sqlite3_stmt *stmt_update_anchor;       /* UPDATE virtual_manifest SET deployment anchor */
    sqlite3_stmt *stmt_remove_file;         /* DELETE FROM virtual_manifest */
    sqlite3_stmt *stmt_file_exists;         /* SELECT 1 FROM virtual_manifest */
    sqlite3_stmt *stmt_get_file;            /* SELECT * FROM virtual_manifest */
    sqlite3_stmt *stmt_get_file_by_storage; /* SELECT * WHERE storage_path = ? */
    sqlite3_stmt *stmt_get_by_profile;      /* SELECT * WHERE profile = ? */
    sqlite3_stmt *stmt_insert_profile;      /* INSERT INTO enabled_profiles */

    /* Directory prepared statements */
    sqlite3_stmt *stmt_insert_directory;           /* INSERT OR REPLACE tracked_directories */
    sqlite3_stmt *stmt_get_all_directories;        /* SELECT * FROM tracked_directories */
    sqlite3_stmt *stmt_get_directories_by_profile; /* SELECT * WHERE profile = ? */
    sqlite3_stmt *stmt_get_directory;              /* SELECT * WHERE filesystem_path = ? */
    sqlite3_stmt *stmt_update_directory;           /* UPDATE tracked_directories (preserves deployed_at) */
    sqlite3_stmt *stmt_remove_directory;           /* DELETE FROM tracked_directories */
    sqlite3_stmt *stmt_set_directory_state;        /* UPDATE tracked_directories SET state */
    sqlite3_stmt *stmt_mark_all_directories_inactive; /* UPDATE tracked_directories SET state = 'inactive' */
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
 * Initialize database schema
 *
 * Creates tables if they don't exist:
 * - schema_meta: Schema versioning
 * - enabled_profiles: User's profile management (with indexes)
 * - virtual_manifest: Deployed file manifest (with indexes)
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
        "    custom_prefix TEXT"
        ") STRICT;"

        /* Index for existence checks */
        "CREATE INDEX IF NOT EXISTS idx_enabled_name "
        "ON enabled_profiles(name);"

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
        "      CHECK(state IN ('active', 'inactive', 'deleted', 'released')),"
        "    "
        "    deployed_blob_oid BLOB NOT NULL DEFAULT (zeroblob(20)),"
        "    deployed_at INTEGER NOT NULL DEFAULT 0,"
        "    "
        "    stat_mtime INTEGER NOT NULL DEFAULT 0,"
        "    stat_size  INTEGER NOT NULL DEFAULT 0,"
        "    stat_ino   INTEGER NOT NULL DEFAULT 0"
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
        "      CHECK(state IN ('active', 'inactive', 'deleted')),"
        "    deployed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))"
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
 * Prepare all statements for state operations
 *
 * Called once per database connection. Statements are reused for all
 * operations, providing 100x speedup for bulk operations.
 *
 * @param state State (must not be NULL, db must be open)
 * @return Error or NULL on success
 */
static error_t *prepare_statements(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    int rc;

    /* Insert/update file (used by manifest sync operations - hot path)
     *
     * Column order mirrors the virtual_manifest layout:
     *   identity (1-4) | VWD cache (5-11) | deployment anchor (12-16)
     *
     * UPDATE-path field preservation (ON CONFLICT clause):
     *
     * VWD cache (storage_path, profile, blob_oid, type, mode, owner, group,
     * encrypted, state): always replaced from excluded — manifest operations
     * are the authoritative writer of this domain.
     *
     * old_profile: Three-branch CASE:
     *   1. Explicit non-NULL from caller — takes precedence (direct override)
     *   2. Profile changing, caller passes NULL — auto-captures current profile
     *      from the existing row (eliminates read-before-write for reassignment)
     *   3. Profile unchanged, caller passes NULL — preserves existing old_profile
     * Clearing is done separately via state_clear_old_profile().
     *
     * Deployment anchor (deployed_blob_oid, deployed_at, stat_*): on UPDATE
     * the existing anchor is preserved; this UPSERT is the sole entry point
     * for non-anchor writers (reconcile/sync/add/rebuild) and they MUST NOT
     * clobber the anchor. State_update_anchor is the only legitimate advancer.
     *
     * The preserve-on-zero-sentinel on deployed_blob_oid lets an INSERT that
     * establishes a never-confirmed row (zero-anchor) coexist with later
     * UPDATEs: a non-zero excluded.deployed_blob_oid would be a bug (writers
     * already go through state_update_anchor), so the CASE defensively
     * preserves. deployed_at and stat_* are unconditionally preserved on
     * UPDATE — anchor.deployed_at set on INSERT is the initial lifecycle
     * value (e.g., file existed when profile was enabled). */
    const char *sql_insert =
        "INSERT INTO virtual_manifest "
        "(filesystem_path, storage_path, profile, old_profile, "
        " blob_oid, type, mode, owner, \"group\", encrypted, state, "
        " deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(filesystem_path) DO UPDATE SET "
        "  storage_path = excluded.storage_path, "
        "  profile      = excluded.profile, "
        "  old_profile  = CASE "
        "                   WHEN excluded.old_profile IS NOT NULL "
        "                        THEN excluded.old_profile "
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
        "  state        = excluded.state, "
        "  deployed_blob_oid = CASE "
        "                        WHEN excluded.deployed_blob_oid = zeroblob(20) "
        "                          THEN virtual_manifest.deployed_blob_oid "
        "                        ELSE excluded.deployed_blob_oid "
        "                      END, "
        "  deployed_at  = virtual_manifest.deployed_at, "
        "  stat_mtime   = virtual_manifest.stat_mtime, "
        "  stat_size    = virtual_manifest.stat_size, "
        "  stat_ino     = virtual_manifest.stat_ino;";

    rc = sqlite3_prepare_v2(state->db, sql_insert, -1, &state->stmt_insert_file, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare insert statement");
    }

    /* Advance deployment anchor (sole writer of the anchor columns)
     *
     * Bind order (numbered placeholders):
     *   ?1 deployed_blob_oid
     *   ?2 deployed_at — reused in both CASE branches so the sentinel test
     *                    and the replacement value cannot drift apart
     *   ?3 stat_mtime
     *   ?4 stat_size
     *   ?5 stat_ino
     *   ?6 filesystem_path
     *
     * The CASE on deployed_at preserves the existing timestamp when the
     * caller passes 0 (first-observation / workspace-flush case) and writes
     * a new timestamp otherwise (apply post-deploy / adoption case). */
    const char *sql_update_anchor =
        "UPDATE virtual_manifest SET "
        "  deployed_blob_oid = ?1, "
        "  deployed_at       = CASE WHEN ?2 = 0 THEN deployed_at ELSE ?2 END, "
        "  stat_mtime        = ?3, "
        "  stat_size         = ?4, "
        "  stat_ino          = ?5 "
        "WHERE filesystem_path = ?6;";

    rc = sqlite3_prepare_v2(
        state->db, sql_update_anchor, -1, &state->stmt_update_anchor, NULL
    );
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        return sqlite_error(state->db, "Failed to prepare update anchor statement");
    }

    /* File exists check (used in status - hot path) */
    const char *sql_exists =
        "SELECT 1 FROM virtual_manifest WHERE filesystem_path = ? LIMIT 1;";

    rc = sqlite3_prepare_v2(state->db, sql_exists, -1, &state->stmt_file_exists, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        return sqlite_error(state->db, "Failed to prepare exists statement");
    }

    /* Get file (used in workspace analysis) */
    const char *sql_get =
        "SELECT storage_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state, "
        "deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino "
        "FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_get, -1, &state->stmt_get_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        sqlite3_finalize(state->stmt_file_exists);
        return sqlite_error(state->db, "Failed to prepare get statement");
    }

    /* Get file by storage path (used by profile discovery) */
    const char *sql_get_by_storage =
        "SELECT filesystem_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state, "
        "deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino "
        "FROM virtual_manifest WHERE storage_path = ? AND state = 'active' LIMIT 1;";

    rc = sqlite3_prepare_v2(
        state->db, sql_get_by_storage, -1, &state->stmt_get_file_by_storage, NULL
    );
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        return sqlite_error(state->db, "Failed to prepare get by storage statement");
    }

    /* Get entries by profile (used by profile disable) */
    const char *sql_by_profile =
        "SELECT filesystem_path, storage_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state, "
        "deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino "
        "FROM virtual_manifest WHERE profile = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_by_profile, -1, &state->stmt_get_by_profile, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        sqlite3_finalize(state->stmt_get_file_by_storage);
        return sqlite_error(state->db, "Failed to prepare get by profile statement");
    }

    /* Remove file (used in revert and cleanup) */
    const char *sql_remove =
        "DELETE FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_remove, -1, &state->stmt_remove_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        sqlite3_finalize(state->stmt_get_file_by_storage);
        sqlite3_finalize(state->stmt_get_by_profile);
        return sqlite_error(state->db, "Failed to prepare remove statement");
    }

    /* Insert profile (used in state_set_profiles) */
    const char *sql_profile =
        "INSERT INTO enabled_profiles (position, name, enabled_at, commit_oid, custom_prefix) "
        "VALUES (?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_profile, -1, &state->stmt_insert_profile, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_anchor);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        sqlite3_finalize(state->stmt_get_file_by_storage);
        sqlite3_finalize(state->stmt_get_by_profile);
        sqlite3_finalize(state->stmt_remove_file);
        return sqlite_error(state->db, "Failed to prepare profile statement");
    }

    return NULL;
}

/**
 * Finalize all prepared statements
 *
 * Called from state_free() before closing database.
 *
 * @param state State (can be NULL)
 */
static void finalize_statements(state_t *state) {
    if (!state) return;

    /* Manifest statements */
    if (state->stmt_insert_file) {
        sqlite3_finalize(state->stmt_insert_file);
        state->stmt_insert_file = NULL;
    }

    if (state->stmt_update_anchor) {
        sqlite3_finalize(state->stmt_update_anchor);
        state->stmt_update_anchor = NULL;
    }

    if (state->stmt_file_exists) {
        sqlite3_finalize(state->stmt_file_exists);
        state->stmt_file_exists = NULL;
    }

    if (state->stmt_get_file) {
        sqlite3_finalize(state->stmt_get_file);
        state->stmt_get_file = NULL;
    }

    if (state->stmt_get_file_by_storage) {
        sqlite3_finalize(state->stmt_get_file_by_storage);
        state->stmt_get_file_by_storage = NULL;
    }

    if (state->stmt_get_by_profile) {
        sqlite3_finalize(state->stmt_get_by_profile);
        state->stmt_get_by_profile = NULL;
    }

    if (state->stmt_remove_file) {
        sqlite3_finalize(state->stmt_remove_file);
        state->stmt_remove_file = NULL;
    }

    /* Profile statements */
    if (state->stmt_insert_profile) {
        sqlite3_finalize(state->stmt_insert_profile);
        state->stmt_insert_profile = NULL;
    }

    /* Directory statements */
    if (state->stmt_insert_directory) {
        sqlite3_finalize(state->stmt_insert_directory);
        state->stmt_insert_directory = NULL;
    }

    if (state->stmt_get_all_directories) {
        sqlite3_finalize(state->stmt_get_all_directories);
        state->stmt_get_all_directories = NULL;
    }

    if (state->stmt_get_directories_by_profile) {
        sqlite3_finalize(state->stmt_get_directories_by_profile);
        state->stmt_get_directories_by_profile = NULL;
    }

    if (state->stmt_get_directory) {
        sqlite3_finalize(state->stmt_get_directory);
        state->stmt_get_directory = NULL;
    }

    if (state->stmt_update_directory) {
        sqlite3_finalize(state->stmt_update_directory);
        state->stmt_update_directory = NULL;
    }

    if (state->stmt_remove_directory) {
        sqlite3_finalize(state->stmt_remove_directory);
        state->stmt_remove_directory = NULL;
    }

    if (state->stmt_set_directory_state) {
        sqlite3_finalize(state->stmt_set_directory_state);
        state->stmt_set_directory_state = NULL;
    }

    if (state->stmt_mark_all_directories_inactive) {
        sqlite3_finalize(state->stmt_mark_all_directories_inactive);
        state->stmt_mark_all_directories_inactive = NULL;
    }
}

/**
 * Free the row cache and mark it unloaded
 *
 * Safe to call repeatedly. Invoked by shape-mutating paths
 * (state_enable_profile, state_disable_profile, state_set_profiles) and by
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
        free(state->profile_entries[i].custom_prefix);
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
 * every row (name, custom_prefix, commit_oid) into the cache. Rows are
 * ordered by position to match the user's precedence order.
 *
 * The cache replaces four previous query-shape functions (get_prefix_map,
 * get_profile_prefix, get_profile_commit_oid, load_commit_oid_map) with a
 * single lazy load + linear peek.
 */
static error_t *load_profile_entries(state_t *state) {
    CHECK_NULL(state);

    /* Already loaded — return immediately.
     * Must precede the db check: state_empty() marks the cache loaded with
     * db==NULL, representing a state with zero enabled profiles. */
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
        "SELECT name, custom_prefix, commit_oid FROM enabled_profiles "
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
        row->custom_prefix = prefix_db ? strdup(prefix_db) : NULL;
        if (oid_blob) memcpy(row->commit_oid.id, oid_blob, GIT_OID_RAWSZ);

        if (!row->name || (prefix_db && !row->custom_prefix)) {
            free(row->name);
            free(row->custom_prefix);
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
            free(entries[j].custom_prefix);
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
 * Peek a single profile's custom prefix
 */
const char *state_peek_profile_prefix(
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
    return entry ? entry->custom_prefix : NULL;
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
 * Enable profile with optional custom prefix
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile,
    const char *custom_prefix
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(state->db);

    if (profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    /* UPSERT: Insert or update on conflict.
     *
     * commit_oid is zeroblob(20) on fresh INSERT — the manifest layer fills it
     * via state_set_profile_commit_oid after syncing entries. On UPSERT conflict
     * (profile already enabled), commit_oid is preserved — it represents the
     * last-synced HEAD and must not be clobbered by a prefix update. */
    const char *sql =
        "INSERT INTO enabled_profiles (name, custom_prefix, enabled_at, commit_oid, position) "
        "VALUES (?1, ?2, ?3, zeroblob(20), "
        "  (SELECT COALESCE(MAX(position), 0) + 1 FROM enabled_profiles)) "
        "ON CONFLICT(name) DO UPDATE SET custom_prefix = ?2, enabled_at = ?3";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare enable profile statement");
    }

    /* Bind parameters */
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_STATIC);
    if (custom_prefix && custom_prefix[0] != '\0') {
        sqlite3_bind_text(stmt, 2, custom_prefix, -1, SQLITE_STATIC);
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
 * Set enabled profiles (bulk operation)
 *
 * Bulk API for atomic profile list replacement (clone, reorder, interactive).
 * Automatically preserves custom_prefix and commit_oid values for profiles
 * that remain enabled.
 *
 * For individual profile changes, prefer state_enable_profile()/state_disable_profile()
 * which provide explicit custom prefix management.
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies enabled_profiles table (virtual_manifest untouched).
 *
 * Preservation is driven by the row cache, which already holds every column
 * we need to keep. Previously, this function queried enabled_profiles twice
 * (once per column) to build two hashmaps; now a single cache load covers
 * both lookups via find_profile_entry().
 *
 * @param state State (must not be NULL)
 * @param profiles Profile names (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_set_profiles(
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
            ERR_STATE_INVALID, "state_set_profiles requires an active transaction"
        );
    }

    /* Ensure the row cache is populated — we read old rows from it to
     * preserve custom_prefix and commit_oid across DELETE + re-INSERT. */
    error_t *err = load_profile_entries(state);
    if (err) {
        return error_wrap(err, "Failed to load profile row cache");
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

        /* Compose the OID to bind once: zero for new profiles, the cached
         * value for profiles that remain enabled. One bind path, no static
         * scratch buffer. */
        git_oid preserved_oid = { 0 };
        if (preserved) git_oid_cpy(&preserved_oid, &preserved->commit_oid);

        /* Reset and bind statement */
        sqlite3_reset(state->stmt_insert_profile);
        sqlite3_clear_bindings(state->stmt_insert_profile);

        /* Bind parameters: position, name, enabled_at, commit_oid, custom_prefix.
         * SQLITE_TRANSIENT: SQLite copies immediately; source lifetimes are ours. */
        sqlite3_bind_int64(state->stmt_insert_profile, 1, (sqlite3_int64) i);
        sqlite3_bind_text(
            state->stmt_insert_profile, 2, name, -1, SQLITE_TRANSIENT
        );
        sqlite3_bind_int64(state->stmt_insert_profile, 3, (sqlite3_int64) now);
        sqlite3_bind_blob(
            state->stmt_insert_profile, 4,
            preserved_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT
        );
        if (preserved && preserved->custom_prefix) {
            sqlite3_bind_text(
                state->stmt_insert_profile, 5,
                preserved->custom_prefix, -1, SQLITE_TRANSIENT
            );
        } else {
            sqlite3_bind_null(state->stmt_insert_profile, 5);
        }

        rc = sqlite3_step(state->stmt_insert_profile);
        if (rc != SQLITE_DONE) {
            return sqlite_error(state->db, "Failed to insert profile");
        }
    }

    /* SQL now reflects the new set. Invalidate so the next peek reloads
     * fresh rows in the new position order. */
    invalidate_profile_entries(state);
    return NULL;
}

/**
 * Add file entry to state
 *
 * HOT PATH: Called 1000+ times in apply loop.
 * Uses prepared statement for 100x speedup.
 *
 * @param state State (must not be NULL)
 * @param entry File entry to add (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_file(state_t *state, const state_file_entry_t *entry) {
    CHECK_NULL(state);
    CHECK_NULL(entry);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_insert_file);

    /* Reset statement (clear previous bindings) */
    sqlite3_reset(state->stmt_insert_file);
    sqlite3_clear_bindings(state->stmt_insert_file);

    /* Bind parameters */
    /* 1-3. filesystem_path, storage_path, profile */
    sqlite3_bind_text(state->stmt_insert_file, 1, entry->filesystem_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 2, entry->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 3, entry->profile, -1, SQLITE_TRANSIENT);

    /* 4. old_profile */
    if (entry->old_profile) {
        sqlite3_bind_text(state->stmt_insert_file, 4, entry->old_profile, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 4);
    }

    /* 5. blob_oid — bound as 20-byte BLOB. Using entry->blob_oid.id (the backing
     * byte array) rather than &entry->blob_oid keeps the intent explicit: we
     * are writing the raw hash bytes, not a struct snapshot whose layout happens
     * to start with them. SQLITE_TRANSIENT lets SQLite copy before we modify. */
    sqlite3_bind_blob(
        state->stmt_insert_file, 5, entry->blob_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT
    );

    /* 6. type */
    const char *type_str = entry->type == STATE_FILE_REGULAR ? "file"
                         : entry->type == STATE_FILE_SYMLINK ? "symlink" : "executable";
    sqlite3_bind_text(state->stmt_insert_file, 6, type_str, -1, SQLITE_STATIC);

    /* 7. mode */
    if (entry->mode > 0) {
        sqlite3_bind_int(state->stmt_insert_file, 7, entry->mode);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 7);
    }

    /* 8. owner */
    if (entry->owner) {
        sqlite3_bind_text(state->stmt_insert_file, 8, entry->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 8);
    }

    /* 9. group */
    if (entry->group) {
        sqlite3_bind_text(state->stmt_insert_file, 9, entry->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 9);
    }

    /* 10. encrypted */
    sqlite3_bind_int(state->stmt_insert_file, 10, entry->encrypted ? 1 : 0);

    /* 11. state */
    if (entry->state && entry->state[0] != '\0') {
        sqlite3_bind_text(state->stmt_insert_file, 11, entry->state, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(state->stmt_insert_file, 11, STATE_ACTIVE, -1, SQLITE_STATIC);
    }

    /* 12. deployed_blob_oid — 20 bytes. Zero sentinel is legitimate (never
     * confirmed); the UPSERT's preserve-on-zero CASE keeps any prior anchor. */
    sqlite3_bind_blob(
        state->stmt_insert_file, 12, entry->anchor.blob_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT
    );

    /* 13. deployed_at (anchor) */
    sqlite3_bind_int64(state->stmt_insert_file, 13, (sqlite3_int64) entry->anchor.deployed_at);

    /* 14-16. stat cache (anchor fast-path witness on deployed_blob_oid) */
    sqlite3_bind_int64(state->stmt_insert_file, 14, entry->anchor.stat.mtime);
    sqlite3_bind_int64(state->stmt_insert_file, 15, entry->anchor.stat.size);
    sqlite3_bind_int64(state->stmt_insert_file, 16, (sqlite3_int64) entry->anchor.stat.ino);

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
    state_file_entry_t **out
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
     *   3-9:  blob_oid, type, mode, owner, group, encrypted, state  (VWD cache)
     *   10-14: deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino  (anchor) */
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
    const char *state_str = (const char *) sqlite3_column_text(stmt, 9);

    /* Deployment anchor (column 10: deployed_blob_oid BLOB NOT NULL, always 20 bytes) */
    deployment_anchor_t anchor = { 0 };
    memcpy(anchor.blob_oid.id, sqlite3_column_blob(stmt, 10), GIT_OID_RAWSZ);
    anchor.deployed_at = (time_t) sqlite3_column_int64(stmt, 11);
    anchor.stat = (stat_cache_t){
        .mtime = sqlite3_column_int64(stmt, 12),
        .size = sqlite3_column_int64(stmt, 13),
        .ino = (uint64_t) sqlite3_column_int64(stmt, 14),
    };

    /* Validate required string columns */
    if (!storage_path || !profile || !type_str) {
        return ERROR(
            ERR_STATE_INVALID, "NULL value in required column for file: %s",
            filesystem_path
        );
    }

    /* Parse file type */
    state_file_type_t type = STATE_FILE_REGULAR;
    if (strcmp(type_str, "symlink") == 0) {
        type = STATE_FILE_SYMLINK;
    } else if (strcmp(type_str, "executable") == 0) {
        type = STATE_FILE_EXECUTABLE;
    }

    /* Create entry (caller owns) */
    state_file_entry_t *entry = NULL;
    error_t *err = state_create_entry(
        storage_path, filesystem_path, profile, old_profile, type, &blob_oid,
        mode, owner, group, encrypted != 0, state_str, &entry
    );

    if (err) return err;

    entry->anchor = anchor;

    *out = entry;
    return NULL;
}

error_t *state_get_file_by_storage(
    const state_t *state,
    const char *storage_path,
    state_file_entry_t **out
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
     *   3-9:  blob_oid, type, mode, owner, group, encrypted, state
     *   10-14: deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino */
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
    const char *state_str = (const char *) sqlite3_column_text(stmt, 9);

    /* Deployment anchor */
    deployment_anchor_t anchor = { 0 };
    memcpy(anchor.blob_oid.id, sqlite3_column_blob(stmt, 10), GIT_OID_RAWSZ);
    anchor.deployed_at = (time_t) sqlite3_column_int64(stmt, 11);
    anchor.stat = (stat_cache_t){
        .mtime = sqlite3_column_int64(stmt, 12),
        .size = sqlite3_column_int64(stmt, 13),
        .ino = (uint64_t) sqlite3_column_int64(stmt, 14),
    };

    if (!filesystem_path || !profile || !type_str) {
        return ERROR(
            ERR_STATE_INVALID,
            "NULL value in required column for storage path: %s", storage_path
        );
    }

    state_file_type_t type = STATE_FILE_REGULAR;
    if (strcmp(type_str, "symlink") == 0) {
        type = STATE_FILE_SYMLINK;
    } else if (strcmp(type_str, "executable") == 0) {
        type = STATE_FILE_EXECUTABLE;
    }

    state_file_entry_t *entry = NULL;
    error_t *err = state_create_entry(
        storage_path, filesystem_path, profile, old_profile, type, &blob_oid,
        mode, owner, group, encrypted != 0, state_str, &entry
    );

    if (err) return err;

    entry->anchor = anchor;

    *out = entry;
    return NULL;
}

/**
 * Get all file entries
 *
 * Returns allocated array that caller MUST free.
 * Original API returned borrowed reference.
 *
 * This change is necessary because SQLite implementation doesn't keep
 * all files in memory.
 *
 * @param state State (must not be NULL)
 * @param out Output array (must not be NULL, caller must free with state_free_all_files)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_files(
    const state_t *state,
    arena_t *arena,
    state_file_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
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
    state_file_entry_t *entries = arena
        ? arena_calloc(arena, file_count, sizeof(state_file_entry_t))
        : calloc(file_count, sizeof(state_file_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate file array");
    }

    /* Helper macros: route allocations through arena or heap */
    #define DUP(s)      (arena ? arena_strdup(arena, (s)) : strdup((s)))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Query all files (16 columns: 4 identity + 7 VWD cache + 5 anchor) */
    const char *sql_files =
        "SELECT filesystem_path, storage_path, profile, old_profile, "
        "blob_oid, type, mode, owner, \"group\", encrypted, state, "
        "deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino "
        "FROM virtual_manifest ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_files, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        if (!arena) free(entries);
        return sqlite_error(state->db, "Failed to prepare select query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < file_count) {
        /* Column layout matches sql_files:
         *   0-3:  identity (filesystem_path, storage_path, profile, old_profile)
         *   4-10: VWD cache (blob_oid, type, mode, owner, group, encrypted, state)
         *   11-15: anchor (deployed_blob_oid, deployed_at, stat_mtime, stat_size, stat_ino) */
        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile = (const char *) sqlite3_column_text(stmt, 2);
        const char *old_profile = (const char *) sqlite3_column_text(stmt, 3);

        /* Read binary blob_oid directly into the entry (no intermediate allocation). */
        memcpy(entries[i].blob_oid.id, sqlite3_column_blob(stmt, 4), GIT_OID_RAWSZ);

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

        /* Deployment anchor */
        memcpy(entries[i].anchor.blob_oid.id, sqlite3_column_blob(stmt, 11), GIT_OID_RAWSZ);
        entries[i].anchor.deployed_at = (time_t) sqlite3_column_int64(stmt, 12);
        entries[i].anchor.stat = (stat_cache_t){
            .mtime = sqlite3_column_int64(stmt, 13),
            .size = sqlite3_column_int64(stmt, 14),
            .ino = (uint64_t) sqlite3_column_int64(stmt, 15),
        };

        /* Validate non-nullable string columns (OIDs already validated above) */
        if (!fs_path || !storage_path || !profile || !type_str) {
            sqlite3_finalize(stmt);
            if (!arena) state_free_all_files(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings (arena or heap) */
        entries[i].filesystem_path = DUP(fs_path);
        entries[i].storage_path = DUP(storage_path);
        entries[i].profile = DUP(profile);
        entries[i].old_profile = DUP_OPT(old_profile);
        entries[i].mode = mode;
        entries[i].owner = DUP_OPT(owner);
        entries[i].group = DUP_OPT(group);

        /* Parse type */
        if (strcmp(type_str, "symlink") == 0) {
            entries[i].type = STATE_FILE_SYMLINK;
        } else if (strcmp(type_str, "executable") == 0) {
            entries[i].type = STATE_FILE_EXECUTABLE;
        } else {
            entries[i].type = STATE_FILE_REGULAR;
        }

        /* Set other fields */
        entries[i].encrypted = (encrypted != 0);
        entries[i].state = state_str ? DUP(state_str) : DUP(STATE_ACTIVE);

        /* Check allocation success */
        if (!entries[i].filesystem_path || !entries[i].storage_path ||
            !entries[i].profile || !entries[i].state) {
            sqlite3_finalize(stmt);
            if (!arena) state_free_all_files(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy entry strings");
        }

        i++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (!arena) state_free_all_files(entries, i);
        return sqlite_error(state->db, "Failed to query files");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

/**
 * Free array returned by state_get_all_files()
 *
 * @param entries Array to free (can be NULL)
 * @param count Number of entries in array
 */
void state_free_all_files(state_file_entry_t *entries, size_t count) {
    if (!entries) return;

    /* blob_oid is an inline binary field — no allocation to free. */
    for (size_t i = 0; i < count; i++) {
        free(entries[i].filesystem_path);
        free(entries[i].storage_path);
        free(entries[i].profile);
        free(entries[i].old_profile);
        free(entries[i].owner);
        free(entries[i].group);
        free(entries[i].state);
    }

    free(entries);
}

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
) {
    CHECK_NULL(meta_item);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* Validate that this is a directory item */
    if (meta_item->kind != METADATA_ITEM_DIRECTORY) {
        const char *kind_str = "UNKNOWN";
        if (meta_item->kind == METADATA_ITEM_FILE) kind_str = "FILE";
        else if (meta_item->kind == METADATA_ITEM_SYMLINK) kind_str = "SYMLINK";

        return ERROR(
            ERR_INVALID_ARG, "Expected DIRECTORY metadata item, got %s",
            kind_str
        );
    }

    /* Helper macros: route allocations through arena or heap */
    #define DUP(s)      (arena ? arena_strdup(arena, (s)) : strdup((s)))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    state_directory_entry_t *entry = arena
        ? arena_calloc(arena, 1, sizeof(state_directory_entry_t))
        : calloc(1, sizeof(state_directory_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate state directory entry");
    }

    /* Derive filesystem path from storage path with appropriate prefix.
     * path_from_storage always returns a heap-allocated string. */
    char *heap_path = NULL;
    error_t *err = path_from_storage(meta_item->key, custom_prefix, &heap_path);
    if (err) {
        if (!arena) free(entry);
        return error_wrap(
            err, "Failed to derive filesystem path from storage path: %s",
            meta_item->key
        );
    }
    if (arena) {
        entry->filesystem_path = arena_strdup(arena, heap_path);
        free(heap_path);
    } else {
        entry->filesystem_path = heap_path;
    }

    entry->storage_path = DUP(meta_item->key);
    entry->profile = DUP(profile);
    entry->mode = meta_item->mode;
    entry->owner = DUP_OPT(meta_item->owner);
    entry->group = DUP_OPT(meta_item->group);
    entry->deployed_at = 0;

    /* Check allocation success */
    if (!entry->filesystem_path || !entry->storage_path || !entry->profile ||
        (meta_item->owner && !entry->owner) || (meta_item->group && !entry->group)) {
        if (!arena) state_free_directory_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy directory entry fields");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entry;
    return NULL;
}

/**
 * Add directory entry to state
 *
 * Uses prepared statement for performance.
 * Replaces existing entry if filesystem_path already exists.
 *
 * @param state State (must not be NULL)
 * @param entry Directory entry (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_add_directory(state_t *state, const state_directory_entry_t *entry) {
    CHECK_NULL(state);
    CHECK_NULL(entry);
    CHECK_NULL(entry->filesystem_path);
    CHECK_NULL(entry->storage_path);
    CHECK_NULL(entry->profile);
    CHECK_NULL(state->db);

    /* Prepare statement if not already prepared */
    if (!state->stmt_insert_directory) {
        const char *sql =
            "INSERT OR REPLACE INTO tracked_directories "
            "(filesystem_path, storage_path, profile, mode, owner, \"group\", state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);";

        int rc = sqlite3_prepare_v2(state->db, sql, -1, &state->stmt_insert_directory, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(state->db, "Failed to prepare insert directory statement");
        }
    }

    sqlite3_stmt *stmt = state->stmt_insert_directory;

    /* Bind parameters */
    sqlite3_bind_text(stmt, 1, entry->filesystem_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->storage_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->profile, -1, SQLITE_STATIC);

    /* Mode (optional) */
    if (entry->mode > 0) {
        sqlite3_bind_int(stmt, 4, entry->mode);
    } else {
        sqlite3_bind_null(stmt, 4);
    }

    /* Owner (optional) */
    if (entry->owner) {
        sqlite3_bind_text(stmt, 5, entry->owner, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    /* Group (optional) */
    if (entry->group) {
        sqlite3_bind_text(stmt, 6, entry->group, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    /* State (defaults to STATE_ACTIVE if not set) */
    if (entry->state && entry->state[0] != '\0') {
        sqlite3_bind_text(stmt, 7, entry->state, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_text(stmt, 7, STATE_ACTIVE, -1, SQLITE_STATIC);
    }

    /* Execute */
    int rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to insert directory");
    }

    return NULL;
}

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
) {
    CHECK_NULL(state);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Empty state (no DB file) — return empty results */
    if (!state->db) return NULL;

    /* Count directories first (avoid realloc, required for arena mode) */
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
    state_directory_entry_t *entries = arena
        ? arena_calloc(arena, dir_count, sizeof(state_directory_entry_t))
        : calloc(dir_count, sizeof(state_directory_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate directories array");
    }

    /* Helper macros: route allocations through arena or heap */
    #define DUP(s)      (arena ? arena_strdup(arena, (s)) : strdup((s)))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *) state;
    if (!mutable_state->stmt_get_all_directories) {
        const char *sql_dirs =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories ORDER BY filesystem_path;";

        rc = sqlite3_prepare_v2(
            mutable_state->db, sql_dirs, -1, &mutable_state->stmt_get_all_directories, NULL
        );
        if (rc != SQLITE_OK) {
            if (!arena) free(entries);
            return sqlite_error(
                mutable_state->db, "Failed to prepare get all directories statement"
            );
        }
    }

    sqlite3_stmt *stmt = mutable_state->stmt_get_all_directories;

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < dir_count) {
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
        sqlite3_int64 deployed_at = sqlite3_column_int64(stmt, 7);

        /* Validate non-nullable columns */
        if (!fs_path || !storage || !profile) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_directories(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings (arena or heap) */
        entries[i].filesystem_path = DUP(fs_path);
        entries[i].storage_path = DUP(storage);
        entries[i].profile = DUP(profile);
        entries[i].mode = mode;
        entries[i].owner = DUP_OPT(owner);
        entries[i].group = DUP_OPT(group);
        entries[i].state = state_str ? DUP(state_str) : DUP(STATE_ACTIVE);
        entries[i].deployed_at = (time_t) deployed_at;

        /* Check allocation success */
        if (!entries[i].filesystem_path || !entries[i].storage_path ||
            !entries[i].profile || !entries[i].state) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_directories(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy directory entry strings");
        }

        i++;
    }

    sqlite3_reset(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        if (!arena) state_free_all_directories(entries, i);
        return sqlite_error(mutable_state->db, "Failed to query directories");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

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
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_directories_by_profile(
    const state_t *state,
    const char *profile,
    arena_t *arena,
    state_directory_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Empty state (no DB file) — return empty results */
    if (!state->db) return NULL;

    /* Count directories first (avoid realloc, required for arena mode) */
    const char *sql_count = "SELECT COUNT(*) FROM tracked_directories WHERE profile = ?;";
    sqlite3_stmt *stmt_count = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql_count, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare directory count query");
    }

    sqlite3_bind_text(stmt_count, 1, profile, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count directories by profile");
    }

    size_t dir_count = (size_t) sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (dir_count == 0) {
        return NULL;  /* Success, no directories */
    }

    /* Allocate array */
    state_directory_entry_t *entries = arena
        ? arena_calloc(arena, dir_count, sizeof(state_directory_entry_t))
        : calloc(dir_count, sizeof(state_directory_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate directories array");
    }

    /* Helper macros: route allocations through arena or heap */
    #define DUP(s)      (arena ? arena_strdup(arena, (s)) : strdup((s)))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *) state;
    if (!mutable_state->stmt_get_directories_by_profile) {
        const char *sql =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories WHERE profile = ? ORDER BY filesystem_path;";

        rc = sqlite3_prepare_v2(
            mutable_state->db, sql, -1, &mutable_state->stmt_get_directories_by_profile, NULL
        );
        if (rc != SQLITE_OK) {
            if (!arena) free(entries);
            return sqlite_error(
                mutable_state->db, "Failed to prepare get directories by profile statement"
            );
        }
    }

    sqlite3_stmt *stmt = mutable_state->stmt_get_directories_by_profile;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < dir_count) {
        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile_str = (const char *) sqlite3_column_text(stmt, 2);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            mode = (mode_t) sqlite3_column_int(stmt, 3);
        }

        const char *owner = (const char *) sqlite3_column_text(stmt, 4);
        const char *group = (const char *) sqlite3_column_text(stmt, 5);
        const char *state_str = (const char *) sqlite3_column_text(stmt, 6);
        sqlite3_int64 deployed_at = sqlite3_column_int64(stmt, 7);

        /* Validate non-nullable columns */
        if (!fs_path || !storage || !profile_str) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_directories(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings (arena or heap) */
        entries[i].filesystem_path = DUP(fs_path);
        entries[i].storage_path = DUP(storage);
        entries[i].profile = DUP(profile_str);
        entries[i].mode = mode;
        entries[i].owner = DUP_OPT(owner);
        entries[i].group = DUP_OPT(group);
        entries[i].state = state_str ? DUP(state_str) : DUP(STATE_ACTIVE);
        entries[i].deployed_at = (time_t) deployed_at;

        /* Check allocation success */
        if (!entries[i].filesystem_path || !entries[i].storage_path ||
            !entries[i].profile || !entries[i].state) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_directories(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy directory entry strings");
        }

        i++;
    }

    sqlite3_reset(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        if (!arena) state_free_all_directories(entries, i);
        return sqlite_error(mutable_state->db, "Failed to query directories");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

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
) {
    CHECK_NULL(state);
    CHECK_NULL(entry);
    CHECK_NULL(entry->filesystem_path);
    CHECK_NULL(state->db);

    /* Prepare statement if not already prepared */
    if (!state->stmt_update_directory) {
        /* CRITICAL: Do NOT update deployed_at - it must be preserved for lifecycle tracking
         *
         * The UPDATE intentionally excludes deployed_at column. This preserves the original
         * deployment timestamp when updating fallback profile during profile disable.
         *
         * Columns updated: storage_path, profile, mode, owner, group
         * Columns preserved: filesystem_path (WHERE clause), deployed_at (lifecycle)
         */
        const char *sql =
            "UPDATE tracked_directories "
            "SET storage_path = ?, profile = ?, mode = ?, owner = ?, \"group\" = ? "
            "WHERE filesystem_path = ?;";

        int rc = sqlite3_prepare_v2(state->db, sql, -1, &state->stmt_update_directory, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(state->db, "Failed to prepare update directory statement");
        }
    }

    sqlite3_stmt *stmt = state->stmt_update_directory;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind parameters (5 fields + WHERE clause) */
    sqlite3_bind_text(stmt, 1, entry->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, entry->profile, -1, SQLITE_TRANSIENT);

    /* Mode (optional) */
    if (entry->mode > 0) {
        sqlite3_bind_int(stmt, 3, entry->mode);
    } else {
        sqlite3_bind_null(stmt, 3);
    }

    /* Owner (optional) */
    if (entry->owner) {
        sqlite3_bind_text(stmt, 4, entry->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 4);
    }

    /* Group (optional) */
    if (entry->group) {
        sqlite3_bind_text(stmt, 5, entry->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    /* WHERE clause: filesystem_path */
    sqlite3_bind_text(stmt, 6, entry->filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update directory");
    }

    /* Check if row was actually updated */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(
            ERR_NOT_FOUND, "Directory not found in state: %s",
            entry->filesystem_path
        );
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

    /* Prepare statement if not already prepared */
    if (!state->stmt_remove_directory) {
        const char *sql = "DELETE FROM tracked_directories WHERE filesystem_path = ?;";

        int rc = sqlite3_prepare_v2(state->db, sql, -1, &state->stmt_remove_directory, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(
                state->db, "Failed to prepare remove directory statement"
            );
        }
    }

    sqlite3_stmt *stmt = state->stmt_remove_directory;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to remove directory");
    }

    return NULL;
}

/**
 * Clear all directory entries
 *
 * Efficiently truncates tracked_directories table.
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_directories(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM tracked_directories;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(
            ERR_STATE_INVALID, "Failed to clear tracked directories: %s",
            errmsg ? errmsg : sqlite3_errstr(rc)
        );
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
}

/**
 * Get directory entry from state
 *
 * Retrieves single directory entry by filesystem path.
 * Returns allocated entry that caller must free with state_free_directory_entry().
 *
 * @param state State (must not be NULL)
 * @param filesystem_path Directory path to lookup (must not be NULL)
 * @param out Directory entry (must not be NULL, caller must free)
 * @return Error or NULL on success (ERR_NOT_FOUND if doesn't exist)
 */
error_t *state_get_directory(
    const state_t *state,
    const char *filesystem_path,
    state_directory_entry_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(out);
    CHECK_NULL(state->db);

    *out = NULL;

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *) state;
    if (!mutable_state->stmt_get_directory) {
        const char *sql =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories WHERE filesystem_path = ?;";

        int rc = sqlite3_prepare_v2(
            mutable_state->db, sql, -1,
            &mutable_state->stmt_get_directory, NULL
        );
        if (rc != SQLITE_OK) {
            return sqlite_error(
                mutable_state->db, "Failed to prepare get directory statement"
            );
        }
    }

    sqlite3_stmt *stmt = mutable_state->stmt_get_directory;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute query */
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        /* Not found */
        sqlite3_reset(stmt);
        return ERROR(ERR_NOT_FOUND, "Directory '%s' not found in state", filesystem_path);
    }
    if (rc != SQLITE_ROW) {
        sqlite3_reset(stmt);
        return sqlite_error(mutable_state->db, "Failed to query directory");
    }

    /* Allocate entry */
    state_directory_entry_t *entry = calloc(1, sizeof(state_directory_entry_t));
    if (!entry) {
        sqlite3_reset(stmt);
        return ERROR(ERR_MEMORY, "Failed to allocate directory entry");
    }

    /* Parse row */
    /* filesystem_path (column 0) */
    const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
    entry->filesystem_path = strdup(fs_path ? fs_path : "");

    /* storage_path (column 1) */
    const char *storage = (const char *) sqlite3_column_text(stmt, 1);
    entry->storage_path = strdup(storage ? storage : "");

    /* profile (column 2) */
    const char *profile = (const char *) sqlite3_column_text(stmt, 2);
    entry->profile = strdup(profile ? profile : "");

    /* mode (column 3, optional) */
    if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
        entry->mode = (mode_t) sqlite3_column_int(stmt, 3);
    } else {
        entry->mode = 0;
    }

    /* owner (column 4, optional) */
    const char *owner = (const char *) sqlite3_column_text(stmt, 4);
    if (owner) {
        entry->owner = strdup(owner);
    }

    /* group (column 5, optional) */
    const char *group = (const char *) sqlite3_column_text(stmt, 5);
    if (group) {
        entry->group = strdup(group);
    }

    /* state (column 6) */
    const char *state_str = (const char *) sqlite3_column_text(stmt, 6);
    if (state_str) {
        entry->state = strdup(state_str);
    }

    /* deployed_at (column 7) */
    entry->deployed_at = sqlite3_column_int64(stmt, 7);

    sqlite3_reset(stmt);

    *out = entry;
    return NULL;
}

/**
 * Set directory lifecycle state
 *
 * Updates the state column for a directory entry.
 * Mirrors state_set_file_state() pattern for consistency.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @param filesystem_path Directory path (must not be NULL)
 * @param new_state Lifecycle state (STATE_ACTIVE, STATE_INACTIVE, or STATE_DELETED)
 * @return Error or NULL on success
 */
error_t *state_set_directory_state(
    state_t *state,
    const char *filesystem_path,
    const char *new_state
) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(new_state);

    /* Validate state value */
    if (strcmp(new_state, STATE_ACTIVE) != 0 && strcmp(new_state, STATE_INACTIVE) != 0 &&
        strcmp(new_state, STATE_DELETED) != 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid state '%s' (must be 'active', 'inactive' or 'deleted')", new_state
        );
    }

    /* Prepare statement if needed */
    if (!state->stmt_set_directory_state) {
        const char *sql = "UPDATE tracked_directories SET state = ? WHERE filesystem_path = ?";

        int rc = sqlite3_prepare_v2(state->db, sql, -1, &state->stmt_set_directory_state, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(state->db, "Failed to prepare set directory state statement");
        }
    }

    sqlite3_stmt *stmt = state->stmt_set_directory_state;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, new_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update directory state");
    }

    /* Check if any row was actually updated */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        /* Directory not found - this is non-fatal, just log */
        return NULL;  /* Graceful degradation */
    }

    return NULL;
}

/**
 * Mark all directories as inactive
 *
 * Bulk operation for manifest_sync_directories to prepare for rebuild.
 * Replaces the nuclear state_clear_directories() approach with mark-and-reactivate pattern.
 *
 * @param state State handle (must not be NULL, must have active transaction)
 * @return Error or NULL on success
 */
error_t *state_mark_all_directories_inactive(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    /* Prepare statement if needed */
    if (!state->stmt_mark_all_directories_inactive) {
        const char *sql = "UPDATE tracked_directories SET state = 'inactive'";

        int rc = sqlite3_prepare_v2(
            state->db, sql, -1,
            &state->stmt_mark_all_directories_inactive, NULL
        );
        if (rc != SQLITE_OK) {
            return sqlite_error(
                state->db, "Failed to prepare mark all directories inactive statement"
            );
        }
    }

    sqlite3_stmt *stmt = state->stmt_mark_all_directories_inactive;
    sqlite3_reset(stmt);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to mark all directories as inactive");
    }

    return NULL;
}

/**
 * Free single directory entry
 */
void state_free_directory_entry(state_directory_entry_t *entry) {
    if (!entry) {
        return;
    }

    free(entry->filesystem_path);
    free(entry->storage_path);
    free(entry->profile);
    free(entry->owner);
    free(entry->group);
    free(entry->state);
    free(entry);
}

/**
 * Free array of directory entries
 */
void state_free_all_directories(state_directory_entry_t *entries, size_t count) {
    if (!entries) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(entries[i].filesystem_path);
        free(entries[i].storage_path);
        free(entries[i].profile);
        free(entries[i].owner);
        free(entries[i].group);
        free(entries[i].state);
    }

    free(entries);
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

    /* If database doesn't exist, return empty state */
    if (!db) {
        free(db_path);
        return state_empty(out);
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
 * Commits the transaction started by state_open(). A state_empty() handle
 * holds no DB connection; state_save() on such a handle is a no-op because
 * state_empty() is only used by init_state(), which never writes profile
 * rows before saving.
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
 * Begin an explicit transaction on a read-only state handle
 */
error_t *state_begin(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    if (state->in_transaction) {
        return ERROR(ERR_STATE_INVALID, "Transaction already active");
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
 * Create empty state
 *
 * Returns in-memory state with no database connection.
 * Useful for testing or when database doesn't exist.
 *
 * @param out State structure (must not be NULL, caller must free with state_free)
 * @return Error or NULL on success
 */
error_t *state_empty(state_t **out) {
    CHECK_NULL(out);

    state_t *state = calloc(1, sizeof(state_t));
    if (!state) {
        return ERROR(ERR_MEMORY, "Failed to allocate state");
    }

    state->db = NULL;
    state->db_path = NULL;
    state->in_transaction = false;
    state->profile_entries = NULL;
    state->profile_entry_count = 0;
    state->profile_entries_loaded = true;  /* Zero rows is a valid loaded state */

    /* No database, no statements */
    state->stmt_insert_file = NULL;
    state->stmt_remove_file = NULL;
    state->stmt_file_exists = NULL;
    state->stmt_get_file = NULL;
    state->stmt_get_file_by_storage = NULL;
    state->stmt_insert_profile = NULL;

    *out = state;
    return NULL;
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
 * Helper function to allocate and initialize a file entry.
 *
 * Populates identity and VWD-cache fields only. entry->anchor is
 * zero-initialized by calloc; hydration callers populate it afterward
 * from row data (anchor is never a caller-supplied field).
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
    state_file_type_t type,
    const git_oid *blob_oid,
    mode_t mode,
    const char *owner,
    const char *group,
    bool encrypted,
    const char *state_value,
    state_file_entry_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(blob_oid);
    CHECK_NULL(out);

    state_file_entry_t *entry = calloc(1, sizeof(state_file_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate entry");
    }

    /* Copy required string fields */
    entry->storage_path = strdup(storage_path);
    entry->filesystem_path = strdup(filesystem_path);
    entry->profile = strdup(profile);

    /* Copy binary blob OID (20 bytes, no allocation) */
    git_oid_cpy(&entry->blob_oid, blob_oid);

    /* Copy optional string fields */
    entry->old_profile = old_profile ? strdup(old_profile) : NULL;
    entry->owner = owner ? strdup(owner) : NULL;
    entry->group = group ? strdup(group) : NULL;
    entry->state = state_value ? strdup(state_value) : strdup(STATE_ACTIVE);

    /* Set non-string fields */
    entry->mode = mode;
    entry->type = type;
    entry->encrypted = encrypted;
    entry->anchor = DEPLOYMENT_ANCHOR_UNSET;

    /* Validate required allocations */
    if (!entry->storage_path || !entry->filesystem_path ||
        !entry->profile || !entry->state) {
        state_free_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Advance a manifest entry's deployment anchor
 *
 * The sole writer of the deployment columns (deployed_blob_oid, deployed_at,
 * stat_*). Call after confirming disk content matches anchor->blob_oid.
 *
 * See state.h for the full contract. In brief:
 *   - anchor->blob_oid must be non-zero.
 *   - anchor->deployed_at == 0 preserves the existing timestamp
 *     (add/update/workspace-flush case).
 *   - anchor->deployed_at != 0 writes the new value
 *     (apply post-deploy / adoption case).
 *   - anchor->stat is always written.
 *   - Not-found is not an error.
 */
error_t *state_update_anchor(
    state_t *state,
    const char *filesystem_path,
    const deployment_anchor_t *anchor
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(anchor);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_update_anchor);

    /* A zero blob_oid here would misclassify the entry as "never confirmed"
     * and strand it in the stale path. Reject rather than silently poison. */
    if (git_oid_is_zero(&anchor->blob_oid)) {
        return ERROR(
            ERR_STATE_INVALID,
            "state_update_anchor called with zero blob_oid for '%s'",
            filesystem_path
        );
    }

    sqlite3_stmt *stmt = state->stmt_update_anchor;

    /* Reset and bind */
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Bind order mirrors sql_update_anchor. ?2 (deployed_at) is used twice */
    sqlite3_bind_blob(stmt, 1, anchor->blob_oid.id, GIT_OID_RAWSZ, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64) anchor->deployed_at);
    sqlite3_bind_int64(stmt, 3, anchor->stat.mtime);
    sqlite3_bind_int64(stmt, 4, anchor->stat.size);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64) anchor->stat.ino);
    sqlite3_bind_text(stmt, 6, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update deployment anchor");
    }

    /* Not-found is OK — entry may not exist (disabled profile, filtered by precedence) */
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
 *   - STATE_ACTIVE   - Normal entry, file is in scope
 *   - STATE_INACTIVE - Staged for removal, reversible (profile disable)
 *   - STATE_DELETED  - Confirmed deletion via remove command
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - filesystem_path MUST exist in virtual_manifest
 *   - new_state MUST be STATE_ACTIVE, STATE_INACTIVE, STATE_DELETED, etc
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
) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(new_state);

    /* Validate state value */
    if (strcmp(new_state, STATE_ACTIVE) != 0 && strcmp(new_state, STATE_INACTIVE) != 0 &&
        strcmp(new_state, STATE_DELETED) != 0 && strcmp(new_state, STATE_RELEASED) != 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid state '%s' (must be 'active', 'inactive', 'deleted', or 'released')",
            new_state
        );
    }

    const char *sql = "UPDATE virtual_manifest SET state = ? WHERE filesystem_path = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare state update");
    }

    sqlite3_bind_text(stmt, 1, new_state, -1, SQLITE_TRANSIENT);
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

/**
 * Set commit_oid for a profile in enabled_profiles
 *
 * Single-row UPDATE on enabled_profiles. Records the profile's current
 * branch HEAD as the last-synced commit.
 *
 * Called after operations that move a profile's branch HEAD:
 * - manifest_sync_diff (after pull/merge)
 * - manifest_add_files (after commit)
 * - manifest_update_files (after commit)
 * - manifest_remove_files (after commit)
 * - manifest_enable_profile (after populating entries)
 * - manifest_populate (after clone-time population)
 * - manifest_repair_stale (after repairing entries)
 *
 * Cache discipline: this mutation patches the row cache *in place* rather
 * than invalidating it. Only the commit_oid field of the matching row
 * changes; name and custom_prefix allocations are preserved. Callers
 * holding borrows obtained via state_peek_profile_prefix() or iterating
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
 * Get entries by profile
 *
 * Returns all manifest entries from the specified profile.
 * Used by profile disable to determine impact of disabling a profile.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param out Output array (must not be NULL, caller must free with state_free_all_files)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_entries_by_profile(
    const state_t *state,
    const char *profile,
    arena_t *arena,
    state_file_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Empty state (no DB file) — return empty results */
    if (!state->db) return NULL;

    CHECK_NULL(state->stmt_get_by_profile);

    /* First, count entries */
    char count_sql[512];
    snprintf(
        count_sql, sizeof(count_sql),
        "SELECT COUNT(*) FROM virtual_manifest WHERE profile = ?;"
    );

    sqlite3_stmt *stmt_count = NULL;
    int rc = sqlite3_prepare_v2(state->db, count_sql, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare count query");
    }

    sqlite3_bind_text(stmt_count, 1, profile, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count entries");
    }

    size_t entry_count = (size_t) sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (entry_count == 0) {
        return NULL;  /* Success, no entries */
    }

    /* Allocate array */
    state_file_entry_t *entries = arena
        ? arena_calloc(arena, entry_count, sizeof(state_file_entry_t))
        : calloc(entry_count, sizeof(state_file_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate entries array");
    }

    /* Helper macros: route allocations through arena or heap */
    #define DUP(s)      (arena ? arena_strdup(arena, (s)) : strdup((s)))
    #define DUP_OPT(s)  ((s) ? DUP(s) : NULL)

    /* Reset and bind profile */
    sqlite3_stmt *stmt = state->stmt_get_by_profile;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);

    /* Fetch all entries. Column layout matches sql_by_profile:
     *   0-3:  identity, 4-10: VWD cache, 11-15: deployment anchor (same as sql_files). */
    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < entry_count) {
        const char *fs_path = (const char *) sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *) sqlite3_column_text(stmt, 1);
        const char *profile = (const char *) sqlite3_column_text(stmt, 2);
        const char *old_profile = (const char *) sqlite3_column_text(stmt, 3);

        /* Read binary blob_oid directly into the entry (no intermediate allocation). */
        memcpy(entries[i].blob_oid.id, sqlite3_column_blob(stmt, 4), GIT_OID_RAWSZ);

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

        /* Deployment anchor */
        memcpy(entries[i].anchor.blob_oid.id, sqlite3_column_blob(stmt, 11), GIT_OID_RAWSZ);
        entries[i].anchor.deployed_at = (time_t) sqlite3_column_int64(stmt, 12);
        entries[i].anchor.stat = (stat_cache_t){
            .mtime = sqlite3_column_int64(stmt, 13),
            .size = sqlite3_column_int64(stmt, 14),
            .ino = (uint64_t) sqlite3_column_int64(stmt, 15),
        };

        if (!fs_path || !storage_path || !profile || !type_str) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_files(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        entries[i].filesystem_path = DUP(fs_path);
        entries[i].storage_path = DUP(storage_path);
        entries[i].profile = DUP(profile);
        entries[i].old_profile = DUP_OPT(old_profile);
        entries[i].mode = mode;
        entries[i].owner = DUP_OPT(owner);
        entries[i].group = DUP_OPT(group);

        if (strcmp(type_str, "symlink") == 0) {
            entries[i].type = STATE_FILE_SYMLINK;
        } else if (strcmp(type_str, "executable") == 0) {
            entries[i].type = STATE_FILE_EXECUTABLE;
        } else {
            entries[i].type = STATE_FILE_REGULAR;
        }

        entries[i].encrypted = (encrypted != 0);
        entries[i].state = state_str ? DUP(state_str) : DUP(STATE_ACTIVE);

        if (!entries[i].filesystem_path || !entries[i].storage_path ||
            !entries[i].profile || !entries[i].state) {
            sqlite3_reset(stmt);
            if (!arena) state_free_all_files(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy entry strings");
        }

        i++;
    }

    sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        if (!arena) state_free_all_files(entries, i);
        return sqlite_error(state->db, "Failed to fetch entries");
    }

    #undef DUP
    #undef DUP_OPT

    *out = entries;
    *count = i;

    return NULL;
}

/**
 * Get last deployed timestamp for a profile
 *
 * Queries the maximum deployed_at timestamp for files from the specified profile.
 *
 * @param state State (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @return Timestamp (0 if profile has no deployed files)
 */
time_t state_get_profile_timestamp(const state_t *state, const char *profile) {
    if (!state || !profile || !state->db) {
        return 0;
    }

    const char *sql = "SELECT MAX(deployed_at) FROM virtual_manifest WHERE profile = ?;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);

    time_t timestamp = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        timestamp = (time_t) sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);

    return timestamp;
}

/**
 * Free file entry
 *
 * @param entry Entry to free (can be NULL)
 */
void state_free_entry(state_file_entry_t *entry) {
    if (!entry) {
        return;
    }

    /* blob_oid is an inline binary field — no allocation to free. */
    free(entry->storage_path);
    free(entry->filesystem_path);
    free(entry->profile);
    free(entry->old_profile);
    free(entry->owner);
    free(entry->group);
    free(entry->state);
    free(entry);
}
