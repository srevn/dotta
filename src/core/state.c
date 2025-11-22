/**
 * state.c - SQLite-based deployment state tracking implementation
 *
 * Uses SQLite for performance and scalability.
 *
 * Key optimizations:
 * - Prepared statements cached for bulk operations
 * - WAL mode for concurrent access
 * - Profiles cached in memory (tiny, read frequently)
 * - Files queried on-demand (large, read occasionally)
 * - Persistent B-tree indexes (no hashmap rebuilding)
 */

#include "state.h"

#include <git2.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/hashmap.h"

/* Schema version - must match database */
#define STATE_SCHEMA_VERSION "4"

/* Database file name */
#define STATE_DB_NAME "dotta.db"

/**
 * State structure
 *
 * Maintains minimal in-memory cache for performance:
 * - Profiles cached (tiny, read frequently)
 * - Files queried on-demand (large, read occasionally)
 * - Prepared statements cached (eliminate preparation overhead)
 */
struct state {
    /* Database connection */
    sqlite3 *db;
    char *db_path;

    /* Transaction state */
    bool in_transaction;     /* BEGIN IMMEDIATE executed */

    /* Cached enabled profiles (loaded lazily) */
    string_array_t *profiles;
    bool profiles_loaded;

    /* Prepared statements (initialized once, reused) */
    sqlite3_stmt *stmt_insert_file;         /* INSERT OR REPLACE virtual_manifest */
    sqlite3_stmt *stmt_update_deployed_at;  /* UPDATE virtual_manifest SET deployed_at */
    sqlite3_stmt *stmt_update_entry;        /* UPDATE virtual_manifest (full) */
    sqlite3_stmt *stmt_remove_file;         /* DELETE FROM virtual_manifest */
    sqlite3_stmt *stmt_file_exists;         /* SELECT 1 FROM virtual_manifest */
    sqlite3_stmt *stmt_get_file;            /* SELECT * FROM virtual_manifest */
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

    return ERROR(ERR_STATE_INVALID, "%s: %s (SQLite error %d)",
        context, errmsg, errcode);
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
        ");"

        /* Insert version (fails silently if already exists) */
        "INSERT OR IGNORE INTO schema_meta (key, value) "
        "VALUES ('version', '" STATE_SCHEMA_VERSION "');"

        /* Enabled profiles table (authority: profile commands) */
        "CREATE TABLE IF NOT EXISTS enabled_profiles ("
        "    position INTEGER PRIMARY KEY,"
        "    name TEXT NOT NULL UNIQUE,"
        "    enabled_at INTEGER NOT NULL,"
        "    custom_prefix TEXT"
        ");"

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
        "    git_oid TEXT NOT NULL,"
        "    blob_oid TEXT NOT NULL,"
        "    "
        "    type TEXT NOT NULL CHECK(type IN ('file', 'symlink', 'executable')),"
        "    mode INTEGER,"
        "    owner TEXT,"
        "    \"group\" TEXT,"
        "    encrypted INTEGER NOT NULL DEFAULT 0,"
        "    "
        "    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active', 'inactive')),"
        "    deployed_at INTEGER NOT NULL DEFAULT 0"
        ");"

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
        "    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active', 'inactive')),"
        "    deployed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))"
        ") STRICT;"

        "CREATE INDEX IF NOT EXISTS idx_tracked_directories_profile "
        "ON tracked_directories(profile);";

    /* Execute schema SQL */
    rc = sqlite3_exec(db, schema_sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to initialize schema: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
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
        return ERROR(ERR_STATE_INVALID,
            "Database missing schema_meta table - corrupted or wrong format");
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return ERROR(ERR_STATE_INVALID, "Database missing schema version");
    }

    const char *db_version = (const char *)sqlite3_column_text(stmt, 0);
    if (!db_version) {
        sqlite3_finalize(stmt);
        return ERROR(ERR_STATE_INVALID, "Schema version is NULL");
    }

    /* Must match exactly */
    if (strcmp(db_version, STATE_SCHEMA_VERSION) != 0) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Schema version mismatch: database has version %s, code expects %s\n"
            "Database was created by different version of dotta",
            db_version, STATE_SCHEMA_VERSION);
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
 * - busy_timeout: Wait up to 5s for lock
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
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to enable WAL mode: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* 2. Fast synchronization (safe on crash, fast on commit) */
    rc = sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to set synchronous mode: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* 3. Larger cache (10MB instead of default 2MB) */
    rc = sqlite3_exec(db, "PRAGMA cache_size=10000;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to set cache size: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* 4. Store temp tables in memory (faster) */
    rc = sqlite3_exec(db, "PRAGMA temp_store=MEMORY;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to set temp store: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* 5. Short busy timeout to handle transient locks gracefully */
    sqlite3_busy_timeout(db, 300);

    return NULL;
}

/**
 * Open database connection
 *
 * Opens or creates database, initializes schema, and configures pragmas.
 * Does NOT start a transaction - use state_load_for_update() for that.
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

        err = ERROR(ERR_FS,
            "Failed to open database: %s",
            db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
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
    rc = sqlite3_prepare_v2(db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_meta';",
        -1, &check_stmt, NULL);

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

    /* Insert/update file (used by manifest sync operations - hot path) */
    const char *sql_insert =
        "INSERT OR REPLACE INTO virtual_manifest "
        "(filesystem_path, storage_path, profile, old_profile, git_oid, blob_oid, "
        " type, mode, owner, \"group\", encrypted, state, deployed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_insert, -1,
                           &state->stmt_insert_file, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare insert statement");
    }

    /* Update deployed_at only (used by apply - hot path) */
    const char *sql_update_deployed_at =
        "UPDATE virtual_manifest SET deployed_at = ? "
        "WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_update_deployed_at, -1,
                           &state->stmt_update_deployed_at, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        return sqlite_error(state->db, "Failed to prepare update deployed_at statement");
    }

    /* Update full entry (used by manifest sync operations) */
    const char *sql_update_entry =
        "UPDATE virtual_manifest SET "
        "storage_path = ?, profile = ?, old_profile = ?, git_oid = ?, blob_oid = ?, "
        "type = ?, mode = ?, owner = ?, \"group\" = ?, encrypted = ?, "
        "state = ?, deployed_at = ? "
        "WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_update_entry, -1,
                           &state->stmt_update_entry, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        return sqlite_error(state->db, "Failed to prepare update entry statement");
    }

    /* File exists check (used in status - hot path) */
    const char *sql_exists =
        "SELECT 1 FROM virtual_manifest WHERE filesystem_path = ? LIMIT 1;";

    rc = sqlite3_prepare_v2(state->db, sql_exists, -1,
                           &state->stmt_file_exists, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        sqlite3_finalize(state->stmt_update_entry);
        return sqlite_error(state->db, "Failed to prepare exists statement");
    }

    /* Get file (used in workspace analysis) */
    const char *sql_get =
        "SELECT storage_path, profile, old_profile, git_oid, blob_oid, "
        "type, mode, owner, \"group\", encrypted, state, deployed_at "
        "FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_get, -1,
                           &state->stmt_get_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        sqlite3_finalize(state->stmt_update_entry);
        sqlite3_finalize(state->stmt_file_exists);
        return sqlite_error(state->db, "Failed to prepare get statement");
    }

    /* Get entries by profile (used by profile disable) */
    const char *sql_by_profile =
        "SELECT filesystem_path, storage_path, profile, old_profile, git_oid, blob_oid, "
        "type, mode, owner, \"group\", encrypted, state, deployed_at "
        "FROM virtual_manifest WHERE profile = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_by_profile, -1,
                           &state->stmt_get_by_profile, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        sqlite3_finalize(state->stmt_update_entry);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        return sqlite_error(state->db, "Failed to prepare get by profile statement");
    }

    /* Remove file (used in revert and cleanup) */
    const char *sql_remove =
        "DELETE FROM virtual_manifest WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_remove, -1,
                           &state->stmt_remove_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        sqlite3_finalize(state->stmt_update_entry);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        sqlite3_finalize(state->stmt_get_by_profile);
        return sqlite_error(state->db, "Failed to prepare remove statement");
    }

    /* Insert profile (used in state_set_profiles) */
    const char *sql_profile =
        "INSERT INTO enabled_profiles (position, name, enabled_at, custom_prefix) "
        "VALUES (?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_profile, -1,
                           &state->stmt_insert_profile, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_update_deployed_at);
        sqlite3_finalize(state->stmt_update_entry);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
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

    if (state->stmt_update_deployed_at) {
        sqlite3_finalize(state->stmt_update_deployed_at);
        state->stmt_update_deployed_at = NULL;
    }

    if (state->stmt_update_entry) {
        sqlite3_finalize(state->stmt_update_entry);
        state->stmt_update_entry = NULL;
    }

    if (state->stmt_file_exists) {
        sqlite3_finalize(state->stmt_file_exists);
        state->stmt_file_exists = NULL;
    }

    if (state->stmt_get_file) {
        sqlite3_finalize(state->stmt_get_file);
        state->stmt_get_file = NULL;
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
 * Load profiles into cache
 *
 * Lazy loading pattern - only loads once, then caches.
 * Profiles are tiny (~100 bytes) and read frequently, so caching
 * is beneficial.
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *load_profiles(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    /* Already loaded - return immediately */
    if (state->profiles_loaded) {
        return NULL;
    }

    /* Create array if needed */
    if (!state->profiles) {
        state->profiles = string_array_create();
        if (!state->profiles) {
            return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        }
    }

    /* Query profiles ordered by position */
    const char *sql = "SELECT name FROM enabled_profiles ORDER BY position ASC;";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare profile query");
    }

    error_t *err = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        if (!name) {
            err = ERROR(ERR_STATE_INVALID, "Profile name is NULL");
            break;
        }

        err = string_array_push(state->profiles, name);
        if (err) break;
    }

    sqlite3_finalize(stmt);

    if (err) return err;

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to query profiles");
    }

    state->profiles_loaded = true;
    return NULL;
}

/**
 * Get enabled profiles
 *
 * Returns copy that caller must free.
 * Profiles are cached on first access.
 *
 * @param state State (must not be NULL)
 * @param out Profile names (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_get_profiles(const state_t *state, string_array_t **out) {
    CHECK_NULL(state);
    CHECK_NULL(out);

    /* Load if not cached (cast away const for internal mutation) */
    error_t *err = load_profiles((state_t *)state);
    if (err) return err;

    /* Return copy (caller owns) */
    string_array_t *copy = string_array_create();
    if (!copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    for (size_t i = 0; i < string_array_size(state->profiles); i++) {
        err = string_array_push(copy, string_array_get(state->profiles, i));
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
 * @param profile_name Profile name to check (must not be NULL)
 * @return true if profile is enabled, false otherwise
 */
bool state_has_profile(const state_t *state, const char *profile_name) {
    if (!state || !profile_name) {
        return false;
    }

    /* Load if not cached (cast away const for internal mutation) */
    error_t *err = load_profiles((state_t *)state);
    if (err) {
        error_free(err);
        return false;
    }

    /* Check if profile exists in enabled list */
    for (size_t i = 0; i < string_array_size(state->profiles); i++) {
        if (strcmp(string_array_get(state->profiles, i), profile_name) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Get unique profiles that have deployed files
 *
 * Extracts all unique profile names from the virtual_manifest table.
 * Uses SQL DISTINCT for efficient deduplication at database level.
 */
error_t *state_get_deployed_profiles(const state_t *state, string_array_t **out) {
    CHECK_NULL(state);
    CHECK_NULL(out);
    CHECK_NULL(state->db);

    *out = NULL;

    /* Create output array */
    string_array_t *profiles = string_array_create();
    if (!profiles) {
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    /* Query for unique profile names (DISTINCT ensures deduplication) */
    const char *sql =
        "SELECT DISTINCT profile FROM virtual_manifest ORDER BY profile;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        string_array_free(profiles);
        return sqlite_error(state->db, "Failed to prepare deployed profiles query");
    }

    /* Collect profile names */
    error_t *err = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *profile_name = (const char *)sqlite3_column_text(stmt, 0);

        if (!profile_name) {
            /* NULL profile name should never happen (NOT NULL constraint) */
            sqlite3_finalize(stmt);
            string_array_free(profiles);
            return ERROR(ERR_STATE_INVALID, "NULL profile in virtual_manifest");
        }

        err = string_array_push(profiles, profile_name);
        if (err) {
            sqlite3_finalize(stmt);
            string_array_free(profiles);
            return error_wrap(err, "Failed to add profile to array");
        }
    }

    sqlite3_finalize(stmt);

    /* Check for query errors */
    if (rc != SQLITE_DONE) {
        string_array_free(profiles);
        return sqlite_error(state->db, "Failed to fetch deployed profiles");
    }

    *out = profiles;
    return NULL;
}

/**
 * Enable profile with optional custom prefix
 */
error_t *state_enable_profile(
    state_t *state,
    const char *profile_name,
    const char *custom_prefix
) {
    CHECK_NULL(state);
    CHECK_NULL(profile_name);

    if (profile_name[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    /* UPSERT: Insert or update on conflict */
    const char *sql =
        "INSERT INTO enabled_profiles (name, custom_prefix, enabled_at, position) "
        "VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(position), 0) + 1 FROM enabled_profiles)) "
        "ON CONFLICT(name) DO UPDATE SET custom_prefix = ?2, enabled_at = ?3";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare enable profile statement");
    }

    /* Bind parameters */
    sqlite3_bind_text(stmt, 1, profile_name, -1, SQLITE_STATIC);
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

    /* Invalidate cache */
    state->profiles_loaded = false;

    return NULL;
}

/**
 * Disable profile
 */
error_t *state_disable_profile(
    state_t *state,
    const char *profile_name
) {
    CHECK_NULL(state);
    CHECK_NULL(profile_name);

    const char *sql = "DELETE FROM enabled_profiles WHERE name = ?1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare disable profile statement");
    }

    sqlite3_bind_text(stmt, 1, profile_name, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to disable profile");
    }

    /* Invalidate cache */
    state->profiles_loaded = false;

    /* Not an error if profile wasn't enabled (DELETE with 0 rows affected is OK) */
    return NULL;
}

/**
 * Get custom prefix map
 */
error_t *state_get_prefix_map(
    const state_t *state,
    hashmap_t **out_map
) {
    CHECK_NULL(state);
    CHECK_NULL(out_map);

    /* Create map */
    hashmap_t *map = hashmap_create(16);
    if (!map) {
        return ERROR(ERR_MEMORY, "Failed to create prefix map");
    }

    /* Query: Only select profiles with custom_prefix set
     * This is efficient - most profiles won't have custom prefixes */
    const char *sql =
        "SELECT name, custom_prefix "
        "FROM enabled_profiles "
        "WHERE custom_prefix IS NOT NULL "
        "ORDER BY position ASC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        hashmap_free(map, NULL);
        return sqlite_error(state->db, "Failed to prepare prefix map query");
    }

    /* Populate map */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name_db = (const char *)sqlite3_column_text(stmt, 0);
        const char *prefix_db = (const char *)sqlite3_column_text(stmt, 1);

        /* Allocate owned copies (map owns these strings) */
        char *name = strdup(name_db);
        char *prefix = strdup(prefix_db);

        if (!name || !prefix) {
            free(name);
            free(prefix);
            sqlite3_finalize(stmt);
            hashmap_free(map, free);  /* Free all allocated strings */
            return ERROR(ERR_MEMORY, "Failed to allocate prefix map entry");
        }

        /* Store in map (prefix ownership transferred) */
        error_t *err = hashmap_set(map, name, prefix);
        if (err) {
            free(name);
            free(prefix);
            sqlite3_finalize(stmt);
            hashmap_free(map, free);
            return err;
        }
        
        /* Free name - hashmap made its own copy of the key */
        free(name);
    }

    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        hashmap_free(map, free);
        return sqlite_error(state->db, "Failed to query prefix map");
    }

    sqlite3_finalize(stmt);
    *out_map = map;
    return NULL;
}

/**
 * Set enabled profiles (bulk operation)
 *
 * Bulk API for atomic profile list replacement (clone, reorder, interactive).
 * Automatically preserves custom_prefix values for profiles that remain enabled.
 *
 * For individual profile changes, prefer state_enable_profile()/state_disable_profile()
 * which provide explicit custom prefix management.
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies enabled_profiles table (virtual_manifest untouched).
 *
 * @param state State (must not be NULL)
 * @param profiles Array of profile names (must not be NULL)
 * @param count Number of profiles
 * @return Error or NULL on success
 */
error_t *state_set_profiles(
    state_t *state,
    char **profiles,
    size_t count
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(state->db);

    /* Load current custom_prefix values before DELETE to preserve them.
     * This enables safe profile reordering without losing custom prefix associations.
     * New profiles get NULL custom_prefix (use state_enable_profile() to set). */
    hashmap_t *prefix_map = NULL;
    error_t *err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        return error_wrap(err, "Failed to load custom prefix map");
    }

    /* Delete all existing profiles */
    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM enabled_profiles;",
                         NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        hashmap_free(prefix_map, free);
        err = ERROR(ERR_STATE_INVALID, "Failed to clear profiles: %s",
                    errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* Insert new profiles with preserved custom_prefix values */
    time_t now = time(NULL);
    for (size_t i = 0; i < count; i++) {
        /* Reset and bind statement */
        sqlite3_reset(state->stmt_insert_profile);
        sqlite3_clear_bindings(state->stmt_insert_profile);

        /* Bind parameters: position, name, enabled_at, custom_prefix */
        sqlite3_bind_int64(state->stmt_insert_profile, 1, (sqlite3_int64)i);
        sqlite3_bind_text(state->stmt_insert_profile, 2, profiles[i], -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(state->stmt_insert_profile, 3, (sqlite3_int64)now);

        /* Lookup and bind preserved custom_prefix (or NULL if not set) */
        const char *custom_prefix = (const char *)hashmap_get(prefix_map, profiles[i]);
        if (custom_prefix) {
            sqlite3_bind_text(state->stmt_insert_profile, 4, custom_prefix, -1, SQLITE_STATIC);
        } else {
            sqlite3_bind_null(state->stmt_insert_profile, 4);
        }

        rc = sqlite3_step(state->stmt_insert_profile);
        if (rc != SQLITE_DONE) {
            hashmap_free(prefix_map, free);
            return sqlite_error(state->db, "Failed to insert profile");
        }
    }

    /* Free the prefix map */
    hashmap_free(prefix_map, free);

    /* Update cache */
    if (state->profiles) {
        string_array_clear(state->profiles);
    } else {
        state->profiles = string_array_create();
        if (!state->profiles) {
            return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        }
    }

    for (size_t i = 0; i < count; i++) {
        err = string_array_push(state->profiles, profiles[i]);
        if (err) return err;
    }

    state->profiles_loaded = true;
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
    /* 1. filesystem_path */
    sqlite3_bind_text(state->stmt_insert_file, 1,
                     entry->filesystem_path, -1, SQLITE_TRANSIENT);

    /* 2. storage_path */
    sqlite3_bind_text(state->stmt_insert_file, 2,
                     entry->storage_path, -1, SQLITE_TRANSIENT);

    /* 3. profile */
    sqlite3_bind_text(state->stmt_insert_file, 3,
                     entry->profile, -1, SQLITE_TRANSIENT);

    /* 4. old_profile */
    if (entry->old_profile) {
        sqlite3_bind_text(state->stmt_insert_file, 4,
                         entry->old_profile, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 4);
    }

    /* 5. git_oid */
    sqlite3_bind_text(state->stmt_insert_file, 5,
                     entry->git_oid, -1, SQLITE_TRANSIENT);

    /* 6. blob_oid */
    sqlite3_bind_text(state->stmt_insert_file, 6,
                     entry->blob_oid, -1, SQLITE_TRANSIENT);

    /* 7. type */
    const char *type_str = entry->type == STATE_FILE_REGULAR ? "file" :
                          entry->type == STATE_FILE_SYMLINK ? "symlink" :
                          "executable";
    sqlite3_bind_text(state->stmt_insert_file, 7, type_str, -1, SQLITE_STATIC);

    /* 8. mode */
    if (entry->mode > 0) {
        sqlite3_bind_int(state->stmt_insert_file, 8, entry->mode);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 8);
    }

    /* 9. owner */
    if (entry->owner) {
        sqlite3_bind_text(state->stmt_insert_file, 9,
                         entry->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 9);
    }

    /* 10. group */
    if (entry->group) {
        sqlite3_bind_text(state->stmt_insert_file, 10,
                         entry->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 10);
    }

    /* 11. encrypted */
    sqlite3_bind_int(state->stmt_insert_file, 11, entry->encrypted ? 1 : 0);

    /* 12. state */
    if (entry->state && entry->state[0] != '\0') {
        sqlite3_bind_text(state->stmt_insert_file, 12, entry->state, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(state->stmt_insert_file, 12, STATE_ACTIVE, -1, SQLITE_STATIC);
    }

    /* 13. deployed_at */
    sqlite3_bind_int64(state->stmt_insert_file, 13, (sqlite3_int64)entry->deployed_at);

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

    /* Reset and bind (cast away const for statement reuse) */
    sqlite3_stmt *stmt = ((state_t *)state)->stmt_file_exists;
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

    /* Reset and bind (cast away const) */
    sqlite3_stmt *stmt = ((state_t *)state)->stmt_get_file;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    sqlite3_bind_text(stmt, 1, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE) {
            return ERROR(ERR_NOT_FOUND, "File not found in state: %s", filesystem_path);
        }
        return sqlite_error(state->db, "Failed to query file");
    }

    /* Extract all 13 columns from scope-based schema */
    const char *storage_path = (const char *)sqlite3_column_text(stmt, 0);
    const char *profile = (const char *)sqlite3_column_text(stmt, 1);
    const char *old_profile = (const char *)sqlite3_column_text(stmt, 2);
    const char *git_oid = (const char *)sqlite3_column_text(stmt, 3);
    const char *blob_oid = (const char *)sqlite3_column_text(stmt, 4);
    const char *type_str = (const char *)sqlite3_column_text(stmt, 5);

    /* Read mode as integer (0 if NULL) */
    mode_t mode = 0;
    if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
        mode = (mode_t)sqlite3_column_int(stmt, 6);
    }

    const char *owner = (const char *)sqlite3_column_text(stmt, 7);
    const char *group = (const char *)sqlite3_column_text(stmt, 8);
    int encrypted = sqlite3_column_int(stmt, 9);
    const char *state_str = (const char *)sqlite3_column_text(stmt, 10);
    sqlite3_int64 deployed_at = sqlite3_column_int64(stmt, 11);

    /* Validate required columns */
    if (!storage_path || !profile || !git_oid || !blob_oid || !type_str) {
        return ERROR(ERR_STATE_INVALID,
            "NULL value in required column for file: %s", filesystem_path);
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
        storage_path,
        filesystem_path,
        profile,
        old_profile,
        type,
        git_oid,
        blob_oid,
        mode,
        owner,
        group,
        encrypted != 0,
        state_str,
        (time_t)deployed_at,
        &entry
    );

    if (err) return err;

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
    state_file_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(out);
    CHECK_NULL(count);
    CHECK_NULL(state->db);

    *out = NULL;
    *count = 0;

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

    size_t file_count = (size_t)sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (file_count == 0) {
        return NULL;  /* Success, no files */
    }

    /* Allocate array */
    state_file_entry_t *entries = calloc(file_count, sizeof(state_file_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate file array");
    }

    /* Query all files with scope-based schema (13 columns) */
    const char *sql_files =
        "SELECT filesystem_path, storage_path, profile, old_profile, git_oid, blob_oid, "
        "type, mode, owner, \"group\", encrypted, state, deployed_at "
        "FROM virtual_manifest ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_files, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(entries);
        return sqlite_error(state->db, "Failed to prepare select query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < file_count) {
        /* Get all 13 columns with NULL checking (scope-based schema) */
        const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *)sqlite3_column_text(stmt, 1);
        const char *profile = (const char *)sqlite3_column_text(stmt, 2);
        const char *old_profile = (const char *)sqlite3_column_text(stmt, 3);
        const char *git_oid = (const char *)sqlite3_column_text(stmt, 4);
        const char *blob_oid = (const char *)sqlite3_column_text(stmt, 5);
        const char *type_str = (const char *)sqlite3_column_text(stmt, 6);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
            mode = (mode_t)sqlite3_column_int(stmt, 7);
        }

        const char *owner = (const char *)sqlite3_column_text(stmt, 8);
        const char *group = (const char *)sqlite3_column_text(stmt, 9);
        int encrypted = sqlite3_column_int(stmt, 10);
        const char *state_str = (const char *)sqlite3_column_text(stmt, 11);
        sqlite3_int64 deployed_at = sqlite3_column_int64(stmt, 12);

        /* Validate non-nullable columns */
        if (!fs_path || !storage_path || !profile ||
            !git_oid || !blob_oid || !type_str) {
            sqlite3_finalize(stmt);
            state_free_all_files(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        /* Copy strings */
        entries[i].filesystem_path = strdup(fs_path);
        entries[i].storage_path = strdup(storage_path);
        entries[i].profile = strdup(profile);
        entries[i].old_profile = old_profile ? strdup(old_profile) : NULL;
        entries[i].git_oid = strdup(git_oid);
        entries[i].blob_oid = strdup(blob_oid);
        entries[i].mode = mode;
        entries[i].owner = owner ? strdup(owner) : NULL;
        entries[i].group = group ? strdup(group) : NULL;

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
        entries[i].state = state_str ? strdup(state_str) : strdup(STATE_ACTIVE);
        entries[i].deployed_at = (time_t)deployed_at;

        /* Check allocation success */
        if (!entries[i].filesystem_path || !entries[i].storage_path || !entries[i].profile ||
            !entries[i].git_oid || !entries[i].blob_oid || !entries[i].state) {
            sqlite3_finalize(stmt);
            state_free_all_files(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy entry strings");
        }

        i++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        state_free_all_files(entries, i);
        return sqlite_error(state->db, "Failed to query files");
    }

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

    for (size_t i = 0; i < count; i++) {
        free(entries[i].filesystem_path);
        free(entries[i].storage_path);
        free(entries[i].profile);
        free(entries[i].old_profile);
        free(entries[i].git_oid);
        free(entries[i].blob_oid);
        free(entries[i].owner);
        free(entries[i].group);
        free(entries[i].state);
    }

    free(entries);
}

/**
 * Clear all file entries (keeps profiles and timestamp)
 *
 * Efficiently truncates virtual_manifest table.
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_files(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM virtual_manifest;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID, "Failed to clear virtual manifest: %s",
                            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
}

/**
 * Create state directory entry from metadata item
 *
 * Converts portable metadata (storage_path) to state entry (both paths).
 * Derives filesystem_path from metadata's storage_path using path_from_storage().
 *
 * @param meta_item Metadata item (must not be NULL, must be DIRECTORY kind)
 * @param profile_name Source profile name (must not be NULL)
 * @param custom_prefix Custom prefix for this profile (NULL for home/root)
 * @param out State directory entry (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *state_directory_entry_create_from_metadata(
    const metadata_item_t *meta_item,
    const char *profile_name,
    const char *custom_prefix,
    state_directory_entry_t **out
) {
    CHECK_NULL(meta_item);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    /* Validate that this is a directory item */
    if (meta_item->kind != METADATA_ITEM_DIRECTORY) {
        return ERROR(ERR_INVALID_ARG, "Expected DIRECTORY metadata item, got %s",
                     meta_item->kind == METADATA_ITEM_FILE ? "FILE" : "UNKNOWN");
    }

    state_directory_entry_t *entry = calloc(1, sizeof(state_directory_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate state directory entry");
    }

    /* Derive filesystem path from storage path with appropriate prefix */
    error_t *err = path_from_storage(meta_item->key, custom_prefix, &entry->filesystem_path);
    if (err) {
        free(entry);
        return error_wrap(err, "Failed to derive filesystem path from storage path: %s",
                         meta_item->key);
    }

    /* Copy storage path */
    entry->storage_path = strdup(meta_item->key);
    if (!entry->storage_path) {
        free(entry->filesystem_path);
        free(entry);
        return ERROR(ERR_MEMORY, "Failed to copy storage path");
    }

    /* Copy profile name */
    entry->profile = strdup(profile_name);
    if (!entry->profile) {
        free(entry->storage_path);
        free(entry->filesystem_path);
        free(entry);
        return ERROR(ERR_MEMORY, "Failed to copy profile name");
    }

    /* Copy metadata fields */
    entry->mode = meta_item->mode;

    /* Copy owner (optional) */
    if (meta_item->owner) {
        entry->owner = strdup(meta_item->owner);
        if (!entry->owner) {
            free(entry->profile);
            free(entry->storage_path);
            free(entry->filesystem_path);
            free(entry);
            return ERROR(ERR_MEMORY, "Failed to copy owner");
        }
    }

    /* Copy group (optional) */
    if (meta_item->group) {
        entry->group = strdup(meta_item->group);
        if (!entry->group) {
            free(entry->owner);
            free(entry->profile);
            free(entry->storage_path);
            free(entry->filesystem_path);
            free(entry);
            return ERROR(ERR_MEMORY, "Failed to copy group");
        }
    }

    /* Initialize lifecycle tracking */
    entry->deployed_at = 0;

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
 * Returns allocated array that caller must free with state_free_all_directories().
 *
 * @param state State (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_get_all_directories(
    const state_t *state,
    state_directory_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *)state;
    if (!mutable_state->stmt_get_all_directories) {
        const char *sql =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories "
            "ORDER BY filesystem_path;";

        int rc = sqlite3_prepare_v2(mutable_state->db, sql, -1,
                                     &mutable_state->stmt_get_all_directories, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(mutable_state->db,
                "Failed to prepare get all directories statement");
        }
    }

    sqlite3_stmt *stmt = mutable_state->stmt_get_all_directories;

    /* Dynamic array for results */
    size_t capacity = 16;
    state_directory_entry_t *entries = malloc(capacity * sizeof(state_directory_entry_t));
    if (!entries) {
        sqlite3_reset(stmt);
        return ERROR(ERR_MEMORY, "Failed to allocate directories array");
    }

    size_t entry_count = 0;

    /* Iterate rows */
    while (true) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            /* Cleanup on error */
            for (size_t i = 0; i < entry_count; i++) {
                free(entries[i].filesystem_path);
                free(entries[i].storage_path);
                free(entries[i].profile);
                free(entries[i].owner);
                free(entries[i].group);
                free(entries[i].state);
            }
            free(entries);
            sqlite3_reset(stmt);
            return sqlite_error(mutable_state->db, "Failed to query directories");
        }

        /* Grow array if needed */
        if (entry_count >= capacity) {
            capacity *= 2;
            state_directory_entry_t *new_entries =
                            realloc(entries, capacity * sizeof(state_directory_entry_t));
            if (!new_entries) {
                /* Cleanup on error */
                for (size_t i = 0; i < entry_count; i++) {
                    free(entries[i].filesystem_path);
                    free(entries[i].storage_path);
                    free(entries[i].profile);
                    free(entries[i].owner);
                    free(entries[i].group);
                    free(entries[i].state);
                }
                free(entries);
                sqlite3_reset(stmt);
                return ERROR(ERR_MEMORY, "Failed to grow directories array");
            }
            entries = new_entries;
        }

        /* Parse row */
        state_directory_entry_t *entry = &entries[entry_count];
        memset(entry, 0, sizeof(state_directory_entry_t));

        /* filesystem_path (column 0) */
        const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
        entry->filesystem_path = strdup(fs_path ? fs_path : "");

        /* storage_path (column 1) */
        const char *storage = (const char *)sqlite3_column_text(stmt, 1);
        entry->storage_path = strdup(storage ? storage : "");

        /* profile (column 2) */
        const char *profile = (const char *)sqlite3_column_text(stmt, 2);
        entry->profile = strdup(profile ? profile : "");

        /* mode (column 3, optional) */
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            entry->mode = (mode_t)sqlite3_column_int(stmt, 3);
        } else {
            entry->mode = 0;
        }

        /* owner (column 4, optional) */
        const char *owner = (const char *)sqlite3_column_text(stmt, 4);
        if (owner) {
            entry->owner = strdup(owner);
        }

        /* group (column 5, optional) */
        const char *group = (const char *)sqlite3_column_text(stmt, 5);
        if (group) {
            entry->group = strdup(group);
        }

        /* state (column 6) */
        const char *state_str = (const char *)sqlite3_column_text(stmt, 6);
        if (state_str) {
            entry->state = strdup(state_str);
        }

        /* deployed_at (column 7) */
        entry->deployed_at = sqlite3_column_int64(stmt, 7);

        entry_count++;
    }

    sqlite3_reset(stmt);

    *out = entries;
    *count = entry_count;
    return NULL;
}

/**
 * Get directories by profile
 *
 * Returns all directory entries from the specified profile.
 * Used by profile disable to determine impact on directories.
 *
 * Returns allocated array that caller must free with state_free_all_directories().
 *
 * @param state State (must not be NULL)
 * @param profile Profile name to filter by (must not be NULL)
 * @param out Output array (must not be NULL)
 * @param count Output count (must not be NULL)
 * @return Error or NULL on success (empty array if no matches)
 */
error_t *state_get_directories_by_profile(
    const state_t *state,
    const char *profile,
    state_directory_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(out);
    CHECK_NULL(count);

    *out = NULL;
    *count = 0;

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *)state;
    if (!mutable_state->stmt_get_directories_by_profile) {
        const char *sql =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories "
            "WHERE profile = ? "
            "ORDER BY filesystem_path;";

        int rc = sqlite3_prepare_v2(mutable_state->db, sql, -1,
                                     &mutable_state->stmt_get_directories_by_profile, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(mutable_state->db,
                "Failed to prepare get directories by profile statement");
        }
    }

    sqlite3_stmt *stmt = mutable_state->stmt_get_directories_by_profile;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);

    /* Dynamic array for results */
    size_t capacity = 16;
    state_directory_entry_t *entries = malloc(capacity * sizeof(state_directory_entry_t));
    if (!entries) {
        sqlite3_reset(stmt);
        return ERROR(ERR_MEMORY, "Failed to allocate directories array");
    }

    size_t entry_count = 0;

    /* Iterate rows */
    while (true) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            /* Cleanup on error */
            for (size_t i = 0; i < entry_count; i++) {
                free(entries[i].filesystem_path);
                free(entries[i].storage_path);
                free(entries[i].profile);
                free(entries[i].owner);
                free(entries[i].group);
                free(entries[i].state);
            }
            free(entries);
            sqlite3_reset(stmt);
            return sqlite_error(mutable_state->db, "Failed to query directories");
        }

        /* Grow array if needed */
        if (entry_count >= capacity) {
            capacity *= 2;
            state_directory_entry_t *new_entries =
                            realloc(entries, capacity * sizeof(state_directory_entry_t));
            if (!new_entries) {
                /* Cleanup on error */
                for (size_t i = 0; i < entry_count; i++) {
                    free(entries[i].filesystem_path);
                    free(entries[i].storage_path);
                    free(entries[i].profile);
                    free(entries[i].owner);
                    free(entries[i].group);
                    free(entries[i].state);
                }
                free(entries);
                sqlite3_reset(stmt);
                return ERROR(ERR_MEMORY, "Failed to grow directories array");
            }
            entries = new_entries;
        }

        /* Parse row */
        state_directory_entry_t *entry = &entries[entry_count];
        memset(entry, 0, sizeof(state_directory_entry_t));

        /* filesystem_path (column 0) */
        const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
        entry->filesystem_path = strdup(fs_path ? fs_path : "");

        /* storage_path (column 1) */
        const char *storage = (const char *)sqlite3_column_text(stmt, 1);
        entry->storage_path = strdup(storage ? storage : "");

        /* profile (column 2) */
        const char *profile_str = (const char *)sqlite3_column_text(stmt, 2);
        entry->profile = strdup(profile_str ? profile_str : "");

        /* mode (column 3, optional) */
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            entry->mode = (mode_t)sqlite3_column_int(stmt, 3);
        } else {
            entry->mode = 0;
        }

        /* owner (column 4, optional) */
        const char *owner = (const char *)sqlite3_column_text(stmt, 4);
        if (owner) {
            entry->owner = strdup(owner);
        }

        /* group (column 5, optional) */
        const char *group = (const char *)sqlite3_column_text(stmt, 5);
        if (group) {
            entry->group = strdup(group);
        }

        /* state (column 6) */
        const char *state_str = (const char *)sqlite3_column_text(stmt, 6);
        if (state_str) {
            entry->state = strdup(state_str);
        }

        /* deployed_at (column 7) */
        entry->deployed_at = sqlite3_column_int64(stmt, 7);

        entry_count++;
    }

    sqlite3_reset(stmt);

    *out = entries;
    *count = entry_count;
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
        return ERROR(ERR_NOT_FOUND, "Directory not found in state: %s",
                    entry->filesystem_path);
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
            return sqlite_error(state->db, "Failed to prepare remove directory statement");
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
        error_t *err = ERROR(ERR_STATE_INVALID, "Failed to clear tracked directories: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
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

    *out = NULL;

    /* Prepare statement if needed (const cast is safe for read-only ops) */
    state_t *mutable_state = (state_t *)state;
    if (!mutable_state->stmt_get_directory) {
        const char *sql =
            "SELECT filesystem_path, storage_path, profile, mode, owner, \"group\", state, deployed_at "
            "FROM tracked_directories "
            "WHERE filesystem_path = ?;";

        int rc = sqlite3_prepare_v2(mutable_state->db, sql, -1,
                                    &mutable_state->stmt_get_directory, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(mutable_state->db,
                "Failed to prepare get directory statement");
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
    const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
    entry->filesystem_path = strdup(fs_path ? fs_path : "");

    /* storage_path (column 1) */
    const char *storage = (const char *)sqlite3_column_text(stmt, 1);
    entry->storage_path = strdup(storage ? storage : "");

    /* profile (column 2) */
    const char *profile = (const char *)sqlite3_column_text(stmt, 2);
    entry->profile = strdup(profile ? profile : "");

    /* mode (column 3, optional) */
    if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
        entry->mode = (mode_t)sqlite3_column_int(stmt, 3);
    } else {
        entry->mode = 0;
    }

    /* owner (column 4, optional) */
    const char *owner = (const char *)sqlite3_column_text(stmt, 4);
    if (owner) {
        entry->owner = strdup(owner);
    }

    /* group (column 5, optional) */
    const char *group = (const char *)sqlite3_column_text(stmt, 5);
    if (group) {
        entry->group = strdup(group);
    }

    /* state (column 6) */
    const char *state_str = (const char *)sqlite3_column_text(stmt, 6);
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
 * @param new_state Lifecycle state (STATE_ACTIVE or STATE_INACTIVE)
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
    if (strcmp(new_state, STATE_ACTIVE) != 0 && strcmp(new_state, STATE_INACTIVE) != 0) {
        return ERROR(ERR_INVALID_ARG, "Invalid state '%s' (must be 'active' or 'inactive')",
                     new_state);
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

        int rc = sqlite3_prepare_v2(state->db, sql, -1,
                                    &state->stmt_mark_all_directories_inactive, NULL);
        if (rc != SQLITE_OK) {
            return sqlite_error(state->db,
                "Failed to prepare mark all directories inactive statement");
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
        return state_create_empty(out);
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
    state->profiles = NULL;
    state->profiles_loaded = false;

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
error_t *state_load_for_update(git_repository *repo, state_t **out) {
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
    state->profiles = NULL;
    state->profiles_loaded = false;

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
        err = ERROR(ERR_CONFLICT,
            "Failed to acquire write lock: %s\n"
            "Another process may be writing to the database",
            errmsg ? errmsg : sqlite3_errstr(rc));
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
 * Commits the transaction started by state_load_for_update().
 *
 * @param repo Repository (must not be NULL)
 * @param state State to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_save(git_repository *repo, state_t *state) {
    CHECK_NULL(repo);
    CHECK_NULL(state);

    error_t *err = NULL;

    /* Case 1: State created with load_for_update() - just commit transaction */
    if (state->db && state->in_transaction) {
        char *errmsg = NULL;
        int rc = sqlite3_exec(state->db, "COMMIT;", NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            err = ERROR(ERR_STATE_INVALID, "Failed to commit transaction: %s",
                errmsg ? errmsg : sqlite3_errstr(rc));
            sqlite3_free(errmsg);
            return err;
        }

        state->in_transaction = false;
        return NULL;
    }

    /* Case 2: State created with state_create_empty() - need to open database and write */
    if (!state->db) {
        /* Get database path */
        char *db_path = NULL;
        err = get_db_path(repo, &db_path);
        if (err) return err;

        /* Open database (create if missing) */
        sqlite3 *db = NULL;
        err = open_db(db_path, true, &db);
        if (err) {
            free(db_path);
            return err;
        }

        state->db = db;
        state->db_path = db_path;

        /* Prepare statements */
        err = prepare_statements(state);
        if (err) {
            sqlite3_close(db);
            state->db = NULL;
            return err;
        }

        /* Begin transaction */
        char *errmsg = NULL;
        int rc = sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            err = ERROR(ERR_CONFLICT, "Failed to acquire write lock: %s",
                        errmsg ? errmsg : sqlite3_errstr(rc));
            sqlite3_free(errmsg);
            finalize_statements(state);
            sqlite3_close(db);
            state->db = NULL;
            return err;
        }

        /* Write profiles if any */
        if (state->profiles && string_array_size(state->profiles) > 0) {
            char **profile_names = calloc(string_array_size(state->profiles), sizeof(char*));
            if (!profile_names) {
                sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
                finalize_statements(state);
                sqlite3_close(db);
                state->db = NULL;
                return ERROR(ERR_MEMORY, "Failed to allocate profile array");
            }

            for (size_t i = 0; i < string_array_size(state->profiles); i++) {
                profile_names[i] = (char *)string_array_get(state->profiles, i);
            }

            err = state_set_profiles(state, profile_names, string_array_size(state->profiles));
            free(profile_names);

            if (err) {
                sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
                finalize_statements(state);
                sqlite3_close(db);
                state->db = NULL;
                return err;
            }
        }

        /* Commit transaction */
        rc = sqlite3_exec(db, "COMMIT;", NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            err = ERROR(ERR_STATE_INVALID, "Failed to commit transaction: %s",
                        errmsg ? errmsg : sqlite3_errstr(rc));
            sqlite3_free(errmsg);
            finalize_statements(state);
            sqlite3_close(db);
            state->db = NULL;
            return err;
        }

        return NULL;
    }

    /* Case 3: Database exists but no transaction active - nothing to do */
    return NULL;
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
error_t *state_create_empty(state_t **out) {
    CHECK_NULL(out);

    state_t *state = calloc(1, sizeof(state_t));
    if (!state) {
        return ERROR(ERR_MEMORY, "Failed to allocate state");
    }

    state->db = NULL;
    state->db_path = NULL;
    state->in_transaction = false;
    state->profiles = string_array_create();
    state->profiles_loaded = true;  /* Empty array is loaded */

    if (!state->profiles) {
        free(state);
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    /* No database, no statements */
    state->stmt_insert_file = NULL;
    state->stmt_remove_file = NULL;
    state->stmt_file_exists = NULL;
    state->stmt_get_file = NULL;
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
        /* Use PASSIVE mode */
        sqlite3_wal_checkpoint_v2(state->db, NULL,
                                  SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
        sqlite3_close(state->db);
        state->db = NULL;
    }

    free(state->db_path);
    string_array_free(state->profiles);
    free(state);
}

/**
 * Create file entry
 *
 * Helper function to allocate and initialize a file entry.
 *
 * @param storage_path Storage path (must not be NULL)
 * @param filesystem_path Filesystem path (must not be NULL)
 * @param profile Profile name (must not be NULL)
 * @param type File type
 * @param git_oid Git commit reference (must not be NULL)
 * @param blob_oid Git blob OID (must not be NULL)
 * @param mode Permission mode (can be NULL)
 * @param owner Owner username (can be NULL)
 * @param group Group name (can be NULL)
 * @param encrypted Encryption flag
 * @param deployed_at Lifecycle timestamp (0 = never deployed, >0 = known)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    const char *old_profile,
    state_file_type_t type,
    const char *git_oid,
    const char *blob_oid,
    mode_t mode,
    const char *owner,
    const char *group,
    bool encrypted,
    const char *state_value,
    time_t deployed_at,
    state_file_entry_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(git_oid);
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
    entry->git_oid = strdup(git_oid);
    entry->blob_oid = strdup(blob_oid);

    /* Copy optional string fields */
    entry->old_profile = old_profile ? strdup(old_profile) : NULL;
    entry->owner = owner ? strdup(owner) : NULL;
    entry->group = group ? strdup(group) : NULL;
    entry->state = state_value ? strdup(state_value) : strdup(STATE_ACTIVE);

    /* Set non-string fields */
    entry->mode = mode;
    entry->type = type;
    entry->encrypted = encrypted;
    entry->deployed_at = deployed_at;

    /* Validate required allocations */
    if (!entry->storage_path || !entry->filesystem_path ||
        !entry->profile || !entry->git_oid || !entry->blob_oid || !entry->state) {
        state_free_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Update deployed_at timestamp (optimized hot path for apply)
 *
 * Updates only the deployed_at field to record lifecycle state.
 * Hot path - called during apply for all deployed files.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param filesystem_path File path to update (must not be NULL)
 * @param deployed_at New deployed_at timestamp (use time(NULL) for current time)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_update_deployed_at(
    state_t *state,
    const char *filesystem_path,
    time_t deployed_at
) {
    CHECK_NULL(state);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_update_deployed_at);

    /* Reset and bind */
    sqlite3_reset(state->stmt_update_deployed_at);
    sqlite3_clear_bindings(state->stmt_update_deployed_at);

    sqlite3_bind_int64(state->stmt_update_deployed_at, 1, (sqlite3_int64)deployed_at);
    sqlite3_bind_text(state->stmt_update_deployed_at, 2, filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(state->stmt_update_deployed_at);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update deployed_at");
    }

    /* Check if row was actually updated */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in manifest", filesystem_path);
    }

    return NULL;
}

/**
 * Clear old_profile for a manifest entry
 *
 * Acknowledges profile ownership change after successful deployment.
 * Sets old_profile to NULL to clear the ownership change flag.
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
 * Set file entry state (active/inactive)
 *
 * Updates the state column for a manifest entry. Used by manifest layer
 * to mark files as inactive when they become orphaned (removed with no fallback).
 *
 * Valid states:
 *   - STATE_ACTIVE   - Normal entry, file is in scope
 *   - STATE_INACTIVE - Marked for removal, awaiting cleanup by apply
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_load_for_update)
 *   - filesystem_path MUST exist in virtual_manifest
 *   - new_state MUST be STATE_ACTIVE or STATE_INACTIVE
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
    if (strcmp(new_state, STATE_ACTIVE) != 0 && strcmp(new_state, STATE_INACTIVE) != 0) {
        return ERROR(ERR_INVALID_ARG, "Invalid state '%s' (must be 'active' or 'inactive')",
                    new_state);
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
 * Update full entry
 *
 * Updates all fields of a manifest entry.
 * Used by manifest sync operations to update entries when Git changes.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param entry Entry with updated fields (must not be NULL)
 * @return Error or NULL on success (not found is an error)
 */
error_t *state_update_entry(
    state_t *state,
    const state_file_entry_t *entry
) {
    CHECK_NULL(state);
    CHECK_NULL(entry);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_update_entry);

    /* Convert type enum to string */
    const char *type_str = entry->type == STATE_FILE_REGULAR ? "file" :
                          entry->type == STATE_FILE_SYMLINK ? "symlink" :
                          "executable";

    /* Reset and bind all 13 fields + filesystem_path for WHERE clause */
    sqlite3_reset(state->stmt_update_entry);
    sqlite3_clear_bindings(state->stmt_update_entry);

    sqlite3_bind_text(state->stmt_update_entry, 1, entry->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_update_entry, 2, entry->profile, -1, SQLITE_TRANSIENT);

    if (entry->old_profile) {
        sqlite3_bind_text(state->stmt_update_entry, 3, entry->old_profile, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_update_entry, 3);
    }

    sqlite3_bind_text(state->stmt_update_entry, 4, entry->git_oid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_update_entry, 5, entry->blob_oid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_update_entry, 6, type_str, -1, SQLITE_STATIC);

    if (entry->mode > 0) {
        sqlite3_bind_int(state->stmt_update_entry, 7, entry->mode);
    } else {
        sqlite3_bind_null(state->stmt_update_entry, 7);
    }

    if (entry->owner) {
        sqlite3_bind_text(state->stmt_update_entry, 8, entry->owner, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_update_entry, 8);
    }

    if (entry->group) {
        sqlite3_bind_text(state->stmt_update_entry, 9, entry->group, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_update_entry, 9);
    }

    sqlite3_bind_int(state->stmt_update_entry, 10, entry->encrypted ? 1 : 0);

    /* 11. state */
    if (entry->state && entry->state[0] != '\0') {
        sqlite3_bind_text(state->stmt_update_entry, 11, entry->state, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(state->stmt_update_entry, 11, STATE_ACTIVE, -1, SQLITE_STATIC);
    }

    /* 12. deployed_at */
    sqlite3_bind_int64(state->stmt_update_entry, 12, (sqlite3_int64)entry->deployed_at);

    /* 13. filesystem_path for WHERE clause */
    sqlite3_bind_text(state->stmt_update_entry, 13, entry->filesystem_path, -1, SQLITE_TRANSIENT);

    /* Execute */
    int rc = sqlite3_step(state->stmt_update_entry);

    if (rc != SQLITE_DONE) {
        return sqlite_error(state->db, "Failed to update entry");
    }

    /* Check if row was actually updated */
    int changes = sqlite3_changes(state->db);
    if (changes == 0) {
        return ERROR(ERR_NOT_FOUND, "File '%s' not found in manifest", entry->filesystem_path);
    }

    return NULL;
}

/**
 * Update git_oid for all manifest entries from a specific profile
 *
 * Synchronizes git_oid to match the profile's current branch HEAD.
 * Maintains invariant: all files from profile P have git_oid = P's HEAD.
 *
 * Called after operations that move branch HEAD:
 * - manifest_sync_diff (after pull/merge)
 * - manifest_add_files (after commit)
 * - manifest_update_files (after commit)
 * - manifest_remove_files (after commit)
 *
 * Updates ALL entries (active and inactive) for consistency.
 * Inactive entries will be removed by apply, but should stay current.
 *
 * @param state State (must not be NULL, must have active transaction)
 * @param profile_name Profile name (must not be NULL)
 * @param new_git_oid New commit OID for profile HEAD (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_update_git_oid_for_profile(
    state_t *state,
    const char *profile_name,
    const git_oid *new_git_oid
) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);
    CHECK_NULL(profile_name);
    CHECK_NULL(new_git_oid);

    /* Convert OID to string */
    char oid_str[GIT_OID_HEXSZ + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), new_git_oid);

    /* Update ALL entries for this profile (active and inactive).
     * Maintains invariant: all files from profile P have git_oid = P's HEAD.
     * Inactive entries will be removed by apply, but should stay consistent. */
    const char *sql = "UPDATE virtual_manifest SET git_oid = ?1 WHERE profile = ?2";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(state->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return ERROR(ERR_STATE_INVALID, "Failed to prepare git_oid update: %s",
                    sqlite3_errmsg(state->db));
    }

    /* Bind parameters */
    sqlite3_bind_text(stmt, 1, oid_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, profile_name, -1, SQLITE_TRANSIENT);

    /* Execute */
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return ERROR(ERR_STATE_INVALID, "Failed to update git_oid for profile '%s': %s",
                    profile_name, sqlite3_errmsg(state->db));
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
    state_file_entry_t **out,
    size_t *count
) {
    CHECK_NULL(state);
    CHECK_NULL(profile);
    CHECK_NULL(out);
    CHECK_NULL(count);
    CHECK_NULL(state->db);
    CHECK_NULL(state->stmt_get_by_profile);

    *out = NULL;
    *count = 0;

    /* First, count entries */
    char count_sql[512];
    snprintf(count_sql, sizeof(count_sql),
             "SELECT COUNT(*) FROM virtual_manifest WHERE profile = ?;");

    sqlite3_stmt *stmt_count = NULL;
    int rc = sqlite3_prepare_v2(((state_t *)state)->db, count_sql, -1, &stmt_count, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare count query");
    }

    sqlite3_bind_text(stmt_count, 1, profile, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt_count);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt_count);
        return sqlite_error(state->db, "Failed to count entries");
    }

    size_t entry_count = (size_t)sqlite3_column_int64(stmt_count, 0);
    sqlite3_finalize(stmt_count);

    if (entry_count == 0) {
        return NULL;  /* Success, no entries */
    }

    /* Allocate array */
    state_file_entry_t *entries = calloc(entry_count, sizeof(state_file_entry_t));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate entries array");
    }

    /* Reset and bind profile */
    sqlite3_stmt *stmt = ((state_t *)state)->stmt_get_by_profile;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_text(stmt, 1, profile, -1, SQLITE_TRANSIENT);

    /* Fetch all entries */
    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < entry_count) {
        const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *)sqlite3_column_text(stmt, 1);
        const char *profile = (const char *)sqlite3_column_text(stmt, 2);
        const char *old_profile = (const char *)sqlite3_column_text(stmt, 3);
        const char *git_oid = (const char *)sqlite3_column_text(stmt, 4);
        const char *blob_oid = (const char *)sqlite3_column_text(stmt, 5);
        const char *type_str = (const char *)sqlite3_column_text(stmt, 6);

        /* Read mode as integer (0 if NULL) */
        mode_t mode = 0;
        if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
            mode = (mode_t)sqlite3_column_int(stmt, 7);
        }

        const char *owner = (const char *)sqlite3_column_text(stmt, 8);
        const char *group = (const char *)sqlite3_column_text(stmt, 9);
        int encrypted = sqlite3_column_int(stmt, 10);
        const char *state_str = (const char *)sqlite3_column_text(stmt, 11);
        sqlite3_int64 deployed_at = sqlite3_column_int64(stmt, 12);

        if (!fs_path || !storage_path || !profile ||
            !git_oid || !blob_oid || !type_str) {
            state_free_all_files(entries, i);
            return ERROR(ERR_STATE_INVALID, "NULL value in required column at row %zu", i);
        }

        entries[i].filesystem_path = strdup(fs_path);
        entries[i].storage_path = strdup(storage_path);
        entries[i].profile = strdup(profile);
        entries[i].old_profile = old_profile ? strdup(old_profile) : NULL;
        entries[i].git_oid = strdup(git_oid);
        entries[i].blob_oid = strdup(blob_oid);
        entries[i].mode = mode;
        entries[i].owner = owner ? strdup(owner) : NULL;
        entries[i].group = group ? strdup(group) : NULL;

        if (strcmp(type_str, "symlink") == 0) {
            entries[i].type = STATE_FILE_SYMLINK;
        } else if (strcmp(type_str, "executable") == 0) {
            entries[i].type = STATE_FILE_EXECUTABLE;
        } else {
            entries[i].type = STATE_FILE_REGULAR;
        }

        entries[i].encrypted = (encrypted != 0);
        entries[i].state = state_str ? strdup(state_str) : strdup(STATE_ACTIVE);
        entries[i].deployed_at = (time_t)deployed_at;

        if (!entries[i].filesystem_path || !entries[i].storage_path || !entries[i].profile ||
            !entries[i].git_oid || !entries[i].blob_oid || !entries[i].state) {
            state_free_all_files(entries, i + 1);
            return ERROR(ERR_MEMORY, "Failed to copy entry strings");
        }

        i++;
    }

    if (rc != SQLITE_DONE) {
        state_free_all_files(entries, i);
        return sqlite_error(state->db, "Failed to fetch entries");
    }

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
 * @param profile_name Profile name (must not be NULL)
 * @return Timestamp (0 if profile has no deployed files)
 */
time_t state_get_profile_timestamp(const state_t *state, const char *profile_name) {
    if (!state || !profile_name || !state->db) {
        return 0;
    }

    const char *sql = "SELECT MAX(deployed_at) FROM virtual_manifest WHERE profile = ?;";
    sqlite3_stmt *stmt = NULL;

    /* Cast away const for statement preparation */
    sqlite3 *db = ((state_t *)state)->db;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, profile_name, -1, SQLITE_TRANSIENT);

    time_t timestamp = 0;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        timestamp = (time_t)sqlite3_column_int64(stmt, 0);
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

    free(entry->storage_path);
    free(entry->filesystem_path);
    free(entry->profile);
    free(entry->old_profile);
    free(entry->git_oid);
    free(entry->blob_oid);
    free(entry->owner);
    free(entry->group);
    free(entry->state);
    free(entry);
}
