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
#include "utils/array.h"

/* Schema version - must match database */
#define STATE_SCHEMA_VERSION "1"

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

    /* Cached selected profiles (loaded lazily) */
    string_array_t *profiles;
    bool profiles_loaded;

    /* Prepared statements (initialized once, reused) */
    sqlite3_stmt *stmt_insert_file;     /* INSERT OR REPLACE deployed_files */
    sqlite3_stmt *stmt_remove_file;     /* DELETE FROM deployed_files */
    sqlite3_stmt *stmt_file_exists;     /* SELECT 1 FROM deployed_files */
    sqlite3_stmt *stmt_get_file;        /* SELECT * FROM deployed_files */
    sqlite3_stmt *stmt_insert_profile;  /* INSERT INTO selected_profiles */
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

    return ERROR(ERR_STATE_INVALID,
        "%s: %s (SQLite error %d)",
        context, errmsg, errcode);
}

/**
 * Initialize database schema
 *
 * Creates tables if they don't exist:
 * - schema_meta: Schema versioning
 * - selected_profiles: User's profile selection (with indexes)
 * - deployed_files: Deployed file manifest (with indexes)
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

        /* Selected profiles table (authority: profile commands) */
        "CREATE TABLE IF NOT EXISTS selected_profiles ("
        "    position INTEGER PRIMARY KEY,"
        "    name TEXT NOT NULL UNIQUE,"
        "    selected_at INTEGER NOT NULL"
        ");"

        /* Index for existence checks */
        "CREATE INDEX IF NOT EXISTS idx_selected_name "
        "ON selected_profiles(name);"

        /* Deployed files table (authority: apply/revert) */
        "CREATE TABLE IF NOT EXISTS deployed_files ("
        "    filesystem_path TEXT PRIMARY KEY,"
        "    storage_path TEXT NOT NULL,"
        "    profile TEXT NOT NULL,"
        "    type TEXT NOT NULL CHECK(type IN ('file', 'symlink', 'executable')),"
        "    hash TEXT,"
        "    mode TEXT,"
        "    deployed_at INTEGER NOT NULL"
        ");"

        /* Indexes for common queries */
        "CREATE INDEX IF NOT EXISTS idx_deployed_profile "
        "ON deployed_files(profile);"

        "CREATE INDEX IF NOT EXISTS idx_deployed_storage "
        "ON deployed_files(storage_path);";

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

    /* Insert/update file (used in apply loop - hot path) */
    const char *sql_insert =
        "INSERT OR REPLACE INTO deployed_files "
        "(filesystem_path, storage_path, profile, type, hash, mode, deployed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_insert, -1,
                           &state->stmt_insert_file, NULL);
    if (rc != SQLITE_OK) {
        return sqlite_error(state->db, "Failed to prepare insert statement");
    }

    /* File exists check (used in status - hot path) */
    const char *sql_exists =
        "SELECT 1 FROM deployed_files WHERE filesystem_path = ? LIMIT 1;";

    rc = sqlite3_prepare_v2(state->db, sql_exists, -1,
                           &state->stmt_file_exists, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        return sqlite_error(state->db, "Failed to prepare exists statement");
    }

    /* Get file (used in workspace analysis) */
    const char *sql_get =
        "SELECT storage_path, profile, type, hash, mode "
        "FROM deployed_files WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_get, -1,
                           &state->stmt_get_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_file_exists);
        return sqlite_error(state->db, "Failed to prepare get statement");
    }

    /* Remove file (used in revert) */
    const char *sql_remove =
        "DELETE FROM deployed_files WHERE filesystem_path = ?;";

    rc = sqlite3_prepare_v2(state->db, sql_remove, -1,
                           &state->stmt_remove_file, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
        return sqlite_error(state->db, "Failed to prepare remove statement");
    }

    /* Insert profile (used in profile select) */
    const char *sql_profile =
        "INSERT INTO selected_profiles (position, name, selected_at) "
        "VALUES (?, ?, ?);";

    rc = sqlite3_prepare_v2(state->db, sql_profile, -1,
                           &state->stmt_insert_profile, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(state->stmt_insert_file);
        sqlite3_finalize(state->stmt_file_exists);
        sqlite3_finalize(state->stmt_get_file);
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

    if (state->stmt_insert_file) {
        sqlite3_finalize(state->stmt_insert_file);
        state->stmt_insert_file = NULL;
    }

    if (state->stmt_file_exists) {
        sqlite3_finalize(state->stmt_file_exists);
        state->stmt_file_exists = NULL;
    }

    if (state->stmt_get_file) {
        sqlite3_finalize(state->stmt_get_file);
        state->stmt_get_file = NULL;
    }

    if (state->stmt_remove_file) {
        sqlite3_finalize(state->stmt_remove_file);
        state->stmt_remove_file = NULL;
    }

    if (state->stmt_insert_profile) {
        sqlite3_finalize(state->stmt_insert_profile);
        state->stmt_insert_profile = NULL;
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
    const char *sql = "SELECT name FROM selected_profiles ORDER BY position ASC;";
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
 * Get selected profiles
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
 * Get unique profiles that have deployed files
 *
 * Extracts all unique profile names from the deployed_files table.
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
        "SELECT DISTINCT profile FROM deployed_files ORDER BY profile;";

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
            return ERROR(ERR_STATE_INVALID, "NULL profile name in deployed_files");
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
 * Set selected profiles
 *
 * Hot path - must be fast even with 10,000 deployed files.
 * Only modifies selected_profiles table (deployed_files untouched).
 *
 * @param state State (must not be NULL)
 * @param profiles Array of profile names (must not be NULL)
 * @param count Number of profiles
 * @return Error or NULL on success
 */
error_t *state_set_profiles(
    state_t *state,
    const char **profiles,
    size_t count
) {
    CHECK_NULL(state);
    CHECK_NULL(profiles);
    CHECK_NULL(state->db);

    /* Delete all existing profiles */
    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM selected_profiles;",
                         NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to clear profiles: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    /* Insert new profiles */
    time_t now = time(NULL);
    for (size_t i = 0; i < count; i++) {
        /* Reset and bind statement */
        sqlite3_reset(state->stmt_insert_profile);
        sqlite3_clear_bindings(state->stmt_insert_profile);

        sqlite3_bind_int64(state->stmt_insert_profile, 1, (sqlite3_int64)i);
        sqlite3_bind_text(state->stmt_insert_profile, 2, profiles[i], -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(state->stmt_insert_profile, 3, (sqlite3_int64)now);

        rc = sqlite3_step(state->stmt_insert_profile);
        if (rc != SQLITE_DONE) {
            return sqlite_error(state->db, "Failed to insert profile");
        }
    }

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
        error_t *err = string_array_push(state->profiles, profiles[i]);
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
    sqlite3_bind_text(state->stmt_insert_file, 1,
                     entry->filesystem_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 2,
                     entry->storage_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_file, 3,
                     entry->profile, -1, SQLITE_TRANSIENT);

    const char *type_str = entry->type == STATE_FILE_REGULAR ? "file" :
                          entry->type == STATE_FILE_SYMLINK ? "symlink" :
                          "executable";
    sqlite3_bind_text(state->stmt_insert_file, 4, type_str, -1, SQLITE_STATIC);

    if (entry->hash) {
        sqlite3_bind_text(state->stmt_insert_file, 5,
                         entry->hash, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 5);
    }

    if (entry->mode) {
        sqlite3_bind_text(state->stmt_insert_file, 6,
                         entry->mode, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(state->stmt_insert_file, 6);
    }

    sqlite3_bind_int64(state->stmt_insert_file, 7, (sqlite3_int64)time(NULL));

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

    /* Extract columns with NULL checking */
    const char *storage_path = (const char *)sqlite3_column_text(stmt, 0);
    const char *profile = (const char *)sqlite3_column_text(stmt, 1);
    const char *type_str = (const char *)sqlite3_column_text(stmt, 2);
    const char *hash = (const char *)sqlite3_column_text(stmt, 3);
    const char *mode = (const char *)sqlite3_column_text(stmt, 4);

    /* Validate required columns */
    if (!storage_path || !profile || !type_str) {
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
        type,
        hash,
        mode,
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
    const char *sql_count = "SELECT COUNT(*) FROM deployed_files;";
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

    /* Query all files */
    const char *sql_files =
        "SELECT filesystem_path, storage_path, profile, type, hash, mode "
        "FROM deployed_files ORDER BY filesystem_path;";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(state->db, sql_files, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(entries);
        return sqlite_error(state->db, "Failed to prepare select query");
    }

    size_t i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < file_count) {
        /* Get columns with NULL checking */
        const char *fs_path = (const char *)sqlite3_column_text(stmt, 0);
        const char *storage_path = (const char *)sqlite3_column_text(stmt, 1);
        const char *profile = (const char *)sqlite3_column_text(stmt, 2);
        const char *type_str = (const char *)sqlite3_column_text(stmt, 3);
        const char *hash = (const char *)sqlite3_column_text(stmt, 4);
        const char *mode = (const char *)sqlite3_column_text(stmt, 5);

        /* Validate non-nullable columns */
        if (!fs_path || !storage_path || !profile || !type_str) {
            sqlite3_finalize(stmt);
            state_free_all_files(entries, i);
            return ERROR(ERR_STATE_INVALID,
                "NULL value in required column at row %zu", i);
        }

        /* Copy strings */
        entries[i].filesystem_path = strdup(fs_path);
        entries[i].storage_path = strdup(storage_path);
        entries[i].profile = strdup(profile);
        entries[i].hash = hash ? strdup(hash) : NULL;
        entries[i].mode = mode ? strdup(mode) : NULL;

        /* Parse type */
        if (strcmp(type_str, "symlink") == 0) {
            entries[i].type = STATE_FILE_SYMLINK;
        } else if (strcmp(type_str, "executable") == 0) {
            entries[i].type = STATE_FILE_EXECUTABLE;
        } else {
            entries[i].type = STATE_FILE_REGULAR;
        }

        /* Check allocation success */
        if (!entries[i].filesystem_path || !entries[i].storage_path ||
            !entries[i].profile) {
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
        free(entries[i].hash);
        free(entries[i].mode);
    }

    free(entries);
}

/**
 * Clear all file entries (keeps profiles and timestamp)
 *
 * Efficiently truncates deployed_files table.
 *
 * @param state State (must not be NULL)
 * @return Error or NULL on success
 */
error_t *state_clear_files(state_t *state) {
    CHECK_NULL(state);
    CHECK_NULL(state->db);

    char *errmsg = NULL;
    int rc = sqlite3_exec(state->db, "DELETE FROM deployed_files;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        error_t *err = ERROR(ERR_STATE_INVALID,
            "Failed to clear deployed files: %s",
            errmsg ? errmsg : sqlite3_errstr(rc));
        sqlite3_free(errmsg);
        return err;
    }

    return NULL;
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
            err = ERROR(ERR_STATE_INVALID,
                "Failed to commit transaction: %s",
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
            err = ERROR(ERR_CONFLICT,
                "Failed to acquire write lock: %s",
                errmsg ? errmsg : sqlite3_errstr(rc));
            sqlite3_free(errmsg);
            finalize_statements(state);
            sqlite3_close(db);
            state->db = NULL;
            return err;
        }

        /* Write profiles if any */
        if (state->profiles && string_array_size(state->profiles) > 0) {
            const char **profile_names = calloc(string_array_size(state->profiles), sizeof(char*));
            if (!profile_names) {
                sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
                finalize_statements(state);
                sqlite3_close(db);
                state->db = NULL;
                return ERROR(ERR_MEMORY, "Failed to allocate profile array");
            }

            for (size_t i = 0; i < string_array_size(state->profiles); i++) {
                profile_names[i] = string_array_get(state->profiles, i);
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
            err = ERROR(ERR_STATE_INVALID,
                "Failed to commit transaction: %s",
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
 * @param hash Content hash (can be NULL)
 * @param mode Permission mode (can be NULL)
 * @param out Entry (must not be NULL, caller must free with state_free_entry)
 * @return Error or NULL on success
 */
error_t *state_create_entry(
    const char *storage_path,
    const char *filesystem_path,
    const char *profile,
    state_file_type_t type,
    const char *hash,
    const char *mode,
    state_file_entry_t **out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    state_file_entry_t *entry = calloc(1, sizeof(state_file_entry_t));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate entry");
    }

    entry->storage_path = strdup(storage_path);
    entry->filesystem_path = strdup(filesystem_path);
    entry->profile = strdup(profile);
    entry->type = type;
    entry->hash = hash ? strdup(hash) : NULL;
    entry->mode = mode ? strdup(mode) : NULL;

    if (!entry->storage_path || !entry->filesystem_path || !entry->profile) {
        state_free_entry(entry);
        return ERROR(ERR_MEMORY, "Failed to copy entry fields");
    }

    *out = entry;
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

    const char *sql = "SELECT MAX(deployed_at) FROM deployed_files WHERE profile = ?;";
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
    free(entry->hash);
    free(entry->mode);
    free(entry);
}
