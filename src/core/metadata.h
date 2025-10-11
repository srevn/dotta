/**
 * metadata.h - File metadata preservation system
 *
 * Captures and restores file permissions (mode) across different machines.
 * Metadata is stored in .dotta/metadata.json within each profile branch,
 * enabling permissions to travel with files through git operations.
 *
 * Design principles:
 * - Track mode (permissions) only - no ownership or timestamps
 * - Per-profile storage for natural layering (darwin overrides global)
 * - Automatic capture during add/update operations
 * - Automatic restoration during apply/revert operations
 * - Graceful degradation when metadata is missing
 *
 * JSON Schema:
 * {
 *   "version": 1,
 *   "files": {
 *     "home/.ssh/config": {"mode": "0600"},
 *     "home/.local/bin/backup.sh": {"mode": "0755"}
 *   }
 * }
 */

#ifndef DOTTA_METADATA_H
#define DOTTA_METADATA_H

#include <git2.h>
#include <sys/types.h>

#include "types.h"

#define METADATA_FILE_PATH ".dotta/metadata.json"
#define METADATA_VERSION 1

/**
 * Metadata entry for a single file
 */
typedef struct {
    char *storage_path;    /* Path in profile (e.g., home/.bashrc) */
    mode_t mode;           /* Permission mode (e.g., 0600, 0644, 0755) */
} metadata_entry_t;

/* Forward declaration */
typedef struct hashmap hashmap_t;

/**
 * Metadata collection
 *
 * Uses both array (for iteration/serialization) and hashmap (for O(1) lookups).
 * The hashmap values point to entries in the array (no separate allocation).
 */
typedef struct {
    metadata_entry_t *entries;
    size_t count;
    size_t capacity;
    int version;           /* Schema version (currently 1) */
    hashmap_t *index;      /* Maps storage_path -> metadata_entry_t* (O(1) lookup) */
} metadata_t;

/**
 * Create empty metadata collection
 *
 * @param out Metadata structure (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_create_empty(metadata_t **out);

/**
 * Free metadata structure
 *
 * Frees all entries and the structure itself.
 *
 * @param metadata Metadata to free (can be NULL)
 */
void metadata_free(metadata_t *metadata);

/**
 * Create metadata entry
 *
 * @param storage_path Path in profile (must not be NULL)
 * @param mode Permission mode (e.g., 0600, 0644, 0755)
 * @param out Entry (must not be NULL, caller must free with metadata_entry_free)
 * @return Error or NULL on success
 */
error_t *metadata_entry_create(
    const char *storage_path,
    mode_t mode,
    metadata_entry_t **out
);

/**
 * Free metadata entry
 *
 * @param entry Entry to free (can be NULL)
 */
void metadata_entry_free(metadata_entry_t *entry);

/**
 * Add or update metadata entry
 *
 * If an entry with the same storage_path exists, it is replaced.
 * Otherwise, a new entry is added.
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param mode Permission mode
 * @return Error or NULL on success
 */
error_t *metadata_set_entry(
    metadata_t *metadata,
    const char *storage_path,
    mode_t mode
);

/**
 * Get metadata entry for a file
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param out Entry pointer (must not be NULL, borrowed reference - do not free)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_get_entry(
    const metadata_t *metadata,
    const char *storage_path,
    const metadata_entry_t **out
);

/**
 * Remove metadata entry
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @return Error or NULL on success (not found returns ERR_NOT_FOUND)
 */
error_t *metadata_remove_entry(
    metadata_t *metadata,
    const char *storage_path
);

/**
 * Check if metadata entry exists
 *
 * @param metadata Metadata collection (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @return true if entry exists
 */
bool metadata_has_entry(
    const metadata_t *metadata,
    const char *storage_path
);

/**
 * Merge metadata from multiple sources
 *
 * Merges metadata collections according to precedence order.
 * Later sources override earlier ones for conflicting entries.
 * This implements profile layering (e.g., darwin overrides global).
 *
 * Example:
 *   sources[0] = global metadata
 *   sources[1] = darwin metadata
 *   Result: darwin entries override global entries
 *
 * @param sources Array of metadata collections (must not be NULL)
 * @param count Number of sources
 * @param out Merged metadata (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *metadata_merge(
    const metadata_t **sources,
    size_t count,
    metadata_t **out
);

/**
 * Capture metadata from filesystem file
 *
 * Reads file permissions from the filesystem and creates a metadata entry.
 * Symlinks are skipped (returns NULL with no error - caller should check *out).
 *
 * @param filesystem_path Path to file on disk (must not be NULL)
 * @param storage_path Path in profile (must not be NULL)
 * @param out Entry (must not be NULL, caller must free with metadata_entry_free)
 *            Set to NULL if file is a symlink (not an error)
 * @return Error or NULL on success
 */
error_t *metadata_capture_from_file(
    const char *filesystem_path,
    const char *storage_path,
    metadata_entry_t **out
);

/**
 * Load metadata from profile branch
 *
 * Reads .dotta/metadata.json from the specified branch.
 * If the file doesn't exist, returns ERR_NOT_FOUND (not a fatal error).
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Branch name (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success (ERR_NOT_FOUND if file doesn't exist)
 */
error_t *metadata_load_from_branch(
    git_repository *repo,
    const char *branch_name,
    metadata_t **out
);

/**
 * Load metadata from file path
 *
 * Reads and parses metadata from a JSON file.
 * Returns ERR_NOT_FOUND if file doesn't exist.
 *
 * @param file_path Path to metadata JSON file (must not be NULL)
 * @param out Metadata (must not be NULL, caller must free with metadata_free)
 * @return Error or NULL on success
 */
error_t *metadata_load_from_file(
    const char *file_path,
    metadata_t **out
);

/**
 * Save metadata to worktree
 *
 * Writes .dotta/metadata.json to a worktree directory.
 * Creates the .dotta/ directory if it doesn't exist.
 * The file should then be staged and committed by the caller.
 *
 * @param worktree_path Path to worktree root (must not be NULL)
 * @param metadata Metadata to save (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_save_to_worktree(
    const char *worktree_path,
    const metadata_t *metadata
);

/**
 * Parse mode string to mode_t
 *
 * Parses octal mode string (e.g., "0600", "0644", "0755") to mode_t.
 * Validates that mode is within valid range (0000-0777).
 *
 * @param mode_str Mode string (must not be NULL)
 * @param out Mode value (must not be NULL)
 * @return Error or NULL on success
 */
error_t *metadata_parse_mode(const char *mode_str, mode_t *out);

/**
 * Format mode_t to string
 *
 * Formats mode_t as octal string (e.g., 0600 -> "0600").
 *
 * @param mode Mode value
 * @param out Mode string (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *metadata_format_mode(mode_t mode, char **out);

#endif /* DOTTA_METADATA_H */
