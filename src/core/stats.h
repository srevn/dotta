/**
 * stats.h - Profile and file statistics
 *
 * Provides efficient statistics gathering for profiles and files,
 * including sizes, counts, and commit history tracking.
 *
 * Design principles:
 * - Minimize expensive operations (defer to verbose mode)
 * - Single-pass algorithms where possible
 * - Clear ownership semantics
 * - Reusable across multiple commands (list, status, etc.)
 *
 * Note: This header uses profile_t which is defined in profiles.h.
 * Users of this header must also include profiles.h.
 */

#ifndef DOTTA_STATS_H
#define DOTTA_STATS_H

#include <git2.h>
#include <time.h>

#include "types.h"
#include "core/profiles.h"
#include "utils/hashmap.h"

/**
 * Profile-level statistics
 *
 * Aggregate information about an entire profile.
 */
typedef struct {
    size_t file_count;   /* Total number of files */
    size_t total_size;   /* Total size in bytes */
} profile_stats_t;

/**
 * File-level statistics
 *
 * Information about a single file.
 */
typedef struct {
    size_t size;         /* File size in bytes */
} file_stats_t;

/**
 * Commit information for display
 *
 * Lightweight commit metadata for list/history views.
 */
typedef struct {
    git_oid oid;              /* Commit OID */
    char *message_summary;    /* First line of commit message (caller must free) */
    time_t timestamp;         /* Commit timestamp */
} commit_info_t;

/**
 * File history
 *
 * List of commits that modified a specific file.
 */
typedef struct {
    commit_info_t *commits;   /* Array of commit info (caller must free) */
    size_t count;             /* Number of commits */
} file_history_t;

/**
 * Get profile statistics
 *
 * Walks profile tree once to compute file count and total size.
 * Efficient: O(n) where n = number of files.
 *
 * Note: This function performs lazy loading of the profile tree,
 * which mutates the profile structure. Caller must own the profile.
 *
 * @param repo Repository (must not be NULL)
 * @param profile Profile (must not be NULL, will be mutated for lazy loading)
 * @param out Statistics (must not be NULL, filled by function)
 * @return Error or NULL on success
 */
error_t *stats_get_profile_stats(
    git_repository *repo,
    profile_t *profile,
    profile_stats_t *out
);

/**
 * Get file statistics
 *
 * Extracts size from git blob metadata (fast).
 *
 * @param repo Repository (must not be NULL)
 * @param entry Tree entry (must not be NULL)
 * @param out Statistics (must not be NULL, filled by function)
 * @return Error or NULL on success
 */
error_t *stats_get_file_stats(
    git_repository *repo,
    git_tree_entry *entry,
    file_stats_t *out
);

/**
 * Build file→commit index for profile
 *
 * Creates an efficient mapping from each file to its most recent commit.
 * Walks commit history once: O(commits × files_per_commit).
 *
 * This is expensive (walks entire history) but much more efficient than
 * querying per-file (which would be O(files × commits)).
 *
 * The index maps: storage_path (char*) → commit_info_t*
 * Caller must free with: hashmap_free(index, (void(*)(void*))stats_free_commit_info)
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param out_index File→commit hashmap (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *stats_build_file_commit_index(
    git_repository *repo,
    const char *profile_name,
    hashmap_t **out_index
);

/**
 * Get file history
 *
 * Returns all commits that modified the specified file, in reverse
 * chronological order (newest first).
 *
 * This walks the entire commit history for the profile: O(commits).
 * Use sparingly (only when user requests specific file history).
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param file_path Storage path of file (must not be NULL)
 * @param out File history (must not be NULL, caller must free with stats_free_file_history)
 * @return Error or NULL on success
 */
error_t *stats_get_file_history(
    git_repository *repo,
    const char *profile_name,
    const char *file_path,
    file_history_t **out
);

/**
 * Free commit info
 *
 * @param info Commit info to free (can be NULL)
 */
void stats_free_commit_info(commit_info_t *info);

/**
 * Free file history
 *
 * @param history File history to free (can be NULL)
 */
void stats_free_file_history(file_history_t *history);

#endif /* DOTTA_STATS_H */
