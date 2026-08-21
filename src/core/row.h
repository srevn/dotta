/**
 * row.h - One row of the manifest
 *
 * The manifest is the precedence-resolved view of every enabled profile
 * at HEAD: one row per managed filesystem path, both kinds, the winning
 * profile's claim already applied. This header holds the row and the two
 * row-shaped carriers every producer and consumer shares — the precedence
 * oracle (core/manifest) produces rows, the workspace partitions them,
 * deploy and cleanup plan over them, and the record dotta keeps of a path
 * (anchor_t, core/state.h) is written from one.
 *
 * Leaf header: nothing above base/ is included here, so state.h and
 * manifest.h can both build on it without including each other.
 */

#ifndef DOTTA_ROW_H
#define DOTTA_ROW_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/**
 * Manifest row — what should stand at a managed path, and from whom
 *
 * A row in the view means the path is managed: the enabled set, in
 * precedence order, names exactly one profile for it, and that profile's
 * tree (or, for a directory, its metadata.json) says what the path is.
 * Every field is Git-derived; nothing here records what dotta did.
 *
 * Per kind:
 *   blob types  — blob_oid is the tree entry; mode defaults from the
 *                 filemode (0644 / 0755, 0 for a link) and metadata may
 *                 override it; encrypted is the metadata-projected cache
 *                 of the blob's own bytes (docs/encryption-spec.md)
 *   DIRECTORY   — claimed from metadata alone: blob_oid is zero,
 *                 encrypted is false, mode/owner/group are the item's
 *
 * Strings are arena-backed by the producer; rows are read through
 * `const manifest_row_t *` and live for the producer's arena.
 */
typedef struct manifest_row {
    /* Identity */
    char *filesystem_path;      /* Deployed path (/home/user/.bashrc) */
    char *storage_path;         /* Path in profile (home/.bashrc) */
    char *profile;              /* Winning profile */

    /* What stands there */
    path_type_t type;           /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    git_oid blob_oid;           /* Blob the composed profile layer expects on disk (zero for DIRECTORY) */
    mode_t mode;                /* Permission mode (e.g., 0644), 0 if no metadata claim */
    char *owner;                /* Owner username (root/ paths only, can be NULL) */
    char *group;                /* Group name (root/ paths only, can be NULL) */
    bool encrypted;             /* Encryption flag (false for DIRECTORY) */
} manifest_row_t;

/**
 * Bound carrier for a borrowed slice of manifest rows
 *
 * Structural type — parallels libgit2's git_strarray and base/array's
 * string_array_t. The producer's signature dictates lifetime via the
 * arena (or other allocator) that backs the rows.
 *
 * Lifetime examples:
 *   workspace_files(ws)             → backed by ws->arena (workspace lifetime).
 *   apply's local divergent buffer  → backed by a ptr_array_t on the heap;
 *                                     valid for the caller's stack scope.
 */
typedef struct {
    const manifest_row_t *const *entries;
    size_t count;
} manifest_rows_t;

/**
 * Project a ptr_array_t bucket of borrowed rows as a typed slice
 *
 * Buckets filled by ptr_array_push(&bucket, row) hold `void *`; the cast
 * layers const onto both pointer levels (T ** → const T *const *, the same
 * rule workspace_files relies on). The view aliases the bucket's storage
 * and is valid for the bucket's lifetime — deploy plans and results, and
 * any other producer that accumulates rows, project through this so
 * every consumer reads one carrier shape.
 */
static inline manifest_rows_t manifest_rows_view(const ptr_array_t *bucket) {
    return (manifest_rows_t){
        .entries = (const manifest_row_t *const *) bucket->items,
        .count = bucket->count,
    };
}

/**
 * Convert a path type to its git filemode
 *
 * The canonical conversion used by workspace divergence analysis and the
 * historical-diff path.
 *
 * Mapping:
 *   PATH_TYPE_SYMLINK    -> GIT_FILEMODE_LINK (0120000)
 *   PATH_TYPE_EXECUTABLE -> GIT_FILEMODE_BLOB_EXECUTABLE (0100755)
 *   PATH_TYPE_DIRECTORY  -> GIT_FILEMODE_TREE (0040000)
 *   PATH_TYPE_FILE       -> GIT_FILEMODE_BLOB (0100644)
 *
 * @param type Path type
 * @return Corresponding git filemode
 */
static inline git_filemode_t path_type_to_git_filemode(path_type_t type) {
    switch (type) {
        case PATH_TYPE_SYMLINK:
            return GIT_FILEMODE_LINK;
        case PATH_TYPE_EXECUTABLE:
            return GIT_FILEMODE_BLOB_EXECUTABLE;
        case PATH_TYPE_DIRECTORY:
            return GIT_FILEMODE_TREE;
        default:
            return GIT_FILEMODE_BLOB;
    }
}

#endif /* DOTTA_ROW_H */
