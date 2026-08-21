/**
 * Manifest Module — the precedence oracle
 *
 * The manifest is the precedence-resolved view of every enabled profile at
 * HEAD: one row per managed filesystem path, both kinds, the winning
 * profile's claim already applied (manifest_row_t, below). It is computed
 * from Git at every load and never stored — Git × enabled set × mount
 * table → rows is a pure function, and nothing here touches the state
 * database. Surface is two-fold:
 *
 *   - Builders: manifest_build walks every enabled profile in precedence
 *     order (later profiles override earlier); manifest_build_tree walks
 *     one Git tree — the historical-diff path (cmd_diff) — and is the
 *     same per-profile step applied once. Both produce manifest_row_t
 *     rows directly, the one row shape every consumer reads, so there is
 *     no bridge between the build step and its readers.
 *
 *   - Readers: manifest_rows (both kinds, unordered), manifest_lookup
 *     (by filesystem path, O(1)) and manifest_lookup_storage (by storage
 *     path, linear); and manifest_diff, the per-profile delta between two
 *     views that the scope-changing verbs and sync print their receipts
 *     from.
 *
 * Core Principles:
 *   - Pure: the view is a function of Git, the enabled set and the mount
 *     table — the same inputs give the same rows on every machine
 *   - Computed, never stored: every load builds it; nothing invalidates
 *     it because nothing is held past its lifetime
 *   - Precedence-aware: one row per path, the winner's kind
 *
 * Workflow:
 *   Commands → manifest_build → rows → workspace / deploy / cleanup
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

#include "core/metadata.h"
#include "core/state.h"
#include "infra/mount.h"

/**
 * Manifest row — what should stand at a managed path, and from whom
 *
 * A row in the view means the path is managed: the enabled set, in
 * precedence order, names exactly one profile for it, and that profile's
 * tree (or, for a directory, its metadata.json) says what the path is.
 * Every field is Git-derived; nothing here records what dotta did — the
 * record dotta keeps of a path (anchor_t, core/state.h) is written from
 * one of these.
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
 * `const manifest_row_t *` and live for the producer's arena. The
 * precedence oracle below produces rows, the workspace partitions them,
 * deploy and cleanup plan over them.
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

/**
 * Manifest (opaque)
 *
 * Rows and their strings live in the arena the builder was given; the
 * path index is heap-allocated and released by manifest_free. A view
 * borrows nothing else — not the caller's profile list, not the mount
 * table — so it outlives both, for the arena's lifetime.
 */
typedef struct manifest manifest_t;

/**
 * Build the manifest from profile names
 *
 * Performance: O(N) where N is total files across all profiles.
 * One Git tree alive per iteration (loaded, walked, freed).
 *
 * `mounts` MUST cover every profile in `profiles` (callers build it from
 * the same list). A custom/ entry whose profile has no target binding is
 * a hard error from the callback (ERR_STATE_INVALID with a repair hint) —
 * every enabling command guarantees the binding, so reaching that branch
 * means corruption, not a machine that lacks a --target.
 *
 * A profile whose branch does not exist contributes no rows; the scope
 * layer already warns about the dead branch on every run, and the
 * workspace reads that profile's records as orphans. Only the existence
 * question is tolerant: a branch that exists but cannot be loaded
 * (corrupt object, I/O) still fails the build, as does a failed lookup —
 * both stay retryable errors, never silent omissions.
 *
 * Per profile, in order: the tree's blobs are claimed first, then the
 * DIRECTORY items of its metadata.json. A blob and a DIRECTORY item of
 * the same profile at one path is stale metadata — a path is a tree or a
 * blob — and the tree is the content authority: the directory claim
 * finds its own profile's row and yields. Across profiles the later
 * (higher) claim replaces the slot whatever its kind, so the view holds
 * one row per path, the winner's kind. A profile without metadata.json
 * contributes no directories and is skipped, not an error.
 *
 * Row order is unspecified; consumers that need parent-before-child
 * sort their own pointer arrays (the workspace does). The oracle is a set.
 *
 * Memory:
 *   - rows, per-row strings and the profile names (duplicated once per
 *     profile): arena-allocated; the caller's arena reclaims them at
 *     arena_destroy. The view borrows nothing from `profiles`.
 *   - index hashmap: heap-allocated; on success the caller releases it
 *     with manifest_free. On error, the hashmap (if allocated) is freed
 *     here and *out is NULL.
 *
 * @param repo Git repository (must not be NULL)
 * @param profiles Enabled profiles in precedence order (must not be NULL;
 *                 may be empty — an empty view)
 * @param mounts Per-machine mount table covering `profiles` (must not be NULL)
 * @param arena Arena backing every allocation produced by the call
 *              (must not be NULL)
 * @param out Manifest (must not be NULL; caller frees with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build(
    git_repository *repo,
    const string_array_t *profiles,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
);

/**
 * Build the manifest from a single Git tree
 *
 * Used by the historical-diff path (cmd_diff): given a tree, profile,
 * mount table, and optional per-tree metadata, produces a manifest_row_t
 * row for every blob the tree exposes (sans repository metadata files —
 * .dottaignore, .bootstrap, .git/, .dotta/) and, when metadata is
 * supplied, for every DIRECTORY item it claims — the same per-profile
 * step manifest_build runs, applied once. Readers that want files only
 * test row->type.
 *
 * Metadata, when supplied, is applied row-by-row in lockstep with the
 * tree walk — mode, owner, group, and encrypted are filled from the
 * tree's own metadata.json. Pass NULL to skip metadata application
 * (rows keep Git-derived defaults, and no directories are claimed).
 * Callers that have already loaded the tree's metadata for their own
 * purposes should pass it here.
 *
 * Custom-prefix resolution is delegated to `mounts`. The handle MUST
 * record a binding for `profile` (with target set) when the tree
 * contains custom/ entries; a missing binding is a hard error from the
 * build callback (ERR_STATE_INVALID with a repair hint). Trees without
 * custom/ entries can pass any mount table, including one with no
 * binding for `profile`.
 *
 * Memory: same contract as manifest_build — every allocation produced by
 * the call lives in the caller's arena; the index is manifest_free's.
 *
 * @param tree Git tree to build from (must not be NULL)
 * @param profile Profile name carried on each row (must not be NULL;
 *                duplicated into the arena)
 * @param mounts Per-machine mount table (must not be NULL)
 * @param metadata Optional per-tree metadata applied to rows (can be NULL)
 * @param arena Arena backing every allocation produced by the call
 *              (must not be NULL)
 * @param out Manifest (must not be NULL; caller frees with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build_tree(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    manifest_t **out
);

/**
 * Every row of the view, both kinds, unordered
 *
 * Pure value return — no allocation, no error path. The slice aliases
 * the view's own storage and is valid for the arena's lifetime.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over every row
 */
manifest_rows_t manifest_rows(const manifest_t *manifest);

/**
 * Look up a row by filesystem path
 *
 * O(1) over the view's index — a path is one managed thing, whatever
 * its kind; callers that want one kind test row->type. NULL when the
 * path is not managed.
 *
 * @param manifest Manifest (NULL returns NULL)
 * @param filesystem_path Path to look up (NULL returns NULL)
 * @return Borrowed row pointer, or NULL if the path is not in the view
 */
const manifest_row_t *manifest_lookup(
    const manifest_t *manifest,
    const char *filesystem_path
);

/**
 * Look up a row by storage path
 *
 * Linear scan — the callers (list, show) ask once per command. Since
 * precedence is resolved, each storage path under home/ and root/ maps
 * to exactly one row; under custom/ two profiles with distinct targets
 * may share a storage path, and the first match is returned.
 *
 * @param manifest Manifest (NULL returns NULL)
 * @param storage_path Storage path to look up, e.g. "home/.bashrc"
 *                     (NULL returns NULL)
 * @return Borrowed row pointer, or NULL if no row has the storage path
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *storage_path
);

/**
 * Free a manifest — the heap index only; rows are the arena's
 *
 * No-op on NULL.
 */
void manifest_free(manifest_t *manifest);

/**
 * Per-profile statistics from a view-to-view diff
 *
 * Fields are populated conditionally based on the profile's role in the
 * transition. The same profile can gain and lose paths simultaneously
 * (e.g., enable A while B was reordered above it), so gain-side and
 * loss-side fields are independent.
 *
 *   Gain-side  — the profile claims path(s) in `after`.
 *   Loss-side  — the profile owned path(s) in `before` that it does not
 *                in `after`.
 *
 * Counters describe the two views and the record; they do NOT verify
 * disk matches anything. Verification is workspace divergence analysis
 * (status/diff/apply). Both kinds count.
 */
typedef struct {
    const char *profile;         /* Profile name (borrowed from the profiles filter) */

    /* Gain-side */
    size_t claimed;              /* Rows this profile wins in `after` */

    /* Gain-side, subsets of claimed (the remainder was unchanged) */
    size_t added;                /* … whose path `before` did not have */
    size_t updated;              /* … whose path `before` had, with blob, type or mode moved */

    /* Loss-side */
    size_t reassigned;           /* Paths `before` had under this profile that `after` gives another */
    size_t departed_owned;       /* Paths `before` had under this profile, gone from `after`, with a record dotta owns (deployed_at > 0) */
    size_t departed_observed;    /* … with a record dotta never owned */
    size_t departed_unseen;      /* … with no record: nothing for apply to do */
} manifest_diff_stats_t;

/**
 * Attribute the transition between two views to profiles
 *
 * The delta the scope-changing verbs (profile enable / disable) and sync
 * print their receipts from: what each profile in `profiles` claims in
 * `after` that it did not in `before`, what it lost to another profile,
 * and what left the view under it — split by the record, because only a
 * path dotta has observed has anything for apply to do at its departure.
 *
 * Attribution (for a profile P in `profiles`):
 *   - every row of `after` under P: claimed; added if `before` has no row
 *     at the path; updated if it has one whose blob, type or mode differs
 *     (owner/group travel with a metadata commit rare enough to ride on
 *     the workspace's verdict instead)
 *   - every row of `before` under P whose path `after` gives another
 *     profile: reassigned
 *   - every row of `before` under P whose path `after` lacks: departed —
 *     owned, observed or unseen by the record at that path
 *   Overlap semantics: if B overrides A for path X, B gets claimed for X
 *   and A gets reassigned for X. The sum is the true size of `after`.
 *
 * `before` may be NULL — an empty view (clone, the first enable): every
 * row of `after` is then added and nothing departed.
 *
 * Preconditions:
 *   - profiles' entries are pairwise unique (duplicates return
 *     ERR_INVALID_ARG — two slots would silently collapse into one)
 *   - out_stats points to an array of length profiles->count; it is
 *     zero-filled here with each profile's name set, so a caller reads
 *     the counts without asking whether anything changed: all-zero
 *     means "nothing for apply to do came out of this transition"
 *
 * Performance: O(A + B + R) — one pass over each view and one index
 * over the record; no Git, no disk, no database.
 *
 * @param before View before the transition (may be NULL = empty)
 * @param after View after the transition (must not be NULL)
 * @param anchors The record, as state_get_all_anchors returns it (may be
 *                NULL when anchor_count is 0)
 * @param anchor_count Number of records
 * @param profiles Profiles to attribute to (must not be NULL)
 * @param out_stats Parallel array (length profiles->count; must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_diff(
    const manifest_t *before,
    const manifest_t *after,
    const anchor_t *anchors,
    size_t anchor_count,
    const string_array_t *profiles,
    manifest_diff_stats_t *out_stats
);

#endif /* DOTTA_MANIFEST_H */
