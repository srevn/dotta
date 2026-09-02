/**
 * Manifest Module — the precedence oracle
 *
 * The manifest is the precedence-resolved view of every enabled profile at HEAD:
 * one row per managed filesystem path, both kinds, the winning profile's claim
 * already applied (manifest_row_t, below). It is computed from Git at every load
 * and never stored — Git × the state's rows × this machine's $HOME → rows is a
 * pure function; the enabled set and each profile's target are read from the
 * state handle's row cache (core/state.h), the mount table is derived from them
 * inside the build, and nothing here writes. Surface is two-fold:
 *
 *   - Builders: manifest_build walks every enabled profile in precedence order
 *     (later profiles override earlier); manifest_build_tree walks one Git tree
 *     — the historical-diff path (cmd_diff) — and is the same per-profile step
 *     applied once. Both produce manifest_row_t rows directly, the one row shape
 *     every consumer reads, so there is no bridge between the build step and
 *     its readers. The dispatcher builds the view once per command for the commands
 *     that declare it (ctx->run.manifest, include/runtime.h); a command that
 *     moves Git or the enabled set builds the post-mutation view itself.
 *
 *   - Readers: manifest_rows (both kinds, unordered), manifest_profiles (the
 *     profiles the rows came from, in precedence order), manifest_lookup (by
 *     filesystem path, O(1)) and manifest_lookup_storage (by storage path, linear);
 *     and manifest_diff, the per-profile delta between two views that the
 *     scope-changing verbs and sync print their receipts from.
 *
 * Core Principles:
 *   - Pure: the view is a function of Git, the state's rows and $HOME — the same
 *     inputs give the same rows on every machine
 *   - Computed, never stored: every load builds it; nothing invalidates it because
 *     nothing is held past its lifetime
 *   - Precedence-aware: one row per path, the winner's kind — later profiles
 *     override earlier, except that a derived directory claim only ever fills
 *     an empty slot (manifest_row_t's `tracked`)
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
#include "infra/mount.h"

/* manifest_build reads the enabled set from the state handle and manifest_diff
 * reads the record (core/state.h) by pointer; both are named here and defined
 * there, as state.h names the row. */
typedef struct state state_t;
typedef struct anchor anchor_t;

/**
 * Manifest row — what should stand at a managed path, and from whom
 *
 * A row in the view means the path is managed: the enabled set, in precedence
 * order, names exactly one profile for it, and that profile's tree (or, for a
 * directory, its metadata.json) says what the path is. Every field is Git-derived;
 * nothing here records what dotta did — the record dotta keeps of a path (anchor_t,
 * core/state.h) is written from one of these.
 *
 * Per kind:
 *   blob types  — blob_oid is the tree entry; mode is the metadata claim, or
 *                 the filemode floor (0644 / 0755) where none is claimed;
 *                 encrypted is the metadata-projected cache of the blob's own
 *                 bytes (docs/encryption-spec.md)
 *   DIRECTORY   — claimed from metadata alone: blob_oid is zero, encrypted is
 *                 false, owner/group are the item's, mode is the claim or
 *                 DIR_MODE_DEFAULT, and tracked is the item's class
 *
 * Two kinds of directory row, and `tracked` is the whole difference between them.
 * Every directory row asserts that a path must exist and says what it looks like
 * where dotta has to make it; `tracked` asserts on top of that which paths the
 * profile manages itself — its attributes the profile's to enforce, its contents
 * the profile's to scan. That is the decision procedure every consumer follows:
 * a question about the path existing is asked of both classes (deploy's ancestors
 * pass, the displacement probe, cleanup's permanence rule), a question about
 * managing it of the tracked ones alone (the untracked scan, the directory
 * divergence, the deploy plan). The second kind is an ancestor claim — derived
 * from the chain above a managed path, so what it carries binds dotta's own
 * creation of that path and nothing else (core/metadata.h). It is false on every
 * other kind, where nothing reads it.
 *
 * Totality: after build, mode is THE mode for every non-link row — floor or claim,
 * never a hole; consumers compare and apply it without a fallback. A link row's
 * mode stays 0 as a don't-care (the discriminator is type, the tree's own truth;
 * symlink(2) takes no mode), and MODE_UNCLAIMED never leaves the claim sheet.
 * Authority, stated once: the filemode is authoritative for type, the metadata
 * claim for permission bits — a hand-edit that contradicts the x-bit across the
 * two is resolved by that contract, not detected per-read.
 *
 * Strings are arena-backed by the producer; rows are read through `const
 * manifest_row_t *` and live for the producer's arena. The precedence oracle
 * below produces rows, the workspace partitions them, deploy and cleanup plan
 * over them.
 */
typedef struct manifest_row {
    /* Identity */
    char *filesystem_path;      /* Deployed path (/home/user/.bashrc) */
    char *storage_path;         /* Path in profile (home/.bashrc) */
    char *profile;              /* Winning profile */

    /* What stands there */
    path_type_t type;           /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    git_oid blob_oid;           /* Blob the composed profile layer expects on disk (zero for DIRECTORY) */
    mode_t mode;                /* Total for every kind that carries one (claim or floor); 0 on a link row, a don't-care */
    char *owner;                /* The claimed owner, or NULL (metadata.h: absence is the invoker's own) */
    char *group;                /* The claimed group, or NULL */
    bool encrypted;             /* Encryption flag (false for DIRECTORY) */
    bool tracked;               /* DIRECTORY rows: the profile manages the directory itself */
} manifest_row_t;

/**
 * Bound carrier for a borrowed slice of manifest rows
 *
 * Structural type — parallels libgit2's git_strarray and base/array's
 * string_array_t. The producer's signature dictates lifetime via the arena (or
 * other allocator) that backs the rows.
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
 * Buckets filled by ptr_array_push(&bucket, row) hold `void *`; the cast layers
 * const onto both pointer levels (T ** → const T *const *, the same rule
 * workspace_files relies on). The view aliases the bucket's storage and is valid
 * for the bucket's lifetime — deploy plans and results, and any other producer
 * that accumulates rows, project through this so every consumer reads one carrier
 * shape.
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
 * Rows and their strings live in the arena the builder was given; the path index
 * is heap-allocated and released by manifest_free. A view borrows nothing else
 * — not the state's row cache it was read from — so it stands across the mutations
 * that invalidate the cache, for the arena's lifetime.
 */
typedef struct manifest manifest_t;

/**
 * Build the manifest over the enabled set
 *
 * The enabled profiles, in precedence order, are read from the state handle's
 * row cache (state_peek_profiles) — the one source every caller would otherwise
 * copy them out of. A state with no database (state_load on a repository never
 * touched by `dotta init`) has no rows and yields an empty view.
 *
 * Performance: O(N) where N is total files across all profiles. One Git tree
 * alive per iteration (loaded, walked, freed).
 *
 * The mount table custom/ paths resolve under is built here, from the same rows
 * (profile_build_mount_table): a re-target is in the next build because the next
 * build reads the rows. A custom/ claim whose profile has no target binding on
 * this machine — a normal lifecycle stage in a shared repository — contributes
 * no row and is recorded on the view (manifest_unbound); the health consumers
 * surface it, and the build stays total over importable content.
 *
 * A profile whose branch does not exist contributes no rows; the scope layer
 * already warns about the dead branch on every run, and the workspace reads that
 * profile's records as orphans. The unbound claim is that observation's sibling
 * at claim scale: this machine cannot place it, and the build says so as data,
 * not failure. Only those two questions are tolerant: a branch that exists but
 * cannot be loaded (corrupt object, I/O) still fails the build, as do a failed
 * lookup and metadata that will not parse — those stay retryable errors, never
 * silent omissions.
 *
 * Per profile, in order: the tree's blobs are claimed first, then the DIRECTORY
 * items of its metadata.json. A blob and a DIRECTORY item of the same profile
 * at one path is stale metadata — a path is a tree or a blob — and the tree is
 * the content authority: the directory claim finds its own profile's row and
 * yields. Across profiles the later (higher) claim replaces the slot whatever
 * its kind, so the view holds one row per path, the winner's kind. A profile
 * without metadata.json contributes no directories and is skipped, not an error.
 *
 * Row order is unspecified; consumers that need parent-before-child sort their
 * own pointer arrays (the workspace does). The oracle is a set.
 *
 * Memory:
 *   - rows, per-row strings, the profile names (duplicated once per profile)
 *     and the mount table: arena-allocated; the caller's arena reclaims them at
 *     arena_destroy. The view borrows nothing from the row cache, so it stands
 *     across the enabled_profiles mutations that invalidate the cache — a `before`
 *     built ahead of a profile enable reads the same after it, and the view after
 *     is the builder called again.
 *   - index hashmap: heap-allocated; on success the caller releases it with
 *     manifest_free. On error, the hashmap (if allocated) is freed here and *out
 *     is NULL.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle the enabled set and targets are read from (must not
 *              be NULL; borrowed, only the row cache is consulted)
 * @param arena Arena backing every allocation produced by the call (must not be
 *              NULL)
 * @param out Manifest (must not be NULL; caller frees with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    manifest_t **out
);

/**
 * Build the manifest from a single Git tree
 *
 * Used by the historical-diff path (cmd_diff): given a tree, profile, mount table
 * — explicit here, since there is no state to derive one from and a past tree
 * is deliberately resolved under today's topology — and optional per-tree metadata,
 * produces a manifest_row_t row for every blob the tree exposes (sans repository
 * metadata files — .dottaignore, .bootstrap, .git/, .dotta/) and, when metadata
 * is supplied, for every DIRECTORY item it claims — the same per-profile step
 * manifest_build runs, applied once. Readers that want files only test row->type.
 *
 * Metadata, when supplied, is applied row-by-row in lockstep with the tree walk
 * — mode, owner, group, and encrypted are filled from the tree's own metadata.json.
 * Pass NULL to skip metadata application (rows keep Git-derived defaults, and
 * no directories are claimed). Callers that have already loaded the tree's metadata
 * for their own purposes should pass it here.
 *
 * Custom-prefix resolution is delegated to `mounts`. A custom/ claim the handle
 * records no binding for contributes no row and is recorded on the view
 * (manifest_unbound) — the same degrade contract as manifest_build, which lets
 * the historical-diff path resolve old trees whose labels today's topology cannot
 * place. Any mount table is acceptable, including one with no binding for
 * `profile`.
 *
 * Memory: same contract as manifest_build — every allocation produced by the
 * call lives in the caller's arena; the index is manifest_free's.
 *
 * @param tree Git tree to build from (must not be NULL)
 * @param profile Profile name carried on each row (must not be NULL;
 *                duplicated into the arena)
 * @param mounts Per-machine mount table (must not be NULL)
 * @param metadata Optional per-tree metadata applied to rows (can be NULL)
 * @param arena Arena backing every allocation produced by the call (must not be
 *              NULL)
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
 * Pure value return — no allocation, no error path. The slice aliases the view's
 * own storage and is valid for the arena's lifetime.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over every row
 */
manifest_rows_t manifest_rows(const manifest_t *manifest);

/**
 * The profiles the view was built from, in precedence order
 *
 * Every enabled profile whose branch existed at build, lowest precedence first
 * — the set the rows came from, as the enabled set reads once the branches that
 * are gone (and contributed nothing) are left out; for a tree view, the one
 * profile. The workspace reads its profile set here: the untracked scan's order
 * and the orphan label's membership are the view's, by construction.
 *
 * Pure value return — no allocation, no error path. The names are the arena's,
 * the same pointers the rows carry, valid for the arena's lifetime.
 *
 * @param manifest Manifest (NULL yields count 0)
 * @param count Receives the number of profiles (must not be NULL)
 * @return Borrowed array of profile names, or NULL when count is 0
 */
const char *const *manifest_profiles(const manifest_t *manifest, size_t *count);

/**
 * One claim the build could not place: its profile has no deployment target on
 * this machine. Recorded, never dropped in silence — the health consumers (status,
 * apply, sync) surface these; the repair is one command (`profile enable <p>
 * --target /path`), the untracking another (`remove`). Strings are the build
 * arena's, same lifetime as the rows.
 */
typedef struct {
    const char *profile;
    const char *storage_path;
    path_kind_t kind;             /* FILE for tree blobs, DIRECTORY for metadata items */
} manifest_unbound_claim_t;

/**
 * Bound carrier for the view's health slice, the manifest_rows_t idiom.
 */
typedef struct {
    const manifest_unbound_claim_t *entries;
    size_t count;
} manifest_unbound_t;

/**
 * The claims the build could not place, grouped by profile
 *
 * Pure value return — no allocation, no error path. Entries arrive in build order,
 * so one profile's claims are contiguous and consumers aggregate in a single
 * pass without sorting. Each (profile, storage path) is recorded once: a stale
 * DIRECTORY item at an unbound blob's storage path contributes no second entry,
 * mirroring the bound path's content-authority rule. Empty on every build whose
 * claims all placed — the common case, costing nothing.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded claims, valid for the arena's lifetime
 */
manifest_unbound_t manifest_unbound(const manifest_t *manifest);

/**
 * Look up a row by filesystem path
 *
 * O(1) over the view's index — a path is one managed thing, whatever its kind;
 * callers that want one kind test row->type. NULL when the path is not managed.
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
 * Linear scan — the callers ask once per command (list, show) or once per BACKED
 * orphan (the workspace's relocation read, each of which already cost a Git tree
 * probe; a lazy per-profile storage index inside the orphan pass's authority
 * cache is the upgrade if a profile-wide re-target ever makes the scan show up).
 * Since precedence is resolved, each storage path under home/ and root/ maps to
 * exactly one row; under custom/ two profiles with distinct targets may share a
 * storage path, and the first match is returned — the profile filter is how a
 * caller that means one claim names it.
 *
 * @param manifest Manifest (NULL returns NULL)
 * @param storage_path Storage path to look up, e.g. "home/.bashrc" (NULL returns
 *                     NULL)
 * @param profile Only rows of this profile match; NULL matches any
 * @return Borrowed row pointer, or NULL if no row has the storage path
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *storage_path,
    const char *profile
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
 * Fields are populated conditionally based on the profile's role in the transition.
 * The same profile can gain and lose paths simultaneously (e.g., enable A while
 * B was reordered above it), so gain-side and loss-side fields are independent.
 *
 *   Gain-side  — the profile claims path(s) in `after`.
 *   Loss-side  — the profile owned path(s) in `before` that it does not
 *                in `after`.
 *
 * Counters describe the two views and the record; they do NOT verify disk matches
 * anything. Verification is workspace divergence analysis (status/diff/apply).
 * Both kinds count.
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
    struct {
        size_t owned;            /* … with a record dotta owns (deployed_at > 0): apply prunes the copy, or releases it if Git let go */
        size_t observed;         /* … with a record dotta never owned: apply releases it, the copy stays */
    } orphans;                   /* Paths `before` had under this profile that `after` lacks, with a record at them */
} manifest_diff_stats_t;

/**
 * Attribute the transition between two views to profiles
 *
 * The delta the scope-changing verbs (profile enable / disable) and sync print
 * their receipts from: what each profile in `profiles` claims in `after` that
 * it did not in `before`, what it lost to another profile, and what left the
 * view under it — counted only where a record stands, because only a path dotta
 * has observed has anything for apply to do at its departure; a departure with
 * no record asks nothing of apply and is not counted.
 *
 * Attribution (for a profile P in `profiles`):
 *   - every row of `after` under P: claimed; added if `before` has no row at
 *     the path; updated if it has one whose blob, type or mode differs (owner/group
 *     travel with a metadata commit rare enough to ride on the workspace's verdict
 *     instead)
 *   - every row of `before` under P whose path `after` gives another profile:
 *     reassigned
 *   - every row of `before` under P whose path `after` lacks, with a record at
 *     the path: an orphan — owned or merely observed, which is the split the
 *     ownership gate reads. What apply then does with an owned one depends on
 *     why the path left: a scope change (profile disable) leaves Git backing it
 *     and apply prunes the copy; a Git removal (sync) does not, and apply releases
 *     it
 *   Overlap semantics: if B overrides A for path X, B gets claimed for X and A
 *   gets reassigned for X. The sum is the true size of `after`.
 *
 * `before` may be NULL — an empty view (clone, the first enable): every row of
 * `after` is then added and nothing departed.
 *
 * Preconditions:
 *   - profiles' entries are pairwise unique (duplicates return ERR_INVALID_ARG
 *     — two slots would silently collapse into one)
 *   - out_stats points to an array of length profiles->count; it is zero-filled
 *     here with each profile's name set, so a caller reads the counts without
 *     asking whether anything changed: all-zero means "nothing for apply to do
 *     came out of this transition"
 *
 * Performance: O(A + B + R) — one pass over each view and one index over the
 * record; no Git, no disk, no database.
 *
 * @param before View before the transition (may be NULL = empty)
 * @param after View after the transition (must not be NULL)
 * @param anchors The record, as state_get_all_anchors returns it (may be NULL
 *                when anchor_count is 0)
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
