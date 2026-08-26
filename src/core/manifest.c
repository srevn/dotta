/**
 * manifest.c - Manifest module implementation
 *
 * The precedence oracle: manifest_build (every enabled profile, in precedence
 * order) and manifest_build_tree (one tree) share one per-profile claim routine
 * that produces manifest_row_t rows directly. There is no persistence step and
 * no bridge type: the view is computed into the caller's arena and read through
 * the accessors below.
 *
 * Key patterns:
 *   - Precedence by claim: manifest_claim is the one find-or-append-and-reset
 *     primitive. A later (higher) claim on a path replaces the slot whatever
 *     its kind; the view holds one row per path.
 *   - Blob OID Extraction: the tree walker reads blob_oid, type and the Git-derived
 *     mode from each borrowed tree entry for O(1) content identity.
 *   - Metadata Integration: the walker attributes per-profile metadata onto each
 *     row during the tree walk (single profile per row, no cross-profile merge
 *     — storage_path collisions across profiles with distinct target values are
 *     kept apart), and the same metadata's DIRECTORY items are claimed after
 *     the walk.
 *   - Diff, not delta-tracking: what a scope transition or a sync did to the
 *     view is read off two views (manifest_diff), never recorded while it happened.
 */

#include "core/manifest.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * Manifest — the precedence oracle's product
 *
 * A pointer spine over rows allocated one by one from the caller's arena, and a
 * path index over them. Rows are stable from the moment they are allocated —
 * only the spine is ever reallocated — so the index stores row pointers directly
 * and manifest_rows hands the spine out as the public slice.
 *
 * Spine growth uses arena_calloc + memcpy (abandon-and-realloc): the old chunk
 * is left to the arena (released at arena_destroy). The index is heap-allocated
 * and released by manifest_free; its keys borrow each row's arena-backed
 * filesystem_path.
 */
struct manifest {
    manifest_row_t **rows;         /* arena-backed pointer spine, abandon-and-realloc growth */
    size_t count;                  /* Rows in the spine */
    size_t capacity;               /* Spine slots allocated */
    hashmap_t *index;              /* fs_path → manifest_row_t *, heap-allocated */
    const char **profiles;         /* The profiles the rows came from, in precedence order (arena) */
    size_t profile_count;          /* Profiles listed */

    /* The health slice: claims the build could not place (no target binding),
     * grouped by profile in build order. Flat arena array, abandon-and-realloc
     * growth like the spine; empty on the common all-bound build (no allocation
     * until the first note). */
    manifest_unbound_claim_t *unbound;
    size_t unbound_count;
    size_t unbound_capacity;
};

/**
 * Context for the blob-claim tree-walk callback
 *
 * Passed to gitops_tree_walk() to populate a manifest directly during tree
 * traversal, eliminating O(N×D) two-pass overhead. The callback extracts identity
 * fields from borrowed tree entries at O(1) per file.
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership
 * - profile: arena-backed name every row of this profile borrows
 * - mounts: borrowed, must not be NULL — keyed by ctx->profile to resolve custom/
 *          entries; a missing binding (MOUNT_RESOLVE_UNBOUND) contributes no
 *          row and is recorded on the view (manifest_note_unbound)
 * - metadata: borrowed (per-profile, reloaded for each profile in the outer build
 *             loop), can be NULL (profile lacks metadata.json)
 * - arena: borrowed, must not be NULL; per-row strings + spine growth allocations
 *          are abandoned to it
 * - error: owned by callback, caller must free on error
 */
struct claim_ctx {
    manifest_t *manifest;          /* Target view (modified by callback) */
    const char *profile;           /* Profile name for rows and error messages */
    const mount_table_t *mounts;   /* Mount table for storage→filesystem resolution */
    const metadata_t *metadata;    /* Per-profile metadata (NULL if absent) */
    arena_t *arena;                /* Arena for allocations (must not be NULL) */
    error_t *error;                /* Error propagation (set on failure) */
};

/**
 * Apply per-profile metadata to a Git-built blob row.
 *
 * Selectively overrides the metadata-owned fields (mode, owner, group, encrypted)
 * on a row whose Git-derived defaults have already been set. Each call attributes
 * a single profile's claim to the row; precedence across profiles is resolved
 * by manifest_claim's reset and the paired re-application of this helper.
 *
 * Per-kind semantics when an item exists for the row's storage_path:
 *   FILE      → override mode; set encrypted; copy owner/group
 *   SYMLINK   → leave mode at 0 (links carry no settable mode); copy owner/group
 *   DIRECTORY → no-op: a path is a tree or a blob, so a DIRECTORY item at a blob's
 *               storage_path is stale metadata, and the tree is the content
 *               authority — the item contributes nothing, not even its owner/group
 *
 * NULL metadata, missing item, and ERR_NOT_FOUND all leave the row's Git-derived
 * defaults intact. Other lookup failures propagate.
 *
 * Override-path callers may freely overwrite owner/group: prior values are
 * arena-borrowed and abandoned to the arena, no per-pointer free required.
 *
 * @param row      Target row (mutable)
 * @param metadata Per-profile metadata (NULL → no-op)
 * @param arena    Allocation arena for string copies (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_apply_metadata(
    manifest_row_t *row,
    const metadata_t *metadata,
    arena_t *arena
) {
    if (!metadata) return NULL;

    const metadata_item_t *item = NULL;
    error_t *err = metadata_get_item(metadata, row->storage_path, &item);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            error_free(err);
            return NULL;
        }
        return err;
    }

    if (item->kind == METADATA_ITEM_DIRECTORY) return NULL;

    /* owner/group apply to both remaining kinds; copy first so the mode/encrypted
     * overrides below can short-circuit after the allocations have already
     * succeeded. arena_strdup returns NULL only on real failure (NULL
     * item->owner/group bypasses the if-guards and leaves the dup NULL). */
    char *owner_dup = NULL;
    if (item->owner) {
        owner_dup = arena_strdup(arena, item->owner);
        if (!owner_dup) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate owner for '%s'",
                row->storage_path
            );
        }
    }

    char *group_dup = NULL;
    if (item->group) {
        group_dup = arena_strdup(arena, item->group);
        if (!group_dup) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate group for '%s'",
                row->storage_path
            );
        }
    }

    /* Allocations succeeded — commit the overrides. */
    row->owner = owner_dup;
    row->group = group_dup;

    switch (item->kind) {
        case METADATA_ITEM_FILE:
            row->mode = item->mode;
            row->encrypted = item->file.encrypted;
            break;
        case METADATA_ITEM_SYMLINK:
            /* mode stays 0 (Git default for links); encrypted stays false. */
            break;
        case METADATA_ITEM_DIRECTORY:
            /* Returned above. */
            break;
    }

    return NULL;
}

/**
 * Claim a filesystem path: the row for it, reset, ready to be filled
 *
 * The one precedence primitive. A path already in the view is being claimed by
 * a later — higher — profile (or by the same profile's directory pass, which
 * yields before calling; see manifest_claim_tree): the existing row is zeroed
 * so nothing of the loser survives — not its owner/group/encrypted, not its kind
 * — and keeps only the indexed key. A new path gets a fresh arena row, indexed
 * then appended, so a failed index insert leaves the spine untouched.
 *
 * The old strings of a reset row are arena-borrowed and abandoned to the caller's
 * arena; the index's key is the row's original filesystem_path string, which
 * stays valid and equal.
 *
 * @param manifest Target view (must not be NULL)
 * @param filesystem_path Arena-backed path the row is keyed by (must not be NULL)
 * @param arena Arena for the row and the spine (must not be NULL)
 * @param out The claimed row, zero but for filesystem_path (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_claim(
    manifest_t *manifest,
    const char *filesystem_path,
    arena_t *arena,
    manifest_row_t **out
) {
    manifest_row_t *row = hashmap_get(manifest->index, filesystem_path);
    if (row) {
        char *key = row->filesystem_path;
        memset(row, 0, sizeof(*row));
        row->filesystem_path = key;
        *out = row;
        return NULL;
    }

    /* Grow the spine if needed.
     *
     * Arena abandon-and-realloc: allocate a new chunk from the arena, memcpy
     * the existing pointers, and swap. The old chunk stays valid for the arena's
     * lifetime but is no longer referenced; the arena reclaims it at arena_destroy.
     * The rows themselves never move, so the index's row pointers are unaffected
     * by the spine relocation. */
    if (manifest->count >= manifest->capacity) {
        if (manifest->capacity > SIZE_MAX / 2) {
            return ERROR(ERR_INTERNAL, "Manifest capacity overflow");
        }
        size_t new_capacity = manifest->capacity * 2;

        manifest_row_t **new_rows = arena_calloc(
            arena, new_capacity, sizeof(*new_rows)
        );
        if (!new_rows) {
            return ERROR(ERR_MEMORY, "Failed to grow manifest");
        }
        memcpy(new_rows, manifest->rows, manifest->count * sizeof(*new_rows));
        manifest->rows = new_rows;
        manifest->capacity = new_capacity;
    }

    row = arena_calloc(arena, 1, sizeof(*row));
    if (!row) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest row");
    }

    /* filesystem_path is arena-borrowed via mount_resolve; the cast discards
     * the const qualifier exposed by mount_resolve's output type. It is the index's
     * key for the rest of the view's life. */
    row->filesystem_path = (char *) filesystem_path;

    error_t *err = hashmap_set(manifest->index, row->filesystem_path, row);
    if (err) {
        return error_wrap(err, "Failed to index manifest row");
    }

    manifest->rows[manifest->count++] = row;
    *out = row;
    return NULL;
}

/**
 * Record one claim the build could not place, once
 *
 * The health primitive both claim sites share: appends (profile, storage_path,
 * kind) to the view's health slice unless the pair is already recorded — the
 * one duplicate source is a stale DIRECTORY item at an unbound blob's storage
 * path, and recording it twice would count one path as two; the blob walked first,
 * so the first writer is the content authority, mirroring the bound path's
 * same-profile rule. The scan is linear over the slice, which holds only the
 * unplaced claims — empty on the common build.
 *
 * Growth is the spine's abandon-and-realloc idiom. Both strings must be
 * arena-backed by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param storage_path Arena-backed storage path (must not be NULL)
 * @param kind The claim's kind (FILE for tree blobs, DIRECTORY for metadata items)
 * @param arena Arena for the array growth (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_note_unbound(
    manifest_t *manifest,
    const char *profile,
    const char *storage_path,
    path_kind_t kind,
    arena_t *arena
) {
    for (size_t i = 0; i < manifest->unbound_count; i++) {
        if (strcmp(manifest->unbound[i].profile, profile) == 0 &&
            strcmp(manifest->unbound[i].storage_path, storage_path) == 0) {
            return NULL;
        }
    }

    if (manifest->unbound_count >= manifest->unbound_capacity) {
        size_t new_capacity =
            manifest->unbound_capacity > 0 ? manifest->unbound_capacity * 2 : 8;

        manifest_unbound_claim_t *grown = arena_calloc(
            arena, new_capacity, sizeof(*grown)
        );
        if (!grown) {
            return ERROR(ERR_MEMORY, "Failed to grow unbound claim list");
        }
        memcpy(
            grown, manifest->unbound,
            manifest->unbound_count * sizeof(*grown)
        );
        manifest->unbound = grown;
        manifest->unbound_capacity = new_capacity;
    }

    manifest->unbound[manifest->unbound_count++] = (manifest_unbound_claim_t){
        .profile = profile,
        .storage_path = storage_path,
        .kind = kind,
    };
    return NULL;
}

/**
 * Tree-walk callback that claims the tree's blobs into the manifest
 *
 * Performance optimization: Instead of collecting paths in pass 1 then
 * re-traversing via git_tree_entry_bypath() in pass 2 (O(N×D)), this callback
 * writes manifest_row_t rows directly in O(N) time.
 *
 * Extracts identity fields (blob_oid, type, mode) from the borrowed tree entry
 * at the callback boundary — no git_tree_entry_dup needed, no opaque handle stored
 * on the row.
 *
 * Handles:
 * - Metadata file filtering (.dotta/, .bootstrap, etc.)
 * - Storage path to filesystem path conversion
 * - Profile precedence override (higher precedence wins — manifest_claim)
 * - File identity extraction from Git tree entry
 * - Per-profile metadata application (mode override, owner, group, encrypted)
 *
 * @param root Directory path within tree (empty string for root level)
 * @param entry Git tree entry (borrowed — valid for callback duration only)
 * @param payload Pointer to claim_ctx
 * @return 0 to continue walk, -1 to stop on error
 */
static int manifest_claim_blob(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct claim_ctx *ctx = (struct claim_ctx *) payload;

    /* Only process blobs (files), skip directories */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build the full storage path from root + entry name, straight into the arena
     * — the row keeps it, so the join is the allocation, and Git's only bound
     * on a path's length is memory. A skipped entry abandons its string to the
     * arena, the module's idiom. */
    const char *name = git_tree_entry_name(entry);
    size_t root_len = root ? strlen(root) : 0;
    size_t name_len = strlen(name);
    char *storage_path = arena_alloc(ctx->arena, root_len + name_len + 1);
    if (!storage_path) {
        ctx->error = ERROR(ERR_MEMORY, "Failed to allocate storage path");
        return -1;
    }
    if (root_len > 0) memcpy(storage_path, root, root_len);
    memcpy(storage_path + root_len, name, name_len + 1);

    /* Skip repository bookkeeping — nothing the branch keeps for dotta's own
     * use is a managed path, and mount_resolve below would refuse it anyway */
    if (profile_is_repo_metadata(storage_path)) {
        return 0;
    }

    /* Convert storage path to filesystem path against the mount table.
     *
     * MOUNT_RESOLVE_UNBOUND fires when storage_path is custom/... and ctx->profile
     * has no target binding on this machine — a normal lifecycle stage in a shared
     * repository (a clone before the target is chosen, a sync that pulled another
     * machine's custom/ claims, a revert that recommitted one), not corruption:
     * no local precondition can bind what another machine adds to the branch.
     * The claim contributes no row — nothing on this machine can place it — and
     * is recorded on the view (manifest_unbound) so the health consumers surface
     * it; it is never dropped in silence. Record-safe by construction: a record
     * can only exist where a binding existed at write time, so no anchor ever
     * joins a skipped claim and no orphan can be manufactured here. Genuine errors
     * (malformed path, OOM) propagate via the err branch. */
    mount_resolve_outcome_t outcome;
    const char *filesystem_path = NULL;
    error_t *err = mount_resolve(
        ctx->mounts, ctx->profile, storage_path, ctx->arena,
        &outcome, &filesystem_path
    );
    if (err) {
        ctx->error = error_wrap(
            err, "Failed to convert path '%s' from profile '%s'",
            storage_path, ctx->profile
        );
        return -1;
    }
    if (outcome == MOUNT_RESOLVE_UNBOUND) {
        ctx->error = manifest_note_unbound(
            ctx->manifest, ctx->profile, storage_path, PATH_KIND_FILE, ctx->arena
        );
        return ctx->error ? -1 : 0;
    }

    /* Claim the path: a fresh row, or the lower-precedence profile's slot reset
     * (precedence override). Either way the row is zero but for its key, and
     * everything below is written the same way. */
    manifest_row_t *row = NULL;
    err = manifest_claim(ctx->manifest, filesystem_path, ctx->arena, &row);
    if (err) {
        ctx->error = err;
        return -1;
    }

    /* ctx->profile is the arena-backed name the builder duplicated; the cast
     * discards its const decoration to fit the row's `char *profile` slot. */
    row->storage_path = storage_path;
    row->profile = (char *) ctx->profile;

    /* Extract identity from borrowed tree entry (blob_oid, type, mode). The
     * overriding profile may differ in filemode (e.g., executable bit). */
    git_oid_cpy(&row->blob_oid, git_tree_entry_id(entry));
    switch (git_tree_entry_filemode(entry)) {
        case GIT_FILEMODE_BLOB_EXECUTABLE:
            row->type = PATH_TYPE_EXECUTABLE;
            row->mode = 0755;
            break;
        case GIT_FILEMODE_LINK:
            row->type = PATH_TYPE_SYMLINK;
            row->mode = 0;
            break;
        default:
            /* A blob (we filtered to blobs above) */
            row->type = PATH_TYPE_FILE;
            row->mode = 0644;
            break;
    }

    /* Apply this profile's metadata claim (if any) to the row. The Git-derived
     * defaults set above are the floor; metadata may override mode and encrypted,
     * and contribute owner/group. */
    err = manifest_apply_metadata(row, ctx->metadata, ctx->arena);
    if (err) {
        /* The caller's outer error path propagates without freeing the view's
         * rows (spine + strings are arena-backed); a half-built row in a failed
         * build is never read. */
        ctx->error = error_wrap(
            err, "Failed to apply metadata to '%s'",
            row->storage_path
        );
        return -1;
    }

    return 0;  /* Continue walk */
}

/**
 * Claim one profile's contribution: the tree's blobs, then its directories
 *
 * The per-profile step both builders run. The tree walk claims every blob
 * (manifest_claim_blob); then every DIRECTORY item of the profile's metadata
 * claims its path — resolved against the mount table, the same way files are —
 * unless this profile already holds the path with a blob: a path is a tree or a
 * blob, so a DIRECTORY item at a blob's storage_path is stale metadata, and the
 * tree is the content authority. A DIRECTORY item under a profile lacking a target
 * binding on this host degrades exactly as the file side does — no row, recorded
 * on the view (manifest_note_unbound) — so both kinds hold under one UNBOUND
 * policy.
 *
 * `profile` is the arena-backed name every row borrows; `metadata` may be NULL
 * (no metadata.json: Git-derived defaults stand, no directories).
 *
 * Memory: every allocation lands in `arena`. On error, rows already claimed are
 * left as they are — the build fails whole and the caller releases the index.
 */
static error_t *manifest_claim_tree(
    manifest_t *manifest,
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena
) {
    /* Build view rows via single-pass tree traversal.
     *
     * The callback extracts identity fields (blob_oid, type, mode) from borrowed
     * tree entries, converts paths via mount_resolve, handles precedence override,
     * applies per-profile metadata to mode/owner/group/encrypted, and populates
     * manifest_row_t rows
     * directly — all in O(N) time. mounts is borrowed from the caller;
     * bindings are keyed by profile (which the callback feeds verbatim into
     * mount_resolve). */
    struct claim_ctx ctx = {
        .manifest = manifest,
        .profile  = profile,
        .mounts   = mounts,
        .metadata = metadata,
        .arena    = arena,
        .error    = NULL
    };

    error_t *err = gitops_tree_walk(tree, manifest_claim_blob, &ctx);
    if (err || ctx.error) {
        err = ctx.error ? ctx.error : err;
        return error_wrap(
            err, "Failed to build manifest for profile '%s'", profile
        );
    }

    if (!metadata) return NULL;

    /* The directory claims: every DIRECTORY item the profile's metadata carries.
     * A tree holds no empty directory, so the item is the claim's whole
     * footprint. */
    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);

    for (size_t j = 0; j < item_count; j++) {
        const metadata_item_t *item = items[j];
        if (item->kind != METADATA_ITEM_DIRECTORY) continue;

        /* Resolve before claiming so the error path claims nothing. */
        mount_resolve_outcome_t outcome;
        const char *filesystem_path = NULL;
        err = mount_resolve(
            mounts, profile, item->key, arena, &outcome, &filesystem_path
        );
        if (err) {
            err = error_wrap(
                err, "Failed to derive filesystem path from storage path: %s",
                item->key
            );
            break;
        }
        if (outcome == MOUNT_RESOLVE_UNBOUND) {
            /* The blob side's degrade contract, DIRECTORY kind: recorded, not
             * placed. The item's key is the metadata's, freed with it — the note
             * keeps an arena copy. The note itself dedups the stale-item case
             * (a DIRECTORY item at an unbound blob's storage path). */
            char *key = arena_strdup(arena, item->key);
            if (!key) {
                err = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
                break;
            }
            err = manifest_note_unbound(
                manifest, profile, key, PATH_KIND_DIRECTORY, arena
            );
            if (err) break;
            continue;
        }

        /* Same-profile rule: the tree's blob outranks the stale item. */
        const manifest_row_t *held = hashmap_get(manifest->index, filesystem_path);
        if (held && strcmp(held->profile, profile) == 0) continue;

        manifest_row_t *row = NULL;
        err = manifest_claim(manifest, filesystem_path, arena, &row);
        if (err) break;

        /* A directory row is claimed from metadata alone: blob_oid stays zero
         * and encrypted false; mode, owner and group are the item's. */
        row->storage_path = arena_strdup(arena, item->key);
        row->profile = (char *) profile;
        row->type = PATH_TYPE_DIRECTORY;
        row->mode = item->mode;
        row->owner = item->owner ? arena_strdup(arena, item->owner) : NULL;
        row->group = item->group ? arena_strdup(arena, item->group) : NULL;

        if (!row->storage_path ||
            (item->owner && !row->owner) || (item->group && !row->group)) {
            err = ERROR(ERR_MEMORY, "Failed to copy directory row fields");
            break;
        }
    }

    return err;
}

/**
 * Allocate a fresh manifest_t, ready for the claim routine.
 *
 * Both the view struct, the initial spine and the profile list (sized for the
 * profiles the build will walk at most) are arena-allocated. The index hashmap
 * is heap-allocated (borrowed-key mode — keys live in the caller's arena and
 * survive the hashmap's lifetime).
 *
 * On error, the function returns ERR_MEMORY and *out is NULL; arena allocations
 * are abandoned to the arena and no heap allocation is outstanding.
 */
static error_t *manifest_allocate(
    arena_t *arena,
    size_t initial_capacity,
    size_t index_capacity,
    size_t profile_capacity,
    manifest_t **out
) {
    *out = NULL;

    manifest_t *manifest = arena_calloc(arena, 1, sizeof(*manifest));
    if (!manifest) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    manifest->capacity = initial_capacity;
    manifest->rows = arena_calloc(arena, manifest->capacity, sizeof(*manifest->rows));
    if (!manifest->rows) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest spine");
    }

    if (profile_capacity > 0) {
        manifest->profiles = arena_calloc(
            arena, profile_capacity, sizeof(*manifest->profiles)
        );
        if (!manifest->profiles) {
            return ERROR(ERR_MEMORY, "Failed to allocate manifest profile list");
        }
    }

    manifest->index = hashmap_borrow(index_capacity);
    if (!manifest->index) {
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    *out = manifest;
    return NULL;
}

/**
 * Build the manifest over the enabled set
 */
error_t *manifest_build(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    /* The enabled set, in position order. Borrowed from the row cache for the
     * loop only: every name a row keeps is duplicated below, so the view never
     * depends on the cache's lifetime. */
    const state_profile_entry_t *profiles = NULL;
    size_t profile_count = 0;
    error_t *err = state_peek_profiles(state, &profiles, &profile_count);
    if (err) {
        return error_wrap(err, "Failed to read enabled profiles");
    }

    /* The topology the same rows describe — each profile's target, and this
     * machine's $HOME — built here, from the rows of this instant, so a custom/
     * path always resolves under the target the row it came from carries. */
    mount_table_t *mounts = NULL;
    err = profile_build_mount_table(state, arena, &mounts);
    if (err) {
        return error_wrap(err, "Failed to build mount table");
    }

    manifest_t *manifest = NULL;
    err = manifest_allocate(arena, 64, 128, profile_count, &manifest);
    if (err) return err;

    /* Process each profile in order (later profiles override earlier) */
    for (size_t i = 0; i < profile_count; i++) {
        /* Arena-allocate the profile name. Rows borrow this pointer; the caller's
         * arena outlives the view (it backs every per-row string the walk writes),
         * so the view never depends on the state's row cache. */
        const char *profile = arena_strdup(arena, profiles[i].name);
        if (!profile) {
            err = ERROR(ERR_MEMORY, "Failed to duplicate profile name");
            goto cleanup;
        }

        /* Does the branch exist? Asked separately because the tree loader maps
         * a missing ref to ERR_GIT like every other failure, and "gone" must
         * not be confused with "broken": gone is an observation — the profile
         * contributes nothing, is not listed among the view's profiles, and the
         * workspace reads its records as orphans — broken is an error that must
         * propagate. */
        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) {
            err = error_wrap(
                err, "Failed to look up branch for profile '%s'", profile
            );
            goto cleanup;
        }
        if (!exists) continue;

        manifest->profiles[manifest->profile_count++] = profile;

        /* Load tree for this profile (scoped to iteration). */
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'", profile
            );
            goto cleanup;
        }

        /* Load this profile's metadata.json from the tree we just opened (avoid
         * a second ref/commit/tree walk). Per-profile lookup is the correctness
         * boundary for attribution: each profile claims its own files and
         * directories via its own metadata, never via a cross-profile merge.
         * ERR_NOT_FOUND here means "no metadata blob in this tree" — normal for
         * old or freshly created profiles, and the claim routine degrades
         * gracefully (Git-derived defaults stand, no directories). */
        metadata_t *profile_metadata = NULL;
        err = metadata_load_from_tree(repo, tree, profile, &profile_metadata);
        if (err) {
            if (err->code != ERR_NOT_FOUND) {
                git_tree_free(tree);
                err = error_wrap(
                    err, "Failed to load metadata for profile '%s'", profile
                );
                goto cleanup;
            }
            error_free(err);
            err = NULL;
            profile_metadata = NULL;
        }

        err = manifest_claim_tree(
            manifest, tree, profile, mounts, profile_metadata, arena
        );
        git_tree_free(tree);
        metadata_free(profile_metadata);

        if (err) goto cleanup;
    }

    *out = manifest;
    return NULL;

cleanup:
    /* The view's spine, rows and strings are arena-abandoned; only the
     * heap-allocated index needs explicit free on the error path. */
    manifest_free(manifest);
    return err;
}

/**
 * Build the manifest from a single Git tree
 */
error_t *manifest_build_tree(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    manifest_t *manifest = NULL;
    error_t *err = manifest_allocate(arena, 64, 128, 1, &manifest);
    if (err) return err;

    /* Arena-allocate the profile name. Rows borrow this pointer; the caller's
     * arena outlives the view (it backs every per-row string the walk writes),
     * so the borrow stays valid until arena_destroy. */
    const char *owned_profile = arena_strdup(arena, profile);
    if (!owned_profile) {
        err = ERROR(ERR_MEMORY, "Failed to duplicate profile name");
        goto cleanup;
    }
    manifest->profiles[manifest->profile_count++] = owned_profile;

    /* mounts and metadata borrow from function parameters — both outlive the
     * tree walk. */
    err = manifest_claim_tree(
        manifest, tree, owned_profile, mounts, metadata, arena
    );
    if (err) {
        err = error_wrap(err, "Failed to build manifest from tree");
        goto cleanup;
    }

    *out = manifest;
    return NULL;

cleanup:
    manifest_free(manifest);
    return err;
}

/**
 * Every row of the view, both kinds, unordered
 *
 * The cast adds const at both pointer levels (T ** → const T *const *) — legal
 * per the C standard's qualifier-conversion rule, no diagnostic required. Mirrors
 * workspace_files's identical bridge cast.
 */
manifest_rows_t manifest_rows(const manifest_t *manifest) {
    if (!manifest) return (manifest_rows_t){ 0 };
    return (manifest_rows_t){
        .entries = (const manifest_row_t *const *) manifest->rows,
        .count = manifest->count,
    };
}

/**
 * The profiles the view was built from, in precedence order
 */
const char *const *manifest_profiles(const manifest_t *manifest, size_t *count) {
    if (!manifest) {
        *count = 0;
        return NULL;
    }
    *count = manifest->profile_count;
    return manifest->profiles;
}

/**
 * The claims the build could not place, grouped by profile
 */
manifest_unbound_t manifest_unbound(const manifest_t *manifest) {
    if (!manifest) return (manifest_unbound_t){ 0 };
    return (manifest_unbound_t){
        .entries = manifest->unbound,
        .count = manifest->unbound_count,
    };
}

/**
 * Look up a row by filesystem path
 */
const manifest_row_t *manifest_lookup(
    const manifest_t *manifest,
    const char *filesystem_path
) {
    if (!manifest || !filesystem_path) return NULL;
    return hashmap_get(manifest->index, filesystem_path);
}

/**
 * Look up a row by storage path
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *storage_path,
    const char *profile
) {
    if (!manifest || !storage_path) return NULL;

    for (size_t i = 0; i < manifest->count; i++) {
        if (profile && strcmp(manifest->rows[i]->profile, profile) != 0) {
            continue;
        }
        if (strcmp(manifest->rows[i]->storage_path, storage_path) == 0) {
            return manifest->rows[i];
        }
    }
    return NULL;
}

/**
 * Free a manifest
 */
void manifest_free(manifest_t *manifest) {
    if (!manifest) return;
    if (manifest->index) {
        hashmap_free(manifest->index, NULL);
        manifest->index = NULL;
    }
    /* The struct, the spine and the rows are the arena's. */
}

/**
 * Attribute the transition between two views to profiles
 *
 * Two passes — every row of `after` for the gain side, every row of `before`
 * for the loss side — over two indexes: profile → stats slot, and the record by
 * path for the departure split. Nothing is written; the rule for what a departure
 * means for apply is the record's presence and ownership at the path, the same
 * fact the workspace reads when it meets the orphan.
 */
error_t *manifest_diff(
    const manifest_t *before,
    const manifest_t *after,
    const anchor_t *anchors,
    size_t anchor_count,
    const string_array_t *profiles,
    manifest_diff_stats_t *out_stats
) {
    CHECK_NULL(after);
    CHECK_NULL(profiles);
    CHECK_NULL(out_stats);

    error_t *err = NULL;
    hashmap_t *stats_map = NULL;
    hashmap_t *anchor_index = NULL;

    /* Stats attribution index. Maps profile name → its out_stats slot (the caller's
     * array, sized before the map is built — the pointers are stable). Keys are
     * borrowed from profiles; the caller keeps it alive for the duration of this
     * call. */
    stats_map = hashmap_borrow(profiles->count > 0 ? profiles->count * 2 : 16);
    if (!stats_map) {
        return ERROR(ERR_MEMORY, "Failed to create stats attribution map");
    }
    for (size_t i = 0; i < profiles->count; i++) {
        const char *name = profiles->items[i];

        /* Duplicate profile names would silently collapse: hashmap_set overwrites,
         * so the later occurrence's slot would receive all attribution and the
         * earlier slot would stay zero-filled. Fail loudly instead — this is a
         * caller-side contract violation. */
        if (hashmap_has(stats_map, name)) {
            err = ERROR(
                ERR_INVALID_ARG,
                "manifest_diff: duplicate profile '%s' in profiles",
                name
            );
            goto cleanup;
        }

        memset(&out_stats[i], 0, sizeof(out_stats[i]));
        out_stats[i].profile = name;
        err = hashmap_set(stats_map, name, &out_stats[i]);
        if (err) {
            err = error_wrap(err, "Failed to populate stats attribution map");
            goto cleanup;
        }
    }

    /* The record, indexed by path, for the orphan split: a departed row with a
     * record dotta owns leaves an orphan apply prunes (or releases, if Git let
     * go), one with a record dotta never owned leaves one the ownership gate
     * releases, one without leaves nothing for apply to do. Keys borrow the
     * records' arena-backed paths. */
    anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
    if (!anchor_index) {
        err = ERROR(ERR_MEMORY, "Failed to create anchors index");
        goto cleanup;
    }
    for (size_t i = 0; i < anchor_count; i++) {
        err = hashmap_set(anchor_index, anchors[i].filesystem_path, (void *) &anchors[i]);
        if (err) {
            err = error_wrap(err, "Failed to index anchors");
            goto cleanup;
        }
    }

    /* Gain side: every row of `after`, attributed to its winner. What `before`
     * had at the path splits claimed into added / updated / unchanged. */
    manifest_rows_t rows = manifest_rows(after);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        manifest_diff_stats_t *slot = hashmap_get(stats_map, row->profile);
        if (!slot) continue;

        slot->claimed++;

        const manifest_row_t *old = manifest_lookup(before, row->filesystem_path);
        if (!old) {
            slot->added++;
        } else if (!git_oid_equal(&old->blob_oid, &row->blob_oid) ||
            old->type != row->type || old->mode != row->mode) {
            slot->updated++;
        }
    }

    /* Loss side: every row of `before`, attributed to its former owner. A path
     * still in `after` under another profile is a reassignment (for user-facing
     * "A → B" messaging); a path `after` lacks is an orphan if a record stands
     * at it, and ownership says which kind. */
    rows = manifest_rows(before);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *old = rows.entries[i];

        manifest_diff_stats_t *slot = hashmap_get(stats_map, old->profile);
        if (!slot) continue;

        const manifest_row_t *row = manifest_lookup(after, old->filesystem_path);
        if (row) {
            if (strcmp(old->profile, row->profile) != 0) slot->reassigned++;
            continue;
        }

        const anchor_t *anchor = hashmap_get(anchor_index, old->filesystem_path);
        if (!anchor) continue;
        if (anchor->deployed_at > 0) {
            slot->orphans.owned++;
        } else {
            slot->orphans.observed++;
        }
    }

cleanup:
    if (stats_map) hashmap_free(stats_map, NULL);
    if (anchor_index) hashmap_free(anchor_index, NULL);
    return err;
}
