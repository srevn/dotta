/**
 * manifest.c - Manifest module implementation
 *
 * Owns the consistency layer for every modification of the virtual_manifest
 * table and the tree-loader primitive (manifest_load_tree_files) that
 * powers the historical-diff path. Both surfaces share a single internal
 * builder — precedence_view_build — that produces state_file_entry_t rows
 * directly. There is no longer a public file_entry_t/manifest_t bridge:
 * persistence and consumers see one row shape end-to-end.
 *
 * Key patterns:
 *   - Precedence Oracle: precedence_view_build (multi-profile) and
 *     precedence_view_load_tree (single-tree) emit a precedence_view_t whose
 *     rows are state_file_entry_t. Consistency-layer entry points consume
 *     the view directly; manifest_load_tree_files publishes its rows
 *     behind a state_files_t carrier.
 *   - Transaction Management: Caller manages transactions, we operate within them
 *   - Blob OID Extraction: Reads pre-populated blob_oid from each row for
 *     O(1) content identity
 *   - Metadata Integration: the precedence builder attributes per-profile
 *     metadata onto each row during the tree walk (single profile per row,
 *     no cross-profile merge — storage_path collisions across profiles with
 *     distinct target values are kept apart).
 */

#include "core/manifest.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * Precedence-view scratch buffer (private to manifest.c)
 *
 * The precedence-oracle's working buffer. Spine and per-entry strings are
 * arena-backed (caller-owned); the index hashmap is heap-allocated and
 * released by the consumer — internal callers free it at function-end,
 * and manifest_load_tree_files releases it before publishing the rows
 * via state_files_t (the public consumer iterates linearly and doesn't
 * need lookup).
 *
 * Rows are state_file_entry_t — the same shape consumed by the persistence
 * layer, so manifest_project_row can pass a row through to state_add_file
 * with no field translation.
 *
 * Spine growth uses arena_calloc + memcpy (abandon-and-realloc): the old
 * chunk is left to the arena (released at arena_destroy) and the hashmap's
 * (uintptr_t)(idx + 1) values stay valid because they encode indices, not
 * pointers.
 */
typedef struct precedence_view {
    state_file_entry_t *entries;   /* arena-backed, abandon-and-realloc growth */
    size_t count;
    size_t capacity;
    hashmap_t *index;              /* fs_path → idx+1, heap-allocated */
} precedence_view_t;

/**
 * Context for the precedence-view build callback
 *
 * Passed to gitops_tree_walk() to populate a precedence_view_t directly
 * during tree traversal, eliminating O(N×D) two-pass overhead. The callback
 * extracts identity fields from borrowed tree entries at O(1) per file.
 *
 * Memory ownership:
 * - view: borrowed, caller retains ownership
 * - mounts: borrowed, must not be NULL — keyed by ctx->profile to resolve
 *          custom/ entries; missing-binding lookups surface as
 *          MOUNT_RESOLVE_UNBOUND and the callback skips silently
 * - metadata: borrowed (per-profile, reloaded for each profile in the outer
 *             build loop), can be NULL (profile lacks metadata.json)
 * - arena: borrowed, must not be NULL; per-row strings + spine growth
 *          allocations are abandoned to it
 * - error: owned by callback, caller must free on error
 */
struct precedence_build_ctx {
    precedence_view_t *view;       /* Target view (modified by callback) */
    const char *profile;           /* Profile name for rows and error messages */
    const mount_table_t *mounts;   /* Mount table for storage→filesystem resolution */
    const metadata_t *metadata;    /* Per-profile metadata (NULL if absent) */
    arena_t *arena;                /* Arena for allocations (must not be NULL) */
    error_t *error;                /* Error propagation (set on failure) */
};

/**
 * Apply per-profile metadata to a Git-built precedence-view row.
 *
 * Selectively overrides the metadata-owned fields (mode, owner, group,
 * encrypted) on a row whose Git-derived defaults have already been set.
 * Each call attributes a single profile's claim to the row; precedence
 * across profiles is resolved by the walker's override pass and paired
 * re-application of this helper.
 *
 * Per-kind semantics when an item exists for the row's storage_path:
 *   FILE      → override mode; set encrypted; copy owner/group
 *   SYMLINK   → leave mode at 0 (links carry no settable mode); copy owner/group
 *   DIRECTORY → no-op (the tree walker filters to blobs; a directory metadata
 *               key cannot legitimately match a blob's storage_path)
 *
 * NULL metadata, missing item, and ERR_NOT_FOUND all leave the row's
 * Git-derived defaults intact. Other lookup failures propagate.
 *
 * Override-path callers may freely overwrite owner/group: prior values are
 * arena-borrowed and abandoned to the arena, no per-pointer free required.
 *
 * @param entry    Target row (mutable)
 * @param metadata Per-profile metadata (NULL → no-op)
 * @param arena    Allocation arena for string copies (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *precedence_view_apply_metadata(
    state_file_entry_t *entry,
    const metadata_t *metadata,
    arena_t *arena
) {
    if (!metadata) return NULL;

    const metadata_item_t *item = NULL;
    error_t *err = metadata_get_item(metadata, entry->storage_path, &item);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            error_free(err);
            return NULL;
        }
        return err;
    }

    /* owner/group apply to all kinds; copy first so the mode/encrypted
     * overrides below can short-circuit after the allocations have already
     * succeeded. arena_strdup returns NULL only on real failure (NULL
     * item->owner/group bypasses the if-guards and leaves the dup NULL). */
    char *owner_dup = NULL;
    if (item->owner) {
        owner_dup = arena_strdup(arena, item->owner);
        if (!owner_dup) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate owner for '%s'",
                entry->storage_path
            );
        }
    }

    char *group_dup = NULL;
    if (item->group) {
        group_dup = arena_strdup(arena, item->group);
        if (!group_dup) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate group for '%s'",
                entry->storage_path
            );
        }
    }

    /* Allocations succeeded — commit the overrides. */
    entry->owner = owner_dup;
    entry->group = group_dup;

    switch (item->kind) {
        case METADATA_ITEM_FILE:
            entry->mode = item->mode;
            entry->encrypted = item->file.encrypted;
            break;
        case METADATA_ITEM_SYMLINK:
            /* mode stays 0 (Git default for links); encrypted stays false. */
            break;
        case METADATA_ITEM_DIRECTORY:
            /* Defensive: walker filters to blobs, so this branch is
             * unreachable in practice. Take no action rather than corrupt
             * a file row with directory mode bits. */
            break;
    }

    return NULL;
}

/**
 * Tree-walk callback that populates the precedence view directly
 *
 * Performance optimization: Instead of collecting paths in pass 1 then
 * re-traversing via git_tree_entry_bypath() in pass 2 (O(N×D)), this
 * callback writes state_file_entry_t rows directly in O(N) time.
 *
 * Extracts identity fields (blob_oid, type, mode) from the borrowed tree
 * entry at the callback boundary — no git_tree_entry_dup needed, no opaque
 * handle stored on the row.
 *
 * Handles:
 * - Metadata file filtering (.dotta/, .bootstrap, etc.)
 * - Storage path to filesystem path conversion
 * - Profile precedence override (higher precedence wins)
 * - Spine growth on demand (arena abandon-and-realloc)
 * - File identity extraction from Git tree entry
 * - Per-profile metadata application (mode override, owner, group, encrypted)
 *
 * @param root Directory path within tree (empty string for root level)
 * @param entry Git tree entry (borrowed — valid for callback duration only)
 * @param payload Pointer to precedence_build_ctx
 * @return 0 to continue walk, -1 to stop on error
 */
static int precedence_view_build_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct precedence_build_ctx *ctx = (struct precedence_build_ctx *) payload;

    /* Only process blobs (files), skip directories */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build full storage path from root + entry name */
    const char *name = git_tree_entry_name(entry);
    char storage_path[1024];
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(
            storage_path, sizeof(storage_path), "%s%s",
            root, name
        );
    } else {
        ret = snprintf(
            storage_path, sizeof(storage_path), "%s",
            name
        );
    }

    /* Check for path truncation */
    if (ret < 0 || (size_t) ret >= sizeof(storage_path)) {
        ctx->error = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return -1;
    }

    /* Skip repository metadata files */
    if (strcmp(storage_path, ".dottaignore") == 0 ||
        strcmp(storage_path, ".bootstrap") == 0 ||
        strcmp(storage_path, ".gitignore") == 0 ||
        strcmp(storage_path, "README.md") == 0 ||
        strcmp(storage_path, "README") == 0 ||
        str_starts_with(storage_path, ".git/") ||
        str_starts_with(storage_path, ".dotta/")) {
        return 0;
    }

    /* Convert storage path to filesystem path against the mount table.
     *
     * MOUNT_RESOLVE_UNBOUND fires when storage_path is custom/... and
     * ctx->profile has no target binding in mounts — machine-specific
     * configuration (e.g., /jails/proxy/root) stored in the per-machine
     * state database. During clone or when a profile is enabled without
     * --target, we can't resolve where those files belong, so the row
     * is skipped silently. Genuine errors (malformed path, OOM)
     * propagate. */
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
    if (outcome == MOUNT_RESOLVE_UNBOUND) return 0;

    /* Check for existing row (profile precedence override) */
    void *idx_ptr = hashmap_get(ctx->view->index, filesystem_path);

    if (idx_ptr) {
        /* Override existing row (profile with higher precedence)
         *
         * Convert pointer back to index. We offset by 1 when storing to
         * distinguish NULL (not found) from index 0.
         * Safe because: indices are always << SIZE_MAX, uintptr_t can hold
         * any valid pointer value, and we never store actual pointers here.
         */
        size_t existing_idx = (size_t) (uintptr_t) idx_ptr - 1;

        /* Duplicate storage path */
        char *dup_storage_path = arena_strdup(ctx->arena, storage_path);
        if (!dup_storage_path) {
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        state_file_entry_t *override = &ctx->view->entries[existing_idx];

        /* Reset every metadata-owned and lifecycle field before the new
         * profile's metadata applies. The lower-precedence profile may have
         * left non-NULL owner/group/encrypted on the slot; carrying those
         * through would leak its attribution into the higher-precedence
         * row. The old string pointers (storage_path, filesystem_path,
         * owner, group) are arena-borrowed and abandoned to the caller's
         * arena when overwritten below.
         *
         * state, old_profile, and anchor are mirrored from the new-entry
         * branch to keep the override path self-contained — any tree-built
         * row carries STATE_ACTIVE, no reassignment witness, and a zero
         * deployment anchor regardless of construction order. */
        override->owner = NULL;
        override->group = NULL;
        override->encrypted = false;
        override->state = STATE_ACTIVE;
        override->old_profile = NULL;
        override->anchor = DEPLOYMENT_ANCHOR_UNSET;

        /* Update with new values from higher-precedence profile.
         * filesystem_path is arena-borrowed via mount_resolve; the cast
         * discards the const qualifier exposed by mount_resolve's output
         * type. ctx->profile is borrowed from the caller's profiles array
         * (or arena-strdup'd in the single-tree path); the cast discards
         * its const decoration to fit the row's `char *profile` slot. */
        override->storage_path = dup_storage_path;
        override->filesystem_path = (char *) filesystem_path;
        override->profile = (char *) ctx->profile;

        /* Extract identity from borrowed tree entry (blob_oid, type, mode).
         * The overriding profile may differ in filemode (e.g., executable bit). */
        git_oid_cpy(&override->blob_oid, git_tree_entry_id(entry));
        switch (git_tree_entry_filemode(entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                override->type = STATE_FILE_EXECUTABLE;
                override->mode = 0755;
                break;
            case GIT_FILEMODE_LINK:
                override->type = STATE_FILE_SYMLINK;
                override->mode = 0;
                break;
            default:
                override->type = STATE_FILE_REGULAR;
                override->mode = 0644;
                break;
        }

        /* Apply the new profile's metadata claim to the slot, if any. The
         * Git-derived defaults set above are the floor; metadata may override
         * mode and encrypted, and contribute owner/group. */
        error_t *meta_err = precedence_view_apply_metadata(
            override, ctx->metadata, ctx->arena
        );
        if (meta_err) {
            /* The slot is already in a consistent post-override shape
             * (owner/group NULL, encrypted false, Git-derived mode). The
             * caller's outer error path propagates without freeing the
             * view (its spine + strings are arena-backed). */
            ctx->error = error_wrap(
                meta_err, "Failed to apply metadata to '%s'",
                override->storage_path
            );
            return -1;
        }
    } else {
        /* Add new row — grow spine if needed.
         *
         * Arena abandon-and-realloc: allocate a new chunk from the arena,
         * memcpy the existing rows, and swap the pointer. The old chunk
         * stays valid for the arena's lifetime but is no longer referenced;
         * the arena reclaims it at arena_destroy. This is safe because the
         * hashmap stores (uintptr_t)(idx + 1) values — indices, not
         * pointers — and is unaffected by the spine relocation. */
        if (ctx->view->count >= ctx->view->capacity) {
            if (ctx->view->capacity > SIZE_MAX / 2) {
                ctx->error = ERROR(
                    ERR_INTERNAL, "Precedence view capacity overflow"
                );
                return -1;
            }
            size_t new_capacity = ctx->view->capacity * 2;

            state_file_entry_t *new_entries = arena_calloc(
                ctx->arena, new_capacity, sizeof(*new_entries)
            );
            if (!new_entries) {
                ctx->error = ERROR(
                    ERR_MEMORY, "Failed to grow precedence view"
                );
                return -1;
            }
            memcpy(
                new_entries, ctx->view->entries,
                ctx->view->count * sizeof(*new_entries)
            );
            ctx->view->entries = new_entries;
            ctx->view->capacity = new_capacity;
        }

        /* Duplicate storage path */
        char *dup_storage_path = arena_strdup(ctx->arena, storage_path);
        if (!dup_storage_path) {
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        /* Initialize row.
         *
         * Spine growth is via arena_calloc, which zeros new memory, so the
         * fresh slot already has every field zero. Re-zero defensively in
         * case a future allocator change drops the calloc semantic; this
         * also gives readers a single self-contained sentence about what
         * the slot's pre-write state is. */
        state_file_entry_t *new_entry = &ctx->view->entries[ctx->view->count];
        memset(new_entry, 0, sizeof(*new_entry));
        new_entry->storage_path = dup_storage_path;
        /* filesystem_path is arena-borrowed via mount_resolve; cast
         * discards the const qualifier from mount_resolve's output type. */
        new_entry->filesystem_path = (char *) filesystem_path;
        new_entry->profile = (char *) ctx->profile;
        /* Tree-built rows always carry STATE_ACTIVE. The literal lives at
         * process scope; manifest_project_row's UPSERT binds it via
         * SQLITE_TRANSIENT (SQLite copies the bytes immediately). */
        new_entry->state = STATE_ACTIVE;
        /* old_profile, anchor stay zero from memset. */

        /* Extract identity from borrowed tree entry (blob_oid, type, mode) */
        git_oid_cpy(&new_entry->blob_oid, git_tree_entry_id(entry));
        switch (git_tree_entry_filemode(entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                new_entry->type = STATE_FILE_EXECUTABLE;
                new_entry->mode = 0755;
                break;
            case GIT_FILEMODE_LINK:
                new_entry->type = STATE_FILE_SYMLINK;
                new_entry->mode = 0;
                break;
            default:
                /* Should never happen (we filtered to blobs above) */
                new_entry->type = STATE_FILE_REGULAR;
                new_entry->mode = 0644;
                break;
        }

        /* Apply this profile's metadata claim (if any) to the slot.
         *
         * Done before the hashmap insertion so any failure rolls back without
         * leaving a stale path → index mapping pointing at a half-built row.
         */
        error_t *meta_err = precedence_view_apply_metadata(
            new_entry, ctx->metadata, ctx->arena
        );
        if (meta_err) {
            /* Strings are arena-borrowed; abandon them to the caller's
             * arena and zero the fields so the unused slot doesn't carry
             * stale attribution into a future overlay. */
            new_entry->storage_path = NULL;
            new_entry->filesystem_path = NULL;
            ctx->error = error_wrap(
                meta_err, "Failed to apply metadata to '%s'",
                storage_path
            );
            return -1;
        }

        /* Store index in hashmap (offset by 1 to distinguish from NULL) */
        err = hashmap_set(
            ctx->view->index, filesystem_path,
            (void *) (uintptr_t) (ctx->view->count + 1)
        );
        if (err) {
            /* Row already added to spine, but hashmap failed.
             * Strings (including any owner/group that apply_metadata
             * succeeded on before this point) are arena-borrowed; abandon
             * them to the caller's arena and zero the fields so the
             * unused slot doesn't carry stale attribution. */
            new_entry->storage_path = NULL;
            new_entry->filesystem_path = NULL;
            new_entry->owner = NULL;
            new_entry->group = NULL;
            ctx->error = error_wrap(err, "Failed to update hashmap");
            return -1;
        }

        ctx->view->count++;
    }

    return 0;  /* Continue walk */
}

/**
 * Allocate a fresh precedence_view_t, ready for the build callback.
 *
 * Both the view struct and the initial spine are arena-allocated. The
 * index hashmap is heap-allocated (borrowed-key mode — keys live in the
 * caller's arena and survive the hashmap's lifetime).
 *
 * On error, the function returns ERR_MEMORY and *out_view is NULL; any
 * partially-constructed heap allocation (the index) is freed before
 * returning. Arena allocations are abandoned to the arena.
 */
static error_t *precedence_view_allocate(
    arena_t *arena,
    size_t initial_capacity,
    size_t index_capacity,
    precedence_view_t **out_view
) {
    *out_view = NULL;

    precedence_view_t *view = arena_calloc(arena, 1, sizeof(*view));
    if (!view) {
        return ERROR(ERR_MEMORY, "Failed to allocate precedence view");
    }

    view->capacity = initial_capacity;
    view->entries = arena_calloc(arena, view->capacity, sizeof(*view->entries));
    if (!view->entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate precedence view spine");
    }

    view->index = hashmap_borrow(index_capacity);
    if (!view->index) {
        return ERROR(ERR_MEMORY, "Failed to create precedence view index");
    }

    *out_view = view;

    return NULL;
}

/**
 * Build precedence view from profile names
 *
 * Performance: O(N) where N is total files across all profiles.
 * One Git tree alive per iteration (loaded, walked, freed).
 *
 * `mounts` MUST cover every profile in `profiles` (callers build it from
 * the same list). Custom/ entries belonging to a profile with no target
 * binding are skipped silently by the callback — that branch is the only
 * place "no --target on this machine" is allowed to influence the view,
 * ensuring policy lives in one site instead of being replicated by each
 * engine entry point.
 *
 * Memory:
 *   - view struct, spine, and per-row strings: arena-allocated; the
 *     caller's arena reclaims them at arena_destroy.
 *   - index hashmap: heap-allocated; on success the caller takes ownership
 *     and must call precedence_view_release(view) when done. On error,
 *     the hashmap (if allocated) is freed here and *out is NULL.
 */
static error_t *precedence_view_build(
    git_repository *repo,
    const string_array_t *profiles,
    const mount_table_t *mounts,
    arena_t *arena,
    precedence_view_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    precedence_view_t *view = NULL;
    error_t *err = precedence_view_allocate(arena, 64, 128, &view);
    if (err) return err;

    /* Process each profile in order (later profiles override earlier) */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Load tree for this profile (scoped to iteration) */
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'", profile
            );
            goto cleanup;
        }

        /* Load this profile's metadata.json from the tree we just opened
         * (avoid a second ref/commit/tree walk). Per-profile lookup is the
         * correctness boundary for VWD attribution: each profile claims its
         * own files via its own metadata, never via a cross-profile merge.
         * ERR_NOT_FOUND here means "no metadata blob in this tree" — normal
         * for old or freshly created profiles, and the callback degrades
         * gracefully (Git-derived defaults stand). */
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

        /* Build view rows via single-pass tree traversal.
         *
         * The callback extracts identity fields (blob_oid, type, mode) from
         * borrowed tree entries, converts paths via mount_resolve, handles
         * precedence override, applies per-profile metadata to
         * mode/owner/group/encrypted, and populates state_file_entry_t
         * rows directly — all in O(N) time.
         *
         * profile borrows from the caller's profiles array — must outlive
         * the view. mounts is borrowed from the caller; bindings are keyed
         * by profile (which the callback feeds verbatim into mount_resolve).
         * metadata borrows from profile_metadata, scoped to this
         * iteration. */
        struct precedence_build_ctx ctx = {
            .view     = view,
            .profile  = profile,
            .mounts   = mounts,
            .metadata = profile_metadata,
            .arena    = arena,
            .error    = NULL
        };

        err = gitops_tree_walk(tree, precedence_view_build_callback, &ctx);
        git_tree_free(tree);
        metadata_free(profile_metadata);

        if (err || ctx.error) {
            err = ctx.error ? ctx.error : err;
            err = error_wrap(
                err, "Failed to build precedence view for profile '%s'",
                profile
            );
            goto cleanup;
        }
    }

    *out = view;
    return NULL;

cleanup:
    /* The view's spine + strings are arena-abandoned; only the heap-
     * allocated index needs explicit free on the error path. */
    if (view && view->index) hashmap_free(view->index, NULL);
    return err;
}

/**
 * Build precedence view from a single Git tree
 *
 * Creates a single-profile view from a specific Git tree, useful for
 * historical diffs against a past commit's tree.
 *
 * `mounts` MUST record a binding for `profile` when the tree contains
 * custom/ entries that should resolve, otherwise those entries are
 * skipped silently. Trees without custom/ entries can pass any mount
 * table handle, including one with no binding for `profile`.
 *
 * Memory: same contract as precedence_view_build (arena-backed view
 * + heap-backed index).
 */
static error_t *precedence_view_load_tree(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    precedence_view_t **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    precedence_view_t *view = NULL;
    error_t *err = precedence_view_allocate(arena, 64, 128, &view);
    if (err) return err;

    /* Arena-allocate the profile name. Rows borrow this pointer; the
     * caller's arena outlives the view (it backs every per-row string
     * the callback writes), so the borrow stays valid until arena_destroy. */
    const char *owned_profile = arena_strdup(arena, profile);
    if (!owned_profile) {
        err = ERROR(ERR_MEMORY, "Failed to duplicate profile name");
        goto cleanup;
    }

    /* Build view rows via single-pass tree traversal.
     *
     * mounts and metadata borrow from function parameters — both outlive
     * the tree walk. */
    struct precedence_build_ctx ctx = {
        .view     = view,
        .profile  = owned_profile,
        .mounts   = mounts,
        .metadata = metadata,
        .arena    = arena,
        .error    = NULL
    };

    err = gitops_tree_walk(tree, precedence_view_build_callback, &ctx);

    if (err || ctx.error) {
        err = ctx.error ? ctx.error : err;
        err = error_wrap(err, "Failed to build precedence view from tree");
        goto cleanup;
    }

    *out = view;
    return NULL;

cleanup:
    if (view && view->index) hashmap_free(view->index, NULL);
    return err;
}

/**
 * Sync a precedence-view row through to the manifest table
 *
 * SCOPE ("Pure VWD-cache writer, plus observation stamp on INSERT"):
 *   This function is authoritative for the VWD-cache columns (storage_path,
 *   profile, blob_oid, type, mode, owner, group, encrypted, state). It NEVER
 *   advances the deployment witness (deployed_blob_oid, deployed_at, stat_*).
 *   Callers needing to advance the witness must follow with
 *   state_update_anchor(), which is the sole legitimate witness writer.
 *
 *   It does stamp anchor.observed_at in-place on the row when the target
 *   path exists on disk (see step 1 of the body). The UPSERT's monotonic
 *   CASE preserves any existing non-zero observed_at on UPDATE, so repeat
 *   calls are idempotent on that column.
 *
 *   Reassignment tracking is automatic: the UPSERT's old_profile CASE
 *   captures the prior profile into old_profile when the profile column
 *   changes, and preserves the existing value otherwise. Clearing is a
 *   separate concern, handled by state_clear_old_profile() once the
 *   user has been shown the reassignment.
 *
 * Single-source-of-truth contract: the row IS the source. mode, owner,
 * group, and encrypted are read directly from view_row — precedence_view_build
 * has already attributed each row to its source profile and applied that
 * profile's metadata.json claim during the tree walk. No metadata side-
 * channel is consulted here, which is what keeps storage_path collisions
 * across profiles with distinct target values from cross-contaminating
 * the row (each row's metadata-owned fields belong to exactly one profile).
 *
 * The `encrypted` field specifically is a metadata-projected cache: the
 * upstream cache is `metadata.json:encrypted`, populated byte-derived at
 * the write boundary (cmds/add.c, cmds/update.c via
 * content_store_file_to_worktree's out_kind). Reconcile projects it through
 * precedence_view_apply_metadata without re-classifying the blob — runtime trusts
 * the cache; write-time establishes the invariant. See
 * docs/encryption-spec.md → "Cache hierarchy and write-time invariant".
 *
 * The witness columns (deployed_blob_oid, deployed_at, stat_*) are left
 * untouched — the UPSERT preserves them on UPDATE, and on INSERT they
 * start at zero. Lifecycle stamping is state_update_anchor's job;
 * capture-from-disk callers (manifest_add_files, manifest_update_files)
 * pair this call with a state_update_anchor(..., now) that stamps
 * deployed_at and the stat witness on both INSERT and UPDATE paths.
 *
 * Note: commit_oid is stored per-profile in enabled_profiles, not per-file.
 * Callers are responsible for calling manifest_persist_profile_head() after
 * syncing to refresh the per-profile commit_oid from the branch's HEAD.
 *
 * Mutation: view_row is mutable so that this function — the one caller
 * authorised to write the row's anchor.observed_at — can stamp the
 * observation directly. No other field is mutated; downstream consumers
 * of view_row see the stamp as part of the row's post-call value.
 *
 * @param repo Git repository
 * @param state State handle (with active transaction)
 * @param view_row Precedence-view row (mutable: anchor.observed_at is stamped
 *                 in place); MUST have blob_oid, profile, and metadata-owned
 *                 fields populated (guaranteed for rows from precedence_view_build)
 * @return Error or NULL on success
 */
static error_t *manifest_project_row(
    git_repository *repo,
    state_t *state,
    state_file_entry_t *view_row
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(view_row);
    CHECK_NULL(view_row->profile);

    /* Probe the filesystem so we can stamp the observation signal on
     * INSERT. observed_at answers "has dotta ever lstat-confirmed this
     * path on disk in scope?" — the classifier uses it to distinguish
     * a ghost file (never seen, classifies UNDEPLOYED) from a file the
     * user has removed (seen, classifies DELETED). The UPSERT's CASE
     * preserves existing non-zero observed_at on UPDATE, so this lstat
     * only matters on INSERT; repeat reconciles are idempotent.
     *
     * Gate is strict: only a successful lstat counts as an observation.
     * ENOENT and every other lstat failure leave observed_at = 0, which
     * keeps ghost files out of DELETED classification.
     *
     * Stamp is in-place: the view's row is read-only after construction
     * except for this monotonic field, and no consumer between build and
     * free reads anchor.observed_at — they read state-DB values via the
     * workspace classifier, which queries the row that this UPSERT just
     * wrote. */
    struct stat probe_st;
    if (lstat(view_row->filesystem_path, &probe_st) == 0) {
        view_row->anchor.observed_at = time(NULL);
    }

    error_t *err = state_add_file(state, view_row);
    if (err) {
        err = error_wrap(
            err, "Failed to sync manifest entry for %s",
            view_row->storage_path
        );
    }

    return err;
}

/**
 * Capture a precedence-view row to the manifest, advancing the deployment
 * anchor with a fresh disk witness.
 *
 * The manifest layer's CAPTURE primitive — paired with manifest_project_row
 * (PROJECTION). Used by manifest_add_files and manifest_update_files at
 * the modified-or-new branch, the two sites where a user's claim of
 * ownership pairs an immediate VWD-cache write with an anchor advance to
 * a fresh-from-disk witness.
 *
 * Bridges the field-completeness asymmetry documented at state.h's
 * state_files_t doc-block: input is a tree-built row (anchor unset by
 * construction); output is a persisted row carrying both VWD cache and a
 * fully-populated anchor. The wrapper performs ONE lstat() — both
 * observed_at (the row's monotonic-once-set first-observation stamp) and
 * the stat_cache witness on the anchor derive from the same stat result,
 * eliminating the prior triplet's redundant probe.
 *
 * Routing invariant (state.h: "ROUTING INVARIANT" on state_update_anchor):
 * manifest-layer path, no live workspace, resolved_out=NULL. Workspace-
 * scope callers (apply's deploy + adoption paths) MUST route through
 * workspace_advance_anchor instead, which mirrors the post-write anchor
 * into the workspace's snapshot.
 *
 * Two SQL roundtrips by design: the UPSERT writes VWD cache (anchor
 * preserved on UPDATE per the CASE in state.c::sql_insert), and the
 * UPDATE writes the anchor. Collapsing to a single UPSERT would weaken
 * the SQL invariant from "physically impossible to clobber the anchor"
 * to "caller-disciplined preserve-on-zero" — a worse trade for
 * sub-millisecond savings.
 *
 * Error contract:
 *   - state_add_file failure (UPSERT) propagates wrapped — the caller
 *     must roll back the transaction.
 *   - state_update_anchor failure is non-fatal: the VWD cache is already
 *     committed, and the next status self-heals via the slow-path
 *     CMP_EQUAL flush.
 *
 * Mutation: row->anchor.observed_at is stamped in place when lstat
 * succeeds (mirrors manifest_project_row's stamp). No other field is
 * mutated.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL, with active transaction)
 * @param row Precedence-view row (mutable: observed_at stamped in place);
 *            MUST have blob_oid, profile, and metadata-owned fields
 *            populated (guaranteed for rows from precedence_view_build)
 * @return Error or NULL on success (anchor-write failures swallowed)
 */
static error_t *manifest_capture_row(
    git_repository *repo,
    state_t *state,
    state_file_entry_t *row
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(row);
    CHECK_NULL(row->profile);

    time_t now = time(NULL);

    /* Single lstat: feeds both the observed_at stamp on the row (consumed
     * by the UPSERT's monotonic CASE) and the stat_cache witness on the
     * anchor (fast-path validity gate). A successful stat is the
     * "observation" event; failure leaves both signals at sentinel-zero,
     * and the next status's slow-path CMP_EQUAL re-derives the witness
     * from disk truth on its own probe. */
    struct stat st;
    bool stat_ok = (lstat(row->filesystem_path, &st) == 0);
    if (stat_ok) {
        row->anchor.observed_at = now;
    }

    /* VWD-cache write. The UPSERT preserves the existing anchor on UPDATE
     * (state.c::sql_insert); the anchor advance below is the only path
     * that writes deployed_blob_oid / deployed_at / stat_*. */
    error_t *err = state_add_file(state, row);
    if (err) {
        return error_wrap(
            err, "Failed to sync manifest entry for %s", row->storage_path
        );
    }

    /* Anchor advance with the witness derived from the same stat above.
     * Failure is non-fatal: VWD cache is already committed; the next
     * status self-heals via the slow-path CMP_EQUAL flush. */
    deployment_anchor_t anchor = {
        .blob_oid    = row->blob_oid,
        .deployed_at = now,
        .observed_at = now,    /* monotonic-once-set in SQL; safe duplicate */
        .stat        = stat_ok ? stat_cache_from_stat(&st) : STAT_CACHE_UNSET,
    };
    error_t *anchor_err = state_update_anchor(
        state, row->filesystem_path, &anchor, NULL
    );
    if (anchor_err) {
        error_free(anchor_err);
    }

    return NULL;
}

/**
 * Load a single Git tree's files into the public state_files_t carrier.
 *
 * The historical-diff path consumes a tree-built file slice that mirrors
 * the workspace's active slice (workspace_active) and apply's deploy result
 * (deploy_result_view). One carrier shape, three producers — a consumer
 * written against state_files_t composes with all of them.
 *
 * Implementation: delegates to precedence_view_load_tree to build a precedence
 * view, then publishes the view's rows behind a fresh pointer array. The
 * row spine and per-row strings live in the caller's arena. The index
 * hashmap is freed eagerly — public consumers iterate by index, never look
 * up by filesystem_path.
 *
 * Memory:
 *   - Spine, per-row strings, view struct, and pointer array all live in
 *     the caller's arena. arena_destroy reclaims them at command end.
 *   - Index hashmap (heap-allocated by precedence_view_load_tree) is released
 *     here before returning.
 *
 * On error: arena allocations are abandoned to the caller's arena (no
 * targeted free); the index hashmap is released; *out is left zero-init.
 *
 * Custom-prefix resolution mirrors precedence_view_load_tree (which mirrors
 * precedence_view_build): mounts MUST record a binding for `profile` when
 * the tree contains custom/ entries that should resolve, otherwise those
 * entries are skipped silently by the build callback.
 *
 * @param tree     Git tree to load (must not be NULL)
 * @param profile  Profile name carried on each row (must not be NULL)
 * @param mounts   Per-machine mount table (must not be NULL)
 * @param metadata Optional per-tree metadata applied to rows (can be NULL)
 * @param arena    Arena backing every allocation produced by the call
 *                 (must not be NULL)
 * @param out      Output state_files_t (must not be NULL; entries are
 *                 borrowed from `arena`, lifetime tied to it)
 * @return Error or NULL on success
 */
error_t *manifest_load_tree_files(
    git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    const metadata_t *metadata,
    arena_t *arena,
    state_files_t *out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (state_files_t){ 0 };

    precedence_view_t *view = NULL;
    error_t *err = precedence_view_load_tree(
        tree, profile, mounts, metadata, arena, &view
    );
    if (err) return err;

    /* The build-time index (filesystem_path → idx + 1) helped the callback
     * detect duplicates and resolve precedence overrides. The public
     * consumer iterates linearly and doesn't need lookup, so release it
     * eagerly rather than tying it to the arena's lifetime. */
    if (view->index) {
        hashmap_free(view->index, NULL);
        view->index = NULL;
    }

    if (view->count == 0) {
        return NULL;  /* *out already zero-init = empty slice */
    }

    /* Publish the view's rows behind a borrowed pointer array. The spine
     * is arena-backed (not heap), so each &view->entries[i] address stays
     * valid for the arena's lifetime. */
    const state_file_entry_t **ptrs = arena_calloc(
        arena, view->count, sizeof(*ptrs)
    );
    if (!ptrs) {
        return ERROR(ERR_MEMORY, "Failed to allocate state_files_t spine");
    }
    for (size_t i = 0; i < view->count; i++) {
        ptrs[i] = &view->entries[i];
    }

    /* The cast adds const at the outer pointer level (T ** → T *const *) —
     * legal per the C standard's qualifier-conversion rule, no diagnostic
     * required. Mirrors workspace_active's identical bridge cast. */
    out->entries = (const state_file_entry_t *const *) ptrs;
    out->count = view->count;

    return NULL;
}

/**
 * Resolve a profile's current branch HEAD and persist it as the
 * stored commit_oid in enabled_profiles.
 *
 * Composes gitops_resolve_branch_head_oid + state_set_profile_commit_oid.
 * Callers pair this with state_enable_profile / state_set_profiles to
 * complete the authoritative-scope contract before manifest_apply_scope:
 * state_enable_profile writes the zero-OID sentinel; this function
 * replaces it with the real branch HEAD. apply_scope then trusts the
 * commit_oid column and does not walk refs on its own.
 *
 * Sites that bypass this helper:
 *   - manifest_detect_stale_profiles: read-only HEAD comparison.
 *   - manifest_sync_diff: caller passes the new HEAD explicitly as new_oid.
 */
error_t *manifest_persist_profile_head(
    git_repository *repo,
    state_t *state,
    const char *profile
) {
    git_oid head_oid;
    error_t *err = gitops_resolve_branch_head_oid(repo, profile, &head_oid);
    if (err) {
        return error_wrap(
            err, "Failed to get HEAD for profile '%s'", profile
        );
    }

    err = state_set_profile_commit_oid(state, profile, &head_oid);
    if (err) {
        return error_wrap(
            err, "Failed to record commit_oid for profile '%s'", profile
        );
    }

    return NULL;
}

/**
 * Project a DIRECTORY metadata item to a state directory entry.
 *
 * Resolves filesystem_path via the mount table. UNBOUND ⇒ silent skip:
 * *out is NULL and the function returns NULL. This happens only for
 * custom/ items whose owning profile has no target binding on this host
 * (clone before --target, or profile enabled without --target).
 *
 * Caller (manifest_sync_directories) guarantees item->kind is DIRECTORY
 * via metadata_get_items_by_kind() — the kind filter is the contract,
 * not a runtime check.
 *
 * @param item    Metadata item (must not be NULL, DIRECTORY kind by caller contract)
 * @param profile Source profile name (must not be NULL)
 * @param mounts  Per-machine mount table (must not be NULL)
 * @param arena   Arena for allocations (must not be NULL)
 * @param out     State directory entry (must not be NULL, lifetime tied to arena)
 * @return Error or NULL on success
 */
static error_t *directory_entry_from_metadata(
    const metadata_item_t *item,
    const char *profile,
    const mount_table_t *mounts,
    arena_t *arena,
    state_directory_entry_t **out
) {
    CHECK_NULL(item);
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    /* Defer entry allocation until after the mount lookup so the skip
     * path performs no allocation. UNBOUND surfaces only when the storage
     * path is custom/... and `profile` has no target binding on this host. */
    mount_resolve_outcome_t outcome;
    const char *fs_path = NULL;
    error_t *err = mount_resolve(
        mounts, profile, item->key, arena, &outcome, &fs_path
    );
    if (err) {
        return error_wrap(
            err, "Failed to derive filesystem path from storage path: %s",
            item->key
        );
    }
    if (outcome == MOUNT_RESOLVE_UNBOUND) return NULL;

    state_directory_entry_t *entry = arena_calloc(arena, 1, sizeof(*entry));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate state directory entry");
    }

    /* filesystem_path is arena-borrowed via mount_resolve; the cast
     * accommodates the struct field's `char *` typing without implying
     * mutability. The borrow shares the arena lifetime of the strdup'd
     * siblings below.
     *
     * deployed_at intentionally left zero-initialized by calloc. The
     * INSERT in state_add_directory omits the column (schema DEFAULT
     * strftime('%s','now') fires for new rows); the UPDATE in
     * state_update_directory also omits it (preserving the existing
     * value on refresh). The field on this struct is never persisted. */
    entry->filesystem_path = (char *) fs_path;
    entry->storage_path = arena_strdup(arena, item->key);
    entry->profile = arena_strdup(arena, profile);
    entry->mode = item->mode;
    entry->owner = item->owner ? arena_strdup(arena, item->owner) : NULL;
    entry->group = item->group ? arena_strdup(arena, item->group) : NULL;

    if (!entry->storage_path || !entry->profile ||
        (item->owner && !entry->owner) || (item->group && !entry->group)) {
        return ERROR(ERR_MEMORY, "Failed to copy directory entry fields");
    }

    *out = entry;
    return NULL;
}

/**
 * Detect which enabled profiles have stale state entries
 *
 * Iterates in-scope profiles and compares each profile's stored commit_oid
 * (from enabled_profiles) against its branch's current HEAD. Mismatch means
 * external Git operations occurred since the last dotta operation.
 *
 * O(P) state queries + O(P) ref lookups where P = profile count.
 *
 * Internal helper for manifest_repair_stale. Not part of the public API —
 * callers reach drift repair through manifest_reconcile.
 */
static error_t *manifest_detect_stale_profiles(
    git_repository *repo,
    const state_t *state,
    const hashmap_t *profile_scope,
    hashmap_t **out_stale
) {
    *out_stale = NULL;

    error_t *err = NULL;
    hashmap_t *stale_map = NULL;

    /* Iterate profile_scope keys — one check per profile, no dedup needed. */
    hashmap_iter_t iter;
    hashmap_iter_init(&iter, profile_scope);

    const char *profile;
    while (hashmap_iter_next(&iter, &profile, NULL)) {
        /* Read stored commit_oid for this profile (borrowed from row cache).
         * NULL = profile not enabled (e.g. race with disable) — skip. */
        const git_oid *stored_oid = state_peek_profile_commit_oid(state, profile);
        if (!stored_oid) continue;

        /* Fetch current branch HEAD via lightweight ref-to-OID lookup.
         *
         * profile_scope is a membership set (NULL values) — manifest_repair_stale
         * populates it from the enabled-profile list before calling us. */
        git_oid head_oid;
        err = gitops_resolve_branch_head_oid(repo, profile, &head_oid);
        if (err) {
            /* Branch may have been deleted — skip (safety handles this) */
            error_free(err);
            err = NULL;
            continue;
        }

        if (!git_oid_equal(stored_oid, &head_oid)) {
            /* Profile is stale — HEAD moved since last dotta operation */
            if (!stale_map) {
                stale_map = hashmap_borrow(16);
                if (!stale_map) {
                    return ERROR(ERR_MEMORY, "Failed to create stale profile map");
                }
            }

            err = hashmap_set(stale_map, profile, (void *) (uintptr_t) 1);
            if (err) {
                hashmap_free(stale_map, NULL);
                return err;
            }
        }
    }

    *out_stale = stale_map;
    return NULL;
}

/**
 * Repair stale state entries from external Git changes
 *
 * Persistent repair: detects state entries whose commit_oid no longer
 * matches the profile branch HEAD, then either updates them from fresh Git
 * state or marks them STATE_RELEASED for release. The deployment anchor
 * (deployed_blob_oid, deployed_at, stat_*) is preserved by the UPSERT
 * across repair — reconcile advances the VWD cache's blob_oid to track Git
 * while leaving the anchor pinned to dotta's last disk confirmation. The
 * divergence between the two is how workspace Phase 1/3 classifies
 * staleness from persistent state (no hashmap escape needed).
 *
 * Internal algorithm implementation. manifest_reconcile is the public entry
 * point — it owns profile-list fetching, transaction scoping, and empty-
 * scope handling; this helper runs the repair algorithm assuming a ready
 * transaction and validated inputs.
 */
static error_t *manifest_repair_stale(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const string_array_t *enabled_profiles,
    manifest_repair_stats_t *out_stats
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_stats);

    memset(out_stats, 0, sizeof(*out_stats));

    error_t *err = NULL;
    size_t all_count = 0;
    state_file_entry_t *all_entries = NULL;
    hashmap_t *profile_scope = NULL;
    hashmap_t *stale_profiles = NULL;
    precedence_view_t *fresh = NULL;

    /* Phase 1: Detect stale profiles via per-profile commit_oid comparison.
     *
     * O(P) state queries + O(P) ref lookups. If no profile is stale, exits
     * immediately without loading file entries (zero cost common case). */
    profile_scope = hashmap_borrow(enabled_profiles->count);
    if (!profile_scope) {
        err = ERROR(ERR_MEMORY, "Failed to create profile scope map");
        goto cleanup;
    }
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        err = hashmap_set(profile_scope, enabled_profiles->items[i], NULL);
        if (err) goto cleanup;
    }

    err = manifest_detect_stale_profiles(
        repo, state, profile_scope, &stale_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to detect stale profiles");
        goto cleanup;
    }

    if (!stale_profiles) {
        goto cleanup;  /* All profiles current — nothing to repair */
    }

    /* Load all state entries for Phase 3 repair loop. Only loaded when
     * staleness is detected — common case (no staleness) pays zero cost. */
    err = state_get_all_files(state, arena, &all_entries, &all_count);
    if (err) {
        err = error_wrap(err, "Failed to load state entries for stale repair");
        goto cleanup;
    }

    /* Phase 2: Build fresh precedence view from current Git state.
     * Provides the ground truth for what files should exist. The build
     * attributes per-profile metadata onto each row, so the repair pass
     * below propagates the correct metadata for whichever profile won
     * precedence after Git moved underneath us.
     *
     * The caller-supplied mount table covers the same enabled set the
     * precedence_view_build pass iterates — the directory rebuild at
     * Phase 4 reuses the handle. */
    err = precedence_view_build(repo, enabled_profiles, mounts, arena, &fresh);
    if (err) {
        err = error_wrap(err, "Failed to build precedence view for stale repair");
        goto cleanup;
    }

    /* Phase 3: Process ACTIVE state entries from stale profiles.
     *
     * Single pass over pre-loaded entries, filtering by stale_profiles map.
     * For each entry: compare against fresh precedence view to determine
     * update (file still in Git) or release (file removed from Git
     * externally).
     */
    for (size_t i = 0; i < all_count; i++) {
        state_file_entry_t *entry = &all_entries[i];

        /* Only repair ACTIVE entries from stale profiles */
        if (!entry->state || strcmp(entry->state, STATE_ACTIVE) != 0) {
            continue;
        }
        if (!entry->profile || !hashmap_get(stale_profiles, entry->profile)) {
            continue;
        }

        /* Look up in fresh precedence view (O(1) index lookup) */
        state_file_entry_t *fresh_entry = NULL;
        if (fresh && fresh->index) {
            void *idx_ptr = hashmap_get(fresh->index, entry->filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fresh_entry = &fresh->entries[idx];
            }
        }

        if (fresh_entry) {
            /* File still in Git (same or different profile via fallback).
             *
             * Use manifest_project_row to update with current Git truth.
             * Preserve deployed_at — the file's lifecycle history is unchanged,
             * only the expected state cache needs updating.
             */

            /* Determine if file content actually changed (blob_oid differs).
             *
             * A profile HEAD can move without changing this file's blob
             * (other files in the commit changed). The flag drives the
             * updated/refreshed stat distinction below so users see real
             * content changes, not bookkeeping.
             *
             * Staleness detection itself no longer consumes this signal —
             * workspace Phase 1/3 reads the persistent deployment anchor
             * directly, comparing anchor.blob_oid against the new Git blob.
             */
            bool blob_changed = !git_oid_equal(&entry->blob_oid, &fresh_entry->blob_oid);

            /* deployed_at preserved by SQL UPSERT, old_profile auto-captured
             * by SQL when the owning profile shifts during repair. */
            bool profile_shifted = strcmp(fresh_entry->profile, entry->profile) != 0;

            err = manifest_project_row(repo, state, fresh_entry);
            if (err) {
                err = error_wrap(
                    err, "Failed to repair stale entry '%s'",
                    entry->storage_path
                );
                goto cleanup;
            }

            /* Track profile reassignment when owning profile shifts during repair */
            if (profile_shifted) {
                out_stats->reassigned++;
            }

            if (blob_changed) {
                out_stats->updated++;
            } else {
                out_stats->refreshed++;
            }
        } else {
            /* File removed from all enabled profiles — loss of authority.
             *
             * Mark STATE_RELEASED so the orphan→safety→cleanup pipeline releases
             * it (leaves file on filesystem, removes state entry).
             *
             * Do NOT remove the state entry here — the full pipeline ensures
             * user visibility and safety checks before any cleanup.
             */
            err = state_set_file_state(state, entry->filesystem_path, STATE_RELEASED);
            if (err) {
                err = error_wrap(
                    err, "Failed to mark '%s' as stale",
                    entry->storage_path
                );
                goto cleanup;
            }

            out_stats->released++;
        }
    }

    /* Phase 4: Update stored commit_oid for each repaired profile. */
    hashmap_iter_t stale_iter;
    hashmap_iter_init(&stale_iter, stale_profiles);

    const char *stale_name;
    while (hashmap_iter_next(&stale_iter, &stale_name, NULL)) {
        err = manifest_persist_profile_head(repo, state, stale_name);
        if (err) goto cleanup;
    }

    /* Phase 4: Sync tracked directories to reflect current Git state.
     *
     * External Git changes may have added/removed directories in metadata.
     * Re-syncing ensures the tracked_directories table is consistent. */
    err = manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    if (err) {
        err = error_wrap(err, "Failed to sync directories after stale repair");
        goto cleanup;
    }

cleanup:
    /* The view's spine + strings and all_entries are arena-backed; the
     * caller's arena (typically ctx->arena) reclaims them at command end.
     * Only the heap-allocated hashmaps need explicit free. */
    if (stale_profiles) hashmap_free(stale_profiles, NULL);
    if (profile_scope) hashmap_free(profile_scope, NULL);
    if (fresh && fresh->index) hashmap_free(fresh->index, NULL);

    return err;
}

/**
 * Reconcile virtual_manifest to the current enabled-profile scope
 *
 * The enabled set is read from state; the caller is responsible for
 * making enabled_profiles authoritative before the call (see header
 * docstring for the ordering rule).
 *
 * Algorithm:
 *   1. Build fresh precedence view from state-authoritative scope.
 *      precedence_view_build attributes per-profile metadata to each row
 *      during the tree walk; manifest_project_row then writes the row's
 *      already-attributed mode/owner/group/encrypted directly to the DB.
 *   2. Snapshot current virtual_manifest (arena-backed, used by step 3).
 *   3. UPSERT every entry in the new manifest. The SQL UPSERT preserves
 *      the deployment anchor on UPDATE, auto-captures old_profile when
 *      the profile column changes, and unconditionally writes
 *      state=STATE_ACTIVE (which reactivates any STATE_INACTIVE row
 *      whose path re-entered scope).
 *   4. Orphan pass. For every pre-reconcile row:
 *        - In new manifest: owner-change stats only (row already updated).
 *        - Not in new manifest: STATE_ACTIVE → STATE_INACTIVE.
 *          STATE_INACTIVE / STATE_DELETED / STATE_RELEASED preserved.
 *   5. Rebuild tracked_directories (mark-ACTIVE-inactive then reactivate).
 */
error_t *manifest_apply_scope(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);

    /* Parallel-NULL contract: either both stats arguments are NULL
     * (caller doesn't want stats) or both are non-NULL (caller owns a
     * zero-fillable array of length stats_filter->count). Mixing is a
     * caller bug; fail loudly rather than writing into unallocated
     * memory or silently skipping requested stats. */
    if ((stats_filter == NULL) != (out_stats == NULL)) {
        return ERROR(
            ERR_INVALID_ARG,
            "manifest_apply_scope: stats_filter and out_stats must both be "
            "NULL or both non-NULL"
        );
    }

    error_t *err = NULL;
    string_array_t *enabled = NULL;
    precedence_view_t *new_view = NULL;
    state_file_entry_t *old_entries = NULL;
    size_t old_count = 0;
    hashmap_t *stats_map = NULL;

    /* Step 1: Read the authoritative scope from state.
     *
     * Precondition: the caller has already updated enabled_profiles
     * to reflect the target set AND populated commit_oid for any
     * newly-introduced profiles (via manifest_persist_profile_head).
     * apply_scope does not walk branch HEADs — it trusts the table. */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to read enabled profiles for scope reconcile");
        goto cleanup;
    }

    /* Step 2: Build fresh precedence view.
     *
     * precedence_view_build consults the mount table only for profiles in
     * the passed list — disabled profiles are never considered, so the
     * ordering rule ("update state first, then reconcile") is enforced
     * by the oracle's own read scope. */
    err = precedence_view_build(repo, enabled, mounts, arena, &new_view);
    if (err) {
        err = error_wrap(err, "Failed to build precedence view for scope reconcile");
        goto cleanup;
    }

    /* Step 3: Snapshot the current virtual_manifest rows (all states).
     *
     * Captured BEFORE step 4's UPSERTs so the orphan pass sees pre-
     * reconcile state — "was this path previously managed?" is a
     * function of the snapshot, not of the in-flight UPDATE that step
     * 4 may have just committed. Arena-allocated: no explicit free. */
    err = state_get_all_files(state, arena, &old_entries, &old_count);
    if (err) {
        err = error_wrap(err, "Failed to snapshot current manifest");
        goto cleanup;
    }

    /* Stats attribution index. Maps profile name → (array index + 1).
     * The +1 offset distinguishes "found at index 0" from "not found"
     * in hashmap_get (which returns NULL when a key is absent). Keys
     * are borrowed from stats_filter; the caller keeps it alive for
     * the duration of this call. */
    if (stats_filter) {
        size_t cap = stats_filter->count > 0 ? stats_filter->count * 2 : 16;
        stats_map = hashmap_borrow(cap);
        if (!stats_map) {
            err = ERROR(ERR_MEMORY, "Failed to create stats attribution map");
            goto cleanup;
        }
        for (size_t i = 0; i < stats_filter->count; i++) {
            const char *name = stats_filter->items[i];

            /* Duplicate profile names would silently collapse: hashmap_set
             * overwrites, so the later occurrence's slot would receive all
             * attribution and the earlier slot would stay zero-filled. Fail
             * loudly instead — this is a caller-side contract violation. */
            if (hashmap_has(stats_map, name)) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "manifest_apply_scope: duplicate profile '%s' in stats_filter",
                    name
                );
                goto cleanup;
            }

            memset(&out_stats[i], 0, sizeof(out_stats[i]));
            out_stats[i].profile = name;
            err = hashmap_set(stats_map, name, (void *) (uintptr_t) (i + 1));
            if (err) {
                err = error_wrap(err, "Failed to populate stats attribution map");
                goto cleanup;
            }
        }
    }

    /* Step 4: Sync every row in the new view.
     *
     * UPSERT semantics (see state.c::sql_insert):
     *   - New path: INSERT with state=ACTIVE, deployed_at=0, anchor unset.
     *   - Existing path: UPDATE VWD-cache columns (storage_path, profile,
     *     blob_oid, type, mode, owner, group, encrypted, state), preserve
     *     the deployment anchor (deployed_blob_oid, deployed_at, stat_*).
     *     The CASE on old_profile auto-captures the prior profile when
     *     the profile column changes, and preserves it otherwise.
     *   - state column overwritten with STATE_ACTIVE unconditionally,
     *     which reactivates STATE_INACTIVE rows whose path re-entered
     *     scope (typical on profile re-enable).
     *
     * Gain-side stats are attributed here: files_claimed counts every
     * row the filtered profile owns; lstat drives the user-visible
     * "already deployed vs needs deployment" fan-out. lstat is NOT a
     * confirmation event — the anchor remains unadvanced here. */
    for (size_t i = 0; i < new_view->count; i++) {
        state_file_entry_t *entry = &new_view->entries[i];

        if (stats_map) {
            void *p = hashmap_get(stats_map, entry->profile);
            if (p) {
                size_t idx = (size_t) (uintptr_t) p - 1;
                out_stats[idx].files_claimed++;

                struct stat st;
                if (lstat(entry->filesystem_path, &st) == 0) {
                    /* File present on disk; match vs profile blob is
                     * unverified — workspace divergence analysis
                     * (status/diff/apply) decides. */
                    out_stats[idx].files_present++;
                } else if (errno == ENOENT) {
                    out_stats[idx].files_missing++;
                } else {
                    /* Inaccessible (permission denied, I/O error, …).
                     * Degrade gracefully: the row is still managed,
                     * and the user sees the access error count. Count
                     * as absent so files_claimed stays the sum of the
                     * on-disk and absent fan-outs. */
                    out_stats[idx].files_missing++;
                    out_stats[idx].access_errors++;
                }
            }
        }

        err = manifest_project_row(repo, state, entry);
        if (err) {
            err = error_wrap(
                err, "Failed to sync '%s' during scope reconcile",
                entry->storage_path
            );
            goto cleanup;
        }
    }

    /* Step 5: Orphan pass over the pre-reconcile snapshot.
     *
     * A row whose filesystem_path is NOT in the new view's index
     * left scope entirely. Flip STATE_ACTIVE → STATE_INACTIVE; leave
     * STATE_INACTIVE (no-op), STATE_DELETED (staged for removal via
     * remove --delete-profile; downgrading would break the post-
     * deletion upgrade path in remove.c), and STATE_RELEASED (external
     * drift classification; downgrading would clobber it) untouched.
     *
     * A row still in the new view was already updated in step 4;
     * we only harvest loss-side stats here (reassignment between
     * precedence winners). */
    for (size_t i = 0; i < old_count; i++) {
        state_file_entry_t *old = &old_entries[i];

        void *idx_ptr = new_view->index
            ? hashmap_get(new_view->index, old->filesystem_path)
            : NULL;

        if (idx_ptr) {
            /* Still covered. If precedence shifted, attribute the loss
             * to the prior owner (for user-facing "A → B" messaging). */
            if (stats_map && old->profile) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                state_file_entry_t *new_entry = &new_view->entries[idx];
                if (strcmp(old->profile, new_entry->profile) != 0) {
                    void *p = hashmap_get(stats_map, old->profile);
                    if (p) {
                        size_t sidx = (size_t) (uintptr_t) p - 1;
                        out_stats[sidx].files_reassigned++;
                    }
                }
            }
            continue;
        }

        /* Not covered — orphan. Only downgrade ACTIVE rows. */
        if (old->state && strcmp(old->state, STATE_ACTIVE) == 0) {
            error_t *flip_err = state_set_file_state(
                state, old->filesystem_path, STATE_INACTIVE
            );
            if (flip_err) {
                /* Non-fatal: orphan detection at workspace-load time
                 * still catches it (STATE_ACTIVE + missing-from-Git
                 * surfaces a warning, and cleanup proceeds). Mirrors
                 * the policy in the primitives this one subsumes. */
                fprintf(
                    stderr, "warning: failed to mark '%s' inactive: %s\n",
                    old->filesystem_path, error_message(flip_err)
                );
                error_free(flip_err);
            }
        }

        if (stats_map && old->profile) {
            void *p = hashmap_get(stats_map, old->profile);
            if (p) {
                size_t sidx = (size_t) (uintptr_t) p - 1;
                out_stats[sidx].files_orphaned++;
            }
        }
    }

    /* Step 6: Rebuild tracked_directories from the new scope.
     *
     * manifest_sync_directories uses the mark-ACTIVE-as-INACTIVE then
     * reactivate pattern (see state_mark_all_directories_inactive —
     * narrowed in a prior commit to preserve STATE_DELETED/RELEASED).
     * Directory fallback and orphan semantics fall out of the rebuild:
     * directories still in any enabled profile's metadata are
     * reactivated with the new owner; directories that left scope
     * remain STATE_INACTIVE for apply-time cleanup.
     *
     * Reuses the mount table built above — directories share the same
     * profile→target resolution as files. */
    err = manifest_sync_directories(repo, state, arena, enabled, mounts);
    if (err) {
        err = error_wrap(err, "Failed to sync tracked directories");
        goto cleanup;
    }

cleanup:
    /* old_entries and the view's spine + strings are arena-backed; the
     * caller's arena (typically ctx->arena) reclaims them at command end.
     * Only the heap-allocated stats and index hashmaps need explicit free. */
    if (stats_map) hashmap_free(stats_map, NULL);
    if (new_view && new_view->index) hashmap_free(new_view->index, NULL);
    string_array_free(enabled);

    return err;
}

/**
 * Reconcile manifest with current Git state (public entry point)
 *
 * Self-contained drift repair: fetches enabled profiles, scopes a write
 * transaction when needed, delegates the repair algorithm to
 * manifest_repair_stale, and commits. Callers supply only the repo and
 * state — everything else is derived.
 */
error_t *manifest_reconcile(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    manifest_repair_stats_t *out_stats
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);

    string_array_t *profiles = NULL;
    error_t *err = state_get_profiles(state, &profiles);
    if (err) {
        return error_wrap(err, "Failed to fetch enabled profiles for reconcile");
    }

    /* Normalize outputs for every early-return path */
    if (out_stats) memset(out_stats, 0, sizeof(*out_stats));

    /* Empty enabled set — no scope to reconcile. Consistent with the
     * "disable last profile, then apply" workflow: nothing to sync. */
    if (!profiles || profiles->count == 0) {
        string_array_free(profiles);
        return NULL;
    }

    /* Scope a write transaction only when the caller doesn't already hold
     * one. Apply runs under dotta_ext_write; sync calls us after its own
     * state_begin. Workspace (from status/diff/update) holds no transaction
     * and needs the scoped one. */
    bool needs_tx = !state_locked(state);
    if (needs_tx) {
        err = state_begin(state);
        if (err) {
            string_array_free(profiles);
            return error_wrap(err, "Failed to begin reconcile transaction");
        }
    }

    /* manifest_repair_stale requires a non-NULL out_stats; route to a local
     * sink when the caller doesn't care so the internal contract stays hidden. */
    manifest_repair_stats_t local_stats;
    manifest_repair_stats_t *stats_target = out_stats ? out_stats : &local_stats;

    err = manifest_repair_stale(repo, state, arena, mounts, profiles, stats_target);

    if (needs_tx) {
        if (err) {
            state_rollback(state);
        } else {
            error_t *commit_err = state_commit(state);
            if (commit_err) {
                err = error_wrap(commit_err, "Failed to commit reconcile transaction");
            }
        }
    }

    string_array_free(profiles);
    return err;
}

/**
 * Remove files from manifest (remove command)
 *
 * Called after remove command deletes files from a profile branch.
 * Handles fallback to lower-precedence profiles or marks for removal.
 *
 * Algorithm:
 *   1. Build fresh precedence view from enabled profiles
 *   2. Build profile→oid map for commit_oid field
 *   3. For each removed file:
 *      a. Resolve to filesystem path
 *      b. Lookup current state entry
 *      c. Check if removed profile owns it (precedence check)
 *      d. If yes:
 *         - Check fresh precedence view for fallback
 *         - Fallback exists: Update to fallback profile (deployed_at preserved)
 *         - No fallback: Entry remains for orphan detection (apply removes)
 *      e. If no (different profile owns): Skip
 *
 * Preconditions:
 *   - state MUST have active transaction
 *   - Git commit MUST be completed (files removed from branch)
 *   - removed_storage_paths MUST be in storage format (home/.bashrc)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Files with fallback updated to fallback profile (deployed_at preserved)
 *   - Files without fallback: entries remain for orphan detection (apply removes)
 *   - Files not owned by removed_profile unchanged
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT: Git operation failed
 *   - ERR_STATE: Database operation failed
 *   - ERR_NOMEM: Memory allocation failed
 *
 * Performance: O(M + N) where M = total files in profiles, N = files removed
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    const string_array_t *enabled_profiles,
    string_array_t *out_marked,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(removed_profile);
    CHECK_NULL(removed_storage_paths);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;
    precedence_view_t *fresh = NULL;
    size_t removed_count = 0;
    size_t fallback_count = 0;

    /* 1. Build fresh precedence view from current Git state (post-removal).
     *
     * The precedence builder attributes per-profile metadata to each row
     * during the tree walk, so any fallback selected from this view
     * already carries the correct mode/owner/group/encrypted for its
     * source profile. */
    err = precedence_view_build(repo, enabled_profiles, mounts, arena, &fresh);
    if (err) {
        return error_wrap(
            err, "Failed to build precedence view for fallback detection"
        );
    }

    /* 2. Process each removed file. */
    for (size_t i = 0; i < removed_storage_paths->count; i++) {
        const char *storage_path = removed_storage_paths->items[i];

        /* Resolve to filesystem path against the mount table. UNBOUND
         * means removed_profile has no target binding for a custom/ path
         * — the file could never have been deployed on this machine, so
         * there is nothing to reassign or release. Skip. */
        mount_resolve_outcome_t outcome;
        const char *filesystem_path = NULL;
        err = mount_resolve(
            mounts, removed_profile, storage_path, arena, &outcome, &filesystem_path
        );
        if (err) {
            err = error_wrap(
                err, "Failed to resolve path: %s", storage_path
            );
            goto cleanup;
        }
        if (outcome == MOUNT_RESOLVE_UNBOUND) continue;

        /* Lookup current manifest entry */
        state_file_entry_t *current_entry = NULL;
        error_t *get_err = state_get_file(state, filesystem_path, &current_entry);

        if (get_err || !current_entry) {
            /* Not in manifest (profile was disabled or file never deployed) */
            if (get_err) {
                error_free(get_err);
            }
            continue;
        }

        /* Check ownership: does removed_profile own this file? */
        if (strcmp(current_entry->profile, removed_profile) != 0) {
            /* Different profile owns it, skip */
            state_free_entry(current_entry);
            continue;
        }

        /* removed_profile owns it, need to update */

        /* Check for fallback in the fresh view using O(1) index lookup */
        state_file_entry_t *fallback = NULL;
        if (fresh && fresh->index) {
            void *idx_ptr = hashmap_get(fresh->index, filesystem_path);
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fallback = &fresh->entries[idx];
            }
        }

        if (fallback) {
            /* Fallback found — sync complete entry from fallback profile.
             * deployed_at preserved by SQL UPSERT, old_profile auto-captured
             * by SQL when the owning profile changes. */
            err = manifest_project_row(repo, state, fallback);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync fallback for %s", filesystem_path
                );
                state_free_entry(current_entry);
                goto cleanup;
            }

            /* Track profile reassignment (old_profile metadata) */
            fallback_count++;
        } else {
            /* No fallback - mark as deleted (controlled deletion)
             *
             * Entry marked STATE_DELETED (controlled deletion via remove command)
             * and remains in state for orphan detection.
             *
             * STATE_DELETED bypasses branch existence checks in safety module,
             * since user intent is unambiguous (explicit remove command).
             *
             * The orphan cleanup flow:
             *   1. Entry marked deleted (this function)
             *   2. Workspace skips removal-pending entries (no Git validation)
             *   3. Workspace orphan detection loads entries → marks as ORPHANED
             *   4. Apply removes (filesystem + state cleanup)
             *
             * Cleanup deferred to apply - DO NOT call state_remove_file() here.
             */

            /* Mark entry as deleted for controlled deletion */
            err = state_set_file_state(state, filesystem_path, STATE_DELETED);
            if (err) {
                /* Non-fatal: log warning but continue */
                fprintf(
                    stderr, "warning: failed to mark '%s' as deleted: %s\n",
                    filesystem_path, error_message(err)
                );
                error_free(err);
                err = NULL;  /* Clear error, continue operation */
            } else if (out_marked) {
                /* Record the precise path so callers releasing management
                 * immediately can scope state_remove_file to paths just
                 * touched, not every STATE_DELETED row for the profile. */
                error_t *push_err = string_array_push(out_marked, filesystem_path);
                if (push_err) {
                    /* Non-fatal: row is marked, just absent from the
                     * caller's release list. The caller skips it; the
                     * row stays STATE_DELETED for apply to clean up. */
                    error_free(push_err);
                }
            }

            removed_count++;
        }

        state_free_entry(current_entry);
    }

    /* Set output counts */
    if (out_removed) *out_removed = removed_count;
    if (out_fallbacks) *out_fallbacks = fallback_count;

    /* After removing files, the profile's branch HEAD has moved to a new commit.
     * Update the per-profile commit_oid in enabled_profiles. */
    err = manifest_persist_profile_head(repo, state, removed_profile);
    if (err) goto cleanup;

    /* 3. Sync tracked directories */
    err = manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    if (err) {
        goto cleanup;
    }

cleanup:
    /* The view's spine + strings are arena-backed; the caller's arena
     * (typically ctx->arena) reclaims them at command end. Only the
     * heap-allocated index hashmap needs explicit free. */
    if (fresh && fresh->index) hashmap_free(fresh->index, NULL);

    return err;
}

/**
 * Sync multiple files to manifest in bulk (optimized for update command)
 *
 * High-performance batch operation that builds a fresh precedence view
 * from Git (post-commit state) instead of using the stale workspace cache.
 * Designed for the update command's workflow where many files are synced
 * at once after Git commits.
 *
 * CRITICAL DESIGN DECISION: This function builds a fresh precedence view
 * from Git because the workspace's cached row snapshot is stale after
 * commits. Using the stale cache would cause fallback to expensive
 * single-file operations for newly added files, resulting in O(N×M)
 * complexity instead of O(M+N).
 *
 * Algorithm:
 *   1. Load enabled profiles from Git
 *   2. Build FRESH precedence view (O(M))
 *   3. Use the view's index for O(1) lookups
 *   4. Build profile→oid map for commit_oid field
 *   5. For each item (O(N)):
 *      - If DELETED: check fresh view for fallback
 *        → Fallback exists: update to fallback profile
 *        → No fallback: entry remains for orphan detection (apply removes)
 *      - Else (modified/new): lookup in fresh precedence view
 *        → Found + precedence matches: sync to state (deployed_at set based on lstat())
 *        → Not found: file filtered/excluded (skip gracefully)
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - Git commits MUST be completed (branches at final state)
 *   - items MUST be FILE kind only (no directories)
 *   - enabled_profiles MUST be current enabled set
 *
 * Postconditions:
 *   - Modified/new files synced with deployed_at set based on lstat()
 *   - Deleted files fallback or entries remain for orphan detection
 *   - Transaction remains open (caller commits)
 *
 * Performance: O(M + N) where M = total files in profiles, N = items to sync
 */
error_t *manifest_update_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const workspace_item_t **items,
    size_t item_count,
    const string_array_t *enabled_profiles,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(items);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_synced);
    CHECK_NULL(out_removed);
    CHECK_NULL(out_fallbacks);

    /* Initialize outputs */
    *out_synced = 0;
    *out_removed = 0;
    *out_fallbacks = 0;

    error_t *err = NULL;
    precedence_view_t *fresh = NULL;

    if (item_count == 0) {
        /* No file items to process, but still sync directories.
         * Handles cases where only directory metadata changed. */
        return manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    }

    /* 1. Build FRESH precedence view from Git (post-commit state).
     *
     * The precedence builder attributes per-profile metadata onto each
     * row, so the sync loop below feeds manifest_project_row rows
     * that already carry the correct mode/owner/group/encrypted for
     * their source profile. */
    err = precedence_view_build(repo, enabled_profiles, mounts, arena, &fresh);
    if (err) {
        return error_wrap(err, "Failed to build fresh precedence view for bulk sync");
    }

    /* 2. Process each item */
    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Skip directories (not in manifest table) */
        if (item->item_kind != WORKSPACE_ITEM_FILE) {
            continue;
        }

        if (item->state == WORKSPACE_STATE_DELETED) {
            /* Handle deleted file - check for fallback in the fresh view */
            void *idx_ptr = hashmap_get(fresh->index, item->filesystem_path);
            state_file_entry_t *fallback = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                fallback = &fresh->entries[idx];
            }

            if (fallback) {
                /* Fallback found — update manifest to the fallback profile.
                 * deployed_at preserved by SQL UPSERT, old_profile auto-captured
                 * by SQL when the owning profile changes. */
                err = manifest_project_row(repo, state, fallback);
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'",
                        item->filesystem_path
                    );
                    goto cleanup;
                }

                (*out_fallbacks)++;
            } else {
                /* No fallback — decide the terminal row state from disk
                 * reality:
                 *
                 *   absent  → purge (apply has no filesystem work to do)
                 *   present → STATE_DELETED (apply removes via safety
                 *             PHASE 1 bypass, sidestepping the PHASE 4
                 *             tree check that would otherwise misroute
                 *             this internal deletion through the
                 *             external-loss RELEASED pathway).
                 *
                 * WORKSPACE_STATE_DELETED classifies the path as absent at
                 * workspace-load time, so the purge branch is the normal
                 * outcome. The stat runs again inside the transaction to
                 * catch the narrow race where the user recreates the file
                 * between workspace load and commit — that path then
                 * falls through to STATE_DELETED and apply re-evaluates
                 * with divergence routing instead of silently dropping
                 * the row.
                 *
                 * ERR_NOT_FOUND from state_remove_file means the row
                 * already vanished (e.g. a concurrent reconcile released
                 * it). The desired end state is reached — swallow.
                 *
                 * All other failures are non-fatal: the Git commit
                 * already succeeded; the next status self-heals via
                 * manifest_reconcile. */
                struct stat st;
                error_t *rm_err;
                if (lstat(item->filesystem_path, &st) != 0 && errno == ENOENT) {
                    rm_err = state_remove_file(state, item->filesystem_path);
                    if (rm_err && error_code(rm_err) == ERR_NOT_FOUND) {
                        error_free(rm_err);
                        rm_err = NULL;
                    }
                } else {
                    rm_err = state_set_file_state(
                        state, item->filesystem_path, STATE_DELETED
                    );
                }
                if (rm_err) {
                    /* Non-fatal: Git commit already succeeded; the next
                     * status will self-heal via manifest_reconcile. */
                    fprintf(
                        stderr, "warning: failed to finalize deletion of '%s': %s\n",
                        item->filesystem_path, error_message(rm_err)
                    );
                    error_free(rm_err);
                }

                (*out_removed)++;
            }
        } else {
            /* Handle modified/new file */
            void *idx_ptr = hashmap_get(fresh->index, item->filesystem_path);
            state_file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                entry = &fresh->entries[idx];
            }

            if (!entry) {
                /* File not in fresh view - filtered/excluded
                 * This is expected behavior (e.g., .dottaignore) - skip gracefully */
                continue;
            }

            /* Check precedence matches */
            if (entry->profile && strcmp(entry->profile, item->profile) != 0) {
                /* Different profile won precedence - skip this file
                 * (higher precedence profile will handle it) */
                continue;
            }

            /* CAPTURE: write VWD cache and advance the anchor with a
             * fresh disk witness. update commits the user's claim of
             * ownership over the just-committed blob, so the anchor stamp
             * is bound to the entry's blob_oid and deployed_at = time(NULL).
             * Skipped (lower-precedence) rows correctly bypass this — only
             * the winning profile's anchor advances, never poisoned with a
             * disk stat that doesn't correspond to its blob_oid. */
            err = manifest_capture_row(repo, state, entry);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync '%s' to manifest", item->filesystem_path
                );
                goto cleanup;
            }

            (*out_synced)++;
        }
    }

    /* 4. After updating files, synchronize commit_oid for ALL files from affected profiles.
     * Each profile that had files updated has a new HEAD commit.
     * Build set of unique profile names from items and sync each. */
    string_array_t *updated_profiles = string_array_new(0);
    if (!updated_profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate updated_profiles array");
        goto cleanup;
    }

    for (size_t i = 0; i < item_count; i++) {
        const char *prof = items[i]->profile;

        /* Check if already processed */
        bool found = false;
        for (size_t j = 0; j < updated_profiles->count; j++) {
            if (strcmp(updated_profiles->items[j], prof) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            err = string_array_push(updated_profiles, prof);
            if (err) {
                string_array_free(updated_profiles);
                goto cleanup;
            }
        }
    }

    /* 5. Set stored commit_oid for each profile whose HEAD moved */
    for (size_t i = 0; i < updated_profiles->count; i++) {
        err = manifest_persist_profile_head(repo, state, updated_profiles->items[i]);
        if (err) {
            string_array_free(updated_profiles);
            goto cleanup;
        }
    }

    string_array_free(updated_profiles);

    /* 6. Sync tracked directories */
    err = manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    if (err) {
        goto cleanup;
    }

cleanup:
    /* The view's spine + strings are arena-backed; the caller's arena
     * (typically ctx->arena) reclaims them at command end. Only the
     * heap-allocated index hashmap needs explicit free. */
    if (fresh && fresh->index) hashmap_free(fresh->index, NULL);

    return err;
}

/**
 * Sync multiple files to manifest in bulk - simplified for add command
 *
 * Optimized bulk operation for adding newly-committed files to manifest.
 * Simpler than manifest_update_files() because:
 * - All files are from the same profile
 * - No deletions (only additions/updates)
 * - Files marked with deployed_at = time(NULL) (captured from filesystem)
 *
 * CRITICAL DESIGN: Like manifest_update_files(), this builds a FRESH
 * manifest from Git (post-commit state). This ensures all newly-added files
 * are found during precedence checks, avoiding O(N×M) fallback to
 * manifest_sync_file().
 *
 * Algorithm:
 *   1. Load enabled profiles from Git (current HEAD, post-commit)
 *   2. Build fresh precedence view (ONCE)
 *   3. Use the view's index for O(1) precedence lookups
 *   4. Build profile→oid map for commit_oid field
 *   5. For each file:
 *      - Convert filesystem_path → storage_path
 *      - Lookup in fresh view
 *      - If precedence matches: sync to state with deployed_at = time(NULL)
 *      - If lower precedence or filtered: skip silently
 *   6. All operations within caller's transaction
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - Git commits MUST be completed (branches at final state)
 *   - filesystem_paths MUST be valid, canonical paths
 *   - profile SHOULD be enabled (function gracefully handles if not)
 *
 * Postconditions:
 *   - Files synced to manifest with deployed_at = time(NULL)
 *   - Lower-precedence files skipped (not an error)
 *   - Filtered files skipped (not an error)
 *   - Transaction remains open (caller commits via state_save)
 *
 * Performance:
 *   - O(M + N) where M = total files in all profiles, N = files to add
 *   - Single fresh precedence-view build from Git
 *   - Batch-optimized state operations
 *
 * Error Handling:
 *   - Transactional: on error, entire batch fails
 *   - Returns error on first failure (fail-fast)
 *   - Path resolution errors are fatal
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *profile,
    const string_array_t *filesystem_paths,
    const string_array_t *enabled_profiles,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(out_synced);

    /* Initialize output */
    *out_synced = 0;

    error_t *err = NULL;
    precedence_view_t *fresh = NULL;

    if (filesystem_paths->count == 0) {
        /* No files to add, but still sync directories.
         * Handles directory-only adds where filesystem_paths
         * is empty but metadata.json has tracked directories. */
        return manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    }

    /* 1. Build FRESH precedence view from Git (post-commit state).
     *
     * The precedence builder attributes per-profile metadata to each
     * row, so manifest_project_row below writes the correct
     * mode/owner/group/encrypted for the profile that won precedence
     * (the only attribution that matters for the row being inserted). */
    err = precedence_view_build(repo, enabled_profiles, mounts, arena, &fresh);
    if (err) {
        return error_wrap(err, "Failed to build fresh precedence view for bulk sync");
    }

    /* 2. Process each file */
    for (size_t i = 0; i < filesystem_paths->count; i++) {
        const char *filesystem_path = filesystem_paths->items[i];

        /* Lookup in fresh view using filesystem_path */
        void *idx_ptr = hashmap_get(fresh->index, filesystem_path);
        state_file_entry_t *entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
            entry = &fresh->entries[idx];
        }

        if (!entry) {
            /* File not in fresh view - filtered/excluded
             * This is expected behavior (e.g., .dottaignore, README.md) - skip gracefully */
            continue;
        }

        /* Defensive: Verify entry has profile name (should never be NULL) */
        if (!entry->profile) {
            /* Should never happen - indicates data corruption or manifest bug */
            err = ERROR(
                ERR_INTERNAL, "Manifest entry '%s' has NULL profile",
                filesystem_path
            );
            goto cleanup;
        }

        /* Check precedence matches */
        if (strcmp(entry->profile, profile) != 0) {
            /* Different profile won precedence - skip this file
             * (higher precedence profile owns it) */
            continue;
        }

        /* CAPTURE: write VWD cache and advance the anchor with a fresh
         * disk witness. add commits the user's claim of ownership over
         * the just-committed blob, so the anchor stamp is bound to the
         * entry's blob_oid and deployed_at = time(NULL). Skipped (lower-
         * precedence) rows correctly bypass this — only the winning
         * profile's anchor advances, never poisoned with a disk stat that
         * doesn't correspond to its blob_oid. */
        err = manifest_capture_row(repo, state, entry);
        if (err) {
            err = error_wrap(
                err, "Failed to sync '%s' to manifest", filesystem_path
            );
            goto cleanup;
        }

        (*out_synced)++;
    }

    /* After adding files, the profile's branch HEAD has moved to a new commit.
     * Update the per-profile commit_oid in enabled_profiles. */
    err = manifest_persist_profile_head(repo, state, profile);
    if (err) goto cleanup;

    /* 4. Sync tracked directories */
    err = manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    if (err) {
        goto cleanup;
    }

cleanup:
    /* The view's spine + strings are arena-backed; the caller's arena
     * (typically ctx->arena) reclaims them at command end. Only the
     * heap-allocated index hashmap needs explicit free. */
    if (fresh && fresh->index) hashmap_free(fresh->index, NULL);

    return err;
}

/**
 * Sync manifest from Git diff (bulk operation)
 *
 * Updates manifest table based on changes between old_oid and new_oid for a
 * single profile. Uses O(M+D) bulk pattern.
 *
 * This is the core function for updating the manifest after sync operations
 * (pull, rebase, merge). It efficiently processes an entire Git diff by:
 *   1. Building the fresh precedence view from Git ONCE (O(M))
 *   2. Using the view's index for O(1) lookups
 *   3. Processing each delta with fast lookups (O(D))
 *
 * Algorithm:
 *   Phase 1: Build Context
 *     - Load all enabled profiles
 *     - Build fresh precedence view from current Git state (post-sync);
 *       precedence_view_build attributes per-profile metadata to each row
 *       during the tree walk
 *     - The view's index serves O(1) file lookups in the delta loop
 *
 *   Phase 2: Compute Diff
 *     - Lookup old and new trees
 *     - Generate Git diff between them
 *
 *   Phase 3: Process Deltas
 *     - For additions/modifications: sync (deployed_at preserved if exists, else set based on lstat())
 *     - For deletions: check for fallbacks, entries remain for orphan detection if none
 *     - Handle precedence: only sync if profile won the file
 *
 * Transaction: Caller must open transaction (state_open) and commit
 *              (state_save) after calling. This function works within an active
 *              transaction.
 *
 * Convergence: Sync updates VWD expected state (commit_oid, blob_oid) but doesn't
 * Semantics    deploy to filesystem. User must run 'dotta apply' which uses runtime
 *              divergence analysis to deploy changes.
 */
error_t *manifest_sync_diff(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *profile,
    const git_oid *old_oid,
    const git_oid *new_oid,
    const string_array_t *enabled_profiles,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks,
    size_t *out_skipped
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(old_oid);
    CHECK_NULL(new_oid);
    CHECK_NULL(enabled_profiles);

    error_t *err = NULL;

    /* Resources to clean up */
    precedence_view_t *fresh = NULL;
    git_tree *old_tree = NULL;
    git_tree *new_tree = NULL;
    git_diff *diff = NULL;

    size_t synced = 0, removed = 0, fallbacks = 0, skipped = 0;

    /* PHASE 1: BUILD CONTEXT (O(M)) */
    /* 1.1. Build fresh precedence view from Git (post-sync state).
     *
     * The precedence builder attributes per-profile metadata to each
     * row, so the delta loop below feeds manifest_project_row rows
     * that already carry the correct mode/owner/group/encrypted for
     * their source profile — fallbacks pick up the right metadata for
     * the *fallback* profile, not the deleting one. */
    err = precedence_view_build(repo, enabled_profiles, mounts, arena, &fresh);
    if (err) {
        err = error_wrap(err, "Failed to build fresh precedence view");
        goto cleanup;
    }

    /* PHASE 2: COMPUTE DIFF (O(D)) */
    /* 2.1. Extract trees from old and new commits for diff */
    err = gitops_get_tree_from_commit(repo, old_oid, &old_tree);
    if (err) {
        err = error_wrap(err, "Failed to get tree from old commit");
        goto cleanup;
    }

    err = gitops_get_tree_from_commit(repo, new_oid, &new_tree);
    if (err) {
        err = error_wrap(err, "Failed to get tree from new commit");
        goto cleanup;
    }

    /* 2.2. Compute diff between old and new trees */
    err = gitops_diff_trees(repo, old_tree, new_tree, NULL, &diff);
    if (err) {
        err = error_wrap(err, "Failed to diff trees");
        goto cleanup;
    }

    size_t num_deltas = git_diff_num_deltas(diff);

    /* PHASE 3: PROCESS DELTAS (O(D)) */
    for (size_t i = 0; i < num_deltas; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta) {
            continue;
        }

        /* Determine storage path based on delta type */
        const char *storage_path = delta->new_file.path;
        if (delta->status == GIT_DELTA_DELETED) {
            storage_path = delta->old_file.path;
        }

        /* Resolve filesystem path against the mount table. Two distinct
         * outcomes route differently:
         *
         *   MOUNT_RESOLVE_UNBOUND — custom/ entry but `profile` has
         *                   no target binding. Counted as skipped so
         *                   the caller can surface "deferred until
         *                   --target is set" in the user-visible report.
         *   err != NULL   — malformed storage path (ERR_INTERNAL from
         *                   mount_decode_label) or allocation failure.
         *                   Skip silently — the Git commit already
         *                   advanced the branch, the next reconcile
         *                   will revisit. */
        mount_resolve_outcome_t outcome;
        const char *filesystem_path = NULL;
        err = mount_resolve(
            mounts, profile, storage_path, arena, &outcome, &filesystem_path
        );
        if (err) {
            error_free(err);
            err = NULL;
            continue;
        }
        if (outcome == MOUNT_RESOLVE_UNBOUND) {
            skipped++;
            continue;
        }

        /* Handle based on delta type */
        if (delta->status == GIT_DELTA_ADDED || delta->status == GIT_DELTA_MODIFIED) {
            /* ADDITION / MODIFICATION */

            /* Lookup in fresh view (O(1)) */
            void *idx_ptr = hashmap_get(fresh->index, filesystem_path);
            state_file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                entry = &fresh->entries[idx];
            }

            if (!entry) {
                /* File not in fresh view (filtered by .dottaignore or other rules)
                 * This is expected behavior - skip gracefully */
                continue;
            }

            /* Check precedence: does the synced profile win?
             *
             * This is critical: if a different profile won precedence for this file,
             * we should NOT update the manifest entry. The winning profile will handle
             * it when its changes are synced. */
            if (entry->profile && strcmp(entry->profile, profile) != 0) {
                /* Different profile won precedence - skip this file */
                continue;
            }

            /* Sync entry to state. deployed_at is preserved by SQL UPSERT on
             * UPDATE; 0 is used for INSERT (new file, never deployed). old_profile
             * auto-captured by SQL when the owning profile changes. */
            err = manifest_project_row(repo, state, entry);
            if (err) {
                err = error_wrap(
                    err, "Failed to sync '%s' to manifest", filesystem_path
                );
                goto cleanup;
            }

            synced++;

        } else if (delta->status == GIT_DELTA_DELETED) {
            /* DELETION */

            /* Check if file exists in the fresh view from OTHER profiles
             * (fallback check)
             *
             * When a file is deleted from one profile, it might still exist in another
             * lower-precedence profile. If so, that profile now "wins" and we should
             * update the manifest to point to it. */
            void *idx_ptr = hashmap_get(fresh->index, filesystem_path);
            state_file_entry_t *entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t) (uintptr_t) idx_ptr - 1;
                entry = &fresh->entries[idx];
            }

            if (entry && entry->profile && strcmp(entry->profile, profile) != 0) {
                /* Fallback found — update manifest to the new profile owner.
                 * deployed_at preserved by SQL UPSERT, old_profile auto-captured
                 * by SQL when the owning profile changes. */
                err = manifest_project_row(repo, state, entry);
                if (err) {
                    err = error_wrap(
                        err, "Failed to sync fallback for '%s'", filesystem_path
                    );
                    goto cleanup;
                }

                /* Track profile reassignment for user visibility */
                fallbacks++;

            } else {
                /* No fallback exists - check if we own this file in current state */

                state_file_entry_t *state_entry = NULL;
                err = state_get_file(state, filesystem_path, &state_entry);

                if (err) {
                    if (err->code == ERR_NOT_FOUND) {
                        /* File not in state (never deployed) - nothing to do */
                        error_free(err);
                        err = NULL;
                        continue;
                    }
                    /* Fatal state error - propagate */
                    goto cleanup;
                }

                /* Check if this profile owns this file */
                if (strcmp(state_entry->profile, profile) == 0) {
                    /* We own the path and no enabled profile provides a
                     * fallback. Decide the terminal row state from disk
                     * reality:
                     *
                     *   absent  → purge (apply has nothing to clean up)
                     *   present → STATE_DELETED (apply removes via safety
                     *             PHASE 1 bypass, sidestepping the PHASE 4
                     *             tree check that would otherwise misroute
                     *             this internal deletion through the
                     *             external-loss RELEASED pathway).
                     *
                     * ERR_NOT_FOUND from state_remove_file means the row
                     * already vanished (e.g. a concurrent reconcile
                     * released it). The desired end state is reached —
                     * swallow.
                     *
                     * All other failures are non-fatal: the Git commit is
                     * already applied to the local branch, and
                     * manifest_reconcile will re-examine the row on the
                     * next status. */
                    struct stat st;
                    if (lstat(filesystem_path, &st) != 0 && errno == ENOENT) {
                        err = state_remove_file(state, filesystem_path);
                        if (err && error_code(err) == ERR_NOT_FOUND) {
                            error_free(err);
                            err = NULL;
                        }
                    } else {
                        err = state_set_file_state(
                            state, filesystem_path, STATE_DELETED
                        );
                    }
                    if (err) {
                        /* Non-fatal: log warning but continue */
                        fprintf(
                            stderr, "warning: failed to finalize deletion of '%s': %s\n",
                            filesystem_path, error_message(err)
                        );
                        error_free(err);
                        err = NULL;  /* Clear error, continue operation */
                    }

                    removed++;
                }

                state_free_entry(state_entry);
            }
        }
    }

    /* Set output counters */
    if (out_synced) *out_synced = synced;
    if (out_removed) *out_removed = removed;
    if (out_fallbacks) *out_fallbacks = fallbacks;
    if (out_skipped) *out_skipped = skipped;

    /* Update the per-profile commit_oid in enabled_profiles to match the new HEAD.
     * Use new_oid directly — it's the explicit sync target passed by the caller,
     * and matches the branch HEAD that gitops_resolve_branch_head_oid would resolve. */
    err = state_set_profile_commit_oid(state, profile, new_oid);
    if (err) {
        err = error_wrap(
            err, "Failed to sync commit_oid for profile '%s'", profile
        );
        goto cleanup;
    }

    /* 4. Sync tracked directories */
    err = manifest_sync_directories(repo, state, arena, enabled_profiles, mounts);
    if (err) {
        goto cleanup;
    }

cleanup:
    /* Free resources in reverse order of acquisition. The view's spine +
     * strings are arena-backed; the caller's arena (typically ctx->arena)
     * reclaims them at command end. Only the heap-allocated index hashmap
     * needs explicit free. */
    if (diff) git_diff_free(diff);
    if (new_tree) git_tree_free(new_tree);
    if (old_tree) git_tree_free(old_tree);
    if (fresh && fresh->index) hashmap_free(fresh->index, NULL);

    return err;
}

/**
 * Sync tracked directories from enabled profiles
 *
 * Rebuilds the tracked_directories table from metadata.
 * Called after profile enable/disable/reorder to maintain directory tracking.
 *
 * Algorithm:
 *   1. Clear all tracked directories (idempotent start)
 *   2. For each enabled profile:
 *      a. Load metadata from Git (or skip if doesn't exist)
 *      b. Extract directories via metadata_get_items_by_kind()
 *      c. Add to state via state_add_directory() with profile attribution
 *   3. All within caller's active transaction
 *
 * Pattern: Rebuild (not incremental)
 *   - Directories have no lifecycle states to preserve
 *   - Clear + repopulate is simple, correct, and fast
 *   - Already idempotent via INSERT OR REPLACE
 *
 * Preconditions:
 *   - state MUST have active transaction (via state_open)
 *   - enabled_profiles MUST be the engine's iteration set (caller built
 *     `mounts` from the same list)
 *
 * Postconditions:
 *   - tracked_directories table reflects enabled_profiles
 *   - Transaction remains open (caller commits)
 *   - Missing metadata handled gracefully (not an error)
 *
 * Performance: O(D) where D = total directories across enabled profiles
 *              (typically < 50 even for large configs)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @param mounts Per-machine mount table covering enabled_profiles
 *              (must not be NULL)
 * @return Error or NULL on success
 */
error_t *manifest_sync_directories(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const string_array_t *enabled_profiles,
    const mount_table_t *mounts
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(enabled_profiles);
    CHECK_NULL(mounts);

    error_t *err = NULL;
    metadata_t *metadata = NULL;
    const metadata_item_t **directories = NULL;

    /* 1. Mark all directories as inactive (soft delete for orphan detection)
     *
     * This preserves directory entries for orphan detection instead of deleting them.
     * Directories not reactivated during rebuild become orphaned and are cleaned by apply.
     */
    err = state_mark_all_directories_inactive(state);
    if (err) {
        return error_wrap(err, "Failed to mark directories inactive");
    }

    /* 2. Rebuild from each enabled profile */
    for (size_t i = 0; i < enabled_profiles->count; i++) {
        const char *profile = enabled_profiles->items[i];

        /* Reset per-iteration state */
        metadata = NULL;
        directories = NULL;

        /* Load metadata (may not exist for old profiles - gracefully skip) */
        err = metadata_load_from_branch(repo, profile, &metadata);
        if (err) {
            if (err->code == ERR_NOT_FOUND) {
                /* No metadata file - old profile or no directories tracked */
                error_free(err);
                err = NULL;
                continue;
            }
            err = error_wrap(
                err, "Failed to load metadata for profile '%s'",
                profile
            );
            goto cleanup;
        }

        /* Extract directories from metadata */
        size_t dir_count = 0;
        directories =
            metadata_get_items_by_kind(metadata, METADATA_ITEM_DIRECTORY, &dir_count);

        /* Reactivate or add each directory to state
         *
         * ARCHITECTURE: Mark-inactive-then-reactivate pattern.
         *
         * For each directory in enabled profile metadata:
         *   - If exists in state → reactivate (STATE_ACTIVE) and update metadata
         *   - If not in state → add new entry with STATE_ACTIVE
         *
         * This preserves deployed_at timestamps and enables clean orphan detection.
         *
         * directory_entry_from_metadata sets *state_dir = NULL on the
         * custom/-without-binding case (silent skip); any other failure
         * propagates.
         */
        for (size_t j = 0; j < dir_count; j++) {
            state_directory_entry_t *state_dir = NULL;

            err = directory_entry_from_metadata(
                directories[j], profile, mounts, arena, &state_dir
            );

            if (err) {
                err = error_wrap(
                    err, "Failed to create state directory entry for '%s'",
                    directories[j]->key
                );
                break;
            }
            if (!state_dir) continue;  /* No binding for custom/ on this host. */

            /* Check if directory already exists in state (may be inactive) */
            state_directory_entry_t *existing = NULL;
            error_t *get_err = state_get_directory(state, state_dir->filesystem_path, &existing);

            if (get_err && get_err->code != ERR_NOT_FOUND) {
                /* Fatal error - failed to query state */
                if (existing) state_free_directory_entry(existing);
                err = error_wrap(get_err, "Failed to check directory state");
                break;
            }

            if (get_err && get_err->code == ERR_NOT_FOUND) {
                /* New directory. state_add_directory defaults state to STATE_ACTIVE
                 * when entry->state is NULL/empty, so we don't need to set it. */
                error_free(get_err);
                state_dir->state = arena_strdup(arena, STATE_ACTIVE);
                if (!state_dir->state) {
                    err = ERROR(ERR_MEMORY, "Failed to allocate state string");
                    break;
                }
                err = state_add_directory(state, state_dir);
            } else {
                /* Existing directory - reactivate and always update
                 *
                 * CRITICAL: Always call state_update_directory, not conditionally.
                 *
                 * Rationale:
                 * - profile field may have changed (directory moved between profiles)
                 * - storage_path may have changed (different profile conventions)
                 * - UPDATE is cheap (single row, indexed by filesystem_path)
                 * - Ensures state consistency regardless of metadata changes
                 * - deployed_at is preserved (stmt_update_entry excludes it)
                 */
                err = state_set_directory_state(state, state_dir->filesystem_path, STATE_ACTIVE);

                /* Always update profile, storage_path, and metadata (preserves deployed_at) */
                if (!err) {
                    err = state_update_directory(state, state_dir);
                }

                state_free_directory_entry(existing);
            }

            if (err) {
                err = error_wrap(
                    err, "Failed to add/update directory '%s' in state",
                    directories[j]->key
                );
                break;
            }
        }

        /* Free per-iteration resources (always, whether error or success) */
        free(directories);
        directories = NULL;
        metadata_free(metadata);
        metadata = NULL;

        if (err) goto cleanup;
    }

cleanup:
    /* Per-iteration resources are NULL on normal exit (freed in loop above).
     * Non-NULL only if outer loop exited before per-iteration cleanup (e.g.,
     * metadata_load_from_branch error before inner loop). state_directory
     * entries built into the borrowed arena live until the caller destroys
     * it (typically command end). */
    if (directories) free(directories);
    if (metadata) metadata_free(metadata);

    /* After rebuild, any directories still in STATE_INACTIVE are orphaned
     * (belonged to disabled profiles with no fallback).
     *
     * They will be detected by workspace orphan analysis and cleaned by apply.
     * This completes the mark-inactive-then-reactivate lifecycle.
     */

    return err;
}
