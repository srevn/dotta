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
 * layer, so the engine passes a row straight through to state_add_file
 * with no field translation.
 *
 * Spine growth uses arena_calloc + memcpy (abandon-and-realloc): the old
 * chunk is left to the arena (released at arena_destroy) and the hashmap's
 * (uintptr_t)(idx + 1) values stay valid because they encode indices, not
 * pointers.
 *
 * heads records, per profile passed to precedence_view_build and index-
 * aligned with that list, the peeled OID whose tree the rows came from —
 * captured by the same git_reference_peel that produced the tree, so the
 * view and the OID can never describe two different commits. A zero OID
 * means the branch did not resolve: nothing was projected for it.
 * precedence_view_load_tree leaves heads NULL (one tree, no branch).
 */
typedef struct precedence_view {
    state_file_entry_t *entries;   /* arena-backed, abandon-and-realloc growth */
    size_t count;
    size_t capacity;
    hashmap_t *index;              /* fs_path → idx+1, heap-allocated */
    git_oid *heads;                /* per build profile, arena-backed; NULL for load_tree */
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
 *          custom/ entries; a missing binding (MOUNT_RESOLVE_UNBOUND) is
 *          a hard error naming the profile and the repair command
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
     * MOUNT_RESOLVE_UNBOUND fires only when storage_path is custom/...
     * and ctx->profile has no target binding in mounts. Under the
     * tightened reorder-only contract on state_reorder_profiles plus
     * the custom-target preconditions enforced by every command that
     * can enable a profile (cmd profile enable, cmd add, cmd clone,
     * interactive save), this state is unreachable through documented
     * paths — a row in enabled_profiles is now guaranteed to carry a
     * target whenever its profile has custom/ files.
     *
     * Reaching UNBOUND here therefore means external DB tampering or a
     * code bug. Surface it as a hard error naming the profile and the
     * repair command instead of silently dropping the row (which used
     * to leave the user with a profile enabled in the DB whose files
     * never deploy). Genuine errors (malformed path, OOM) propagate
     * via the err branch above. */
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
        ctx->error = ERROR(
            ERR_STATE_INVALID,
            "Profile '%s' has files under custom/ but no deployment "
            "target binding.\nHint: Run 'dotta profile disable %s && "
            "dotta profile enable %s --target /path'",
            ctx->profile, ctx->profile, ctx->profile
        );
        return -1;
    }

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
         * lifecycle, old_profile, and anchor are mirrored from the new-entry
         * branch to keep the override path self-contained — any tree-built
         * row carries LIFECYCLE_ACTIVE, no reassignment marker, and a zero
         * deployment anchor regardless of construction order. */
        override->owner = NULL;
        override->group = NULL;
        override->encrypted = false;
        override->lifecycle = LIFECYCLE_ACTIVE;
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
        /* Tree-built rows always carry LIFECYCLE_ACTIVE. The enum's zero
         * default already covers this via memset above; the explicit
         * assignment documents intent and survives any future allocator
         * change that drops the calloc semantic. */
        new_entry->lifecycle = LIFECYCLE_ACTIVE;
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
 * the same list). A custom/ entry whose profile has no target binding is
 * a hard error from the callback (ERR_STATE_INVALID with a repair hint) —
 * every enabling command guarantees the binding, so reaching that branch
 * means corruption, not a machine that lacks a --target.
 *
 * A profile whose branch does not exist contributes no rows and leaves
 * its heads[] slot zero; the caller decides what that means for the rows
 * it used to own (manifest_apply_scope gives them its leftover lifecycle).
 * Only the existence question is tolerant: a branch that exists but
 * cannot be loaded (corrupt object, I/O) still fails the build, as does a
 * failed lookup — both stay retryable errors, never silent omissions.
 *
 * Memory:
 *   - view struct, spine, heads, and per-row strings: arena-allocated;
 *     the caller's arena reclaims them at arena_destroy.
 *   - index hashmap: heap-allocated; on success the caller takes ownership
 *     and must hashmap_free(view->index) when done. On error, the hashmap
 *     (if allocated) is freed here and *out is NULL.
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

    /* One slot per profile, zero by calloc — the "did not resolve"
     * sentinel needs no separate write. */
    view->heads = arena_calloc(arena, profiles->count, sizeof(*view->heads));
    if (!view->heads) {
        err = ERROR(ERR_MEMORY, "Failed to allocate precedence view heads");
        goto cleanup;
    }

    /* Process each profile in order (later profiles override earlier) */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Does the branch exist? Asked separately because the tree loader
         * maps a missing ref to ERR_GIT like every other failure, and
         * "gone" must not be confused with "broken": gone is an
         * observation the caller's leftover policy answers, broken is an
         * error that must propagate. */
        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) {
            err = error_wrap(
                err, "Failed to look up branch for profile '%s'", profile
            );
            goto cleanup;
        }
        if (!exists) continue;

        /* Load tree for this profile (scoped to iteration), capturing the
         * peeled OID it came from into the profile's heads[] slot. */
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile, &tree, &view->heads[i]);
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
 * custom/ entries; the callback treats a missing binding as a hard
 * error. Trees without custom/ entries can pass any mount table handle,
 * including one with no binding for `profile`.
 *
 * Memory: same contract as precedence_view_build (arena-backed view
 * + heap-backed index). heads stays NULL — a tree is not a branch.
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
 * Load a single Git tree's files into the public state_files_t carrier.
 *
 * The historical-diff path consumes a tree-built file slice that mirrors
 * the workspace's active slice (workspace_files) and apply's deploy result
 * (state_files_view). One carrier shape, three producers — a consumer
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
 * the tree contains custom/ entries; a missing binding is a hard error
 * from the build callback.
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
     * required. Mirrors workspace_files's identical bridge cast. */
    out->entries = (const state_file_entry_t *const *) ptrs;
    out->count = view->count;

    return NULL;
}

/**
 * Project a DIRECTORY metadata item to a state directory entry.
 *
 * Resolves filesystem_path via the mount table. UNBOUND is treated as a
 * hard error: under the tightened state_reorder_profiles contract plus
 * the custom-target preconditions enforced by every enabling command,
 * a custom/ directory cannot legitimately exist under a profile lacking
 * a target binding. The previous silent-skip masked corrupted state
 * (custom/ profile rows with NULL target) — we surface it instead with
 * a repair hint, matching the precedence-builder's symmetric treatment
 * for files.
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

    /* Defer entry allocation until after the mount lookup so the error
     * path performs no allocation. UNBOUND can only surface for a
     * custom/ key whose owning profile lacks a target on this host —
     * unreachable through documented paths, so treat it as corruption
     * with a repair hint instead of silently dropping the row. */
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
    if (outcome == MOUNT_RESOLVE_UNBOUND) {
        return ERROR(
            ERR_STATE_INVALID,
            "Profile '%s' has directory '%s' under custom/ but no "
            "deployment target binding.\nHint: Run 'dotta profile "
            "disable %s && dotta profile enable %s --target /path'",
            profile, item->key, profile, profile
        );
    }

    state_directory_entry_t *entry = arena_calloc(arena, 1, sizeof(*entry));
    if (!entry) {
        return ERROR(ERR_MEMORY, "Failed to allocate state directory entry");
    }

    /* filesystem_path is arena-borrowed via mount_resolve; the cast
     * accommodates the struct field's `char *` typing without implying
     * mutability. The borrow shares the arena lifetime of the strdup'd
     * siblings below.
     *
     * observed_at is left zero by calloc; the sync loop's probe stamps
     * it before persisting when the path exists on disk. */
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
 * Rebuild tracked directories from enabled profiles
 *
 * The directory-side counterpart to file projection, and the engine's
 * last step: sweeps tracked_directories, re-projects it from every
 * enabled profile's metadata, and retires the rows the sweep left
 * behind. Self-contained — one transaction-scoped operation establishing
 * one postcondition. File rows are outside its scope: the engine demotes
 * and reclaims those itself, so this call alone rebuilds directories and
 * touches nothing in virtual_manifest.
 *
 * Mark-inactive-then-reactivate sweep:
 *   1. Downgrade every LIFECYCLE_ACTIVE row to LIFECYCLE_INACTIVE
 *      (LIFECYCLE_DELETED preserved — staged deletion intent survives).
 *   2. For each enabled profile's metadata directory, probe the path
 *      (scope-entry observation — mirror of the engine's per-row lstat)
 *      and UPSERT via state_add_directory: the row is (re)activated under
 *      its current owner and the witness is seeded if the path exists.
 *      The UPSERT's SQL CASE preserves any existing non-zero observed_at,
 *      so repeat syncs are idempotent on the witness.
 *   3. Rows not reactivated left scope. Witnessed ones stay INACTIVE and
 *      surface as orphans for apply-time cleanup; unwitnessed ones are
 *      deleted outright — step 1 demoted them, so retiring them is this
 *      rebuild's own cleanup, not a service to the caller.
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - enabled_profiles is the engine's iteration set (the caller built
 *     `mounts` from the same list)
 *
 * Postconditions:
 *   - tracked_directories reflects enabled_profiles: rows still in scope
 *     are LIFECYCLE_ACTIVE with their witness preserved; witnessed rows
 *     that left scope are LIFECYCLE_INACTIVE (staged for apply-time
 *     cleanup); unwitnessed rows that left scope are deleted outright
 *   - A profile without metadata.json contributes no directories and is
 *     skipped, not an error
 *   - Transaction remains open
 *
 * Performance: O(D) where D = total directories across enabled profiles
 *              (typically < 50 even for large configs)
 *
 * @param repo Git repository (must not be NULL)
 * @param state State with active transaction (must not be NULL)
 * @param arena Arena for the per-row state_directory_entry_t allocations.
 *              Entries live until the caller destroys the arena (typically
 *              command end). Must not be NULL.
 * @param enabled_profiles Current enabled profiles (must not be NULL)
 * @param mounts Per-machine mount table covering enabled_profiles
 *               (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_sync_directories(
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

    /* 1. Mark all ACTIVE directories inactive (soft delete for the sweep)
     *
     * Rows not reactivated during rebuild left scope: witnessed ones become
     * orphans for apply-time cleanup; unwitnessed ones are retired by
     * step 3 below.
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
        directories = metadata_get_items_by_kind(
            metadata, METADATA_ITEM_DIRECTORY, &dir_count
        );

        /* Project each directory: one UPSERT (re)activates the row under
         * its current owner and refreshes metadata; the SQL preserves any
         * existing witness. directory_entry_from_metadata treats a missing
         * custom/ binding as a hard error, so success implies a row. */
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

            /* Scope-entry observation probe — mirror of the engine's per-row
             * lstat. Success of any type counts: a file squatting on the
             * path is still "something was here"; type divergence is a
             * separate signal. Failure leaves observed_at at sentinel-zero
             * (ghost until a later witness event). */
            struct stat probe_st;
            if (lstat(state_dir->filesystem_path, &probe_st) == 0) {
                state_dir->observed_at = time(NULL);
            }

            err = state_add_directory(state, state_dir);
            if (err) {
                err = error_wrap(
                    err, "Failed to project directory '%s' into state",
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

    /* 3. Retire the ghosts the sweep left behind — INACTIVE and never
     * witnessed means nothing on disk to clean. Guarded on success: after a
     * partial rebuild the predicate cannot tell rows the re-projection
     * never reached from rows that genuinely left scope. */
    if (!err) err = state_reclaim_unmaterialized_directories(state);

    return err;
}

/**
 * Would projecting `row` over `old` change nothing?
 *
 * True when the UPSERT state_add_file issues for `row` would rewrite
 * every column it writes to its current value: `old` is ACTIVE (the
 * state column is written ACTIVE), every VWD-cache column —
 * storage_path, profile, blob_oid, type, mode, owner, group, encrypted —
 * equals the view's, and a witness is on record (observed_at is
 * monotonic once set, so no probe could move it). The columns the UPSERT
 * does not take from the row need no comparison: old_profile's CASE
 * preserves it when the profile is unchanged, and the deployment anchor
 * is preserved on every UPDATE. The engine leaves such a row alone — no
 * probe, no write.
 *
 * Exact by construction: a row that differs in any written column, is
 * not ACTIVE, or has never been witnessed (the probe may flip it this
 * time) is not settled.
 *
 * @param old Snapshot row at the same filesystem_path, or NULL
 * @param row View row about to be projected
 * @return true iff the projection can skip the row
 */
static bool manifest_row_settled(
    const state_file_entry_t *old,
    const state_file_entry_t *row
) {
    if (!old || old->lifecycle != LIFECYCLE_ACTIVE || old->anchor.observed_at == 0) {
        return false;
    }
    if (!git_oid_equal(&old->blob_oid, &row->blob_oid) ||
        old->type != row->type ||
        old->mode != row->mode ||
        old->encrypted != row->encrypted ||
        strcmp(old->storage_path, row->storage_path) != 0 ||
        strcmp(old->profile, row->profile) != 0) {
        return false;
    }

    /* owner and group are optional: equal when both are unset, or both
     * set to the same name. */
    if ((old->owner == NULL) != (row->owner == NULL) ||
        (old->owner && strcmp(old->owner, row->owner) != 0)) {
        return false;
    }
    if ((old->group == NULL) != (row->group == NULL) ||
        (old->group && strcmp(old->group, row->group) != 0)) {
        return false;
    }

    return true;
}

/**
 * Project the enabled-profile scope into virtual_manifest
 *
 * The one projection engine. The enabled set (membership and order) is
 * read from state; the caller makes it authoritative before the call and
 * names, through `leftover`, what a row that falls out of the projection
 * means (see the header for why that is a parameter and not derived).
 * Idempotent: applying the same scope twice is a no-op — every row is
 * settled the second time and every HEAD persist writes the same OID.
 *
 * Algorithm:
 *   1. Read the enabled set from state.
 *   2. Build the fresh precedence view at each branch's HEAD.
 *      precedence_view_build attributes per-profile metadata to each row
 *      during the tree walk; step 4 writes the row's already-attributed
 *      mode/owner/group/encrypted directly to the DB. A branch that does
 *      not exist contributes no rows and leaves its heads[] slot zero.
 *   3. Snapshot current virtual_manifest (arena-backed, every lifecycle)
 *      and index it by filesystem_path.
 *   4. UPSERT every view row whose snapshot row would change — a settled
 *      row (ACTIVE, witnessed, every VWD column already at the view's
 *      value) is skipped without a probe unless stats are requested for
 *      its profile. One lstat per probed row stamps the witness and
 *      feeds the attributed present/missing fan-out. The SQL UPSERT
 *      preserves the deployment anchor on UPDATE, auto-captures
 *      old_profile when the profile column changes, and unconditionally
 *      writes state=LIFECYCLE_ACTIVE — a path that re-entered the
 *      projection is ACTIVE whatever lifecycle it carried.
 *   5. Leftover pass over the snapshot: every ACTIVE row not in the view
 *      takes `leftover`; a non-ACTIVE row outside the view is preserved.
 *   5b. Record, for every profile whose branch resolved, the OID the view
 *      was projected from as enabled_profiles.commit_oid.
 *   6. Reclaim the file rows step 5 demoted that were never witnessed —
 *      a ghost has no filesystem obligation, so nothing may stage it.
 *   7. Rebuild tracked_directories (sweep, re-project, reclaim).
 */
error_t *manifest_apply_scope(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    state_lifecycle_t leftover,
    const string_array_t *stats_filter,
    manifest_scope_stats_t *out_stats
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);

    /* Two admissible fates for a row that left the projection: the user
     * took its profile out of scope here (INACTIVE), or Git no longer
     * has it (RELEASED). ACTIVE would keep a row the engine cannot back;
     * DELETED would claim an intent no scope transition carries. Both
     * are caller bugs — fail loudly. */
    if (leftover != LIFECYCLE_INACTIVE && leftover != LIFECYCLE_RELEASED) {
        return ERROR(
            ERR_INVALID_ARG,
            "manifest_apply_scope: leftover must be LIFECYCLE_INACTIVE or "
            "LIFECYCLE_RELEASED"
        );
    }

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
    hashmap_t *old_index = NULL;

    /* Step 1: Read the authoritative scope from state.
     *
     * Precondition: the caller has already updated enabled_profiles
     * membership and order to the target set. commit_oid is not read
     * here — step 5b writes it from the tree the view was built from. */
    err = state_get_profiles(state, &enabled);
    if (err) {
        err = error_wrap(err, "Failed to read enabled profiles for scope projection");
        goto cleanup;
    }

    /* Step 2: Build fresh precedence view at HEAD.
     *
     * precedence_view_build consults the mount table only for profiles in
     * the passed list — disabled profiles are never considered, so the
     * ordering rule ("update state first, then project") is enforced by
     * the oracle's own read scope. */
    err = precedence_view_build(repo, enabled, mounts, arena, &new_view);
    if (err) {
        err = error_wrap(err, "Failed to build precedence view for scope projection");
        goto cleanup;
    }

    /* Step 3: Snapshot the current virtual_manifest rows (all states) and
     * index them by filesystem_path.
     *
     * Captured BEFORE step 4's UPSERTs so both passes see pre-projection
     * state. Step 4 asks, per view row, what the UPSERT would change —
     * "already ACTIVE at these values?" decides whether the row is
     * written at all, and the attribution splits claimed into added /
     * updated / unchanged. Step 5 asks which rows left. Arena-allocated:
     * no explicit free. The index borrows the snapshot's arena-backed
     * paths as keys; values point into the snapshot. */
    err = state_get_all_files(state, arena, &old_entries, &old_count);
    if (err) {
        err = error_wrap(err, "Failed to snapshot current manifest");
        goto cleanup;
    }

    old_index = hashmap_borrow(old_count > 0 ? old_count : 16);
    if (!old_index) {
        err = ERROR(ERR_MEMORY, "Failed to create manifest snapshot index");
        goto cleanup;
    }
    for (size_t i = 0; i < old_count; i++) {
        err = hashmap_set(
            old_index, old_entries[i].filesystem_path, &old_entries[i]
        );
        if (err) {
            err = error_wrap(err, "Failed to index manifest snapshot");
            goto cleanup;
        }
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

    /* Step 4: Project every row in the new view.
     *
     * The row IS the source. precedence_view_build attributed each row
     * to its winning profile and applied that profile's metadata.json
     * claim (mode, owner, group, encrypted) during the tree walk, so no
     * metadata side channel is consulted here — which is what keeps
     * storage_path collisions across profiles with distinct targets
     * from cross-contaminating a row. The `encrypted` column in
     * particular is a metadata-projected cache: its upstream is
     * metadata.json:encrypted, classified byte-derived at the write
     * boundary (cmds/add.c, cmds/update.c via
     * content_store_file_to_worktree's out_kind), and the engine
     * projects it without re-classifying the blob — runtime trusts the
     * cache, write-time establishes the invariant (docs/encryption-spec.md
     * → "Cache hierarchy and write-time invariant").
     *
     * UPSERT semantics (see state.c::sql_insert):
     *   - New path: INSERT with state=ACTIVE, deployed_at=0, anchor unset.
     *   - Existing path: UPDATE the VWD-cache columns (storage_path,
     *     profile, blob_oid, type, mode, owner, group, encrypted, state);
     *     preserve the deployment anchor (deployed_blob_oid, deployed_at,
     *     stat_*) — the engine is a pure VWD-cache writer, never a
     *     confirmation event; state_update_anchor is the anchor's sole
     *     writer, and the capture-from-disk verbs follow the engine with
     *     it on the rows they won. The CASE on old_profile auto-captures
     *     the prior profile when the profile column changes, and
     *     preserves it otherwise; clearing is state_clear_old_profile's,
     *     once the user has been shown the reassignment.
     *   - state column overwritten with LIFECYCLE_ACTIVE unconditionally,
     *     which reactivates any INACTIVE, DELETED or RELEASED row whose
     *     path re-entered the projection (a profile re-enable, a revert,
     *     a pulled re-add). The anchor survives the round trip, so the
     *     workspace reads the returning file as clean or [stale] by
     *     content, never as a fresh deployment.
     *
     * A settled row (manifest_row_settled) is left alone — no probe, no
     * write — so the writes are the rows that moved, not the view. An
     * attributed row is still probed when settled: the caller asked how
     * many of its rows are on disk, and that is the probe's other job.
     *
     * One probe per row, and only for rows that need it. It stamps the
     * observation signal in place before the UPSERT: observed_at answers
     * "has dotta ever lstat-confirmed this path on disk in scope?", and
     * the classifier reads it to tell a ghost (never seen, classifies
     * UNDEPLOYED) from a file the user removed (seen, classifies
     * DELETED). The UPSERT's CASE keeps any earlier non-zero value, so
     * repeat projections are idempotent on the column; only a successful
     * lstat counts — ENOENT and every other failure leave observed_at at
     * 0, which keeps ghosts out of DELETED classification. The same
     * probe drives the attributed fan-out (files_present / files_missing
     * / access_errors — the user-visible "already on disk vs needs
     * deployment"), and it is NOT a confirmation event: the anchor stays
     * where it was. The snapshot lookup splits files_claimed into
     * added / updated / unchanged. */
    time_t now = time(NULL);

    for (size_t i = 0; i < new_view->count; i++) {
        state_file_entry_t *entry = &new_view->entries[i];
        const state_file_entry_t *old = hashmap_get(
            old_index, entry->filesystem_path
        );
        bool settled = manifest_row_settled(old, entry);

        manifest_scope_stats_t *slot = NULL;
        if (stats_map) {
            void *p = hashmap_get(stats_map, entry->profile);
            if (p) slot = &out_stats[(size_t) (uintptr_t) p - 1];
        }

        if (slot) {
            slot->files_claimed++;

            /* What the UPSERT does to this path: insert or reactivate
             * (added), move the expected state apply acts on (updated),
             * or rewrite the same value (neither). Owner/group travel
             * with a metadata commit rare enough to ride on the
             * workspace's verdict instead. */
            if (!old || old->lifecycle != LIFECYCLE_ACTIVE) {
                slot->files_added++;
            } else if (!git_oid_equal(&old->blob_oid, &entry->blob_oid) ||
                old->type != entry->type ||
                old->mode != entry->mode) {
                slot->files_updated++;
            }
        }

        /* Nothing to write and nothing to count: the row is not probed. */
        if (settled && !slot) continue;

        struct stat st;
        bool present = (lstat(entry->filesystem_path, &st) == 0);

        if (slot) {
            if (present) {
                /* On disk; whether it matches the profile blob is
                 * unverified — workspace divergence analysis
                 * (status/diff/apply) decides. */
                slot->files_present++;
            } else {
                /* Absent, or inaccessible (permission denied, I/O
                 * error, …). Degrade gracefully: the row is still
                 * managed, and the user sees the access error count.
                 * Counted as missing so files_claimed stays the sum
                 * of the on-disk and absent fan-outs. */
                slot->files_missing++;
                if (errno != ENOENT) slot->access_errors++;
            }
        }

        /* Counted, and already at the view's values: nothing to write. */
        if (settled) continue;

        if (present) entry->anchor.observed_at = now;

        err = state_add_file(state, entry);
        if (err) {
            err = error_wrap(
                err, "Failed to project '%s' during scope projection",
                entry->storage_path
            );
            goto cleanup;
        }
    }

    /* Step 5: Leftover pass over the pre-projection snapshot.
     *
     * A row whose filesystem_path is NOT in the new view's index left
     * the projection. An ACTIVE row takes `leftover`. LIFECYCLE_INACTIVE,
     * LIFECYCLE_DELETED and LIFECYCLE_RELEASED rows are preserved, and
     * not counted: each records an intent — staged for removal, deletion
     * ordered, authority lost — that predates this call, and a scope
     * transition that swept past it neither caused nor changes it.
     *
     * The row is not removed here. The full pipeline — the workspace's
     * observation, cleanup's verdict, apply's receipt — ensures user
     * visibility and safety checks before anything leaves disk or state.
     *
     * A row still in the new view was already updated in step 4; we
     * only harvest loss-side stats here (reassignment between
     * precedence winners). */
    for (size_t i = 0; i < old_count; i++) {
        state_file_entry_t *old = &old_entries[i];

        void *idx_ptr = hashmap_get(new_view->index, old->filesystem_path);

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

        /* Not covered. Only an ACTIVE row is this call's departure. */
        if (old->lifecycle != LIFECYCLE_ACTIVE) continue;

        err = state_set_file_state(state, old->filesystem_path, leftover);
        if (err) {
            /* Fatal — the caller rolls the transaction back. Left ACTIVE,
             * the row would be analysed against a blob Git may no longer
             * have instead of retiring. */
            err = error_wrap(
                err, "Failed to mark '%s' %s", old->filesystem_path,
                leftover == LIFECYCLE_RELEASED ? "released" : "inactive"
            );
            goto cleanup;
        }

        if (stats_map && old->profile) {
            void *p = hashmap_get(stats_map, old->profile);
            if (p) {
                size_t sidx = (size_t) (uintptr_t) p - 1;
                /* A row never witnessed on disk leaves scope with no
                 * filesystem obligation: step 6's reclaim retires it
                 * (same predicate, SQL-enforced) — attribute it as
                 * reclaimed, not staged for removal. */
                if (old->anchor.observed_at == 0) {
                    out_stats[sidx].files_reclaimed++;
                } else {
                    out_stats[sidx].files_orphaned++;
                }
            }
        }
    }

    /* Step 5b: Git reference currency. The OID written is the one whose
     * tree was just projected — captured by the same peel, so the
     * manifest and commit_oid can never describe two different commits
     * and no second ref lookup can race. A branch that did not resolve
     * left its slot zero and its stored commit_oid untouched. */
    for (size_t i = 0; i < enabled->count; i++) {
        if (git_oid_is_zero(&new_view->heads[i])) continue;

        err = state_set_profile_commit_oid(
            state, enabled->items[i], &new_view->heads[i]
        );
        if (err) {
            err = error_wrap(
                err, "Failed to record commit_oid for profile '%s'",
                enabled->items[i]
            );
            goto cleanup;
        }
    }

    /* Step 6: Retire the ghosts step 5 demoted. Never witnessed means
     * no filesystem obligation, so there is nothing for apply to clean —
     * and the attribution above predicted exactly this set, from the
     * same observed_at test. */
    err = state_reclaim_unmaterialized_files(state);
    if (err) {
        err = error_wrap(err, "Failed to reclaim ghost file rows");
        goto cleanup;
    }

    /* Step 7: Rebuild tracked directories. Directory fallback and orphan
     * semantics fall out of it: directories still in any enabled profile's
     * metadata are reactivated with the new owner; witnessed directories
     * that left scope remain LIFECYCLE_INACTIVE for apply-time cleanup.
     *
     * Reuses the mount table built above — directories share the same
     * profile→target resolution as files. */
    err = manifest_sync_directories(repo, state, arena, enabled, mounts);
    if (err) {
        err = error_wrap(err, "Failed to rebuild tracked directories");
        goto cleanup;
    }

cleanup:
    /* old_entries and the view's spine + strings are arena-backed; the
     * caller's arena (typically ctx->arena) reclaims them at command end.
     * Only the heap-allocated hashmaps need explicit free. */
    if (stats_map) hashmap_free(stats_map, NULL);
    if (old_index) hashmap_free(old_index, NULL);
    if (new_view && new_view->index) hashmap_free(new_view->index, NULL);
    string_array_free(enabled);

    return err;
}

/**
 * Has any enabled branch moved past the HEAD the manifest was projected from?
 *
 * Profile-level drift: enabled_profiles.commit_oid ≠ refs/heads/<profile>.
 * O(P) row-cache reads + O(P) ref lookups, first mismatch answers — the
 * gate that keeps manifest_reconcile's common case at zero writes.
 *
 * A branch that does not resolve is not drift. The projection skips it
 * and leaves its commit_oid alone, so counting it would re-run the
 * engine on every load for as long as the branch stays enabled — a
 * misconfiguration the scope layer already warns about on every run.
 * The workspace observes that branch's rows as released at load. A
 * lookup that fails for any other reason is left for the next load the
 * same way: no answer is not a reason to project.
 *
 * Cannot fail: every lookup it makes is either answered or deferred.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle (must not be NULL)
 * @param profiles Enabled profiles (must not be NULL)
 * @return true if at least one enabled branch is ahead of its stored HEAD
 */
static bool manifest_detect_drift(
    git_repository *repo,
    const state_t *state,
    const string_array_t *profiles
) {
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Borrowed from the row cache. NULL only for a profile that is
         * not enabled — the list we iterate came from that same cache. */
        const git_oid *stored = state_peek_profile_commit_oid(state, profile);
        if (!stored) continue;

        git_oid head;
        error_t *err = gitops_resolve_branch_head_oid(repo, profile, &head);
        if (err) {
            error_free(err);
            continue;
        }

        if (!git_oid_equal(stored, &head)) return true;
    }

    return false;
}

/**
 * Reconcile manifest with current Git state (drift check over the engine)
 *
 * Self-contained: fetches the enabled set, asks manifest_detect_drift
 * whether any enabled branch moved, and only then scopes a write
 * transaction (when the caller holds none) and runs manifest_apply_scope
 * with leftover = LIFECYCLE_RELEASED — a row that left the projection
 * here was dropped by Git, not by the user. Callers supply the repo,
 * state, arena and mounts, and optionally the engine's stats pair;
 * everything else is derived.
 */
error_t *manifest_reconcile(
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

    /* The engine's pairing rule, checked here too because this function
     * writes the array itself before the engine is reached. */
    if ((stats_filter == NULL) != (out_stats == NULL)) {
        return ERROR(
            ERR_INVALID_ARG,
            "manifest_reconcile: stats_filter and out_stats must both be "
            "NULL or both non-NULL"
        );
    }

    /* Establish the stats postcondition up front so every early return
     * below — empty enabled set, no drift — leaves the array in the same
     * shape the engine produces: zero counts under each profile's name.
     * The engine re-establishes the same on its own entry. */
    if (stats_filter) {
        for (size_t i = 0; i < stats_filter->count; i++) {
            memset(&out_stats[i], 0, sizeof(out_stats[i]));
            out_stats[i].profile = stats_filter->items[i];
        }
    }

    string_array_t *profiles = NULL;
    error_t *err = state_get_profiles(state, &profiles);
    if (err) {
        return error_wrap(err, "Failed to fetch enabled profiles for reconcile");
    }

    /* Empty enabled set — no scope to reconcile. Consistent with the
     * "disable last profile, then apply" workflow: nothing to sync. */
    if (!profiles || profiles->count == 0) {
        string_array_free(profiles);
        return NULL;
    }

    /* Common case: every enabled branch is where the manifest left it.
     * O(P) and no write — the cost profile every workspace load relies on,
     * and what keeps a sync that pulled nothing free of manifest work. */
    bool drifted = manifest_detect_drift(repo, state, profiles);
    string_array_free(profiles);
    if (!drifted) return NULL;

    /* Scope a write transaction only when the caller doesn't already hold
     * one. Apply runs under dotta_ext_write. Workspace (from status/diff/
     * update), sync and revert hold no transaction and need the scoped one. */
    bool needs_tx = !state_locked(state);
    if (needs_tx) {
        err = state_begin(state);
        if (err) {
            return error_wrap(err, "Failed to begin reconcile transaction");
        }
    }

    err = manifest_apply_scope(
        repo, state, arena, mounts, LIFECYCLE_RELEASED, stats_filter, out_stats
    );

    if (needs_tx) {
        if (!err) {
            err = state_commit(state);
            if (err) {
                err = error_wrap(err, "Failed to commit reconcile transaction");
            }
        }
        /* A failed COMMIT leaves the transaction open (state_commit keeps
         * in_transaction set), so the rollback below covers both the
         * engine's failure and the commit's: a scoped transaction never
         * outlives this call for the next state_locked() check to inherit. */
        if (err) {
            state_rollback(state);
        }
    }

    return err;
}

/**
 * Remove files from manifest (remove command)
 *
 * Engine first, then the verb's intent on the rows it named. The
 * projection already did the structural work — a path another enabled
 * profile still provides was reassigned to it (old_profile captured by
 * the UPSERT), a path nothing provides took LIFECYCLE_RELEASED, a ghost
 * among those was reclaimed, commit_oid is current, directories rebuilt.
 * The engine called every departure a discovery because it cannot know
 * better; this verb does — the removal was asked for, and the user said
 * what to do with the deployed copy.
 *
 * Algorithm:
 *   1. manifest_apply_scope(leftover = LIFECYCLE_RELEASED)
 *   2. For each removed storage path, resolved against the mount table:
 *      a. ACTIVE row: another profile holds the path. It is counted as
 *         a fallback iff old_profile == removed_profile — the engine
 *         just moved it away from us; otherwise a higher-precedence
 *         profile owned it all along and nothing changed.
 *      b. RELEASED row owned by removed_profile: ours, and nothing backs
 *         it now. delete_files → LIFECYCLE_DELETED (apply prunes a clean
 *         copy); otherwise the row is purged — released from management
 *         now, the deployed copy left where it is.
 *      c. Anything else — no row (never projected, or a ghost the engine
 *         reclaimed), another profile's release, an INACTIVE or DELETED
 *         row from an earlier verb — is not this call's to touch.
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commit removing the paths MUST be complete
 *   - removed_storage_paths are storage paths (home/.bashrc)
 *
 * Postconditions (beyond manifest_apply_scope's):
 *   - removed_profile's departed paths are LIFECYCLE_DELETED
 *     (delete_files) or gone from virtual_manifest (!delete_files)
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup or fate write failed — the caller
 *     rolls back; the Git commit stands and the next reconcile projects
 *     again (the fate overlay is not replayed: the path then reads as
 *     released)
 *
 * Performance: manifest_apply_scope + O(N) point lookups, N = paths removed
 */
error_t *manifest_remove_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *removed_profile,
    const string_array_t *removed_storage_paths,
    bool delete_files,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(removed_profile);
    CHECK_NULL(removed_storage_paths);

    if (out_removed) *out_removed = 0;
    if (out_fallbacks) *out_fallbacks = 0;

    /* 1. Project the enabled set at its post-removal HEADs. */
    error_t *err = manifest_apply_scope(
        repo, state, arena, mounts, LIFECYCLE_RELEASED, NULL, NULL
    );
    if (err) {
        return error_wrap(err, "Failed to project manifest after remove");
    }

    /* 2. Overlay the verb's intent on each path it removed. */
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
            return error_wrap(err, "Failed to resolve path: %s", storage_path);
        }
        if (outcome == MOUNT_RESOLVE_UNBOUND) continue;

        /* The post-projection row. Absent means the path was never in
         * the manifest (profile disabled, path filtered) or a ghost the
         * engine just reclaimed — nothing for apply to do either way. */
        state_file_entry_t *row = NULL;
        err = state_get_file(state, filesystem_path, &row);
        if (err) {
            if (error_code(err) != ERR_NOT_FOUND) {
                return error_wrap(err, "Failed to read manifest row for %s", storage_path);
            }
            error_free(err);
            err = NULL;
            continue;
        }

        if (row->lifecycle == LIFECYCLE_ACTIVE) {
            /* Another profile holds the path. old_profile == removed_profile
             * iff the engine's UPSERT just captured the reassignment away
             * from us; otherwise a higher profile owned it all along and
             * the deployment is untouched. */
            if (row->old_profile && strcmp(row->old_profile, removed_profile) == 0) {
                if (out_fallbacks) (*out_fallbacks)++;
            }
        } else if (row->lifecycle == LIFECYCLE_RELEASED &&
            strcmp(row->profile, removed_profile) == 0) {
            /* Ours, and nothing backs it now. The row is not left for the
             * pipeline to discover: the verb knows the user's answer. */
            err = delete_files
                ? state_set_file_state(state, filesystem_path, LIFECYCLE_DELETED)
                : state_remove_file(state, filesystem_path);
            if (err) {
                state_free_entry(row);
                return error_wrap(
                    err, "Failed to %s '%s'",
                    delete_files ? "stage removal of" : "release", filesystem_path
                );
            }
            if (out_removed) (*out_removed)++;
        }

        state_free_entry(row);
    }

    return NULL;
}

/**
 * Update files in manifest (update command)
 *
 * Engine first, then the verb's intent on the items it committed. The
 * projection establishes the VWD at the post-commit HEADs: a modified
 * file's row carries its new blob, a new file has a row, a deleted
 * file's row was reassigned to a lower profile or took
 * LIFECYCLE_RELEASED. Two things only update knows follow, per item:
 *
 *   anchor — a modified or new file was captured FROM disk a moment ago,
 *            so disk is the just-committed blob: the deployment anchor
 *            advances to that blob with a fresh stat, and the next status
 *            takes the fast path. Only the winning profile's row is
 *            anchored; a stat bound to a lower-precedence blob would
 *            poison the winner's fast path.
 *   fate   — a deleted file (WORKSPACE_STATE_DELETED: dotta had witnessed
 *            it and the user removed it) left Git by this commit. A row
 *            the engine reassigned is a fallback for apply to deploy; a
 *            row it released is purged — nothing backs it and nothing is
 *            on disk. No lstat: a file recreated between workspace load
 *            and this call is left on disk unmanaged, which is the
 *            release outcome, never a prune.
 *
 * Algorithm:
 *   1. manifest_apply_scope(leftover = LIFECYCLE_RELEASED)
 *   2. For each FILE item (directories ride on the engine's rebuild):
 *      - DELETED: ACTIVE row under another profile → fallback;
 *                 otherwise removed, and a RELEASED row under the
 *                 item's profile is purged
 *      - else:    ACTIVE row under the item's profile → anchor advance
 *                 (shadowed or filtered paths receive nothing)
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commits MUST be complete (branches at their final state)
 *
 * Postconditions (beyond manifest_apply_scope's):
 *   - Captured rows: anchor = (blob_oid, now, fresh stat); an anchor-write
 *     failure is non-fatal — the VWD cache is already projected and the
 *     next status self-heals the anchor through the slow-path CMP_EQUAL
 *     flush
 *   - Deleted paths without a fallback are gone from virtual_manifest
 *   - Transaction remains open (caller commits)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup or purge failed — the caller rolls
 *     back; the Git commits stand and the next reconcile projects again
 *
 * Performance: manifest_apply_scope + O(N) point lookups, N = items
 */
error_t *manifest_update_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const workspace_item_t **items,
    size_t item_count,
    size_t *out_synced,
    size_t *out_removed,
    size_t *out_fallbacks
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(items);
    CHECK_NULL(out_synced);
    CHECK_NULL(out_removed);
    CHECK_NULL(out_fallbacks);

    *out_synced = 0;
    *out_removed = 0;
    *out_fallbacks = 0;

    /* 1. Project the enabled set at its post-commit HEADs. */
    error_t *err = manifest_apply_scope(
        repo, state, arena, mounts, LIFECYCLE_RELEASED, NULL, NULL
    );
    if (err) {
        return error_wrap(err, "Failed to project manifest after update");
    }

    /* 2. Overlay the verb's intent on each item it committed. */
    time_t now = time(NULL);

    for (size_t i = 0; i < item_count; i++) {
        const workspace_item_t *item = items[i];

        /* Directories have no manifest row; the engine rebuilt theirs. */
        if (item->item_kind != PATH_KIND_FILE) continue;

        state_file_entry_t *row = NULL;
        err = state_get_file(state, item->filesystem_path, &row);
        if (err) {
            if (error_code(err) != ERR_NOT_FOUND) {
                return error_wrap(
                    err, "Failed to read manifest row for %s", item->filesystem_path
                );
            }
            error_free(err);
            err = NULL;
        }

        if (item->state == WORKSPACE_STATE_DELETED) {
            if (row && row->lifecycle == LIFECYCLE_ACTIVE) {
                /* A lower profile still provides the path: the engine
                 * reassigned the row (old_profile = this profile) and apply
                 * deploys the fallback. A row still under this profile is
                 * not ours to count — the commit did not remove it. */
                if (strcmp(row->profile, item->profile) != 0) (*out_fallbacks)++;
            } else {
                if (row && row->lifecycle == LIFECYCLE_RELEASED &&
                    strcmp(row->profile, item->profile) == 0) {
                    err = state_remove_file(state, item->filesystem_path);
                    if (err) {
                        state_free_entry(row);
                        return error_wrap(
                            err, "Failed to purge '%s' after its deletion",
                            item->filesystem_path
                        );
                    }
                }
                (*out_removed)++;
            }
        } else if (row && row->lifecycle == LIFECYCLE_ACTIVE &&
            strcmp(row->profile, item->profile) == 0) {
            /* CAPTURE: disk is the just-committed blob — advance the anchor
             * from a fresh probe. Not-found and write failures are both
             * non-fatal here (see the postconditions). */
            deployment_anchor_t anchor = capture_anchor_from_disk(
                item->filesystem_path, &row->blob_oid, now
            );
            error_t *anchor_err = state_update_anchor(
                state, item->filesystem_path, &anchor, NULL
            );
            if (anchor_err) error_free(anchor_err);

            (*out_synced)++;
        }

        if (row) state_free_entry(row);
    }

    return NULL;
}

/**
 * Add files to manifest (add command)
 *
 * Engine first, then the verb's intent on the paths it committed. The
 * projection establishes the VWD at the post-commit HEADs — every path
 * this add committed has a row under whichever enabled profile wins it.
 * What only add knows: those files were captured FROM disk a moment
 * ago, so for each path whose row this profile won, disk is the
 * just-committed blob and the deployment anchor advances to it with a
 * fresh stat. The next status takes the fast path. A path a higher-
 * precedence profile owns receives nothing — its row is the winner's,
 * and a stat bound to this profile's blob would poison the winner's
 * fast path. A path with no row (filtered by .dottaignore, or the
 * profile is not enabled) receives nothing either.
 *
 * Algorithm:
 *   1. manifest_apply_scope(leftover = LIFECYCLE_RELEASED)
 *   2. For each filesystem path: ACTIVE row under `profile` → anchor
 *      advance, counted in out_synced
 *
 * Preconditions:
 *   - state MUST have an active write transaction
 *   - the Git commit MUST be complete
 *   - filesystem_paths are canonical filesystem paths
 *   - `profile` is enabled (the caller checked; an add to a disabled
 *     profile never reaches the manifest layer)
 *
 * Postconditions (beyond manifest_apply_scope's):
 *   - Rows `profile` won for the added paths carry anchor =
 *     (blob_oid, now, fresh stat); an anchor-write failure is non-fatal
 *     — the VWD cache is already projected and the next status self-
 *     heals the anchor through the slow-path CMP_EQUAL flush
 *   - Transaction remains open (caller commits via state_save)
 *
 * Error Conditions:
 *   - ERR_GIT / ERR_STATE_INVALID / ERR_MEMORY from the engine
 *   - ERR_STATE_INVALID: a row lookup failed — the caller rolls back;
 *     the Git commit stands and the next reconcile projects again
 *
 * Performance: manifest_apply_scope + O(N) point lookups, N = paths added
 */
error_t *manifest_add_files(
    git_repository *repo,
    state_t *state,
    arena_t *arena,
    const mount_table_t *mounts,
    const char *profile,
    const string_array_t *filesystem_paths,
    size_t *out_synced
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(filesystem_paths);
    CHECK_NULL(out_synced);

    *out_synced = 0;

    /* 1. Project the enabled set at its post-commit HEADs. */
    error_t *err = manifest_apply_scope(
        repo, state, arena, mounts, LIFECYCLE_RELEASED, NULL, NULL
    );
    if (err) {
        return error_wrap(err, "Failed to project manifest after add");
    }

    /* 2. Anchor every row this profile won among the paths it committed. */
    time_t now = time(NULL);

    for (size_t i = 0; i < filesystem_paths->count; i++) {
        const char *filesystem_path = filesystem_paths->items[i];

        state_file_entry_t *row = NULL;
        err = state_get_file(state, filesystem_path, &row);
        if (err) {
            if (error_code(err) != ERR_NOT_FOUND) {
                return error_wrap(
                    err, "Failed to read manifest row for %s", filesystem_path
                );
            }
            error_free(err);
            err = NULL;
            continue;
        }

        if (row->lifecycle == LIFECYCLE_ACTIVE && strcmp(row->profile, profile) == 0) {
            /* CAPTURE: disk is the just-committed blob — advance the anchor
             * from a fresh probe. Write failures are non-fatal (see the
             * postconditions). */
            deployment_anchor_t anchor = capture_anchor_from_disk(
                filesystem_path, &row->blob_oid, now
            );
            error_t *anchor_err = state_update_anchor(
                state, filesystem_path, &anchor, NULL
            );
            if (anchor_err) error_free(anchor_err);

            (*out_synced)++;
        }

        state_free_entry(row);
    }

    return NULL;
}
