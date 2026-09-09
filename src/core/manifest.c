/**
 * manifest.c - Manifest module implementation
 *
 * The precedence oracle: manifest_build (every enabled profile, in precedence
 * order) and manifest_build_tree (one tree) share one per-profile step,
 * manifest_contribute, that produces manifest_row_t rows directly. There is no
 * persistence step and no bridge type: the view is computed into the caller's
 * arena and read through the accessors below.
 *
 * Key patterns:
 *   - Two layers, built in two moves (core/manifest.h): manifest_contribute places
 *     one profile's claims whole into that profile's own contribution — one row
 *     per location within it, the within-profile rule settled by manifest_settle
 *     — and manifest_layer then runs precedence over the settled contributions,
 *     once, into the view's index. Nothing published is ever rewritten: a row
 *     that loses a location keeps its own row and simply leaves the slice, which
 *     is what lets a lower profile's claim be read after a higher one wins
 *     (manifest_lookup_claim) and what makes an index the one thing that says
 *     who stands where.
 *   - Blob OID Extraction: the tree walker reads blob_oid, type and the Git-derived
 *     mode from each borrowed tree entry for O(1) content identity.
 *   - Metadata Integration: the per-profile step loads the sheet of the tree it
 *     is reading — no caller supplies one — and the walker attributes it onto
 *     each row during the tree walk (single profile per row, no cross-profile
 *     merge — storage_path collisions across profiles with distinct target values
 *     are kept apart); the same sheet's DIRECTORY items are placed after the walk.
 *   - One naming rule, one body: manifest_ascend is what the settle asks for
 *     the fresh name of a contested location and what manifest_name answers callers
 *     with, so the name the view keeps and the name the namer gives are the same
 *     answer by construction. One claim shape beneath it: both layers a namer
 *     reads speak manifest_claim_t, so the leaf and the rung ask one producer
 *     (manifest_standing) and differ only in which of its two projections they
 *     take.
 *   - Diff, not delta-tracking: what a scope transition or a sync did to the
 *     view is read off two views (manifest_diff), never recorded while it happened.
 */

#include "core/manifest.h"

#include <stdlib.h>
#include <string.h>

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
 * One profile's claims, placed under the topology, precedence aside
 *
 * One row per location within the profile, and its own index over them. `rows`
 * is allocated once at the step's tail, sized exactly from the index, and nothing
 * on it is ever rewritten: a name that lost the location and a derived claim an
 * explicit one retook stay in the arena and simply leave the slice.
 *
 * The index is heap-allocated and released by manifest_free with the view's own;
 * its keys borrow the arena-backed location each row carries.
 */
typedef struct {
    const char *profile;           /* Arena-backed; the same pointer every row of it carries */
    manifest_row_t **rows;         /* The rows standing, in claim order (arena, exact) */
    size_t count;                  /* Rows standing */
    hashmap_t *index;              /* location → the row standing there, heap-allocated */
} contribution_t;

/**
 * Manifest — the precedence oracle's product
 *
 * The contributions, in precedence order, and the index precedence leaves over
 * them. Rows are allocated one by one from the caller's arena and are stable
 * from the moment they are allocated, so both indexes store row pointers directly.
 * Each spine — a contribution's and the view's — is cut once, exactly, from what
 * its index points at; there is no growth and no reallocation, and manifest_rows
 * hands the view's out as the public slice.
 *
 * profiles[i] names contributions[i]: one array is the public projection of the
 * other, kept beside it because manifest_profiles owes a contiguous array of names.
 */
struct manifest {
    contribution_t *contributions; /* One per profile, in precedence order (arena) */
    const char **profiles;         /* Their names, the public projection (arena) */
    size_t profile_count;          /* Both arrays' count */

    manifest_row_t **rows;         /* The winners, cut once at layering (arena, exact) */
    size_t count;                  /* Rows in the spine */
    hashmap_t *index;              /* location → the winning row, heap-allocated */

    const mount_table_t *mounts;   /* The table the rows were placed by: the build's own, or a tree view's caller's */

    /* The two health slices: claims the build could not place (no target binding)
     * and names a profile did not keep (it names the location otherwise), both
     * grouped by profile in build order. Flat arena arrays, abandon-and-realloc
     * growth; empty on the common build (no allocation until the first note). */
    manifest_unbound_claim_t *unbound;
    size_t unbound_count;
    size_t unbound_capacity;
    manifest_unkept_claim_t *unkept;
    size_t unkept_count;
    size_t unkept_capacity;
};

/**
 * Context for the blob-claim tree-walk callback
 *
 * Everything one walk of one tree needs to place that profile's blobs where they
 * stand: the contribution being filled, the table that places them, the sheet
 * that claims them, and the three lists the step spends. Handed to gitops_tree_walk
 * once per profile and read at O(1) per entry.
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership — the mount table and the unbound
 *             slice are read and written through it
 * - contribution: the profile's own, borrowed from manifest_contribute: its
 *             arena-backed name (every row of this profile borrows the pointer)
 *             and its location index
 * - profile: the contribution's name, for rows and error messages
 * - mounts: borrowed, must not be NULL — keyed by ctx->profile to resolve custom/
 *          entries; a missing binding (no location) contributes no row and is
 *          recorded on the view (manifest_note_unbound)
 * - metadata: borrowed from manifest_contribute, which loads the sheet of the
 *             tree being read; never NULL — a tree without one holds an empty
 *             sheet, so there is no absent case for the walker to carry
 * - placed / contenders: the step's build-local lists, borrowed — every row this
 *             profile placed, and the rows that arrived at a location it had
 *             already named. Both are spent when manifest_contribute returns.
 * - contradicted: borrowed, the third of them — the sheet's DIRECTORY keys this
 *             walk met a blob at, written here and read by the directory pass.
 *             Keyed by the arena name the walk joined, which outlives it.
 * - arena: borrowed, must not be NULL; per-row strings are abandoned to it
 * - error: owned by callback, caller must free on error
 */
struct claim_ctx {
    manifest_t *manifest;          /* Target view (modified by callback) */
    contribution_t *contribution;  /* The profile's own claims and their index */
    const char *profile;           /* Profile name for rows and error messages */
    const mount_table_t *mounts;   /* Mount table for storage→filesystem resolution */
    const metadata_t *metadata;    /* The tree's own claim sheet, never NULL */
    ptr_array_t *placed;           /* Every row this step placed, in claim order */
    ptr_array_t *contenders;       /* The rows that met a location already named */
    hashmap_t *contradicted;       /* The sheet's names this tree holds a blob at */
    arena_t *arena;                /* Arena for allocations (must not be NULL) */
    error_t *error;                /* Error propagation (set on failure) */
};

/**
 * Apply this profile's claim to a Git-built blob row.
 *
 * Selectively overrides the claim-owned fields (mode, owner, group, encrypted)
 * on a row whose Git-derived defaults have already been set. Each call attributes
 * a single profile's claim to the row, and no row ever carries two: precedence
 * across profiles picks between whole rows and rewrites none of them.
 *
 * owner/group ride every blob row; mode/encrypted are the tree's to admit, and
 * the mode only when claimed — an unclaimed one leaves the filemode floor standing,
 * so the row leaves the build total either way.
 *
 * No claim leaves the Git-derived defaults intact, and there are two ways to
 * make none: a key the sheet does not carry, and a key it carries a DIRECTORY
 * item at — which the tree contradicts, and which the caller drops where it reads
 * the name (manifest_claim_blob). The item's kind is therefore not read here:
 * the caller hands the claim a blob can take, or nothing.
 *
 * The row is fresh and unpublished — every row is, nothing being reset any more
 * — and a failure here aborts the build whole, so the fields are written as they
 * are read: there is no prior owner or group a half-done call could replace,
 * and a half-built row in a failed build is never read.
 *
 * @param row   Target row (mutable)
 * @param claim This profile's claim over the row's name, NULL where it makes
 *              none (may be NULL)
 * @param arena Allocation arena for string copies (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_apply_claim(
    manifest_row_t *row,
    const metadata_item_t *claim,
    arena_t *arena
) {
    if (!claim) {
        return NULL;
    }

    /* owner/group apply to every blob row, links included: the ownership claim
     * is true regardless of what the path became. arena_strdup returns NULL only
     * on real failure (a NULL claim->owner/group bypasses the if-guard and leaves
     * the field NULL). */
    if (claim->owner) {
        row->owner = arena_strdup(arena, claim->owner);
        if (!row->owner) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate owner for '%s'",
                row->storage_path
            );
        }
    }

    if (claim->group) {
        row->group = arena_strdup(arena, claim->group);
        if (!row->group) {
            return ERROR(
                ERR_MEMORY, "Failed to duplicate group for '%s'",
                row->storage_path
            );
        }
    }

    /* mode/encrypted apply only where a mode can stand — the tree's word
     * (row->type), never the claim's kind — and only the mode the claim makes:
     * an unclaimed one leaves the filemode floor. */
    if (row->type != PATH_TYPE_SYMLINK) {
        if (claim->mode != MODE_UNCLAIMED) {
            row->mode = claim->mode;     /* A 0000 claim is a claim */
        }
        row->encrypted = claim->encrypted;
    }

    return NULL;
}

/**
 * A row of this contribution at `location`: allocated and on the list of everything
 * the profile placed
 *
 * Whether it *stands* at the location is the caller's next line — the index takes
 * it, or the contest does. Nothing here is ever reset or overwritten: a name
 * that loses keeps its own row and leaves the slice at the settle, which is what
 * lets a lower profile's claim be read after a higher one wins the location
 * (manifest_lookup_claim) and what makes an index the one thing that says who
 * stands where.
 *
 * `location` is arena-borrowed from mount_resolve; the cast discards the const
 * qualifier its output type carries. The row keeps it as its key for the view's
 * life. Two names at one location produce two arena strings with equal content,
 * and both indexes key by content — no string is shared, and a hashmap_set that
 * replaces a value keeps the key pointer it was first given, which stays valid
 * and equal for the arena's lifetime.
 *
 * @param placed The step's list of every row placed (must not be NULL)
 * @param location Arena-backed location the row is keyed by (must not be NULL)
 * @param arena Arena for the row (must not be NULL)
 * @param out The placed row, zero but for filesystem_path (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_place(
    ptr_array_t *placed,
    const char *location,
    arena_t *arena,
    manifest_row_t **out
) {
    manifest_row_t *row = arena_calloc(arena, 1, sizeof(*row));
    if (!row) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest row");
    }
    row->filesystem_path = (char *) location;

    error_t *err = ptr_array_push(placed, row);
    if (err) {
        return error_wrap(err, "Failed to record a placed row");
    }

    *out = row;
    return NULL;
}

/**
 * Record one claim the build could not place
 *
 * The health primitive both claim sites share: appends (profile, storage_path,
 * kind) to the view's health slice. No dedup, and none possible — the two passes
 * note disjoint names. The blob pass notes names the tree holds a blob at; the
 * directory pass notes sheet keys it does not, the content-authority rule having
 * contradicted the rest before either pass resolved anything. And within a pass
 * a name is its own: a tree holds one blob per path, a sheet one item per key.
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
 * Record one name the contribution did not keep
 *
 * The health primitive the settle spends its losers through: appends (profile,
 * name, kind) against the name that stood at the location. No dedup — a row is
 * in one group and is recorded once if it loses, and no two rows of one profile
 * share a name (the tree holds one blob per path, the sheet one item per key,
 * and the content-authority rule settles the one name they can both carry before
 * the contest sees it).
 *
 * Growth is the unbound slice's abandon-and-realloc idiom. Every string must be
 * arena-backed by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param row The row whose name did not stand (must not be NULL)
 * @param kept The name that did (must not be NULL)
 * @param arena Arena for the array growth (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_note_unkept(
    manifest_t *manifest,
    const char *profile,
    const manifest_row_t *row,
    const char *kept,
    arena_t *arena
) {
    if (manifest->unkept_count >= manifest->unkept_capacity) {
        size_t new_capacity =
            manifest->unkept_capacity > 0 ? manifest->unkept_capacity * 2 : 8;

        manifest_unkept_claim_t *grown = arena_calloc(
            arena, new_capacity, sizeof(*grown)
        );
        if (!grown) {
            return ERROR(ERR_MEMORY, "Failed to grow unkept claim list");
        }
        memcpy(grown, manifest->unkept, manifest->unkept_count * sizeof(*grown));
        manifest->unkept = grown;
        manifest->unkept_capacity = new_capacity;
    }

    manifest->unkept[manifest->unkept_count++] = (manifest_unkept_claim_t){
        .profile = profile,
        .storage_path = row->storage_path,
        .kind = path_type_kind(row->type),
        .kept = kept,
        .filesystem_path = row->filesystem_path,
    };
    return NULL;
}

/**
 * The claim standing at `location` for this asker
 *
 * The two layers a namer reads, nearest first. A claim the command has admitted
 * and not yet committed answers alone, whatever its kind: it is the nearer
 * statement about the place, so a staged FILE names its own location and nothing
 * under it, shadowing a tracked directory the branch holds at the same location
 * exactly as it will once committed — where the blob takes the location and the
 * directory's name is the one the contribution does not keep. A location the
 * verb entered without claiming holds a NULL value, and hashmap_get folds "absent"
 * and "entered, claimed nothing" into the one answer the layer below is owed.
 *
 * Where the command claimed nothing the profile's own committed row speaks,
 * projected into the same pair: a derived row is no claim at all, and every other
 * row names its own location. The derived filter runs first, so a
 * PATH_KIND_DIRECTORY leaving the projection is a tracked directory's.
 *
 * The two questions the pair answers are the two its callers ask — manifest_name's
 * leaf takes any name it finds, manifest_ascend's rung takes a directory's alone
 * (manifest_claim_beneath). The name is borrowed from whichever layer answered;
 * both outlive the call, and both callers copy or compose at once.
 *
 * The contribution is taken rather than the view because that is what keeps the
 * O(P) search for it out of the per-rung loop. A public form reads (view, profile,
 * location, pending) and finds the contribution itself, as manifest_lookup_claim
 * does — a wrapper over this one, never a second body.
 *
 * @param c The profile's own contribution, or NULL when the view has none for it
 * @param pending The asking profile's uncommitted claims, or NULL
 * @param location The location to read (must not be NULL)
 * @return The claim standing there, or a NULL name when none does
 */
static manifest_claim_t manifest_standing(
    const contribution_t *c, const hashmap_t *pending, const char *location
) {
    const manifest_claim_t *staged = pending ? hashmap_get(pending, location) : NULL;
    if (staged) return *staged;

    const manifest_row_t *row = c ? hashmap_get(c->index, location) : NULL;
    if (!row || manifest_is_derived(row)) return (manifest_claim_t){ 0 };

    return (manifest_claim_t){
        .storage_path = row->storage_path,
        .kind = path_type_kind(row->type),
    };
}

/**
 * The name `profile` composes for `location` from what stands above it
 *
 * The rungs above the location, nearest first: the claim standing at each one
 * (manifest_standing — this command's own listing where it has one there, else
 * the profile's committed row), and the location is composed beneath the first
 * that names what lies beneath it, a DIRECTORY claim of either layer
 * (manifest_claim_beneath). A root of the profile ends the ascent at every rung,
 * the location itself included: nothing of the profile's stands above its own
 * binding, and mount_name composes the answer beneath the deepest root it has
 * (NULL when the location is that root). An ancestor claim names nothing, and a
 * blob names its own location and nothing under it — a name beneath a file is a
 * tree entry the stage refuses — so both are climbed past.
 *
 * The claim is asked before the root at every rung, and the loop's shape is what
 * makes that true: the root test at the top reads the rung whose claim the previous
 * turn read, so the order over the rungs is root(L), claim(P1), root(P1),
 * claim(P2), … Written with the root test after the up-step instead, a typed
 * `home/jail` standing at web's own target would be climbed past, and web's name
 * for what lies beneath it would be the binding's rather than its own claim's.
 *
 * The root "/" is a rung the ascent passes through and never reads: no storage
 * path spells it, so nothing can be listed or tracked there, and the sentinel —
 * a root of every namespace — ends the ascent at the top of the next turn. The
 * skip is load-bearing, not an optimisation: the tail arithmetic below assumes
 * a separator where the rung ends, which the root and the empty prefix do not have.
 *
 * The scratch copy is the arena's and abandoned, the module's idiom: the ascent
 * is asked once per argument and once per contested location, never per walked
 * child.
 *
 * @param c The profile's own contribution, or NULL when the view has none for it
 * @param mounts The table the view was placed by (must not be NULL)
 * @param profile The asker — the contribution's own name when it has one
 * @param location Absolute location (must not be NULL)
 * @param pending The command's uncommitted claims, or NULL
 * @param arena Arena that owns the answer (must not be NULL)
 * @param out_storage The composed name, NULL at a root (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_ascend(
    const contribution_t *c,
    const mount_table_t *mounts,
    const char *profile,
    const char *location,
    const hashmap_t *pending,
    arena_t *arena,
    const char **out_storage
) {
    *out_storage = NULL;

    char *rung = arena_strdup(arena, location);
    if (!rung) {
        return ERROR(ERR_MEMORY, "Failed to copy the location");
    }
    size_t len = strlen(rung);

    for (;;) {
        if (mount_root(mounts, profile, rung)) break;

        size_t up = str_path_parent_len(rung);
        if (up >= len) break;   /* "/" is its own parent; the sentinel ends it anyway */
        len = up;
        rung[len] = '\0';
        if (len < 2) continue;  /* "/" and the empty prefix name nothing — see above */

        /* The two layers at this rung, the nearer answering alone, and only a
         * directory naming what lies beneath it. */
        const char *above = manifest_claim_beneath(manifest_standing(c, pending, rung));
        if (!above) continue;

        *out_storage = arena_str_format(arena, "%s/%s", above, location + len + 1);
        if (!*out_storage) {
            return ERROR(ERR_MEMORY, "Failed to compose the name");
        }
        return NULL;
    }

    return mount_name(mounts, profile, location, arena, out_storage);
}

/**
 * By location, then by name
 *
 * A parent's location is a strict prefix of its child's and strcmp puts a prefix
 * before every extension, so lexicographic order settles a contested parent before
 * a deeper group's ascent reads it. The name breaks the tie, so the order is
 * total and the runs are stable whatever qsort does with equals.
 */
static int contest_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_location = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_location ? by_location
                       : strcmp((*ra)->storage_path, (*rb)->storage_path);
}

/**
 * Bytewise by name: the order a location's group is decided and reported in.
 */
static int name_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    return strcmp((*ra)->storage_path, (*rb)->storage_path);
}

/**
 * Decide every location this profile named twice, and record what did not stand
 *
 * The within-profile rule's last clause, run once the contribution is whole so
 * the ascent reads every tracked parent the profile has: **the name the profile
 * would give the location fresh** stands — beneath its tracked parent, else beneath
 * its deepest root, which is the binding's custom/ over the portable home/ over
 * the absolute root/ — and between names none of which it is, the bytewise-least.
 * Every other name is recorded against the one that stood (manifest_note_unkept).
 *
 * The group is the index's holder plus the run, sorted whole, so the holder is
 * a member and not a special case: every loser reads bytewise, the first-arrived
 * included, and the winner is group[0] unless a member *is* the fresh name. No
 * comparator carries `fresh` and no bool survives the loop.
 *
 * Two rows of one group can never share a name, so the order is total: the tree
 * holds one blob per path, the sheet one item per key, and the content-authority
 * rule contradicts the one name they can both carry at the blob, before either
 * name was resolved and long before the contest sees it.
 *
 * `fresh` is NULL when the location is a root of the profile — mount_name's own
 * answer, a root having no name — and the bytewise-least then stands, no name
 * being the fresh one there.
 *
 * Empty on every profile that names each of its locations once, which is the
 * whole cost on a branch this machine authored alone.
 *
 * @param manifest Target view — the mount table, and the unkept slice (must not
 *                 be NULL)
 * @param c The contribution being settled (must not be NULL)
 * @param contenders The rows that met a location already named (must not be NULL)
 * @param arena Arena for the groups and the composed names (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_settle(
    manifest_t *manifest,
    contribution_t *c,
    ptr_array_t *contenders,
    arena_t *arena
) {
    if (contenders->count == 0) return NULL;

    /* The contest, typed once: a ptr_array holds void *, and every read below
     * is a row's location or its name. */
    manifest_row_t **rows = (manifest_row_t **) contenders->items;

    qsort(rows, contenders->count, sizeof(*rows), contest_order);

    for (size_t i = 0; i < contenders->count;) {
        const char *location = rows[i]->filesystem_path;

        size_t n = 0;
        while (i + n < contenders->count &&
            strcmp(rows[i + n]->filesystem_path, location) == 0) n++;

        /* The group: the name that arrived first, and the ones that met it. */
        manifest_row_t **group = arena_calloc(arena, n + 1, sizeof(*group));
        if (!group) {
            return ERROR(ERR_MEMORY, "Failed to allocate a contested group");
        }
        group[0] = hashmap_get(c->index, location);
        for (size_t g = 0; g < n; g++) group[g + 1] = rows[i + g];
        qsort(group, n + 1, sizeof(*group), name_order);

        const char *fresh = NULL;
        error_t *err = manifest_ascend(
            c, manifest->mounts, c->profile, location, NULL, arena, &fresh
        );
        if (err) {
            return error_wrap(
                err, "Failed to name '%s' for profile '%s'", location, c->profile
            );
        }

        /* The fresh name if a member is it, else the bytewise-least. */
        manifest_row_t *winner = group[0];
        for (size_t g = 0; fresh && g <= n; g++) {
            if (strcmp(group[g]->storage_path, fresh) != 0) continue;
            winner = group[g];
            break;
        }

        err = hashmap_set(c->index, location, winner);
        if (err) {
            return error_wrap(err, "Failed to index a settled row");
        }
        for (size_t g = 0; g <= n; g++) {
            if (group[g] == winner) continue;
            err = manifest_note_unkept(
                manifest, c->profile, group[g], winner->storage_path, arena
            );
            if (err) return err;
        }

        i += n;
    }

    return NULL;
}

/**
 * Tree-walk callback that places the tree's blobs into the contribution
 *
 * The blob half of the per-profile step, and the whole of it that Git drives:
 * one entry at a time, in one walk, a finished manifest_row_t or nothing. In
 * order — the content gate (a blob under a storage label, and nothing else),
 * the name joined from the walk's root, the location it resolves to, the row,
 * its identity, this profile's claim over it, and the within-profile placement
 * rule that says whether it stands or contends.
 *
 * Identity — blob_oid, type and the Git-derived mode — is read off the borrowed
 * entry here, at the one boundary where the entry is valid, so no row carries
 * an opaque handle and nothing is duplicated to outlive the walk.
 *
 * @param root Directory path within tree (empty string for root level)
 * @param entry Git tree entry (borrowed — valid for callback duration only)
 * @param payload Pointer to claim_ctx
 * @return 0 to continue walk, -1 to stop on error
 */
static int manifest_claim_blob(
    const char *root, const git_tree_entry *entry, void *payload
) {
    struct claim_ctx *ctx = (struct claim_ctx *) payload;

    /* Only process blobs (files), skip directories — and, in the same line, a
     * gitlink, which is neither. dotta never writes one (sys/stage refuses the
     * mode), but `dotta git` and a foreign push can, and the view's answer is
     * that it claims nothing: no row, no location, nothing beneath it composed
     * through it. Stated rather than incidental, because a selection of rows is
     * what export copies (cmds/export.c collect_location) and it copies around
     * such an entry in silence. */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* The content gate: a managed path lives under a storage label, so the walk's
     * own root is the whole test — a blob at the branch root, or beneath a tree
     * no label names, is not content. dotta's own files (.dottaignore, .bootstrap,
     * .dotta/) sit there, and so does whatever else a hand or a tool left beside
     * them: a README, a LICENSE, a docs/ tree. Asked on the root, before the
     * join, so machinery costs no allocation and no unlabelled path reaches the
     * shape check below to be read as corruption. */
    if (!mount_spec_for_path(root)) {
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

    /* The entry name is Git's, not this machine's. mount_resolve joins a label's
     * tail verbatim on the strength of the path having been validated at its
     * write boundary, and for a branch this machine authored it was — but a branch
     * that arrived by clone or sync was validated by whoever wrote it, which is
     * to say not at all. A tree can name a subtree "..", so the shape has to be
     * checked where the tree is read, the same reason metadata's key loop checks
     * its own (core/metadata.c). Malformed here is corruption, not a lifecycle
     * stage: it takes the err branch below rather than the unbound note. */
    error_t *err = mount_validate_storage(storage_path);
    if (err) {
        ctx->error = error_wrap(
            err, "Invalid path in profile '%s'", ctx->profile
        );
        return -1;
    }

    /* This blob's claim, by the name the tree gave it — and, in the same answer,
     * the content authority. A path is a tree or a blob and the tree is the content
     * authority, so a DIRECTORY item standing at a blob's name is stale metadata:
     * it claims nothing here, not even its owner or group, and nothing in the
     * directory pass either, which reads the name back from this set rather than
     * asking the tree a second time. Asked before the resolve, because a claim
     * is read by name and a name needs no location — so the one rule covers the
     * blob this machine can place and the blob it cannot, and the health slice
     * counts one path once.
     *
     * The row a contradicted claim leaves carries the filemode floor and
     * `encrypted` false, which reads a ciphertext blob through the plaintext
     * comparison and prints [modified] on every load (core/workspace.c). The
     * contradiction is the branch's and that is where it gets fixed; the view
     * states it rather than repairs it. */
    const metadata_item_t *claim = metadata_lookup(ctx->metadata, storage_path);
    if (claim && claim->kind == PATH_KIND_DIRECTORY) {
        err = hashmap_set(ctx->contradicted, storage_path, NULL);
        if (err) {
            ctx->error = error_wrap(
                err, "Failed to record the stale claim '%s' of profile '%s'",
                storage_path, ctx->profile
            );
            return -1;
        }
        claim = NULL;
    }

    /* Convert storage path to filesystem path against the mount table.
     *
     * No location when storage_path is custom/... and ctx->profile has no target
     * binding on this machine — a normal lifecycle stage in a shared repository
     * (a clone before the target is chosen, a sync that pulled another machine's
     * custom/ claims, a revert that recommitted one), not corruption: no local
     * precondition can bind what another machine adds to the branch. The claim
     * contributes no row — nothing on this machine can place it — and is recorded
     * on the view (manifest_unbound) so the health consumers surface it; it is
     * never dropped in silence. Record-safe by construction: a record can only
     * exist where a binding existed at write time, so no anchor ever joins a
     * skipped claim and no orphan can be manufactured here. Genuine errors
     * (malformed path, OOM) propagate via the err branch. */
    const char *filesystem_path = NULL;
    err = mount_resolve(
        ctx->mounts, ctx->profile, storage_path, ctx->arena, &filesystem_path
    );
    if (err) {
        ctx->error = error_wrap(
            err, "Failed to convert path '%s' from profile '%s'",
            storage_path, ctx->profile
        );
        return -1;
    }
    if (!filesystem_path) {
        ctx->error = manifest_note_unbound(
            ctx->manifest, ctx->profile, storage_path, PATH_KIND_FILE, ctx->arena
        );
        return ctx->error ? -1 : 0;
    }

    /* Place the row, then say whether it stands. During this pass every row of
     * the contribution is a blob, so the first arm is exactly "nothing stands
     * here" and the second is exactly "a second name of this profile", for the
     * settle to decide. The sibling rule across profiles is manifest_layer's,
     * where an explicit claim takes a held location outright: that is the whole
     * difference between precedence and a profile naming one place twice. */
    const manifest_row_t *held = hashmap_get(ctx->contribution->index, filesystem_path);

    manifest_row_t *row = NULL;
    err = manifest_place(ctx->placed, filesystem_path, ctx->arena, &row);
    if (err) {
        ctx->error = err;
        return -1;
    }

    /* ctx->profile is the arena-backed name the step duplicated; the cast discards
     * its const decoration to fit the row's `char *profile` slot. */
    row->storage_path = storage_path;
    row->profile = (char *) ctx->profile;

    /* Extract identity from the borrowed tree entry (blob_oid, type, mode). */
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

    /* Apply this profile's claim (if any) to the row. The Git-derived defaults
     * set above are the floor; a claim may override mode and encrypted, and
     * contribute owner/group. A contender is a finished row and takes its own
     * claim like any other — the claim was read by the row's own name. */
    err = manifest_apply_claim(row, claim, ctx->arena);
    if (err) {
        /* The caller's outer error path propagates without freeing the view's
         * rows (spines + strings are arena-backed); a half-built row in a failed
         * build is never read. */
        ctx->error = error_wrap(
            err, "Failed to apply metadata to '%s'",
            row->storage_path
        );
        return -1;
    }

    err = !held || manifest_is_derived(held)
        ? hashmap_set(ctx->contribution->index, filesystem_path, row)
        : ptr_array_push(ctx->contenders, row);
    if (err) {
        ctx->error = error_wrap(
            err, "Failed to place '%s' of profile '%s'", storage_path, ctx->profile
        );
        return -1;
    }

    return 0;  /* Continue walk */
}

/**
 * One profile's contribution: the tree's blobs, then its sheet's directories
 *
 * The per-profile step both builders run, and the whole of the within-profile
 * rule. The contribution is registered here — its arena-backed name (every row
 * of it borrows the pointer), its own location index, and its slot in the view's
 * parallel arrays — so one function owns one profile's claims from the name to
 * the settled spine, and the builders hand over a tree and a name.
 *
 * The tree walk places every blob (manifest_claim_blob); then every DIRECTORY
 * item of the profile's sheet places its own, resolved against the mount table
 * the same way files are, subject to the three rules the loop below states. A
 * DIRECTORY item under a profile lacking a target binding on this host degrades
 * exactly as the file side does — no row, recorded on the view
 * (manifest_note_unbound) — so both kinds hold under one UNBOUND policy. The
 * settle then decides every location this profile named twice, and the tail cuts
 * the spine to what stands.
 *
 * The sheet is the tree's, loaded here and never handed in: it is a blob of the
 * very tree being read, so no caller of a builder chooses a policy for a fact
 * this step is the authority on.
 *
 * Memory: every allocation the view keeps lands in `arena`; the sheet is this
 * call's and is released at its tail (no row borrows it — each takes an arena
 * copy), and so are the step's three lists, whose lifetime is this call and not
 * the view's. On error, rows already placed are left as they are — the build
 * fails whole and the caller releases the indexes.
 *
 * @param manifest Target view (must not be NULL; its mount table is what places
 *                 rows)
 * @param repo Repository the tree's blobs are read from (must not be NULL)
 * @param tree The profile's tree (must not be NULL)
 * @param profile The profile whose claims these are (must not be NULL; copied)
 * @param arena Arena backing the contribution (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_contribute(
    manifest_t *manifest,
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    arena_t *arena
) {
    /* Register the contribution before anything can fail into it: the name is
     * arena-backed so the view never depends on the state's row cache, and the
     * index is allocated before profile_count counts the slot, so manifest_free
     * over a build that stopped partway frees exactly what was made. */
    contribution_t *c = &manifest->contributions[manifest->profile_count];

    c->profile = arena_strdup(arena, profile);
    if (!c->profile) {
        return ERROR(ERR_MEMORY, "Failed to duplicate profile name");
    }
    c->index = hashmap_borrow(128);
    if (!c->index) {
        return ERROR(ERR_MEMORY, "Failed to create contribution index");
    }
    manifest->profiles[manifest->profile_count++] = c->profile;

    /* This profile's claim sheet, read from the tree already open rather than
     * through a second ref/commit/tree lookup. Per-profile is the correctness
     * boundary for attribution — each profile places its own files and directories
     * via its own sheet, never via a cross-profile merge — and loading it here
     * is what makes that structural: the step is handed one tree and one name.
     * A tree without a sheet loads as an empty one (Git-derived defaults stand,
     * no directories); every error is a sheet that would not load, and the build
     * fails whole rather than read it as "no claims". */
    metadata_t *metadata = NULL;
    error_t *err = metadata_load_from_tree(repo, tree, c->profile, &metadata);
    if (err) {
        return error_wrap(
            err, "Failed to load metadata for profile '%s'", c->profile
        );
    }

    /* The step's three lists, spent when it returns (Rule 1 — they are valid
     * across one build, and the contribution is valid across the view's life):
     * every row this profile placed, in claim order; the rows that met a location
     * it had already named; and the sheet's names the tree contradicted. The
     * second is empty on every profile that names each of its locations once,
     * the third on every branch whose sheet its own tree agrees with.
     *
     * The third borrows its keys: each is the arena name the walk joined, which
     * outlives the map by the whole view. */
    ptr_array_t placed PTR_ARRAY_AUTO = { 0 };
    ptr_array_t contenders PTR_ARRAY_AUTO = { 0 };

    hashmap_t *contradicted = hashmap_borrow(8);
    if (!contradicted) {
        err = ERROR(ERR_MEMORY, "Failed to create contradiction index");
        goto cleanup;
    }

    /* The blobs, in one walk (manifest_claim_blob). The table is the view's,
     * and bindings are keyed by profile — which the callback feeds verbatim into
     * mount_resolve, so a custom/ claim of this profile places under this profile's
     * target and no other's. */
    struct claim_ctx ctx = {
        .manifest     = manifest,
        .contribution = c,
        .profile      = c->profile,
        .mounts       = manifest->mounts,
        .metadata     = metadata,
        .placed       = &placed,
        .contenders   = &contenders,
        .contradicted = contradicted,
        .arena        = arena,
        .error        = NULL
    };

    err = gitops_tree_walk(tree, manifest_claim_blob, &ctx);
    if (ctx.error) {
        /* The callback's error names the entry that failed; the walk's own is
         * the abort libgit2 stamped in answer to it — an echo of this call's
         * own decision, which names nothing and is freed rather than dropped. */
        error_free(err);
        err = ctx.error;
    }
    if (err) {
        err = error_wrap(
            err, "Failed to build manifest for profile '%s'", c->profile
        );
        goto cleanup;
    }

    /* The directory claims: every DIRECTORY item the profile's metadata carries.
     * A tree holds no empty directory, so the item is the claim's whole
     * footprint. */
    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);

    for (size_t j = 0; j < item_count; j++) {
        const metadata_item_t *item = items[j];
        if (item->kind != PATH_KIND_DIRECTORY) continue;

        /* The content authority, asked of the pass that read the tree: a path
         * is a tree or a blob, so an item the tree holds a blob at is stale
         * metadata and claims nothing. The blob pass met that name and contradicted
         * it there — by the name alone, before it resolved anything — so the
         * rule reaches the item this machine can place and the one it cannot
         * alike, and no arm below has to recognise a name it has no location
         * for. Asked before the tracked test too, whose order keeps the settle's
         * group free of two rows under one name. */
        if (hashmap_has(contradicted, item->key)) continue;

        /* Resolve before placing so the error path places nothing. */
        const char *filesystem_path = NULL;
        err = mount_resolve(
            manifest->mounts, c->profile, item->key, arena, &filesystem_path
        );
        if (err) {
            err = error_wrap(
                err, "Failed to convert path '%s' from profile '%s'",
                item->key, c->profile
            );
            break;
        }
        if (!filesystem_path) {
            /* The blob side's degrade contract, DIRECTORY kind: recorded, not
             * placed. The item's key is the metadata's, freed with it — the note
             * keeps an arena copy. */
            char *key = arena_strdup(arena, item->key);
            if (!key) {
                err = ERROR(
                    ERR_MEMORY, "Failed to duplicate storage path '%s' of profile '%s'",
                    item->key, c->profile
                );
                break;
            }
            err = manifest_note_unbound(
                manifest, c->profile, key, PATH_KIND_DIRECTORY, arena
            );
            if (err) break;
            continue;
        }

        const manifest_row_t *held = hashmap_get(c->index, filesystem_path);

        /* A derived claim never takes a held slot: it is a consequence of an
         * older name, not a source of new ones. Explicit outranks derived within
         * one profile as across them, so a tracked item falls through to the
         * placement rule below and takes a derived row's slot there.
         *
         * Ancestors are structurally shared where claims are per-profile and
         * precedence-resolved, and two profiles that traverse the same directory
         * derive it identically: their claims carry no intent to conflict, so
         * they do not compete. That is manifest_layer's half of the rule; here
         * the two chains are one profile's own, and the first placed stands —
         * the row says the profile holds a subtree beneath the location, never
         * which name its subtree runs through.
         *
         * The first placed is the sheet's first key (items arrive in insertion
         * order and the writer sorts, core/metadata.c), and the tie-break settles
         * more than a name: a derived claim carries the mode, owner and group
         * dotta creates the directory with, and two chains captured at different
         * moments can disagree about them — 0700 under home/jail/etc, 0755 under
         * custom/etc, one location. Neither is the truer statement, both being
         * what disk held when a walk passed through, so the tie is stated here
         * rather than decided. Nothing is recorded either: manifest_unkept is
         * names, and a derived claim named nothing. */
        if (held && !item->tracked) continue;

        manifest_row_t *row = NULL;
        err = manifest_place(&placed, filesystem_path, arena, &row);
        if (err) break;

        /* A directory row is claimed from metadata alone: blob_oid stays zero
         * and encrypted false; owner, group and the class are the item's, and
         * the mode is the claim or the floor — the row leaves the build total. */
        row->storage_path = arena_strdup(arena, item->key);
        row->profile = (char *) c->profile;
        row->type = PATH_TYPE_DIRECTORY;
        row->tracked = item->tracked;
        row->mode = item->mode != MODE_UNCLAIMED ? item->mode : DIR_MODE_DEFAULT;
        row->owner = item->owner ? arena_strdup(arena, item->owner) : NULL;
        row->group = item->group ? arena_strdup(arena, item->group) : NULL;

        /* The three are refused together, where every other allocation in this
         * file is refused on the line that made it: the row above is one statement,
         * and the only failure any of its copies has is the arena's — one
         * exhaustion, named by the path and the profile that were being placed
         * when it came. */
        if (!row->storage_path ||
            (item->owner && !row->owner) || (item->group && !row->group)) {
            err = ERROR(
                ERR_MEMORY, "Failed to copy directory row fields for '%s' in profile '%s'",
                item->key, c->profile
            );
            break;
        }

        /* The placement rule, as the blob pass states it. */
        err = !held || manifest_is_derived(held)
            ? hashmap_set(c->index, filesystem_path, row)
            : ptr_array_push(&contenders, row);
        if (err) {
            err = error_wrap(
                err, "Failed to place '%s' of profile '%s'", item->key, c->profile
            );
            break;
        }
    }
    if (err) goto cleanup;

    /* Every location this profile named twice, decided once. */
    err = manifest_settle(manifest, c, &contenders, arena);
    if (err) goto cleanup;

    /* The contribution's rows: what the index points at, in claim order. A name
     * that lost and a derived claim an explicit one retook stay in the arena
     * and leave the slice. Sized exactly — the index is the count. */
    size_t standing = hashmap_size(c->index);
    if (standing > 0) {
        c->rows = arena_calloc(arena, standing, sizeof(*c->rows));
        if (!c->rows) {
            err = ERROR(
                ERR_MEMORY, "Failed to allocate rows for profile '%s'", c->profile
            );
            goto cleanup;
        }
        for (size_t j = 0; j < placed.count; j++) {
            manifest_row_t *row = placed.items[j];
            if (hashmap_get(c->index, row->filesystem_path) == row) {
                c->rows[c->count++] = row;
            }
        }
    }

cleanup:
    hashmap_free(contradicted, NULL);
    metadata_free(metadata);
    return err;
}

/**
 * Precedence over the settled contributions, and the winners' spine
 *
 * Today's cross-profile rule, applied to finished contributions instead of to
 * rows mid-build: for each contribution in precedence order, an explicit row
 * takes the location whatever stands there, and a derived one only fills an empty
 * one — two profiles that traverse the same directory derive it identically,
 * their claims carry no intent to conflict, and the first to name the path holds
 * it, so the row's owner does not move when a profile above it is enabled and
 * no reassignment churn appears in the receipts over a directory nobody named.
 *
 * The spine is then cut once, exactly, from what the index points at, in claim
 * order across the contributions — so a path a higher profile overrides sits at
 * the winner's place. Row order is unspecified and this is what there is of it.
 *
 * Run once at the tail of each builder, so manifest_lookup is never asked
 * mid-build. An empty view allocates no spine and manifest_rows answers an empty
 * slice.
 *
 * @param manifest The view whose contributions are all settled (must not be NULL)
 * @param arena Arena for the spine (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *manifest_layer(manifest_t *manifest, arena_t *arena) {
    for (size_t i = 0; i < manifest->profile_count; i++) {
        const contribution_t *c = &manifest->contributions[i];
        for (size_t j = 0; j < c->count; j++) {
            manifest_row_t *row = c->rows[j];

            /* A derived row only fills an empty location; an explicit one takes
             * whatever stands there. */
            if (manifest_is_derived(row) &&
                hashmap_has(manifest->index, row->filesystem_path)) continue;

            error_t *err = hashmap_set(manifest->index, row->filesystem_path, row);
            if (err) return error_wrap(err, "Failed to index manifest row");
        }
    }

    size_t standing = hashmap_size(manifest->index);
    if (standing == 0) return NULL;

    manifest->rows = arena_calloc(arena, standing, sizeof(*manifest->rows));
    if (!manifest->rows) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest spine");
    }
    for (size_t i = 0; i < manifest->profile_count; i++) {
        const contribution_t *c = &manifest->contributions[i];
        for (size_t j = 0; j < c->count; j++) {
            manifest_row_t *row = c->rows[j];
            if (hashmap_get(manifest->index, row->filesystem_path) == row) {
                manifest->rows[manifest->count++] = row;
            }
        }
    }

    return NULL;
}

/**
 * Allocate a fresh manifest_t, ready for the per-profile step.
 *
 * The view struct, the contributions array and the profile list beside it (both
 * sized for the profiles the build will walk at most) are arena-allocated; each
 * contribution fills its own slot as it is registered (manifest_contribute).
 * The index hashmap is heap-allocated (borrowed-key mode — keys live in the
 * caller's arena and survive the hashmap's lifetime). No spine is allocated here:
 * each is cut once, exactly, from the index that decides it.
 *
 * On error, the function returns ERR_MEMORY and *out is NULL; arena allocations
 * are abandoned to the arena and no heap allocation is outstanding.
 */
static error_t *manifest_allocate(
    arena_t *arena,
    size_t index_capacity,
    size_t profile_capacity,
    manifest_t **out
) {
    *out = NULL;

    manifest_t *manifest = arena_calloc(arena, 1, sizeof(*manifest));
    if (!manifest) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    if (profile_capacity > 0) {
        manifest->contributions = arena_calloc(
            arena, profile_capacity, sizeof(*manifest->contributions)
        );
        manifest->profiles = arena_calloc(
            arena, profile_capacity, sizeof(*manifest->profiles)
        );
        if (!manifest->contributions || !manifest->profiles) {
            return ERROR(ERR_MEMORY, "Failed to allocate manifest contributions");
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
 * The table the enabled rows describe
 *
 * State-aware adapter that materializes enabled_profiles' (name, target) rows
 * into mount_t entries and delegates the augmentation (HOME, canonical HOME,
 * root sentinel) to mount_table_build. The one derivation of this machine's
 * topology from the rows: manifest_build runs it below before it places a row,
 * and the dispatcher runs it alone for a command that declares `mounts` without
 * the view, so the two read one value from one instant's rows.
 */
error_t *manifest_mount_table(
    const state_t *state,
    arena_t *arena,
    mount_table_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    state_profiles_t rows = state_peek_profiles(state);

    mount_t *mounts = NULL;
    if (rows.count > 0) {
        mounts = arena_calloc(arena, rows.count, sizeof(*mounts));
        if (!mounts) {
            return ERROR(ERR_MEMORY, "Failed to allocate mounts");
        }
        for (size_t i = 0; i < rows.count; i++) {
            mounts[i] = (mount_t){
                .profile = rows.entries[i].name,
                .target = rows.entries[i].target
            };
        }
    }

    return mount_table_build(arena, mounts, rows.count, out);
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
    state_profiles_t profiles = state_peek_profiles(state);

    /* The topology the same rows describe — each profile's target, and this
     * machine's $HOME — built here, from the rows of this instant, so a custom/
     * path always resolves under the target the row it came from carries. */
    mount_table_t *mounts = NULL;
    error_t *err = manifest_mount_table(state, arena, &mounts);
    if (err) {
        return error_wrap(err, "Failed to build mount table");
    }

    manifest_t *manifest = NULL;
    err = manifest_allocate(arena, 128, profiles.count, &manifest);
    if (err) return err;
    manifest->mounts = mounts;

    /* One contribution per profile, in order; precedence runs over them once
     * every one of them is settled. */
    for (size_t i = 0; i < profiles.count; i++) {
        const char *profile = profiles.entries[i].name;

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

        /* Load tree for this profile (scoped to iteration). */
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'", profile
            );
            goto cleanup;
        }

        /* The profile's claims: its own sheet, read by the step from the tree
         * just opened, and its blobs. One view, many sheets — each read under
         * the name whose claims it is. The name the step copies is what every
         * row of it borrows, so the view never depends on the state's row cache. */
        err = manifest_contribute(manifest, repo, tree, profile, arena);
        git_tree_free(tree);

        if (err) goto cleanup;
    }

    err = manifest_layer(manifest, arena);
    if (err) goto cleanup;

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
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    manifest_t *manifest = NULL;
    error_t *err = manifest_allocate(arena, 128, 1, &manifest);
    if (err) return err;

    /* mounts borrows from a function parameter — it outlives the tree walk, and
     * the table outlives the view (manifest_mounts lends it). The sheet is the
     * step's, loaded from `tree` and released there. */
    manifest->mounts = mounts;

    /* One contribution, settled and layered like any other, so a tree view answers
     * manifest_lookup_claim and manifest_name exactly as an enabled view does. */
    err = manifest_contribute(manifest, repo, tree, profile, arena);
    if (err) goto cleanup;

    err = manifest_layer(manifest, arena);
    if (err) goto cleanup;

    *out = manifest;
    return NULL;

cleanup:
    manifest_free(manifest);
    return err;
}

/**
 * Build the manifest from a branch's tip
 *
 * The load is wrapped and the build is not: a build's own failures already name
 * the profile they were reading.
 */
error_t *manifest_build_branch(
    git_repository *repo,
    const char *branch,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, branch, &tree, NULL);
    if (err) {
        return error_wrap(err, "Failed to load tree for profile '%s'", branch);
    }

    err = manifest_build_tree(repo, tree, branch, mounts, arena, out);
    git_tree_free(tree);

    return err;
}

/**
 * Every winning row of the view, both kinds, unordered
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
 * The table the rows were placed by
 */
const mount_table_t *manifest_mounts(const manifest_t *manifest) {
    if (!manifest) return NULL;
    return manifest->mounts;
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
 * The names the profiles hold for locations they also name otherwise
 */
manifest_unkept_t manifest_unkept(const manifest_t *manifest) {
    if (!manifest) return (manifest_unkept_t){ 0 };
    return (manifest_unkept_t){
        .entries = manifest->unkept,
        .count = manifest->unkept_count,
    };
}

/**
 * The contribution `profile` placed, or NULL when the view has none for it
 *
 * Linear over the profiles: the enabled set, so a handful of strcmp. A NULL asker
 * has no contribution — it is the shared roots and nothing else (manifest_name).
 */
static const contribution_t *manifest_contribution(
    const manifest_t *manifest, const char *profile
) {
    if (!profile) return NULL;

    for (size_t i = 0; i < manifest->profile_count; i++) {
        if (strcmp(manifest->contributions[i].profile, profile) == 0) {
            return &manifest->contributions[i];
        }
    }

    return NULL;
}

/**
 * The row `profile` holds at `filesystem_path` in its own contribution
 */
const manifest_row_t *manifest_lookup_claim(
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path
) {
    if (!manifest || !filesystem_path) return NULL;

    const contribution_t *c = manifest_contribution(manifest, profile);

    return c ? hashmap_get(c->index, filesystem_path) : NULL;
}

/**
 * What `profile` calls `location` under this view
 *
 * The leaf clause and the ascent, over the one two-layer read (manifest_standing):
 * the claim standing at the location names it whatever its kind — this command's
 * own if it has admitted one there, since it has already named this very location
 * — and a location nothing stands at falls through to the ascent, the profile
 * holding no row there or holding a derived one, which is no claim.
 *
 * The answer is the caller's arena's whichever rung produced it: the leaf clause
 * copies, which costs one strdup on a call made once per argument and buys the
 * absence of a contract where three lifetimes meet.
 */
error_t *manifest_name(
    const manifest_t *manifest,
    const char *profile,
    const char *location,
    const hashmap_t *pending,
    arena_t *arena,
    const char **out_storage
) {
    CHECK_NULL(manifest);
    CHECK_NULL(location);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    const contribution_t *c = manifest_contribution(manifest, profile);

    const char *here = manifest_standing(c, pending, location).storage_path;
    if (here) {
        *out_storage = arena_strdup(arena, here);
        if (!*out_storage) {
            return ERROR(ERR_MEMORY, "Failed to copy the name");
        }
        return NULL;
    }

    return manifest_ascend(
        c, manifest->mounts, profile, location, pending, arena, out_storage
    );
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
 * Look up a row by its claim
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *storage_path,
    const char *profile
) {
    if (!manifest || !storage_path || !profile) return NULL;

    for (size_t i = 0; i < manifest->count; i++) {
        const manifest_row_t *row = manifest->rows[i];
        if (strcmp(row->profile, profile) == 0 &&
            strcmp(row->storage_path, storage_path) == 0) {
            return row;
        }
    }
    return NULL;
}

/**
 * How many rows hold this name, and the row when one does
 */
size_t manifest_holders(
    const manifest_t *manifest,
    const char *storage_path,
    const manifest_row_t **out_row
) {
    *out_row = NULL;
    if (!manifest || !storage_path) return 0;

    size_t count = 0;
    const manifest_row_t *held = NULL;
    for (size_t i = 0; i < manifest->count; i++) {
        if (strcmp(manifest->rows[i]->storage_path, storage_path) == 0) {
            held = manifest->rows[i];
            count++;
        }
    }
    if (count == 1) *out_row = held;
    return count;
}

/**
 * Free a manifest
 *
 * Every heap index the build made: one per registered contribution, then the
 * view's own. A build that stopped partway registered as many contributions as
 * it counted, and each index is allocated before its slot is counted, so this
 * frees exactly what was made.
 */
void manifest_free(manifest_t *manifest) {
    if (!manifest) return;
    for (size_t i = 0; i < manifest->profile_count; i++) {
        if (manifest->contributions[i].index) {
            hashmap_free(manifest->contributions[i].index, NULL);
            manifest->contributions[i].index = NULL;
        }
    }
    if (manifest->index) {
        hashmap_free(manifest->index, NULL);
        manifest->index = NULL;
    }
    /* The struct, the spines and the rows are the arena's. */
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

        /* `tracked` sits beside the mode for the same reason the mode is here:
         * a directory that stops being a scan root and a convergence target —
         * or becomes one — is a different promise at the path, and a class flip
         * usually carries the same mode across, so without this term the receipt
         * would call it unchanged. */
        const manifest_row_t *old = manifest_lookup(before, row->filesystem_path);
        if (!old) {
            slot->added++;
        } else if (!git_oid_equal(&old->blob_oid, &row->blob_oid) ||
            old->type != row->type || old->mode != row->mode ||
            old->tracked != row->tracked) {
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
