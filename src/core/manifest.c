/**
 * manifest.c - The view: implementation
 *
 * Two builders, manifest_build (every enabled profile, in precedence order) and
 * manifest_build_profile (one profile), share one per-profile step,
 * manifest_contribute, that places the claims a profile's walk shows
 * (core/profiles.h) as manifest_row_t rows directly. There is no persistence
 * step and no bridge type: the view is computed into the caller's arena and read
 * through the accessors below.
 *
 * Key patterns:
 *   - Two layers, built in two moves (core/manifest.h): manifest_contribute places
 *     one profile's claims whole into that profile's own contribution — its
 *     explicit claims, the within-profile rule settled by manifest_settle, and
 *     its derived claims apart from them — and manifest_layer then runs precedence
 *     over the settled contributions, once, into the view's index: the explicit
 *     claims first, each contribution's in its own precedence, then the derived,
 *     then the layer's rung at each place a blob lost, noting each claim a
 *     profile's own claims leave no room where its check finds it. Nothing
 *     published is ever rewritten: a claim that stands nowhere keeps its own
 *     row and simply leaves the slice, which is what lets a claim be read after
 *     another stands over it (manifest_lookup_claim) and what makes an index
 *     the one thing that says who stands where.
 *   - One decode, placed: the per-profile step walks the profile it is handed
 *     (core/profiles.h profile_walk), which reads its own tree's sheet — no caller
 *     supplies one — and shows each claim decoded, the blob's identity read off
 *     the borrowed tree entry, its blobs first and its directory claims after;
 *     the step places each as it arrives (single profile per row, no cross-profile
 *     merge — storage_path collisions across profiles with distinct target values
 *     are kept apart).
 *   - One naming rule, one body: manifest_ascend is what the settle asks for
 *     the fresh name of a contested path and what manifest_name answers callers
 *     with, so the name the view keeps and the name the namer gives are the same
 *     answer by construction. The choice between a path's names has one body
 *     too (manifest_decide), asked by the settle over the group it has just built
 *     and again by every namer that reads that path, because a command's own
 *     uncommitted claims change what the path would be called fresh. One claim
 *     shape beneath both: the two layers a namer reads speak manifest_claim_t,
 *     so the leaf and the rung ask one producer (manifest_kept) and differ only
 *     in which of its two projections they take.
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
#include "core/profiles.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * One profile's claims, placed under the topology, precedence aside
 *
 * Two decisions, kept apart from placement on, each in an index of its own: the
 * explicit claim kept at a path — a blob of any type, a tracked directory — one
 * a path, the settle deciding where the profile names one twice; and the derived
 * claim placed there first, the profile's chain through the path. A derived row
 * is no claim at all, naming neither itself nor what lies beneath it
 * (core/manifest.h manifest_is_derived), so it never contends and no namer reads
 * it. It is kept whatever the profile claims explicitly at its path: whether it
 * stands is the layer's question, asked of every profile at once (manifest_layer).
 *
 * `rows` is allocated once at the step's tail, sized exactly from the two indexes,
 * and nothing on it is ever rewritten: a name that lost the path, and a second
 * chain through one, stay in the arena and simply leave the slice.
 *
 * Every index is the build's arena's, as the view's own is; their keys borrow
 * the arena-backed path each row carries.
 */
typedef struct {
    const char *profile;           /* Arena-backed; the same pointer every row of it carries */
    manifest_row_t **rows;         /* Every row each index keeps, in claim order (arena, exact) */
    size_t count;                  /* Rows in it */
    hashmap_t *explicit;           /* path → the explicit claim kept there (arena) */
    hashmap_t *derived;            /* path → the derived claim placed there first (arena) */

    /* Every name the profile holds at a path it names more than once: the settle's
     * own group, NULL-terminated, in name order. NULL until a settle happens —
     * which is never, on a profile that names each of its paths once. The group
     * outlives the contest because the decision does: manifest_kept re-asks it
     * wherever a name is read, an asker's own claims being able to change which
     * name the next settle keeps, and manifest_holds_name reads it to answer
     * whether a name is one the profile already holds.
     *
     * Every member is an explicit row: a derived claim never contends, held apart
     * (manifest_place_claim), so no reader of a group filters derived. */
    hashmap_t *contested;          /* path → manifest_row_t ** (arena) */
} contribution_t;

/**
 * Manifest — the view
 *
 * The contributions, in precedence order, and the index precedence leaves over
 * them. Rows are allocated one by one from the caller's arena and are stable
 * from the moment they are allocated, so every index stores row pointers directly.
 * Each spine — a contribution's and the view's — is cut once, exactly, from what
 * its indexes point at; there is no growth and no reallocation, and manifest_rows
 * hands the view's out as the public slice.
 *
 * The health channel's slices — what the build could not make a row of — are
 * flat arena arrays grown by arena_grow where each entry is noted, lent whole,
 * and empty on the common build: no allocation until the first note.
 */
struct manifest {
    /* The contributions, one per profile the build walks, in precedence order,
     * and their names beside them: profiles[i] names contributions[i], one array
     * the public projection of the other, kept because manifest_profiles owes a
     * contiguous array of names. */
    contribution_t *contributions;               /* Arena; one per profile */
    const char **profiles;                       /* Arena; their names, the rows' own pointers */
    size_t profile_count;                        /* Both arrays' count */

    /* Precedence over the settled contributions: the index, one row standing
     * per path — a claim, or the layer's rung — and the spine cut once from it
     * at layering (manifest_layer). */
    const manifest_row_t **rows;                 /* Arena, exact; the rows standing */
    size_t count;                                /* Rows in the spine */
    hashmap_t *index;                            /* Arena; path → the row standing there */

    /* The table the rows were placed by, lent back by manifest_mounts: the build's
     * own, derived from the rows it read, or, for one profile's view, the
     * caller's. */
    const mount_table_t *mounts;                 /* The build's, or the caller's */

    /* The claims the build could not place: no target binding here (manifest_unbound) */
    manifest_unbound_claim_t *unbound;           /* Arena; grouped by profile, in build order */
    size_t unbound_count;
    size_t unbound_capacity;

    /* The names the settle did not keep: another is kept at the path (manifest_unkept) */
    manifest_unkept_claim_t *unkept;             /* Arena; grouped by profile, in build order */
    size_t unkept_count;
    size_t unkept_capacity;

    /* The tracked claims a profile's own tree contradicts (manifest_contradicted) */
    manifest_contradicted_claim_t *contradicted; /* Arena; grouped by profile, in build order */
    size_t contradicted_count;
    size_t contradicted_capacity;

    /* The enabled profiles the build found no branch for (manifest_missing) */
    const char **missing;                        /* Arena; in the enabled set's order */
    size_t missing_count;
    size_t missing_capacity;
};

/**
 * The claim walk: what one walk of one profile carries to place its claims
 *
 * Everything the walk's visitor needs to place one profile's claims: the view
 * and the contribution being filled, and the two lists the step spends. Handed
 * to each profile's walk once and read at O(1) per claim — and to its second
 * question, the claims its tree contradicts, whose visitor reads the view, the
 * profile's name and the arena alone (manifest_note_claim).
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership — the mount table and the unbound
 *             slice are read and written through it
 * - contribution: the profile's own, borrowed from manifest_contribute: its
 *             arena-backed name (every row of this profile borrows the pointer,
 *             and the table is keyed by it to place a custom/ claim) and its
 *             two indexes
 * - placed: the step's build-local list, borrowed — every row this profile placed,
 *             spent when manifest_contribute returns
 * - contenders: the rows that arrived at a path the profile had already named,
 *             grown in the arena as rows (arena_grow), so the settle sorts them
 *             where they are; spent with the walk
 * - arena: borrowed, must not be NULL; per-row strings are abandoned to it
 *
 * The claims arrive decoded and lent for the visit (core/profiles.h profile_walk),
 * so the walk carries no sheet: the profile read it.
 */
typedef struct {
    manifest_t *manifest;         /* Target view (modified by the visitor) */
    contribution_t *contribution; /* The profile's own claims and their indexes */
    ptr_array_t *placed;          /* Every row this step placed, in claim order */
    manifest_row_t **contenders;  /* The rows that met a path already named */
    size_t contender_count;
    size_t contender_capacity;
    arena_t *arena;               /* Arena for allocations (must not be NULL) */
} claim_walk_t;

/**
 * A row of this contribution at `filesystem_path`: allocated and on the list of
 * everything the profile placed
 *
 * Whether it is *kept* at the path is the caller's next line: the index of its
 * class takes it, the contest does, or — a second chain through a path — neither
 * does. Nothing here is ever reset or overwritten: a name that loses keeps its
 * own row and leaves the slice at the settle, which is what lets a lower profile's
 * claim be read after a higher one wins the path (manifest_lookup_claim) and
 * what makes an index the one thing that says who stands where.
 *
 * `filesystem_path` is arena-borrowed from mount_resolve; the cast discards the
 * const qualifier its output type carries. The row keeps it as its key for the
 * view's life. Two names at one path produce two arena strings with equal content,
 * and every index keys by content — no string is shared, and a hashmap_set that
 * replaces a value keeps the key pointer it was first given, which stays valid
 * and equal for the arena's lifetime.
 *
 * @param placed The step's list of every row placed (must not be NULL)
 * @param filesystem_path Arena-backed path the row is keyed by (must not be NULL)
 * @param arena Arena for the row (must not be NULL)
 * @return The placed row, zero but for filesystem_path
 */
static manifest_row_t *manifest_place(
    ptr_array_t *placed,
    const char *filesystem_path,
    arena_t *arena
) {
    manifest_row_t *row = arena_calloc(arena, 1, sizeof(*row));
    row->filesystem_path = filesystem_path;
    ptr_array_push(placed, row);

    return row;
}

/**
 * Record one claim the build could not place
 *
 * The health primitive a claim the placement cannot resolve is spent through:
 * appends (profile, storage_path, kind) to the view's health slice. No dedup,
 * and none possible — the profile's walk shows a name once (core/profiles.h
 * profile_walk): a name the tree holds a blob at, or a sheet key it holds no
 * blob at or above, the content-authority rule having contradicted the rest before
 * anything was resolved. And a tree holds one blob per path, a sheet one directory
 * claim per key.
 *
 * The slice grows in the arena (arena_grow). Both strings must be arena-backed
 * by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param storage_path Arena-backed storage path (must not be NULL)
 * @param kind The claim's kind (FILE for tree blobs, DIRECTORY for metadata items)
 * @param arena Arena for the array growth (must not be NULL)
 */
static void manifest_note_unbound(
    manifest_t *manifest,
    const char *profile,
    const char *storage_path,
    path_kind_t kind,
    arena_t *arena
) {
    manifest->unbound = arena_grow(
        arena, manifest->unbound, &manifest->unbound_capacity,
        manifest->unbound_count + 1, sizeof(*manifest->unbound)
    );

    manifest->unbound[manifest->unbound_count++] = (manifest_unbound_claim_t){
        .profile = profile,
        .storage_path = storage_path,
        .kind = kind,
    };
}

/**
 * Record one name the contribution did not keep
 *
 * The health primitive the settle spends its losers through: appends (profile,
 * name, kind) against the name that stood at the path. No dedup — a row is in
 * one group and is recorded once if it loses, and no two rows of one profile
 * share a name (the tree holds one blob per path, the sheet one directory claim
 * per key, and the content-authority rule settles the one name they can both
 * carry before the contest sees it).
 *
 * The slice grows in the arena, as the unbound one does. Every string must be
 * arena-backed by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param row The row whose name was not kept (must not be NULL)
 * @param kept The name that was (must not be NULL)
 * @param arena Arena for the array growth (must not be NULL)
 */
static void manifest_note_unkept(
    manifest_t *manifest,
    const char *profile,
    const manifest_row_t *row,
    const char *kept,
    arena_t *arena
) {
    manifest->unkept = arena_grow(
        arena, manifest->unkept, &manifest->unkept_capacity,
        manifest->unkept_count + 1, sizeof(*manifest->unkept)
    );

    manifest->unkept[manifest->unkept_count++] = (manifest_unkept_claim_t){
        .profile = profile,
        .storage_path = row->storage_path,
        .kind = path_type_kind(row->type),
        .kept = kept,
        .filesystem_path = row->filesystem_path,
    };
}

/**
 * Record one claim a profile's own claims leave no room
 *
 * The health primitive both of the slice's producers spend through: the documents',
 * a tracked claim the profile's own tree contradicts (manifest_note_claim), and
 * this machine's, a claim the layer finds beneath a standing blob of its own or
 * a blob of its own whose place its claims beneath take (manifest_layer). Appends
 * (profile, name, kind) against what leaves it no room, which is one of two by
 * where it stands — the blob at or above it, or the directory taking its place
 * — the other NULL. No dedup, and none needed: a claim the tree contradicts is
 * one the walk never shows, and the layer decides each claim the walk shows once.
 *
 * The slice grows in the arena, as the others do. Every string must be arena-backed
 * by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param storage_path The claim that stands nowhere (must not be NULL)
 * @param kind Its kind
 * @param blob_above The blob at its name or at a rung above it, or NULL
 * @param place The name the directory taking its place has, or NULL
 * @param arena Arena for the array growth (must not be NULL)
 */
static void manifest_note_contradicted(
    manifest_t *manifest,
    const char *profile,
    const char *storage_path,
    path_kind_t kind,
    const char *blob_above,
    const char *place,
    arena_t *arena
) {
    manifest->contradicted = arena_grow(
        arena, manifest->contradicted, &manifest->contradicted_capacity,
        manifest->contradicted_count + 1, sizeof(*manifest->contradicted)
    );

    manifest->contradicted[manifest->contradicted_count++] = (manifest_contradicted_claim_t){
        .profile = profile,
        .storage_path = storage_path,
        .kind = kind,
        .blob_above = blob_above,
        .place = place,
    };
}

/**
 * Record one enabled profile the build found no branch for
 *
 * The health primitive the build spends a missing branch through, the profile
 * contributing nothing. No dedup, and none needed — the enabled set names each
 * profile once.
 *
 * The slice grows in the arena, as the other two do. The name must be arena-backed
 * by the caller; the entry borrows it for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param arena Arena for the array growth (must not be NULL)
 */
static void manifest_note_missing(
    manifest_t *manifest,
    const char *profile,
    arena_t *arena
) {
    manifest->missing = arena_grow(
        arena, manifest->missing, &manifest->missing_capacity,
        manifest->missing_count + 1, sizeof(*manifest->missing)
    );

    manifest->missing[manifest->missing_count++] = profile;
}

/**
 * What one naming question is asked under
 *
 * The profile's own contribution, the table its rows were placed by, the asker,
 * the claims this command has admitted and not yet committed, and the arena the
 * answer lands in. Built once per manifest_name and once per settle; the three
 * functions below thread it and read nothing else.
 *
 * `c` is NULL for an asker the view has no contribution for — the shared roots
 * and nothing else, as the table reads a NULL asker (infra/mount.h).
 */
typedef struct {
    const contribution_t *c;       /* The asker's own claims, or NULL */
    const mount_table_t *mounts;   /* The table those claims were placed by */
    const char *profile;           /* The asker; the contribution's own name when it has one */
    const hashmap_t *pending;      /* This command's uncommitted claims, or NULL */
    arena_t *arena;                /* Arena that owns every composed answer */
} naming_t;

/* The ascent and the kept claim are one rule read from two ends, and each asks
 * the other: a name is composed from the claims kept above the path, and the
 * claim kept where the profile names one path twice is what the next settle will
 * keep there — which is the ascent's own answer under this command's claims.
 * The pair terminates because the ascent reads rungs strictly above the path it
 * is asked about, so every turn is a strictly shorter path and the depth is bounded
 * by the rungs; it is entered at all only at a contested path. */
static const char *manifest_ascend(const naming_t *n, const char *filesystem_path);

/**
 * A row as a namer reads it
 *
 * The projection both layers meet in (core/manifest.h manifest_claim_t): a row
 * names its own path, its kind saying whether anything can be named beneath —
 * every row a namer reads is an explicit claim, the contribution holding the
 * derived apart (contribution_t). NULL projects to no claim, which is the answer
 * a path the profile holds nothing at is owed.
 */
static manifest_claim_t manifest_row_claim(const manifest_row_t *row) {
    if (!row) return (manifest_claim_t){ 0 };

    return (manifest_claim_t){
        .storage_path = row->storage_path,
        .kind = path_type_kind(row->type),
    };
}

/**
 * Which of the names in a group the contribution keeps at `filesystem_path`
 *
 * The settle's last clause, on its own so that it has one body: **the name the
 * profile would give the path fresh** is kept where the profile holds it, and
 * the bytewise-least — the group's own head, the array being sorted by name —
 * is kept where it does not.
 *
 * Two askers, one answer. manifest_settle asks it over the group it has just
 * built, with no pending layer, and stores the result; manifest_kept asks it
 * again wherever a name is read, because an asker's own uncommitted claims change
 * what the path's ascent composes and therefore which name the next settle will
 * keep (209 C3 §1.10). Spelling the rule once is what keeps the name the view
 * keeps and the name a namer gives from drifting apart.
 *
 * At a root of the profile the fresh name is the word the table's tie chose, so
 * a group holding both `home` and `root` on a machine whose HOME is "/" keeps
 * `root` — the portable reading, and the one every path beneath that directory
 * composes under (infra/mount.h mount_root_above). Read the other way the view
 * and the table would disagree about one directory: the group would keep `home`
 * as the bytewise-least while the ascent named `/etc/x` beneath the sentinel.
 *
 * @param n What the question is asked under (must not be NULL)
 * @param filesystem_path The path the group contends for (must not be NULL)
 * @param group Every name the profile holds there, NULL-terminated, in name order
 *              (must not be NULL, and must hold at least one row)
 * @return The row whose name is kept; never NULL
 */
static manifest_row_t *manifest_decide(
    const naming_t *n, const char *filesystem_path, manifest_row_t **group
) {
    const char *fresh = manifest_ascend(n, filesystem_path);

    /* The fresh name if a member is it, else the bytewise-least. */
    for (size_t g = 0; group[g]; g++) {
        if (strcmp(group[g]->storage_path, fresh) == 0) return group[g];
    }
    return group[0];
}

/**
 * The claim kept at `filesystem_path` for this asker
 *
 * Three arms, and the first that speaks answers. Where the profile names the
 * path more than once, **the settle answers**: which of a profile's names is
 * kept somewhere is the settle's question and never a single claim's, so it is
 * asked here under this command's claims rather than read off the last build.
 * That is what makes a capture land on the name the machine will use: a claim
 * admitted above a contested path changes what the path's ascent composes, and
 * with it the name the next settle keeps (209 C3 §1.10). A verb admits at such
 * a path only a name the profile already holds (core/manifest.h
 * manifest_holds_name), so the group is the whole of what that settle will decide
 * over and the pending layer cannot add to it.
 *
 * Where the profile names the path once or not at all, the two layers a namer
 * reads answer, nearest first. A claim the command has admitted and not yet
 * committed answers alone, whatever its kind: it is the nearer statement about
 * the place, so a staged FILE names its own path and nothing under it, standing
 * in for a tracked directory the profile holds at the same path exactly as it
 * will once committed. Where the command claimed nothing the profile's own
 * committed row speaks, projected into the same pair.
 *
 * The answer is what the profile's next contribution will keep at the path, given
 * the claims the asker has admitted **so far**: naming is a snapshot taken when
 * a path is listed, and a claim a later argument admits above one already named
 * does not re-name it (cmds/add.c).
 *
 * With no pending layer the first arm reproduces the choice the settle already
 * made and the index already holds — a cost, never a difference — and the cost
 * is a group that exists only where a branch arrived holding two names for one
 * path.
 *
 * The two questions the pair answers are the two its callers ask — manifest_name's
 * leaf takes any name it finds, manifest_ascend's rung takes a directory's alone
 * (manifest_claim_beneath). The name is borrowed from whichever layer answered;
 * both outlive the call, and both callers copy or compose at once.
 *
 * The contribution is taken through the context rather than the view because
 * that is what keeps the O(P) search for it out of the per-rung loop. A public
 * form reads (view, profile, filesystem_path, pending) and finds the contribution
 * itself, as manifest_lookup_claim does — a wrapper over this one, never a second
 * body.
 *
 * @param n What the question is asked under (must not be NULL)
 * @param filesystem_path The path to read (must not be NULL)
 * @return The claim kept there, a NULL name where none is
 */
static manifest_claim_t manifest_kept(const naming_t *n, const char *filesystem_path) {
    const contribution_t *c = n->c;

    manifest_row_t **group =
        c && c->contested ? hashmap_get(c->contested, filesystem_path) : NULL;
    if (group) return manifest_row_claim(manifest_decide(n, filesystem_path, group));

    const manifest_claim_t *staged =
        n->pending ? hashmap_get(n->pending, filesystem_path) : NULL;
    if (staged) return *staged;

    return manifest_row_claim(c ? hashmap_get(c->explicit, filesystem_path) : NULL);
}

/**
 * The name `profile` composes for `filesystem_path` from what it keeps above it
 *
 * The table is asked once, up front: the deepest root of the profile enclosing
 * the path, and the tail past it (infra/mount.h mount_root_above). That one answer
 * is the whole of what the roots have to say here — where the ascent floors,
 * whether the path is itself a root, and the label and tail a name is spelled
 * from — where asking per rung answered the same question N+2 times.
 *
 * Then the rungs above the path, nearest first: the claim kept at each one
 * (manifest_kept — this command's own listing where it has one there, else what
 * the profile's committed claims settle on), and the path is composed beneath
 * the first that names what lies beneath it, a DIRECTORY claim of either layer
 * (manifest_claim_beneath). An ancestor claim names nothing, and a blob names
 * its own path and nothing under it — a name beneath its own is one the stage
 * refuses, and a path beneath its place one its writer refuses before it names
 * anything while the blob stands (cmds/add.c cmd_add, through manifest_blob_above),
 * and names past it where the blob lost the place to the claims beneath it — so
 * both are climbed past. Where no claim above gave a name, the root's label and
 * the tail spell one (infra/label.h label_compose), the word alone at the root
 * itself.
 *
 * The root is the floor and not a per-rung test, because no root of the profile
 * can stand strictly between it and the path — one that did would enclose the
 * path more tightly and have won the find. So `strlen(root->filesystem_path)`
 * is the one rung a root stands at, the root directory's being "/" like any other,
 * and the loop's condition says the ascent reaches it and stops. The claim kept
 * at every rung is still read before the root decides, the root's own rung
 * included: written the other way, a typed `home/jail` kept at web's own target
 * would be climbed past, and web's name for what lies beneath it would be the
 * binding's rather than its own claim's.
 *
 * The root directory is that rung on a machine where more than one root stands
 * at it — a HOME of "/" (a container's bare uid) or a target of one — because
 * one label takes the tie there (infra/mount.h mount_root_above) while a claim
 * keyed by any of the three words may be placed at the same directory. Read,
 * the claim names what lies beneath it; skipped, the tie's label does, and a
 * walk beneath a tracked root offers its finds under a word the profile's own
 * claim contradicts.
 *
 * The scratch copy is the arena's and abandoned, the module's idiom, and is taken
 * for every path a root encloses — at a root the loop reads nothing of it, one
 * bump an arm to skip it is not worth, a root being one path of at most three.
 * How often the rest is paid is not "once per newly listed path": the ascent
 * runs for every path nothing is kept at — including one a caller goes on to
 * exclude or refuse — and again at every contested path a namer reads, and again
 * at every contested rung one of those ascents passes through.
 *
 * @param n What the question is asked under (must not be NULL)
 * @param filesystem_path Absolute path (must not be NULL)
 * @return The composed name; never NULL
 */
static const char *manifest_ascend(const naming_t *n, const char *filesystem_path) {
    /* The roots' whole answer, asked once. The sentinel encloses every absolute
     * path, so one nothing encloses is not a path at all, and no claim is read
     * for a caller's bug. */
    const char *tail = NULL;
    const mount_root_t *root = mount_root_above(n->mounts, n->profile, filesystem_path, &tail);
    CHECK_ARG(root != NULL, "a name is asked of an absolute path");

    char *rung = arena_strdup(n->arena, filesystem_path);
    size_t len = strlen(rung);
    const size_t floor = strlen(root->filesystem_path);   /* the rung the root stands at */

    while (len > floor) {
        len = str_path_parent_len(rung);
        rung[len] = '\0';

        /* What is kept at this rung, and only a directory naming what lies beneath
         * it. */
        const char *above = manifest_claim_beneath(manifest_kept(n, rung));
        if (!above) continue;

        /* What lies beneath the rung (base/string.h str_path_beneath), read off
         * `filesystem_path`, because the truncation above took `rung`'s byte at
         * that offset. */
        return arena_str_format(
            n->arena, "%s/%s", above, str_path_beneath(filesystem_path, rung, len)
        );
    }

    /* Nothing of the profile's above it: the root's own label, and the tail —
     * the word alone at the root itself. */
    return label_compose(n->arena, root->label, tail);
}

/**
 * Is the claim kept at a place the name the profile would give the place fresh?
 *
 * The rule a place is decided by — a blob of the profile's own, claims of its
 * own beneath it under another label: the blob is decided first where it is,
 * and last, losing the place to the claims beneath it, where it is not. Both
 * ends of the naming rule, read at one path: the profile's ascent there and the
 * claim its settle keeps there (manifest_kept) — the place's blob, nothing pending,
 * and under a command's claims whichever of the place's names the next settle
 * will keep.
 *
 * One answer for the two readers that must agree on it: the layer's order, which
 * stands a place's blob first or last by it (manifest_precedence), and the place
 * a command's claims would move to the other side, asked of the committed claims
 * and again under the command's (manifest_moved_place).
 *
 * @param n What the question is asked under (must not be NULL)
 * @param filesystem_path A place: a path the profile keeps a blob at (must not
 *                        be NULL)
 * @return Whether the claim kept there is the fresh name
 */
static bool manifest_fresh(const naming_t *n, const char *filesystem_path) {
    return strcmp(
        manifest_ascend(n, filesystem_path), manifest_kept(n, filesystem_path).storage_path
    ) == 0;
}

/**
 * By filesystem path, then by name
 *
 * A parent's path is a strict prefix of its child's and strcmp puts a prefix
 * before every extension, so lexicographic order settles a contested parent before
 * a deeper group's ascent reads it. The name breaks the tie, so the order is
 * total and the runs are stable whatever qsort does with equals.
 *
 * Over a list of rows (manifest_row_t **), each slot read as the row pointer it
 * holds — never a pointer spine (include/types.h ptr_array_t).
 */
static int filesystem_order(const void *a, const void *b) {
    const manifest_row_t *ra = *(manifest_row_t *const *) a;
    const manifest_row_t *rb = *(manifest_row_t *const *) b;

    int by_path = strcmp(ra->filesystem_path, rb->filesystem_path);

    return by_path ? by_path : strcmp(ra->storage_path, rb->storage_path);
}

/**
 * Bytewise by name: the order a path's group is decided and reported in, over a
 * group of rows as filesystem_order reads one.
 */
static int name_order(const void *a, const void *b) {
    const manifest_row_t *ra = *(manifest_row_t *const *) a;
    const manifest_row_t *rb = *(manifest_row_t *const *) b;

    return strcmp(ra->storage_path, rb->storage_path);
}

/**
 * Decide every path this profile named twice, and record what was not kept
 *
 * The within-profile rule's last clause, run once the contribution is whole so
 * the ascent reads every tracked parent the profile has. The choice itself is
 * manifest_decide's, asked here with no pending layer — beneath its tracked parent,
 * else beneath its deepest root, which is the binding's custom/ over the portable
 * home/ over the absolute root/. Every other name is recorded against the one
 * kept (manifest_note_unkept).
 *
 * The group is the path's holder plus the run, sorted whole, so the holder is a
 * member and not a special case: every loser reads bytewise, the first-arrived
 * included. No comparator carries `fresh` and no bool survives the loop.
 *
 * Two rows of one group can never share a name, so the order is total: the tree
 * holds one blob per path, the sheet one directory claim per key, and the
 * content-authority rule contradicts the one name they can both carry at the
 * blob, before either name was resolved and long before the contest sees it.
 *
 * The group outlives this call, indexed on the contribution: what is kept at a
 * contested path is a rule and not a fact the build fixes, so every namer that
 * reads the path asks it again under whatever claims it has admitted
 * (manifest_kept), and the admission that keeps such a group from growing asks
 * whether a name is one of these (manifest_holds_name).
 *
 * Empty on every profile that names each of its paths once, which is the whole
 * cost on a branch this machine authored alone.
 *
 * @param manifest Target view — the mount table, and the unkept slice (must not
 *                 be NULL)
 * @param c The contribution being settled (must not be NULL)
 * @param contenders The rows that met a path already named, sorted here in place
 *                   (NULL where there are none)
 * @param contender_count How many
 * @param arena Arena for the groups and the composed names (must not be NULL)
 */
static void manifest_settle(
    manifest_t *manifest,
    contribution_t *c,
    manifest_row_t **contenders,
    size_t contender_count,
    arena_t *arena
) {
    if (contender_count == 0) return;

    /* The index of the groups, allocated where the first one is about to exist:
     * a contribution with no contender never has one, and the readers test the
     * pointer rather than a count. */
    c->contested = hashmap_borrow(arena, 8);

    /* What every question below is asked under: this contribution, and no claim
     * beyond it — the settle reads the profile as it arrived. */
    const naming_t n = {
        .c       = c,
        .mounts  = manifest->mounts,
        .profile = c->profile,
        .pending = NULL,
        .arena   = arena,
    };

    /* The contest by path, so the rows contending for one path form a run and a
     * parent's run comes before its children's (filesystem_order) */
    qsort(contenders, contender_count, sizeof(*contenders), filesystem_order);

    for (size_t i = 0; i < contender_count;) {
        const char *filesystem_path = contenders[i]->filesystem_path;

        size_t count = 0;
        while (i + count < contender_count &&
            strcmp(contenders[i + count]->filesystem_path, filesystem_path) == 0) count++;

        /* The group: the name that arrived first, and the ones that met it. One
         * slot past them stays NULL — the group outlives this loop, and every
         * reader of it walks to the terminator. */
        manifest_row_t **group = arena_calloc(arena, count + 2, sizeof(*group));
        group[0] = hashmap_get(c->explicit, filesystem_path);
        for (size_t g = 0; g < count; g++) group[g + 1] = contenders[i + g];
        qsort(group, count + 1, sizeof(*group), name_order);

        manifest_row_t *kept = manifest_decide(&n, filesystem_path, group);

        hashmap_set(c->explicit, filesystem_path, kept);

        /* The group, kept against the path it contended for. Indexed after the
         * winner is in place, so a deeper group's ascent — which reaches this
         * rung by path order, parents first — reads a settled state whichever
         * way it looks. */
        hashmap_set(c->contested, filesystem_path, group);

        for (size_t g = 0; group[g]; g++) {
            if (group[g] == kept) continue;
            manifest_note_unkept(
                manifest, c->profile, group[g], kept->storage_path, arena
            );
        }

        i += count;
    }
}

/**
 * Walk visitor that places one of the profile's claims into the contribution
 *
 * The whole of the per-profile step the profile's walk drives (core/profiles.h
 * profile_walk): one decoded claim at a time — its blobs first, then its directory
 * claims — a finished manifest_row_t or nothing. In order: the name copied, the
 * path it resolves to, the row, and where it is kept — a derived claim held apart,
 * the first of two chains through one path, and an explicit one by the
 * within-profile placement rule that says whether it is kept or contends.
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The claim walk (claim_walk_t)
 * @return NULL: placing a claim fails nowhere
 */
static error_t manifest_place_claim(const profile_claim_t *claim, void *payload) {
    claim_walk_t *walk = payload;
    contribution_t *c = walk->contribution;

    /* The walk lends the name for this call alone; the row and the unbound note
     * keep it past the walk, so it is copied into the arena — once, and Git's
     * only bound on a path's length is memory. */
    const char *storage_path = arena_strdup(walk->arena, claim->storage_path);

    /* Convert storage path to filesystem path against the mount table.
     *
     * No path when storage_path is custom/... and the profile has no target binding
     * on this machine — a normal lifecycle stage in a shared repository (a clone
     * before the target is chosen, a sync that pulled another machine's custom/
     * claims, a revert that recommitted one), not corruption: no local precondition
     * can bind what another machine adds to the branch. The claim contributes
     * no row — nothing on this machine can place it — and is recorded on the
     * view (manifest_unbound) so the health consumers surface it; it is never
     * dropped in silence, and both kinds hold under that one UNBOUND policy.
     * Record-safe by construction: a record can only exist where a binding existed
     * at write time, so no record ever joins a skipped claim and no orphan can
     * be manufactured here. The shape was checked where the profile read the
     * name — a blob's at its walk, an item's at its parse — so the label is one. */
    const char *filesystem_path = mount_resolve(
        walk->arena, walk->manifest->mounts, c->profile, storage_path
    );
    if (!filesystem_path) {
        manifest_note_unbound(
            walk->manifest, c->profile, storage_path, path_type_kind(claim->type),
            walk->arena
        );
        return NULL;
    }

    /* The row is the claim, placed: one profile's, and fresh — nothing is reset
     * or rewritten any more, so each field is written once, from the claim. Its
     * mode is the claim's or its type's floor (core/profiles.h profile_claim_mode),
     * so the row leaves the build total; the strings it keeps are the arena's,
     * the profile's being the name the step duplicated. A contender is a finished
     * row and takes its own claim like any other, and so is a second chain. */
    manifest_row_t *row = manifest_place(walk->placed, filesystem_path, walk->arena);
    row->storage_path = storage_path;
    row->profile = c->profile;
    row->type = claim->type;
    git_oid_cpy(&row->blob_oid, &claim->blob_oid);
    row->mode = profile_claim_mode(claim);
    row->owner = arena_strdup(walk->arena, claim->owner);
    row->group = arena_strdup(walk->arena, claim->group);
    row->encrypted = claim->encrypted;
    row->tracked = claim->tracked;

    /* Then where it is kept, in the index of its class: the two never meet here,
     * and which stands where the profile holds both is the layer's question,
     * asked across every profile at once (manifest_layer).
     *
     * A derived claim takes a path no chain of the profile's runs through yet,
     * and a second chain through one is held nowhere: a derived claim is a
     * consequence of an older name, not a source of new ones.
     *
     * Ancestors are structurally shared where claims are per-profile and
     * precedence-resolved, and two profiles that traverse the same directory
     * derive it identically: their claims carry no intent to conflict, so they
     * do not compete. That is manifest_layer's half of the rule; here the two
     * chains are one profile's own, and the first placed is kept — the row says
     * the profile holds a subtree beneath the path, never which name its subtree
     * runs through.
     *
     * The first placed is the byte-least name (the walk shows directory claims
     * in key order, core/profiles.h profile_walk, whatever the document spells),
     * and the tie-break settles more than a name: a derived claim carries the
     * mode, owner and group dotta creates the directory with, and two chains
     * captured at different moments can disagree about them — 0700 under
     * home/jail/etc, 0755 under custom/etc, one path. Neither is the truer
     * statement, both being what disk held when a walk passed through, so the
     * tie is stated here rather than decided — by the names alone, which no
     * spelling of the document moves. Nothing is recorded either: manifest_unkept
     * is names, and a derived claim named nothing. */
    if (manifest_is_derived(row)) {
        hashmap_add(c->derived, filesystem_path, row);
        return NULL;
    }

    /* An explicit claim takes a path the profile names nothing at explicitly,
     * and contends where it names one: the blobs arrive first, so while they do
     * the second arm is exactly "a second name of this profile", for the settle
     * to decide, and a tracked directory claim after them contends with an explicit
     * one. A directory claim at a blob's own name never arrives — the profile
     * drops it — which is what keeps the settle's group free of two rows under
     * one name. The sibling rule across profiles is manifest_layer's, where the
     * highest explicit claim takes the path: that is the whole difference between
     * precedence and a profile naming one place twice. */
    if (!hashmap_add(c->explicit, filesystem_path, row)) {
        walk->contenders = arena_grow(
            walk->arena, walk->contenders, &walk->contender_capacity,
            walk->contender_count + 1, sizeof(*walk->contenders)
        );
        walk->contenders[walk->contender_count++] = row;
    }

    return NULL;
}

/**
 * Walk visitor that notes one claim the profile's own tree contradicts
 *
 * The walk's second question, beside the claims it places (manifest_place_claim):
 * profile_contradicted shows each directory claim a blob of the profile's tree
 * stands at or above, and a tracked one is noted against that blob
 * (manifest_note_contradicted); a derived one records nothing. The claim and
 * its strings are lent for the visit (core/profiles.h), so the two names are
 * copied into the arena the view lives in.
 *
 * @param claim One claim the profile's tree contradicts (borrowed — valid for
 *              the call only)
 * @param payload The claim walk (claim_walk_t)
 * @return NULL: noting a claim fails nowhere
 */
static error_t manifest_note_claim(const profile_claim_t *claim, void *payload) {
    claim_walk_t *walk = payload;

    /* A derived claim is the way to a tracked one, recorded in its own right,
     * or to none, which the profile's next settle prunes: the repair is a tracked
     * claim's */
    if (!claim->tracked) return NULL;

    manifest_note_contradicted(
        walk->manifest, walk->contribution->profile,
        arena_strdup(walk->arena, claim->storage_path), PATH_KIND_DIRECTORY,
        arena_strdup(walk->arena, claim->blob_above), NULL, walk->arena
    );

    return NULL;
}

/**
 * One profile's contribution: the claims its walk shows, placed
 *
 * The per-profile step both builders run, and the whole of the within-profile
 * rule. The contribution is registered here — its arena-backed name (every row
 * of it borrows the pointer), its two indexes, and its slot in the view's parallel
 * arrays — so one function owns one profile's claims from the name to the settled
 * spine, and the builders hand over a profile.
 *
 * The profile's walk shows every claim the profile makes, decoded (core/profiles.h
 * profile_walk) — its blobs, then the directory claims its own tree does not
 * contradict — and each is placed as it arrives (manifest_place_claim): resolved
 * against the mount table, recorded where this machine cannot place it
 * (manifest_note_unbound), and kept or contending. The tracked claims its tree
 * does contradict are noted on the view's health beside them (manifest_note_claim).
 * The settle then decides every path this profile named twice, and the tail cuts
 * the spine to what each index keeps.
 *
 * The walk reads the profile's own sheet, strictly: a sheet that will not load
 * fails the build rather than read as "no claims", so no caller of a builder
 * chooses a policy for a fact this step is the authority on.
 *
 * Memory: every allocation lands in `arena`, the step's two lists included, which
 * stay there past the call, but the sheet the walk reads where no question has
 * yet, which the profile keeps (core/profiles.h); no row borrows the profile —
 * each takes an arena copy. On error, rows already placed are left as they are
 * — the build fails whole, and nothing frees a view.
 *
 * @param manifest Target view (must not be NULL; its mount table is what places
 *                 rows)
 * @param profile The profile (must not be NULL; its name is copied, and its sheet
 *                read through it)
 * @param arena Arena backing the contribution (must not be NULL)
 * @return Error or NULL on success
 */
static error_t manifest_contribute(
    manifest_t *manifest,
    profile_t *profile,
    arena_t *arena
) {
    /* Register the contribution before anything can fail into it: the name is
     * arena-backed so the view never depends on the profile or on the state's
     * row cache, and the indexes are the arena's too, so a build that stops partway
     * leaves nothing behind but the arena's bytes. */
    contribution_t *c = &manifest->contributions[manifest->profile_count];

    *c = (contribution_t){
        .profile = arena_strdup(arena, profile_name(profile)),
        .explicit = hashmap_borrow(arena, 128),
        .derived = hashmap_borrow(arena, 32),
    };
    manifest->profiles[manifest->profile_count++] = c->profile;

    /* The step's two lists, read only while it runs: every row this profile placed,
     * in claim order, and the rows that met a path it had already named, which
     * the walk grows itself. The second is empty on every profile that names
     * each of its paths once. Both are the build's arena's, left there when the
     * step returns: a pointer per row placed. */
    ptr_array_t placed;
    ptr_array_init(&placed, arena, 0);

    claim_walk_t walk = {
        .manifest     = manifest,
        .contribution = c,
        .placed       = &placed,
        .arena        = arena
    };

    /* The profile's claims, decoded once and read strictly, each placed as it
     * arrives (manifest_place_claim). Per-profile is the correctness boundary
     * for attribution — each profile places its own files and directories via
     * its own branch, never via a cross-profile merge — and the table is the
     * view's, its bindings keyed by profile, so a custom/ claim of this profile
     * places under this profile's target and no other's. The walk names the profile
     * over its own failures (core/profiles.h), so nothing here says it again. */
    error_t err = profile_walk(profile, PROFILE_READ_STRICT, manifest_place_claim, &walk);
    if (err) return err;

    /* The tracked claims its own tree contradicts, which no row stands for, noted
     * on the view's health (manifest_note_claim): the sheet the walk read, each
     * directory claim classified again — the walk shows a claim or does not,
     * and says nothing of the ones it does not */
    err = profile_contradicted(profile, PROFILE_READ_STRICT, manifest_note_claim, &walk);
    if (err) return err;

    /* Every path this profile named twice, decided once. */
    manifest_settle(manifest, c, walk.contenders, walk.contender_count, arena);

    /* The contribution's rows: every row kept in the index of its class, in claim
     * order. A name that lost and a second chain stay in the arena and leave
     * the slice; a derived claim at the path of the profile's own explicit claim
     * stays in it, for the layer to hide. Sized exactly — the two indexes are
     * the count. */
    size_t kept = hashmap_size(c->explicit) + hashmap_size(c->derived);
    if (kept > 0) {
        c->rows = arena_calloc(arena, kept, sizeof(*c->rows));
        for (size_t j = 0; j < placed.count; j++) {
            manifest_row_t *row = placed.entries[j];
            const manifest_row_t *held = hashmap_get(
                manifest_is_derived(row) ? c->derived : c->explicit, row->filesystem_path
            );
            if (held == row) {
                c->rows[c->count++] = row;
            }
        }
    }

    return NULL;
}

/**
 * The nearest blob an index holds strictly above a path, or NULL
 *
 * The rungs are the path's own key cut at each separator, nearest first, each
 * read off the key's bytes by its length (base/string.h str_path_parent_len_n,
 * base/hashmap.h hashmap_get_n), so nothing is copied: the root directory, the
 * path's last parent, is the last rung read, and "/" has none above it. A directory
 * row of either class stops nothing.
 *
 * Where `interior` is given, a rung it holds ends the climb with none: a standing
 * explicit claim lies beneath that rung, and no row stands strictly beneath a
 * standing blob, so none stands at the rung or above it. That makes the interior
 * the climb's memo while the layer decides: a claim whose parent a sibling marked
 * asks one probe.
 *
 * Readers: the layer's two passes, over the view's index with its interior
 * (manifest_layer); one contribution's places, over its own explicit claims
 * (manifest_places); and manifest_blob_above, over the view built — both with none.
 *
 * @param index The index climbed (must not be NULL)
 * @param interior The layer's interior, or NULL
 * @param filesystem_path Where to ask, absolute: a key (must not be NULL)
 * @return The nearest blob row above the path, as the index holds it, or NULL
 */
static manifest_row_t *manifest_index_blob_above(
    const hashmap_t *index, const hashmap_t *interior, const char *filesystem_path
) {
    for (size_t len = strlen(filesystem_path); len > 1;) {
        len = str_path_parent_len_n(filesystem_path, len);

        /* A standing claim beneath this rung: no blob stands at it or above */
        if (interior && hashmap_get_n(interior, filesystem_path, len)) return NULL;

        manifest_row_t *row = hashmap_get_n(index, filesystem_path, len);
        if (row && row->type != PATH_TYPE_DIRECTORY) return row;
    }

    return NULL;
}

/**
 * Mark every strict ancestor of a claim the layer just stood as interior, to
 * its contribution
 *
 * Nearest first, to the root directory, and stopping at the first rung the
 * contribution marked already: an earlier climb of its own marked that rung and
 * every one above it. A mark is overwritten, never removed, and the contributions
 * are decided highest first, so an interior path carries the lowest contribution
 * with a standing explicit claim beneath it so far — the side a blob lost there
 * loses to (manifest_layer).
 *
 * The map owns its keys: the one copy of the path, taken at the first rung written,
 * is cut in place from there up, and the map copies a rung it is new to.
 */
static void manifest_mark_interior(
    hashmap_t *interior, contribution_t *c, const char *filesystem_path, arena_t *frame
) {
    char *rung = NULL;

    for (size_t len = strlen(filesystem_path); len > 1;) {
        len = str_path_parent_len_n(filesystem_path, len);
        if (hashmap_get_n(interior, filesystem_path, len) == c) return;

        if (!rung) rung = arena_strdup(frame, filesystem_path);
        rung[len] = '\0';
        hashmap_set(interior, rung, c);
    }
}

/**
 * A contribution's places, in path order: each blob of its own that one of its
 * own explicit claims lies strictly beneath, so an outer place precedes an inner
 * one
 *
 * Under another label, necessarily: one label holds no such pair, the stage
 * refusing a name beneath a blob of its own tree (sys/stage.c stage_admit_path),
 * so a contribution whose explicit claims keep to one label is not climbed at
 * all. Each explicit claim climbs the contribution's own explicit claims for
 * the nearest blob above it, so a nested pair names its inner blob too; a blob
 * two claims meet is kept once.
 *
 * Readers: the order a contribution's claims are decided in (manifest_precedence),
 * and the freshness a command's claims would move (manifest_moved_place).
 *
 * @param c The contribution (must not be NULL)
 * @param places Room for one blob per row of `c` (must not be NULL)
 * @return How many places `places` holds
 */
static size_t manifest_places(const contribution_t *c, manifest_row_t **places) {
    /* The label the first explicit claim names, and the first claim naming another */
    size_t j = 0;
    while (j < c->count && manifest_is_derived(c->rows[j])) j++;
    if (j == c->count) return 0;

    const label_t label = label_of(c->rows[j]->storage_path);
    while (j < c->count &&
        (manifest_is_derived(c->rows[j]) || label_of(c->rows[j]->storage_path) == label)) {
        j++;
    }
    if (j == c->count) return 0;

    /* The nearest blob of its own above each explicit claim, by path: a blob
     * two claims meet is adjacent then, and kept once */
    size_t count = 0;
    for (j = 0; j < c->count; j++) {
        if (manifest_is_derived(c->rows[j])) continue;

        manifest_row_t *blob = manifest_index_blob_above(
            c->explicit, NULL, c->rows[j]->filesystem_path
        );
        if (blob) places[count++] = blob;
    }
    if (count > 1) qsort(places, count, sizeof(*places), filesystem_order);

    size_t kept = 0;
    for (size_t p = 0; p < count; p++) {
        if (kept == 0 || places[kept - 1] != places[p]) places[kept++] = places[p];
    }

    return kept;
}

/**
 * A contribution's explicit claims, in the order its own precedence decides them
 *
 * A place is decided by its fresh name: the profile's own ascent there, nothing
 * pending — the rule the settle decides two names at one path by (manifest_fresh).
 * A place's blob that name spells comes first, outermost first, so while it stands
 * it leaves no room for the profile's claims beneath it; every other explicit
 * claim follows, in claim order; a place's blob another name spells comes last,
 * so the profile's claims beneath it stand first and need its place as a directory.
 * The frame's order, never the cut's, so the spine keeps claim order.
 *
 * @param manifest The view, for the table the ascent reads (must not be NULL)
 * @param c The contribution (must not be NULL)
 * @param frame The layer's frame, for the places and the ascents (must not be NULL)
 * @param order Room for one row per row of `c` (must not be NULL)
 * @return How many claims `order` holds
 */
static size_t manifest_precedence(
    const manifest_t *manifest, const contribution_t *c, arena_t *frame,
    manifest_row_t **order
) {
    manifest_row_t **places = arena_calloc(frame, c->count, sizeof(*places));
    const size_t place_count = manifest_places(c, places);

    /* The places a fresh name spells, first; the others wait for the claims beneath
     * them */
    const naming_t n = {
        .c       = c,
        .mounts  = manifest->mounts,
        .profile = c->profile,
        .pending = NULL,
        .arena   = frame,
    };
    manifest_row_t **later = arena_calloc(frame, place_count, sizeof(*later));
    size_t later_count = 0;
    size_t count = 0;
    for (size_t p = 0; p < place_count; p++) {
        manifest_row_t *blob = places[p];
        if (manifest_fresh(&n, blob->filesystem_path)) {
            order[count++] = blob;
        } else {
            later[later_count++] = blob;
        }
    }

    /* Every other explicit claim, in claim order: a place's blob in its place's
     * turn */
    for (size_t j = 0; j < c->count; j++) {
        manifest_row_t *row = c->rows[j];
        if (manifest_is_derived(row)) continue;
        if (place_count > 0 &&
            bsearch(&row, places, place_count, sizeof(*places), filesystem_order)) {
            continue;
        }
        order[count++] = row;
    }

    for (size_t k = 0; k < later_count; k++) order[count++] = later[k];

    return count;
}

/**
 * The layer's rung at a lost blob's place: the directory the claims beneath it need
 *
 * Named by the overriding side's own ascent — never manifest_name, whose leaf
 * clause would answer a name that side holds at the place — and attributed to
 * it: the contribution whose standing claims beneath made the blob lose, the
 * lowest of them when it lost. So a rung never takes the lost claim's own name.
 * A blob decided before any claim of its own beneath it can lose only to a higher
 * profile, which names the rung; one decided after them loses to its own, whose
 * ascent there is the fresh name the blob's is not (manifest_precedence). At a
 * root of that side the name is its label's word alone (infra/label.h
 * label_compose), a directory row at a root like any other. Its mode is the
 * default, with no owner and no group, absence's word (core/metadata.h).
 *
 * @param manifest The view, for the table the ascent reads (must not be NULL)
 * @param beneath The contribution the blob lost to (must not be NULL)
 * @param filesystem_path The place, the lost blob's own key (must not be NULL)
 * @param arena Arena for the row and its name: it may stand (must not be NULL)
 * @return The rung, a derived directory row no contribution holds
 */
static manifest_row_t *manifest_rung(
    const manifest_t *manifest, const contribution_t *beneath, const char *filesystem_path,
    arena_t *arena
) {
    const naming_t n = {
        .c       = beneath,
        .mounts  = manifest->mounts,
        .profile = beneath->profile,
        .pending = NULL,
        .arena   = arena,
    };

    manifest_row_t *rung = arena_calloc(arena, 1, sizeof(*rung));
    *rung = (manifest_row_t){
        .filesystem_path = filesystem_path,
        .storage_path = manifest_ascend(&n, filesystem_path),
        .profile = beneath->profile,
        .type = PATH_TYPE_DIRECTORY,
        .mode = DIR_MODE_DEFAULT,
    };

    return rung;
}

/**
 * Precedence over the settled contributions, and the winners' spine
 *
 * A claim stands unless a claim decided before it stands at its path, a standing
 * blob stands above it, or — the claim a blob — explicit claims stand beneath
 * it, which need its place as a directory: a blob leaves no room at its place
 * or beneath it, whichever profile's claim the other is. Two decisions, in two
 * passes over the finished contributions, and nothing either decides is ever
 * undone.
 *
 * The explicit claims first, highest precedence first, and each contribution's
 * in its own precedence (manifest_precedence), each decided against what stands
 * so far. Then the derived claims, lowest precedence first, each filling a path
 * no row holds and no standing blob stands above — two profiles that traverse
 * the same directory derive it identically, their claims carry no intent to
 * conflict, and the first to name the path holds it, so the row's owner does
 * not move when a profile above it is enabled and no reassignment churn appears
 * in the receipts over a directory nobody named. A derived claim at the path of
 * its own profile's explicit claim meets that claim here and is hidden like any
 * other. Last, at each place a blob lost and no derived claim filled, the layer's
 * rung (manifest_rung): the directory the claims beneath it need.
 *
 * Where what leaves a claim no room is its own profile's — a blob of its own
 * above it, or the claims of its own beneath it — the profile places one chain
 * under two labels, and the claim is contradicted: noted where its check finds
 * it, beside what leaves it no room (manifest_note_contradicted). Another profile's
 * claim standing over it is layering, and noted nowhere.
 *
 * After it no row stands strictly beneath a standing blob, so whatever hides a
 * claim that stands nowhere is read off its position: the row at its path, else
 * the blob above it.
 *
 * The spine is then cut once, exactly, from what the index points at, in claim
 * order across the contributions — so a path a higher profile overrides sits at
 * the winner's place — and the rungs that stand after them. Row order is
 * unspecified and this is what there is of it.
 *
 * Run once at the tail of each builder, so manifest_lookup is never asked
 * mid-build. An empty view allocates no spine and manifest_rows answers an empty
 * slice.
 *
 * @param manifest The view whose contributions are all settled (must not be NULL)
 * @param arena Arena for the spine and the rungs (must not be NULL)
 */
static void manifest_layer(manifest_t *manifest, arena_t *arena) {
    /* The passes' scratch, freed once both are done: the interior — every path
     * a standing explicit claim lies strictly beneath, to the lowest contribution
     * with one there so far — and each contribution's order. The rungs are the
     * spine's tail, made at each blob's loss in the arena the spine is cut in. */
    arena_t *frame = arena_create(0);
    hashmap_t *interior = hashmap_create(frame, 128);
    ptr_array_t rungs;
    ptr_array_init(&rungs, arena, 0);

    /* The explicit claims, highest precedence first */
    for (size_t i = manifest->profile_count; i-- > 0;) {
        contribution_t *c = &manifest->contributions[i];

        manifest_row_t **order = arena_calloc(frame, c->count, sizeof(*order));
        const size_t count = manifest_precedence(manifest, c, frame, order);

        for (size_t j = 0; j < count; j++) {
            manifest_row_t *row = order[j];

            /* Above it: a standing blob leaves it no room — its own profile's,
             * by the pointer every row of a contribution carries, a contradiction
             * noted beside that blob; another's, layering */
            const manifest_row_t *above = manifest_index_blob_above(
                manifest->index, interior, row->filesystem_path
            );
            if (above) {
                if (above->profile == c->profile) {
                    manifest_note_contradicted(
                        manifest, c->profile, row->storage_path, path_type_kind(row->type),
                        above->storage_path, NULL, arena
                    );
                }
                continue;
            }

            /* At its path: a claim decided before it stands there */
            if (hashmap_has(manifest->index, row->filesystem_path)) continue;

            /* Beneath it, the claim a blob: standing explicit claims need its
             * place as a directory, the lowest contribution with one there read
             * now, at the loss, to name and own the rung — its own, a contradiction
             * noted beside the name the place takes, the rung's */
            const contribution_t *beneath = row->type == PATH_TYPE_DIRECTORY
                ? NULL : hashmap_get(interior, row->filesystem_path);
            if (beneath) {
                manifest_row_t *rung = manifest_rung(
                    manifest, beneath, row->filesystem_path, arena
                );
                ptr_array_push(&rungs, rung);
                if (beneath == c) {
                    manifest_note_contradicted(
                        manifest, c->profile, row->storage_path, path_type_kind(row->type),
                        NULL, rung->storage_path, arena
                    );
                }
                continue;
            }

            hashmap_set(manifest->index, row->filesystem_path, row);
            manifest_mark_interior(interior, c, row->filesystem_path, frame);
        }
    }

    /* The derived claims, lowest precedence first: a row fills a path no row
     * holds and no standing blob stands above */
    for (size_t i = 0; i < manifest->profile_count; i++) {
        const contribution_t *c = &manifest->contributions[i];
        for (size_t j = 0; j < c->count; j++) {
            manifest_row_t *row = c->rows[j];
            if (!manifest_is_derived(row) ||
                manifest_index_blob_above(manifest->index, interior, row->filesystem_path)) {
                continue;
            }

            hashmap_add(manifest->index, row->filesystem_path, row);
        }
    }

    arena_free(frame);

    /* The rungs: a lost blob's place no derived claim filled. The first made at
     * a place stands — the highest blob lost there — and the rest are the arena's
     * bytes. */
    for (size_t r = 0; r < rungs.count; r++) {
        manifest_row_t *rung = rungs.entries[r];
        hashmap_add(manifest->index, rung->filesystem_path, rung);
    }

    size_t standing = hashmap_size(manifest->index);
    if (standing == 0) return;

    manifest->rows = arena_calloc(arena, standing, sizeof(*manifest->rows));
    for (size_t i = 0; i < manifest->profile_count; i++) {
        const contribution_t *c = &manifest->contributions[i];
        for (size_t j = 0; j < c->count; j++) {
            manifest_row_t *row = c->rows[j];
            if (hashmap_get(manifest->index, row->filesystem_path) == row) {
                manifest->rows[manifest->count++] = row;
            }
        }
    }
    for (size_t r = 0; r < rungs.count; r++) {
        const manifest_row_t *rung = rungs.entries[r];
        if (hashmap_get(manifest->index, rung->filesystem_path) == rung) {
            manifest->rows[manifest->count++] = rung;
        }
    }
}

/**
 * Allocate a fresh manifest_t, ready for the per-profile step.
 *
 * The view struct, the contributions array and the profile list beside it (both
 * sized for the profiles the build will walk at most) are arena-allocated, and
 * so is the index, which borrows its keys from the rows it points at
 * (hashmap_borrow); each contribution fills its own slot as it is registered
 * (manifest_contribute). No spine is allocated here: each is cut once, exactly,
 * from the indexes that decide it.
 */
static manifest_t *manifest_allocate(
    arena_t *arena,
    size_t index_capacity,
    size_t profile_capacity
) {
    manifest_t *manifest = arena_calloc(arena, 1, sizeof(*manifest));

    if (profile_capacity > 0) {
        manifest->contributions = arena_calloc(
            arena, profile_capacity, sizeof(*manifest->contributions)
        );
        manifest->profiles = arena_calloc(
            arena, profile_capacity, sizeof(*manifest->profiles)
        );
    }

    manifest->index = hashmap_borrow(arena, index_capacity);

    return manifest;
}

/**
 * The table the enabled rows describe
 *
 * State-aware adapter that materializes enabled_profiles' (name, target) rows
 * into mount_t entries and delegates the augmentation (HOME, the root sentinel)
 * to mount_table_build. The one derivation of this machine's topology from the
 * rows: manifest_build runs it below before it places a row, the dispatcher runs
 * it alone for a command that declares `mounts` without the view, and a command
 * that brought a binding of its own runs it with that, so every one of them reads
 * one value from one instant's rows.
 */
error_t manifest_mount_table(
    const state_t *state,
    const mount_t *binding,
    arena_t *arena,
    mount_table_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    state_profiles_t rows = state_profiles(state);

    /* One slot per row plus the binding's, which is always there to reserve:
     * the array is never NULL and mount_table_build takes it with a count of
     * zero. The binding goes in first and its profile's row is skipped below,
     * so substituting for a row and adding where there is none are one arm. */
    mount_t *mounts = arena_calloc(arena, rows.count + 1, sizeof(*mounts));

    size_t count = 0;
    if (binding) {
        mounts[count++] = *binding;
    }
    for (size_t i = 0; i < rows.count; i++) {
        if (binding && strcmp(rows.entries[i].name, binding->profile) == 0) {
            continue;
        }
        mounts[count++] = (mount_t){
            .profile = rows.entries[i].name,
            .target = rows.entries[i].target
        };
    }

    return mount_table_build(arena, mounts, count, out);
}

/**
 * Build the manifest over the enabled set
 */
error_t manifest_build(
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
    state_profiles_t enabled_profiles = state_profiles(state);

    /* The topology the same rows describe — each profile's target, and this
     * machine's $HOME — built here, from the rows of this instant, so a custom/
     * path always resolves under the target the row it came from carries. */
    mount_table_t *mounts = NULL;
    error_t err = manifest_mount_table(state, NULL, arena, &mounts);
    if (err) return err;

    manifest_t *manifest = manifest_allocate(arena, 128, enabled_profiles.count);
    manifest->mounts = mounts;

    /* One contribution per profile, in order; precedence runs over them once
     * every one of them is settled. */
    for (size_t i = 0; i < enabled_profiles.count; i++) {
        const char *name = enabled_profiles.entries[i].name;

        /* The profile's tree, scoped to the iteration, or none where its branch
         * is gone — and "missing" is not "broken": missing is an observation —
         * the profile contributes nothing, is listed among the missing
         * (manifest_missing) and not among the view's profiles, and the workspace
         * reads its records as orphans — broken is an error that must propagate. */
        git_tree *tree = NULL;
        err = gitops_branch_tree(repo, name, &tree);
        if (err) return err;
        if (!tree) {
            manifest_note_missing(manifest, arena_strdup(arena, name), arena);
            continue;
        }

        /* The profile's claims: the profile at the tree just opened, its sheet
         * read by the profile's walk from that tree, under the name whose claims
         * they are. One view, many profiles. The name the step copies is what
         * every row of it borrows, so the view never depends on the state's row
         * cache, and the profile goes with the tree. */
        profile_t *profile = profile_open(name, tree);
        err = manifest_contribute(manifest, profile, arena);
        profile_free(profile);
        git_tree_free(tree);

        if (err) return err;
    }

    manifest_layer(manifest, arena);

    *out = manifest;
    return NULL;
}

/**
 * Build the manifest from one profile
 */
error_t manifest_build_profile(
    profile_t *profile,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(profile);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    manifest_t *manifest = manifest_allocate(arena, 128, 1);

    /* mounts borrows from a function parameter — it outlives the profile's walk,
     * and the table outlives the view (manifest_mounts lends it). The profile
     * is the caller's, and the view keeps nothing of it. */
    manifest->mounts = mounts;

    /* One contribution, settled and layered like any other, so one profile's
     * view answers manifest_lookup_claim and manifest_name exactly as an enabled
     * view does. */
    error_t err = manifest_contribute(manifest, profile, arena);
    if (err) return err;

    manifest_layer(manifest, arena);

    *out = manifest;
    return NULL;
}

/**
 * Every row standing in the view, both kinds, unordered
 *
 * The spine holds its rows const, so it is lent as it is: the slice adds const
 * to the pointers alone, the one conversion C makes with no cast (C11 6.5.16.1).
 */
manifest_rows_t manifest_rows(const manifest_t *manifest) {
    if (!manifest) return (manifest_rows_t){ 0 };
    return (manifest_rows_t){
        .entries = manifest->rows,
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
 * The names the profiles hold for paths they also name otherwise
 */
manifest_unkept_t manifest_unkept(const manifest_t *manifest) {
    if (!manifest) return (manifest_unkept_t){ 0 };
    return (manifest_unkept_t){
        .entries = manifest->unkept,
        .count = manifest->unkept_count,
    };
}

/**
 * The tracked directory claims the profiles' own trees contradict
 */
manifest_contradicted_t manifest_contradicted(const manifest_t *manifest) {
    if (!manifest) return (manifest_contradicted_t){ 0 };
    return (manifest_contradicted_t){
        .entries = manifest->contradicted,
        .count = manifest->contradicted_count,
    };
}

/**
 * The enabled profiles the build found no branch for
 */
manifest_missing_t manifest_missing(const manifest_t *manifest) {
    if (!manifest) return (manifest_missing_t){ 0 };
    return (manifest_missing_t){
        .entries = manifest->missing,
        .count = manifest->missing_count,
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
    if (!c) return NULL;

    /* The explicit claim kept there, else the derived claim placed there */
    const manifest_row_t *row = hashmap_get(c->explicit, filesystem_path);

    return row ? row : hashmap_get(c->derived, filesystem_path);
}

/**
 * The row `profile` holds under `storage_path` in its own contribution
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *profile,
    const char *storage_path
) {
    if (!manifest || !storage_path) return NULL;

    const contribution_t *c = manifest_contribution(manifest, profile);
    if (!c) return NULL;

    /* The one row of its own that spells the name, standing or not: a name is
     * one claim, placed at one path (core/manifest.h) */
    for (size_t j = 0; j < c->count; j++) {
        const manifest_row_t *row = c->rows[j];
        if (strcmp(row->storage_path, storage_path) == 0) {
            return row;
        }
    }

    return NULL;
}

/**
 * Does `profile` hold `storage_path` as a name for `filesystem_path`?
 */
bool manifest_holds_name(
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path,
    const char *storage_path
) {
    if (!manifest || !filesystem_path || !storage_path) return false;

    const contribution_t *c = manifest_contribution(manifest, profile);
    if (!c) return false;

    /* Where the profile names the path more than once, the group is every name
     * it holds there, the kept one among them — so membership is the whole question
     * and which of them is kept is not asked. */
    manifest_row_t **group =
        c->contested ? hashmap_get(c->contested, filesystem_path) : NULL;
    if (group) {
        for (size_t g = 0; group[g]; g++) {
            if (strcmp(group[g]->storage_path, storage_path) == 0) return true;
        }
        return false;
    }

    const manifest_row_t *row = hashmap_get(c->explicit, filesystem_path);

    return row && strcmp(row->storage_path, storage_path) == 0;
}

/**
 * Is the row a claim its profile holds, rather than the layer's rung?
 */
bool manifest_holds_row(const manifest_t *manifest, const manifest_row_t *row) {
    if (!manifest || !row) return false;

    /* The index of its own class holds the contribution's row by its key, as
     * the cut reads it (manifest_contribute): the rung is in neither */
    const contribution_t *c = manifest_contribution(manifest, row->profile);

    return c && hashmap_get(
        manifest_is_derived(row) ? c->derived : c->explicit, row->filesystem_path
    ) == row;
}

/**
 * What `profile` calls `filesystem_path` under this view
 *
 * The leaf clause and the ascent, over the one read that answers what is kept
 * somewhere (manifest_kept): the claim kept at the path names it whatever its
 * kind — this command's own if it has admitted one there, since it has already
 * named this very path, and the one the next settle will keep where the profile
 * names the path twice — and a path nothing is kept at falls through to the ascent,
 * the profile holding no row there or holding a derived one, which is no claim.
 *
 * The answer is the caller's arena's whichever rung produced it: the leaf clause
 * copies, which costs one strdup and buys the absence of a contract where three
 * lifetimes meet.
 */
const char *manifest_name(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path,
    const hashmap_t *pending
) {
    CHECK_NULL(arena);
    CHECK_NULL(manifest);
    CHECK_NULL(filesystem_path);

    const naming_t n = {
        .c       = manifest_contribution(manifest, profile),
        .mounts  = manifest->mounts,
        .profile = profile,
        .pending = pending,
        .arena   = arena,
    };

    manifest_claim_t here = manifest_kept(&n, filesystem_path);
    if (here.storage_path) return arena_strdup(arena, here.storage_path);

    return manifest_ascend(&n, filesystem_path);
}

/**
 * The name `profile` has for `filesystem_path` under this view
 */
const char *manifest_claim_name(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path
) {
    CHECK_NULL(arena);
    CHECK_NULL(manifest);
    CHECK_NULL(filesystem_path);

    /* The claim it holds there, before the name one would take: a derived claim
     * is held and names nothing, so the ascent climbs past it and would answer
     * a name the profile never held. Else the name the profile would give the
     * place — its label's word at a root of its own. Either answer is the arena's:
     * the row's name is copied, as the namer's own leaf clause copies. */
    const manifest_row_t *row = manifest_lookup_claim(manifest, profile, filesystem_path);

    return row ? arena_strdup(arena, row->storage_path)
               : manifest_name(arena, manifest, profile, filesystem_path, NULL);
}

/**
 * The first of `profile`'s places whose side a command's claims would move
 *
 * The profile's places as the layer finds them (manifest_places), each asked
 * the layer's own question twice (manifest_fresh): of the claims committed, and
 * under the command's. A side moves where the two answers part. The places and
 * the ascents are scratch in the caller's arena, the module's idiom; the answer
 * is the view's row.
 */
const manifest_row_t *manifest_moved_place(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const hashmap_t *pending
) {
    CHECK_NULL(arena);
    CHECK_NULL(manifest);

    const contribution_t *c = manifest_contribution(manifest, profile);
    if (!c) return NULL;

    manifest_row_t **places = arena_calloc(arena, c->count, sizeof(*places));
    const size_t place_count = manifest_places(c, places);

    /* The profile as committed, and as this command would leave it */
    const naming_t before = {
        .c       = c,
        .mounts  = manifest->mounts,
        .profile = c->profile,
        .pending = NULL,
        .arena   = arena,
    };
    const naming_t after = {
        .c       = c,
        .mounts  = manifest->mounts,
        .profile = c->profile,
        .pending = pending,
        .arena   = arena,
    };

    for (size_t p = 0; p < place_count; p++) {
        const char *filesystem_path = places[p]->filesystem_path;
        if (manifest_fresh(&before, filesystem_path) !=
            manifest_fresh(&after, filesystem_path)) {
            return places[p];
        }
    }

    return NULL;
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
 * The blob the view holds strictly above a path
 */
const manifest_row_t *manifest_blob_above(
    const manifest_t *manifest,
    const char *filesystem_path
) {
    CHECK_NULL(manifest);
    CHECK_NULL(filesystem_path);

    return manifest_index_blob_above(manifest->index, NULL, filesystem_path);
}

/**
 * Does an active path lie strictly beneath `path`?
 */
bool manifest_active_beneath(const manifest_t *manifest, const char *path) {
    if (!manifest || !path) return false;

    /* The spine is the rows standing, in no order a bound could read: every row
     * is asked */
    const size_t len = strlen(path);
    for (size_t i = 0; i < manifest->count; i++) {
        if (str_path_beneath(manifest->rows[i]->filesystem_path, path, len)) {
            return true;
        }
    }

    return false;
}

/**
 * The one row holding this name, or a refusal naming every holder
 */
error_t manifest_holder(
    arena_t *arena, const manifest_t *manifest, const char *storage_path,
    const manifest_row_t **out_row
) {
    CHECK_NULL(arena);
    CHECK_NULL(manifest);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_row);

    /* The holders counted, the last one kept: one is the answer, and none is an
     * answer too. A row holds its name where its profile holds the row, so the
     * layer's rung, under a name no profile holds, is no holder. */
    size_t holders = 0;
    const manifest_row_t *held = NULL;
    for (size_t i = 0; i < manifest->count; i++) {
        const manifest_row_t *row = manifest->rows[i];
        if (strcmp(row->storage_path, storage_path) == 0 && manifest_holds_row(manifest, row)) {
            held = row;
            holders++;
        }
    }
    *out_row = holders == 1 ? held : NULL;
    if (holders < 2) return NULL;

    /* Several: each named with the path that tells it apart, in the spine's order,
     * which is precedence order — manifest_layer cuts it contribution by
     * contribution — and joined in the caller's arena, where nothing is owed a
     * release. */
    string_array_t named;
    string_array_init(&named, arena, holders);
    for (size_t i = 0; i < manifest->count; i++) {
        const manifest_row_t *row = manifest->rows[i];
        if (strcmp(row->storage_path, storage_path) != 0 || !manifest_holds_row(manifest, row)) {
            continue;
        }
        string_array_pushf(&named, "%s (%s)", row->profile, row->filesystem_path);
    }

    return error_create(
        ERR_INVALID_ARG, "'%s' is held by %zu profiles: %s",
        storage_path, holders, string_array_join(arena, &named, ", ")
    );
}

/**
 * Attribute the transition between two views to profiles, in their claims
 *
 * Two passes — every claim of `after` for the gain side, every claim of `before`
 * for the loss side — over an index of profile → stats slot, the profile's own
 * claim at a path `after` stands nothing at (manifest_lookup_claim), and a search
 * of the record by path for a claim that departed (state_find_record); then each
 * profile's departed rows, gathered into the slice that lends them. Nothing is
 * written; the rule for what a claim `after` lacks means for apply is the one
 * the workspace reads when it meets the record there — a claim its profile still
 * holds is overridden, the landing's of the blob above it, and any other has
 * departed, which leaves apply an orphan where a record stands. Nothing here
 * can fail: the one thing a caller can get wrong, a profile named twice, is its
 * bug.
 */
void manifest_diff(
    const manifest_t *before,
    const manifest_t *after,
    const state_record_t *records,
    size_t record_count,
    const string_array_t *profiles,
    arena_t *arena,
    manifest_diff_stats_t *out_stats
) {
    CHECK_NULL(after);
    CHECK_NULL(profiles);
    CHECK_NULL(arena);
    CHECK_NULL(out_stats);

    /* Stats attribution index. Maps profile name → its out_stats slot (the caller's
     * array, sized before the map is built — the pointers are stable). Keys are
     * borrowed from profiles; the caller keeps it alive for the duration of this
     * call. The index is the call's alone, in a frame freed at its end: the answer
     * is the caller's array. */
    arena_t *frame = arena_create(0);
    hashmap_t *stats_map = hashmap_borrow(frame, profiles->count);
    for (size_t i = 0; i < profiles->count; i++) {
        const char *name = profiles->entries[i];

        /* Duplicate profile names would silently collapse: hashmap_set overwrites,
         * so the later occurrence's slot would receive all attribution and the
         * earlier slot would stay zero-filled. Every caller hands in a set —
         * the enabled set, or a request deduplicated as it was read — so a
         * duplicate is the caller's bug, named here rather than counted wrong. */
        CHECK_ARG(
            !hashmap_has(stats_map, name), "a diff was asked to count one profile twice"
        );

        memset(&out_stats[i], 0, sizeof(out_stats[i]));
        out_stats[i].profile = name;
        hashmap_set(stats_map, name, &out_stats[i]);
    }

    /* Gain side: every claim of `after`, attributed to the profile it stands
     * under. A derived row counts nowhere — the way to the claims beneath it,
     * which apply creates as they need it — and what `before` stood at the path
     * splits the claims into added / updated / unchanged. */
    manifest_rows_t rows = manifest_rows(after);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (manifest_is_derived(row)) continue;

        manifest_diff_stats_t *slot = hashmap_get(stats_map, row->profile);
        if (!slot) continue;

        /* No claim before — no row, or the way a derived row was — is a claim
         * born. Against one, every field of what stands there, in the row's own
         * order, but the two flags: the encrypted stamp is the blob's own and
         * moves with the blob, and between two claims a class flip is a type
         * flip. */
        const manifest_row_t *old = manifest_lookup(before, row->filesystem_path);
        if (!old || manifest_is_derived(old)) {
            slot->added++;
        } else if (old->type != row->type ||
            !git_oid_equal(&old->blob_oid, &row->blob_oid) ||
            old->mode != row->mode || !str_equal(old->owner, row->owner) ||
            !str_equal(old->group, row->group)) {
            slot->updated++;
        }
    }

    /* Loss side: every claim of `before`, attributed to its former owner, a derived
     * row counting nowhere here either. A path still in `after` under another
     * profile is a reassignment (for user-facing "A → B" messaging); a path `after`
     * lacks is overridden where its profile claims it still, else departed if a
     * record stands at it — the slot it departed from noted beside the row, one
     * note a row of `before`, in the frame */
    rows = manifest_rows(before);
    manifest_diff_stats_t **departed = arena_calloc(frame, rows.count, sizeof(*departed));
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *old = rows.entries[i];
        if (manifest_is_derived(old)) continue;

        manifest_diff_stats_t *slot = hashmap_get(stats_map, old->profile);
        if (!slot) continue;

        const manifest_row_t *row = manifest_lookup(after, old->filesystem_path);
        if (row) {
            if (strcmp(old->profile, row->profile) != 0) slot->reassigned++;
            continue;
        }

        /* The profile claims the path still, and it stands nowhere: with no row
         * at its path, a blob stands above it (manifest_layer), and its copy is
         * that blob's landing's. It has not departed, so no record is asked. */
        if (manifest_lookup_claim(after, old->profile, old->filesystem_path)) {
            slot->overridden++;
            continue;
        }

        /* The record, searched by path (state_find_record): a departed claim
         * with one leaves an orphan, whose fate is the orphan analysis's at apply;
         * one without leaves nothing for apply to do. */
        if (state_find_record(records, record_count, old->filesystem_path)) {
            departed[i] = slot;
            slot->departed.count++;
        }
    }

    /* Each profile's departed rows, `before`'s in its order: a slice of `arena`
     * made at the count the pass reached and filled from the notes, by a scan
     * that ends at the profile's last — a decision made once, and no slice grown */
    for (size_t p = 0; p < profiles->count; p++) {
        manifest_diff_stats_t *slot = &out_stats[p];
        const manifest_row_t **entries = arena_calloc(
            arena, slot->departed.count, sizeof(*entries)
        );

        for (size_t i = 0, n = 0; n < slot->departed.count; i++) {
            if (departed[i] == slot) entries[n++] = rows.entries[i];
        }
        slot->departed.entries = entries;
    }

    arena_free(frame);
}
