/**
 * manifest.c - Manifest module implementation
 *
 * The precedence oracle: manifest_build (every enabled profile, in precedence
 * order) and manifest_build_branch (one branch) share one per-profile step,
 * manifest_contribute, that places the claims a branch's walk shows (core/branch.h)
 * as manifest_row_t rows directly. There is no persistence step and no bridge
 * type: the view is computed into the caller's arena and read through the accessors
 * below.
 *
 * Key patterns:
 *   - Two layers, built in two moves (core/manifest.h): manifest_contribute places
 *     one profile's claims whole into that profile's own contribution — one row
 *     per path within it, the within-profile rule settled by manifest_settle —
 *     and manifest_layer then runs precedence over the settled contributions,
 *     once, into the view's index. Nothing published is ever rewritten: a row
 *     that loses a path keeps its own row and simply leaves the slice, which is
 *     what lets a lower profile's claim be read after a higher one wins
 *     (manifest_lookup_claim) and what makes an index the one thing that says
 *     who stands where.
 *   - One decode, placed: the per-profile step walks the branch it is handed
 *     (core/branch.h branch_walk), which reads its own tree's sheet — no caller
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
 *     so the leaf and the rung ask one producer (manifest_standing) and differ
 *     only in which of its two projections they take.
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
#include "core/branch.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * One profile's claims, placed under the topology, precedence aside
 *
 * One row per path within the profile, and its own index over them. `rows` is
 * allocated once at the step's tail, sized exactly from the index, and nothing
 * on it is ever rewritten: a name that lost the path and a derived claim an
 * explicit one retook stay in the arena and simply leave the slice.
 *
 * Both indexes are the build's arena's, as the view's own is; their keys borrow
 * the arena-backed path each row carries.
 */
typedef struct {
    const char *profile;           /* Arena-backed; the same pointer every row of it carries */
    manifest_row_t **rows;         /* The rows standing, in claim order (arena, exact) */
    size_t count;                  /* Rows standing */
    hashmap_t *index;              /* path → the row standing there (arena) */

    /* Every name the profile holds at a path it names more than once: the settle's
     * own group, NULL-terminated, in name order. NULL until a settle happens —
     * which is never, on a branch whose profile names each of its paths once.
     * The group outlives the contest because the decision does: manifest_standing
     * re-asks it wherever a name is read, an asker's own claims being able to
     * change which name the next settle keeps, and manifest_holds_name reads it
     * to answer whether a name is one the profile already holds.
     *
     * Every member is an explicit row. A contender is pushed only against a held
     * explicit claim — manifest_place_claim states that placement rule once,
     * for both kinds — so no reader of a group filters derived. */
    hashmap_t *contested;          /* path → manifest_row_t ** (arena) */
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

    /* Precedence over the settled contributions: the index, one winning row per
     * path, and the spine cut once from it at layering (manifest_layer). */
    manifest_row_t **rows;                       /* Arena, exact; the winners */
    size_t count;                                /* Rows in the spine */
    hashmap_t *index;                            /* Arena; path → the winning row */

    /* The table the rows were placed by, lent back by manifest_mounts: the build's
     * own, derived from the rows it read, or, for a branch's view, the caller's. */
    const mount_table_t *mounts;                 /* The build's, or the caller's */

    /* The claims the build could not place: no target binding here (manifest_unbound) */
    manifest_unbound_claim_t *unbound;           /* Arena; grouped by profile, in build order */
    size_t unbound_count;
    size_t unbound_capacity;

    /* The names the settle did not keep: another stands at the path (manifest_unkept) */
    manifest_unkept_claim_t *unkept;             /* Arena; grouped by profile, in build order */
    size_t unkept_count;
    size_t unkept_capacity;

    /* The enabled profiles the build found no branch for (manifest_missing) */
    const char **missing;                        /* Arena; in the enabled set's order */
    size_t missing_count;
    size_t missing_capacity;
};

/**
 * The claim walk: what one walk of one branch carries to place its claims
 *
 * Everything the walk's visitor needs to place one profile's claims where they
 * stand: the view and the contribution being filled, and the two lists the step
 * spends. Handed to the branch's walk once per profile and read at O(1) per claim.
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership — the mount table and the unbound
 *             slice are read and written through it
 * - contribution: the profile's own, borrowed from manifest_contribute: its
 *             arena-backed name (every row of this profile borrows the pointer,
 *             and the table is keyed by it to place a custom/ claim) and its
 *             path index
 * - placed / contenders: the step's build-local lists, borrowed — every row this
 *             profile placed, and the rows that arrived at a path it had already
 *             named. Both are spent when manifest_contribute returns.
 * - arena: borrowed, must not be NULL; per-row strings are abandoned to it
 *
 * The claims arrive decoded and lent for the visit (core/branch.h branch_walk),
 * so the walk carries no sheet: the branch read it.
 */
typedef struct {
    manifest_t *manifest;         /* Target view (modified by the visitor) */
    contribution_t *contribution; /* The profile's own claims and their index */
    ptr_array_t *placed;          /* Every row this step placed, in claim order */
    ptr_array_t *contenders;      /* The rows that met a path already named */
    arena_t *arena;               /* Arena for allocations (must not be NULL) */
} claim_walk_t;

/**
 * A row of this contribution at `filesystem_path`: allocated and on the list of
 * everything the profile placed
 *
 * Whether it *stands* at the path is the caller's next line — the index takes
 * it, or the contest does. Nothing here is ever reset or overwritten: a name
 * that loses keeps its own row and leaves the slice at the settle, which is what
 * lets a lower profile's claim be read after a higher one wins the path
 * (manifest_lookup_claim) and what makes an index the one thing that says who
 * stands where.
 *
 * `filesystem_path` is arena-borrowed from mount_resolve; the cast discards the
 * const qualifier its output type carries. The row keeps it as its key for the
 * view's life. Two names at one path produce two arena strings with equal content,
 * and both indexes key by content — no string is shared, and a hashmap_set that
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
 * and none possible — the branch's walk shows a name once (core/branch.h
 * branch_walk): a name the tree holds a blob at, or a sheet key it does not,
 * the content-authority rule having contradicted the rest before anything was
 * resolved. And a tree holds one blob per path, a sheet one item per key.
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
 * share a name (the tree holds one blob per path, the sheet one item per key,
 * and the content-authority rule settles the one name they can both carry before
 * the contest sees it).
 *
 * The slice grows in the arena, as the unbound one does. Every string must be
 * arena-backed by the caller; the entry borrows them for the view's lifetime.
 *
 * @param manifest Target view (must not be NULL)
 * @param profile Arena-backed profile name (must not be NULL)
 * @param row The row whose name did not stand (must not be NULL)
 * @param kept The name that did (must not be NULL)
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

/* The ascent and the standing are one rule read from two ends, and each asks
 * the other: a name is composed from what stands above the path, and what stands
 * where the profile names one path twice is what the next settle will keep there
 * — which is the ascent's own answer under this command's claims. The pair
 * terminates because the ascent reads rungs strictly above the path it is asked
 * about, so every turn is a strictly shorter path and the depth is bounded by
 * the rungs; it is entered at all only where a group stands. */
static const char *manifest_ascend(const naming_t *n, const char *filesystem_path);

/**
 * A row as a namer reads it
 *
 * The projection both layers meet in (core/manifest.h manifest_claim_t): a derived
 * row is no claim at all, naming neither itself nor what lies beneath it, and
 * every other row names its own path with its kind saying whether anything can
 * be named beneath. NULL projects to nothing standing, which is the answer a
 * path the profile holds nothing at is owed.
 */
static manifest_claim_t manifest_row_claim(const manifest_row_t *row) {
    if (!row || manifest_is_derived(row)) return (manifest_claim_t){ 0 };

    return (manifest_claim_t){
        .storage_path = row->storage_path,
        .kind = path_type_kind(row->type),
    };
}

/**
 * Which of the names in a group the contribution keeps at `filesystem_path`
 *
 * The settle's last clause, on its own so that it has one body: **the name the
 * profile would give the path fresh** stands where the profile holds it, and
 * the bytewise-least — the group's own head, the array being sorted by name —
 * stands where it does not.
 *
 * Two askers, one answer. manifest_settle asks it over the group it has just
 * built, with no pending layer, and stores the result; manifest_standing asks
 * it again wherever a name is read, because an asker's own uncommitted claims
 * change what the path's ascent composes and therefore which name the next settle
 * will keep (209 C3 §1.10). Spelling the rule once is what keeps the name the
 * view keeps and the name a namer gives from drifting apart.
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
 * @return The row whose name stands; never NULL
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
 * The claim standing at `filesystem_path` for this asker
 *
 * Three arms, and the first that speaks answers. Where the profile names the
 * path more than once, **the settle answers**: which of a profile's names stands
 * somewhere is the settle's question and never a single claim's, so it is asked
 * here under this command's claims rather than read off the last build. That is
 * what makes a capture land on the name the machine will use: a claim admitted
 * above a contested path changes what the path's ascent composes, and with it
 * the name the next settle keeps (209 C3 §1.10). A verb admits at such a path
 * only a name the profile already holds (core/manifest.h manifest_holds_name),
 * so the group is the whole of what that settle will decide over and the pending
 * layer cannot add to it.
 *
 * Where the profile names the path once or not at all, the two layers a namer
 * reads answer, nearest first. A claim the command has admitted and not yet
 * committed answers alone, whatever its kind: it is the nearer statement about
 * the place, so a staged FILE names its own path and nothing under it, shadowing
 * a tracked directory the branch holds at the same path exactly as it will once
 * committed. Where the command claimed nothing the profile's own committed row
 * speaks, projected into the same pair.
 *
 * The answer is what the profile's next contribution will stand at the path,
 * given the claims the asker has admitted **so far**: naming is a snapshot taken
 * when a path is listed, and a claim a later argument admits above one already
 * named does not re-name it (cmds/add.c).
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
 * @return The claim standing there, a NULL name when none does
 */
static manifest_claim_t manifest_standing(const naming_t *n, const char *filesystem_path) {
    const contribution_t *c = n->c;

    manifest_row_t **group =
        c && c->contested ? hashmap_get(c->contested, filesystem_path) : NULL;
    if (group) return manifest_row_claim(manifest_decide(n, filesystem_path, group));

    const manifest_claim_t *staged =
        n->pending ? hashmap_get(n->pending, filesystem_path) : NULL;
    if (staged) return *staged;

    return manifest_row_claim(c ? hashmap_get(c->index, filesystem_path) : NULL);
}

/**
 * The name `profile` composes for `filesystem_path` from what stands above it
 *
 * The table is asked once, up front: the deepest root of the profile enclosing
 * the path, and the tail past it (infra/mount.h mount_root_above). That one answer
 * is the whole of what the roots have to say here — where the ascent floors,
 * whether the path is itself a root, and the label and tail a name is spelled
 * from — where asking per rung answered the same question N+2 times.
 *
 * Then the rungs above the path, nearest first: the claim standing at each one
 * (manifest_standing — this command's own listing where it has one there, else
 * what the profile's committed claims settle on), and the path is composed beneath
 * the first that names what lies beneath it, a DIRECTORY claim of either layer
 * (manifest_claim_beneath). An ancestor claim names nothing, and a blob names
 * its own path and nothing under it — a name beneath a file is a tree entry the
 * stage refuses — so both are climbed past. Where no claim above gave a name,
 * the root's label and the tail spell one (infra/label.h label_compose), the
 * word alone at the root itself.
 *
 * The root is the floor and not a per-rung test, because no root of the profile
 * can stand strictly between it and the path — one that did would enclose the
 * path more tightly and have won the find. So `strlen(root->filesystem_path)`
 * is the one rung a root stands at, the root directory's being "/" like any other,
 * and the loop's condition says the ascent reaches it and stops. The claim standing
 * at every rung is still read before the root decides, the root's own rung
 * included: written the other way, a typed `home/jail` standing at web's own
 * target would be climbed past, and web's name for what lies beneath it would
 * be the binding's rather than its own claim's.
 *
 * The root directory is that rung on a machine where more than one root stands
 * at it — a HOME of "/" (a container's bare uid) or a target of one — because
 * one label takes the tie there (infra/mount.h mount_root_above) while a claim
 * keyed by any of the three words may stand at the same directory. Read, the
 * claim names what lies beneath it; skipped, the tie's label does, and a walk
 * beneath a tracked root offers its finds under a word the profile's own claim
 * contradicts.
 *
 * The scratch copy is the arena's and abandoned, the module's idiom, and is taken
 * for every path a root encloses — at a root the loop reads nothing of it, one
 * bump an arm to skip it is not worth, a root being one path of at most three.
 * How often the rest is paid is not "once per newly listed path": the ascent
 * runs for every path nothing stands at — including one a caller goes on to exclude
 * or refuse — and again at every contested path a namer reads, and again at every
 * contested rung one of those ascents passes through.
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

        /* What stands at this rung, and only a directory naming what lies beneath
         * it. */
        const char *above = manifest_claim_beneath(manifest_standing(n, rung));
        if (!above) continue;

        /* Past the rung and its separator — which the root directory, being its
         * own separator, does not have: the boundary infra/mount.c tail_under_root
         * reads at a root and infra/label.c label_split at a word, read here at
         * a rung. Off `filesystem_path`, because the truncation above took `rung`'s
         * byte at that offset. */
        const char *past = filesystem_path + len;
        if (*past == '/') past++;

        return arena_str_format(n->arena, "%s/%s", above, past);
    }

    /* Nothing of the profile's above it: the root's own label, and the tail —
     * the word alone at the root itself. */
    return label_compose(n->arena, root->label, tail);
}

/**
 * By filesystem path, then by name
 *
 * A parent's path is a strict prefix of its child's and strcmp puts a prefix
 * before every extension, so lexicographic order settles a contested parent before
 * a deeper group's ascent reads it. The name breaks the tie, so the order is
 * total and the runs are stable whatever qsort does with equals.
 */
static int filesystem_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_path = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_path ? by_path : strcmp((*ra)->storage_path, (*rb)->storage_path);
}

/**
 * Bytewise by name: the order a path's group is decided and reported in.
 */
static int name_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    return strcmp((*ra)->storage_path, (*rb)->storage_path);
}

/**
 * Decide every path this profile named twice, and record what did not stand
 *
 * The within-profile rule's last clause, run once the contribution is whole so
 * the ascent reads every tracked parent the profile has. The choice itself is
 * manifest_decide's, asked here with no pending layer — beneath its tracked parent,
 * else beneath its deepest root, which is the binding's custom/ over the portable
 * home/ over the absolute root/. Every other name is recorded against the one
 * that stood (manifest_note_unkept).
 *
 * The group is the index's holder plus the run, sorted whole, so the holder is
 * a member and not a special case: every loser reads bytewise, the first-arrived
 * included. No comparator carries `fresh` and no bool survives the loop.
 *
 * Two rows of one group can never share a name, so the order is total: the tree
 * holds one blob per path, the sheet one item per key, and the content-authority
 * rule contradicts the one name they can both carry at the blob, before either
 * name was resolved and long before the contest sees it.
 *
 * The group outlives this call, indexed on the contribution: what stands at a
 * contested path is a rule and not a fact the build fixes, so every namer that
 * reads the path asks it again under whatever claims it has admitted
 * (manifest_standing), and the admission that keeps such a group from growing
 * asks whether a name is one of these (manifest_holds_name).
 *
 * Empty on every profile that names each of its paths once, which is the whole
 * cost on a branch this machine authored alone.
 *
 * @param manifest Target view — the mount table, and the unkept slice (must not
 *                 be NULL)
 * @param c The contribution being settled (must not be NULL)
 * @param contenders The rows that met a path already named (must not be NULL)
 * @param arena Arena for the groups and the composed names (must not be NULL)
 */
static void manifest_settle(
    manifest_t *manifest,
    contribution_t *c,
    ptr_array_t *contenders,
    arena_t *arena
) {
    if (contenders->count == 0) return;

    /* The index of the groups, allocated where the first one is about to exist:
     * a contribution with no contender never has one, and the readers test the
     * pointer rather than a count. */
    c->contested = hashmap_borrow(arena, 8);

    /* What every question below is asked under: this contribution, and no claim
     * beyond it — the settle reads the branch as it arrived. */
    const naming_t n = {
        .c       = c,
        .mounts  = manifest->mounts,
        .profile = c->profile,
        .pending = NULL,
        .arena   = arena,
    };

    /* The contest, typed once: a ptr_array holds void *, and every read below
     * is a row's path or its name. */
    manifest_row_t **rows = (manifest_row_t **) contenders->entries;

    qsort(rows, contenders->count, sizeof(*rows), filesystem_order);

    for (size_t i = 0; i < contenders->count;) {
        const char *filesystem_path = rows[i]->filesystem_path;

        size_t count = 0;
        while (i + count < contenders->count &&
            strcmp(rows[i + count]->filesystem_path, filesystem_path) == 0) count++;

        /* The group: the name that arrived first, and the ones that met it. One
         * slot past them stays NULL — the group outlives this loop, and every
         * reader of it walks to the terminator. */
        manifest_row_t **group = arena_calloc(arena, count + 2, sizeof(*group));
        group[0] = hashmap_get(c->index, filesystem_path);
        for (size_t g = 0; g < count; g++) group[g + 1] = rows[i + g];
        qsort(group, count + 1, sizeof(*group), name_order);

        manifest_row_t *kept = manifest_decide(&n, filesystem_path, group);

        hashmap_set(c->index, filesystem_path, kept);

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
 * Walk visitor that places one of the branch's claims into the contribution
 *
 * The whole of the per-profile step the branch's walk drives (core/branch.h
 * branch_walk): one decoded claim at a time — its blobs first, then its directory
 * claims — a finished manifest_row_t or nothing. In order: the name kept, the
 * path it resolves to, a derived claim's yield to a held path, the row, and the
 * within-profile placement rule that says whether it stands or contends.
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The claim walk (claim_walk_t)
 * @return NULL: placing a claim fails nowhere
 */
static error_t manifest_place_claim(const branch_claim_t *claim, void *payload) {
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
     * be manufactured here. The shape was checked where the branch read the name
     * — a blob's at its walk, an item's at its parse — so the label is one. */
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

    const manifest_row_t *held = hashmap_get(c->index, filesystem_path);

    /* A derived claim never takes a held slot: it is a consequence of an older
     * name, not a source of new ones. Explicit outranks derived within one profile
     * as across them, so a tracked claim falls through to the placement rule
     * below and takes a derived row's slot there.
     *
     * Ancestors are structurally shared where claims are per-profile and
     * precedence-resolved, and two profiles that traverse the same directory
     * derive it identically: their claims carry no intent to conflict, so they
     * do not compete. That is manifest_layer's half of the rule; here the two
     * chains are one profile's own, and the first placed stands — the row says
     * the profile holds a subtree beneath the path, never which name its subtree
     * runs through.
     *
     * The first placed is the sheet's first key (the walk shows directory claims
     * in the sheet's own order, core/branch.h branch_walk, and the writer sorts,
     * core/metadata.c), and the tie-break settles more than a name: a derived
     * claim carries the mode, owner and group dotta creates the directory with,
     * and two chains captured at different moments can disagree about them —
     * 0700 under home/jail/etc, 0755 under custom/etc, one path. Neither is the
     * truer statement, both being what disk held when a walk passed through, so
     * the tie is stated here rather than decided. Nothing is recorded either:
     * manifest_unkept is names, and a derived claim named nothing. */
    if (held && claim->type == PATH_TYPE_DIRECTORY && !claim->tracked) return NULL;

    /* The row is the claim, placed: one profile's, and fresh — nothing is reset
     * or rewritten any more, so each field is written once, from the claim. Its
     * mode is the claim's or its type's floor (core/branch.h branch_claim_mode),
     * so the row leaves the build total; the strings it keeps are the arena's,
     * the profile's being the name the step duplicated. A contender is a finished
     * row and takes its own claim like any other. */
    manifest_row_t *row = manifest_place(walk->placed, filesystem_path, walk->arena);
    row->storage_path = storage_path;
    row->profile = c->profile;
    row->type = claim->type;
    git_oid_cpy(&row->blob_oid, &claim->blob_oid);
    row->mode = branch_claim_mode(claim);
    row->owner = arena_strdup(walk->arena, claim->owner);
    row->group = arena_strdup(walk->arena, claim->group);
    row->encrypted = claim->encrypted;
    row->tracked = claim->tracked;

    /* Then say whether it stands. The blobs arrive first, so while they do every
     * row of the contribution is a blob, and the first arm is exactly "nothing
     * stands here" and the second exactly "a second name of this profile", for
     * the settle to decide; a directory claim after them takes a derived row's
     * slot or contends with an explicit one. A directory claim at a blob's own
     * name never arrives — the branch drops it — which is what keeps the settle's
     * group free of two rows under one name. The sibling rule across profiles
     * is manifest_layer's, where an explicit claim takes a held path outright:
     * that is the whole difference between precedence and a profile naming one
     * place twice. */
    if (!held || manifest_is_derived(held)) {
        hashmap_set(c->index, filesystem_path, row);
    } else {
        ptr_array_push(walk->contenders, row);
    }

    return NULL;
}

/**
 * One profile's contribution: the claims its branch's walk shows, placed
 *
 * The per-profile step both builders run, and the whole of the within-profile
 * rule. The contribution is registered here — its arena-backed name (every row
 * of it borrows the pointer), its own path index, and its slot in the view's
 * parallel arrays — so one function owns one profile's claims from the name to
 * the settled spine, and the builders hand over a branch.
 *
 * The branch's walk shows every claim the branch makes, decoded (core/branch.h
 * branch_walk) — its blobs, then the directory claims its own tree does not
 * contradict — and each is placed as it arrives (manifest_place_claim): resolved
 * against the mount table, recorded where this machine cannot place it
 * (manifest_note_unbound), and standing or contending. The settle then decides
 * every path this profile named twice, and the tail cuts the spine to what stands.
 *
 * The walk reads the branch's own sheet, strictly: a sheet that will not load
 * fails the build rather than read as "no claims", so no caller of a builder
 * chooses a policy for a fact this step is the authority on.
 *
 * Memory: every allocation lands in `arena`, the step's two lists included, which
 * stay there past the call, but the sheet the walk reads where no question has
 * yet, which the branch keeps (core/branch.h); no row borrows the branch — each
 * takes an arena copy. On error, rows already placed are left as they are — the
 * build fails whole, and nothing frees a view.
 *
 * @param manifest Target view (must not be NULL; its mount table is what places
 *                 rows)
 * @param branch The profile's branch (must not be NULL; its name is copied, and
 *               its sheet read through it)
 * @param arena Arena backing the contribution (must not be NULL)
 * @return Error or NULL on success
 */
static error_t manifest_contribute(
    manifest_t *manifest,
    branch_t *branch,
    arena_t *arena
) {
    /* Register the contribution before anything can fail into it: the name is
     * arena-backed so the view never depends on the branch or on the state's
     * row cache, and the index is the arena's too, so a build that stops partway
     * leaves nothing behind but the arena's bytes. */
    contribution_t *c = &manifest->contributions[manifest->profile_count];

    c->profile = arena_strdup(arena, branch_profile(branch));
    c->index = hashmap_borrow(arena, 128);
    manifest->profiles[manifest->profile_count++] = c->profile;

    /* The step's two lists, read only while it runs: every row this profile placed,
     * in claim order, and the rows that met a path it had already named. The
     * second is empty on every profile that names each of its paths once. Both
     * are the build's arena's, left there when the step returns: a pointer per
     * row placed. */
    ptr_array_t placed;
    ptr_array_t contenders;
    ptr_array_init(&placed, arena);
    ptr_array_init(&contenders, arena);

    claim_walk_t walk = {
        .manifest     = manifest,
        .contribution = c,
        .placed       = &placed,
        .contenders   = &contenders,
        .arena        = arena
    };

    /* The branch's claims, decoded once and read strictly, each placed as it
     * arrives (manifest_place_claim). Per-profile is the correctness boundary
     * for attribution — each profile places its own files and directories via
     * its own branch, never via a cross-profile merge — and the table is the
     * view's, its bindings keyed by profile, so a custom/ claim of this profile
     * places under this profile's target and no other's. The walk names the profile
     * over its own failures (core/branch.h), so nothing here says it again. */
    error_t err = branch_walk(branch, BRANCH_READ_STRICT, manifest_place_claim, &walk);
    if (err) return err;

    /* Every path this profile named twice, decided once. */
    manifest_settle(manifest, c, &contenders, arena);

    /* The contribution's rows: what the index points at, in claim order. A name
     * that lost and a derived claim an explicit one retook stay in the arena
     * and leave the slice. Sized exactly — the index is the count. */
    size_t standing = hashmap_size(c->index);
    if (standing > 0) {
        c->rows = arena_calloc(arena, standing, sizeof(*c->rows));
        for (size_t j = 0; j < placed.count; j++) {
            manifest_row_t *row = placed.entries[j];
            if (hashmap_get(c->index, row->filesystem_path) == row) {
                c->rows[c->count++] = row;
            }
        }
    }

    return NULL;
}

/**
 * Precedence over the settled contributions, and the winners' spine
 *
 * Today's cross-profile rule, applied to finished contributions instead of to
 * rows mid-build: for each contribution in precedence order, an explicit row
 * takes the path whatever stands there, and a derived one only fills an empty
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
 */
static void manifest_layer(manifest_t *manifest, arena_t *arena) {
    for (size_t i = 0; i < manifest->profile_count; i++) {
        const contribution_t *c = &manifest->contributions[i];
        for (size_t j = 0; j < c->count; j++) {
            manifest_row_t *row = c->rows[j];

            /* A derived row only fills an empty path; an explicit one takes
             * whatever stands there. */
            if (manifest_is_derived(row)) {
                hashmap_add(manifest->index, row->filesystem_path, row);
            } else {
                hashmap_set(manifest->index, row->filesystem_path, row);
            }
        }
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
}

/**
 * Allocate a fresh manifest_t, ready for the per-profile step.
 *
 * The view struct, the contributions array and the profile list beside it (both
 * sized for the profiles the build will walk at most) are arena-allocated, and
 * so is the index, which borrows its keys from the rows it points at
 * (hashmap_borrow); each contribution fills its own slot as it is registered
 * (manifest_contribute). No spine is allocated here: each is cut once, exactly,
 * from the index that decides it.
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
    state_profiles_t profiles = state_profiles(state);

    /* The topology the same rows describe — each profile's target, and this
     * machine's $HOME — built here, from the rows of this instant, so a custom/
     * path always resolves under the target the row it came from carries. */
    mount_table_t *mounts = NULL;
    error_t err = manifest_mount_table(state, NULL, arena, &mounts);
    if (err) return err;

    manifest_t *manifest = manifest_allocate(arena, 128, profiles.count);
    manifest->mounts = mounts;

    /* One contribution per profile, in order; precedence runs over them once
     * every one of them is settled. */
    for (size_t i = 0; i < profiles.count; i++) {
        const char *profile = profiles.entries[i].name;

        /* The profile's tree, scoped to the iteration, or none where its branch
         * is gone — and "missing" is not "broken": missing is an observation —
         * the profile contributes nothing, is listed among the missing
         * (manifest_missing) and not among the view's profiles, and the workspace
         * reads its records as orphans — broken is an error that must propagate. */
        git_tree *tree = NULL;
        err = gitops_branch_tree(repo, profile, &tree);
        if (err) return err;
        if (!tree) {
            manifest_note_missing(manifest, arena_strdup(arena, profile), arena);
            continue;
        }

        /* The profile's claims: its branch over the tree just opened, its sheet
         * read by the branch's walk from that tree, under the name whose claims
         * they are. One view, many branches. The name the step copies is what
         * every row of it borrows, so the view never depends on the state's row
         * cache, and the branch goes with the tree. */
        branch_t *branch = branch_open(repo, profile, tree);
        err = manifest_contribute(manifest, branch, arena);
        branch_free(branch);
        git_tree_free(tree);

        if (err) return err;
    }

    manifest_layer(manifest, arena);

    *out = manifest;
    return NULL;
}

/**
 * Build the manifest from one branch
 */
error_t manifest_build_branch(
    branch_t *branch,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(branch);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    manifest_t *manifest = manifest_allocate(arena, 128, 1);

    /* mounts borrows from a function parameter — it outlives the branch's walk,
     * and the table outlives the view (manifest_mounts lends it). The branch is
     * the caller's, and the view keeps nothing of it. */
    manifest->mounts = mounts;

    /* One contribution, settled and layered like any other, so a branch's view
     * answers manifest_lookup_claim and manifest_name exactly as an enabled view
     * does. */
    error_t err = manifest_contribute(manifest, branch, arena);
    if (err) return err;

    manifest_layer(manifest, arena);

    *out = manifest;
    return NULL;
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

    return c ? hashmap_get(c->index, filesystem_path) : NULL;
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
     * it holds there, the standing one among them — so membership is the whole
     * question and which of them stands is not asked. */
    manifest_row_t **group =
        c->contested ? hashmap_get(c->contested, filesystem_path) : NULL;
    if (group) {
        for (size_t g = 0; group[g]; g++) {
            if (strcmp(group[g]->storage_path, storage_path) == 0) return true;
        }
        return false;
    }

    const manifest_row_t *row = hashmap_get(c->index, filesystem_path);

    return row && !manifest_is_derived(row) &&
           strcmp(row->storage_path, storage_path) == 0;
}

/**
 * What `profile` calls `filesystem_path` under this view
 *
 * The leaf clause and the ascent, over the one read that answers what stands
 * somewhere (manifest_standing): the claim standing at the path names it whatever
 * its kind — this command's own if it has admitted one there, since it has already
 * named this very path, and the one the next settle will keep where the profile
 * names the path twice — and a path nothing stands at falls through to the ascent,
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

    manifest_claim_t here = manifest_standing(&n, filesystem_path);
    if (here.storage_path) return arena_strdup(arena, here.storage_path);

    return manifest_ascend(&n, filesystem_path);
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
     * answer too. */
    size_t holders = 0;
    const manifest_row_t *held = NULL;
    for (size_t i = 0; i < manifest->count; i++) {
        if (strcmp(manifest->rows[i]->storage_path, storage_path) == 0) {
            held = manifest->rows[i];
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
    string_array_init_cap(&named, arena, holders);
    for (size_t i = 0; i < manifest->count; i++) {
        const manifest_row_t *row = manifest->rows[i];
        if (strcmp(row->storage_path, storage_path) != 0) continue;
        string_array_pushf(&named, "%s (%s)", row->profile, row->filesystem_path);
    }

    return error_create(
        ERR_INVALID_ARG, "'%s' is held by %zu profiles: %s",
        storage_path, holders, string_array_join(arena, &named, ", ")
    );
}

/**
 * Attribute the transition between two views to profiles
 *
 * Two passes — every row of `after` for the gain side, every row of `before`
 * for the loss side — over an index of profile → stats slot, and a search of
 * the record by path for the departure split (state_find_record). Nothing is
 * written; the rule for what a departure means for apply is the record's presence
 * and ownership at the path, the same fact the workspace reads when it meets
 * the orphan. Nothing here can fail: the one thing a caller can get wrong, a
 * profile named twice, is its bug.
 */
void manifest_diff(
    const manifest_t *before,
    const manifest_t *after,
    const state_record_t *records,
    size_t record_count,
    const string_array_t *profiles,
    manifest_diff_stats_t *out_stats
) {
    CHECK_NULL(after);
    CHECK_NULL(profiles);
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

    /* Gain side: every row of `after`, attributed to its winner. What `before`
     * had at the path splits claimed into added / updated / unchanged. */
    manifest_rows_t rows = manifest_rows(after);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        manifest_diff_stats_t *slot = hashmap_get(stats_map, row->profile);
        if (!slot) continue;

        slot->claimed++;

        /* Every field of what stands there, in the row's own order, but the
         * encrypted stamp: the blob's own, it moves with the blob. `tracked`
         * sits beside the mode for the same reason the mode is here: a directory
         * that stops being a scan root and a convergence target — or becomes
         * one — is a different promise at the path, and a class flip usually
         * carries the same mode across, so without this term the receipt would
         * call it unchanged. */
        const manifest_row_t *old = manifest_lookup(before, row->filesystem_path);
        if (!old) {
            slot->added++;
        } else if (old->type != row->type ||
            !git_oid_equal(&old->blob_oid, &row->blob_oid) ||
            old->mode != row->mode || !str_equal(old->owner, row->owner) ||
            !str_equal(old->group, row->group) || old->tracked != row->tracked) {
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

        /* The record, searched by path for the orphan split (state_find_record):
         * a departed row with a record dotta owns leaves an orphan apply prunes
         * (or releases, if Git let go), one with a record dotta never owned leaves
         * one the ownership gate releases, one without leaves nothing for apply
         * to do. */
        const state_record_t *record = state_find_record(
            records, record_count, old->filesystem_path
        );
        if (!record) continue;
        if (record->deployed_at > 0) {
            slot->orphans.owned++;
        } else {
            slot->orphans.observed++;
        }
    }

    arena_free(frame);
}
