/**
 * manifest.h - The precedence oracle
 *
 * The manifest is the precedence-resolved view of every enabled profile at HEAD:
 * one row per managed filesystem path, both kinds, the winning profile's claim
 * already applied (manifest_row_t, below). It is computed from Git at every load
 * and never stored — Git × the state's rows × this machine's $HOME → rows is a
 * pure function; the enabled set and each profile's target are read from the
 * state handle's row cache (core/state.h), the mount table is derived from them
 * inside the build, and nothing here writes. Surface is two-fold — builders and
 * readers — with one function beside them: manifest_mount_table, the build's
 * own table derivation on its own, for a command that needs this machine's topology
 * without a view (include/runtime.h).
 *
 * The view has two layers. A **contribution** is one profile's claims placed
 * under this machine's topology: its tree's blobs and its sheet's directory items,
 * one row per location *within the profile*, with what this machine cannot place
 * recorded beside it (manifest_unbound) and what the profile names twice recorded
 * against the name it kept (manifest_unkept). A contribution is what one branch
 * says about this machine, precedence aside. The **index** is precedence over
 * settled contributions: one winning row per location, a later profile's explicit
 * claim taking a held location and a derived one only filling an empty one.
 *
 * Everything that asks *who wins* reads the index — manifest_lookup, manifest_rows,
 * manifest_lookup_storage, manifest_holders, manifest_diff: deployment, the
 * record's join, the workspace, every screen. Everything that asks *what does
 * this profile call this location* reads that profile's own contribution —
 * manifest_lookup_claim, manifest_name: a location P lost to a higher profile
 * is still named by what P holds.
 *
 * Within one profile, at one location: an explicit claim (a blob of any type, a
 * `tracked` directory item) outranks a derived one whichever arrives first, and
 * nothing is recorded — the derived row named nothing; a DIRECTORY item whose
 * own name the tree holds a blob at is stale metadata and claims nothing, a path
 * being a tree or a blob and the tree the content authority; and two explicit
 * names are decided when the contribution is whole — **the name the profile would
 * give the location fresh** stands (manifest_name's ascent), or the bytewise-least
 * where the branch holds no such name, and every other is recorded against it.
 *
 * Two things a claim can fail to become, and the health channel says both. A
 * claim this machine cannot place has no location: manifest_unbound, the repair
 * a `--target`. A claim the view did not **keep** has one, and another name of
 * the same profile stands there: manifest_unkept, the repair a `remove`. Both
 * are claims the branch holds and the view has no row for, for two different
 * reasons; a claim precedence hides is neither — it is **overridden**, the normal
 * shape of layering, and no health question at all. A name the view did not keep
 * is in the branch and in no row: no screen, no filter and no record join meets
 * it, and `remove` — which reads the branch, not the view — is the one verb that
 * can still name it.
 *
 *   - Builders: manifest_build walks every enabled profile in precedence order
 *     (later profiles override earlier); manifest_build_tree walks one Git tree
 *     — the historical-diff path (cmd_diff) — and is the same per-profile step
 *     applied once. Each step loads the claim sheet of the tree it reads: a tree
 *     without one holds an empty sheet, and a sheet that will not load fails
 *     the build rather than read as "no claims", so no caller of a builder chooses
 *     a policy for a fact the builder is the authority on. That is the view's
 *     rule and only the view's — a command reading a sheet for its own screen
 *     decides for itself (core/metadata.h). Both produce manifest_row_t rows
 *     directly, the one row shape every consumer reads, so there is no bridge
 *     between the build step and its readers. The dispatcher builds the view
 *     once per command for the commands that declare it (ctx->run.manifest,
 *     include/runtime.h); a command that moves Git or the enabled set builds
 *     the post-mutation view itself.
 *
 *   - Readers: manifest_rows (every winning row, both kinds, unordered),
 *     manifest_profiles (the profiles the rows came from, in precedence order),
 *     manifest_mounts (the table the rows were placed by, lent), manifest_lookup
 *     (by filesystem path, O(1)), manifest_lookup_storage (by claim — a storage
 *     path under one profile, linear), manifest_holders (how many rows hold a
 *     name, and the one when one does), manifest_lookup_claim and manifest_name
 *     (one profile's own contribution, whoever won the location); and
 *     manifest_diff, the per-profile delta between two views that the
 *     scope-changing verbs and sync print their receipts from.
 *
 * Core Principles:
 *   - Pure: the view is a function of Git, the state's rows and $HOME — the same
 *     inputs give the same rows on every machine
 *   - Computed, never stored: every load builds it; nothing invalidates it because
 *     nothing is held past its lifetime
 *   - Precedence-aware over settled contributions — a profile's claims are placed
 *     whole before any of them is compared with another's: one row per path,
 *     the winner's kind, later profiles overriding earlier, except that a derived
 *     directory claim only ever fills an empty slot (manifest_row_t's `tracked`)
 *
 * Workflow:
 *   Commands → manifest_build → rows → workspace / deploy / cleanup
 */

#ifndef DOTTA_MANIFEST_H
#define DOTTA_MANIFEST_H

#include <git2.h>
#include <string.h>
#include <sys/stat.h>
#include <types.h>

#include "base/hashmap.h"
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
 * Winner or not: `profile` is the profile whose claim the row is, and a row is
 * never rewritten when a higher profile takes its location. A row read through
 * the view's index stands there; a row read through manifest_lookup_claim is
 * one profile's claim at a location whether or not it stands.
 *
 * Strings are arena-backed by the producer; rows are read through `const
 * manifest_row_t *` and live for the producer's arena. The precedence oracle
 * below produces rows, the workspace partitions them, deploy and cleanup plan
 * over them.
 */
typedef struct manifest_row {
    /* Identity */
    char *filesystem_path;      /* Deployed path (/home/user/.bashrc): physical spelling */
    char *storage_path;         /* Path in profile (home/.bashrc) */
    char *profile;              /* The profile whose claim the row is */

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
 * Is the row the claim (`profile`, `storage_path`)?
 *
 * The test a writer of the record makes before it advances one against a row. A
 * record binds what dotta confirmed — the blob, the stat — to the claim it names,
 * so the row has to be that very claim: the winner standing at a location may
 * be another claim of the same profile — a branch that arrived from a machine
 * whose roots kept two names apart holds both — and its blob is neither what
 * was captured nor anything the record's own name can be read under (core/state.h
 * anchor_t). Both halves, because within one profile a location is not an identity.
 *
 * Readers: add's two anchor loops (cmds/add.c), update's capture loop
 * (cmds/update.c), the workspace's confirmation recorder (core/workspace.c) and
 * apply's two acknowledgement loops (cmds/apply.c), which are what moves a record
 * onto the claim standing at its path. The let-go loops ask the other direction
 * — whether any row still stands at the path — and are not readers of this. NULL
 * is no claim.
 */
static inline bool manifest_is_claim(
    const manifest_row_t *row, const char *profile, const char *storage_path
) {
    return row && strcmp(row->profile, profile) == 0 &&
           strcmp(row->storage_path, storage_path) == 0;
}

/**
 * Is the row an ancestor claim — a directory derived from the chain above a managed
 * path, never named by anyone?
 *
 * The bottom of the lattice a namer reads: the one kind of row that does not
 * name its own location. Every other kind does, a blob as much as a tracked
 * directory, so this is not the test for whether anything may be named *beneath*
 * a row. That one is narrower — a tracked directory alone (manifest_claim_beneath)
 * — and a walker that composes children beneath every row this answers false
 * for composes them beneath a blob, where the namer composes beneath the root's
 * label instead.
 *
 * What reads it: the projection of a row into a claim gives it none, a contribution
 * lets an explicit claim of the same profile take its slot, the index lets it
 * fill an empty location and never take a held one, and a search reads it as
 * "the profile holds a subtree beneath here" — one of possibly several chains,
 * never a name (manifest_lookup_claim's note). False on every other kind, where
 * `tracked` is false and nothing reads it.
 *
 * Readers: the projection a namer reads a row through, the two claim passes and
 * the layering (core/manifest.c).
 */
static inline bool manifest_is_derived(const manifest_row_t *row) {
    return row && row->type == PATH_TYPE_DIRECTORY && !row->tracked;
}

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
 * is heap-allocated and released by manifest_free. A view built over the enabled
 * set borrows nothing else — not the state's row cache it was read from — so it
 * stands across the mutations that invalidate the cache, for the arena's lifetime.
 * A tree view borrows the one thing its caller handed it, the mount table, and
 * lends it back (manifest_mounts).
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
 * (manifest_mount_table): a re-target is in the next build because the next build
 * reads the rows. A custom/ claim whose profile has no target binding on this
 * machine — a normal lifecycle stage in a shared repository — contributes no
 * row and is recorded on the view (manifest_unbound); the health consumers surface
 * it, and the build stays total over importable content.
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
 * Per profile, in order: the tree's blobs are placed first, then the DIRECTORY
 * items of its metadata.json, into that profile's own contribution — the
 * within-profile rule (the two layers, above): an explicit claim outranks a derived
 * one, a DIRECTORY item whose own name the tree holds a blob at is stale metadata
 * and claims nothing, and two explicit names at one location are decided when
 * the contribution is whole, the fresh name kept and every other recorded
 * (manifest_unkept). Only then does precedence run: across profiles the later
 * (higher) claim takes the location whatever its kind, a derived one filling an
 * empty location alone, so the view holds one row per path, the winner's kind.
 * A profile without metadata.json contributes no directories and is skipped,
 * not an error.
 *
 * Row order is unspecified; consumers that need parent-before-child sort their
 * own pointer arrays (the workspace does). The oracle is a set. What order there
 * is is each contribution's claim order, the contributions in precedence order
 * — so a path a higher profile overrides sits at the winner's place, not the
 * loser's.
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
 * One profile's view of one tree: a manifest_row_t row for every blob the tree
 * exposes (sans repository metadata files — .dottaignore, .bootstrap, .git/,
 * .dotta/) and for every DIRECTORY item the tree's own claim sheet carries —
 * the same per-profile step manifest_build runs, applied once, sheet included
 * (the Builders note above: the sheet is loaded here, never handed in, so one
 * rule reads it). Readers that want files only test row->type.
 *
 * The tree is the caller's to choose — a branch tip, a historical commit's, a
 * stage's — and `profile` names whose claims these are, since a tree carries no
 * name; the mount table is explicit for the same reason, there being no state
 * to derive one from and a past tree deliberately resolved under today's topology.
 * The sheet's claims are applied row-by-row in lockstep with the walk: mode,
 * owner, group and encrypted come from the tree's own metadata.json.
 *
 * Custom-prefix resolution is delegated to `mounts`. A custom/ claim the handle
 * records no binding for contributes no row and is recorded on the view
 * (manifest_unbound) — the same degrade contract as manifest_build, which lets
 * the historical-diff path resolve old trees whose labels today's topology cannot
 * place. Any mount table is acceptable, including one with no binding for
 * `profile`.
 *
 * One contribution, settled and layered like any other, so a tree view answers
 * manifest_lookup_claim and manifest_name for `profile` exactly as an enabled
 * view answers them for one of its own.
 *
 * Memory: same contract as manifest_build — every allocation produced by the
 * call lives in the caller's arena; the index is manifest_free's.
 *
 * @param repo Git repository the tree's blobs (the sheet among them) are read
 *             from (must not be NULL)
 * @param tree Git tree to build from (must not be NULL)
 * @param profile Profile name carried on each row, and the name the sheet is
 *                read under (must not be NULL; duplicated into the arena)
 * @param mounts Per-machine mount table (must not be NULL)
 * @param arena Arena backing every allocation produced by the call (must not be
 *              NULL)
 * @param out Manifest (must not be NULL; caller frees with manifest_free)
 * @return Error or NULL on success
 */
error_t *manifest_build_tree(
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
);

/**
 * Every winning row of the view, both kinds, unordered
 *
 * The index's rows — what stands at each managed location. A name a profile did
 * not keep and a claim a higher profile overrode are both absent: the first is
 * manifest_unkept's, the second is layering, and neither is a row.
 *
 * Pure value return — no allocation, no error path. The slice aliases the view's
 * own storage and is valid for the arena's lifetime.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over every winning row
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
 * The table the rows were placed by
 *
 * The one the build made from the rows it read (manifest_build), or the caller's
 * (manifest_build_tree). Borrowed for the view's lifetime — the build's is the
 * arena's, and a tree view's caller keeps its table alive as long as the view.
 * Rule 1, never cache a cache: a consumer that holds the view and needs the
 * topology it was placed by reads it here rather than building a second table
 * from the same rows, so the arguments it locates and the rows it selects read
 * one value. Readers: the dispatcher (`run.mounts` for a command that declares
 * the view, include/runtime.h); show and list without a profile, which build
 * the view themselves and locate the argument through its table.
 *
 * Pure value return — no allocation, no error path.
 *
 * @param manifest Manifest (NULL returns NULL)
 * @return Borrowed table, never NULL for a built view
 */
const mount_table_t *manifest_mounts(const manifest_t *manifest);

/**
 * The table the enabled rows describe
 *
 * The same derivation manifest_build runs before it places a row — each enabled
 * profile's (name, target) from the state's row cache, augmented with this
 * machine's $HOME and the empty-prefix root sentinel (infra/mount.h) — offered
 * without a view, for a command that declares `mounts` and not `manifest`
 * (include/runtime.h). A command declaring both reads manifest_mounts instead
 * and gets the view's own: one build, one value, and the arguments it locates
 * read the topology its rows were placed by. Rule 1, never cache a cache.
 *
 * The derivation stays the builder's, never a parameter of it: a re-target is
 * in the next view because the next build reads the rows again, and a caller
 * handed the table would have to remember to rebuild it after every mutation
 * that moves one — silently placing a custom/ row under yesterday's target when
 * it forgot.
 *
 * Name and target are read from the row cache for the call only — the table copies
 * every string it keeps — so the handle is a value: the topology the rows described
 * at the instant it was built, readable for the arena's lifetime whatever
 * enabled_profiles mutation follows.
 *
 * A state with no database has no rows and yields the bare table (HOME and the
 * root sentinel). A row read that fails on an opened database is an error and
 * propagates: a bare table in its place would classify every input as home/ or
 * root/ and resolve no custom/ path, silently.
 *
 * @param state State handle (must not be NULL; borrowed, not freed)
 * @param arena Arena backing the handle (must not be NULL; outlives the handle)
 * @param out Output handle (must not be NULL; lifetime tracks arena)
 * @return Error or NULL on success
 */
error_t *manifest_mount_table(
    const state_t *state,
    arena_t *arena,
    mount_table_t **out
);

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
 * pass without sorting. Each (profile, storage path) is recorded once, the dedup
 * by name: a stale DIRECTORY item at an unbound blob's storage path contributes
 * no second entry, which is the same test the bound path makes of the same pair
 * (a path is a tree or a blob, and the tree is the content authority). Empty on
 * every build whose claims all placed — the common case, costing nothing.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded claims, valid for the arena's lifetime
 */
manifest_unbound_t manifest_unbound(const manifest_t *manifest);

/**
 * One name a profile holds for a location it also names otherwise, recorded against
 * the name it kept.
 *
 * Strings are the build arena's; no row pointer — the entry says what this
 * profile's branch holds, and the index may point elsewhere. The name is in the
 * branch and in no row: `remove` is the one verb that can still take it, which
 * is why that is the repair.
 */
typedef struct {
    const char *profile;
    const char *storage_path;      /* the name that was not kept */
    path_kind_t kind;              /* its kind (a screen prints it with a suffix) */
    const char *kept;              /* the name the contribution kept at this location */
    const char *filesystem_path;   /* the location every name of the group resolves to */
} manifest_unkept_claim_t;

/**
 * Bound carrier for the view's second health slice, the manifest_rows_t idiom.
 */
typedef struct {
    const manifest_unkept_claim_t *entries;
    size_t count;
} manifest_unkept_t;

/**
 * The names the profiles hold for locations they also name otherwise
 *
 * Pure value return — no allocation, no error path. Grouped by profile in build
 * order, a location's entries contiguous and bytewise by name, so one linear
 * walk counts both names and locations without sorting. Each (profile, name)
 * appears once — a name resolves to one location under one profile, and a name
 * the tree and the sheet both carry is settled before the contest by the
 * content-authority rule. Empty on every build whose profiles each name their
 * locations once. A change of roots between two writes is what breaks that, and
 * this machine's own captures do it as readily as an import: capture under
 * `~/jail`, bind the profile there, capture again, and the branch holds
 * `home/jail/…` beside `custom/…` for one file.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded names, valid for the arena's lifetime
 */
manifest_unkept_t manifest_unkept(const manifest_t *manifest);

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
 * Look up a row by its claim: the storage path under one profile
 *
 * A name keys within one profile (infra/mount.h): the pair (profile, storage
 * path) names at most one row — under home/ and root/ precedence leaves one row
 * per name, and under custom/ one profile has one target — so the lookup is exact.
 * `profile` is required; a NULL profile names no row, the API's own return
 * convention, since a pointer-returning lookup has no CHECK_NULL to refuse with.
 * A caller with no profile in hand asks manifest_holders: the first of several
 * rows holding a name was never an answer.
 *
 * The winners, like every reader of the index: this asks whether a claim *wins*
 * somewhere, and a claim precedence overrode — or a name the profile did not
 * keep — wins nowhere and answers NULL. That is exactly what the workspace's
 * relocation read wants: a claim standing under another profile is not "relocated",
 * the copy at the old location is simply no longer active.
 *
 * Linear scan — its reader asks once per BACKED orphan (the workspace's relocation
 * read, each of which already cost a Git tree probe; a lazy per-profile storage
 * index inside the orphan pass's authority cache is the upgrade if a profile-wide
 * re-target ever makes the scan show up).
 *
 * @param manifest Manifest (NULL returns NULL)
 * @param storage_path Storage path to look up, e.g. "home/.bashrc" (NULL returns
 *                     NULL)
 * @param profile The claim's profile (NULL names no row)
 * @return Borrowed row pointer, or NULL when the profile holds no row at the name
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *storage_path,
    const char *profile
);

/**
 * How many rows hold this name, and the row when one does
 *
 * A name keys within one profile (infra/mount.h): under custom/ two profiles at
 * two targets hold one name for two files, and under home/ or root/ precedence
 * leaves one. The count is the caller's admission question — none, one, more —
 * and `*out_row` is the row iff exactly one holds the name: the claim a caller
 * without a profile may act on. It is NULL when none does and NULL when more
 * than one does — the first of several was the arbitrary answer this replaces
 * (show and list without -p read it, and answered one profile's file for
 * another's), and it has no reader; a caller that must name each holder walks
 * manifest_rows. Readers: show and list without a profile.
 *
 * The winners, like manifest_lookup_storage beside it: a name that wins nowhere
 * is held by nobody here.
 *
 * Linear scan, once per command.
 *
 * @param manifest Manifest (NULL yields 0)
 * @param storage_path Storage path, e.g. "custom/etc/foo" (NULL yields 0)
 * @param out_row Receives the one holder, or NULL (must not be NULL)
 * @return How many rows hold the name
 */
size_t manifest_holders(
    const manifest_t *manifest,
    const char *storage_path,
    const manifest_row_t **out_row
);

/**
 * The row `profile` holds at `filesystem_path` in its own contribution — the
 * claim it placed there, whether or not it wins the location in the index.
 *
 * NULL when the profile is not in the view, holds nothing there, or is NULL —
 * the API's own return convention, a pointer-returning lookup having no CHECK_NULL
 * to refuse with. O(P) over the profiles to find the contribution, then O(1): P
 * is the enabled set, and a caller that asks once per directory entry pays a
 * handful of strcmp.
 *
 * A DIRECTORY row here names and does not enumerate, and that is true of both
 * classes: neither is an identity for the subtree standing beneath the location.
 * A derived row says the profile holds a subtree there, and its `storage_path`
 * is one of the chains its own names run through — a profile bound after some
 * of its files were captured legitimately derives two. A tracked row says what
 * the profile will call paths beneath the location from now on, and says nothing
 * about the ones already captured: tracked `home/jail/etc` stands over
 * `home/jail/etc/a` and `custom/etc/b` alike, and its own Git subtree holds only
 * the first. A caller that wants the subtree reads the rows beneath the location,
 * never the tree beneath the name.
 *
 * No production reader yet: the namer holds the contribution already and reads
 * its index directly. The unit pins are what read this, and the first production
 * reader will be the claim search a profile-scoped verb makes.
 */
const manifest_row_t *manifest_lookup_claim(
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path
);

/**
 * A claim as a namer reads it: the name, and how far it reaches
 *
 * `kind` is the whole reason this is a value and not a string: a claim at a
 * location names the location whatever it is, but only a DIRECTORY names what
 * lies beneath it — a name beneath a blob is a tree entry the stage refuses. The
 * row is the claim entire, its mode and owner and blob (manifest_lookup_claim);
 * this pair is the claim as a namer needs it.
 *
 * The two layers a namer reads speak this one shape. A claim a verb has admitted
 * in this command and not yet committed — add's listing, the `pending` map — is
 * one; a row of the profile's own contribution projects into the other, a derived
 * row being no claim at all (it names neither itself nor what lies beneath:
 * manifest_is_derived) and every other row naming its own location, with its
 * kind saying whether anything can be named beneath it. A DIRECTORY the command
 * admitted is a claim it made — an argument, or a directory its walk entered; a
 * verb that would admit a derived claim has no business naming through it.
 *
 * The map is keyed by location in the spelling the view's own rows carry (what
 * mount_locate produced), which is what the ascent truncates to reach a rung;
 * and it is the asking profile's own listing, a claim of it standing in for that
 * profile's committed row at the same place and for no other profile's.
 *
 * A stored claim always names. A location a verb entered without claiming (a
 * root met from above) is stored with a NULL *value*: hashmap_has says walked,
 * hashmap_get says claimed. A NULL `storage_path` is nothing standing, and `kind`
 * says nothing then.
 */
typedef struct {
    const char *storage_path;
    path_kind_t kind;
} manifest_claim_t;

/**
 * The name anything beneath this claim's location composes under, or NULL when
 * nothing does
 *
 * The top of the lattice manifest_is_derived names the bottom of. A claim names
 * its own location whatever its kind — that is `storage_path`, read directly —
 * and only a DIRECTORY names what lies beneath it; a claim that names nothing
 * answers NULL by its name, whatever its kind says. So the two questions a namer
 * asks are one read and two projections of it, and neither leans on which value
 * of the kind is the enum's zero.
 *
 * Readers: the ascent's rung (core/manifest.c manifest_ascend). The walk that
 * lists a directory for capture and the scan that offers its untracked children
 * ask the same question by hand today, each down a climb of its own.
 */
static inline const char *manifest_claim_beneath(manifest_claim_t claim) {
    return claim.kind == PATH_KIND_DIRECTORY ? claim.storage_path : NULL;
}

/**
 * What `profile` calls `location` under this view
 *
 * Two layers at every rung, the location included, and the nearer answers alone:
 * a claim this command has admitted and not yet committed (`pending`: location
 * → manifest_claim_t; NULL for every other reader) speaks for the place whatever
 * its kind, and only where it says nothing does the profile's committed row speak.
 * So a staged blob shadows a tracked directory the branch holds at the same
 * location, exactly as it will once committed — where the blob takes the location
 * and the directory's name is the one the contribution does not keep.
 *
 * The claim standing at the location is its name; else the location is composed
 * beneath the nearest rung above it that names what lies beneath — a DIRECTORY
 * claim of either layer (manifest_claim_beneath), asked before the root at every
 * rung; else what the profile's own roots make of it (infra/mount.h mount_name),
 * which is NULL when the location is one of them. An ancestor claim names nothing,
 * and nothing is named beneath a blob. The profile's own contribution is read,
 * never the index: a location it lost to a higher profile is still named by what
 * it holds. `profile` may be NULL — the shared roots alone, as mount_name reads it.
 *
 * This is the rule the view itself runs when a profile names one location twice
 * — minus the leaf clause, which is the one thing a settle cannot ask, a name
 * standing there being what it is deciding. The settle takes the ascent's answer
 * alone and keeps the name of the group that IS it; where the branch holds none
 * of it — the composed name is a name nobody committed — the bytewise-least stands
 * instead. Every other name is manifest_unkept's, and this function then answers
 * the kept one at that location, whichever of the two ways it was chosen.
 *
 * The answer is the caller's arena's, whichever rung produced it; NULL is a root.
 *
 * @param manifest Manifest (must not be NULL)
 * @param profile The asker, or NULL for the shared roots alone
 * @param location Absolute location (must not be NULL)
 * @param pending The asking profile's uncommitted claims, keyed by location
 *                (manifest_claim_t), or NULL
 * @param arena Arena that owns `*out_storage` (must not be NULL)
 * @param out_storage Arena-backed storage path, NULL at a root (must not be NULL;
 *                    NULL after an error)
 * @return Error or NULL on success
 */
error_t *manifest_name(
    const manifest_t *manifest,
    const char *profile,
    const char *location,
    const hashmap_t *pending,
    arena_t *arena,
    const char **out_storage
);

/**
 * Free a manifest — the heap indexes only; rows are the arena's
 *
 * The view's own index and each contribution's. A build that failed partway has
 * as many contributions as it registered, so this frees exactly what it made.
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
 *
 * `reassigned` here is this transition's own delta — a path `before` held under
 * one profile that `after` gives another — and not the standing fact the screens
 * name by the same word: a record dotta owns naming a profile the row does not
 * is workspace_reassigned (core/workspace.h), true from whenever it began until
 * apply acknowledges it. Both appear in sync's receipt, twenty lines apart,
 * answering different questions.
 */
typedef struct {
    const char *profile;         /* Profile name (borrowed from the profiles filter) */

    /* Gain-side */
    size_t claimed;              /* Rows this profile wins in `after` */

    /* Gain-side, subsets of claimed (the remainder was unchanged) */
    size_t added;                /* … whose path `before` did not have */
    size_t updated;              /* … whose path `before` had, with blob, type, mode or class moved */

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
 *     the path; updated if it has one whose blob, type, mode or `tracked` class
 *     differs (owner/group travel with a metadata commit rare enough to ride on
 *     the workspace's verdict instead)
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
