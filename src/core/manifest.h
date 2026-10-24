/**
 * manifest.h - The view: every enabled profile's claims, placed and layered
 *
 * The manifest is the precedence-resolved view of every enabled profile at HEAD:
 * one row per active filesystem path, both kinds, the claim standing there already
 * applied (manifest_row_t, below). It is computed from Git at every load and
 * never stored — Git × the state's rows × this machine's $HOME → rows is a pure
 * function; the enabled set and each profile's target are read from the state
 * handle's row cache (core/state.h), the mount table is derived from them inside
 * the build, and nothing here writes. Surface is two-fold — builders and readers
 * — with one function beside them: manifest_mount_table, the build's own table
 * derivation on its own, for a command that needs this machine's topology without
 * a view (include/runtime.h) or with a binding of its own the rows do not hold yet.
 *
 * The view has two layers. A **contribution** is one profile's claims placed
 * under this machine's topology: its tree's blobs and its sheet's directory items,
 * two decisions per path *within the profile* — the explicit claim kept there,
 * and the derived claim placed there first — with what this machine cannot place
 * recorded beside them (manifest_unbound) and what the profile names twice recorded
 * against the name it kept (manifest_unkept). A contribution is what one profile
 * says about this machine, precedence aside. The **index** is precedence over
 * settled contributions, its two decisions made apart, one row standing per path.
 * An explicit claim stands unless a claim decided before it stands at its path,
 * a standing blob stands above it, or — the claim a blob — explicit claims stand
 * beneath it: a blob leaves no room at its place or beneath it. The highest
 * profile's claims are decided first, and each profile's in its own precedence,
 * which decides where its own blob and its own claims beneath it meet under two
 * labels: the blob stands where its name is the one the profile would give the
 * place fresh, and the claims beneath it where it is not — the side that stands
 * nowhere contradicted by the other, a health fact, where another profile's claim
 * standing over it is layering. A derived claim fills a path no row holds and
 * no standing blob stands above, the lowest profile's first. And where a blob
 * lost to the claims beneath it and no derived claim fills its place, the **layer's
 * rung** stands there: the directory those claims need, a row no contribution
 * holds. So no row stands strictly beneath a standing blob, and a claim that
 * stands nowhere has a row at its path or a standing blob above it.
 *
 * Everything that asks *what stands where* reads the index — manifest_lookup,
 * manifest_rows, manifest_blob_above, manifest_active_beneath, manifest_holder,
 * manifest_diff: deployment, the record's join, the workspace, every screen.
 * Everything that asks *what does this profile hold* — its claim at a path or
 * by a name, what it calls a path — reads that profile's own contribution —
 * manifest_lookup_claim, manifest_lookup_storage, manifest_name,
 * manifest_claim_name: a claim of P that stands nowhere is still found and named
 * by what P holds.
 *
 * Within one profile, at one path: an explicit claim (a blob of any type, a
 * `tracked` directory item) outranks a derived one whichever arrives first, and
 * nothing is recorded — the derived row named nothing; a DIRECTORY item whose
 * name the tree holds a blob at or above is contradicted and claims nothing, a
 * path being a tree or a blob and the tree the content authority; and two explicit
 * names are decided when the contribution is whole — **the name the profile would
 * give the path fresh** is kept (manifest_name's ascent), or the bytewise-least
 * where the profile holds no such name, and every other is recorded against it.
 * That decision is not a fact the build fixes but a rule, re-asked wherever a
 * name is read: a command's own uncommitted claims change what a path would be
 * called fresh, so manifest_name answers what the *next* settle will keep rather
 * than what the last one did.
 *
 * Three things a claim can fail to become, and the health channel says each. A
 * claim this machine cannot place stands nowhere: manifest_unbound, the repair
 * a `--target`. A claim its profile did not **keep** has one, and another name
 * of the same profile is kept there: manifest_unkept, the repair a `remove`. A
 * claim the profile's own claims **contradict** stands nowhere though the profile
 * holds it — in its tree, a directory claim a blob of the same profile stands
 * at or above; on this machine, where two of its labels place one chain, a claim
 * beneath a standing blob of its own, or a blob of its own whose place its claims
 * beneath take: manifest_contradicted, the repair a removal of one of the two,
 * or a re-capture of the file where both are one path. All three are claims the
 * profile holds and the view has no row for, for three different reasons; a claim
 * another profile's claim stands over — at its path, above it, or beneath it
 * where it is a blob — is none of them: it is **overridden**, the normal shape
 * of layering, and no health question at all. A name the view did not keep is
 * in the profile and in no row, so nothing keyed by the view meets it: no filter,
 * no record join, no divergence screen, no deploy. The verbs that read a profile
 * directly serve it as readily as any other name — `dotta list -p P` lists it,
 * `dotta show -p P` prints its bytes — and none of them says it is unused, which
 * is what the health channel is for; `remove`, which reads the profile too, is
 * the one verb that takes it away. And one thing a profile can fail to be: here.
 * An enabled profile Git holds no branch for is **missing** and contributes
 * nothing: manifest_missing, the channel's fourth slice, the repair a disable,
 * or a fetch that brings the branch back.
 *
 *   - Builders: manifest_build walks every enabled profile in precedence order
 *     (later profiles override earlier); manifest_build_profile walks one profile
 *     the caller opened at a tree it holds or loaded at its head (core/profiles.h)
 *     — the historical diff (cmds/diff.c diff_commit_to_workspace), export's
 *     path arm, and the path argument of `show -p` and `list -p`, named over
 *     whatever tree the verb selected — and is the same per-profile step applied
 *     once. Each step places the claims its profile's walk shows (core/profiles.h
 *     profile_walk), which reads the claim sheet of the tree it walks: a tree
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
 *   - Readers: manifest_rows (every row standing, both kinds, unordered),
 *     manifest_profiles (the profiles the rows came from, in precedence order),
 *     manifest_mounts (the table the rows were placed by, lent), manifest_lookup
 *     (by filesystem path, O(1)), manifest_blob_above and manifest_active_beneath
 *     (the blob standing above a path, and whether a row stands beneath it),
 *     manifest_holder (the one row holding a name, or a refusal naming each),
 *     manifest_lookup_claim and manifest_lookup_storage (one profile's claim,
 *     at a path and by its name), manifest_name, manifest_claim_name,
 *     manifest_holds_name, manifest_holds_row and manifest_moved_place (one
 *     profile's own contribution, whatever stands); and manifest_diff, the
 *     per-profile delta between two views, in claims, that sync's Manifest block
 *     prints.
 *
 * Core Principles:
 *   - Pure: the view is a function of Git, the state's rows and $HOME — the same
 *     inputs give the same rows on every machine
 *   - Computed, never stored: every load builds it; nothing invalidates it because
 *     nothing is held past its lifetime
 *   - Precedence-aware over settled contributions — a profile's claims are placed
 *     whole before any of them is compared with another's: one row per path,
 *     the explicit claims decided before the derived — a later profile's explicit
 *     claim overriding an earlier one's at its path, a standing blob leaving no
 *     room beneath it and losing its place to the claims standing beneath it,
 *     and a derived directory claim filling only a path no claim holds, the
 *     earliest profile's first (manifest_row_t's `tracked`)
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
 * reads the record (core/state.h) by pointer, and manifest_build_profile reads
 * a profile (core/profiles.h); each is named here and defined there. */
typedef struct state state_t;
typedef struct state_record state_record_t;
typedef struct profile profile_t;

/**
 * Manifest row — what should stand at an active path, and from whom
 *
 * A row in the view means the path is active: the enabled set, in precedence
 * order, names exactly one profile for it, and that profile's tree (or, for a
 * directory, its metadata.json) says what the path is — but at the layer's rung,
 * a directory the claims beneath a lost blob's place need, which no document of
 * its profile holds (core/manifest.c manifest_layer). Every field is Git-derived;
 * nothing here records what dotta did — the record dotta keeps of a path
 * (state_record_t, core/state.h) is written from one of these.
 *
 * Per kind:
 *   blob types  — blob_oid is the tree entry; mode is the metadata claim, or
 *                 the filemode floor (0644 / 0755) where none is claimed; encrypted
 *                 is the metadata-projected cache of the blob's own bytes
 *                 (docs/encryption-spec.md). A link row carries neither: see
 *                 Totality below
 *   DIRECTORY   — claimed from metadata alone, or required by the layer at a
 *                 place a blob lost: blob_oid is zero, encrypted is false,
 *                 owner/group are the item's, mode is the claim or
 *                 DIR_MODE_DEFAULT, and tracked is the item's class — the rung's
 *                 the default with no owner, group or class
 *
 * Two kinds of directory row, and `tracked` is the whole difference between them.
 * Every directory row asserts that a path must exist and says what it looks like
 * where dotta has to create it; `tracked` asserts on top of that which paths
 * the profile tracks itself — its attributes the profile's to enforce, its contents
 * the profile's to scan. That is the decision procedure every consumer follows:
 * a question about the path existing is asked of both classes (deploy's ancestors
 * pass, the displacement probe, cleanup's permanence rule), a question about
 * tracking it of the tracked ones alone (the untracked scan, the directory
 * divergence, the deploy plan). The second kind is an ancestor claim — derived
 * from the chain above a tracked path, so what it carries binds dotta's own
 * creation of that path and nothing else (core/metadata.h) — or the layer's rung,
 * which no chain derives and which binds the same creation. It is false on every
 * other kind, where nothing reads it.
 *
 * Totality: after build, mode is THE mode for every non-link row — floor or claim,
 * never a hole; consumers compare and apply it without a fallback. A link row's
 * mode and encrypted are both don't-cares, 0 and false: neither reaches a link
 * row (core/profiles.c profile_decode_blob's link rule), the discriminator being
 * type, the tree's own truth — symlink(2) takes no mode, and a link's bytes are
 * its target rather than content anything could seal. Its owner and group are
 * kept, a link being owned like any path. MODE_UNCLAIMED reaches no row: the
 * claim's floor resolves it (core/profiles.h profile_claim_mode). Authority,
 * stated once: the filemode is authoritative for type, the metadata claim for
 * permission bits — a hand-edit that contradicts the x-bit across the two is
 * resolved by that contract, not detected per-read.
 *
 * Standing or not: `profile` is the profile whose claim the row is — for the
 * layer's rung, the profile whose standing claims beneath made the blob lose,
 * which holds no claim there — and a row is never rewritten when another claim
 * stands over it. A row read through the view's index stands there; a row read
 * through manifest_lookup_claim is one profile's claim at a path whether or not
 * it stands.
 *
 * Strings are arena-backed by the producer; rows are read through `const
 * manifest_row_t *` and live for the producer's arena. The builders below produce
 * rows, the workspace partitions them, deploy and cleanup plan over them.
 */
typedef struct manifest_row {
    /* Identity */
    const char *filesystem_path; /* Deployed path (/home/user/.bashrc), as spelled */
    const char *storage_path;   /* Path in profile (home/.bashrc) */
    const char *profile;        /* The profile whose claim the row is; the rung's, its owner */

    /* What stands there: manifest_diff's updated compares type through group */
    path_type_t type;           /* FILE, SYMLINK, EXECUTABLE or DIRECTORY */
    git_oid blob_oid;           /* Blob the composed profile layer expects on disk (zero for DIRECTORY) */
    mode_t mode;                /* Total for every kind that carries one (claim or floor); 0 on a link row, a don't-care */
    const char *owner;          /* The claimed owner, or NULL; what absence says is the sheet's (metadata.h) */
    const char *group;          /* The claimed group, or NULL */
    bool encrypted;             /* Encryption flag (false for DIRECTORY) */
    bool tracked;               /* DIRECTORY rows: the profile tracks the directory itself */
} manifest_row_t;

/**
 * Is the row the claim (`profile`, `storage_path`)?
 *
 * The test a writer of the record makes before it writes one against a row. A
 * record binds what dotta confirmed — the blob, the stat — to the claim it names,
 * so the row has to be that very claim: the winner standing at a path may be
 * another claim of the same profile — a branch that arrived from a machine whose
 * roots kept two names apart holds both — and its blob is neither what was captured
 * nor anything the record's own name can be read under (core/state.h
 * state_record_t). Both halves, because within one profile a path is not an
 * identity.
 *
 * Readers: add's anchor pass (cmds/add.c add_write_record) and update's capture
 * loop (cmds/update.c update_write_record), each asking whether the claim a capture
 * committed still stands at its path — whose the path is, the record's content
 * being the capture's own; the file analysis's content note (core/workspace.c
 * workspace_analyze_file); and apply's acknowledgements — the two loops over
 * the clean items (cmds/apply.c cmd_apply) and the record phase's, of a directory
 * fixed in place (apply_write_record) — which are what moves a record onto the
 * claim standing at its path. The let-go loops ask the other direction — whether
 * any row still stands at the path — and are not readers of this. NULL is no claim.
 */
static inline bool manifest_is_claim(
    const manifest_row_t *row, const char *profile, const char *storage_path
) {
    return row && strcmp(row->profile, profile) == 0 &&
           strcmp(row->storage_path, storage_path) == 0;
}

/**
 * Is the row an ancestor claim — a directory derived from the chain above a tracked
 * path, or the layer's rung at a lost blob's place, never named by anyone?
 *
 * The bottom of the lattice a namer reads: the one kind of row that does not
 * name its own path. Every other kind does, a blob as much as a tracked directory,
 * so this is not the test for whether anything may be named *beneath* a row.
 * That one is narrower — a tracked directory alone (manifest_claim_beneath) —
 * and a walker that composes children beneath every row this answers false for
 * composes them beneath a blob, where the namer composes beneath the root's label
 * instead.
 *
 * What reads it: a contribution keeps it apart from the profile's explicit claims,
 * and keeps it where the profile holds one of them at its path too, for the layer
 * to hide or, where that claim is a blob that lost its place, to stand; the index
 * lets it fill a path no claim stands at and never take one a claim stands at;
 * and a search reads it as "the profile holds a subtree beneath here" — one of
 * possibly several chains, never a name (manifest_lookup_claim's note). False
 * on every other kind, where `tracked` is false and nothing reads it.
 *
 * Readers: a claim's placement, the cut of a contribution's rows, the layering's
 * two passes, the order the first decides a contribution's claims in, and the
 * index of its own class a row is asked of (core/manifest.c manifest_place_claim,
 * manifest_contribute, manifest_layer, manifest_places, manifest_precedence,
 * manifest_holds_row); the reassignment predicate, the absence rule and the route
 * table's derived arm (core/workspace.h workspace_reassigned, core/workspace.c
 * classify_absent, workspace_item_route); the record's owed work, where a derived
 * row neither vouches for a claim nor needs a voucher (core/workspace.c
 * workspace_pending); the untracked scan's word at a child, a rung being the
 * one claim that settles nothing about the path it stands at (core/workspace.c
 * workspace_scan); the tags' clean arm, where a rung nothing diverged on reads
 * [ancestor] (core/workspace.c workspace_item_tags); update's derive-scope slice,
 * a leaf's row and the claim each profile holds where the user's node squats
 * above it (cmds/update.c cmd_update); the two refusals of a second name for
 * one path, where a derived claim names nothing and so blocks nothing (cmds/add.c
 * cmd_add, cmds/revert.c revert_refuse_second_name); add's rule question, where
 * it claims nothing either and so is a discovery, meeting every rule (cmds/add.c
 * add_verdict); the walk that enters such a directory for the claims beneath it
 * (cmds/add.c add_collect); add's ancestry refusal, where the capturing profile's
 * derived claim at the user's link is the one its climb retires (cmds/add.c
 * add_refuse_ancestry); and the per-profile counts `status -v` prints, where a
 * derived row is no directory the profile tracks (cmds/status.c
 * status_print_profiles). Every other `tracked` read in the tree stands where
 * the kind is already settled and asks the field's own meaning, not this predicate.
 */
static inline bool manifest_is_derived(const manifest_row_t *row) {
    return row && row->type == PATH_TYPE_DIRECTORY && !row->tracked;
}

/**
 * Bound carrier for a borrowed slice of manifest rows
 *
 * Structural type — parallels libgit2's git_strarray and base/array's
 * string_array_t. The producer's signature dictates lifetime via the arena (or
 * other allocator) that backs the rows: manifest_rows(view) lends the view's,
 * backed by the view's arena (the command's); cmds/update.c lends two of its
 * own — cmd_update's named-run leaves, in the command's arena, and update_execute's
 * per-profile share of them, in an array the next profile refills (valid for
 * one update_profile call). The rows are the view's however long a slice lives.
 */
typedef struct {
    const manifest_row_t *const *entries;
    size_t count;
} manifest_rows_t;

/**
 * Manifest (opaque)
 *
 * A value of the arena the builder was given — its rows, their strings and its
 * indexes — and nothing frees one. A view built over the enabled set borrows
 * nothing else — not the state's row cache it was read from — so it stands across
 * the mutations that replace the cache, for the arena's lifetime. One profile's
 * view borrows the one thing its caller handed it beside the profile, the mount
 * table, and lends it back (manifest_mounts); of the profile it keeps nothing.
 */
typedef struct manifest manifest_t;

/**
 * Build the manifest over the enabled set
 *
 * The enabled profiles, in precedence order, are read from the state handle's
 * row cache (state_profiles) — the one source every caller would otherwise copy
 * them out of. A state with no database (state_load on a repository never touched
 * by `dotta init`) has no rows and yields an empty view.
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
 * profile's records as orphans. The unbound claim is the dead branch's sibling
 * at claim scale: this machine cannot place it, and the build says so as data,
 * not failure. Only those two questions are tolerant: a branch that exists but
 * cannot be loaded (corrupt object, I/O) still fails the build, as do a failed
 * lookup and metadata that will not parse — those stay retryable errors, never
 * silent omissions.
 *
 * Per profile, in order: the claims its walk shows (core/profiles.h profile_walk)
 * — the tree's blobs first, then the DIRECTORY items of its metadata.json — are
 * placed into that profile's own contribution, the explicit and the derived each
 * in an index of its own — the within-profile rule (the two layers, above): a
 * DIRECTORY item whose name the tree holds a blob at or above is contradicted
 * and claims nothing, two explicit names at one path are decided when the
 * contribution is whole, the fresh name kept and every other recorded
 * (manifest_unkept), and a derived claim is held apart, the first of two chains
 * through one path. Only then does precedence run, in two passes: the explicit
 * claims, the later (higher) profile's first and each profile's in its own
 * precedence, a claim standing at a path no claim before it stands at unless a
 * standing blob stands above it or, the claim a blob, standing claims beneath
 * it need its place as a directory — a contradiction where either is its own
 * profile's (manifest_contradicted); then the derived claims, each filling a
 * path no row holds and no standing blob stands above, the earlier profile's
 * first; and last the layer's rung at each place a blob lost that no derived
 * claim fills — so an explicit claim outranks a derived one within a profile as
 * across them, and the view holds one row per path. A profile without metadata.json
 * contributes no directories and is skipped, not an error.
 *
 * Row order is unspecified; consumers that need parent-before-child sort their
 * own pointer arrays (the workspace does). The oracle is a set. What order there
 * is is each contribution's claim order, the contributions in precedence order
 * — so a path a higher profile overrides sits at the winner's place, not the
 * loser's — and the layer's rungs after them.
 *
 * Memory:
 *   - rows, per-row strings, the profile names (duplicated once per profile)
 *     and the mount table: arena-allocated; the caller's arena reclaims them at
 *     arena_free. The view borrows nothing from the row cache, so it stands across
 *     the enabled_profiles mutations that replace the cache — a `before` built
 *     ahead of a profile enable reads the same after it, and the view after is
 *     the builder called again.
 *   - the indexes: the arena's too, so nothing frees a view. On error *out is
 *     NULL, and what the build made stays the arena's bytes.
 *
 * @param repo Git repository (must not be NULL)
 * @param state State handle the enabled set and targets are read from (must not
 *              be NULL; borrowed, only the row cache is consulted)
 * @param arena Arena backing every allocation produced by the call (must not be
 *              NULL)
 * @param out Manifest (must not be NULL)
 * @return Error or NULL on success
 */
error_t manifest_build(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    manifest_t **out
);

/**
 * Build the manifest from one profile
 *
 * One profile's view: a manifest_row_t row for every claim the profile's walk
 * shows that stands (core/profiles.h profile_walk) — every blob its tree exposes
 * (machinery aside: every name outside the label grammar, dotta's own files among
 * them — core/profiles.h, the decode) and every DIRECTORY item its own sheet
 * carries that the tree does not contradict — the same per-profile step
 * manifest_build runs, applied once, sheet included (the Builders note above:
 * the walk reads it, strictly, so one rule reads it). Readers that want files
 * only test row->type.
 *
 * The profile is the caller's to open — at a tree it holds, a historical commit's
 * or a stage's or the one a verb selected (core/profiles.h profile_open), or at
 * its head (profile_load) — and it names whose claims these are, a tree carrying
 * no name. The view keeps nothing of it: every string a row holds is copied, so
 * the profile may be freed as soon as this returns. The mount table is explicit
 * too, there being no state to derive one from and a past tree deliberately
 * resolved under today's topology.
 *
 * Custom-prefix resolution is delegated to `mounts`. A custom/ claim the table
 * records no binding for contributes no row and is recorded on the view
 * (manifest_unbound) — the same degrade contract as manifest_build, which lets
 * the historical-diff path resolve old trees whose labels today's topology cannot
 * place. Any mount table is acceptable, including one with no binding for the
 * profile.
 *
 * One contribution, settled and layered like any other, so one profile's view
 * answers manifest_lookup_claim and manifest_name for its profile exactly as an
 * enabled view answers them for one of its own, and its rows are the places the
 * profile's own claims settle on this machine: where its blob and its claims
 * beneath it meet under two labels, the side its fresh name spells stands, and
 * a lost blob's place is a directory — its own derived claim there, or the layer's
 * rung. No policy enters here: no raw argument, no fallback, no enabled-set
 * question, and the profile need not be enabled.
 *
 * Readers: the historical diff (cmds/diff.c diff_commit_to_workspace, whose
 * comparison and coverage answer each read the whole view); export's path arm
 * (cmds/export.c export_collect_filesystem), which selects the rows one profile
 * places at and beneath a path — the rows, not the Git subtree of whatever name
 * stands there, which is what manifest_lookup_claim's own note is about; the
 * path argument of `show -p` and `list -p`, named over whatever tree the verb
 * selected (cmds/show.c cmd_show, cmds/list.c list_file_history, which ask it
 * manifest_claim_name); revert's two questions of a tree, the claim held at a
 * path and the second-name admission (cmds/revert.c revert_claim_held,
 * revert_refuse_second_name); add, which builds one over its draft's base
 * (core/profiles.h profile_draft_base) and asks it every naming question for
 * the length of the command (cmds/add.c cmd_add); `ignore --test`'s named arm
 * (cmds/ignore.c ignore_test); and the two cross-profile searches, which build
 * one per local profile (cmds/revert.c revert_select_profile, through
 * revert_claim_held, and cmds/remove.c remove_overlaps).
 *
 * Memory: every allocation produced by the call lives in the caller's arena, as
 * manifest_build's does, but the sheet the walk reads where no question has yet,
 * which the profile keeps until profile_free (core/profiles.h).
 *
 * @param profile The profile (must not be NULL; borrowed for the call, its sheet
 *                read through it)
 * @param mounts Per-machine mount table (must not be NULL)
 * @param arena Arena backing every allocation produced by the call (must not be
 *              NULL)
 * @param out Manifest (must not be NULL)
 * @return Error or NULL on success
 */
error_t manifest_build_profile(
    profile_t *profile,
    const mount_table_t *mounts,
    arena_t *arena,
    manifest_t **out
);

/**
 * Every row standing in the view, both kinds, unordered
 *
 * The index's rows — what stands at each active path: a claim, or the layer's
 * rung, which no contribution holds (manifest_holds_row). A name a profile did
 * not keep and a claim another stands over — at its path, above it, or beneath
 * it where it is a blob — are both absent: the first is manifest_unkept's, the
 * second is layering, and neither is a row.
 *
 * Pure value return — no allocation, no error path. The slice aliases the view's
 * own storage and is valid for the arena's lifetime.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over every row standing
 */
manifest_rows_t manifest_rows(const manifest_t *manifest);

/**
 * The profiles the view was built from, in precedence order
 *
 * Every enabled profile whose branch existed at build, lowest precedence first
 * — the set the rows came from, as the enabled set reads once the branches that
 * are gone (and contributed nothing) are left out; for one profile's view, its
 * one profile.
 *
 * Readers: the scope, whose enabled set this is (core/scope.c scope_build); the
 * untracked scan's registration (core/workspace.c workspace_analyze_untracked),
 * where a later profile's tracked directory takes a directory an earlier one
 * stands at, the index's own rule read from the same order; add's ancestry refusal,
 * which asks every profile but the capturing one for its claim at a link
 * (cmds/add.c add_refuse_ancestry); and update's named derivation, which asks
 * every profile for an explicit claim where the user's node squats above a leaf
 * (cmds/update.c cmd_update).
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
 * (manifest_build_profile). Borrowed for the view's lifetime — the build's is
 * the arena's, and the caller of one profile's view keeps its table alive as
 * long as the view. Rule 1, never cache a cache: a consumer that holds the view
 * and needs the topology it was placed by reads it here rather than building a
 * second table from the same rows, so the names it places and the rows it selects
 * read one value. Readers: the dispatcher (`run.mounts` for a command that declares
 * the view, include/runtime.h); a filesystem argument to `ignore --test`, and
 * add's label receipt, its let-go and its ancestry refusal (cmds/add.c
 * add_print_labels, add_write_record, add_refuse_ancestry), each of which builds
 * a view of its own and reads the table back from it rather than beside it. Show
 * and list build one too and ask it nothing: their arm reads the view by key alone.
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
 * machine's $HOME and the root sentinel at "/" (infra/mount.h) — offered without
 * a view, for a command that declares `mounts` and not `manifest`
 * (include/runtime.h). A command declaring both reads manifest_mounts instead
 * and gets the view's own: one build, one value. Rule 1, never cache a cache.
 *
 * `binding` is NULL for a reader describing the machine as it stands — the
 * dispatcher's build and the view's own. A command that declares a binding of
 * its own, which no row need hold (`add --target` on a new profile, or a disabled
 * one), passes it here rather than building a table beside this one: the
 * substitution is total and by name — the profile's own row is not read, so a
 * binding with no target says that profile is bound nowhere in this run (mount_t)
 * — and it is the only difference between the two tables. Every verb over a table
 * reads the asker's own entries (infra/mount.h), so a table holding the binding
 * alone would answer the command the same; what the one derivation buys is that
 * the rows the command's table is built from are the rows the view it later joins
 * by is built from (cmds/add.c).
 *
 * The derivation itself stays the builder's, never a parameter of it — a binding
 * is one pairing the run declares, not a table handed in: a re-target is in the
 * next view because the next build reads the rows again, and a caller handed
 * the table would have to remember to rebuild it after every mutation that moves
 * one — silently placing a custom/ row under yesterday's target when it forgot.
 *
 * Name and target are read from the row cache for the call only — the table copies
 * every string it keeps — so the handle is a value: the topology the rows described
 * at the instant it was built, readable for the arena's lifetime whatever
 * enabled_profiles mutation follows.
 *
 * A state with no database has no rows and yields the bare table (HOME and the
 * root sentinel). The rows are the handle's, read when it was loaded (core/state.h
 * state_profiles); what can refuse here is a target's spelling (infra/mount.h
 * mount_table_build).
 *
 * @param state State handle (must not be NULL; borrowed, not freed)
 * @param binding The run's own binding, standing for its profile's row, or NULL
 *                for the machine as the rows describe it (borrowed for the call)
 * @param arena Arena backing the handle (must not be NULL; outlives the handle)
 * @param out Output handle (must not be NULL; lifetime tracks arena)
 * @return Error or NULL on success
 */
error_t manifest_mount_table(
    const state_t *state,
    const mount_t *binding,
    arena_t *arena,
    mount_table_t **out
);

/**
 * One claim the build could not place: its profile has no deployment target on
 * this machine. Recorded, never dropped in silence — the health consumers (status,
 * apply, sync) surface these; export reads the count alone, for the reason its
 * refusal gives, and so does add's enable hint over its own opened tree
 * (cmds/add.c); and an enable that names an enabled profile holding them says
 * so, with the flag (cmds/profile.c profile_enable). The repair is one command
 * (`profile enable <p> --target /path`), the untracking another (`remove`). The
 * screen says **no target** or **needs a target**, never "unbound": the header's
 * word is what the build could not do, the screen's is what the user must give.
 * Strings are the build arena's, same lifetime as the rows.
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
 * so one profile's claims are contiguous. Each (profile, storage path) appears
 * once and nothing enforces it: the profile's walk shows a name once
 * (core/profiles.h profile_walk) — a name the tree holds a blob at, or a sheet
 * key it holds no blob at or above, the content-authority rule having contradicted
 * the rest (a path is a tree or a blob, and the tree is the content authority)
 * — a tree holding one blob per path and a sheet one directory claim per key.
 * Empty on every build whose claims all placed — the common case, costing nothing.
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded claims, valid for the arena's lifetime
 */
manifest_unbound_t manifest_unbound(const manifest_t *manifest);

/**
 * One name a profile holds for a path it also names otherwise, recorded against
 * the name it kept.
 *
 * Strings are the build arena's; no row pointer — the entry says what this profile
 * holds, and the index may point elsewhere. The name is in the profile and in
 * no row: `remove` is the one verb that can still take it, which is why that is
 * the repair.
 *
 * The screen says **unused path**, never "unkept name": `name` on a dotta screen
 * is a profile's (`profile enable <name>`) and every screen calls a storage path
 * a path. The words differ because the subjects do — kept/unkept is what the
 * settle did inside this contribution and is always true of it; used/unused is
 * what the machine does with the result, which a higher profile's row can change.
 * `kept` is this profile's name for the path, never a promise that anything reads
 * it, and a screen that says otherwise contradicts the window onto the view two
 * sections above it.
 */
typedef struct {
    const char *profile;
    const char *storage_path;      /* the name that was not kept */
    path_kind_t kind;              /* its kind (a screen prints it with a suffix) */
    const char *kept;              /* the name the contribution kept at this path */
    const char *filesystem_path;   /* the path every name of the group resolves to */
} manifest_unkept_claim_t;

/**
 * Bound carrier for the view's second health slice, the manifest_rows_t idiom.
 */
typedef struct {
    const manifest_unkept_claim_t *entries;
    size_t count;
} manifest_unkept_t;

/**
 * The names the profiles hold for paths they also name otherwise
 *
 * Pure value return — no allocation, no error path. Grouped by profile in build
 * order, a path's entries contiguous and bytewise by name, so a listing prints
 * a path's names together in a stable order. Each (profile, name) appears once
 * — a name resolves to one path under one profile, and a name the tree and the
 * sheet both carry is settled before the contest by the content-authority rule.
 * Empty on every build whose profiles each name their paths once.
 *
 * Two names meet where two of this machine's roots overlap, and that needs no
 * exotic topology: `home/` lies beneath `root/` on every machine, so a profile
 * carrying both spellings of one path collides here with no binding in sight. A
 * `custom/` target inside `$HOME` puts the other pair in reach, and an import
 * carries one here whole — though this machine's own captures no longer author
 * one, a verb admitting only a name the profile already holds
 * (manifest_holds_name).
 *
 * Readers: the health channel's own listing (cmds/status.c status_print_profiles),
 * and the completed selection's refusal in add (cmds/add.c add_refuse_moves) —
 * which reads the slice as every name its claims can move, since no group can
 * grow under an uncommitted claim and only which member is kept can change; which
 * side of a place they move is another question (manifest_moved_place).
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded names, valid for the arena's lifetime
 */
manifest_unkept_t manifest_unkept(const manifest_t *manifest);

/**
 * One claim a profile's own claims leave no room: another claim of the same profile
 * stands, so this one stands nowhere — in the profile and in no row, the third
 * way a claim fails to become one. Two scopes, one word. In the profile's
 * documents, a tracked directory claim with a blob of the same profile at its
 * name or at a rung above it (core/profiles.h profile_contradicted): the tree
 * is the content authority, so the blob stands and the claim nowhere. On this
 * machine, where two of its labels place one chain (core/manifest.c
 * manifest_layer): a claim beneath a standing blob of its own, or a blob of its
 * own whose place its claims beneath take — which side stands decided by the
 * name the profile would give the place fresh. Explicit claims alone: a derived
 * one is the way to a claim, recorded here, or to none, which the profile's next
 * settle prunes.
 *
 * What leaves the claim no room is one of two, by where it stands, and the other
 * is NULL. `blob_above` is a blob at the claim's name or at a rung above it —
 * at its name in the documents alone, two names at one path on this machine being
 * manifest_unkept's. `place` is the directory taking a blob's place, named as
 * the profile names the place fresh — the spelling its claims beneath compose
 * under, so a removal by that name takes them. A binding inside the place, or a
 * third label, puts them under another spelling, and the name then holds none
 * of them: the profile's listing names what does.
 *
 * The screen says **contradicted**, the decode's word, for both scopes, and names
 * what leaves the claim no room — the two things a repair chooses between. Strings
 * are the build arena's, same lifetime as the rows.
 */
typedef struct {
    const char *profile;
    const char *storage_path;      /* the claim that stands nowhere */
    path_kind_t kind;              /* its kind (a screen prints it with a suffix) */
    const char *blob_above;        /* the blob at its name or at a rung above it, or NULL */
    const char *place;             /* the directory taking its place, by name, or NULL */
} manifest_contradicted_claim_t;

/**
 * Bound carrier for the view's third health slice, the manifest_rows_t idiom.
 */
typedef struct {
    const manifest_contradicted_claim_t *entries;
    size_t count;
} manifest_contradicted_t;

/**
 * The claims the profiles' own claims leave no room, in their documents and on
 * this machine
 *
 * Pure value return — no allocation, no error path. The documents' entries come
 * first, in build order, one profile's contiguous, each in key order; then this
 * machine's, in the layer's order, one profile's contiguous, the highest first,
 * each in the order its precedence decides its claims (core/manifest.c
 * manifest_layer). So a profile can appear once a scope, and no reader keys on
 * the order: status filters it per profile, apply and sync list it whole. Each
 * (profile, storage path) once: the sheet holds one directory claim a key, a
 * claim its tree contradicts is one the walk never shows, and the layer decides
 * each claim the walk shows once. Empty on every build whose profiles contradict
 * none of their own claims — the common case, costing the build a second
 * classification of each directory claim, and the layer one comparison where a
 * blob and a claim leave each other no room.
 *
 * Readers: the health channel's listing (cmds/status.c status_print_profiles),
 * apply's section (cmds/apply.c cmd_apply) and sync's after its Git phase
 * (cmds/sync.c cmd_sync); and add's own remedy over its one profile's view, a
 * file it captures at a claim's own name taking it — a documents' entry, this
 * machine's never meeting its blob at one name (cmds/add.c cmd_add).
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the recorded claims, valid for the arena's lifetime
 */
manifest_contradicted_t manifest_contradicted(const manifest_t *manifest);

/**
 * Bound carrier for the view's fourth health slice, the manifest_rows_t idiom:
 * the missing profiles' names, the build arena's.
 */
typedef struct {
    const char *const *entries;
    size_t count;
} manifest_missing_t;

/**
 * The enabled profiles the build found no branch for, in the enabled set's order
 *
 * A profile the state enables and Git no longer holds contributes nothing: it
 * is not among manifest_profiles, and every record it left is an orphan no branch
 * backs, which the workspace reads as a file released and a directory by what
 * is left in it (core/workspace.c workspace_analyze_orphans). Missing is an
 * observation, never an error (manifest_build): the health channel's fact about
 * a profile, where manifest_unbound, manifest_unkept and manifest_contradicted
 * are its facts about claims. Only Git surgery, or a state write that failed
 * after `remove` deleted the branch, leaves one. Empty on every build whose enabled
 * profiles all have their branches, and on one profile's view.
 *
 * The screen says **no branch**: the header's word is what the build found of
 * the profile, the screen's is what it lacks — the branch a fetch brings back,
 * or the profile a disable lets go of.
 *
 * Readers: the health channel's listing (cmds/status.c status_print_profiles)
 * and apply's (cmds/apply.c cmd_apply).
 *
 * @param manifest Manifest (NULL returns an empty slice)
 * @return Borrowed slice over the profiles' names, valid for the arena's lifetime
 */
manifest_missing_t manifest_missing(const manifest_t *manifest);

/**
 * Look up a row by filesystem path
 *
 * O(1) over the view's index — a path is one row, whatever its kind; callers
 * that want one kind test row->type. NULL when the path is not active.
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
 * The blob the view holds strictly above a path — the row, or NULL
 *
 * A blob leaves no room at its place or beneath it on this machine, whichever
 * label names either: the namespace rule over locations, where core/profiles.c
 * profile_blob_above asks it over one profile's names. Whichever profile's blob
 * the view holds there, precedence applied (manifest_lookup) — over one profile's
 * view, that profile's own. At most one stands above any path: the layer stands
 * no row strictly beneath a standing blob (core/manifest.c manifest_layer), so
 * no two standing blobs nest. A directory row of either kind stops nothing: an
 * ancestor claim names neither itself nor anything beneath it
 * (manifest_is_derived), which is why a derived row at one key is no answer about
 * the other.
 *
 * Strictly above: a blob at the path itself is the path's own row, which
 * manifest_lookup answers and its kind settles, so no reader asks it here.
 *
 * The rungs are the path's own key cut at each separator — a root's spelling
 * and a shorter tail, whichever label named it (infra/mount.h) — nearest first,
 * each read off the key's own bytes by its length (base/string.h
 * str_path_parent_len_n, base/hashmap.h hashmap_get_n), so nothing is copied.
 * The root directory is read and ends the climb, because a claim can stand there
 * — `root` spells it, and `home` or `custom` on a machine whose HOME or target
 * is one (infra/label.h) — and the view places a blob at any of the three as a
 * FILE row at that directory (core/manifest.c manifest_place_claim). The namer's
 * ascent over these very rungs floors on the asker's own root (manifest_name):
 * it names a path for one profile, reading that profile's claims at its root
 * and beneath. This climb has no asker — it asks what stands at a path, whoever
 * holds it — so the root directory is its floor, as it is deploy's (core/deploy.c
 * nearest_ancestor), and "/" itself has nothing above it.
 *
 * Readers: cmds/add.c cmd_add, of the path an argument names — a capture beneath
 * one of the profile's own files, whichever label names either, over the one
 * profile's view its names come from; core/workspace.c workspace_analyze_orphans,
 * of an orphan's path — a copy beneath a standing blob is that blob's landing's
 * (WORKSPACE_STATE_OVERRIDDEN); and cmds/status.c status_print_workspace, of
 * such a copy, whose line names what stands over it, by the call that made it one.
 *
 * @param manifest Manifest (must not be NULL)
 * @param filesystem_path Where to ask, absolute: a key (must not be NULL)
 * @return The blob row standing above the path, or NULL
 */
const manifest_row_t *manifest_blob_above(
    const manifest_t *manifest,
    const char *filesystem_path
);

/**
 * Does an active path lie strictly beneath `path`?
 *
 * Whether the view holds a row beneath the path, at any depth — every directory
 * above an active path is its ancestor, not its parent alone — on disk or not:
 * a row standing, as the index holds it, so a claim that stands nowhere is none.
 * The root included: every row but one at "/" lies beneath it. Pure value return
 * — no allocation, no error path.
 *
 * The question core/workspace.h workspace_active_beneath asks of the join's active
 * items, which are these rows, by the same relation (base/string.h
 * str_path_beneath), so the two cannot part: the join answers off its items'
 * order by a lower bound, and this off the rows standing, unordered
 * (manifest_rows), by a scan — for a caller that holds no workspace.
 *
 * Readers: cmds/add.c add_refuse_ancestry (dotta's own link above a capture,
 * which a row of the view beneath it makes the node its landing replaces). A
 * reader not on this list is a bug.
 *
 * @param manifest Manifest (NULL answers false)
 * @param path Directory to ask about, as a key spells one (NULL answers false)
 * @return true where an active path lies strictly beneath it
 */
bool manifest_active_beneath(const manifest_t *manifest, const char *path);

/**
 * The one row holding this name, or a refusal naming every holder
 *
 * A name keys within one profile (infra/mount.h): under custom/ two profiles at
 * two targets hold one name for two files, and under home/ or root/ precedence
 * leaves one. One holder is the claim a caller without a profile may act on,
 * and none answers NULL. Several is no answer — the first of several answered
 * one profile's file for another's — so the refusal names each holder with the
 * path that tells it apart, in precedence order, and `*out_row` is NULL beside it.
 *
 * The rows standing, where manifest_lookup_storage answers one profile's claim
 * by its name standing or not: a name that stands nowhere is held by nobody here.
 * And a row holds its name only where its profile holds the row
 * (manifest_holds_row): the layer's rung stands under a name no profile holds,
 * and is no holder.
 *
 * Linear scan, once per command. Readers: cmds/show.c cmd_show and cmds/list.c
 * list_file_history, each without a profile.
 *
 * @param arena Arena the refusal's holders are joined in (must not be NULL)
 * @param manifest Manifest (must not be NULL)
 * @param storage_path Storage path, e.g. "custom/etc/foo" (must not be NULL)
 * @param out_row The one holder, or NULL for none and for several (must not be
 *                NULL)
 * @return The refusal when several rows hold the name, NULL otherwise
 */
error_t manifest_holder(
    arena_t *arena,
    const manifest_t *manifest,
    const char *storage_path,
    const manifest_row_t **out_row
);

/**
 * The row `profile` holds at `filesystem_path` in its own contribution — its
 * explicit claim there, else the derived claim it placed there first — whether
 * or not it stands there in the index: a claim at the path, a standing blob above
 * it, or the claims beneath it where it is a blob can each stand over it. So at
 * a place where the profile's own blob lost to its own claims beneath, this is
 * the blob, where the index stands a directory: the profile holds the blob, and
 * a reader that wants what stands asks the index (manifest_lookup).
 *
 * NULL when the profile is not in the view, holds nothing there, or is NULL —
 * the API's own return convention, a pointer-returning lookup having no CHECK_NULL
 * to refuse with. O(P) over the profiles to find the contribution, then O(1): P
 * is the enabled set, and a caller that asks once per directory entry pays a
 * handful of strcmp.
 *
 * A DIRECTORY row here names and does not enumerate, and that is true of both
 * classes: neither is an identity for the subtree standing beneath the path. A
 * derived row says the profile holds a subtree there, and its `storage_path` is
 * one of the chains its own names run through — a profile bound after some of
 * its files were captured legitimately derives two. A tracked row says what the
 * profile will call everything beneath it from now on, and says nothing about
 * the ones already captured: tracked `home/jail/etc` is above `home/jail/etc/a`
 * and `custom/etc/b` alike, and its own Git subtree holds only the first. A caller
 * that wants the subtree reads the rows beneath the path, never the tree beneath
 * the name.
 *
 * Where the profile names the path more than once this is the row the settle
 * kept, which is the path's shape. It is not always the row a namer answers from:
 * manifest_name under a pending layer answers the name the *next* settle will
 * keep, and that can be another of the group's. A caller that reads both reads
 * one for the shape the profile's claims give the path and the other for the
 * name it is about to author.
 *
 * Readers: the name a profile has for a path (manifest_claim_name), which asks
 * this before the namer — a derived claim is something the profile holds and
 * nothing it names, so the namer alone would climb past it and answer a name
 * the profile never held; revert's two questions of a tree, the claim held at a
 * path and the second-name admission (cmds/revert.c revert_claim_held,
 * revert_refuse_second_name), the first asked of every local profile by its search
 * (revert_select_profile); remove's search, what every other local profile claims
 * where a removal takes a claim, each asked of its own view (cmds/remove.c
 * remove_overlaps); add's three questions of a path it names or walks (cmds/add.c
 * cmd_add and add_collect): which rules reach it — a claim meets the -e layer
 * alone, no rule of discovery (add_verdict) — whether the profile's own claim
 * agrees with what stands there now — the one reading that sees an explicit claim
 * with nothing beneath it for either of the profile's documents to find, and a
 * derived row included, since a profile holding a subtree beneath a path is a
 * statement a path that became a file contradicts — and whether the add captures
 * it, a claim being left as it stands but under --force (add_list); every claim
 * an enabled profile holds at a link above a capture, the capturing profile's
 * off its own view and every other's off the enabled one (cmds/add.c
 * add_refuse_ancestry); whether a row a transition left no row at is its profile's
 * claim there still, standing nowhere, which counts it overridden rather than
 * departed (manifest_diff); whether any profile holds an explicit claim where
 * the user's node squats above a named update's leaf, a lost blob's place no
 * re-derivation frees (cmds/update.c cmd_update); whether the untracked scan's
 * owner holds a blob at a child no row of its own stands at (core/workspace.c
 * workspace_scan); and `ignore --test`'s note beneath a verdict that excludes a
 * path its asker holds, which the rules never reach (cmds/ignore.c ignore_test).
 */
const manifest_row_t *manifest_lookup_claim(
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path
);

/**
 * The row `profile` holds under `storage_path` in its own contribution — the
 * claim by its name, as manifest_lookup_claim answers the claim at a path — whether
 * or not it stands
 *
 * A name keys within one profile (infra/mount.h), and the profile holds it in
 * one row at most: the name places at one path under the profile's table, it is
 * one claim — a blob of the tree, or the sheet's one item at its key, the decode
 * dropping an item a blob of its own name contradicts (core/profiles.h
 * profile_contradicted) — and the contribution keeps one row of each class at a
 * path. So the lookup is exact, and the row is the claim's own: a claim that
 * stands nowhere — another's claim at its path, a standing blob above it, the
 * claims beneath it where it is a blob, or its own profile's, which contradict
 * it — answers its row here as manifest_lookup_claim answers it at its path,
 * and a reader that wants what stands asks the index (manifest_lookup). NULL
 * where the profile holds no row under the name: a name it does not hold, one
 * this machine cannot place (manifest_unbound), one its settle did not keep
 * (manifest_unkept), a second chain through one path, every name of a profile
 * the view holds no contribution for — a disabled one's — and the pair the layer's
 * rung carries, which no contribution holds (manifest_holds_row).
 *
 * `profile` is required; a NULL profile names no row, the API's own return
 * convention, since a pointer-returning lookup has no CHECK_NULL to refuse with.
 * A caller with no profile in hand asks manifest_holder: the first of several
 * rows holding a name was never an answer.
 *
 * Linear over the profile's own rows, and nothing for a profile the view holds
 * no contribution for, the commonest ask: a disabled profile's orphans. A
 * relocation within an enabled profile — a moved target or HOME — scans that
 * profile's rows once per orphan, and an index of each contribution's rows by
 * name is the upgrade if a measure ever shows the scan.
 *
 * Reader: the relocation read (core/workspace.c workspace_analyze_orphans), once
 * per owned orphan whose claim may stand elsewhere — a file its profile still
 * holds, which has already cost a walk of its history, and a directory, which
 * no history is asked of — never a file its history took away, which no row of
 * its profile carries.
 *
 * @param manifest Manifest (NULL returns NULL)
 * @param profile The claim's profile (NULL names no row)
 * @param storage_path Storage path to look up, e.g. "home/.bashrc" (NULL returns
 *                     NULL)
 * @return Borrowed row pointer, or NULL where the profile holds no row under
 *         the name
 */
const manifest_row_t *manifest_lookup_storage(
    const manifest_t *manifest,
    const char *profile,
    const char *storage_path
);

/**
 * Does `profile` hold `storage_path` as a name for `filesystem_path`?
 *
 * A name in this profile's own contribution — the claim kept at the path, or
 * one the settle recorded against it (manifest_unkept) — and never the tree's
 * shape: a subtree the profile's own blobs spell is not a name it holds, and an
 * empty tracked directory is a name with no tree entry at all. Both inputs are
 * why the tree cannot answer this.
 *
 * A derived row answers false: an ancestor claim names nothing, and an explicit
 * claim may be authored over it. An unbound claim answers false too — it stands
 * nowhere on this machine, so it stands at none.
 *
 * The question a verb asks before authoring a name the user typed: a name the
 * profile already holds is a re-capture, and only a name new to it at a path
 * the profile already names is a second name. The committed claims alone are
 * read — a name this command has already admitted is its own listing to check.
 * O(1) where the profile names the path once, and a scan of the group where it
 * names it twice.
 *
 * It is also the boundary the namer's own answer rests on: because a verb admits
 * only a name the profile holds, the group the settle decides over cannot grow
 * under an uncommitted claim, and manifest_name can answer what the next settle
 * will keep.
 *
 * A name this answers true for is a claim the profile holds, standing or not:
 * the group's kept member, or an uncontested one, its derived claims held apart.
 * Where it stands nowhere, a row stands at its path — another claim, or, where
 * it is a blob the claims beneath it took the place of, the directory they need
 * — or a standing blob above it, and nothing else can stand over it (the layer,
 * core/manifest.c manifest_layer). So a caller that asks this first reads no
 * row at the path as a blob above it (cmds/add.c add_write_record).
 *
 * Readers: add's typed-argument admission and its record join (cmds/add.c), and
 * revert's restore admission (cmds/revert.c). The two admissions spell one rule:
 * a profile names a path once — three clauses at each site, the row's own two
 * read where the row is in hand for the sentence, and this predicate the third.
 * A drift between them is a defect, which is why both are named here. The record
 * join asks the other question the predicate answers: whether a capture's name
 * is still the profile's where the walk read it — the table cannot have moved
 * under the command's lock, but Git's branch can, another writer's commit taking
 * the name away since the capture's (cmds/add.c add_receipt_t's `gone`).
 *
 * @param manifest Manifest (NULL answers false)
 * @param profile The asker (NULL answers false)
 * @param filesystem_path Where the claim is placed (NULL answers false)
 * @param storage_path The name in question (NULL answers false)
 * @return Whether this profile holds that name for that path
 */
bool manifest_holds_name(
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path,
    const char *storage_path
);

/**
 * Is the row a claim its profile holds, rather than the layer's rung?
 *
 * True of every row a contribution holds, asked through any lookup — the index
 * or the profile's own (manifest_lookup_claim) — and so of every row the view
 * stands but the layer's rung (core/manifest.c manifest_layer): its profile is
 * the one it is attributed to, and its name one that profile would give the place,
 * never one it holds. Asked of the row's own class, as the contribution keeps
 * it apart: a derived row is held where the profile's derived claims hold it,
 * though the profile holds an explicit claim at the same path standing nowhere
 * — its own blob, lost to its own claims beneath, whose place its derived claim
 * fills.
 *
 * Readers: the name's holders, a rung holding no name (manifest_holder), and
 * export's directory claims, a rung being none to count (cmds/export.c
 * export_collect_filesystem, export_entry_from_row).
 *
 * @param manifest Manifest (NULL answers false)
 * @param row A row of this view (NULL answers false)
 * @return Whether the row's profile holds it
 */
bool manifest_holds_row(const manifest_t *manifest, const manifest_row_t *row);

/**
 * A claim as a namer reads it: the name, and how far it reaches
 *
 * `kind` is the whole reason this is a value and not a string: a claim at a path
 * names that path whatever it is, but only a DIRECTORY names what lies beneath
 * it — nothing is named beneath a blob: a name beneath its own is one the stage
 * refuses, and a path beneath its place one its writer refuses before it names
 * anything while the blob stands (cmds/add.c cmd_add, through manifest_blob_above),
 * and names past it where the blob lost the place to the claims beneath it. The
 * row is the claim entire, its mode and owner and blob (manifest_lookup_claim);
 * this pair is the claim as a namer needs it.
 *
 * The two layers a namer reads speak this one shape. A claim a verb has admitted
 * in this command and not yet committed — add's listing, the `pending` map — is
 * one; an explicit claim of the profile's own contribution projects into the
 * other, naming its own path with its kind saying whether anything can be named
 * beneath it. A derived row is no claim at all (it names neither itself nor what
 * lies beneath: manifest_is_derived), and the contribution keeps it apart, where
 * no namer reads it. A DIRECTORY the command admitted is a claim it made — an
 * argument, or a directory its walk entered; a verb that would admit a derived
 * claim has no business naming through it.
 *
 * The nearer layer answers alone for a place the profile names at most once.
 * Where it names a place more than once, *which* of its names is kept there is
 * the settle's question and not a single claim's, and the namer asks it again
 * under the claims admitted (manifest_name).
 *
 * The map is keyed by filesystem path in the spelling the view's own rows carry
 * — where a claim of this profile is placed, which is mount_resolve's answer
 * for its name (infra/mount.h). That is the key the ascent truncates to reach a
 * rung; and the map is the asking profile's own listing, a claim of it standing
 * in for that profile's committed row at the same place and for no other profile's.
 *
 * A stored claim always names: every path the verb listed carries the claim it
 * listed it under, a root's included (cmds/add.c add_list), so an entry in such
 * a map is a claim and one lookup answers both questions a reader has of it. A
 * NULL `storage_path` is no claim, and `kind` says nothing then.
 */
typedef struct {
    const char *storage_path;
    path_kind_t kind;
} manifest_claim_t;

/**
 * The name anything beneath this claim's path composes under, or NULL when nothing
 * does
 *
 * The top of the lattice manifest_is_derived names the bottom of. A claim names
 * its own path whatever its kind — that is `storage_path`, read directly — and
 * only a DIRECTORY names what lies beneath it; a claim that names nothing answers
 * NULL by its name, whatever its kind says. So the two questions a namer asks
 * are one read and two projections of it, and neither leans on which value of
 * the kind is the enum's zero.
 *
 * Readers: the ascent's rung (core/manifest.c manifest_ascend), which is now
 * the whole of it for both walkers — neither carries a frame and neither composes
 * anything, every listing and every offer asking the namer for its own name
 * (cmds/add.c, core/workspace.c).
 */
static inline const char *manifest_claim_beneath(manifest_claim_t claim) {
    return claim.kind == PATH_KIND_DIRECTORY ? claim.storage_path : NULL;
}

/**
 * What `profile` calls `filesystem_path` under this view
 *
 * Two layers at every rung, the path included, and the nearer answers alone: a
 * claim this command has admitted and not yet committed (`pending`: the path →
 * manifest_claim_t; NULL for every other reader) speaks for the place whatever
 * its kind, and only where it says nothing does the profile's committed row speak.
 * So a staged blob stands in for a tracked directory the profile holds at the
 * same path, exactly as it will once committed — where the blob takes the path
 * and the directory's name is the one the contribution does not keep.
 *
 * The claim kept at the path is its name; else the path is composed beneath the
 * nearest rung above it that names what lies beneath — a DIRECTORY claim of either
 * layer (manifest_claim_beneath), asked at every rung down to the profile's own
 * root and *before* that root decides, so a claim kept at the root itself outranks
 * it; else the label of the root it lies under and the tail past it (infra/mount.h
 * mount_root_above, infra/label.h label_compose), which at the root itself is
 * the word alone. An ancestor claim names nothing, and nothing is named beneath
 * a blob. The profile's own contribution is read, never the index: a path it
 * lost to a higher profile is still named by what it holds. `profile` may be
 * NULL — the shared roots alone, as the table reads one (infra/mount.h).
 *
 * This is the rule the view itself runs when a profile names one path twice —
 * minus the leaf clause, which is the one thing a settle cannot ask, the name
 * kept there being what it is deciding. The settle takes the ascent's answer
 * alone and keeps the name of the group that IS it; where the profile holds none
 * of it — the composed name is a name nobody committed — the bytewise-least is
 * kept instead. Every other name is manifest_unkept's.
 *
 * **What the next settle will keep.** At such a path this function does not report
 * that decision but re-takes it, because `pending` can change what the path's
 * ascent composes and therefore which name the settle keeps. What comes back is
 * the name the profile's next contribution will keep there, given the claims
 * the asker has admitted — by induction on the rungs, top down: a path the asker
 * claims and the profile does not otherwise name has that claim and no other; a
 * path the profile names more than once is decided by the settle's own rule over
 * its group, re-asked under the rungs above it; and a verb admits at such a path
 * only a name the profile already holds (manifest_holds_name), so no group grows.
 * That is what lets a capture land on the bytes the machine will deploy rather
 * than on a name the next load abandons.
 *
 * The induction is over the claims admitted **so far**. Naming is a snapshot
 * taken when a path is listed, and a claim a later argument admits above a path
 * already named does not re-name it; a verb whose arguments can do that says so
 * where it orders them (cmds/add.c).
 *
 * With `pending` NULL the re-taking reproduces the choice the settle already
 * made — a cost, never a difference — and the cost exists only where a branch
 * arrived holding two names for one path.
 *
 * The answer is the caller's arena's, whichever rung produced it, and never NULL:
 * naming is total over the paths a root encloses, which is every absolute path
 * — the sentinel encloses them all — so no reader meets an absence and none asks
 * a second authority what one would have meant.
 *
 * Readers: `ignore --test`'s subject, one per asker (cmds/ignore.c ignore_test);
 * the prospective name the claim name falls through to (manifest_claim_name);
 * the name every capture lands under — add's argument arm, its walk, and the
 * one refusal its completed selection owes, all over the command's own listing
 * (cmds/add.c cmd_add, add_collect, add_refuse_moves), and the frame a walk's
 * refusal offers to leave out, named as the walk named it (add_refuse_unjudged);
 * and the name the untracked scan offers a new path under, one per entry its
 * guards let through, with no pending layer — the scan admits nothing
 * (core/workspace.c workspace_scan). The settle of a contribution's collisions
 * asks the same rule (core/manifest.c manifest_settle).
 *
 * @param arena Arena the name lives in (must not be NULL)
 * @param manifest Manifest (must not be NULL)
 * @param profile The asker, or NULL for the shared roots alone
 * @param filesystem_path Where to ask, absolute (must not be NULL)
 * @param pending The asking profile's uncommitted claims, keyed by filesystem
 *                path (manifest_claim_t), or NULL
 * @return The name; never NULL
 */
const char *manifest_name(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path,
    const hashmap_t *pending
);

/**
 * The name `profile` has for `filesystem_path` under this view: the claim it
 * holds there, or the name a claim there would take
 *
 * A filesystem key, and the only one. The resolver answers two and the other is
 * already settled where the argument was read (infra/path.h): a name the user
 * typed is Git's key, so the caller's own question decides whether the profile
 * holds it (core/profiles.h profile_holds) and there is nothing here to ask — a
 * name no claim sheet mentions, a bare subtree, a name the view did not keep,
 * is held by the profile and never by its view. What arrives here is the key
 * that needs the profile's view to answer it.
 *
 * Asked of the profile's own contribution, in this order: the row it holds there
 * (manifest_lookup_claim) answers with its own name whatever its kind, so
 * home/jail/etc/x under a binding at ~/jail is found by ~/jail/etc/x and the
 * chain above a file captured before the binding answers as the claim it is;
 * else the name the profile would give the path (manifest_name) — the word a
 * history search and a not-found line need, which at a root of the profile's
 * own is that root's label's word. Two arms and no third: naming is total, so
 * every path this is asked about has a name.
 *
 * The row before the namer is the contract, not a shortcut: a derived claim is
 * something the profile holds and nothing it names (manifest_is_derived), so
 * the namer alone would climb past it and answer a name the profile never held.
 * Search first, name second.
 *
 * A name, never an enumeration. A DIRECTORY claim names its path and says nothing
 * about what stands beneath it (manifest_lookup_claim); a verb that means
 * everything at a place selects rows by path (cmds/export.c) and never walks
 * this answer's subtree.
 *
 * The path keys against the rows by strcmp (infra/mount.h). The answer is the
 * caller's arena's whichever arm produced it, as manifest_name's is.
 *
 * Its readers build the view for it, one profile's (manifest_build_profile) over
 * the tree the verb selected, and that build is the whole of what a path costs:
 * one tree walk, and the sheet loaded at the profile's first question
 * (core/profiles.h). Its other face: a profile whose sheet will not load refuses
 * a path where the name its caller answers unaided proceeds — the view is strict,
 * a verb's own read is not. A ref or a tree that will not load refuses both.
 *
 * Readers: `show -p` and `list -p`, over the view of the tree the verb selected
 * (the head, or the commit the user named, so a name that changed since is found
 * as of then: cmds/show.c cmd_show, cmds/list.c list_file_history). `export`
 * selects rows instead, `remove` matches its own claims, `revert` reads the claim
 * held in the tree it edits (cmds/revert.c revert_claim_held), and `ignore --test`
 * asks manifest_name itself.
 *
 * @param arena Arena the name lives in (must not be NULL)
 * @param manifest Manifest (must not be NULL)
 * @param profile The asker, or NULL for the shared roots alone (manifest_name)
 * @param filesystem_path Where to ask, spelled as the rows are keyed (must not
 *        be NULL)
 * @return The name; never NULL
 */
const char *manifest_claim_name(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const char *filesystem_path
);

/**
 * The first of `profile`'s places whose side a command's claims would move —
 * its blob, or NULL
 *
 * A place is a blob of the profile's own with explicit claims of its own beneath
 * it under another label, and the name the profile would give it fresh decides
 * which of the two stands: the blob where the claim its settle keeps there is
 * that name, the claims beneath it where it is not (core/manifest.c
 * manifest_layer). A directory claim this command admits above the place changes
 * what that name composes (`pending`, as manifest_name reads it), and with it
 * the side the next build stands — a file where apply created a directory, or
 * the reverse, which no capture asked for. Each place is asked alone, the ascent
 * climbing past a blob.
 *
 * The places are the profile's as committed. A capture moves none of them: beneath
 * a standing blob it is refused (cmds/add.c cmd_add, through manifest_blob_above),
 * beneath a lost one it composes under the place's fresh name, and at a place's
 * path it names the blob, or is refused by kind where the directory stands. A
 * place a capture makes — a blob over claims of its own under a root inside it
 * — is decided when it arrives, over the capture's own bytes.
 *
 * Reader: the completed selection's refusal in add (cmds/add.c add_refuse_moves).
 *
 * @param arena Arena the scratch lives in (must not be NULL)
 * @param manifest Manifest (must not be NULL)
 * @param profile The asker (NULL holds no place)
 * @param pending The asking profile's uncommitted claims, keyed by filesystem
 *                path (manifest_claim_t), or NULL
 * @return The place's blob as the view holds it, or NULL where none moves
 */
const manifest_row_t *manifest_moved_place(
    arena_t *arena,
    const manifest_t *manifest,
    const char *profile,
    const hashmap_t *pending
);

/**
 * Per-profile statistics from a view-to-view diff, in claims
 *
 * A claim is an explicit row — a file, a link, a tracked directory: the unit
 * `dotta list` and `status -v` count (core/profiles.h profile_counts_t). A derived
 * row is the way to the claims beneath it, which apply creates or lets go as
 * they need it, so it counts on neither side. One profile can gain claims and
 * lose others in one transition (a pull that adds one path and removes another),
 * so gain-side and loss-side fields are independent.
 *
 *   Gain-side  — the claims `after` stands under the profile.
 *   Loss-side  — the claims `before` stood under the profile that `after` does
 *                not.
 *
 * Counters describe the two views and the record; they do NOT verify disk matches
 * anything. Verification is workspace divergence analysis (status/diff/apply).
 *
 * `reassigned` here is this transition's own delta — a claim `before` held under
 * one profile whose path `after` gives another — and not the standing fact the
 * screens name by the same word: a record dotta owns naming a profile the row
 * does not is workspace_reassigned (core/workspace.h), true from whenever it
 * began until apply acknowledges it. `overridden` is the transition's own the
 * same way — a claim `before` stood under a profile that still holds it in `after`,
 * where it stands nowhere — and not the copy the record keeps there, overridden
 * (core/workspace.h WORKSPACE_STATE_OVERRIDDEN) from whenever a blob came to
 * stand above it until that blob goes or its landing clears the copy.
 */
typedef struct {
    const char *profile;   /* Profile name (borrowed from the profiles filter) */

    /* Gain-side */
    size_t added;          /* Claims at a path `before` stood no claim at */
    size_t updated;        /* Claims at a path `before` stood one at, its type, blob, mode, owner or group moved */

    /* Loss-side */
    size_t reassigned;     /* Claims whose path `after` gives another profile */
    size_t overridden;     /* Claims the profile holds still, standing nowhere in `after` */
    size_t orphaned;       /* Claims gone, with a record at the path: orphans the next apply settles */
} manifest_diff_stats_t;

/**
 * Attribute the transition between two views to profiles, in their claims
 *
 * The delta sync's Manifest block prints (cmds/sync.c cmd_sync): what each profile
 * in `profiles` claims in `after` that it did not in `before`, what it lost to
 * another profile's row or to a blob standing above it, and what left the view
 * under it — the last counted only where a record stands, because only a path
 * dotta has observed has anything for apply to do at its departure; a departure
 * with no record asks nothing of apply and is not counted.
 *
 * Attribution (for a profile P in `profiles`, over its claims; a derived row of
 * either view counts nowhere):
 *   - every claim of `after` under P: added if `before` stands no claim at the
 *     path — no row, or a derived one, a claim born where a way was; updated if
 *     it stands one whose type, blob, mode, owner or group differs. Between two
 *     claims a class flip is a type flip, so `tracked` needs no term of its own
 *   - every claim of `before` under P whose path `after` gives another profile:
 *     reassigned
 *   - every claim of `before` under P whose path `after` stands no row at, P
 *     claiming the path there still (manifest_lookup_claim): overridden. No row
 *     at its path leaves a blob standing above it — another profile's, or on
 *     this machine P's own, which contradicts it (manifest_contradicted) — and
 *     its copy is that blob's landing's, which clears it (core/workspace.c
 *     workspace_analyze_orphans), so no record is asked
 *   - every other claim of `before` under P whose path `after` lacks, with a
 *     record at the path: orphaned. What apply does there is the orphan analysis's
 *     (core/workspace.c workspace_analyze_orphans): a copy beneath a blob `after`
 *     stands is that blob's landing's, and otherwise the record's ownership and
 *     — a file's Git, a directory's what is left in it — say whether apply prunes
 *     the copy or releases it
 *   Overlap semantics, by where the claim standing over A's at path X is
 *   (core/manifest.c manifest_layer): at X, B gets added or updated for X and A
 *   reassigned; beneath X, A's blob there having lost its place to the claims
 *   beneath it, the row standing at X — a derived claim filling the place, or
 *   the layer's rung, attributed to the side A lost to — is the way to the claims
 *   beneath it, counted on their own, and A is reassigned for X, or, the row
 *   being A's own, counted nowhere; above X — a blob, which leaves no row at X
 *   — A gets overridden for X.
 *
 * `before` may be NULL — an empty view: every claim of `after` is then added
 * and nothing departed.
 *
 * Preconditions:
 *   - profiles' entries are pairwise unique: two slots would silently collapse
 *     into one, so a duplicate is the caller's bug, a death
 *   - out_stats points to an array of length profiles->count; it is zero-filled
 *     here with each profile's name set, so a caller reads the counts without
 *     asking whether anything changed
 *
 * Performance: O(A + B (P + log R)) — one pass over each view, and per claim
 * `after` stands nothing at, the profile's claim there (P the profiles `after`
 * holds) and, where it claims none, a search of the record; no Git, no disk, no
 * database.
 *
 * @param before View before the transition (may be NULL = empty)
 * @param after View after the transition (must not be NULL)
 * @param records The record, as state_records returns it — in its order, which
 *                the search rests on (may be NULL when record_count is 0)
 * @param record_count Number of records
 * @param profiles Profiles to attribute to (must not be NULL)
 * @param out_stats Parallel array (length profiles->count; must not be NULL)
 */
void manifest_diff(
    const manifest_t *before,
    const manifest_t *after,
    const state_record_t *records,
    size_t record_count,
    const string_array_t *profiles,
    manifest_diff_stats_t *out_stats
);

#endif /* DOTTA_MANIFEST_H */
