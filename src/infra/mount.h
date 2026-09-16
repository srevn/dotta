/**
 * mount.h - Where a label lands: the per-machine table of roots
 *
 * Where a label lands
 * -------------------
 * A profile names what it holds portably, `<label>/<tail>` (infra/label.h), and
 * this module is where each label stands on one machine:
 *
 *   home/X   - X under $HOME (per-machine $HOME resolution)
 *   root/X   - /X (filesystem root; same on every machine)
 *   custom/X - X under a per-profile, per-machine deployment target (configured
 *              via `--target` at profile-enable time)
 *
 * Storage paths are stable across machines; the per-machine filesystem location
 * of a label is decided by the mount table below. The grammar of a name — the
 * three words, the shape rule and the split beneath both — is the layer under
 * this one: this module reads it, and it reads nothing of the table.
 *
 * The table
 * ---------
 * The machine's topology: its roots — the invoker's HOME, `/`, and one target
 * per binding — each by one spelling, the one its binder typed (HOME as the
 * identity spells it, a target as the row holds it). Built at the boundary where
 * the binding source is in scope (CLI options, state row cache), then consulted
 * many times; a value — the topology at the instant it was built — for the arena's
 * lifetime. The build reads no disk: the table is a pure function of the rows
 * and the identity, and every verb over it is string work.
 *
 * A location — where a claim stands on this machine: the key the view's rows,
 * the record and every screen share — is a root's spelling joined with a tail.
 * A key is the spelling its writer typed, and the four producers of one agree
 * because they read the same strings: mount_resolve (a root's spelling and a
 * claim's tail), the location door (an argument, folded; infra/path.h
 * path_input_locate), a walk's join (a parent and a name) and a climb's cut — a
 * key truncated at a separator, which is a root's spelling and a shorter tail
 * whichever label named it, so an ancestor's key is never manufactured a second
 * way (core/manifest.c manifest_ascend, core/workspace.c blob_over, core/cleanup.c,
 * infra/pathspec.c). So two locations are one path iff they are one string, and
 * a symlink anywhere in a path is a component like any other:
 * nothing here reads through one, `~/.config -> ~/dotfiles/config` stays the
 * entry it is, and two claims through and around it are two claims. A filesystem
 * that folds case or normalization can stand one entry at two strings; the two
 * readers that act on an entry read the entry and not the string (core/workspace.c
 * standing_row, for cleanup and discovery alone).
 *
 * Identity is read at two kinds of place, neither of them this table. Where a
 * spelling is made from a source that did not spell it under a root: the binders
 * (mount_same_target — one directory under two spellings is one binding, and
 * the row keeps the spelling it has), which add's path completion asks once more
 * so its offer stands under the spelling the command will read its arguments
 * under (cmds/completion.c), and the normalizer's working directory (infra/path.h).
 * And where acting on a string alone would duplicate or destroy: the scan's roots
 * and its leaf probe, cleanup's guard (core/workspace.c), and add's refusal of
 * a HOME that reaches the filesystem root through a link (cmds/add.c).
 *
 * Every root's spelling is absolute and folded (sys/filesystem.h fs_is_folded),
 * each established where it is made: the sentinel's is the literal "", HOME's
 * is the identity's (sys/identity, normalized at identity_init), and a row's
 * target is normalized and validated where it is written (the binders,
 * mount_validate_target) over a column that holds no other shape (core/state.c:
 * a target no binder would write is refused where a hand makes the edit). So
 * the build meets only spellings that are keys — `/` spelled "" — and refuses
 * any other as a caller's bug (mount_table_build). A row bound nowhere holds
 * NULL, which contributes no mount; the repair is a re-bind.
 *
 * The root directory is spelled "" in the table — the one spelling that joins a
 * tail with one slash and encloses every absolute path at depth zero: the
 * sentinel's, HOME's when HOME is "/" (a container's bare uid), and a binding's
 * when its target is "/" (a container's own root; mount_table_build). One reader
 * turns it back into the path it spells, for a caller that walks a root rather
 * than joins beneath it (mount_root_location).
 *
 * One table, one reading
 * ----------------------
 * Every verb reads the asker's own entries — its target if it is bound, HOME,
 * `/` — and no other profile's: another profile's target is an ordinary directory
 * in this namespace, named portably, and a table holding one profile's binding
 * would answer that profile exactly as the whole table does. The table holds
 * every binding because one build serves every asker of the view (core/manifest),
 * each contribution its own asker; that is why the asker is a parameter and not
 * a table of its own.
 *
 * A namespace is one profile's view over the table. N profiles may claim one
 * location under N names; the view layers them by precedence (core/manifest),
 * and within one profile the view keeps one. Nothing is exclusive: a binding
 * says where a profile's names resolve, not who owns the files there.
 *
 * Three questions over the same data:
 *   - What a profile would call a location it holds no claim at (location ->
 *     storage): mount_name, beneath the deepest of that profile's own roots;
 *     nothing at a root itself. The fuller question — a claim of the profile
 *     standing at or above the location, and only then this — is core/manifest.h's
 *     manifest_name, whose last rung this is.
 *   - Whether a location is one of a profile's roots: mount_root, the walkers'
 *     and the climb's question.
 *   - Where a profile's claim stands (profile + storage -> filesystem):
 *     mount_resolve. A name is composed beneath a root's spelling, so resolving
 *     one places it back at the very location it was composed from.
 *
 * Traversal is refused at the boundary and trusted below it: a storage path where
 * a branch, a sheet or an argument is read (infra/label.h label_validate_storage),
 * a target where a binding is written (mount_validate_target). The verbs over
 * the table join a tail on that strength and validate nothing themselves.
 */

#ifndef DOTTA_MOUNT_H
#define DOTTA_MOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <types.h>

#include "infra/label.h"

/**
 * What a label implies.
 *
 * The label names *which namespace a storage path is in* (infra/label.h); the
 * row carries *what the label implies*: the noun a screen calls the root by,
 * and the two per-label facts every consumer ultimately asks — "is resolution
 * profile-keyed?" and "do files under this label carry ownership metadata?".
 *
 * One row per label, indexed by it — the shape utils/config.h's strategies and
 * crypto/kdf.h's presets take — so a fact of a label is a subscript and never a
 * lookup.
 *
 * Every field here is leaving, and the row with them: the noun becomes what the
 * table renders from the root it found, `per_profile` becomes the owner the build
 * stamps on an entry, and `tracks_ownership` becomes the sheet's own statement
 * about what an absent claim means. Until each moves, this is where its reader
 * subscripts.
 */
typedef struct mount_spec {
    const char *noun;             /* The root's word for a screen — a complete noun
                                   * phrase; a per_profile root takes " of profile
                                   * '<name>'" after it (mount_root_describe) */
    bool per_profile;             /* True iff resolution is profile-keyed (CUSTOM) */
    bool tracks_ownership;        /* True iff files under this label carry ownership
                                   * metadata */
} mount_spec_t;

extern const mount_spec_t mount_kinds[LABEL_COUNT];

/**
 * Validate a deployment target (the `--target` argument) as the row will hold it.
 *
 * The binders locate first (infra/path.h path_input_locate: tilde, the working
 * directory, `.`, `..`, `//`), so what reaches here is the absolute path the
 * row stores; the shape rule holds for a caller that did not (the interactive
 * save's validate, on text a resolve refused).
 *
 * Refuses, in order, one message each:
 *  - a spelling that is not absolute and folded (sys/filesystem.h fs_is_folded)
 *    — the shape every key has
 *  - a path that does not stand (a link to nothing named as such), or that is
 *    not a directory — one stat, through a link standing at the spelling: a binding
 *    means the directory the link reaches, as mount_same_target reads it
 *  - the directory dotta's own store stands in, by identity off that same stat
 *    — named outright or reached through a link, a binding there would put a
 *    profile's custom/ tree over the store's own config and refs at the next
 *    apply. The pair is the caller's to hand in: where the store is, is the run's
 *    fact (utils/repo.h, git_repository_path), which this table cannot ask
 *
 * The shape before the disk, so a traversal is refused by what it is and never
 * by its absence. The filesystem root is a target like any other: a binding there
 * names the machine custom/ for that profile, and the next machine binds the
 * same profile where it likes (mount_table_build). Every target this admits is
 * absolute and folded, which is the build's precondition.
 *
 * Filesystem access is required for the existence + directory checks.
 *
 * @param target Deployment target to validate (must not be NULL)
 * @param store_dev Device of the store's directory, as its caller stat'd it
 * @param store_ino Inode of the same: together, the one directory no binding
 *                  may reach, compared against the stat this function already takes
 * @return Error or NULL when valid
 */
error_t *mount_validate_target(const char *target, dev_t store_dev, ino_t store_ino);

/**
 * Do two target spellings name one directory?
 *
 * A binding names a place, not a spelling, and the row keeps the spelling its
 * binder typed — the key of every path beneath it (the table's paragraph above).
 * So the binders ask this of a target typed against the row's, and a second
 * spelling of the row's own directory is never written as a move: a move re-keys
 * every record under the profile — each becomes a stale key the guard releases
 * and the next apply re-owns (core/workspace) — and one that changes only the
 * row's spelling buys that churn for nothing. A spelling that stands is named
 * by its directory: the two are one when they have one device and inode, through
 * a symlink standing at either (a target is validated by the directory it reaches,
 * through a link standing at it — mount_validate_target — so a binding means
 * that directory). One that does not stand — a stale row, its directory gone —
 * is named by its spelling, and a differing one is a move. One of the two places
 * identity is read where a spelling is made (the other is the normalizer's working
 * directory, infra/path.h); the two CLI binders say at NORMAL which spelling
 * they kept (cmds/profile.c, cmds/add.c), the interactive save, which has no
 * line to say it in, puts the kept spelling back on the item its next screen
 * renders (cmds/interactive.c plan_classify), and add's path completion, which
 * has none either, lists under it (cmds/completion.c completion_paths_under) so
 * the offer and the capture read one spelling.
 *
 * Readers: add's pre-flight, profile enable's retarget arm, the interactive save's
 * classify, add's path completion.
 */
bool mount_same_target(const char *a, const char *b);

/**
 * Opaque mount-table handle. Built by `mount_table_build`; lifetime tracks the
 * arena passed at build time, and nothing else — every string is the arena's.
 * There is no destructor — arena_destroy reclaims everything.
 */
typedef struct mount_table mount_table_t;

/**
 * A single mount: the profile <-> deployment-target pairing.
 *
 * POD value type passed by callers to `mount_table_build`. Both fields are borrowed
 * for the call only — the table copies what it keeps.
 *
 * - profile: the owning profile's name; required, whatever the target. A binding
 *   is a profile's: an entry with no profile would be a root of every namespace
 *   (mount_name and mount_root read a NULL profile as "the shared roots — HOME
 *   and `/`"), which is the machine-wide name this module does not produce.
 *   mount_table_build refuses one.
 * - target: where the profile's custom/ tree stands, as its binder wrote it —
 *   absolute and folded (sys/filesystem.h fs_is_folded), "/" included, which
 *   the table spells "" — and the key of every custom/ path beneath it. NULL or
 *   empty contributes no mount: the profile is bound nowhere in that table. Any
 *   other string is refused at the build (mount_table_build).
 */
typedef struct {
    const char *profile;
    const char *target;
} mount_t;

/**
 * Build a mount table from a flat array of mounts.
 *
 * Each mount is known by one spelling, its binder's, and every location beneath
 * it is that spelling joined with a tail (the table's paragraph above). The build
 * reads no disk: the table is a pure function of `mounts` and the identity.
 *
 * The table is augmented internally with:
 *   - A HOME mount at the invoker's home as the identity spells it (sys/identity).
 *   - A ROOT mount whose target is the empty string (universal fallback for
 *     absolute paths that match no other mount).
 *
 * A mount with no profile, or with a target that is not absolute and folded, is
 * refused (ERR_INVALID_ARG): a binding is a profile's, and a root is a spelling
 * that is a key. Both invariants are established here so the readers need no
 * per-read check (mount_t above), and both hold of every input by construction
 * — the store's column for a row (core/state.c), mount_validate_target for a
 * command's own binding. A target of "/" is a root like any other, spelled ""
 * for the join's sake (the table's paragraph above), and takes the tie from the
 * sentinel: every path of that profile outside a deeper root is custom/. A NULL
 * or empty target contributes nothing: the profile is bound nowhere, which the
 * view records (core/manifest.h manifest_unbound) and a re-bind repairs. A store
 * a hand still got a malformed row into — its constraints switched off, or its
 * marker bumped without the table — fails every command that builds the view
 * but one: `profile disable`, whose receipt's view is built tolerantly on purpose
 * (cmds/profile.c), which is the way out, then a re-bind.
 *
 * Lifetime:
 *   - Output is allocated entirely from `arena`, every string included: the table
 *     borrows nothing from `mounts`, so it is a value for the arena's lifetime
 *     — readable after the rows it was built from have moved.
 *   - The home is copied into the arena at build time, immune to later setenv
 *     mutations.
 *
 * Errors:
 *   - ERR_INVALID_ARG when a mount names no profile, or names a target that is
 *     not absolute and folded.
 *   - ERR_MEMORY on arena allocation failure.
 *
 * Two production readers. core/manifest.h's manifest_mount_table shapes the state's
 * rows — and a command's own binding, where the run brought one — into the array:
 * every verb reads the asker's own entries, so a table holding one binding would
 * answer its profile as the whole table does, and the one derivation is kept
 * because the rows a command's table is built from are the rows the view it later
 * joins by is built from (cmds/add.c). core/profiles.c's profile_needs_target
 * builds the table no state can produce — no mounts at all, HOME and the sentinel
 * alone — to ask a branch what it needs apart from what this machine binds.
 *
 * @param arena       Arena for the table and its internal storage
 * @param mounts      Caller-declared mounts (may be NULL when count is 0)
 * @param mount_count Number of mounts
 * @param out         Output handle (must not be NULL)
 * @return Error or NULL on success
 */
error_t *mount_table_build(
    arena_t *arena,
    const mount_t *mounts,
    size_t mount_count,
    mount_table_t **out
);

/**
 * What `profile` would call a location it holds no claim at.
 *
 * "<label>/<tail>" beneath the deepest of the profile's own roots — its target,
 * HOME, `/` — or NULL when the location *is* that root: a root has no canonical
 * name, and the tree standing there is its label's. Another profile's target is
 * invisible here (the "One table, one reading" paragraph above). At a tie — two
 * of the profile's own roots at one directory — a binding wins, because it is
 * the more specific statement (`~/.rc` under a binding at $HOME is `custom/.rc`;
 * `/etc/x` under a binding at "/" is `custom/etc/x`, and nothing under HOME is,
 * HOME being the deeper root); between HOME and `/` at one directory the portable
 * name wins (a HOME of "/" yields to the sentinel, so `/etc/x` is `root/etc/x`
 * — `home/` there would name the whole filesystem on every other machine). A
 * NULL `profile` names through HOME and `/` alone: a profile with no binding on
 * this machine, or no profile at all.
 *
 * `location` is a key — a row's, a record's, an argument's as the normalizer
 * spelled it, a walk's join — and the test is a string's: a root encloses the
 * location iff its spelling is a prefix of it on a component boundary, the root
 * itself included. Nothing is respelled here and nothing is read through.
 *
 * A name is composed beneath a root's spelling, so mount_resolve places an answer
 * of this one back at the very location it was composed from.
 *
 * This is the *last* rung of the question a command actually asks. A claim of
 * the profile standing at or above the location outranks every root, and
 * core/manifest.h's manifest_name is the whole ascent with this at its end.
 *
 * The answer is the arena's. NULL is a root, and mount_root names which.
 *
 * Errors:
 *   - ERR_INTERNAL when no root encloses the location — a malformed table, or a
 *     `location` that is not absolute. The sentinel encloses every absolute path
 *     at depth zero and belongs to every namespace, so a well-formed table always
 *     answers.
 *   - ERR_MEMORY on arena allocation failure.
 *
 * Readers: the last rung of the namer's ascent (core/manifest.c manifest_ascend),
 * and nothing else. No command reads it: a command asks what a profile calls a
 * location, which is its claim there first and this only at the end of the climb.
 * `ignore --test` was one until its subject became the whole ascent's
 * (core/manifest.h manifest_name); the five `-p` verbs shared an interim resolver
 * over it (infra/path.h) until each found its claim where it stands
 * (core/profiles.h profile_claim_name) or matched by location outright
 * (cmds/remove.c); and add's argument arm and its walk were the last two, until
 * they asked the namer instead.
 *
 * @param table       Mount table (must not be NULL)
 * @param profile     The asker, or NULL for the shared roots alone
 * @param location    Absolute location (must not be NULL)
 * @param arena       Arena that owns `*out_storage`
 * @param out_storage Arena-borrowed storage path, NULL at a root (must not be
 *                    NULL; NULL after an error)
 * @return Error or NULL on success
 */
error_t *mount_name(
    const mount_table_t *table,
    const char *profile,
    const char *location,
    arena_t *arena,
    const char **out_storage
);

/**
 * Does a root of `profile` stand exactly at `location`, and which?
 *
 * By the root's one spelling: exact equality is the whole test, a key being a
 * string of the rows' own (the table's paragraph above). True, `*out_label`
 * written, when one does; false, `*out_label` untouched, when none does.
 * `out_label` may be NULL for a caller that asks only whether.
 *
 * A root met from above is entered unlisted and its children are named from its
 * label; a symlink standing at one is skipped by a walk and followed by the
 * argument that names it (cmds/add.c, find -H's rule); a claim the climb would
 * author at one is not authored (core/metadata.c). Asked once per directory entry
 * and once per chain rung. Never fails, allocates nothing; `table` and `location`
 * must not be NULL, `profile` may be — a NULL asker meets the shared roots (HOME,
 * `/`) alone, so the answer is never a per_profile root.
 *
 * Readers, by what they read. Whether alone: the namer's ascent, at every rung
 * rather than once per argument (core/manifest.c manifest_ascend), and the climb's
 * root guard (core/metadata.c capture_ancestor). The root's label alone, holding
 * the invariant that a root stands there (mount_root_describe): add's two root
 * refusals — the argument arm and the already-walked arm (cmds/add.c), `ignore
 * --test`'s root line (cmds/ignore.c), the claim search's root refusal
 * (core/profiles.c profile_claim_name). Both: revert's, asked directly where
 * its own search answered nothing at the location (cmds/revert.c).
 */
bool mount_root(
    const mount_table_t *table,
    const char *profile,
    const char *location,
    label_t *out_label
);

/**
 * Where `profile`'s root of `label` stands, as a location.
 *
 * The inverse of mount_root: that one asks which root stands at a location, this
 * one where a root stands. The entry's spelling as a path — "/" where the table
 * spells the root "" (the sentinel, a HOME of "/", a binding at "/") — or NULL
 * for a per_profile root the profile is not bound at here, and for a NULL asker
 * naming one. A location and never the table's own spelling, because the reader
 * walks it, stats it and joins beneath it by the walkers' rule (a separator unless
 * the directory is "/"), and the one spelling that is not a path — "" — is exactly
 * the one lstat answers ENOENT to. HOME and the sentinel are every asker's and
 * always answer.
 *
 * The entry, not the tie: a HOME that is also a binding is one directory under
 * two labels, and each label answers its own spelling here, where mount_root
 * and mount_name give the binding the tie. Never fails, allocates nothing; the
 * answer is the table's for the arena's lifetime, or the literal "/".
 *
 * Reader: the view's contribution, which asks where each root the sheet scans
 * stands and records the one that stands nowhere (core/manifest.c
 * manifest_contribute). No walker asks the table: the contribution having asked
 * once, the scan reads the view.
 */
const char *mount_root_location(
    const mount_table_t *table,
    const char *profile,
    label_t label
);

/* The longest sentence mount_root_describe renders: "the deployment target" (20),
 * " of profile '" (13), a profile name, the closing quote and the terminator.
 * The name is bounded by the ref it becomes, not by git's 255 — that one is per
 * component and a profile name has several: gitops_build_refname refuses a name
 * that will not fit DOTTA_REFNAME_MAX after "refs/heads/", and every site that
 * turns a profile into a ref goes through it (sys/gitops.h). */
#define MOUNT_NOUN_MAX 320

/**
 * A root's noun for a screen, rendered into `buf` and returned: "your home
 * directory", "the filesystem root", "the deployment target of profile 'web'".
 *
 * `root` is the root being described, as the label mount_root wrote, and every
 * caller holds one a table found. Most have just had mount_name answer NULL for
 * the same table, asker and location — asked directly, or as the last rung of
 * the namer's ascent (core/manifest.c manifest_ascend), which is the only way
 * that one answers NULL — the same find over the same data, an invariant rather
 * than a hope; they ask mount_root for the label and never read whether. A caller
 * whose own search already answered nothing at the location asks mount_root
 * directly and reads both (cmds/revert.c), which establishes the same thing.
 * `profile` is read only for a per_profile root, and a per_profile root found
 * in a table can only have been found by the profile that owns it, so it is
 * non-NULL exactly when it is read.
 *
 * The body's `&& profile` therefore guards nothing: it stood for the one caller
 * that reached a label with no table behind it, and there is none now — what a
 * label names is no place and is said in the grammar's own word (infra/path.h
 * path_input_refuse_label). The arm and the parameter leave together when a root
 * becomes a value the table hands out; until then the guard is kept, an unreachable
 * branch being the better of it and an unreachable "(null)".
 *
 * Returns `buf`, so the noun reaches the message it belongs to as a value rather
 * than through a statement of its own: every site that says a place has no name
 * would otherwise spell the noun its own way — and the message is the same one
 * whether a pattern, an argument, a search or a revert asked. The sentence around
 * it stays the site's, every one of them.
 *
 * Truncates rather than fails: a screen noun, not a key.
 */
const char *mount_root_describe(
    label_t root,
    const char *profile,
    char *buf,
    size_t size
);

/**
 * Where a claim stands on this machine: a storage path through a profile's mount.
 *
 * Resolution table:
 *   home/X   -> $HOME/X                  (profile may be NULL)
 *   root/X   -> /X                       (profile may be NULL)
 *   custom/X -> <profile's target>/X     (profile must match a CUSTOM mount)
 *
 * The location is the root's spelling, "/", and the tail: the key of the claim,
 * and the one every producer of a key agrees on (the table's paragraph above).
 * A link anywhere in it is a component — a claim captured through one stands
 * where its spelling says, and so does a claim of the link itself.
 *
 * Absence is NULL, as every lookup in the tree answers it (manifest_lookup,
 * state_peek_profile_target, hashmap_get): `*out_location` is NULL when the claim
 * is `custom/` and the profile has no target on this machine — a clone before
 * the target is chosen, a sync that pulled another machine's claims — and the
 * callers read it as the fact it is: the manifest's claim routine skips
 * the claim and records it on the view (manifest_unbound, the health channel);
 * user-facing contexts fall back to a display spelling (remove.c) or let a hint
 * stand in (ignore.c). HOME and ROOT lookups always answer — those entries are
 * unconditional in every well-formed mount table. `*out_location` is NULL on
 * entry, so it is NULL after an error too.
 *
 * Errors:
 *   - ERR_INTERNAL when `storage_path` lacks a known label (the input boundary
 *     is supposed to validate before reaching here; this guards against contract
 *     drift).
 *   - ERR_MEMORY on arena allocation failure.
 *
 * @param table        Mount table (must not be NULL)
 * @param profile      Owning profile (may be NULL for home/ and root/ paths)
 * @param storage_path Storage-format path (must not be NULL, validated)
 * @param arena        Arena that owns the location
 * @param out_location Arena-borrowed filesystem path; NULL for a custom/ claim
 *                     the profile cannot place here (must not be NULL)
 * @return Error or NULL on success
 */
error_t *mount_resolve(
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    arena_t *arena,
    const char **out_location
);

#endif /* DOTTA_MOUNT_H */
