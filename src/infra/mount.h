/**
 * mount.h - Storage labels and per-machine deployment mount table
 *
 * Storage-path namespace
 * ----------------------
 * Dotta encodes deployment locations into a portable namespace:
 *
 *   home/X   - X under $HOME (per-machine $HOME resolution)
 *   root/X   - /X (filesystem root; same on every machine)
 *   custom/X - X under a per-profile, per-machine deployment target (configured
 *              via `--target` at profile-enable time)
 *
 * The label (`home`, `root`, `custom`) names which mount kind a storage path
 * belongs to. Storage paths are stable across machines; the per-machine filesystem
 * location of a label is decided by the mount table below.
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
 * claim's tail), the normalizer (an argument, folded; infra/path.h), a walk's
 * join (a parent and a name) and a climb's cut — a key truncated at a separator,
 * which is a root's spelling and a shorter tail whichever label named it, so an
 * ancestor's key is never manufactured a second way (core/manifest.c
 * manifest_ascend, core/workspace.c blob_over, core/cleanup.c, infra/pathspec.c).
 * So two locations are one path iff they are one string, and a symlink anywhere
 * in a path is a component like any other:
 * nothing here reads through one, `~/.config -> ~/dotfiles/config` stays the
 * entry it is, and two claims through and around it are two claims. A filesystem
 * that folds case or normalization can stand one entry at two strings; the two
 * readers that act on an entry read the entry and not the string (core/workspace.c
 * standing_row, for cleanup and discovery alone).
 *
 * Identity is read at two kinds of place, neither of them this table. Where a
 * spelling is made from a source that did not spell it under a root: the binders
 * (mount_same_target — one directory under two spellings is one binding, and
 * the row keeps the spelling it has) and the normalizer's working directory
 * (infra/path.h). And where acting on a string alone would duplicate or destroy:
 * the scan's roots and its leaf probe, cleanup's guard (core/workspace.c), and
 * add's refusal of a root that reaches the filesystem root (cmds/add.c).
 *
 * A row's target is normalized and validated where it is written (the binders,
 * mount_validate_target); the build asks only what an entry is — an absolute
 * path that is not the root, `/` being the one spelling that ends in its own
 * separator, which the sentinel spells "" for the join's sake — and a row that
 * came through no binder keys its claims at whatever it spells, which no argument
 * can spell back. The repair is a re-bind: at a different directory, or a disable
 * and an enable, since the binders keep a row's spelling for its own directory
 * (mount_table_build).
 *
 * The root directory is spelled "" in the table — the one spelling that joins a
 * tail with one slash and encloses every absolute path at depth zero: the
 * sentinel's, and HOME's when HOME is "/" (a container's bare uid).
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
 * SECURITY CRITICAL: All conversions validate against path traversal.
 */

#ifndef DOTTA_MOUNT_H
#define DOTTA_MOUNT_H

#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * Mount kinds — one per storage label.
 */
typedef enum {
    MOUNT_HOME,    /* home/...   -> $HOME/... */
    MOUNT_ROOT,    /* root/...   -> /... */
    MOUNT_CUSTOM,  /* custom/... -> per-profile deployment target */
} mount_kind_t;

/**
 * The kinds' arity, for a walk over the labels (cmds/export.c's tree, cmds/add.c's
 * receipt) and for an array with one slot per kind. A macro, not an enumerator,
 * for the reason WORKSPACE_ROUTE_COUNT is one (core/workspace.h): a switch over
 * the kinds must not have to name a sentinel.
 */
#define MOUNT_KIND_COUNT (MOUNT_CUSTOM + 1)

/**
 * Behavioral attributes for a mount kind.
 *
 * The kind names *what the storage label is*; the spec carries *what the label
 * implies*. Single source of truth for the label string, for the noun a screen
 * calls the root by, and for the per-kind invariants every consumer ultimately
 * asks for: "is resolution profile-keyed?" and "do files of this kind carry
 * ownership metadata?". Adding a fourth kind is one row in the internal SPECS
 * table; consumers read attributes directly without growing a switch.
 *
 * Stable storage: SPECS rows live in static data, so the pointers returned by
 * `mount_spec_for_kind` and `mount_spec_for_path` are valid for the process
 * lifetime. Callers borrow.
 */
typedef struct mount_spec {
    const char *label;            /* Storage-label string ("home", "root", "custom") */
    const char *noun;             /* The root's word for a screen — a complete noun
                                   * phrase; a per_profile root takes " of profile
                                   * '<name>'" after it (mount_root_describe) */
    bool per_profile;             /* True iff resolution is profile-keyed (CUSTOM) */
    bool tracks_ownership;        /* True iff files of this kind carry ownership metadata */
} mount_spec_t;

/**
 * Resolve a mount kind to its spec.
 *
 * Returns NULL when `kind` falls outside the known range (e.g., a cast from an
 * unrelated integer). Otherwise returns a borrowed pointer into the static SPECS
 * table; valid for the process lifetime.
 */
const mount_spec_t *mount_spec_for_kind(mount_kind_t kind);

/**
 * Resolve a storage path to its kind's spec by reading the leading label. Returns
 * NULL when `storage_path` is NULL or does not begin with a known label; otherwise
 * the borrowed spec for the matching kind. No tail validation — callers needing
 * full validation use mount_validate_storage.
 *
 * This is also the content gate every walk over a profile tree asks of its own
 * walk root: a managed path stands under a label, so a blob at the branch root,
 * or beneath a tree no label names, is the branch's own machinery — dotta's files
 * (.dottaignore, .bootstrap, .dotta/) and whatever else a hand or a tool left
 * beside them. Nothing else distinguishes them, and nothing needs to: a branch
 * may hold what it likes next to the labels, and no walk of content sees it or
 * refuses it. Readers: the view's claim routine (core/manifest.c), the file listing
 * and the branch statistics (core/profiles.c), the refspec completion
 * (cmds/completion.c). cmds/export.c asks the neighbouring question of a top-level
 * entry's bare name and spells it there — a label as a name rather than as a
 * prefix, which this cannot answer (it requires the '/').
 */
const mount_spec_t *mount_spec_for_path(const char *storage_path);

/**
 * Validate a storage path's syntactic shape.
 *
 * Checks:
 *  - Non-empty
 *  - Starts with "home/", "root/", or "custom/"
 *  - Not absolute (no leading '/')
 *  - No "..", ".", or empty component (path traversal)
 *  - No "//" (consecutive slashes)
 *  - No trailing slash (must reference a file, not a directory prefix)
 *
 * Pure rule check — no filesystem access, no arena, no state.
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL when valid
 */
error_t *mount_validate_storage(const char *storage_path);

/**
 * Validate a user-provided deployment target (the `--target` argument).
 *
 * The binders resolve first (path_input_normalize: tilde, relative, `.`, `..`),
 * so the absolute path the row stores is what reaches this check; the syntactic
 * rules below are the boundary's own and hold for a caller that did not (the
 * interactive save's validate, on text a resolve refused).
 *
 * Checks:
 *  - Absolute path (starts with '/')
 *  - No "..", ".", or empty component
 *  - No "//" (consecutive slashes)
 *  - No trailing slash
 *  - Resolves via realpath() and refers to an existing directory
 *  - Not the filesystem root '/', under any spelling that reaches it
 *
 * Filesystem access is required for the existence + directory checks.
 *
 * @param target Deployment target to validate (must not be NULL)
 * @return Error or NULL when valid
 */
error_t *mount_validate_target(const char *target);

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
 * a symlink standing at either (a target is validated through realpath, so a
 * link there is the directory it reaches). One that does not stand — a stale
 * row, its directory gone — is named by its spelling, and a differing one is a
 * move. One of the two places identity is read where a spelling is made (the
 * other is the normalizer's working directory, infra/path.h); the two CLI binders
 * say at NORMAL which spelling they kept (cmds/profile.c, cmds/add.c). The
 * interactive save says nothing: its screen is built once, so the spelling it
 * discarded is the one still shown (cmds/interactive.c).
 *
 * Readers: add's pre-flight, profile enable's retarget arm, the interactive save's
 * classify.
 */
bool mount_same_target(const char *a, const char *b);

/**
 * Return the mount-relative path: a pointer past the storage label.
 *
 * The subject every user-authored pattern is evaluated against. A pattern — in
 * `.dottaignore`, `[ignore] patterns`, `--exclude`, `auto_encrypt` — is matched
 * against the path relative to its mount root, what a `.gitignore` at `~`, at
 * `/` or at the deployment target would see: `home/.ssh/id_rsa` is matched as
 * `.ssh/id_rsa`, `root/etc/hosts` as `etc/hosts`. Labels are dotta's, never the
 * pattern's, and nothing above the mount root takes part. Paths are resolved
 * through the table; patterns are not.
 *
 * Zero allocation; the returned pointer aliases `storage_path` and shares its
 * lifetime. Returns `storage_path` unchanged when no label matches (or NULL when
 * the input is NULL).
 *
 * @param storage_path Storage path (may be NULL)
 * @return Pointer past the label, or `storage_path` unchanged
 */
const char *mount_strip_label(const char *storage_path);

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
 *   absolute, folded, no trailing slash (mount_validate_target) — and the key
 *   of every custom/ path beneath it. NULL or empty contributes no mount, and
 *   neither does a relative spelling or "/": the entry is dropped at build time,
 *   and the profile is bound nowhere in that table. Those two are the whole of
 *   the build's question (the table's paragraph above).
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
 * A mount with no profile is refused (ERR_INVALID_ARG): a binding is a profile's,
 * and the invariant is established here so the readers need no per-read check
 * (mount_t above). A mount whose target is NULL, empty, relative or "/" contributes
 * nothing and is dropped: the first two name no target, and the last two are
 * spellings the table cannot hold as a root — "/" ends in its own separator, so
 * the join would double it, and the sentinel already stands there — which no
 * binder writes and a hand-edited row can. Dropped and not refused because the
 * profile is then merely bound nowhere, which the view records (core/manifest.h
 * manifest_unbound) and a re-bind repairs, where a refusal would fail the command
 * that repairs it.
 *
 * Lifetime:
 *   - Output is allocated entirely from `arena`, every string included: the table
 *     borrows nothing from `mounts`, so it is a value for the arena's lifetime
 *     — readable after the rows it was built from have moved.
 *   - The home is copied into the arena at build time, immune to later setenv
 *     mutations.
 *
 * Errors:
 *   - ERR_INVALID_ARG when a mount names no profile.
 *   - ERR_MEMORY on arena allocation failure.
 *
 * One production reader: core/manifest.h's manifest_mount_table, which shapes
 * the state's rows — and a command's own binding, where the run brought one —
 * into the array. Every verb reads the asker's own entries, so a table holding
 * one binding would answer its profile as the whole table does; the one derivation
 * is kept because the rows a command's table is built from are the rows the view
 * it later joins by is built from (cmds/add.c).
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
 * the more specific statement (`~/.rc` under a binding at $HOME is `custom/.rc`);
 * between HOME and `/` at one directory the portable name wins (a HOME of "/"
 * yields to the sentinel, so `/etc/x` is `root/etc/x` — `home/` there would name
 * the whole filesystem on every other machine). A NULL `profile` names through
 * HOME and `/` alone: a profile with no binding on this machine, or no profile
 * at all.
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
 * The root of `profile` standing exactly at `location`, or NULL when none does.
 *
 * By the root's one spelling: exact equality is the whole test, a key being a
 * string of the rows' own (the table's paragraph above).
 *
 * A root met from above is entered unlisted and its children are named from
 * `->label`; a symlink standing at one is skipped by a walk and followed by the
 * argument that names it (cmds/add.c, find -H's rule); a claim the climb would
 * author at one is not authored (core/metadata.c). Asked once per directory entry
 * and once per chain rung. Never fails, allocates nothing; `table` and `location`
 * must not be NULL, `profile` may be — a NULL asker meets the shared roots (HOME,
 * `/`) alone, so the answer is never a per_profile spec.
 *
 * Readers: the namer's ascent, which asks it at every rung rather than once per
 * argument (core/manifest.c manifest_ascend); the climb's root guard
 * (core/metadata.c capture_ancestor), add's two root refusals — the argument
 * arm and the already-walked arm (cmds/add.c), `ignore --test`'s root line
 * (cmds/ignore.c), the claim search's root refusal (core/profiles.c
 * profile_claim_name) and revert's, asked directly where its own search answered
 * nothing at the location (cmds/revert.c).
 */
const mount_spec_t *mount_root(
    const mount_table_t *table,
    const char *profile,
    const char *location
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
 * `root` is the spec mount_root answered and must not be NULL — that is the whole
 * precondition, and the callers reach it two ways. Most have just had mount_name
 * answer NULL for the same table, asker and location — asked directly, or as
 * the last rung of the namer's ascent (core/manifest.c manifest_ascend), which
 * is the only way that one answers NULL — the same find over the same data, an
 * invariant rather than a hope. A caller whose own search already answered nothing
 * at the location asks mount_root directly and reads its answer (cmds/revert.c),
 * which establishes the same thing. `profile` is read only for a per_profile
 * root, and a per_profile root can only have been found by the profile that owns
 * it, so it is non-NULL exactly when it is read.
 *
 * Returns `buf`, so the noun reaches the message it belongs to as a value rather
 * than through a statement of its own: five sites print this sentence and would
 * otherwise spell it five ways — the message that a location has no name is the
 * same message whether a pattern, an argument, a search or a revert asked.
 *
 * Truncates rather than fails: a screen noun, not a key.
 */
const char *mount_root_describe(
    const mount_spec_t *root,
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
