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
 * each established where it is made: the sentinel's is the literal "/", HOME's
 * is the identity's (sys/identity, normalized at identity_init), and a row's
 * target is normalized and validated where it is written (the binders,
 * mount_validate_target) over a column that holds no other shape (core/state.c:
 * a target no binder would write is refused where a hand makes the edit). So
 * the build meets only spellings that are keys, keeps each as it stands, and
 * refuses any other as a caller's bug (mount_table_build). A row bound nowhere
 * holds NULL, which contributes no mount; the repair is a re-bind.
 *
 * So a root is a path wherever it is read — printed, compared to an argument,
 * measured against a rung. The root directory is the one root that *is* its own
 * separator, and the table's two string verbs read it one byte shorter: "" is
 * the prefix that joins a tail with one slash and encloses every absolute path
 * at depth zero, and it is where the sentinel, a HOME of "/" (a container's bare
 * uid) and a binding whose target is "/" (a container's own root) all stand.
 * That reading is made in one place and nowhere published (mount.c join_prefix).
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
 * Four questions over two searches. Three answer a root of the asker's — the
 * table's own, lent (mount_root_t) — and the fourth a string the table composed:
 *   - Which root encloses a location, and what lies past it: mount_root_above,
 *     the search itself, asked once per name by the view's ascent. A name is
 *     what that root's label and that tail spell, and the ascent spells it there
 *     (core/manifest.c manifest_ascend): the table hands out what it found and
 *     composes nothing, one reader being no reason to own the sentence.
 *   - Which root stands exactly at a location, and whose: mount_root_at, the
 *     same search with nothing past the root — the climb's question and every
 *     refusal that names a place.
 *   - Where the asker's root of a label stands: mount_root_of, by label rather
 *     than by place — the view's contribution and add's receipt.
 *   - Where a profile's claim stands (profile + storage -> filesystem):
 *     mount_resolve — that second find, then the join. A name is composed beneath
 *     a root, so resolving one places it back at the very location it was composed
 *     from. This verb composes where the ascent's does not, because its join
 *     has many readers and the name's has one.
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
 *   is a profile's: a root no profile bound is a root of every namespace (every
 *   verb reads a NULL profile as "the shared roots — HOME and `/`"), which is
 *   the machine-wide name this module does not produce. mount_table_build refuses
 *   one.
 * - target: where the profile's custom/ tree stands, as its binder wrote it —
 *   absolute and folded (sys/filesystem.h fs_is_folded), "/" included, which
 *   the table keeps as it stands — and the key of every custom/ path beneath
 *   it. NULL or empty contributes no mount: the profile is bound nowhere in that
 *   table. Any other string is refused at the build (mount_table_build).
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
 *   - A ROOT mount at "/" (the universal fallback: every absolute path stands
 *     under it, at depth zero, so no other root is owed a fallback case).
 *
 * A mount with no profile, or with a target that is not absolute and folded, is
 * refused (ERR_INVALID_ARG): a binding is a profile's, and a root is a spelling
 * that is a key. Both invariants are established here so the readers need no
 * per-read check (mount_t above), and both hold of every input by construction
 * — the store's column for a row (core/state.c), mount_validate_target for a
 * command's own binding. A target of "/" is a root like any other and takes the
 * tie from the sentinel: every path of that profile outside a deeper root is
 * custom/. A NULL or empty target contributes nothing: the profile is bound
 * nowhere, which the view records (core/manifest.h manifest_unbound) and a re-bind
 * repairs. A store a hand still got a malformed row into — its constraints switched
 * off, or its marker bumped without the table — fails every command that builds
 * the view but one: `profile disable`, whose receipt's view is built tolerantly
 * on purpose (cmds/profile.c), which is the way out, then a re-bind.
 *
 * One binding per profile is the input's shape and not a rule refused here: both
 * production readers hand in one — the state's rows are keyed by name
 * (core/state.c) and manifest_mount_table skips the row a command's own binding
 * stands for — and a profile handed two would have two custom/ roots, of which
 * every verb below finds whichever the array holds first. A caller building its
 * own array owes the same.
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
 * One of the asker's roots, as the table holds it.
 *
 * `location` is where the root stands, as a path: every reader prints it, compares
 * it to an argument the normalizer spelled, or measures a rung against it — and
 * the one root that is its own separator, "/", is spelled so here like any other
 * (the table's paragraph above). `profile` is the whole of whose a root is —
 * the one that bound it: the build refuses a binding that names none (mount_t),
 * so NULL reads as "the machine's own word" — HOME, `/` — and never as "unknown".
 * A name composed beneath a root a profile bound is this machine's arrangement,
 * which the next machine re-binds where it likes; one composed beneath a root
 * the machine placed is portable and re-mounts by the word. Every policy asking
 * "may the user have chosen this place?" reads this field and no label. Not the
 * *file* ownership every claim carries beside its group (core/manifest.h
 * manifest_row_t, core/metadata.h) — that one is a system identity, and this
 * one a profile name.
 *
 * And not the label's own rule, of which this field is the consequence and never
 * the cause: the build binds custom/ entries and nothing else (mount_table_build),
 * so a reader asking whether a *namespace* is anyone's to re-target asks the
 * label and would learn nothing here that it did not already hand in. A reader
 * asking whether *this place* is the user's holds a root because it needs the
 * place, and asks here — which is every reader below.
 *
 * The table's own row, lent: every find answers a pointer into the table, NULL
 * for absence as every lookup in the tree answers it (core/manifest.h
 * manifest_lookup, mount_resolve below, hashmap_get), and every string is the
 * arena the table was built in or a literal. A reader that outlives the table
 * copies what it keeps, as a reader of a view's row does. Two roots can stand
 * at one directory — a profile bound at HOME's own spelling — and they are two
 * rows with two labels and two binders, which is why no reader compares the
 * pointers.
 */
typedef struct {
    label_t label;          /* The namespace mounted here */
    const char *location;   /* Where it stands, as a path */
    const char *profile;    /* The profile that bound it; NULL for HOME and / */
} mount_root_t;

/**
 * The deepest root of `profile` at or above `location`, and the tail past it.
 *
 * At or above, the reflexive case being the one mount_root_at asks for alone:
 * the tail says which, "" where the location *is* the root.
 *
 * The one search, handed out whole. A namespace is one profile's: the shared
 * roots (HOME, the sentinel, both unbound) and its own binding; another profile's
 * target is skipped before it can win (the "One table, one reading" paragraph
 * above). Tightest container wins, and a root encloses the location iff it is a
 * prefix of it on a component boundary, the root itself included — `location`
 * is a key, so the test is a string's and nothing is respelled or read through.
 *
 * At an equal depth two of the asker's own roots stand at one directory, and
 * the more specific statement takes it — a binding over the shared roots, and
 * the sentinel over a HOME that is "/": `~/.rc` under a binding at $HOME is under
 * the binding, and `/etc/x` on a machine whose HOME is "/" (a container's bare
 * uid) is under the sentinel, the reading that means the same directory on every
 * other machine. Three roots can stand at "/": the sentinel always, HOME when
 * it is "/", and a binding whose target is "/". The binding takes both ties —
 * every path of that profile outside a deeper root is custom/, which is what
 * binding a profile at the root means — and between HOME and the sentinel the
 * portable name wins. One profile has one binding (mount_table_build).
 *
 * `*out_tail` aliases `location`: "" when the location *is* the root, the tail
 * past it otherwise. NULL when no root encloses the location — a malformed table,
 * or a location that is not absolute; the sentinel encloses every absolute path
 * at depth zero, so a well-formed table always answers, and `*out_tail` is then
 * untouched. Never fails, allocates nothing.
 *
 * Reader: the view's ascent, once per name (core/manifest.c manifest_ascend),
 * which reads all three of the answer — the root ends the climb, its `location`
 * is the rung it ends at, and its label and the tail compose the name where no
 * claim above gave one (infra/label.h label_compose). Nothing else needs the
 * tail: the two questions a command asks are below.
 */
const mount_root_t *mount_root_above(
    const mount_table_t *table,
    const char *profile,
    const char *location,
    const char **out_tail
);

/**
 * Does a root of `profile` stand exactly at `location`, and which?
 *
 * The search above with nothing past the root: by its one spelling, exact equality
 * being the whole test, a key being a string of the rows' own (the table's
 * paragraph above). The root when one stands there, NULL when none does — so
 * the tie is that search's, and a NULL asker, meeting the shared roots alone,
 * is never answered a binding.
 *
 * A root met from above is entered unlisted and its children are named from its
 * label; a symlink standing at one is skipped by a walk and followed by the
 * argument that names it (cmds/add.c, find -H's rule); a claim the climb would
 * author at one is not authored (core/metadata.c). Asked once per chain rung
 * and once per argument that names a place. Never fails, allocates nothing; `table`
 * and `location` must not be NULL, `profile` may be.
 *
 * Readers: the climb's root guard (core/metadata.c capture_ancestor), the claim
 * search's refusal (core/profiles.c profile_claim_name), `ignore --test`'s root
 * line (cmds/ignore.c), add's two root arms — the argument's, whose root-link
 * rule reads its binder, and the already-walked arm (cmds/add.c) — and revert's,
 * asked where its own search answered nothing at the location (cmds/revert.c).
 * Every one of them has an asker to name. A reader holding a view and nobody to
 * name asks core/manifest.h manifest_root_at, which asks this once per profile
 * the view holds: a NULL asker here meets the shared roots alone, so it would
 * answer HOME for a location a profile bound and is no stand-in for the view's
 * own question.
 */
const mount_root_t *mount_root_at(
    const mount_table_t *table,
    const char *profile,
    const char *location
);

/**
 * Where the asker's root of `label` stands, and whose it is.
 *
 * The inverse of mount_root_at: that one asks which root stands at a location,
 * this one where a root stands. NULL when the asker has none here — a custom/
 * nobody bound, a NULL asker naming one; HOME and the sentinel are every asker's
 * and always answer.
 *
 * The row, not the tie: a HOME that is also a binding is one directory under
 * two labels, and each label answers its own row here, where the enclosing search
 * and mount_root_at give the binding the tie. Never fails, allocates nothing.
 *
 * Readers: add's receipt, which names the place the custom/ names it captured
 * went under (cmds/add.c report_labels).
 */
const mount_root_t *mount_root_of(
    const mount_table_t *table,
    const char *profile,
    label_t label
);

/* The longest sentence mount_root_describe renders: "the deployment target" (21),
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
 * Rendered from the root itself, so the profile named is the one the build stamped
 * and no caller can hand the wrong one; a bound root has one to name by that
 * same refusal of a nameless binding (mount_t). One switch under -Wswitch, the
 * one place a label's meaning on a screen is decided — and what a *label* names,
 * no root having been found for it, is no place at all and is said in the grammar's
 * own word (infra/path.h path_input_refuse_label).
 *
 * `root` is non-NULL, and every caller holds one a find answered: directly, or
 * through the namer, whose NULL is exactly mount_root_at's answer over the same
 * table, asker and location — the same find over the same data, an invariant
 * rather than a hope (core/manifest.h manifest_name). One caller holds two
 * structures that could disagree instead of one find, and says so rather than
 * dereferencing (cmds/add.c's already-walked arm).
 *
 * Returns `buf`, so the noun reaches the message it belongs to as a value rather
 * than through a statement of its own: every site that says a place has no name
 * would otherwise spell the noun its own way — and the message is the same one
 * whether a pattern, an argument, a search or a revert asked. Three sites say a
 * sentence of their own around it: `ignore --test` answers rather than refuses,
 * --test being a query, and add's two indict the argument ("cannot be added
 * itself", "which this command has already walked through"). The fourth sentence
 * — what a verb that acts on one path says of a location standing at a root —
 * is one fact with one producer, mount_root_refuse below, which renders this
 * noun into it.
 *
 * Truncates rather than fails: a screen noun, not a key, so it stands inside an
 * ERROR() argument. `size` is one byte at least — the switch's tail is written
 * before its arms, so an empty buffer is the one thing this cannot take; every
 * caller holds a MOUNT_NOUN_MAX or a PATH_MAX.
 */
const char *mount_root_describe(
    const mount_root_t *root,
    char *buf,
    size_t size
);

/**
 * The refusal a location standing at a root earns from a verb that acts on one path
 *
 *   '/home/me' is your home directory: name what is inside it
 *
 * One sentence for the four verbs that own it, because it is one fact: a root
 * is a place and never a name, so a verb that acts on one path has nothing to
 * act on at one. Why each asked differs — a claim search found nothing standing
 * there (core/profiles.c profile_claim_name), a commit held nothing
 * (cmds/revert.c), the enabled view has no row (cmds/show.c, cmds/list.c) — and
 * what is said is a fact of the root, said in the root's own words. A verb that
 * means a place and everything beneath it takes a root as the prefix it is and
 * refuses nothing (cmds/remove.c, cmds/export.c); add's two arms indict the
 * argument instead, a root that is a directory being a thing add can walk.
 *
 * Every byte comes from `root`: where it stands, and the noun of its rule
 * (mount_root_describe). No spelling is handed in because there is none to hand
 * — a location key is absolute and folded wherever one is made (infra/path.h
 * path_input_locate, mount_resolve's join), and a find answers by exact equality,
 * so the root's own `location` is the argument's spelling. `root` is non-NULL,
 * as mount_root_describe's is.
 *
 * The sibling for a *label* is infra/path.h path_input_refuse_label: that one
 * says a namespace is not a path in it, this one that a place is not a thing in
 * it. The remedy is the same because the mistake is.
 *
 * @param root The root the location stands at (must not be NULL)
 * @return The refusal; never NULL
 */
error_t *mount_root_refuse(const mount_root_t *root);

/**
 * Where a claim stands on this machine: a storage path through a profile's mount.
 *
 * Resolution table:
 *   home/X   -> $HOME/X                  (profile may be NULL)
 *   root/X   -> /X                       (profile may be NULL)
 *   custom/X -> <profile's target>/X     (profile must match a CUSTOM mount)
 *
 * The location is the root, one separator and the tail: the key of the claim,
 * and the one every producer of a key agrees on (the table's paragraph above).
 * A link anywhere in it is a component — a claim captured through one stands
 * where its spelling says, and so does a claim of the link itself.
 *
 * Absence is the find's own, handed on unchanged: mount_root_of answers no root
 * of the name's label for this asker, so the two have one producer and one reading
 * between them. `*out_location` is then NULL — the claim is `custom/` and the
 * profile has no target on this machine, a clone before the target is chosen, a
 * sync that pulled another machine's claims — which is how every lookup in the
 * tree answers an absence (manifest_lookup, state_peek_profile_target,
 * hashmap_get), and the callers read it as the fact it is: the manifest's claim
 * routine skips
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
