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
 * per binding — each by the spelling its binder typed and by the physical spelling
 * realpath gives it. Built at the boundary where the binding source is in scope
 * (CLI options, state row cache), then consulted many times; a value — the topology
 * at the instant it was built — for the arena's lifetime.
 *
 * A location — where a claim stands on this machine: the key the view's rows,
 * the record and every screen share — is the physical spelling as far as the
 * table knows its roots. A mount is known by the spelling its binder typed (HOME
 * as the identity spells it), read through every enclosing alias the table holds,
 * and by what it reaches as realpath spells it; both views spell a location from
 * the physical, whichever spelling reached them. A binding realpath cannot answer
 * — its directory gone since it was bound — is known by that one spelling, which
 * is as far as the table can say it reaches and is the very location a claim
 * beneath it resolves to, so name and resolve place one location there too. So
 * one file has one location for every alias a binder declared — a root's two
 * spellings, a root beneath another root's alias, a claim beneath a root's alias
 * — and a root is a root under any of them. A tail is Git's and is joined as
 * written: a link
 * inside one that no binding names is a leaf of its own, as `~/.config ->
 * ~/dotfiles/config` must stay, and two claims through and around it are two
 * claims. A bind mount or a firmlink is two physicals for one directory: the
 * binders' compare (mount_same_target) reads the inode, this table the spelling.
 *
 * The root directory is spelled "" in the table — the one spelling that joins a
 * tail with one slash and encloses every absolute path at depth zero: the
 * sentinel's, and HOME's when HOME is "/" (a container's bare uid) or reaches
 * it through a link.
 *
 * One table, two readings
 * -----------------------
 * The machine's — where a spelling stands (mount_locate) and where a claim stands
 * (mount_resolve) — reads every entry, whoever asks: an alias is a spelling of
 * a directory for everyone, and a claim beneath another profile's declared link
 * keys with that link's own claims. The namespace's — what a profile would call
 * a location (mount_name) and whether a location is one of its roots (mount_root)
 * — reads the asker's own entries alone: its target if it is bound, HOME, `/`,
 * and no other profile's target. That is why the asker is a parameter and not a
 * table of its own: locate must see every binding, and name must see one.
 *
 * A namespace is one profile's view over the table. N profiles may claim one
 * location under N names; the view layers them by precedence (core/manifest),
 * and within one profile the view keeps one. Nothing is exclusive: a binding
 * says where a profile's names resolve, not who owns the files there.
 *
 * Four questions over the same data:
 *   - Where a spelling stands (filesystem -> location): mount_locate, the
 *     physical spelling as far as the table knows its roots — asked once per
 *     argument and once per directory a walk enters, never per child, and no
 *     other question's first step.
 *   - What a profile would call a location it holds no claim at (location ->
 *     storage): mount_name, beneath the deepest of that profile's own roots;
 *     nothing at a root itself. The fuller question — a claim of the profile
 *     standing at or above the location, and only then this — is core/manifest.h's
 *     manifest_name, whose last rung this is.
 *   - Whether a location is one of a profile's roots: mount_root, the walkers'
 *     and the climb's question, and the one place either spelling of a root
 *     answers.
 *   - Where a profile's claim stands (profile + storage -> filesystem):
 *     mount_resolve. A name is composed beneath a root's physical alone, so
 *     resolving one places it back at the very location it was composed from.
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
 * The kinds' arity, for a walk over the labels (cmds/export.c) and for an array
 * with one slot per kind. A macro, not an enumerator, for the reason
 * WORKSPACE_ROUTE_COUNT is one (core/workspace.h): a switch over the kinds must
 * not have to name a sentinel.
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
 * The table keys a location by the physical spelling, so two spellings of one
 * directory classify alike and key alike; the binders ask the same of a target
 * typed against the row's, so an alias of the row's own directory is never written
 * as a move — the row keeps the spelling its binder typed, the one the screens
 * print. A move re-keys every record under the profile — the relocation read
 * (core/workspace) meets one file under two keys and releases the old — and one
 * that changes only the row's spelling buys that churn for nothing. A spelling
 * that stands is named by its directory: the two are one when they have one device
 * and inode, through a symlink standing at either (a target is validated through
 * realpath, so a link there is the directory it reaches). One that does not stand
 * — a stale row, its directory gone — is named by its spelling, and a differing
 * one is a move.
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
 * - target: Absolute filesystem path with no trailing slash. NULL or empty
 *   contributes no mount; the entry is dropped at build time.
 */
typedef struct {
    const char *profile;
    const char *target;
} mount_t;

/**
 * Build a mount table from a flat array of mounts.
 *
 * Each mount is known by two spellings — its binder's, read through every enclosing
 * alias the table holds, and the physical, what it reaches as realpath spells
 * it (the settled spelling itself when realpath agrees, or cannot answer) — so
 * a path typed through either classifies under it, and the location either view
 * spells is the physical: one key per file for every alias a binder declared
 * (the "Mount table" paragraph above).
 *
 * The table is augmented internally with:
 *   - A HOME mount whose target is the invoker's home (sys/identity), in both
 *     spellings, so a symlinked HOME (macOS's /tmp -> /private/tmp) is one root
 *     under either without leaking a separate row into the table.
 *   - A ROOT mount whose target is the empty string (universal fallback for
 *     absolute paths that match no other mount).
 *
 * A mount with no profile is refused (ERR_INVALID_ARG): a binding is a profile's,
 * and the invariant is established here so the readers need no per-read check
 * (mount_t above). Mounts with NULL or empty `target` contribute nothing — they
 * are filtered at build time. (The previous binding-table architecture recorded
 * such entries to distinguish "profile not in table" from "profile in table but
 * no target on this machine"; both cases were indistinguishable at every call
 * site, so the entries were dead.)
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
 * Where a filesystem spelling stands on this machine: its location.
 *
 * The physical spelling as far as the table knows its roots. Every declared alias
 * above the final component is read through what it reaches, the deepest first,
 * again until none does; and a spelling that is a root's own — as its binder
 * typed it, or that spelling read through the aliases above it — is the directory
 * the binding names, whoever asks: `~/jail/link` where q is bound through the
 * link is q's target, and HOME typed as the identity spells it is HOME's physical
 * however many links stand above it (`/tmp -> /private/tmp`). A spelling through
 * a link no binding names is left as written: a tail is Git's.
 *
 * Pure string work over the table — no stat, no realpath — so the spelling need
 * not exist (show, revert, remove, a filter for a path not yet deployed), and
 * it is asked once per argument and once per directory a walk enters, never per
 * child: a child joined beneath a location is a location, the walkers' rule,
 * and a directory that is a binder's own spelling is the one join that is not —
 * read through here, so the walk goes on inside it under the physical. Every
 * location the table produces — a resolve's, a row's, a child joined beneath
 * one — is its own answer, which is what makes a location a key the resolver's
 * answer and the view's rows share by strcmp. The one exception is stated here,
 * not hidden: a claim of the very link a binding is declared through (a stranger's
 * `home/jail/link`) stands at the link (mount_resolve), and that spelling, located,
 * is the binding's directory — the row is reached beneath its parent and by its
 * name, never by its own spelling, and a walk that meets the link offers it as
 * the leaf it is rather than asking here.
 *
 * `fs_path` is absolute and lexically normalized (path_input_normalize); the
 * fold is established there, not re-checked here. The answer is the arena's, or
 * the table's own when the spelling is a root's — both outlive the call, and
 * every caller locates through a table its own arena built.
 *
 * Readers: the resolver's filesystem arm (infra/path path_input_resolve), the
 * key an argument is matched by; add's argument arm and every directory its walk
 * descends into (cmds/add.c); `ignore --test`'s filesystem arm (cmds/ignore.c).
 * The namer does not locate — its input is a location, and this is what makes one.
 *
 * @param table        Mount table (must not be NULL)
 * @param fs_path      Absolute, normalized filesystem spelling (must not be NULL)
 * @param arena        Arena that owns `*out_location`
 * @param out_location Arena-borrowed location (must not be NULL; NULL after an
 *                     error)
 * @return Error or NULL on success
 */
error_t *mount_locate(
    const mount_table_t *table,
    const char *fs_path,
    arena_t *arena,
    const char **out_location
);

/**
 * What `profile` would call a location it holds no claim at.
 *
 * "<label>/<tail>" beneath the deepest of the profile's own roots — its target,
 * HOME, `/` — or NULL when the location *is* that root: a root has no canonical
 * name, and the tree standing there is its label's. Another profile's target is
 * invisible here (the "One table, two readings" paragraph above). At a tie —
 * two of the profile's own roots at one directory — a binding wins, because it
 * is the
 * more specific statement (`~/.rc` under a binding at $HOME is `custom/.rc`);
 * between HOME and `/` at one directory the portable name wins (a HOME of "/"
 * yields to the sentinel, so `/etc/x` is `root/etc/x` — `home/` there would name
 * the whole filesystem on every other machine). A NULL `profile` names through
 * HOME and `/` alone: a profile with no binding on this machine, or no profile
 * at all.
 *
 * `location` is a location — mount_locate's answer — or the one spelling that
 * is not: one whose *last component* is a declared alias's own, which is what a
 * walk's join at a leaf and mount_resolve's answer at such a claim both produce.
 * Nothing above the last component is ever left unresolved, so mount_root's
 * either-spelling test is exact equality. Nothing is respelled here: locate is
 * asked once per argument and once per directory a walk enters, and the walkers
 * join.
 *
 * A name is composed beneath a root's *physical* — the last component's spelling
 * can only answer "the root itself", which has no name — so mount_resolve places
 * an answer of this one back at the very location it was composed from.
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
 * add's argument arm and its walk (cmds/add.c), and the interim resolver `remove`
 * still shares (infra/path.h path_input_classify). `ignore --test` was one until
 * its subject became the whole ascent's (core/manifest.h manifest_name), and
 * show, list and revert until their claim was found where it stands
 * (core/profiles.h profile_claim_name); add's two are what C3 takes.
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
 * By either spelling — the physical, or the binder's own — because the two
 * questions that reach it hand over a spelling locate would have read through:
 * a walk joins `<parent location>/<name>` for a leaf without locating, and
 * mount_resolve answers a claim of a declared alias's own spelling with that
 * spelling (its own stated exception). Both leave at most the last component
 * unresolved, so exact equality is the whole test. An argument is located before
 * it gets here, and a located root's spelling is its physical.
 *
 * A root met from above is entered unlisted and its children are named from
 * `->label`; a symlink standing at one is skipped; a claim the climb would author
 * at one is not authored (core/metadata.c). Asked once per directory entry and
 * once per chain rung. Never fails, allocates nothing; `table` and `location`
 * must not be NULL, `profile` may be — a NULL asker meets the shared roots (HOME,
 * `/`) alone, so the answer is never a per_profile spec.
 *
 * Readers: the namer's ascent, which asks it at every rung rather than once per
 * argument — the location itself included, where mount_resolve's exception can
 * hand it an alias's own spelling (core/manifest.c manifest_ascend); the climb's
 * root guard (core/metadata.c capture_ancestor), add's argument-arm refusal
 * (cmds/add.c), `ignore --test`'s root line (cmds/ignore.c) and the claim search's
 * root refusal (core/profiles.c profile_claim_name).
 */
const mount_spec_t *mount_root(
    const mount_table_t *table,
    const char *profile,
    const char *location
);

/* The longest sentence mount_root_describe renders: "the deployment target" (20),
 * " of profile '" (13), a profile name (a branch name — 255 bytes at git's limit),
 * the closing quote and the terminator. */
#define MOUNT_NOUN_MAX 320

/**
 * A root's noun for a screen, rendered into `buf` and returned: "your home
 * directory", "the filesystem root", "the deployment target of profile 'web'".
 *
 * `root` is the spec mount_root answered and must not be NULL; the caller has
 * just had mount_name answer NULL for the same table, asker and location — asked
 * directly, or as the last rung of the namer's ascent (core/manifest.c
 * manifest_ascend), which is the only way that one answers NULL — and that is
 * the same find over the same data, an invariant rather than a hope. `profile`
 * is read only for a per_profile root, and a per_profile root can only have been
 * found by the profile that owns it, so it is non-NULL exactly when it is read.
 *
 * Returns `buf`, so the noun reaches the message it belongs to as a value rather
 * than through a statement of its own: three sites print this sentence and would
 * otherwise spell it three ways — the message that a location has no name is
 * the same message whether a pattern, an argument or a search asked.
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
 * The location is the physical spelling as far as the table knows: the mount's
 * physical, "/", the tail, and a declared alias inside the tail — a target some
 * profile is bound at through a link inside this mount — read through what it
 * reaches, so a claim captured through that link keys with the target's own claims.
 * A claim at the alias's own spelling is the link standing there, and stands as
 * joined.
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
