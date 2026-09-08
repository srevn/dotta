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
 * Mount table
 * -----------
 * Per-machine topology that maps storage labels to filesystem paths and back.
 * Built at the boundary where the binding source is in scope (CLI options, state
 * row cache), then consulted many times; a value — the topology at the instant
 * it was built — for the arena's lifetime.
 *
 * A location — where a claim stands on this machine: the key the view's rows,
 * the record and every screen share — is the physical spelling as far as the
 * table knows its roots. A mount is known by the spelling its binder typed (HOME
 * as the identity spells it), read through every enclosing alias the table holds,
 * and by what it reaches as realpath spells it; both views spell a location from
 * the physical, whichever spelling reached them. So one file has one location
 * for every alias a binder declared — a root's two spellings, a root beneath
 * another root's alias, a claim beneath a root's alias — and a root is a root
 * under any of them. A tail is Git's and is joined as written: a link
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
 * Three questions over the same data:
 *   - Where a spelling stands (filesystem -> location): mount_locate, the
 *     physical spelling as far as the table knows its roots — asked once per
 *     argument, never per child, and the forward view's first step.
 *   - Forward (filesystem -> storage): mount_classify locates, then picks the
 *     longest-matching target (tightest container wins, same semantic as filesystem
 *     mount points or URL routers).
 *   - Backward (profile + storage -> filesystem): mount_resolve looks
 *     up the per-profile target.
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
 * Behavioral attributes for a mount kind.
 *
 * The kind names *what the storage label is*; the spec carries *what the label
 * implies*. Single source of truth for label/display strings and for the per-kind
 * invariants every consumer ultimately asks for: "is resolution profile-keyed?"
 * and "do files of this kind carry ownership metadata?". Adding a fourth kind
 * is one row in the internal SPECS table; consumers read attributes directly
 * without growing a switch.
 *
 * Stable storage: SPECS rows live in static data, so the pointers returned by
 * `mount_spec_for_kind` and `mount_spec_for_path` are valid for the process
 * lifetime. Callers borrow.
 */
typedef struct mount_spec {
    const char *label;            /* Storage-label string ("home", "root", "custom") */
    const char *display;          /* Human-readable display name */
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
 * Validate a user-provided mount target (the `--target` argument).
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
 * @param target Mount target to validate (must not be NULL)
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
 * A single mount: profile <-> deployment-target pairing.
 *
 * POD value type passed by callers to `mount_table_build`. Both fields are borrowed
 * for the call only — the table copies what it keeps.
 *
 * - profile: Profile name (NULL for callers that have only target strings, no
 *   profile names — e.g. one-shot internal scratch use).
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
 * it (the spelling itself when realpath agrees, or cannot answer) — so a path
 * typed through either classifies under it, and the location either view spells
 * is the physical: one key per file for every alias a binder declared (the "Mount
 * table" paragraph above).
 *
 * The table is augmented internally with:
 *   - A HOME mount whose target is the invoker's home (sys/identity), in both
 *     spellings, so a symlinked HOME (macOS's /tmp -> /private/tmp) is one root
 *     under either without leaking a separate row into the table.
 *   - A ROOT mount whose target is the empty string (universal fallback for
 *     absolute paths that match no other mount).
 *
 * Mounts with NULL or empty `target` contribute nothing — they are filtered at
 * build time. (The previous binding-table architecture recorded such entries to
 * distinguish "profile not in table" from "profile in table but no target on
 * this machine"; both cases were indistinguishable at every call site, so the
 * entries were dead.)
 *
 * Lifetime:
 *   - Output is allocated entirely from `arena`, every string included: the table
 *     borrows nothing from `mounts`, so it is a value for the arena's lifetime
 *     — readable after the rows it was built from have moved.
 *   - The home is copied into the arena at build time, immune to later setenv
 *     mutations.
 *
 * Errors:
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
 * it is asked once per argument, never per child: a child joined beneath a location
 * is a location, the walkers' rule. Every location the table produces — a
 * resolve's, a row's, a child joined beneath one — is its own answer, which is
 * what makes a location a key the resolver's answer and the view's rows share
 * by strcmp. The one exception is stated here, not hidden: a claim of the very
 * link a binding is declared through (a stranger's `home/jail/link`) stands at
 * the link (mount_resolve), and that spelling, located, is the binding's directory
 * — the row is reached beneath its parent and by its name, never by its own
 * spelling.
 *
 * `fs_path` is absolute and lexically normalized (path_input_normalize); the
 * fold is established there, not re-checked here. The answer is the arena's, or
 * the table's own when the spelling is a root's — both outlive the call, and
 * every caller locates through a table its own arena built.
 *
 * Readers: the resolver's filesystem arm (infra/path path_input_resolve), the
 * key an argument is matched by; mount_classify, whose first step this is.
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
 * Outcome of mount_classify. Encodes "did the path land under a mount, or did
 * it equal a mount root exactly?" as data so callers don't catch ERR_INVALID_ARG
 * as control flow.
 *
 * TAIL — `*out_storage` is set to an arena-borrowed storage path ("home/X",
 *        "root/X", "custom/X") for the path's tail under the winning mount.
 * ROOT — `fs_path` exactly equals a mount target ($HOME, /, or a --target). No
 *        storage-path encoding exists for the mount root itself; `*out_storage`
 *        is NULL. `*out_kind` (if requested) still receives the matched kind.
 *        Walker callers treat this as "skip this entry, descendants appear
 *        separately."
 */
typedef enum {
    MOUNT_CLASSIFY_TAIL,
    MOUNT_CLASSIFY_ROOT,
} mount_classify_outcome_t;

/**
 * Classify an absolute filesystem path into a storage path.
 *
 * The path is located first (mount_locate: every declared alias above its entry
 * resolved, a root's own spelling read as the directory the binding names — and
 * a located path is its own answer), and then the deepest mount enclosing the
 * location wins (tightest container). Ties at equal depth — two mounts at one
 * directory — are broken by declaration order (stable, earlier wins). The typed
 * spelling never leaves this call: a path typed physically, through the binder's
 * spelling, or through an enclosing root's alias classifies the same.
 *
 * The empty-target ROOT mount has length 0, so it always loses to any non-empty
 * match and serves as the universal fallback when no other mount contains the path.
 *
 * Outcome contract:
 *   - MOUNT_CLASSIFY_TAIL: `*out_storage` is set to an arena-borrowed storage
 *     path. Lifetime tracks `arena`; callers do not free it.
 *   - MOUNT_CLASSIFY_ROOT: `fs_path` equals a mount target exactly; `*out_storage`
 *     is NULL. The matched spec (if `out_spec != NULL`) is still written so callers
 *     can decide on label vocabulary without re-classifying. Caller decides whether
 *     to treat this as an error or a skip.
 *   - ERR_INTERNAL when no entry matched (only possible on a malformed mount
 *     table — the ROOT sentinel always wins in well-formed tables).
 *   - ERR_MEMORY on arena allocation failure.
 *
 * @param table       Mount table (must not be NULL)
 * @param fs_path     Absolute path to classify (must not be NULL)
 * @param arena       Arena that owns `*out_storage` allocation when TAIL
 * @param outcome     Receives the classification outcome (must not be NULL)
 * @param out_storage Arena-borrowed storage path when TAIL; NULL when ROOT (must
 *                    not be NULL)
 * @param out_spec    Optional: receives a borrowed pointer to the winning
 *                    mount's spec (vocabulary attributes — label string,
 *                    tracks_ownership, per_profile). Populated in both TAIL and
 *                    ROOT outcomes. Pass NULL when only the storage path is needed.
 * @return Error or NULL on success
 */
error_t *mount_classify(
    const mount_table_t *table,
    const char *fs_path,
    arena_t *arena,
    mount_classify_outcome_t *outcome,
    const char **out_storage,
    const mount_spec_t **out_spec
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
