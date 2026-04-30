/**
 * mount.h - Storage labels and per-machine deployment mount table
 *
 * Storage-path namespace
 * ----------------------
 * Dotta encodes deployment locations into a portable namespace:
 *
 *   home/X   - X under $HOME (per-machine $HOME resolution)
 *   root/X   - /X (filesystem root; same on every machine)
 *   custom/X - X under a per-profile, per-machine deployment target
 *              (configured via `--target` at profile-enable time)
 *
 * The label (`home`, `root`, `custom`) names which mount kind a storage
 * path belongs to. Storage paths are stable across machines; the per-machine
 * filesystem location of a label is decided by the mount table below.
 *
 * Mount table
 * -----------
 * Per-machine topology that maps storage labels to filesystem paths and
 * back. Built once per command at the boundary where the binding source
 * is in scope (CLI options, state row cache), then consulted many times.
 *
 * Two views over the same data:
 *   - Forward (filesystem -> storage): mount_classify picks the
 *     longest-matching target (tightest container wins, same semantic
 *     as filesystem mount points or URL routers).
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
 * The kind names *what the storage label is*; the spec carries *what the
 * label implies*. Single source of truth for label/display strings and
 * for the per-kind invariants every consumer ultimately asks for:
 * "is resolution profile-keyed?" and "do files of this kind carry
 * ownership metadata?". Adding a fourth kind is one row in the internal
 * SPECS table; consumers read attributes directly without growing a
 * switch (Rule 2 — vocabulary is the dispatch).
 *
 * Stable storage: SPECS rows live in static data, so the pointers
 * returned by `mount_spec_for_kind` and `mount_spec_for_path` are
 * valid for the process lifetime. Callers borrow.
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
 * Returns NULL when `kind` falls outside the known range (e.g., a
 * cast from an unrelated integer). Otherwise returns a borrowed pointer
 * into the static SPECS table; valid for the process lifetime.
 */
const mount_spec_t *mount_spec_for_kind(mount_kind_t kind);

/**
 * Resolve a storage path to its kind's spec by reading the leading
 * label. Returns NULL when `storage_path` is NULL or does not begin
 * with a known label; otherwise the borrowed spec for the matching
 * kind. No tail validation — callers needing full validation use
 * mount_validate_storage.
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
 * Checks:
 *  - Absolute path (starts with '/')
 *  - Not the filesystem root '/' itself
 *  - No "..", ".", or empty component
 *  - No "//" (consecutive slashes)
 *  - No trailing slash
 *  - Resolves via realpath() and refers to an existing directory
 *
 * Filesystem access is required for the existence + directory checks.
 *
 * @param target Mount target to validate (must not be NULL)
 * @return Error or NULL when valid
 */
error_t *mount_validate_target(const char *target);

/**
 * Return a pointer past the storage label of `storage_path`.
 *
 * Strips leading "home/", "root/", or "custom/" so callers can match the
 * user-facing tail against patterns written without the storage label
 * (e.g. ".ssh/id_*"). Zero allocation; the returned pointer aliases
 * `storage_path` and shares its lifetime.
 *
 * Returns `storage_path` unchanged when no label matches (or when input
 * is NULL).
 *
 * @param storage_path Storage path (may be NULL)
 * @return Pointer past the label, or `storage_path` unchanged
 */
const char *mount_strip_label(const char *storage_path);

/**
 * Opaque mount-table handle. Built by `mount_table_build`; lifetime
 * tracks the arena passed at build time. There is no destructor —
 * arena_destroy reclaims everything.
 */
typedef struct mount_table mount_table_t;

/**
 * A single mount: profile <-> deployment-target pairing.
 *
 * POD value type passed by callers to `mount_table_build`. Both fields
 * are borrowed pointers; their lifetimes are the caller's responsibility
 * and must outlive the arena passed to `mount_table_build`.
 *
 * - profile: Profile name (NULL for callers that have only target
 *   strings, no profile names — e.g. one-shot internal scratch use).
 * - target: Absolute filesystem path with no trailing slash. NULL or
 *   empty contributes no mount; the entry is dropped at build time.
 */
typedef struct {
    const char *profile;
    const char *target;
} mount_t;

/**
 * Build a mount table from a flat array of mounts.
 *
 * Each mount in the table is a symlink-aware equivalence class:
 * internally it caches both the user-supplied target and its
 * realpath-canonical sibling (when distinct), so forward
 * classification matches a path against either surface form. Backward
 * resolution (mount_resolve) returns the raw target the user typed.
 *
 * The table is augmented internally with:
 *   - A HOME mount whose target is $HOME (captured from getenv at
 *     build time, expanded into its raw + canonical pair). Catches
 *     symlinks like macOS's /tmp -> /private/tmp on the classification
 *     side without leaking a separate row into the table.
 *   - A ROOT mount whose target is the empty string (universal
 *     fallback for absolute paths that match no other mount).
 *
 * Mounts with NULL or empty `target` contribute nothing — they are
 * filtered at build time. (The previous binding-table architecture
 * recorded such entries to distinguish "profile not in table" from
 * "profile in table but no target on this machine"; both cases were
 * indistinguishable at every call site, so the entries were dead.)
 *
 * Lifetime:
 *   - Output is allocated entirely from `arena`.
 *   - Borrowed string fields in `mounts` must outlive `arena`.
 *   - $HOME is captured into the arena at build time, immune to later
 *     setenv mutations.
 *
 * Errors:
 *   - ERR_FS  if HOME cannot be resolved (env unset and passwd lookup
 *             fails).
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
 * Outcome of mount_classify. Encodes "did the path land under a mount,
 * or did it equal a mount root exactly?" as data so callers don't catch
 * ERR_INVALID_ARG as control flow.
 *
 * TAIL — `*out_storage` is set to an arena-borrowed storage path
 *        ("home/X", "root/X", "custom/X") for the path's tail under
 *        the winning mount.
 * ROOT — `fs_path` exactly equals a mount target ($HOME, /, or a
 *        --target). No storage-path encoding exists for the mount
 *        root itself; `*out_storage` is NULL. `*out_kind` (if
 *        requested) still receives the matched kind. Walker callers
 *        treat this as "skip this entry, descendants appear separately."
 */
typedef enum {
    MOUNT_CLASSIFY_TAIL,
    MOUNT_CLASSIFY_ROOT,
} mount_classify_outcome_t;

/**
 * Classify an absolute filesystem path into a storage path.
 *
 * Picks the longest-matching mount target (tightest container wins).
 * Each entry contributes up to two surface forms (raw + realpath-
 * canonical); a path matching either form is considered to belong to
 * that mount. Ties on equal target length are broken by declaration
 * order (stable, earlier wins).
 *
 * The empty-target ROOT mount has length 0, so it always loses to any
 * non-empty match and serves as the universal fallback when no other
 * mount contains the path.
 *
 * Outcome contract:
 *   - MOUNT_CLASSIFY_TAIL: `*out_storage` is set to an arena-borrowed
 *     storage path. Lifetime tracks `arena`; callers do not free it.
 *   - MOUNT_CLASSIFY_ROOT: `fs_path` equals a mount target exactly;
 *     `*out_storage` is NULL. The matched spec (if `out_spec != NULL`)
 *     is still written so callers can decide on label vocabulary
 *     without re-classifying. Caller decides whether to treat this as
 *     an error or a skip.
 *   - ERR_INTERNAL when no entry matched (only possible on a malformed
 *     mount table — the ROOT sentinel always wins in well-formed tables).
 *   - ERR_MEMORY on arena allocation failure.
 *
 * @param table       Mount table (must not be NULL)
 * @param fs_path     Absolute path to classify (must not be NULL)
 * @param arena       Arena that owns `*out_storage` allocation when TAIL
 * @param outcome     Receives the classification outcome (must not be NULL)
 * @param out_storage Arena-borrowed storage path when TAIL; NULL when ROOT
 *                    (must not be NULL)
 * @param out_spec    Optional: receives a borrowed pointer to the winning
 *                    mount's spec (vocabulary attributes — label string,
 *                    tracks_ownership, per_profile). Populated in both
 *                    TAIL and ROOT outcomes. Pass NULL when only the
 *                    storage path is needed.
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
 * Outcome of mount_resolve. Encodes "did the (kind, profile) lookup find
 * a binding?" as data so callers don't pattern-match on a NULL pointer.
 *
 * BOUND   — `*out_fs` is set to an arena-borrowed filesystem path.
 * UNBOUND — the lookup hit a `custom/` profile that has no --target on
 *           this host (e.g., a clone before the user has configured a
 *           target). `*out_fs` is unspecified; callers must not read it.
 *           HOME and ROOT lookups never produce UNBOUND — those entries
 *           are unconditional in every well-formed mount table.
 */
typedef enum {
    MOUNT_RESOLVE_BOUND,
    MOUNT_RESOLVE_UNBOUND,
} mount_resolve_outcome_t;

/**
 * Convert a storage path to a filesystem path using a profile's mount.
 *
 * Resolution table:
 *   home/X   -> $HOME/X                  (profile may be NULL)
 *   root/X   -> /X                       (profile may be NULL)
 *   custom/X -> <profile's target>/X     (profile must match a CUSTOM mount)
 *
 * Outcome contract:
 *   - MOUNT_RESOLVE_BOUND: `*out_fs` is set to an arena-borrowed
 *     filesystem path. The pointer's lifetime tracks `arena`; callers
 *     do not free it.
 *   - MOUNT_RESOLVE_UNBOUND: `*out_fs` is unspecified. Callers branch on
 *     the outcome — silent skip in batch contexts (manifest tree-walks,
 *     state directory entry creation), display fallback in user-facing
 *     contexts (remove.c).
 *   - ERR_INTERNAL when `storage_path` lacks a known label (the input
 *     boundary is supposed to validate before reaching here; this guards
 *     against contract drift).
 *   - ERR_MEMORY on arena allocation failure.
 *
 * @param table        Mount table (must not be NULL)
 * @param profile      Owning profile (may be NULL for home/ and root/ paths)
 * @param storage_path Storage-format path (must not be NULL, validated)
 * @param arena        Arena that owns `*out_fs` allocation when BOUND
 * @param outcome      Receives the lookup outcome (must not be NULL)
 * @param out_fs       Arena-borrowed filesystem path when BOUND; unspecified
 *                     when UNBOUND. (must not be NULL)
 * @return Error or NULL on success
 */
error_t *mount_resolve(
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    arena_t *arena,
    mount_resolve_outcome_t *outcome,
    const char **out_fs
);

#endif /* DOTTA_MOUNT_H */
