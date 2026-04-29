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
 * The label (`home`, `root`, `custom`) names which mount class a storage
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
 * Mount classes — the three storage label namespaces.
 */
typedef enum {
    MOUNT_HOME,    /* home/...   -> $HOME/... */
    MOUNT_ROOT,    /* root/...   -> /... */
    MOUNT_CUSTOM,  /* custom/... -> per-profile deployment target */
} mount_kind_t;

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
 * Extract the mount kind from a storage path.
 *
 * Reads only the leading label; does not validate the rest of the path.
 * Returns true and writes `*out_kind` when the input is a storage path
 * (starts with "home/", "root/", or "custom/"). Returns false and leaves
 * `*out_kind` unmodified for NULL, empty, or non-storage input — callers
 * that previously paired `mount_is_storage_path` with `mount_kind_of` can
 * collapse to a single check.
 *
 * No silent default: a malformed input never silently lands as MOUNT_ROOT.
 *
 * @param storage_path Storage path (may be NULL)
 * @param out_kind     Mount kind for the leading label (must not be NULL)
 * @return true when storage_path is a storage path; false otherwise
 */
bool mount_kind_extract(const char *storage_path, mount_kind_t *out_kind);

/**
 * Return true when `path` syntactically begins with a known storage label.
 *
 * Pure string-prefix check; no allocation, no filesystem access. NULL and
 * empty inputs return false.
 *
 * Equivalent to `mount_kind_extract(path, &unused)`; kept as a separate
 * predicate for call sites that only need the boolean and not the kind.
 *
 * @param path Path to test (may be NULL)
 * @return true when `path` starts with "home/", "root/", or "custom/"
 */
bool mount_is_storage_path(const char *path);

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
 * The table is augmented internally with:
 *   - A HOME mount whose target is $HOME (raw form captured from
 *     getenv at build time).
 *   - A second HOME mount whose target is the realpath-canonical $HOME,
 *     when distinct from the raw form. Catches symlinks like macOS's
 *     /tmp -> /private/tmp on the classification side.
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
 * Classify an absolute filesystem path into a storage path.
 *
 * Picks the longest-matching mount target (tightest container wins).
 * Ties on equal target length are broken by declaration order
 * (stable, earlier wins). Returns ERR_INVALID_ARG when the path
 * exactly equals a mount target — there is no storage representation
 * for the mount root itself.
 *
 * The empty-target ROOT mount has length 0, so it always loses to any
 * non-empty match and serves as the universal fallback when no other
 * mount contains the path.
 *
 * @param table       Mount table (must not be NULL)
 * @param fs_path     Absolute path to classify (must not be NULL)
 * @param out_storage Allocated storage path on success (caller frees)
 * @param out_kind    Optional: receives the winning mount's kind
 * @return Error or NULL on success
 */
error_t *mount_classify(
    const mount_table_t *table,
    const char *fs_path,
    char **out_storage,
    mount_kind_t *out_kind
);

/**
 * Convert a storage path to a filesystem path using a profile's mount.
 *
 * Resolution table:
 *   home/X   -> $HOME/X                  (profile may be NULL)
 *   root/X   -> /X                       (profile may be NULL)
 *   custom/X -> <profile's target>/X     (profile must match a CUSTOM mount)
 *
 * Error semantics:
 *   - ERR_INVALID_ARG when `storage_path` is malformed (rejected by
 *     mount_validate_storage). Always propagate.
 *   - ERR_NOT_FOUND when `storage_path` starts with "custom/" but
 *     `profile` has no CUSTOM mount in the table (profile not enabled
 *     with --target on this machine, or a clone before the user has
 *     configured a target). Callers that resolve every storage entry
 *     against its source profile (manifest_build_callback,
 *     manifest_sync_diff, manifest_sync_directories) treat this as a
 *     silent skip — a profile without a target contributes nothing to
 *     the VWD on this host. Callers that resolve a single user-supplied
 *     path treat it as a hard error.
 *
 * @param table        Mount table (must not be NULL)
 * @param profile      Owning profile (may be NULL for home/ and root/ paths)
 * @param storage_path Storage-format path (must not be NULL, validated)
 * @param out_fs       Allocated filesystem path on success (caller frees)
 * @return Error or NULL on success
 */
error_t *mount_resolve(
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    char **out_fs
);

/**
 * Resolve flexible user input to a canonical storage path.
 *
 * Accepted input formats:
 *   1. Absolute paths:  /path/to/file
 *   2. Tilde paths:     ~/path/to/file
 *   3. Relative paths:  ./path, ../path, .dotfile, path/to/file
 *                       (resolved via the current working directory)
 *   4. Storage paths:   home/..., root/..., custom/...
 *
 * Notes on relative paths:
 *   Paths starting with '.' are treated as relative, including dotfiles
 *   like '.bashrc'. This allows convenient shorthand: typing '.bashrc'
 *   in $HOME resolves to 'home/.bashrc'. For single-component paths
 *   without '.', use explicit './' to indicate relative-path intent.
 *
 * Pattern-based: the file need not exist on disk. Used by show / revert /
 * remove / filter commands that query Git data, not the filesystem.
 *
 * Filesystem-path inputs are classified against `table` (longest match
 * wins), so users can specify /mnt/jail/etc/nginx.conf and have it
 * correctly become custom/etc/nginx.conf when /mnt/jail is bound.
 * Callers without state-derived mounts pass a zero-decl mount table —
 * HOME and the root sentinel are always present internally.
 *
 * Examples:
 *   ~/.bashrc                   -> home/.bashrc
 *   ./config (in $HOME)         -> home/config
 *   ./config (in /etc)          -> root/etc/config
 *   .bashrc (in $HOME)          -> home/.bashrc
 *   ../file (in $HOME/project)  -> home/file
 *   home/.bashrc                -> validated and returned as-is
 *   /etc/hosts                  -> root/etc/hosts
 *   /mnt/jail/etc/nginx.conf    -> custom/etc/nginx.conf (when /mnt/jail in table)
 *   config (no slash)           -> ERROR: ambiguous (use ./config)
 *
 * @param input       User-provided path string (must not be NULL)
 * @param table       Mount table (must not be NULL)
 * @param out_storage Allocated storage path on success (caller frees)
 * @return Error or NULL on success
 */
error_t *mount_resolve_input(
    const char *input,
    const mount_table_t *table,
    char **out_storage
);

#endif /* DOTTA_MOUNT_H */
