/**
 * path.h - Path resolution and conversion
 *
 * Handles conversion between filesystem paths and storage paths.
 *
 * Storage path format:
 * - home/.bashrc   -> $HOME/.bashrc
 * - root/etc/hosts -> /etc/hosts
 *
 * SECURITY CRITICAL: Prevents path traversal attacks.
 *
 * Design principles:
 * - Reject any path containing ".."
 * - Validate all paths before conversion
 * - Canonicalize when needed
 * - Clear error messages
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

/**
 * Normalize user input path to absolute filesystem path
 *
 * Transformation order:
 * 1. Tilde expansion (~/ → $HOME)
 * 2. Custom prefix: join with relative paths, prepend to absolute paths
 *    (absolute paths already under prefix pass through unchanged)
 * 3. CWD joining (relative, no prefix)
 *
 * The custom_prefix defines a virtual filesystem root. All paths (relative
 * and absolute) are resolved within that context. An absolute path like
 * /etc/hosts with prefix /jail becomes /jail/etc/hosts because the path
 * is "absolute within the jail".
 *
 * Security: Rejects path traversal (..) in relative paths with custom_prefix.
 *
 * Examples:
 *   ("~/file", NULL)              → "$HOME/file"
 *   ("rel/file", "/jail")         → "/jail/rel/file"
 *   ("/etc/hosts", "/jail")       → "/jail/etc/hosts"
 *   ("/jail/etc/hosts", "/jail")  → "/jail/etc/hosts" (already under prefix)
 *   ("rel/file", NULL)            → "$CWD/rel/file"
 *   ("../escape", "/jail")        → ERROR
 *
 * @param user_path User-provided path (filesystem or tilde)
 * @param custom_prefix Optional prefix defining virtual filesystem root (can be NULL)
 * @param out Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_normalize_input(
    const char *user_path,
    const char *custom_prefix,
    char **out
);

/**
 * Classify absolute filesystem path into storage path
 *
 * Pure classifier — does NOT normalize the input. Callers must provide
 * an already-resolved absolute filesystem path (use path_normalize_input()
 * first if working with raw user input).
 *
 * Classification semantic (tightest container wins):
 *   The candidate with the longest matching prefix is selected. An
 *   explicit --prefix is typically more specific than $HOME and wins
 *   naturally. When a prefix is a strict ancestor of $HOME, $HOME wins
 *   (more portable storage paths). Root is the universal fallback.
 *
 * Examples:
 *   ("/home/user/.bashrc", NULL)           -> home/.bashrc (PREFIX_HOME)
 *   ("/jail/etc/nginx.conf", "/jail")      -> custom/etc/nginx.conf (PREFIX_CUSTOM)
 *   ("/home/user/.bashrc", "/home/user/r") -> home/.bashrc (not under prefix)
 *   ("/etc/hosts", NULL)                   -> root/etc/hosts (PREFIX_ROOT)
 *
 * @param filesystem_path Absolute filesystem path (must start with '/')
 * @param custom_prefix Custom prefix to detect (NULL if not using custom/)
 * @param storage_path Output storage path (caller must free)
 * @param prefix_out Output prefix type (can be NULL)
 * @return Error or NULL on success
 */
error_t *path_to_storage(
    const char *filesystem_path,
    const char *custom_prefix,
    char **storage_path,
    path_prefix_t *prefix_out
);

/**
 * Convert storage path to filesystem path
 *
 * For custom/ paths, requires custom_prefix parameter.
 * For home/ and root/ paths, custom_prefix is ignored (can be NULL).
 *
 * Examples:
 *   home/.bashrc (NULL)           -> $HOME/.bashrc
 *   root/etc/hosts (NULL)         -> /etc/hosts
 *   custom/etc/nginx.conf (/jail) -> /jail/etc/nginx.conf
 *
 * @param storage_path Storage path (e.g., "custom/etc/nginx.conf")
 * @param custom_prefix Custom prefix for custom/ paths (NULL for home/root)
 * @param filesystem_path Output filesystem path (caller must free)
 * @return Error or NULL on success
 */
error_t *path_from_storage(
    const char *storage_path,
    const char *custom_prefix,
    char **filesystem_path
);

/**
 * Validate storage path
 *
 * Checks:
 * - No ".." or "." components (path traversal)
 * - Starts with "home/", "root/", or "custom/"
 * - Not absolute (no leading /)
 * - Not empty
 * - No trailing slash (must reference a file, not a directory)
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_storage(const char *storage_path);

/**
 * Expand ~ to $HOME
 *
 * Examples:
 *   ~/.bashrc -> /home/user/.bashrc
 *   ~/foo/bar -> /home/user/foo/bar
 *
 * @param path Path with ~ prefix (must not be NULL)
 * @param out Expanded path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_expand_home(const char *path, char **out);

/**
 * Return pointer into storage_path past the storage prefix.
 *
 * Strips leading "home/", "root/", or "custom/" for callers that need
 * the user-facing tail (e.g. pattern matching against config patterns
 * like ".ssh/id_*", which are written without the storage prefix).
 *
 * Returns storage_path unchanged when no prefix matches or when input
 * is NULL. Never NULL for non-NULL input. Zero allocation; the returned
 * pointer aliases storage_path and shares its lifetime.
 *
 * @param storage_path Storage path (can be NULL)
 * @return Pointer past the prefix, or storage_path unchanged
 */
const char *path_strip_storage_prefix(const char *storage_path);

/**
 * Get $HOME directory
 *
 * @param out HOME directory path (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_get_home(char **out);

/* Forward declaration for the deployment-topology handle introduced
 * below. path_resolve_input and path_filter_create consume it as the
 * single source of "which prefixes does this command see?". */
typedef struct path_roots path_roots_t;

/**
 * Resolve flexible path input to canonical storage format
 *
 * Accepts multiple input formats:
 *   1. Absolute paths: /path/to/file
 *   2. Tilde paths: ~/path/to/file
 *   3. Relative paths: ./path, ../path, .dotfile, path/to/file (resolved via CWD)
 *   4. Storage paths: home/..., root/..., custom/...
 *
 * Note on relative paths:
 *   Paths starting with '.' are treated as relative, including dotfiles like
 *   '.bashrc'. This allows convenient shorthand: typing '.bashrc' in $HOME
 *   resolves to 'home/.bashrc'. For single-component paths without '.', use
 *   explicit './' prefix to indicate relative path intent.
 *
 * Pattern-based conversion: file need not exist on disk. Used by
 * show/revert/remove/filter commands that query Git data, not the filesystem.
 *
 * Custom prefix detection:
 *   `roots` carries the per-machine (storage label → deployment root)
 *   topology — every custom prefix the caller wants recognized, plus
 *   HOME and the empty-prefix root sentinel that path_roots_build adds
 *   internally. Filesystem-path inputs are classified against the
 *   handle's candidate set; the longest-matching prefix wins. Callers
 *   that have no custom prefixes still pass a roots built with zero
 *   bindings (HOME + root only).
 *
 *   Classification semantic (tightest container wins):
 *   The candidate with the longest matching prefix is selected. When two
 *   custom prefixes overlap (e.g. /opt and /opt/apps), the more specific
 *   one wins regardless of enable order. When a custom prefix is a strict
 *   ancestor of $HOME, $HOME wins (more portable storage paths).
 *
 * Path normalization:
 *   All paths are normalized to resolve '.' and '..' components before
 *   conversion to storage format. This ensures consistent HOME detection
 *   regardless of how the path is expressed.
 *
 * Examples:
 *   ~/.bashrc                   -> home/.bashrc
 *   ./config (in $HOME)         -> home/config
 *   ./config (in /etc)          -> root/etc/config
 *   .bashrc (in $HOME)          -> home/.bashrc (dotfile as relative path)
 *   ../file (in $HOME/project)  -> home/file (.. resolved)
 *   home/.bashrc                -> validated and returned as home/.bashrc
 *   /etc/hosts                  -> root/etc/hosts
 *   /mnt/jail/etc/nginx.conf    -> custom/etc/nginx.conf (if /mnt/jail in roots)
 *   config (no slash)           -> ERROR: ambiguous (use ./config)
 *
 * @param input User-provided path string (must not be NULL)
 * @param roots Deployment topology handle (must not be NULL)
 * @param out_storage_path Output in storage format (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *path_resolve_input(
    const char *input,
    const path_roots_t *roots,
    char **out_storage_path
);

/**
 * Per-machine deployment topology
 *
 * Captures the union of (storage label → deployment root) mappings active
 * on this machine as a single first-class value:
 *
 *   home/   → $HOME            (process-global, derived from getenv)
 *   root/   → /                (universal sentinel)
 *   custom/ → per-profile      (configured via --prefix at enable time)
 *
 * Built once per command at the boundary where the binding source is in
 * scope (CLI, state row cache), then consulted many times downstream.
 * Replaces the duplicated candidate-set construction and HOME
 * canonicalization that was sprinkled across every reader.
 *
 * Two views over the same data:
 *   - Backward (filesystem → storage): path_roots_classify picks the
 *     longest-matching prefix from the augmented candidate set.
 *   - Forward (profile + storage → filesystem): path_roots_to_filesystem
 *     looks up the per-profile deployment root.
 *
 * Lifetime: arena-allocated. All borrowed strings (binding fields) must
 * outlive the arena passed to path_roots_build. There is no destructor —
 * arena_destroy reclaims everything.
 *
 * (path_roots_t itself is forward-declared earlier in this header so
 * path_resolve_input and path_filter_create can reference it before the
 * full topology API is introduced below.)
 */

/**
 * Profile ↔ deployment-root binding
 *
 * POD value type. Both fields are borrowed pointers; their lifetime is
 * the caller's responsibility and must outlive the arena used to build
 * the roots handle.
 *
 * - profile: NULL when the binding has no profile association (e.g.,
 *   PR 1 internal scratch use where the caller has only prefix strings,
 *   not profile names).
 * - deploy_root: NULL when the profile contributes no custom row (the
 *   profile is recorded for forward-resolution lookups, but it has no
 *   custom deployment root configured on this machine).
 */
typedef struct {
    const char *profile;       /* may be NULL */
    const char *deploy_root;   /* absolute path, no trailing slash; may be NULL */
} path_binding_t;

/**
 * Build a path_roots handle from a flat array of profile bindings.
 *
 * The handle is augmented internally with HOME (raw + canonical when
 * distinct from raw) and the empty-prefix root sentinel — callers do
 * not pass these. Bindings whose deploy_root is NULL or empty
 * contribute no candidate row; their profile names (when non-NULL)
 * are still recorded so forward-resolution lookups can distinguish
 * "profile not in roots" from "profile has no deploy_root".
 *
 * Lifetime:
 *   - Output is allocated entirely from `arena`.
 *   - Borrowed string fields in `bindings` must outlive `arena`.
 *   - $HOME is captured into the arena at build time, immune to later
 *     setenv mutations.
 *
 * Errors:
 *   - ERR_FS if HOME cannot be resolved (env unset and passwd lookup fails).
 *   - ERR_MEMORY on arena allocation failure.
 *
 * @param arena Arena for the handle and its internal storage (must not be NULL)
 * @param bindings Profile bindings; may be NULL when binding_count == 0
 * @param binding_count Number of bindings (zero is valid — yields HOME + root only)
 * @param out Output handle (must not be NULL; lifetime tracks arena)
 * @return Error or NULL on success
 */
error_t *path_roots_build(
    arena_t *arena,
    const path_binding_t *bindings,
    size_t binding_count,
    path_roots_t **out
);

/**
 * Classify an absolute filesystem path into a storage path
 *
 * Picks the longest-matching prefix from the roots' candidate set
 * (tightest container wins). Same semantics as path_to_storage's
 * classifier core, but the candidate set is supplied by `roots` rather
 * than rebuilt per call.
 *
 * @param roots Roots handle (must not be NULL)
 * @param filesystem_path Absolute path to classify (must not be NULL)
 * @param out_storage_path Allocated storage path on success (caller frees)
 * @param out_kind Optional: receives the winning candidate's kind
 * @return Error or NULL on success
 */
error_t *path_roots_classify(
    const path_roots_t *roots,
    const char *filesystem_path,
    char **out_storage_path,
    path_prefix_t *out_kind
);

/**
 * Convert a storage path to a filesystem path using the profile's binding
 *
 * Resolution table:
 *   home/X   → $HOME/X                            (profile may be NULL)
 *   root/X   → /X                                 (profile may be NULL)
 *   custom/X → <profile's deploy_root>/X          (profile must match a binding)
 *
 * Error semantics:
 *   - ERR_INVALID_ARG — storage_path is malformed (rejected by
 *     path_validate_storage: missing label, illegal label, traversal,
 *     etc.). Always propagate.
 *   - ERR_NOT_FOUND — storage_path starts with "custom/" but the profile
 *     has no deploy_root in roots (profile not enabled with --prefix on
 *     this machine, or a clone before `dotta key set --prefix`). Callers
 *     that resolve "every storage entry against its source profile"
 *     (manifest_build_callback, manifest_sync_diff, manifest_sync_directories)
 *     treat this as a silent skip, since a profile without a deployment
 *     root contributes nothing to the VWD on this host. Callers that
 *     resolve a single user-supplied path treat it as a hard error.
 *
 * @param roots Roots handle (must not be NULL)
 * @param profile Owning profile (may be NULL for home/ and root/ paths)
 * @param storage_path Storage-format path (must not be NULL, validated)
 * @param out_filesystem_path Allocated filesystem path on success (caller frees)
 * @return Error or NULL on success
 */
error_t *path_roots_to_filesystem(
    const path_roots_t *roots,
    const char *profile,
    const char *storage_path,
    char **out_filesystem_path
);

/**
 * Look up a profile's deployment root
 *
 * Direct accessor for callers that need only the per-profile prefix
 * (e.g., diagnostic output, external command invocation). For
 * storage→filesystem conversion, prefer path_roots_to_filesystem.
 *
 * Returns NULL when:
 *   - roots or profile is NULL
 *   - the profile is not in roots (not enabled, filtered out at build, etc.)
 *   - the binding exists but has no deploy_root (profile has no --prefix)
 *
 * The returned pointer is borrowed; lifetime tracks the arena.
 *
 * @param roots Roots handle (NULL returns NULL)
 * @param profile Profile name (NULL returns NULL)
 * @return Borrowed deploy_root or NULL
 */
const char *path_roots_deploy_root_for_profile(
    const path_roots_t *roots,
    const char *profile
);

/* Forward declaration for the compiled glob ruleset; defined in
 * base/gitignore.h. Kept opaque here so path.h does not pull in the
 * whole ignore engine. */
typedef struct gitignore_ruleset gitignore_ruleset_t;

/**
 * Path filter for selective file operations
 *
 * Supports three types of filter entries:
 *   1. Exact paths: "home/.bashrc" - matches single file
 *   2. Directory prefixes: "home/.config/fish" - matches all files under directory
 *   3. Glob patterns: "*.vim", "home/ ** / *.conf" - pattern-based matching
 *
 * NULL filter semantics: matches all paths (no filtering).
 *
 * Glob storage: patterns are compiled once into `glob_ruleset` (the
 * authoritative matcher) and also kept as raw strings in
 * `glob_patterns[]` for diagnostic consumers (e.g. diff.c's
 * unmatched-pattern warning). Both are borrowed from the arena passed
 * to `path_filter_create` (typically `ctx->arena`); the arena must
 * outlive the filter.
 */
typedef struct {
    struct hashmap *exact_paths;         /* Exact paths for O(1) lookup (hashmap owns keys) */
    gitignore_ruleset_t *glob_ruleset;   /* Compiled globs; NULL when glob_count == 0; arena-borrowed */
    char **glob_patterns;                /* Arena-borrowed strings; retained for diagnostics */
    size_t glob_count;                   /* Number of glob patterns */
    size_t count;                        /* Total entries (exact + globs) */
} path_filter_t;

/**
 * Create path filter from user input paths
 *
 * Accepts three types of inputs:
 *   1. Glob patterns (*, ?, []) - stored as-is for pattern matching
 *      Examples: "*.vim", "home/ ** / *.conf" (recursive)
 *
 *   2. Filesystem paths - resolved to storage format
 *      Examples: ~/.bashrc, /etc/hosts, ./config, ../path
 *
 *   3. Storage paths - validated and stored directly
 *      Examples: home/.bashrc, root/etc/hosts, custom/etc/nginx.conf
 *
 * Glob pattern rules:
 * - Basename-only patterns ("*.vim") match at any depth
 * - Patterns with "/" must use storage format (e.g., home/ followed by glob)
 * - Recursive patterns (doublestar followed by /foo) match at any depth
 *
 * Custom prefix detection:
 *   `roots` carries every (storage label → deployment root) mapping the
 *   filter should recognize. Filesystem-path inputs are classified
 *   against the handle's candidate set (longest match wins), so users
 *   can specify /mnt/jail/etc/nginx.conf and have it correctly match
 *   custom/etc/nginx.conf when /mnt/jail is bound in roots.
 *
 * NULL semantics:
 * - If inputs is NULL or count is 0, returns NULL filter (matches all)
 * - A NULL filter passed to path_filter_matches() matches all paths
 * - `roots` must be non-NULL even when no custom prefixes are configured
 *   (callers without state pass a zero-binding roots — HOME + root only)
 *
 * Error handling:
 * - If any path resolution fails, returns error and cleans up
 * - Partial results are not returned
 *
 * @param inputs User-provided path or pattern strings (can be NULL if count is 0)
 * @param count Number of inputs
 * @param roots Deployment topology handle (must not be NULL)
 * @param arena Borrowed allocator backing glob_ruleset and glob_patterns
 *              entries; must outlive the filter (must not be NULL)
 * @param out Path filter (must not be NULL, receives NULL if no filter)
 * @return Error or NULL on success
 */
error_t *path_filter_create(
    char *const *inputs,
    size_t count,
    const path_roots_t *roots,
    arena_t *arena,
    path_filter_t **out
);

/**
 * Check if storage path matches filter
 *
 * Matching semantics (gitignore-style via base/gitignore):
 * - Exact match: "home/.bashrc" matches "home/.bashrc"
 * - Directory prefix: "home/.config" matches "home/.config/fish/config.fish"
 * - Glob patterns: recursive globs match nested paths
 * - Basename patterns: "*.vim" matches "home/.vim/vimrc.vim"
 *
 * Returns true if:
 * - Filter is NULL (no restrictions, matches all)
 * - storage_path matches any filter entry
 *
 * Thread safety: Safe for concurrent reads with same filter.
 *
 * @param filter Path filter (NULL = match all)
 * @param storage_path Storage path to check (must not be NULL)
 * @return true if matches, false otherwise
 */
bool path_filter_matches(
    const path_filter_t *filter,
    const char *storage_path
);

/**
 * Free path filter
 *
 * Frees all allocated storage paths and the filter structure.
 * Safe to call with NULL.
 *
 * @param filter Filter to free (can be NULL)
 */
void path_filter_free(path_filter_t *filter);

/**
 * Validate custom prefix parameter
 *
 * Validates that a user-provided custom prefix is safe to use.
 *
 * Checks:
 * - Absolute path (starts with /)
 * - No path traversal (no ../, ./, //)
 * - No trailing slash (normalized)
 * - Directory exists (via realpath)
 * - Is a directory (not a file)
 *
 * Security Notes:
 * - Uses realpath() to normalize and verify existence
 * - Follows symlinks (documented behavior)
 * - Prevents path traversal attacks
 *
 * @param prefix Custom prefix to validate (must not be NULL)
 * @return Error or NULL if valid
 */
error_t *path_validate_custom_prefix(const char *prefix);

#endif /* DOTTA_PATH_H */
