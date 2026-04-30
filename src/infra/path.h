/**
 * path.h - User-input path resolution
 *
 * Façade over mount_classify and the filesystem helpers that converts
 * flexible CLI path arguments (storage labels, absolute, tilde, relative)
 * into a canonical storage path.
 *
 * The single chokepoint for input-shape dispatch; topology primitives
 * (mount_classify, mount_resolve, mount_table_build) live one layer
 * down in infra/mount.
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

#include "infra/mount.h"

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
 * @param table       Mount table (must not be NULL)
 * @param input       User-provided path string (must not be NULL)
 * @param arena       Arena that owns the returned storage path
 * @param out_storage Arena-borrowed storage path on success (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_resolve(
    const mount_table_t *table,
    const char *input,
    arena_t *arena,
    const char **out_storage
);

/**
 * Normalize a CLI filesystem-path argument to an absolute path,
 * optionally re-rooted under `target_root`.
 *
 * When `target_root` is non-NULL, it acts as a virtual root: every
 * typed path is resolved as if the user were operating inside that
 * directory (chroot-style). Generalises any "operate within this
 * tree" usage — chroots, container overlays, fakeroot trees, vendor
 * directories, staging areas, project subroots. Tilde paths bypass
 * the re-rooting: `~/X` always lands under $HOME, since HOME is its
 * own namespace.
 *
 * Compose model (target_root="/jail", canonical="/private/jail"):
 *   ~/file                  -> $HOME/file       (tilde bypass)
 *   rel/file                -> /jail/rel/file   (relative + target)
 *   /etc/foo                -> /jail/etc/foo    (host-absolute re-rooted)
 *   /jail/etc/foo           -> /jail/etc/foo    (already inside, raw)
 *   /private/jail/etc/foo   -> /private/jail/etc/foo
 *                                               (already inside,
 *                                                canonical surface form)
 *   /jail/../etc/secret     -> ERROR            (escapes after `..`
 *                                                resolution)
 *
 * Without `target_root`:
 *   ~/file                  -> $HOME/file
 *   /etc/foo                -> /etc/foo
 *   rel/file                -> $CWD/rel/file
 *
 * Symlink-aware re-rooting: each "already inside" check cross-products
 * the raw `target_root` with its realpath-canonical sibling, so a
 * canonical CLI input (from getcwd / find / tab-completion) under a
 * raw-typed target — or the reverse, e.g. macOS's `/tmp -> /private/tmp`
 * with `--target /tmp/web` — is recognised as inside without being
 * re-prepended to nonsense.
 *
 * Pairs with path_input_resolve. This function stops at the absolute
 * filesystem path; path_input_resolve continues through mount
 * classification to a storage path. Callers that walk directories
 * (need filesystem paths to opendir / stat) use this; callers that
 * query Git data (need storage paths) use the resolver. The output
 * is fed into mount_classify per-file when the storage path is
 * needed.
 *
 * Storage-path inputs ("home/", "root/", "custom/") are not handled
 * here — those are validated and consumed via mount_validate_storage
 * + mount_resolve at the call site. This function answers the
 * "filesystem path" arm of the input-shape dispatch.
 *
 * @param input        User-provided path (filesystem or tilde; must
 *                     not be NULL)
 * @param target_root  Optional virtual root that re-roots every
 *                     non-tilde input. NULL or empty disables
 *                     re-rooting; relative inputs then resolve via
 *                     the actual CWD.
 * @param out          Normalized absolute path (caller must free,
 *                     must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_normalize(
    const char *input,
    const char *target_root,
    char **out
);

#endif /* DOTTA_PATH_H */
