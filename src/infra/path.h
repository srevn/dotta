/**
 * path.h - User-input path resolution
 *
 * Façade over mount_classify and the filesystem helpers that converts flexible
 * CLI path arguments (storage labels, absolute, tilde, relative) into a canonical
 * storage path.
 *
 * The single chokepoint for input-shape dispatch; topology primitives
 * (mount_classify, mount_resolve, mount_table_build) live one layer down in
 * infra/mount.
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
 *   Paths starting with '.' are treated as relative, including dotfiles like
 *   '.bashrc'. This allows convenient shorthand: typing '.bashrc' in $HOME resolves
 *   to 'home/.bashrc'. For single-component paths without '.', use explicit './'
 *   to indicate relative-path intent.
 *
 * Pattern-based: the file need not exist on disk. Used by show / revert / remove
 * / filter commands that query Git data, not the filesystem.
 *
 * Filesystem-path inputs are classified against `table` (longest match wins),
 * so users can specify /mnt/jail/etc/nginx.conf and have it correctly become
 * custom/etc/nginx.conf when /mnt/jail is bound. Callers without state-derived
 * mounts pass a zero-decl mount table — HOME and the root sentinel are always
 * present internally.
 *
 * Examples:
 *   ~/.bashrc                   -> home/.bashrc
 *   ./config (in $HOME)         -> home/config
 *   ./config (in /etc)          -> root/etc/config
 *   .bashrc (in $HOME)          -> home/.bashrc
 *   ../file (in $HOME/project)  -> home/file
 *   home/.bashrc                -> validated and returned as-is
 *   home/.config/nvim/          -> home/.config/nvim (directory spelling shed)
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
 * Normalize a CLI filesystem-path argument to an absolute path
 *
 * The shell's reading: a tilde path expands under $HOME, a relative one — `./x`,
 * `../x`, a dotfile's `.x`, `path/to/file` — resolves against the working directory
 * as the shell spells it, and an absolute one stands; then `.`, `..`, a run of
 * slashes and the directory spelling are folded lexically. No symlink is resolved
 * and the path need not exist: the fold is string work over the spelling, so a
 * symlink argument stays the link.
 *
 *   ~/file       -> $HOME/file
 *   /etc/foo     -> /etc/foo
 *   rel/file     -> $CWD/rel/file
 *   ./a/../b/    -> $CWD/b
 *
 * The filesystem arm of path_input_resolve is this function followed by
 * mount_classify; the commands that read a filesystem spelling and walk it (add),
 * bind it (the binders' --target), test it (ignore --test) or complete beneath
 * it (the completion's root) call it directly. Storage-path inputs ("home/",
 * "root/", "custom/") are not this function's — they are validated and placed
 * at the call site (mount_validate_storage, mount_resolve). add's re-rooting
 * under --target is add's own grammar, spelled around this call (cmds/add.c,
 * spell_argument).
 *
 * @param input User-provided path (filesystem or tilde; must not be NULL)
 * @param out   Normalized absolute path (caller must free, must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_normalize(const char *input, char **out);

#endif /* DOTTA_PATH_H */
