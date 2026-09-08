/**
 * path.h - The key a CLI path argument names
 *
 * A location keys across profiles — the view's rows, the record, every screen —
 * and a storage path keys within one (infra/mount.h). The resolver answers in
 * the one the user named and manufactures neither from the other: what a profile
 * calls a location is a claim standing in a branch, and a command asks the branch
 * (core/manifest.h, the view by location; core/profiles.h). The one exception
 * is path_input_classify below, the former resolver, which still manufactures a
 * name from a location for the verbs that have no branch reader yet.
 *
 * The single chokepoint for input-shape dispatch; the topology primitives
 * (mount_locate, mount_resolve, mount_table_build) live one layer down in
 * infra/mount.
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

#include "infra/mount.h"

/**
 * The key an argument names.
 */
typedef enum {
    PATH_KEY_LOCATION,          /* a filesystem shape: absolute, tilde, relative */
    PATH_KEY_STORAGE,           /* a storage shape: home/…, root/…, custom/… */
} path_key_t;

/**
 * A CLI path argument, read: the key, and the one name it is in.
 *
 * A sum type, spelled the way C spells one: the tag says which member is set,
 * and the member keeps its vocabulary at the use site — a reader that switches
 * on the key reads `location` in one arm and `storage_path` in the other, and
 * no second pointer promises to be NULL. Both are the arena's.
 */
typedef struct {
    path_key_t key;
    union {
        const char *location;       /* PATH_KEY_LOCATION: absolute, normalized, located */
        const char *storage_path;   /* PATH_KEY_STORAGE: validated, the directory spelling shed */
    };
} path_input_t;

/**
 * Read a CLI path argument: the shape dispatch, and nothing else.
 *
 * A storage shape is validated and kept as typed, its trailing slash shed (the
 * UI's listings print directory claims slash-marked, and the filesystem arm sheds
 * its own inside the normalizer; the two surface forms resolve alike). A filesystem
 * shape is normalized (path_input_normalize: tilde, the working directory,
 * `.`/`..`/`//` folded) and located (mount_locate): the answer is where the
 * spelling stands, physical as far as the table knows its roots. No profile, no
 * name, no stat: the argument need not exist, and a root is a location like any
 * other — the verb that cannot take one refuses it in its own words. A bare name
 * is refused: add's grammar reads one as the jail's or the working directory's
 * (cmds/add.c spell_argument); the resolver does not, because its callers' first
 * positional may be a profile.
 *
 *   ~/.bashrc                 -> LOCATION  $HOME/.bashrc    (physical, under a symlinked HOME)
 *   ./config    (in /etc)     -> LOCATION  /etc/config
 *   .bashrc     (in $HOME)    -> LOCATION  $HOME/.bashrc
 *   ~/link/x    (q bound at ~/link -> ~/real)
 *                             -> LOCATION  $HOME/real/x     (the alias above it read through)
 *   ~/link      (q bound so)  -> LOCATION  $HOME/real       (a binder's spelling is the binding's)
 *   ~                         -> LOCATION  $HOME            (a root is a location; the verb decides)
 *   home/.config/nvim/        -> STORAGE   home/.config/nvim
 *   home/../x                 -> refused   (mount_validate_storage)
 *   config                    -> refused   (neither shape)
 *
 * `*out` is zeroed on entry: after an error it is no answer, and a reader that
 * ignores the error meets a NULL rather than a stale string — the zeroed key is
 * PATH_KEY_LOCATION, whose member is then NULL.
 *
 * Readers: the pathspec's exact entries and the anchors of its filesystem-shaped
 * rules (infra/pathspec); show and list without a profile (the view by location,
 * a name by its holders); path_input_classify.
 *
 * @param table Mount table (must not be NULL)
 * @param input User-provided path string (must not be NULL)
 * @param arena Arena that owns the answer's string
 * @param out   The key and its name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_resolve(
    const mount_table_t *table,
    const char *input,
    arena_t *arena,
    path_input_t *out
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
 * mount_locate; the commands that read a filesystem spelling and walk it (add),
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

/**
 * The resolver's former answer: a filesystem argument named through its roots.
 *
 * The name the asker's own roots give a location (infra/mount.h mount_name) —
 * which is the last rung of the question, not the question: the claim standing
 * there, in the branch that holds it, is what a verb actually wants. Kept under
 * its own name for the verbs that still ask it (show -p, list -p, revert, export,
 * remove) until the claim is found where it stands (core/profiles.h); deleted
 * with that landing. Not a reader for new code. A storage shape is the name as
 * typed; a root is refused as it always was ("is a mount root").
 *
 * `profile` is the asker: with none, the location is named through HOME and `/`
 * alone, so a claim a bound profile holds under `custom/` is not found — a clean
 * miss until the search reads the branches.
 *
 * @param table       Mount table (must not be NULL)
 * @param profile     The asker, or NULL for the shared roots alone
 * @param input       User-provided path string (must not be NULL)
 * @param arena       Arena that owns the returned storage path
 * @param out_storage Arena-borrowed storage path on success; NULL after an error
 *                    (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_classify(
    const mount_table_t *table,
    const char *profile,
    const char *input,
    arena_t *arena,
    const char **out_storage
);

#endif /* DOTTA_PATH_H */
