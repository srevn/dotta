/**
 * path.h - The key a CLI path argument names
 *
 * A location keys across profiles — the view's rows, the record, every screen —
 * and a storage path keys within one (infra/mount.h). The resolver answers in
 * the one the user named and manufactures neither from the other: what a profile
 * calls a location is a claim standing in a branch, and a command asks the branch
 * (core/manifest.h, the view by location; core/profiles.h profile_claim_name,
 * one profile's own). There is no exception left: nothing here manufactures one
 * key from the other, and no surface below offers to.
 *
 * A label alone is the third, and it is neither of those two: it keys no path
 * at all but the namespace above every path of its kind — a root, which is where
 * names begin and so can never be a leaf. It is a key because it can be matched
 * with (every name of that kind is beneath it) and because it is the one address
 * a root has that no machine has to supply: a custom/ tree bound nowhere here
 * still answers to `custom/`.
 *
 * The single chokepoint for input-shape dispatch. Of infra/mount it reads the
 * storage-label vocabulary alone — mount_spec_for_path, mount_spec_for_label,
 * mount_validate_storage, mount_root_describe over a spec these answered, a label
 * being a label on every machine — and never the table of roots: no root's spelling
 * is read to make a key, so the answer is the argument, HOME and the working
 * directory and nothing else. That is what lets the normalizer stand beside
 * mount_resolve's join as a producer of one key (infra/mount.h, the four
 * producers), and why no caller hands a topology down to read an argument.
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

/**
 * The key an argument names.
 */
typedef enum {
    PATH_KEY_LOCATION,          /* a filesystem shape: absolute, tilde, relative */
    PATH_KEY_STORAGE,           /* a storage shape: home/…, root/…, custom/… */
    PATH_KEY_LABEL,             /* a label alone, slash-marked: home/, root/, custom/ */
} path_key_t;

/**
 * A CLI path argument, read: the key, and the one name it is in.
 *
 * A sum type, spelled the way C spells one: the tag says which member is set,
 * and the member keeps its vocabulary at the use site — a reader that switches
 * on the key reads `location` in one arm and `storage_path` in the next, and no
 * second pointer promises to be NULL.
 *
 * The third key is a label, which is the one address a root has: a location and
 * a name are this machine's and the profile's, while a label is the same word
 * everywhere. The tag names what was read, as the other two do, and the member
 * is the label the vocabulary publishes — the spec that describes the root it
 * names is one total lookup away (infra/mount.h mount_spec_for_label). The
 * separator is no part of it: a verb that matches with the key wants the bare
 * prefix, and a verb that prints it adds the '/' its message needs.
 *
 * `location` and `storage_path` are the arena's; `label` is the spec table's
 * own static string and outlives every arena.
 */
typedef struct {
    path_key_t key;
    union {
        const char *location;       /* PATH_KEY_LOCATION: absolute, normalized */
        const char *storage_path;   /* PATH_KEY_STORAGE: validated, the directory spelling shed */
        const char *label;          /* PATH_KEY_LABEL: the label alone, the spec's own string */
    };
} path_input_t;

/**
 * Read a CLI path argument: the shape dispatch, and nothing else.
 *
 * A storage shape is read in two: the label alone is a root — the namespace itself,
 * which is no storage path (mount_validate_storage refuses one) and no location
 * either, a label being the same word on every machine — and anything beneath
 * it is a name, validated and kept as typed. Either way the trailing slash is
 * shed (the UI's listings print directory claims slash-marked, and the filesystem
 * arm sheds its own inside the normalizer; the two surface forms resolve alike).
 * A filesystem shape is normalized (path_input_normalize: tilde, the working
 * directory, `.`/`..`/`//` folded), and that spelling is the key: a location is
 * a string of its own, a link in it a component, so the answer keys against the
 * view's rows by strcmp when it was spelled the way the rows were (infra/mount.h).
 * No profile, no name, no stat, no table: the argument need not exist, and a
 * root named by its own spelling (`~`, a target's path) is a location like any
 * other — a place, where the label that names the same root is a namespace, and
 * the two are different keys for that reason. The verb that cannot take either
 * refuses it in its own words. A bare name is refused: add's grammar reads one
 * as the jail's or the working directory's (cmds/add.c spell_argument); the
 * resolver does not, because its callers' first positional may be a profile.
 *
 *   ~/.bashrc                 -> LOCATION  $HOME/.bashrc    (HOME as the identity spells it)
 *   ./config    (in /etc)     -> LOCATION  /etc/config
 *   .bashrc     (in $HOME)    -> LOCATION  $HOME/.bashrc
 *   ~/link/x    (~/link -> ~/real, bound or not)
 *                             -> LOCATION  $HOME/link/x     (the link is a component)
 *   ~/link/../x               -> LOCATION  $HOME/x          ('..' pops the link's spelling)
 *   ~                         -> LOCATION  $HOME            (a root is a location; the verb decides)
 *   home/.config/nvim/        -> STORAGE   home/.config/nvim
 *   custom/                   -> LABEL     custom           (the namespace, not a path in it)
 *   home/../x                 -> refused   (mount_validate_storage)
 *   config                    -> refused   (neither shape)
 *
 * `*out` is zeroed on entry: after an error it is no answer, and a reader that
 * ignores the error meets a NULL rather than a stale string — the zeroed key is
 * PATH_KEY_LOCATION, whose member is then NULL.
 *
 * Readers, and what each does with a label — a reader not on this list is a bug.
 * The tag is read by a switch where every key does work of its own and by an
 * `if` where the site narrows (it refuses one key, or a predicate upstream already
 * ruled one out), so this list, and not -Wswitch, is what says the sweep is whole:
 *
 *   - the pathspec's exact entries (infra/pathspec) take one: a label is the
 *     prefix every name of that namespace is beneath, and the entry it makes is
 *     storage-keyed like any name. The anchors of its filesystem-shaped rules
 *     never meet one — the arm that compiles them has already ruled a label out.
 *   - remove (cmds/remove.c) takes one: every claim beneath the label, matched
 *     by name, which is the one form that reaches a profile with no binding here.
 *   - export (cmds/export.c) takes one: the whole tree under the label. Its own
 *     catch arm makes the same key out of the bare word its grammar allows.
 *   - show and list without a profile (cmds/) refuse one, and with a profile
 *     hand the key to the branch namer, which refuses it there (core/profiles.h
 *     profile_claim_name); revert refuses one at its door, so
 *     profile_discover_claims is never handed one.
 *   - add's storage head (cmds/add.c) refuses one: a label names no path to
 *     capture, and `add <p> ~` and `add <p> <target>` name the place it labels.
 *     add's filesystem head is add's own grammar, spelled around
 *     path_input_normalize.
 *   - `ignore --test` (cmds/ignore.c) reports one: a root has no name for a pattern
 *     to match, which is the answer its location spelling earns too.
 *
 * @param input User-provided path string (must not be NULL)
 * @param arena Arena that owns the answer's string, where one is copied — a label
 *              answers the vocabulary's own and copies nothing (must not be NULL)
 * @param out   The key and its name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_resolve(const char *input, arena_t *arena, path_input_t *out);

/**
 * The refusal a label argument earns from a verb that acts on one path
 *
 *   'custom/' is the deployment target of profile 'web': name what is inside it
 *   'home/' is your home directory: name what is inside it
 *
 * One sentence for the five sites that own it, because it is one fact: the verb
 * was handed a namespace where it wanted a path in one. What each verb then does
 * with the error is its own — returned, or carried to a cleanup label.
 *
 * `label` is a resolve's own answer (path_input_t.label), which is one of the
 * three strings the vocabulary publishes, so the lookup beneath it cannot miss;
 * that is the whole precondition, and it is mount_root_describe's own read one
 * rung earlier. `profile` is the asker, or NULL where the verb has none to name
 * — `show custom/` chose no profile and cannot — and the noun then stands without
 * an owner (infra/mount.h mount_root_describe).
 *
 * The separator is the message's and never the key's: a label is carried bare
 * because the verbs that take one match with it, and printed slash-marked because
 * that is the one spelling that reaches this key. The same refusal for the
 * *location* spelling of a root is its two callers' own sentence (core/profiles.c,
 * cmds/revert.c): they hold a location and no label, and a location needs no
 * separator added to it.
 *
 * Reads the label vocabulary and no table, as the resolver does (this file's
 * banner): mount_spec_for_label is the label set, and mount_root_describe takes
 * the spec it answers.
 *
 * @param label   The label a resolve answered (must not be NULL)
 * @param profile The asker, or NULL where the verb named none
 * @return The refusal; never NULL
 */
error_t *path_input_refuse_label(const char *label, const char *profile);

/**
 * Normalize a CLI filesystem-path argument to an absolute path
 *
 * The shell's reading, with the working directory spelled for a key: a tilde
 * path expands under $HOME, an absolute one stands, and a relative one — `./x`,
 * `../x`, a dotfile's `.x`, `path/to/file` — is the working directory's, which
 * the shell spelled as the user reached it ($PWD, pwd -L's rule) or the kernel
 * spelled physically (getcwd, where the shell set none — sudo, cron, env -i —
 * or a stale one). A working directory beneath HOME is spelled under HOME as
 * the identity spells it whichever of the two spelled it: the argument spelled
 * no directory, and a key under HOME is HOME's spelling (infra/mount.h). The
 * argument's own tail is the user's and stands, so `home/../c` typed above HOME's
 * directory is the shell's `<parent>/c` and never HOME's parent. Then `.`, `..`,
 * a run of slashes and the directory spelling fold lexically. No symlink is
 * resolved and the path need not exist: the fold is string work over the spelling,
 * so a symlink argument stays the link, and a `..` after one pops the link's
 * spelling, not the directory it reaches. A working directory reached through a
 * link no root names — beneath HOME, or above it through a link that is not HOME's
 * own — keeps the kernel's spelling of that link's target, as a typed absolute
 * path through it would.
 *
 *   ~/file                    -> $HOME/file
 *   /etc/foo                  -> /etc/foo
 *   rel/file                  -> $CWD/rel/file
 *   ./a/../b/                 -> $CWD/b
 *   ./x         (in ~/sub, however the shell spelled it, or spelled nothing)
 *                             -> $HOME/sub/x
 *   ~/link/../x               -> $HOME/x       ('..' pops the link's spelling)
 *   home/../c   (in HOME's parent, spelled physically)
 *                             -> <parent>/c    (the tail is the user's)
 *
 * The filesystem arm of path_input_resolve is this function and a copy; the
 * commands that read a filesystem spelling and walk it (add), bind it (the binders'
 * --target), test it (ignore --test) or complete beneath it (the completion's
 * root) call it directly. A target given as an absolute or tilde path is the
 * user's own; one given relatively is spelled by the rule above like any other
 * relative argument. Storage-path inputs ("home/", "root/", "custom/") are not
 * this function's — they are validated and placed at the call site
 * (mount_validate_storage, mount_resolve). add's re-rooting under --target is
 * add's own grammar, spelled around this call (cmds/add.c, spell_argument). The
 * answer is malloc's: three of the callers own it — the interactive save's per-edit
 * target, the completion, the binder that frees at its label — and the rest hand
 * it on and free it.
 *
 * @param input User-provided path (filesystem or tilde; must not be NULL)
 * @param out   Normalized absolute path (caller must free, must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_normalize(const char *input, char **out);

#endif /* DOTTA_PATH_H */
