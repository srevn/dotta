/**
 * path.h - The key a CLI path argument names
 *
 * A location keys across profiles — the view's rows, the record, every screen —
 * and a storage path keys within one (infra/label.h). The resolver answers in
 * the one the user named and manufactures neither from the other: what a profile
 * calls a location is a claim standing in a branch, and a command asks the branch
 * (core/manifest.h, the view by location; core/profiles.h profile_claim_name,
 * one profile's own). There is no exception left: nothing here manufactures one
 * key from the other, and no surface below offers to.
 *
 * There is no third key: a label alone is a name like any other, the one that
 * names the namespace's own directory (infra/label.h), and it reads in the storage
 * vocabulary as `home/x` does. Where a namespace lands is a root, and a root is
 * a place the table finds for an asker (infra/mount.h) — nothing this module reads.
 *
 * The single chokepoint for input-shape dispatch. It reads the grammar of a name
 * (infra/label.h: label_prefixes, label_validate_storage) and nothing of the
 * table of roots: no root's spelling is read to make a key and no root's noun
 * to refuse one, so the answer is the argument, HOME and the working directory
 * and nothing else. That is what lets the location door stand beside
 * mount_resolve's join as a producer of one key (infra/mount.h, the four
 * producers), and why no caller hands a topology down to read an argument.
 *
 * One question stands before any reading, over the spelling alone and the caller's
 * to ask first: whether a positional announces a path at all, where a verb's
 * slot could hold a profile instead (path_input_announces_path). It resolves
 * nothing, and it is not the resolver's own reading, which is wider.
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

/**
 * The key an argument names.
 */
typedef enum {
    PATH_KEY_LOCATION,          /* a filesystem shape: absolute, tilde, relative */
    PATH_KEY_STORAGE,           /* a storage shape: home/…, root/…, custom/…, or the word alone */
} path_key_t;

/**
 * A CLI path argument, read: the key, and the one name it is in.
 *
 * A sum type, spelled the way C spells one: the tag says which member is set,
 * and the member keeps its vocabulary at the use site — a reader that switches
 * on the key reads `location` in one arm and `storage_path` in the next, and no
 * second pointer promises to be NULL.
 *
 * The union holds two members of one type on purpose. It states "one of these,
 * never both" where a struct would state "both, one of them NULL", and it keeps
 * each key's own word at the site that reads it; collapsing the two to a `name`
 * would save eight bytes nobody spends and lose the vocabulary that tells a reader
 * which machine's answer it holds.
 *
 * Both members are the arena's.
 */
typedef struct {
    path_key_t key;
    union {
        const char *location;       /* PATH_KEY_LOCATION: absolute, normalized */
        const char *storage_path;   /* PATH_KEY_STORAGE: validated, the directory spelling shed */
    };
} path_input_t;

/**
 * Does the positional announce a path, or is it a name?
 *
 * The grammars' question, asked of a token whose slot is still undecided: the
 * leading positional of list, diff, apply and update may be a profile or a path,
 * and this tells the two apart with no repository in hand. A path announces itself
 * — absolute (`/x`), tilde (`~/x`), dot-relative (`./x`, `../x`, `.rc`), under
 * a storage label (infra/label.h label_prefixes), or a pattern that selects one.
 * A name announces nothing, and neither does a name with a separator in it: the
 * layering convention spells profiles `<os>/<variant>` and
 * `hosts/<host>/<variant>`, so `darwin/work` and `src/config` are one shape and
 * only the profile reading has no other spelling — `./src/config` is the path's.
 * A profile whose own name announces a path is named with -p, which is what each
 * of the four calls that flag at its own slot.
 *
 * The pattern alphabet is the pathspec's rule gate (infra/pathspec.c
 * pathspec_create), not wildmatch's whole grammar: a token answered here as a
 * pattern is one the filter compiles as a rule, and the two sets move together
 * or a pattern lands in the bucket that cannot read it.
 *
 * This is not the resolver's own reading of the same string, and neither implies
 * the other: this one is asked before a slot is decided, and the resolver's
 * filesystem shape is wider — it reads `a/b` as a path, its caller having decided
 * so — while its refusal is narrower, a pattern announcing a path that no reading
 * places:
 *
 *   input        announces a path   the resolver reads
 *   config       no                 refused
 *   src/config   no                 $CWD/src/config
 *   *.conf       yes                refused
 *   ./config     yes                $CWD/config
 *   home/x       yes                home/x
 *   home         yes                home
 *
 * Reads the grammar and no table of roots, as the resolver does (this file's
 * banner). The other classifier a positional meets — a token shaped like a commit
 * — reads Git's vocabulary and is spelled where that syntax lives (base/refspec.h
 * refspec_looks_like_commit); diff asks this one first, so a token that announces
 * a path is never read as a commit.
 *
 * Readers: list's inference form and its completion, diff's and apply's positional
 * classifiers, update's first-positional rule and its completion.
 *
 * @param input The positional (may be NULL, which announces nothing)
 * @return true iff the input announces a path, or a pattern that selects one
 */
bool path_input_announces_path(const char *input);

/**
 * Read a CLI path argument: the shape dispatch, and nothing else.
 *
 * A storage shape is the name as typed, the directory spelling shed (the UI's
 * listings print directory claims slash-marked, and the filesystem arm sheds
 * its own inside the normalizer; the two surface forms resolve alike): a name
 * beneath a label, or the word alone, which is the namespace's own directory
 * and a key like any name. A filesystem shape is located (path_input_locate:
 * tilde, the working directory, `.`/`..`/`//` folded), and that spelling is the
 * key: a location is a string of its own, a link in it a component, so the answer
 * keys against the view's rows by strcmp when it was spelled the way the rows
 * were (infra/mount.h). No profile, no name, no stat, no table: the argument
 * need not exist, and a root named by its own spelling (`~`, a target's path)
 * is a location like any other, where the same root named by its label's word
 * is a name — two keys for one place, and the verb decides what to do with each.
 * A word standing alone that is none of the three is refused, because a caller's
 * path slot may hold a profile and the resolver cannot see whose does: add's
 * grammar reads one as the jail's or the working directory's and reads it through
 * the location door (cmds/add.c spell_argument).
 *
 *   ~/.bashrc                 -> LOCATION  $HOME/.bashrc    (HOME as the identity spells it)
 *   ./config    (in /etc)     -> LOCATION  /etc/config
 *   .bashrc     (in $HOME)    -> LOCATION  $HOME/.bashrc
 *   ~/link/x    (~/link -> ~/real, bound or not)
 *                             -> LOCATION  $HOME/link/x     (the link is a component)
 *   ~/link/../x               -> LOCATION  $HOME/x          ('..' pops the link's spelling)
 *   ~                         -> LOCATION  $HOME            (a root is a location; the verb decides)
 *   home/.config/nvim/        -> STORAGE   home/.config/nvim
 *   custom/                   -> STORAGE   custom           (the namespace's own directory)
 *   home                      -> STORAGE   home
 *   home/../x                 -> refused   (label_validate_storage)
 *   config                    -> refused   (a word standing alone)
 *
 * `*out` is zeroed on entry: after an error it is no answer, and a reader that
 * ignores the error meets a NULL rather than a stale string — the zeroed key is
 * PATH_KEY_LOCATION, whose member is then NULL.
 *
 * Readers, and what each does with the two keys — a reader not on this list is
 * a bug. A verb that admits only some of them says so in a switch, where -Wswitch
 * owns the completeness claim: a third key becomes a compile error at each verb
 * that has to decide rather than a fallthrough read of a member the tag does
 * not name. The two heads that read the input's shape before the key state their
 * domain the same way, over the keys their own predicate can hand them, and the
 * key it cannot says so in its arm (cmds/add.c, cmds/ignore.c):
 *
 *   - the pathspec's exact entries (infra/pathspec) take either: a name matches
 *     against a claim's name and a location against where it stands, and the
 *     word alone is the name every name of its namespace is beneath. The anchors
 *     of its filesystem-shaped rules are located, never resolved.
 *   - remove (cmds/remove.c) takes either: the claims beneath the subject, matched
 *     by name or by place, the name being the one form that reaches a profile
 *     with no binding here.
 *   - export (cmds/export.c) takes either, one arm each: a name is a key in the
 *     branch's own tree, a location is a selection of the profile's rows.
 *   - show, list and revert (cmds/) take either: a name the user typed is Git's
 *     key already, and a location is the branch's to name (core/profiles.h
 *     profile_claim_name, profile_discover_claims).
 *   - add's storage head (cmds/add.c) takes the name alone: its own predicate
 *     dispatched on the storage shape, so a location arriving there is its bug
 *     and says so.
 *   - `ignore --test` (cmds/ignore.c) takes either, per asker: a name's subject
 *     is its tail — "" at the namespace's own directory, which no rule reaches
 *     — and a location's is the name each asker has for it.
 *
 * @param input User-provided path string (must not be NULL)
 * @param arena Arena that owns the answer's string (must not be NULL)
 * @param out   The key and its name (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_resolve(const char *input, arena_t *arena, path_input_t *out);

/**
 * The location a filesystem-shaped argument names, in the arena
 *
 * path_input_normalize's reading, copied once into the arena the caller keys
 * from: the one door a location key is read through, standing beside
 * mount_resolve's join (infra/mount.h, the four producers of one location). `*out`
 * is the location on success and NULL after an error, so a reader that ignores
 * the error meets a NULL rather than a stale string.
 *
 * One grammar, not three: every input is read as a filesystem spelling, so `home/x`
 * is the working directory's `home/x` and never a name, and a bare `config` is
 * the working directory's too where path_input_resolve refuses it. Which door a
 * verb reads through is its own positional grammar's answer — one whose first
 * positional may be a profile reads the key, and one that has ruled the storage
 * vocabulary out already, or never had one, reads the location here — so a name
 * handed to this door comes back as a filesystem reading of itself, which is
 * the whole reason the two are named apart.
 *
 * Readers, and what makes each one this door's — a reader not on this list is a
 * bug:
 *
 *   - path_input_resolve's own filesystem arm: this is that arm.
 *   - add's argument grammar (cmds/add.c spell_argument) and `ignore --test`'s
 *     filesystem arm (cmds/ignore.c): both dispatched on the storage shape
 *     themselves, and both read a bare name as a path where the resolver will not.
 *   - the two binders' --target (cmds/add.c, cmds/profile.c) and the root the
 *     completion offers beneath (cmds/completion.c): a target names a directory
 *     on this machine and has no storage vocabulary to dispatch on.
 *   - a glob's anchor (infra/pathspec.c compile_rule): the components before
 *     the first metacharacter, which that rule's own gate has already made a
 *     filesystem spelling.
 *
 * @param input User-provided path (filesystem or tilde; must not be NULL)
 * @param arena Arena that owns the answer (must not be NULL)
 * @param out   The location: absolute, folded, the arena's (must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_locate(const char *input, arena_t *arena, const char **out);

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
 * The reading every location key is made by: path_input_locate is this function
 * and a copy, and everything that keys from an argument — the resolver's own
 * filesystem arm, add's grammar, the two binders, `ignore --test`, the completion,
 * a glob's anchor — goes through that door. A target given as an absolute or
 * tilde path is the user's own; one given relatively is spelled by the rule above
 * like any other relative argument. Storage-path inputs ("home/", "root/",
 * "custom/") are not this function's — they are validated and placed at the call
 * site (infra/label.h label_validate_storage, infra/mount.h mount_resolve). add's
 * re-rooting under --target is add's own grammar, spelled around the door
 * (cmds/add.c, spell_argument).
 *
 * The answer is malloc's, and one reader wants it that way: the interactive save's
 * per-edit target (cmds/interactive.c), replaced on every commit of the prompt
 * and freed with the item it is on — which an arena cannot do. A reader that
 * keys from the answer is path_input_locate's, not this function's.
 *
 * @param input User-provided path (filesystem or tilde; must not be NULL)
 * @param out   Normalized absolute path (caller must free, must not be NULL)
 * @return Error or NULL on success
 */
error_t *path_input_normalize(const char *input, char **out);

#endif /* DOTTA_PATH_H */
