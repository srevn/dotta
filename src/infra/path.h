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
 * A label alone is the third, and it is neither of those two: it keys no path
 * at all but the namespace every name of its kind begins with. It is a key because
 * it can be matched with (every name of that kind is beneath it) and because it
 * is the same word on every machine, which a location and a name are not: a custom/
 * tree bound nowhere here still answers to `custom/`. Where a namespace lands
 * is a root, and a root is a place the table finds for an asker (infra/mount.h)
 * — never a thing a label names, and nothing this module reads.
 *
 * The single chokepoint for input-shape dispatch. It reads the grammar of a name
 * (infra/label.h: label_split, label_validate_storage, label_words) and nothing
 * of the table of roots: no root's spelling is read to make a key and no root's
 * noun to refuse one, so the answer is the argument, HOME and the working directory
 * and nothing else. That is what lets the location door stand beside
 * mount_resolve's join as a producer of one key (infra/mount.h, the four
 * producers), and why no caller hands a topology down to read an argument.
 *
 * Two questions stand before any reading, both over the spelling alone and both
 * the caller's to ask first: whether a positional announces a path at all, where
 * a verb's slot could hold a profile instead (path_input_announces_path), and
 * whether the input is the one shape the resolver has no reading for
 * (path_input_is_bare). Neither resolves anything, and neither is the other's
 * negation.
 */

#ifndef DOTTA_PATH_H
#define DOTTA_PATH_H

#include <types.h>

#include "infra/label.h"

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
 * The third key is a label, which names a namespace and no path in it: a location
 * and a name are this machine's and the profile's, while a label is the same
 * word everywhere. The tag names what was read, as the other two do, and the
 * member is the label itself, the one currency the grammar has (infra/label.h):
 * the verb that matches or prints with it reads its word, `label_words[label]`,
 * and the verb that refuses or indexes with it holds the label as it is. The
 * separator is no part of it: a verb that matches with the key wants the bare
 * prefix, and a verb that prints it adds the '/' its message needs.
 *
 * `location` and `storage_path` are the arena's; `label` is a value.
 */
typedef struct {
    path_key_t key;
    union {
        const char *location;       /* PATH_KEY_LOCATION: absolute, normalized */
        const char *storage_path;   /* PATH_KEY_STORAGE: validated, the directory spelling shed */
        label_t label;              /* PATH_KEY_LABEL: the namespace the label names */
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
 * This and path_input_is_bare are two questions, and not each other's negation.
 * This one is asked before a slot is decided; that one by a caller already holding
 * a path slot, about the one shape the resolver has no reading for. The resolver's
 * own filesystem shape is wider than either — it reads `a/b` as a path, its caller
 * having decided so:
 *
 *   input        announces a path   stands alone   the resolver reads
 *   config       no                 yes            refused
 *   src/config   no                 no             $CWD/src/config
 *   *.conf       yes                yes            refused
 *   ./config     yes                no             $CWD/config
 *   home/x       yes                no             home/x
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
 * Does the input stand alone — a single component with no shape at all?
 *
 * The one input path_input_resolve has no reading for: a word with no separator
 * in it and no leading '/', '~' or '.' announcing a filesystem place. A path
 * shape means a place on this machine at every verb and a label-prefixed one a
 * name in a branch, but a word alone means nothing by itself — a verb's own
 * positional grammar is the only thing that can say what it is, and the resolver
 * stands downstream of every one of them with no sight of which handed it a string.
 * So it refuses a word alone for all of them: a worst case earned by the one
 * slot that can hold a profile — revert's `<file> <commit>`, whose first positional
 * is a file or a profile with nothing to tell them apart — and paid by the slots
 * that cannot, which are most of them.
 *
 * Said here, in the positive, for the caller whose grammar has taken the profile
 * already and has a reading to put in the refusal's place: export's second
 * positional is a name at its branch root — a label and its whole subtree, or
 * machinery it names in its own words (cmds/export.c). A caller with no reading
 * of its own asks nothing here; the refusal is the right answer for it, whatever
 * its slot could hold.
 *
 * A name under a label carries the separator its label ends with, so nothing
 * under one is bare; a label *alone* is, and the caller that has a reading for
 * one says so before it asks here. The empty string is no name and is not bare:
 * the resolver refuses it in its own words, and a caller that hands it on gets
 * that sentence rather than one of its own.
 *
 * Readers: the resolver's own refusal, and export's grammar. A verb that reads
 * a bare word as a path asks nothing here — it goes to path_input_locate, whose
 * grammar has no bare-word refusal to pre-empt (add, the binders, `ignore --test`,
 * the completion).
 *
 * @param input The argument (may be NULL, which stands for nothing)
 * @return true iff the input is a word standing alone
 */
bool path_input_is_bare(const char *input);

/**
 * Read a CLI path argument: the shape dispatch, and nothing else.
 *
 * A storage shape is read in two: the label alone is the namespace itself, which
 * is no storage path (label_validate_storage refuses one) and no location either,
 * a label being the same word on every machine — and anything beneath it is a
 * name, validated and kept as typed. Either way the trailing slash is shed (the
 * UI's listings print directory claims slash-marked, and the filesystem arm sheds
 * its own inside the normalizer; the two surface forms resolve alike). A filesystem
 * shape is located (path_input_locate: tilde, the working directory, `.`/`..`/`//`
 * folded), and that spelling is the key: a location is a string of its own, a
 * link in it a component, so the answer keys against the view's rows by strcmp
 * when it was spelled the way the rows were (infra/mount.h). No profile, no name,
 * no stat, no table: the argument need not exist, and a root named by its own
 * spelling (`~`, a target's path) is a location like any other — a place, where
 * the label of the namespace that lands there names no place at all, and the
 * two are different keys for that reason. The verb that cannot take either refuses
 * it in its own words. A word standing alone is refused (path_input_is_bare),
 * because a caller's path slot may hold a profile and the resolver cannot see
 * whose does: add's grammar reads one as the jail's or the working directory's
 * and reads it through the location door (cmds/add.c spell_argument), and the
 * caller whose slot has taken the profile says so at the predicate.
 *
 *   ~/.bashrc                 -> LOCATION  $HOME/.bashrc    (HOME as the identity spells it)
 *   ./config    (in /etc)     -> LOCATION  /etc/config
 *   .bashrc     (in $HOME)    -> LOCATION  $HOME/.bashrc
 *   ~/link/x    (~/link -> ~/real, bound or not)
 *                             -> LOCATION  $HOME/link/x     (the link is a component)
 *   ~/link/../x               -> LOCATION  $HOME/x          ('..' pops the link's spelling)
 *   ~                         -> LOCATION  $HOME            (a root is a location; the verb decides)
 *   home/.config/nvim/        -> STORAGE   home/.config/nvim
 *   custom/                   -> LABEL     LABEL_CUSTOM     (the namespace, not a path in it)
 *   home/../x                 -> refused   (label_validate_storage)
 *   config                    -> refused   (path_input_is_bare)
 *
 * `*out` is zeroed on entry: after an error it is no answer, and a reader that
 * ignores the error meets a NULL rather than a stale string — the zeroed key is
 * PATH_KEY_LOCATION, whose member is then NULL.
 *
 * Readers, and what each does with a label — a reader not on this list is a bug.
 *
 * A verb that admits only some of the keys says so in a switch at its door, above
 * everything it would open, build or announce under one, and every read below
 * narrows with an `if` that rests on the door. Which keys a verb takes is the
 * verb's fact and not this module's, and a switch is how C states one: that is
 * where -Wswitch owns the completeness claim, so a fourth key becomes a compile
 * error at each verb that has to decide rather than a fallthrough read of a member
 * the tag does not name. Every reader below states its domain that way, the two
 * heads that read the input's shape before the key included: theirs is stated
 * over the keys their own predicate can hand them, and the key it cannot says
 * so in its arm (cmds/add.c, cmds/ignore.c):
 *
 *   - the pathspec's exact entries (infra/pathspec) take one: a label is the
 *     prefix every name of that namespace is beneath, and the entry it makes is
 *     storage-keyed like any name. The anchors of its filesystem-shaped rules
 *     never meet one — the arm that compiles them has already ruled a label out.
 *   - remove (cmds/remove.c) takes one: every claim beneath the label, matched
 *     by name, which is the one form that reaches a profile with no binding here.
 *   - export (cmds/export.c) takes one: the whole tree under the label. It makes
 *     the same key out of a bare label before it asks here, its own grammar having
 *     a reading for a word standing alone where this one has none
 *     (path_input_is_bare).
 *   - show, list and revert (cmds/) each refuse one at their own door, above
 *     the profile question and above anything opened under it: what a label names
 *     is the same on every machine and for every asker, so no profile is read
 *     to say it. The branch namer takes a location and has no label to refuse
 *     (core/profiles.h profile_claim_name), and profile_discover_claims is never
 *     handed one.
 *   - add's storage head (cmds/add.c) refuses one: a label names no path to
 *     capture, and the directory a namespace lands in is named by its own spelling
 *     — `add <p> ~`, `add <p> <target>` — which is add's filesystem head, add's
 *     own grammar spelled around path_input_locate.
 *   - `ignore --test` (cmds/ignore.c) answers one, above the rules and the askers
 *     and once for all of them: a namespace is no subject for a pattern, and no
 *     asker reads that differently. Its location spelling earns a different answer
 *     for a different reason — a place the asker has no name for.
 *
 * @param input User-provided path string (must not be NULL)
 * @param arena Arena that owns the answer's string, where one is copied — a label
 *              answers the vocabulary's own and copies nothing (must not be NULL)
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
 * The refusal a label argument earns from a verb that acts on one path
 *
 *   'custom/' names a namespace, not a path in it: name what is inside it
 *
 * One sentence for the four doors that own it, because it is one fact: the verb
 * was handed a namespace where it wanted a path in one. What each verb then does
 * with the error is its own — returned, or carried to a cleanup label.
 *
 * True on every machine and for every asker, which is what lets it be said with
 * nothing looked up: `label` is a resolve's own answer (path_input_t.label) and
 * the message's word is the grammar's (infra/label.h label_words). Where a
 * namespace lands is a root, a place the table finds for an asker, and a namespace
 * that lands nowhere here is a namespace still — so no table is asked and no
 * profile is named. The refusal a *location* standing at such a place earns is
 * this one's sibling, said of the root the table found and in the root's own
 * noun (infra/mount.h mount_root_refuse): that one names a place and this one a
 * namespace, and they say different things for that reason. The remedy is the
 * same because the mistake is.
 *
 * The separator is the message's and never the key's: a label is carried as the
 * label it is because the verbs that take one match or index with it, and printed
 * slash-marked because that is the one spelling that reaches this key — the
 * vocabulary's word and not the argument's, so `custom///` is refused as `custom/`.
 *
 * One site says this clause with a tail of its own: `ignore --test` answers a
 * label rather than refusing one, --test being a query (cmds/ignore.c).
 *
 * @param label The namespace the argument named
 * @return The refusal; never NULL
 */
error_t *path_input_refuse_label(label_t label);

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
