/**
 * label.h - The grammar of a storage name
 *
 * A profile names what it holds portably: `<label>/<tail>`, the label one of
 * three words and the tail a relative path with no traversal in it — or the label
 * alone, which names the namespace's own directory and is a name like any other.
 * The label says which namespace the name is in — home/ under the invoker's HOME,
 * root/ under `/`, custom/ under the target this machine binds for the profile
 * — and the tail is the name within it, the subject every user-authored pattern
 * is matched against
 * (core/ignore.h). Where a namespace lands on a machine is infra/mount's table;
 * what a claim under a label says about its path is the sheet's (core/metadata.h).
 * This module is the words and the shape alone: no table, no arena beyond the
 * one compose, no disk, no identity.
 *
 * A name that arrives from outside this process — a blob a tree holds, a key a
 * sheet writes, an argument a user types — becomes a name here and nowhere else.
 * label_validate_storage is that boundary: traversal is refused at it and trusted
 * below (infra/mount.h), and its four tree-and-sheet readers are the whole reason
 * every verb beneath may join a tail onto a root's spelling without looking.
 * The bytes of a name are the cipher's associated data (crypto/cipher.h), so
 * the shape rule refuses a malformed name and folds nothing, and the one
 * recognition reads a prefix and validates nothing, its domain being any string
 * with NULL in it. No wrapper for a name is stored anywhere: the bytes are the
 * wire form and the authenticated one both, so a split is a value on the stack
 * for one call, refspec_t's shape, never a member.
 *
 * Three verbs pay for that decision. A name is a string of a particular shape
 * and C cannot say so, so label_of, label_tail and label_compose assert what
 * they cannot declare — the two projections where they take a name, the compose
 * where it makes one. A path under no label is a caller's bug, and one abort
 * per verb is what stands against it where a header sentence is all that otherwise
 * would.
 */

#ifndef DOTTA_LABEL_H
#define DOTTA_LABEL_H

#include <types.h>

/**
 * The three labels — one per namespace a profile names its content under.
 *
 * The vocabulary's one currency: what a reader holds, passes, stores and loops
 * over. A label indexes — label_words at every word reader, a receipt's counts
 * at cmds/add.c report_labels — and costs nothing to keep. Its word is read from
 * label_words where a string is printed, written or matched, and read back into
 * a label where a tree or an argument is read (label_split, label_of). No reader
 * holds a label's word in a label's place: the word is `label_words[label]` at
 * the point of use.
 *
 * A fourth label is an enumerator here, an entry in label_words, one more slot
 * in every array sized by LABEL_COUNT, a decision at every reader that derives
 * a consequence from one — and a hand edit to label_validate_storage's sentence,
 * which spells the three words as prose and is the one spelling no array reaches.
 */
typedef enum {
    LABEL_HOME,    /* home/...   -> $HOME/... */
    LABEL_ROOT,    /* root/...   -> /... */
    LABEL_CUSTOM,  /* custom/... -> per-profile deployment target */
} label_t;

/**
 * The labels' arity, for a walk over them (the grammar's own, and cmds/add.c
 * report_labels) and for an array with one slot per label (label_words itself,
 * and that receipt's counts). A macro, not an enumerator, so the type holds no
 * sentinel: every label_t a reader holds subscripts label_words in range.
 */
#define LABEL_COUNT (LABEL_CUSTOM + 1)

/**
 * The word of each label — "home", "root", "custom".
 *
 * Read where a string is printed, written or matched. Static, and outliving every
 * arena, so a word read from here may be kept without a copy. Nothing persists
 * a label's ordinal — the sheet keys by name, the record by path, and the cipher
 * seals the name's own bytes — so the order here is free: a permutation moves
 * one screen, the receipt's label lines, which add prints in it (cmds/add.c
 * report_labels).
 */
extern const char *const label_words[LABEL_COUNT];

/**
 * A string split at its label.
 *
 * `tail` is NULL when no label prefixes the string — the whole verdict, for a
 * caller asking a string what it is — and `label` is then unread, holding the
 * zero the answer was built from (gitignore_match_t's shape: one field gates
 * its siblings). "" is a tail, and two spellings answer with it: the word alone
 * ("home"), which is the key of the namespace's own directory, and the word spelled
 * as a directory ("home/"), which is an input and never a key. Nothing here folds
 * — a caller that reads a directory spelling as the key sheds its own separators
 * first (infra/path.c path_input_resolve), and "home//" is a tail of separators
 * — and the tail aliases the input, so the two share a lifetime.
 */
typedef struct {
    label_t label;       /* Which namespace the string is in */
    const char *tail;    /* Past the label and its '/'; NULL when none prefixes it */
} label_split_t;

/**
 * Split a string at its leading label.
 *
 * Single source of truth for the `home/` | `root/` | `custom/` -> label mapping,
 * and the one walk beneath the string questions below. Total — every string is
 * answered, NULL included:
 *
 *   "home/.bashrc"   -> { LABEL_HOME,   ".bashrc" }
 *   "custom/etc/foo" -> { LABEL_CUSTOM, "etc/foo" }
 *   "home/"          -> { LABEL_HOME,   ""        }
 *   "home"           -> { LABEL_HOME,   ""        }
 *   "/abs/path"      -> { .tail = NULL }
 *   "homework"       -> { .tail = NULL }
 *   NULL             -> { .tail = NULL }
 *
 * Walks label_words, so the label set has one home — adding a fourth needs no
 * edit here.
 *
 * Reader: the one caller that wants both halves. The table's join takes the label
 * to find the asker's root and joins the tail onto its spelling, answering the
 * root's own directory where the tail is empty (infra/mount.c mount_resolve). A
 * caller wanting the verdict and no half of the answer asks label_prefixes, which
 * is this call and one comparison.
 *
 * @param s Any string, or NULL
 * @return The split; `tail` NULL when no label prefixes `s`
 */
label_split_t label_split(const char *s);

/**
 * Is `s` a name in the grammar — "home/…", "root/…", "custom/…", or one of those
 * words alone?
 *
 * The word and its boundary, nothing of the tail: the question any string may
 * be asked, NULL included, where the two projections beneath it ask for a path
 * that passed this one. The word alone is the namespace's own directory and holds
 * what a directory holds, so it is a name like any other and answers true; a
 * word with something else past it ("homework") stands under none. A label spelled
 * as a directory answers true as well — "custom/" is the word and an empty tail
 * — the marker being an input's spelling and never a key's.
 *
 * It is the content gate every walk over a profile tree asks of the name an entry
 * stands at. A managed path is a name in the grammar, so a blob beneath a tree
 * no label names, or one at the branch root under no word, is the branch's own
 * machinery: dotta's files (.dottaignore, .bootstrap, .dotta/) and whatever else
 * a hand or a tool left beside them. Nothing else distinguishes them, and nothing
 * needs to: a branch may hold what it likes next to the labels, and no walk of
 * content sees it.
 *
 * The question reads no further than the name's first component, which is what
 * lets a walk holding no joined name ask it of the walk's root where there is
 * one and of the entry's own name where there is not, and get the joined name's
 * answer: a libgit2 walk root is "" or ends in '/', so a non-empty one carries
 * the whole answer. Where the joined name is the site's own product the gate is
 * asked of the name (core/manifest.c manifest_claim_blob, cmds/export.c
 * collect_tree_callback); where building one is the only thing the gate would
 * pay for, it is asked of the two (core/profiles.c tree_entry_content_path,
 * cmds/completion.c refspec_emit_cb). One reader was always handed the whole
 * name and is the shape the others now take (cmds/diff.c select_delta).
 *
 * And it is the shape dispatch on an argument, which reads a storage shape before
 * the filesystem shapes.
 *
 * Readers: the view's claim routine (core/manifest.c manifest_claim_blob), the
 * file listing and the branch statistics (core/profiles.c tree_entry_content_path),
 * the refspec completion (cmds/completion.c refspec_emit_cb), export's walk
 * (cmds/export.c collect_tree_callback), diff's delta selection (cmds/diff.c
 * select_delta), the rule compiler (infra/pathspec.c compile_rule), the resolver's
 * storage arm and the question its neighbour asks of a positional whose slot is
 * undecided (infra/path.c path_input_resolve, path_input_announces_path), the
 * two input heads that dispatch on shape before reading it (cmds/add.c cmd_add,
 * cmds/ignore.c test_path_ignore) and export's profile slot's own grammar
 * (cmds/export.c export_post_parse).
 */
bool label_prefixes(const char *s);

/**
 * The label of a storage path: which namespace it names.
 *
 * `storage_path` stands under a label (label_prefixes) — the whole precondition,
 * and every reader holds a path that does: a name the namer composed beneath a
 * root's label (core/manifest.h manifest_name), a row's or a record's, validated
 * where the branch or the sheet was read (label_validate_storage), or an argument
 * the resolver's first arm dispatched on that very test (infra/path.c
 * path_input_resolve). Asserted, never answered: a path under no label is a
 * caller's bug, and no label may stand in for it — least of all LABEL_ROOT in
 * silence.
 *
 * Readers: the two that derive a consequence from the namespace, each an exhaustive
 * switch — what the sheet reads into an absent ownership claim (core/metadata.c
 * metadata_ownership) and which rule placed the root a relocated claim lands
 * under (core/workspace.c workspace_add_diverged) — and one that only indexes
 * by it, add's receipt counting names by their label (cmds/add.c report_labels).
 */
label_t label_of(const char *storage_path);

/**
 * Return the mount-relative path: a pointer past the storage label.
 *
 * The subject every user-authored pattern is evaluated against. A pattern — in
 * `.dottaignore`, `[ignore] patterns`, `--exclude`, `auto_encrypt` — is matched
 * against the path relative to its mount root, what a `.gitignore` at `~`, at
 * `/` or at the deployment target would see: `home/.ssh/id_rsa` is matched as
 * `.ssh/id_rsa`, `root/etc/hosts` as `etc/hosts`. Labels are dotta's, never the
 * pattern's, and nothing above the mount root takes part. Paths are resolved
 * through the table (infra/mount.h); patterns are not.
 *
 * Zero allocation; the returned pointer aliases `storage_path` and shares its
 * lifetime. label_of's precondition, asserted the same way: every reader holds
 * a composed or a validated path, and a tail of something that stands under no
 * label is not an answer.
 *
 * Readers: every surface a pattern is evaluated on — the enumeration
 * core/ignore.h's "The subject" describes without naming. The two walks ask of
 * what they found (cmds/add.c is_excluded, core/workspace.c
 * scan_directory_for_untracked), the scope of a row for --exclude (core/scope.c
 * scope_is_excluded), the policy of a name for auto_encrypt (core/policy.c
 * encryption_policy_matches_auto_patterns), and `ignore --test` twice, of its
 * argument and of the name the view gave it (cmds/ignore.c test_path_ignore).
 * One reader counts rather than matches: the climb, whose rungs are the separators
 * in the tail (core/metadata.c metadata_capture_ancestors).
 *
 * @param storage_path Storage path, under a label
 * @return Pointer past the label; "" for the word alone, and for a label spelled
 *         as a directory
 */
const char *label_tail(const char *storage_path);

/**
 * Validate a storage path's syntactic shape.
 *
 * Checks:
 *  - Non-empty
 *  - Starts with "home/", "root/", or "custom/", or is one of those words alone
 *  - Not absolute (no leading '/')
 *  - No "..", ".", or empty component (path traversal)
 *  - No "//" (consecutive slashes)
 *  - No trailing slash: a key never carries the directory marker, the label's
 *    own directory being spelled by the word alone
 *
 * The order is the sentence's, not the rule's: an empty path and an absolute
 * one are refused in their own words above the label test, which would otherwise
 * answer for them and say the wrong thing.
 *
 * Pure rule check — no filesystem access, no arena, no state.
 *
 * Readers: the four boundaries a name arrives across — a branch's tree at the
 * view's claim routine (core/manifest.c manifest_claim_blob) and at the file
 * listing (core/profiles.c tree_entry_content_path), the sheet's keys
 * (core/metadata.c metadata_from_json), export's walk (cmds/export.c
 * collect_tree_callback) — and the resolver's storage arm, where the name is
 * one the user typed (infra/path.c path_input_resolve).
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL when valid
 */
error_t *label_validate_storage(const char *storage_path);

/**
 * The name a label and a tail spell: "<word>/<tail>", or "<word>" alone.
 *
 * The write side of label_split's boundary, so the grammar owns both directions
 * of it and no consumer spells the join: the separator stands iff something stands
 * past the word, and an empty tail spells the word alone — the namespace's own
 * directory, a key like any name. `tail` must not be NULL, asserted as the two
 * projections assert the same rule read from the other side.
 *
 * Reader: the last rung of the namer's ascent, which is the one place in the
 * tree a filesystem path becomes a name (core/manifest.c manifest_ascend), over
 * the root the table found for it (infra/mount.h mount_root_above).
 *
 * @param arena Arena that owns the answer (must not be NULL)
 * @param label The namespace the name is in
 * @param tail  The name within it (must not be NULL; "" spells the word alone)
 * @return The name, the arena's; NULL on allocation failure
 */
const char *label_compose(arena_t *arena, label_t label, const char *tail);

#endif /* DOTTA_LABEL_H */
