/**
 * label.h - The grammar of a storage name
 *
 * A profile names what it holds portably: `<label>/<tail>`, the label one of
 * three words and the tail a relative path with no traversal in it. The label
 * says which namespace the name is in — home/ under the invoker's HOME, root/
 * under `/`, custom/ under the target this machine binds for the profile — and
 * the tail is the name within it, the subject every user-authored pattern is
 * matched against
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
 * the shape rule refuses a malformed name and folds nothing, and the two
 * recognitions read a prefix or a whole word and validate nothing, their domain
 * being any string with NULL in it. No wrapper for a name is stored anywhere:
 * the bytes are the wire form and the authenticated one both, so a split is a
 * value on the stack for one call, refspec_t's shape, never a member.
 *
 * Three verbs pay for that decision. A name is a string of a particular shape
 * and C cannot say so, so label_of, label_tail and label_compose assert what
 * they cannot declare — the two projections where they take a name, the compose
 * where it makes one. The assert is not theatre against an invented bug: this
 * tree holds a bare word in a field typed as a name by design (the health slice's
 * ROOT entry, core/manifest.h), so "looks like a name, is not one" is a real
 * inhabitant here, and one abort per verb is what stands against it where a header
 * sentence is all that otherwise would.
 */

#ifndef DOTTA_LABEL_H
#define DOTTA_LABEL_H

#include <types.h>

/**
 * The three labels — one per namespace a profile names its content under.
 *
 * The vocabulary's one currency: what a reader holds, passes, stores and loops
 * over. A label indexes (the sheet's roots, a receipt's counts) and costs nothing
 * to keep. Its word is read from label_words where a string is printed, written
 * or matched, and parsed back into a label where a document, a tree or an argument
 * is read (label_parse, label_of). No reader holds a label's word in a label's
 * place: the word is `label_words[label]` at the point of use.
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
 * The labels' arity, for a walk over them (cmds/add.c's receipt, the sheet's
 * writer, the view's contribution) and for an array with one slot per label (the
 * sheet's roots, the receipt's counts). A macro, not an enumerator, so the type
 * holds no sentinel: every label_t a reader holds subscripts label_words in range.
 */
#define LABEL_COUNT (LABEL_CUSTOM + 1)

/**
 * The word of each label — "home", "root", "custom".
 *
 * Read where a string is printed, written or matched. Static, and outliving every
 * arena, which is what lets a word read from here be kept without a copy (the
 * view's health slice, core/manifest.h). The sheet writes its `roots` array in
 * this order under a claim of byte-determinism, so the order is persisted: a
 * permutation rewrites every sheet that scans two roots (core/metadata.c
 * metadata_to_json).
 */
extern const char *const label_words[LABEL_COUNT];

/**
 * A string split at its label.
 *
 * `tail` is NULL when no label prefixes the string — the whole verdict, for a
 * caller asking a string what it is — and `label` is then unread, holding the
 * zero the answer was built from (gitignore_match_t's shape: one field gates
 * its siblings). "" is a tail: a label spelled as a directory ("home/") stands
 * under its label with nothing past it, and "home//" is a tail of separators.
 * Nothing here folds — a caller that reads a directory spelling as the label
 * alone sheds its own separators first (infra/path.c) — and the tail aliases
 * the input, so the two share a lifetime.
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
 *   "/abs/path"      -> { .tail = NULL }
 *   "home"           -> { .tail = NULL }
 *   NULL             -> { .tail = NULL }
 *
 * Walks label_words, so the label set has one home — adding a fourth needs no
 * edit here.
 *
 * @param s Any string, or NULL
 * @return The split; `tail` NULL when no label prefixes `s`
 */
label_split_t label_split(const char *s);

/**
 * Does `s` stand under a label — "home/…", "root/…", "custom/…"?
 *
 * The prefix and its separator, nothing of the tail: the question any string
 * may be asked, NULL included, where the two projections beneath it ask for a
 * path that passed this one. It is the content gate every walk over a profile
 * tree asks of its own walk root — a managed path stands under a label, so a
 * blob at the branch root, or beneath a tree no label names, is the branch's
 * own machinery: dotta's files (.dottaignore, .bootstrap, .dotta/) and whatever
 * else a hand or a tool left beside them. Nothing else distinguishes them, and
 * nothing needs to: a branch may hold what it likes next to the labels, and no
 * walk of content sees it. A caller *handed* such a name rather than finding it
 * refuses in its own words — export's name arm, which takes a label as a key
 * and meets whatever stands there (cmds/export.c). And it is the shape dispatch
 * on an argument, which reads a storage shape before the filesystem shapes. A
 * label alone, with no separator, stands under none: that is the whole-word
 * question, label_parse, and a caller wanting either asks both (cmds/export.c's
 * grammar). A label spelled as a directory does stand under one — "custom/" is
 * the label and an empty tail — so a gate meant to catch a label asks it of the
 * word.
 *
 * Readers: the view's claim routine (core/manifest.c), the file listing and the
 * branch statistics (core/profiles.c), the refspec completion (cmds/completion.c),
 * diff's delta selection (cmds/diff.c), the rule compiler (infra/pathspec.c),
 * the resolver's storage arm and the question its neighbour asks of a positional
 * whose slot is undecided (infra/path.c path_input_resolve,
 * path_input_announces_path), the two input heads that dispatch on shape before
 * reading it (cmds/add.c, cmds/ignore.c) and export's two — its profile slot's
 * own grammar, and the gate its name arm asks of the key it is handed
 * (cmds/export.c).
 */
bool label_prefixes(const char *s);

/**
 * The label of a storage path: which namespace it names.
 *
 * `storage_path` stands under a label (label_prefixes) — the whole precondition,
 * and every reader holds a path that does: a name the namer composed beneath a
 * root's label (core/manifest.h manifest_name), a row's or a record's, validated
 * where the branch or the sheet was read (label_validate_storage), or an argument
 * the resolver's first arm dispatched on that very test (infra/path.c). Asserted,
 * never answered: a path under no label is a caller's bug, and no label may stand
 * in for it — least of all LABEL_ROOT in silence.
 *
 * Readers: the ownership captures and the divergence check (core/metadata.c,
 * core/workspace.c); cleanup's relocation hold (core/cleanup.c); add's receipt,
 * counting names by their label (cmds/add.c).
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
 * @param storage_path Storage path, under a label
 * @return Pointer past the label; "" for a label spelled as a directory
 */
const char *label_tail(const char *storage_path);

/**
 * The label a bare word names: "home", "root", "custom" — the whole word.
 *
 * The whole name and not a prefix, which is what tells this apart from
 * label_prefixes: "home/x" names no label here, and "home" stands under no label
 * there. The two are the vocabulary's atoms, and a caller wanting either spells
 * the union at its own site (cmds/export.c's grammar, where a lone positional
 * that is content rather than a profile is one or the other).
 *
 * Writes `*out` and answers true when `word` is a label; false, `*out` untouched,
 * when it is not — an unknown word is the caller's to refuse in its own sentence,
 * the sheet's and export's differing. `out` may be NULL for a caller that asks
 * only whether, and `word` may be NULL, which names nothing. Walks label_words,
 * so a fourth label needs no edit here.
 *
 * Readers: the sheet's parser, one entry of `roots` at a time (core/metadata.c
 * metadata_from_json); and export's three — its bare-word arm, which makes the
 * resolver's key out of the word its own grammar allows, its branch-root walk,
 * where a top-level tree entry is content iff its name is a label, and the catch
 * that reads a lone positional in the profile slot as the user's misuse
 * (cmds/export.c).
 */
bool label_parse(const char *word, label_t *out);

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
 * The order is the sentence's, not the rule's: an empty path and an absolute
 * one are refused in their own words above the label test, which would otherwise
 * answer for them and say the wrong thing.
 *
 * Pure rule check — no filesystem access, no arena, no state.
 *
 * Readers: the four boundaries a name arrives across — a branch's tree at the
 * view's claim routine (core/manifest.c) and at the file listing (core/profiles.c),
 * the sheet's keys (core/metadata.c), export's walk (cmds/export.c) — and the
 * resolver's storage arm, where the name is one the user typed (infra/path.c).
 *
 * @param storage_path Path to validate (must not be NULL)
 * @return Error or NULL when valid
 */
error_t *label_validate_storage(const char *storage_path);

/**
 * The name a label and a tail spell: "<word>/<tail>".
 *
 * The write side of label_split's separator, so the grammar owns both directions
 * of it and no consumer spells the join. `tail` is non-empty — a label alone is
 * no storage name, which the shape rule refuses and which would key a tree entry
 * and seal a blob under a namespace's own word — and a caller holding an empty
 * tail holds a root, whose having no name is its own answer (core/manifest.h
 * manifest_name). Asserted, as the two projections assert the same rule read
 * from the other side.
 *
 * Reader: the last rung of the namer's ascent, which is the one place in the
 * tree a location becomes a name (core/manifest.c manifest_ascend), over the
 * root the table found for it (infra/mount.h mount_root_above).
 *
 * @param arena Arena that owns the answer (must not be NULL)
 * @param label The namespace the name is in
 * @param tail  The name within it (must not be NULL or empty)
 * @return The name, the arena's; NULL on allocation failure
 */
const char *label_compose(arena_t *arena, label_t label, const char *tail);

#endif /* DOTTA_LABEL_H */
