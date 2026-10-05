/**
 * branch.h - A profile's branch, over one tree
 *
 * A profile's branch holds one document in two: the tree — what stands at each
 * name, its bytes and its filemode — and the sheet (core/metadata.h), what the
 * profile claims of a name beyond what a tree can say, and the directories a
 * tree cannot hold. A reader wants the claims, never the two documents: it opens
 * the branch over a tree and asks the handle, which reads that tree's own sheet
 * once, at the first question that needs it.
 *
 * The decode, stated once, applied by the walk to every name it meets (branch_walk)
 * and by branch_find to the one it is asked, by the same rules — so the claim
 * branch_find answers at a name is the one the walk shows there:
 * - a name in the grammar is content and nothing else is: dotta's own files and
 *   whatever a hand left beside the labels are machinery, skipped, a tree of it
 *   with everything beneath (infra/label.h label_prefixes)
 * - a blob of any filemode is a claim, its type the filemode's; a tree is the
 *   way to what lies beneath it; a gitlink is nothing — dotta writes none, and
 *   it places nothing on disk
 * - a name in the tree is Git's, not this machine's, so its shape is checked
 *   where it is read (infra/label.h label_validate_storage): one outside the
 *   grammar is the branch's failure, never a claim
 * - a blob takes the sheet's FILE item at its name — the mode, the owner and
 *   group, the seal's stamp — but what a link cannot carry: no mode (symlink(2)
 *   takes none), no stamp (a link's bytes are its target)
 * - a path is a tree or a blob, and the tree is the content authority: a DIRECTORY
 *   item at a blob's name claims nothing, at the blob or as a directory
 *
 * Failures are worded here, once, naming the profile: a sheet that will not load
 * in the loader's words (core/metadata.h metadata_load_from_tree); the tree's
 * under "Cannot read profile '%s'" for a walk, and "Cannot read '%s' in profile
 * '%s'" for a point question, which names the name it was asked. No reader says
 * the profile again but one: export's path arm, whose wrap over the view's failure
 * names it in its own words (cmds/export.c collect_filesystem).
 *
 * Memory: a handle's own, made by branch_open or branch_load and released by
 * branch_free. The tree it is opened over is the caller's and outlives it; a
 * tip branch_load read is the handle's. A claim a walk shows is lent for its
 * visit; one branch_find answers, for the handle's life, kept in an arena of
 * the handle's own.
 */

#ifndef DOTTA_BRANCH_H
#define DOTTA_BRANCH_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/**
 * What a profile claims at one name, decoded
 *
 * The row less its placement: the fields are manifest_row_t's, by name, so a
 * reader filling a row from a claim reads one role on both sides — less the
 * filesystem path and the profile, which are where the view places the claim
 * and whose it is (core/manifest.h). One field means something else: `mode` is
 * the sheet's, MODE_UNCLAIMED where none is claimed (core/metadata.h), where
 * the row's is total — branch_claim_mode resolves it, and a reader that asks
 * whether a mode is claimed at all compares with MODE_UNCLAIMED.
 *
 * Lent, its strings with it: for the visit that shows it, or, one branch_find
 * answers, for the life of the handle that answered it.
 */
typedef struct {
    const char *storage_path;   /* The name: a blob's in the tree, a directory's in the sheet */
    path_type_t type;           /* A blob's filemode; DIRECTORY: a sheet item */
    git_oid blob_oid;           /* The tree entry's; zero for a directory */
    mode_t mode;                /* The sheet's claim, or MODE_UNCLAIMED — always on a link */
    const char *owner;          /* The sheet's, or NULL: none named */
    const char *group;          /* The sheet's, or NULL: none named */
    bool encrypted;             /* The seal's stamp; never on a link or a directory */
    bool tracked;               /* A directory's class; false on every blob */
} branch_claim_t;

/**
 * The mode a claim stands for: its own, else its type's floor
 *
 * 0644 for a file, 0755 for an executable, the directory default for a directory
 * (core/metadata.h DIR_MODE_DEFAULT), and 0 on a link, which carries none — the
 * row's don't-care. A claimed 0000 is a claim. The one producer of the floor
 * the view's rows carry (core/manifest.h manifest_row_t, "Totality").
 *
 * Readers: core/manifest.c manifest_place_claim. cmds/export.c export_entry_mode
 * spells the same rule a second time over a raw item, and says so.
 *
 * @param claim A decoded claim (must not be NULL)
 * @return The mode the claim stands for
 */
mode_t branch_claim_mode(const branch_claim_t *claim);

/**
 * A profile's branch over one tree (opaque)
 *
 * The tree, the profile whose claims it holds, and the sheet read from it at
 * the first question that needs it — kept, or its failure kept, for every question
 * after — and the claims it lends (branch_find), kept until it is released.
 */
typedef struct branch branch_t;

/**
 * A profile's branch over a tree the caller holds
 *
 * Any tree, and it outlives the handle: a tip, a commit's, a stage's, Git's empty
 * tree. `profile` names whose claims these are, since a tree carries no name.
 * Reads nothing — the sheet waits for the first question that needs it — so the
 * open cannot fail.
 *
 * Readers: core/manifest.c manifest_build (each enabled tip gitops_branch_tree
 * found), cmds/add.c cmd_add and cmds/revert.c cmd_revert (the tree a stage opened
 * at, and revert's target commit's), cmds/diff.c diff_commit_to_workspace (the
 * commit's), cmds/export.c cmd_export, cmds/show.c cmd_show and cmds/list.c
 * list_file_history (the tree the verb selected); and branch_load, over the tip
 * it read.
 *
 * @param repo The repository the sheet's blob is read through (must not be NULL;
 *             borrowed)
 * @param profile Whose claims these are (must not be NULL; copied)
 * @param tree The tree (must not be NULL; borrowed, and outlives the handle)
 * @return The handle (released by branch_free); never NULL
 */
branch_t *branch_open(git_repository *repo, const char *profile, const git_tree *tree);

/**
 * A profile's branch at its tip, where the reader needs the branch to stand
 *
 * branch_open over the tip gitops_load_branch_tree reads, the tree the handle's
 * own. A branch that does not stand is refused in gitops' words (sys/gitops.h,
 * ERR_NOT_FOUND naming the reference), never answered empty; nothing is said
 * over them, the reference naming the branch. A reader for whom the absence is
 * an answer reads gitops_branch_tree and opens over what it finds (core/manifest.c
 * manifest_build).
 *
 * Readers: core/profiles.c profile_needs_target, profile_build_filesystem_index,
 * claim_by_filesystem_path and claim_by_name; cmds/ignore.c ignore_test.
 *
 * @param repo Repository (must not be NULL; borrowed)
 * @param profile The branch's name, and whose claims these are (must not be NULL;
 *                copied)
 * @param out The handle (must not be NULL; released by branch_free); NULL on a
 *            failure
 * @return Error or NULL on success
 */
error_t branch_load(git_repository *repo, const char *profile, branch_t **out);

/**
 * Release a handle: its sheet, the claims it lent, its copy of the name, and a
 * tip it loaded
 *
 * @param branch Handle (NULL is a no-op)
 */
void branch_free(branch_t *branch);

/**
 * Whose claims these are: the name the handle was opened under
 *
 * Readers: core/manifest.c manifest_contribute, which names a contribution's
 * rows by it, and the helpers that hold a branch and ask its view by profile or
 * word a refusal under it (core/profiles.c profile_claim_name, cmds/export.c
 * collect_filesystem, cmds/revert.c claim_standing, refuse_second_name and
 * entry_to_restore); and cmds/show.c show_file, whose bytes the profile's key
 * opens and whose warning names it.
 *
 * @param branch Handle (must not be NULL)
 * @return The handle's copy; valid until branch_free
 */
const char *branch_profile(const branch_t *branch);

/**
 * How a question reads a sheet that will not load
 *
 * Spelled at every question a tolerant reader could answer, STRICT included:
 * whether a reader may go on without the sheet's half is its own decision about
 * its own output, never a default. A tolerant reader that says what its read
 * lost asks branch_sheet_failure. branch_holds spells none: whether the sheet
 * alone holds a claim at a name is a question only the sheet answers, so its
 * failure is that answer's.
 */
typedef enum {
    BRANCH_READ_STRICT,     /* the sheet's failure is the question's */
    BRANCH_READ_TOLERANT    /* the tree's half answers; the sheet's failure is kept */
} branch_read_t;

/**
 * A walk's visitor: one decoded claim, lent for the call, and the caller's payload,
 * untouched. Its failure ends the walk and is the walk's answer, as it made it.
 */
typedef error_t (*branch_visit_fn)(const branch_claim_t *claim, void *payload);

/**
 * The branch's claims, decoded, shown to a visitor — every claim it makes but
 * those its own tree contradicts
 *
 * The blobs first, in the tree's pre-order; then the directory claims no blob
 * stands at the name of, in the sheet's own order — so a reader that keeps the
 * first of two claims at one place keeps the sheet's first, and that order is
 * the document's: the writer sorts by key (core/metadata.c metadata_to_json), a
 * hand may not. A name is shown once: a blob, or a directory claim no blob stands
 * at.
 *
 * STRICT: a sheet that will not load is the walk's failure, before any claim is
 * shown. TOLERANT: the walk shows the tree's claims at their floors — no mode,
 * owner or stamp claimed — and no directory claim, the sheet's half alone lost,
 * and branch_sheet_failure says why. A tree that will not read is the walk's
 * failure under either.
 *
 * Readers: core/manifest.c manifest_contribute.
 *
 * @param branch Handle (must not be NULL); its sheet is read by the first question
 *               that needs it, a walk or branch_sheet_failure
 * @param read The sheet's policy for this walk
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read profile '%s'"; or the visitor's, as it made it
 */
error_t branch_walk(
    branch_t *branch,
    branch_read_t read,
    branch_visit_fn visit,
    void *payload
);

/**
 * What stands at one name: the four things a branch can hold there
 *
 * Three of the tree's entry kinds, and the one claim a tree cannot hold. FILE
 * is any blob — bytes, an executable, a link's target — the filemode beside it
 * saying which; DIRECTORY is a subtree, or a directory claim the sheet alone
 * holds (a tracked directory with nothing beneath it, an ancestor chain the tree
 * no longer has); SUBMODULE is a gitlink, which dotta never writes (sys/stage.c
 * put_entry refuses the mode) and every verb refuses by its noun; NOTHING is
 * neither document holding the name.
 */
typedef enum {
    BRANCH_HELD_NOTHING,       /* neither document holds the name */
    BRANCH_HELD_FILE,          /* the tree: a blob, of any filemode */
    BRANCH_HELD_DIRECTORY,     /* the tree: a subtree, or the sheet alone: a claim */
    BRANCH_HELD_SUBMODULE,     /* the tree: a gitlink */
} branch_held_kind_t;

/**
 * The answer whole: which of the four, and for the tree's entries the two facts
 * a verb reads off one, by value — so no entry outlives the call that read it.
 */
typedef struct {
    branch_held_kind_t kind;   /* which of the four stands at the name */
    git_oid oid;               /* the entry's id, zero where the sheet answered */
    git_filemode_t filemode;   /* the entry's mode word, 0 where the sheet answered */
} branch_held_t;

/**
 * What the branch holds at `name`
 *
 * Asked of the two documents in the order the authority rule reads them
 * (core/metadata.h): the tree first, because a name is Git's key and the tree
 * is the content authority, so an entry is the whole answer whatever the sheet
 * says at the name; the sheet on the tree's silence alone, for the one claim a
 * tree cannot hold — the directory claim standing at the name, as the walk shows
 * it. A FILE item without a blob claims nothing and answers NOTHING. This is
 * the namespace's question, not the walk's: a gitlink at a directory claim's
 * name answers SUBMODULE where the walk shows the claim, since a gitlink
 * contradicts nothing.
 *
 * Strict, with no policy to spell: whether the sheet alone holds a claim at a
 * name is a question only the sheet answers, so a sheet that will not load is
 * this answer's failure wherever the tree is silent — dotta cannot then say whether
 * the branch holds the name — and it is never read where the tree speaks. A tree
 * without a sheet holds an empty one (core/metadata.h metadata_load_from_tree),
 * so a branch that never wrote one answers NOTHING there, not an error.
 *
 * The payload is the tree's entry and only the tree's: `oid` and `filemode` are
 * that entry's for the three answers the tree gives, and both are zero exactly
 * where the sheet alone answered. That convention has one reader, export's name
 * arm, which tells a subtree from a claim the sheet alone holds by it
 * (core/profiles.h profile_holds, cmds/export.c collect_storage); revert's restore
 * reads the entry of a FILE answer, which the tree always gave (cmds/revert.c
 * cmd_revert, step 8). `out` is written on success alone.
 *
 * Readers: the verbs that act on one name — cmds/show.c show_file, cmds/list.c
 * list_file_history (the history's pre-check), cmds/revert.c entry_to_restore —
 * and the search by name across the local branches (core/profiles.c claim_by_name).
 * Export's name arm asks core/profiles.h profile_holds instead, over the sheet
 * it read tolerantly. A reader not on this list is a bug. Three neighbours ask
 * another question and are not readers: revert's read of the tip at the name it
 * writes (cmds/revert.c cmd_revert, step 11) asks Git's one-entry rule, which
 * the sheet must not answer — a directory claim there is retired by the write,
 * not refused; the orphan probe (core/workspace.c workspace_orphan_authority)
 * asks whether the branch holds the claim a record remembers, which a subtree
 * and a gitlink stand at a name without making — the tree first, as here, and
 * the sheet only for a directory the tree holds no blob for — and folds every
 * failure to UNVERIFIED; and the count's staleness probe and export's claim append
 * (core/profiles.c profile_get_tree_stats, cmds/export.c append_claim_dirs) hold
 * the sheet's item and ask whether the tree contradicts it, which is the
 * enumeration's question (core/branch.c branch_walk's contradiction index).
 *
 * @param branch Handle (must not be NULL); its sheet is read only where the tree
 *               is silent
 * @param name A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's, in the loader's words
 */
error_t branch_holds(branch_t *branch, const char *name, branch_held_t *out);

/**
 * The claim of `kind` the branch makes at `name`, decoded, or NULL
 *
 * The claim branch_walk shows at the name, asked of that name alone: a file claim
 * where a blob stands there, the sheet's FILE item read over it by the walk's
 * own rules — the link rule, and a DIRECTORY item at a blob's name claiming nothing
 * at the blob; a directory claim where the sheet keeps one and no blob stands
 * at the name. A question the tree answers is the tree's — no blob, no file claim;
 * a blob, no directory claim — and reads no sheet. Only an open one does, under
 * `read`: STRICT, a sheet that will not load is the answer's failure; TOLERANT,
 * a file claim stands at its floors and a directory claim is none, as in the
 * walk, the failure kept (branch_sheet_failure).
 *
 * `name` is a validated storage path. The walk checks the shape of every name
 * it meets, because Git's names arrive unchecked; a point question trusts the
 * one it is handed, checked where it was read (infra/path.h path_input_resolve).
 *
 * Lent for the handle's life, kept in an arena of the handle's own; its strings
 * are the sheet's, or the handle's copy of the name.
 *
 * Readers: cmds/show.c show_file (a file claim, TOLERANT: the header).
 *
 * @param branch Handle (must not be NULL)
 * @param read The sheet's policy for this question
 * @param kind A file's claim or a directory's
 * @param name A validated storage path (must not be NULL)
 * @param out The claim, or NULL where the branch makes none of that kind there
 *            (must not be NULL; NULL after an error)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's (STRICT), in the loader's words
 */
error_t branch_find(
    branch_t *branch,
    branch_read_t read,
    path_kind_t kind,
    const char *name,
    const branch_claim_t **out
);

/**
 * Why the sheet will not load, or NULL where it does
 *
 * Loads it at the first ask and answers the same failure from then on — minted
 * once and answered again (base/error.h "Lifetime") — so a reader that went on
 * without it can say what its read lost, once. A tree that holds no sheet holds
 * an empty one, which is no failure (core/metadata.h metadata_load_from_tree).
 *
 * Readers: branch_walk and the point questions (branch_holds, branch_find), which
 * read the sheet through it; and cmds/show.c show_file, whose header says what
 * its tolerant read lost.
 *
 * @param branch Handle (must not be NULL)
 * @return The sheet's failure, in the loader's words, or NULL
 */
error_t branch_sheet_failure(branch_t *branch);

#endif /* DOTTA_BRANCH_H */
