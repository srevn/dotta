/**
 * profiles.h - A profile: what its name says, and what it claims at a tree
 *
 * A profile is dotta's: a name, and what it claims at each of its commits. Git
 * keeps it as a branch of the same name (sys/gitops.h gitops_branch_refname),
 * and the name is the key the other stores answer by — the enabled rows
 * (core/state.h), the keys (crypto/keymgr.h). One corner stays open: under
 * `core.precomposeunicode` Git reads a name in decomposed Unicode as its composed
 * form (sys/gitops.h gitops_reference_find), and dotta keeps the spelling a name
 * was typed in, so there one profile can be two keys.
 *
 * At each commit a profile is one document in two: the tree — what stands at
 * each name, its bytes and its filemode — and the sheet (core/metadata.h), what
 * the profile claims of a name beyond what a tree can say, and the directories
 * a tree cannot hold. A reader wants the claims, never the two documents: it
 * opens the profile at a tree and asks the handle, which reads that tree's own
 * sheet once, at the first question that needs it. What the handle reads is Git's
 * alone, the tree and its sheet: no view, no record, no disk.
 *
 * The decode, stated once, applied by the walk to every name it meets
 * (profile_walk) and by profile_find to the one it is asked, by the same rules
 * — so the claim profile_find answers at a name is the one the walk shows there:
 * - a name in the grammar is content and nothing else is: dotta's own files and
 *   whatever a hand left beside the labels are machinery, skipped, a tree of it
 *   with everything beneath (infra/label.h label_prefixes)
 * - a blob of any filemode is a claim, its type the filemode's; a tree is the
 *   way to what lies beneath it; a gitlink is nothing — dotta writes none, and
 *   it places nothing on disk
 * - a name in the tree is Git's, not this machine's, so its shape is checked
 *   where it is read (infra/label.h label_validate_storage): one outside the
 *   grammar is the profile's failure, never a claim
 * - a blob takes the sheet's FILE item at its name — the mode, the owner and
 *   group, the seal's stamp — but what a link cannot carry: no mode (symlink(2)
 *   takes none), no stamp (a link's bytes are its target)
 * - a path is a tree or a blob, and the tree is the content authority: a DIRECTORY
 *   item at a blob's name claims nothing, at the blob or as a directory — the
 *   walk shows no such claim, and profile_contradicted shows each one
 *
 * The agreement rests on the tree Git writes, its names sorted, each held once
 * and none holding a '/' (git fsck's TREE_NOT_SORTED, DUPLICATE_ENTRIES and
 * FULL_PATHNAME, lib/git/fsck.h): a question at one name finds it by a binary
 * search over a tree's names (lib/libgit2/src/libgit2/tree.c
 * git_tree_entry_bypath), and so does the classification of each directory claim,
 * where the walk's tree half shows every entry as stored. Over a tree a hand
 * wrote otherwise, both can miss a name the walk shows; the decode states it
 * rather than repairs it.
 *
 * Failures are worded here, once, naming the profile: a sheet that will not load
 * in the loader's words (core/metadata.h metadata_load_from_tree); the tree's
 * under "Cannot read profile '%s'" for a walk, and "Cannot read '%s' in profile
 * '%s'" for a question asked at one name — a point question's, or the
 * classification's at a directory claim's own — which names the name it was asked.
 * No reader says the profile again.
 *
 * Memory: a handle's own, made by profile_open or profile_load and released whole
 * by profile_free: an arena of its own, holding the handle, its copy of the name
 * and every claim profile_find answers; the sheet it read; and a head profile_load
 * read. Any other tree it is opened at is the caller's, and outlives it. A claim
 * a visitor is shown is lent for its visit; one profile_find answers, for the
 * handle's life.
 *
 * The layering convention, least specific first:
 * 1. global
 * 2. <os> (darwin, linux, freebsd) — the OS's base profile
 * 3. <os>/<variant> (darwin/work, freebsd/services) — its variants
 * 4. hosts/<hostname> — the host's base profile
 * 5. hosts/<hostname>/<variant> (hosts/visavis/github) — its variants
 *
 * A layer is its base or its variants, never both: Git keeps no branch whose
 * name a slash continues beside one of that name, so `darwin` and `darwin/work`
 * cannot both stand (lib/libgit2/src/libgit2/refdb_fs.c reference_path_available).
 * A variant is one level deep, a name with no further slash, and variants are
 * layered in byte order.
 *
 * The convention is a seed, not the precedence. Precedence is this machine's
 * enabled order (enabled_profiles.position, core/state.h): later enabled wins,
 * enable appends, reorder moves, and the repository knows nothing of it. The
 * convention is the order a set the machine enumerated is enabled or run in —
 * detection at clone, and every --all — because such a set has no other; named
 * profiles keep the order they were typed in (profile_order).
 */

#ifndef DOTTA_PROFILES_H
#define DOTTA_PROFILES_H

#include <git2.h>
#include <sys/stat.h>
#include <types.h>

/**
 * The profiles this machine layers, matched by name among those available
 *
 * Its own layers of the convention: "global", where available, then its OS's —
 * the system's name uname gives, lowered — and its host's, hosts/<hostname>,
 * each a base or its variants; answered in the convention's order (profile_order).
 * Names alone: nothing here reads Git, the caller lists what is available. A
 * system call that fails costs its layer, never the answer.
 *
 * Reader: cmds/clone.c cmd_clone, among the branches its fetch brought.
 *
 * @param arena Arena the answer lives in (must not be NULL)
 * @param available The names to match among (must not be NULL)
 * @return The matched names in the convention's order, possibly none
 */
string_array_t profile_detect(arena_t *arena, const string_array_t *available);

/**
 * Order profile names by the layering convention — least specific first.
 *
 *     rank 0   "global"          the universal base
 *     rank 1   everything else   the OS's layer, and any name the other two do
 *                                not take
 *     rank 2   "hosts/..."       the most specific layer
 *
 * Within a rank, byte order on the name. That is a total order on names alone:
 * it needs no machine, so a hub machine enabling every profile and a bare clone
 * enabling the three that match it seed the three in the same relative order.
 *
 * The seed, and nothing after it. A set the machine enumerated has no order of
 * its own, and this is the one it gets: profile_detect returns its answer in
 * it, and every --all — profile enable, clone, bootstrap — sorts its set with
 * it before the loop that enables or runs. A set the user typed keeps the order
 * typed, and once a row exists its position is the machine's: enable appends,
 * reorder moves, and no command sorts an enabled set again.
 *
 * Sorts in place. Stable is not required — the key is total on distinct names,
 * and branch names are distinct.
 *
 * @param names Profile names to order in place (NULL is a no-op)
 */
void profile_order(string_array_t *names);

/**
 * Is there a profile of this name here, or refuse
 *
 * The refusing shape of gitops_branch_exists, for the verbs whose only use of
 * the answer is to stop: NULL iff the profile's branch is here; the lookup's
 * own error when Git could not say, never an absence; otherwise ERR_NOT_FOUND,
 * "Profile '<name>' doesn't exist locally; 'dotta profile fetch <name>' brings
 * it from a remote that holds it".
 *
 * Readers: cmds/ignore.c ignore_test and cmd_ignore (the edit), cmds/bootstrap.c
 * cmd_bootstrap (the names its selection reads), cmds/show.c cmd_show,
 * cmds/export.c cmd_export, cmds/list.c list_files and list_file_history (an
 * explicit profile's), cmds/revert.c revert_select_profile (the -p arm), and
 * core/scope.c scope_build, on its filter's refusal path. A verb that acts on
 * both answers — add (open or create), enable's skip, remove's --force arm,
 * validate's probe, the enabled set resolved without a view (core/scope.c
 * scope_resolve_enabled) — asks gitops_branch_exists itself and reads the bool;
 * the view's build reads gitops_branch_tree, whose absence is its answer
 * (core/manifest.c manifest_build).
 *
 * @param repo Repository (must not be NULL)
 * @param name Profile name (must not be NULL)
 * @return NULL when the profile is here; else the refusal, or Git's error
 */
error_t profile_require(git_repository *repo, const char *name);

/**
 * What a profile claims at one name, decoded
 *
 * The row less its placement: the fields are manifest_row_t's, by name, so a
 * reader filling a row from a claim reads one role on both sides — less the
 * filesystem path and the profile, which are where the view places the claim
 * and whose it is (core/manifest.h). One field means something else: `mode` is
 * the sheet's, MODE_UNCLAIMED where none is claimed (core/metadata.h), where
 * the row's is total — profile_claim_mode resolves it, and a reader that asks
 * whether a mode is claimed at all compares with MODE_UNCLAIMED.
 *
 * Lent, its strings with it: for the visit that shows it, or, one profile_find
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
} profile_claim_t;

/**
 * The mode a claim stands for: its own, else its type's floor
 *
 * 0644 for a file, 0755 for an executable, the directory default for a directory
 * (core/metadata.h DIR_MODE_DEFAULT), and 0 on a link, which carries none — the
 * row's don't-care. A claimed 0000 is a claim. The one producer of the floor
 * the view's rows carry (core/manifest.h manifest_row_t, "Totality").
 *
 * Readers: core/manifest.c manifest_place_claim; and export's projection of a
 * claim and the root its name arm makes (cmds/export.c export_entry_from_claim,
 * export_collect_storage), so the mode an export copies off a claim is the one
 * a row would place.
 *
 * @param claim A decoded claim (must not be NULL)
 * @return The mode the claim stands for
 */
mode_t profile_claim_mode(const profile_claim_t *claim);

/**
 * A profile at one tree (opaque)
 *
 * The tree, the name whose claims it holds, and the sheet read from it at the
 * first question that needs it — kept, or its failure kept, for every question
 * after — and the claims it lends (profile_find), kept until it is released.
 */
typedef struct profile profile_t;

/**
 * A profile at a tree the caller holds
 *
 * Any tree, and it outlives the handle: a head, a commit's, a stage's, Git's
 * empty tree. `name` says whose claims these are, since a tree carries no name;
 * the sheet is read through the repository the tree was read from. Reads nothing
 * — the sheet waits for the first question that needs it — so the open cannot fail.
 *
 * Readers: core/manifest.c manifest_build (each enabled head gitops_branch_tree
 * found) and core/workspace.c workspace_orphan_authority (each orphan's profile's
 * head, found the same way), cmds/add.c cmd_add and cmds/revert.c cmd_revert
 * (the tree a stage opened at, and revert's target commit's), cmds/diff.c
 * diff_commit_to_workspace (the commit's), cmds/export.c cmd_export, cmds/show.c
 * cmd_show and cmds/list.c list_file_history (the tree the verb selected),
 * cmds/list.c list_profiles and list_files (the tree of the head each listing
 * read, so what each prints is that commit's); and profile_load, at the head it
 * read.
 *
 * @param name Whose claims these are (must not be NULL; copied)
 * @param tree The tree (must not be NULL; borrowed, and outlives the handle)
 * @return The handle (released by profile_free); never NULL
 */
profile_t *profile_open(const char *name, const git_tree *tree);

/**
 * A profile at its head, where the reader needs its branch to stand
 *
 * profile_open at the head gitops_load_branch_tree reads, the tree the handle's
 * own. A branch that does not stand is refused in gitops' words (sys/gitops.h,
 * ERR_NOT_FOUND naming the reference), never answered empty; nothing is said
 * over them, the reference naming the branch. A reader for whom the absence is
 * an answer reads gitops_branch_tree and opens the profile at what it finds
 * (core/manifest.c manifest_build, core/workspace.c workspace_orphan_authority).
 *
 * Readers: cmds/remove.c remove_build_filesystem_index and cmds/revert.c
 * revert_select_profile, which load every local profile; cmds/ignore.c ignore_test;
 * the questions asked of a head by name, what it holds and whether it needs a
 * target — cmds/profile.c profile_list and profile_enable, cmds/clone.c cmd_clone,
 * cmds/interactive.c read_targets; what a profile's deletion takes, every claim
 * for its hooks and the counts for its preview (cmds/remove.c remove_profile);
 * and the directory claims a completion offers at a profile's head
 * (cmds/completion.c completion_directories).
 *
 * @param repo Repository (must not be NULL; borrowed)
 * @param name The profile's name, which its branch is named by (must not be NULL;
 *             copied)
 * @param out The handle (must not be NULL; released by profile_free); NULL on a
 *            failure
 * @return Error or NULL on success
 */
error_t profile_load(git_repository *repo, const char *name, profile_t **out);

/**
 * Release a handle: its arena — the handle, its name and the claims it lent —
 * its sheet, and a head it loaded
 *
 * @param profile Handle (NULL is a no-op)
 */
void profile_free(profile_t *profile);

/**
 * Whose claims these are: the name the handle was opened under
 *
 * Readers: core/manifest.c manifest_contribute, which names a contribution's
 * rows by it, and the helpers that hold a profile and ask its view by name or
 * word a refusal under it (cmds/export.c export_collect_profile,
 * export_collect_storage and export_collect_filesystem, cmds/revert.c
 * revert_claim_standing, revert_refuse_second_name and revert_target_entry);
 * and cmds/show.c show_file, whose bytes the profile's key opens and whose warning
 * names it.
 *
 * @param profile Handle (must not be NULL)
 * @return The handle's copy; valid until profile_free
 */
const char *profile_name(const profile_t *profile);

/**
 * How a question reads a sheet that will not load
 *
 * Spelled at every question a tolerant reader could answer, STRICT included:
 * whether a reader may go on without the sheet's half is its own decision about
 * its own output, never a default. A tolerant reader that says what its read
 * lost asks profile_load_sheet. profile_holds spells none: whether the sheet
 * alone holds a claim at a name is a question only the sheet answers, so its
 * failure is that answer's.
 */
typedef enum {
    PROFILE_READ_STRICT,     /* the sheet's failure is the question's */
    PROFILE_READ_TOLERANT    /* the tree's half answers; the sheet's failure is kept */
} profile_read_t;

/**
 * Load the sheet at the first ask: its failure, or NULL where it loads
 *
 * Read once and kept, the sheet or its failure — minted once and answered again
 * (base/error.h "Lifetime") — so a later ask reads nothing, and a reader that
 * went on without the sheet can say what its read lost, once. A tree that holds
 * no sheet holds an empty one, which is no failure (core/metadata.h
 * metadata_load_from_tree).
 *
 * Readers: profile_walk, profile_contradicted and the point questions
 * (profile_holds, profile_find), which read the sheet through it; cmds/show.c
 * show_file, whose header says what its tolerant read lost; cmds/list.c list_files,
 * whose verbose rows say what its tolerant walk lost; cmds/export.c cmd_export,
 * which says what a tolerant arm's collection lost, once, beside the two arms
 * whose copy came out empty, where the failure is the answer
 * (export_collect_profile, export_collect_storage); and cmds/remove.c
 * remove_profile, which says before its preview what its hooks' tolerant list lost.
 *
 * @param profile Handle (must not be NULL)
 * @return The sheet's failure, in the loader's words, or NULL
 */
error_t profile_load_sheet(profile_t *profile);

/**
 * A walk's visitor: one decoded claim, lent for the call, and the caller's payload,
 * untouched. Its failure ends the walk and is the walk's answer, as it made it.
 */
typedef error_t (*profile_visit_fn)(const profile_claim_t *claim, void *payload);

/**
 * The profile's claims, decoded, shown to a visitor — every claim it makes but
 * those its own tree contradicts, which profile_contradicted shows
 *
 * The blobs first, in the tree's pre-order; then the directory claims no blob
 * stands at the name of, in the sheet's own order — so a reader that keeps the
 * first of two claims at one place keeps the sheet's first, and that order is
 * the document's: the writer sorts by key (core/metadata.c metadata_to_json), a
 * hand may not. A name is shown once: a blob, or a directory claim no blob stands
 * at. Each directory claim is the one profile_find answers at its name, by the
 * same question asked of it there, so the walk and a question at one name cannot
 * part.
 *
 * STRICT: a sheet that will not load is the walk's failure, before any claim is
 * shown. TOLERANT: the walk shows the tree's claims at their floors — no mode,
 * owner or stamp claimed — and no directory claim, the sheet's half alone lost,
 * and profile_load_sheet says why. A tree that will not read is the walk's failure
 * under either.
 *
 * Readers: core/manifest.c manifest_contribute; profile_counts, its tally; the
 * labels a profile claims under (profile_needs_target); the bytes a profile line
 * weighs (cmds/list.c list_profiles, through list_size_claim); the file listing's
 * rows, read TOLERANT (cmds/list.c list_files, through list_collect_file);
 * export's whole and name arms, read TOLERANT, the second keeping the claims
 * beneath its name (cmds/export.c export_collect_profile and
 * export_collect_storage, through export_collect_claim); the directory claims a
 * completion offers (cmds/completion.c completion_directories, through
 * completion_offer_directory); and every claim a profile's deletion hands its
 * hooks, read TOLERANT before profile_contradicted (cmds/remove.c remove_profile,
 * through remove_collect_claim).
 *
 * @param profile Handle (must not be NULL); its sheet is read by the first question
 *                that needs it, a walk or profile_load_sheet
 * @param read The sheet's policy for this walk
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read profile '%s'" — or, at a directory claim's own name,
 *         under "Cannot read '%s' in profile '%s'", which needs a store that
 *         changed beneath the walk; or the visitor's, as it made it
 */
error_t profile_walk(
    profile_t *profile,
    profile_read_t read,
    profile_visit_fn visit,
    void *payload
);

/**
 * The directory claims the profile's own tree contradicts, decoded, shown to a
 * visitor — the claims the walk does not show
 *
 * Every DIRECTORY item the sheet holds is shown by exactly one of profile_walk
 * and this, by the one question that classifies it: the directory claim standing
 * at its name, profile_find's — none where a blob stands there. So a reader asks
 * for the claims that stand, the walk, or for every claim the profile makes,
 * the walk and these; where the classification draws its line moves a claim between
 * the two, never out of the second reader's sight. Each is shown in the sheet's
 * own order, decoded as the walk would have shown it had no blob stood at its name.
 *
 * STRICT: a sheet that will not load is the failure, before any claim is shown.
 * TOLERANT: none is shown past one, the failure kept (profile_load_sheet).
 *
 * Readers: every claim a profile's deletion hands its hooks, read TOLERANT after
 * the walk, through the walk's visitor (cmds/remove.c remove_profile, through
 * remove_collect_claim).
 *
 * @param profile Handle (must not be NULL); its sheet read through it
 * @param read The sheet's policy for this question
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read '%s' in profile '%s'", naming the claim's name; or
 *         the visitor's, as it made it
 */
error_t profile_contradicted(
    profile_t *profile,
    profile_read_t read,
    profile_visit_fn visit,
    void *payload
);

/**
 * What a profile holds, counted: the claims its walk shows, by kind
 *
 * Every blob a file, and every tracked directory claim the walk shows a directory.
 * An ancestor claim is the way to content, never content, and counting the spine
 * would inflate the number the screens call "directories" past anything the user
 * named.
 *
 * Counted from the profile, not from the view: the listings that print it name
 * available profiles too, and a profile nothing has enabled owns no rows. Shown
 * the walk's claims, a profile that wins every path it claims counts here as
 * its rows do there. `status -v` counts something else, the view's rows a profile
 * wins (cmds/status.c status_print_profiles): the holds/wins split, and the two
 * are free to disagree (docs/profiles.md).
 *
 * A count reads no blob. The bytes the files stand for are a listing's to fold,
 * beside the rows that must sum to them (cmds/list.c list_size_claim).
 */
typedef struct {
    size_t file_count;        /* The blob claims the walk shows */
    size_t directory_count;   /* The tracked directory claims it shows */
} profile_counts_t;

/**
 * Count what the profile holds, in one walk of its claims
 *
 * Strict, with no policy to spell: whether a profile holds directories is a
 * question only its sheet answers, so a sheet that will not load is the counts'
 * failure and never a profile claiming none — profile_holds spells none for the
 * same reason. A tree that holds no sheet claims no directory, which is no failure
 * (core/metadata.h metadata_load_from_tree). A tree the walk refuses is the counts'
 * failure too, a name outside the grammar among it, never one skipped past. A
 * screen that would rather print than refuse decides that on its own line, as
 * each reader below does.
 *
 * `out` is written once, on success alone: a walk that stopped short leaves it
 * as the caller supplied it, so no screen prints half a count.
 *
 * Readers: the screens that name what a profile holds — `dotta list -v`'s profile
 * rows and the file listing's no-files arm (cmds/list.c list_profiles, list_files),
 * `profile list`'s enabled and available rows (cmds/profile.c profile_list),
 * and the deletion's preview and confirmation (cmds/remove.c remove_profile). A
 * reader not on this list is a bug, and a screen that counts what a profile holds
 * beside this one is the second producer these counts exist to prevent.
 *
 * @param profile Handle (must not be NULL); its sheet read through it
 * @param out The counts (must not be NULL; written on success alone)
 * @return Error or NULL on success: the sheet's, in the loader's words; the tree's,
 *         under "Cannot read profile '%s'"
 */
error_t profile_counts(profile_t *profile, profile_counts_t *out);

/**
 * Does this profile need a deployment target?
 *
 * Definitional, not a rule of its own: the labels its walk shows claims under,
 * each asked of the one table no state row can produce — HOME and the root
 * sentinel, no binding — for the profile's root of it (infra/mount.h
 * mount_root_of). A label with no root there is one only a binding places, so a
 * claim under it is the answer: every home/ and root/ claim has its root there;
 * a custom/ claim — a blob under custom/ or at the word itself, a custom/ item
 * of the sheet, tracked or derived — has none. An empty custom tree needs none,
 * by the same reading: the walk shows no claim in it, and a binding would place
 * nothing for it.
 *
 * It is the view's own answer by another route, and agrees with it by construction:
 * the view's contribution places every claim the same walk shows, and records
 * on the health slice exactly the claims whose label the table has no root of
 * (core/manifest.c manifest_place_claim, through mount_resolve, whose absence
 * is mount_root_of's). So a view built over the profile under that table holds
 * an unbound claim exactly where this says yes (tests/test-profiles.c holds the
 * two together), and none is built here.
 *
 * The profile's fact and not this machine's: asked under a table with no binding
 * so that what the profile needs and what this machine binds are two facts, the
 * first answerable where the second is not in scope (clone holds no state at
 * its skip), and unchanged by a row this machine writes.
 *
 * Complete or an error: a sheet this build cannot read, and a tree the walk refuses
 * — a name outside the storage grammar, a subtree the store lacks — fail here,
 * the failures the next view build over the same profile would fail on, met before
 * `profile enable` writes the row. A profile that will not load is its caller's,
 * which loads it (profile_load). A caller that must not fail whole on one profile
 * absorbs the error and renders the row as unreadable (cmds/interactive.c
 * read_targets), as cmds/profile.c's listing already does for its counts' error.
 *
 * Readers: the three enablers' skip — `profile enable` (cmds/profile.c
 * profile_enable), clone (cmds/clone.c cmd_clone), the editor's OFF→ON gate —
 * the two marks, the listing's available rows and the editor's, and the editor's
 * `t`, live only on a row that can be bound. The listing asks it of the handle
 * its row counted at (cmds/profile.c profile_list); the editor's three read the
 * one answer its rows keep (cmds/interactive.c read_targets). The rule these
 * keep is "a profile that needs a target is not enabled without one", and its
 * scope is theirs alone, not an invariant of the rows: the editor prompts and
 * lets a row be saved unbound (cmds/interactive.c plan_classify says why), add's
 * implicit enable authors no such row (a created profile's custom/ claim requires
 * --target, which the row takes), sync and a re-bind can leave an enabled row
 * needing one, and `profile validate` does not ask — an enabled row with no binding
 * is a lifecycle stage the health channel names, not an inconsistency. add asks
 * no producer: it holds a view over its own opened tree under its own table and
 * reads the slice on that (cmds/add.c add_print_enable).
 *
 * Cost: one walk of the profile — whose sheet a question before it may have parsed
 * already, the handle keeping it — and a two-root table in a frame of the call's
 * own: the product is a bool and nothing outlives the call (include/runtime.h
 * "Memory", no arena in reach). Measured at 0.165.12, a walk past the parse costs
 * about 0.13 µs a claim; the view built here before cost 2.5 ms per 1,000 paths.
 *
 * @param profile Handle, at its head as every reader loads it (must not be NULL;
 *                its sheet read through it)
 * @param needs_target Output flag: the profile holds a claim under a label the
 *                     binding-less table has no root of (must not be NULL; false
 *                     after an error)
 * @return Error or NULL on success: the sheet's, in the loader's words; the tree's,
 *         under "Cannot read profile '%s'"
 */
error_t profile_needs_target(profile_t *profile, bool *needs_target);

/**
 * What stands at one name: the four things a profile can hold there
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
    PROFILE_HELD_NOTHING,       /* neither document holds the name */
    PROFILE_HELD_FILE,          /* the tree: a blob, of any filemode */
    PROFILE_HELD_DIRECTORY,     /* the tree: a subtree, or the sheet alone: a claim */
    PROFILE_HELD_SUBMODULE,     /* the tree: a gitlink */
} profile_held_kind_t;

/**
 * The answer whole: which of the four, and for the tree's entries the two facts
 * a verb reads off one, by value — so no entry outlives the call that read it.
 */
typedef struct {
    profile_held_kind_t kind;   /* which of the four stands at the name */
    git_oid oid;                /* the entry's id, zero where the sheet answered */
    git_filemode_t filemode;    /* the entry's mode word, 0 where the sheet answered */
} profile_held_t;

/**
 * What the profile holds at `storage_path`
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
 * the profile holds the name — and it is never read where the tree speaks. A
 * tree without a sheet holds an empty one (core/metadata.h
 * metadata_load_from_tree), so a profile that never wrote one answers NOTHING
 * there, not an error.
 *
 * The payload is the tree's entry and only the tree's: `oid` and `filemode` are
 * that entry's for the three answers the tree gives, and both are zero exactly
 * where the sheet alone answered. Its one reader is revert's restore, which reads
 * the entry of a FILE answer, which the tree always gave (cmds/revert.c cmd_revert,
 * step 8); every other reader reads the kind alone. `out` is written on success
 * alone.
 *
 * Readers: the verbs that act on one name — cmds/show.c show_file, cmds/list.c
 * list_file_history (the history's pre-check), cmds/revert.c revert_target_entry
 * — the search by name across the local profiles (cmds/revert.c
 * revert_select_profile), and export's name arm, which words a copy with nothing
 * in it by what stands at the name (cmds/export.c export_collect_storage). A
 * reader not on this list is a bug. Two neighbours ask another question and are
 * not readers: revert's read of the head at the name it writes (cmds/revert.c
 * cmd_revert, step 11) asks Git's one-entry rule, which the sheet must not answer
 * — a directory claim there is retired by the write, not refused; and the orphan
 * probe (core/workspace.c workspace_orphan_authority) asks whether the profile
 * holds the claim a record remembers, which a subtree and a gitlink stand at a
 * name without making — profile_find's directory claim for a directory record,
 * and for a file record the tree alone, Git's one-entry rule again — and folds
 * every failure to UNVERIFIED.
 *
 * @param profile Handle (must not be NULL); its sheet is read only where the
 *                tree is silent
 * @param storage_path A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's, in the loader's words
 */
error_t profile_holds(profile_t *profile, const char *storage_path, profile_held_t *out);

/**
 * The claim of `kind` the profile makes at `storage_path`, decoded, or NULL
 *
 * The claim profile_walk shows at the name, asked of that name alone: a file
 * claim where a blob stands there, the sheet's FILE item read over it by the
 * walk's own rules — the link rule, and a DIRECTORY item at a blob's name claiming
 * nothing at the blob; a directory claim where the sheet keeps one and no blob
 * stands at the name. A question the tree answers is the tree's — no blob, no
 * file claim; a blob, no directory claim — and reads no sheet. Only an open one
 * does, under `read`: STRICT, a sheet that will not load is the answer's failure;
 * TOLERANT, a file claim stands at its floors and a directory claim is none, as
 * in the walk, the failure kept (profile_load_sheet).
 *
 * `storage_path` is validated. The walk checks the shape of every name it meets,
 * because Git's names arrive unchecked; a point question trusts the one it is
 * handed, checked where it was read (infra/path.h path_input_resolve) or kept
 * (a record's, which the store holds to the grammar: core/state.h).
 *
 * Lent for the handle's life, kept in its arena; its strings are the sheet's,
 * or the handle's copy of the storage path.
 *
 * Readers: cmds/show.c show_file (a file claim, TOLERANT: the header),
 * cmds/export.c export_collect_storage (a file claim and a directory claim, both
 * TOLERANT: the single-file copy, or the copy's root) and core/workspace.c
 * workspace_orphan_authority (a directory claim, STRICT: whether the profile
 * still backs an orphan's directory).
 *
 * @param profile Handle (must not be NULL)
 * @param read The sheet's policy for this question
 * @param kind A file's claim or a directory's
 * @param storage_path A validated storage path (must not be NULL)
 * @param out The claim, or NULL where the profile makes none of that kind there
 *            (must not be NULL; NULL after an error)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's (STRICT), in the loader's words
 */
error_t profile_find(
    profile_t *profile,
    profile_read_t read,
    path_kind_t kind,
    const char *storage_path,
    const profile_claim_t **out
);

#endif /* DOTTA_PROFILES_H */
