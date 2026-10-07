/**
 * profiles.h - A profile: what its name says, what it claims at a tree, and the
 * draft of its next commit
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
 * a tree cannot hold, each claim keyed by its kind and its name, so one name
 * may carry a file's item and a directory's. A reader wants the claims, never
 * the two documents: it opens the profile at a tree and asks the handle, which
 * reads that tree's own sheet once, at the first question that needs it. What
 * the handle reads is Git's alone, the tree and its sheet: no view, no record,
 * no disk. A writer wants the claims too: it opens the profile's draft
 * (profile_draft_t) — its next commit, built on a stage (sys/stage.h) — asks
 * the draft's base, the profile at the tree the draft opened at, and edits the
 * draft: never the two documents, which the draft keeps together by the rules
 * its type states. The draft looks at the disk in one place, the way above a
 * file a writer captured from it.
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
 * - a path is a tree or a blob, and the tree is the content authority, so a blob
 *   leaves no room at its name or beneath it: a DIRECTORY item at a blob's name
 *   claims nothing, at the blob or as a directory, and one beneath a blob claims
 *   nothing either — the walk shows no such claim, and profile_contradicted shows
 *   each one; a gitlink, which places nothing on disk, contradicts nothing
 *
 * The agreement rests on the tree Git writes, its names sorted, each held once
 * and none holding a '/' (git fsck's TREE_NOT_SORTED, DUPLICATE_ENTRIES and
 * FULL_PATHNAME, lib/git/fsck.h): a question at one name finds it by a binary
 * search over a tree's names (lib/libgit2/src/libgit2/tree.c
 * git_tree_entry_bypath), and so does the classification of each directory claim,
 * at each rung of its name (git_tree_entry_byname), where the walk's tree half
 * shows every entry as stored. Over a tree a hand wrote otherwise, both can miss
 * a name the walk shows; the decode states it rather than repairs it.
 *
 * Failures are worded here, once, naming the profile: a sheet that will not load
 * in the loader's words (core/metadata.h metadata_load_from_tree); the tree's
 * under "Cannot read profile '%s'" for a walk, and "Cannot read '%s' in profile
 * '%s'" for a question asked at one name — a point question's, or the
 * classification's on the way to a directory claim's name — which names the name
 * it was asked. No reader says the profile again. A removal a profile's draft
 * cannot make is refused in its own document's words (profile_remove), and a
 * name, a capture or a restore it cannot admit under "Cannot stage '%s'"
 * (profile_admit, profile_capture_file, profile_restore_file).
 *
 * Memory: a handle's own, made by profile_open or profile_load and released whole
 * by profile_free: an arena of its own, holding the handle, its copy of the name,
 * the sheet it read, every claim profile_find answers and the name of each blob
 * profile_contradicted names over a claim; and a head profile_load read. Any
 * other tree it is opened at is the caller's, and outlives it. A claim a visitor
 * is shown is lent for its visit; one profile_find answers, for the handle's life.
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

/* A profile's draft takes a capture of a file (infra/content.h) and climbs through
 * a mount table (infra/mount.h), each by pointer; each is named here and defined
 * there. */
typedef struct content_capture content_capture_t;
typedef struct mount_table mount_table_t;

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
 * whether a mode is claimed at all compares with MODE_UNCLAIMED. And one is no
 * row's: `blob_above`, the name of the blob that contradicts a claim
 * profile_contradicted shows — at the claim's name, or at a rung above it — and
 * NULL on every claim the walk shows or profile_find answers, which nothing
 * contradicts.
 *
 * Lent, its strings with it: for the visit that shows it, or, one profile_find
 * answers, for the life of the handle that answered it. One a capture answers
 * is the caller's: its name the one the caller handed, its owner and group in
 * the arena the caller handed (profile_capture_file, profile_capture_directory).
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
    const char *blob_above;     /* The blob at its name or above it: profile_contradicted's alone */
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
 * head, found the same way), cmds/revert.c cmd_revert (its target commit's),
 * cmds/diff.c diff_commit_to_workspace (the commit's), cmds/export.c cmd_export,
 * cmds/show.c cmd_show and cmds/list.c list_file_history (the tree the verb
 * selected), cmds/list.c list_profiles and list_files (the tree of the head each
 * listing read, so what each prints is that commit's); profile_load, at the head
 * it read; and a profile's draft, at the tree its stage opened at — a head, or
 * Git's empty tree (profile_draft_open, profile_draft_orphan).
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
 * and the directory claims a completion offers at a profile's head — export's
 * (cmds/completion.c completion_directories) and remove's own (cmds/remove.c
 * remove_complete).
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
 * Release a handle: its arena — the handle, its name, its sheet and the claims
 * it lent — and a head it loaded
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
 * revert_claim_standing, revert_refuse_second_name and revert_target_claim);
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
 * (profile_holds, profile_find), which read the sheet through it; a profile's
 * draft, which reads it at the open, strictly, and copies it for the commit
 * (profile_draft_open, profile_draft_orphan); cmds/revert.c cmd_revert, which
 * reads its target commit's before any question of it, its failure said as the
 * commit's; cmds/show.c show_file, whose header says what its tolerant read lost;
 * cmds/list.c list_files, whose verbose rows say what its tolerant walk lost;
 * cmds/export.c cmd_export, which says what a tolerant arm's collection lost,
 * once, beside the two arms whose copy came out empty, where the failure is the
 * answer (export_collect_profile, export_collect_storage); and cmds/remove.c
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
 * stands at or above, in key order — the document's as the serializer writes it
 * (core/metadata.h metadata_to_json), whatever a hand spelled — so a reader that
 * keeps the first of two claims at one place keeps the byte-least name's. A name
 * is shown once: a blob, or a directory claim no blob stands at or above. Each
 * directory claim is the one profile_find answers at its name, by the same question
 * asked of it there, so the walk and a question at one name cannot part.
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
 * completion offers export (cmds/completion.c completion_directories, through
 * completion_offer_directory), and those remove's own names would take, before
 * profile_contradicted's (cmds/remove.c remove_complete, through
 * remove_offer_directory); and every claim the profile makes, before
 * profile_contradicted's, through one visitor — the universe a removal's arguments
 * are matched against, read STRICT, and every claim a deletion takes, read TOLERANT
 * (cmds/remove.c remove_list_claims, through remove_collect_claim, for
 * remove_resolve and remove_profile).
 *
 * @param profile Handle (must not be NULL); its sheet is read by the first question
 *                that needs it, a walk or profile_load_sheet
 * @param read The sheet's policy for this walk
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read profile '%s'" — or, on the way to a directory claim's
 *         name, under "Cannot read '%s' in profile '%s'", which needs a store
 *         that changed beneath the walk; or the visitor's, as it made it
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
 * and this, by the one question that classifies it: whether a blob stands at
 * its name or at a rung above it — profile_find's directory claim at that name,
 * none where one does. So a reader asks for the claims that stand, the walk, or
 * for every claim the profile makes, the walk and these; where the classification
 * draws its line moves a claim between the two, never out of the second reader's
 * sight. Each is shown in key order, decoded as the walk would have shown it
 * had no blob stood at or above its name, and with that blob, by its name
 * (blob_above).
 *
 * STRICT: a sheet that will not load is the failure, before any claim is shown.
 * TOLERANT: none is shown past one, the failure kept (profile_load_sheet).
 *
 * Readers: every claim the profile makes, after the walk, through the walk's
 * visitor — the universe a removal's arguments are matched against, read STRICT,
 * and every claim a deletion takes, read TOLERANT (cmds/remove.c
 * remove_list_claims, through remove_collect_claim, for remove_resolve and
 * remove_profile); the directory claims remove's own names would take, read STRICT
 * after the walk (cmds/remove.c remove_complete, through remove_offer_directory);
 * and the tracked claims the view's health names, each with its blob, read STRICT
 * after the walk (core/manifest.c manifest_contribute, through
 * manifest_note_contradicted).
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
 * put_entry refuses the mode) — a verb that acts on one name refuses it by its
 * noun, while a file captured from the disk at its name takes its place, as Git's
 * own add does (profile_capture_file); NOTHING is neither document holding the
 * name.
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
 * profile_entry answers it from the tree alone, and profile_holds gives the tree's
 * answer wherever the tree has one.
 */
typedef struct {
    profile_held_kind_t kind;   /* which of the four stands at the name */
    git_oid oid;                /* the entry's id, zero where the sheet answered */
    git_filemode_t filemode;    /* the entry's mode word, 0 where the sheet answered */
} profile_held_t;

/**
 * What the profile's tree holds at `storage_path`: Git's one-entry rule
 *
 * The tree alone, the sheet never read, in three of the four answers: FILE a
 * blob of any filemode, DIRECTORY a subtree, SUBMODULE a gitlink; and NOTHING,
 * no entry at the name or none to reach it through — a blob or a gitlink above
 * the name leaves nothing there to find (lib/libgit2/src/libgit2/tree.c
 * git_tree_entry_bypath). The payload is the entry's, its id and its mode word,
 * zero beside NOTHING. Three answers read as three: an intermediate subtree that
 * will not load is the failure, never an absence.
 *
 * The question asked where the sheet must not answer: what can stand in a blob's
 * way at a name — a directory claim there never does, giving way to the blob
 * written where it stands and riding it where the tree's own blob contradicts
 * it — and what backs a file, a file claim being a blob, which the tree alone
 * holds.
 *
 * Readers: profile_holds, which asks it first and the sheet on its silence;
 * profile_find, whose file claim is the blob it answers; cmds/revert.c cmd_revert,
 * at the name the restore writes in the head (step 11), the entry's identity
 * what the preview diffs; core/workspace.c workspace_orphan_authority, for a
 * file record, folding a failure to UNVERIFIED; the encryption policy's prior —
 * the blob the profile holds at the name in the tree its draft opened at, judged
 * by its own bytes, and none where no blob stands — at each capture
 * (cmds/update.c update_capture) and in add's decision pass (cmds/add.c cmd_add);
 * and add's held-entry gate before it (cmds/add.c cmd_add), what the profile
 * holds under a name the command chose, a file claim being a blob.
 *
 * @param profile Handle (must not be NULL); its sheet is never read
 * @param storage_path A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"
 */
error_t profile_entry(profile_t *profile, const char *storage_path, profile_held_t *out);

/**
 * What the profile holds at `storage_path`
 *
 * Asked of the two documents in the order the authority rule reads them
 * (core/metadata.h): the tree first (profile_entry), because a name is Git's
 * key and the tree is the content authority, so an entry is the whole answer
 * whatever the sheet says at the name; the sheet on the tree's silence alone —
 * no entry at the name, and no blob above it, which leaves the name no room —
 * for the one claim a tree cannot hold: the directory claim standing at the name,
 * as the walk shows it. A FILE item without a blob claims nothing and answers
 * NOTHING. This is the namespace's question, not the walk's: a gitlink at a
 * directory claim's name answers SUBMODULE where the walk shows the claim, since
 * a gitlink contradicts nothing.
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
 * profile_entry's for the three answers the tree gives, and both are zero exactly
 * where the sheet alone answered. Every reader reads the kind alone, and a reader
 * that wants the entry asks profile_entry. `out` is written on success alone.
 *
 * Readers: the verbs that act on one name — cmds/show.c show_file, cmds/list.c
 * list_file_history (the history's pre-check), cmds/revert.c revert_target_claim
 * — the search by name across the local profiles (cmds/revert.c
 * revert_select_profile), export's name arm, which words a copy with nothing in
 * it by what stands at the name (cmds/export.c export_collect_storage), and
 * remove's directory offer, which offers a claim where no blob stands at its
 * name (cmds/remove.c remove_offer_directory). A reader not on this list is a
 * bug. Four neighbours ask profile_entry instead, the tree alone: revert's read
 * of the head at the name it writes (cmds/revert.c cmd_revert, step 11), where
 * a directory claim is never refused — it gives way to the write where it stands,
 * and rides it where the head's blob contradicts it; the orphan probe's file
 * arm (core/workspace.c workspace_orphan_authority), which asks whether a blob
 * still backs a file record, a subtree and a gitlink standing at a name without
 * making a file claim — its directory arm asking profile_find; the encryption
 * prior of update's captures and of add's decision pass (cmds/update.c
 * update_capture, cmds/add.c cmd_add), a blob's bytes or none; and add's held-entry
 * gate (cmds/add.c cmd_add), a blob at a name the command chose — a gitlink there
 * is no claim, and the capture takes its place without --force.
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
 * claim where a blob stands there (profile_entry), the sheet's FILE item read
 * over it by the walk's own rule, the link rule; a directory claim where the
 * sheet keeps one and no blob stands at the name or above it. A question the
 * tree answers is the tree's — no blob, no file claim; a blob at the name or
 * above it, no directory claim — and reads no sheet. Only an open one does, under
 * `read`: STRICT, a sheet that will not load is the answer's failure; TOLERANT,
 * a file claim stands at its floors and a directory claim is none, as in the
 * walk, the failure kept (profile_load_sheet).
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
 * TOLERANT: the single-file copy, or the copy's root), cmds/revert.c
 * revert_target_claim (a file claim, STRICT: the claim the commit holds, which
 * the restore writes), core/workspace.c workspace_orphan_authority (a directory
 * claim, STRICT: whether the profile still backs an orphan's directory), and a
 * profile's draft at each rung of the way a restore brings back (a directory
 * claim, STRICT, of the commit's profile: profile_restore_file).
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

/**
 * A profile's draft: its next commit, both of its documents in memory (opaque)
 *
 * One profile's next tree, on a stage (sys/stage.h: one ref's next tree, staged
 * in memory), and the sheet that rides it — a stage is Git's, a draft dotta's.
 * Opened at the profile's head (profile_draft_open), or over Git's empty tree
 * for a profile the commit creates (profile_draft_orphan), it holds its stage;
 * the profile at the tree the stage opened at — the base, read and never edited,
 * lent for every question a writer asks before it edits; and the sheet the commit
 * will carry — the base's, copied at the open (core/metadata.h metadata_clone)
 * and edited from then on, so every claim the base lends stands whatever the
 * commit does. A writer asks the base and edits the draft; it never holds the
 * sheet — it hands the draft what it captured from the disk or restores from a
 * commit, and the draft authors the claim — and the draft answers what the base
 * cannot: whether a name a writer chooses before reading it has room beside the
 * names chosen with it (profile_admit), and whether its edits move anything
 * (profile_changed). Every edit keeps the document's rules, stated here once:
 *   - a write touches its own kind: a removal takes its claim — a file's the
 *     blob and the FILE item at its name, a directory's the DIRECTORY item —
 *     never the other kind's at the same name, so a directory claim a removed
 *     blob contradicted stands again, carried, and a FILE item no blob backs
 *     rides a directory captured at its name. The one write across kinds is a
 *     blob's where a directory claim stands, no blob at or above its name in
 *     the base: the blob takes that claim's place, and a claim the base's blob
 *     at the name contradicts rides the write, carried;
 *   - the admission, asked of every blob the commit writes, a capture's and a
 *     restore's, and of every name a writer chooses before it reads a byte
 *     (profile_admit): a blob may stand at a name unless a tracked directory
 *     claim the commit carries stands strictly beneath it, one the base does
 *     not contradict — the sheet's half — and unless the tree has no room,
 *     sys/stage's half (sys/stage.h stage_put, stage_put_blob, stage_admit_blob).
 *     A claim the base holds contradicted is never in the way, so writing again
 *     the blob that contradicts it carries it; nor is a derived claim, which
 *     what anchors it refuses on its own, and the prune takes where nothing does.
 *     A directory admitted is a claim the commit carries from its admission, so
 *     a blob chosen above it later meets it as it meets one the base holds;
 *   - the ancestors: a derived claim exists iff something tracked stands beneath
 *     it, and three edits keep that — the climb, which claims the way to a leaf
 *     from the disk, each rung where its own name resolves
 *     (profile_capture_ancestors); the way a restored file stood on at its commit,
 *     brought back at each rung the base holds nothing at, with no disk read
 *     (profile_restore_file); and the prune, at the commit, of every derived
 *     claim nothing tracked stands beneath any longer (core/profiles.c
 *     profile_prune_ancestors), its key handed to the writer's record phase where
 *     it has one. Revert has none, so a record a rung its commit pruned stood
 *     on is released by the next load, which finds the claim gone
 *     (core/workspace.c workspace_orphan_authority);
 *   - the gate, each document held against the one the draft opened: a commit
 *     no edit of which moved the tree or the sheet makes nothing — no prune, no
 *     save, no commit — so imported redundancy rides a commit and never drives
 *     one; the sheet is saved only where its claims are no longer the base's
 *     (core/metadata.h metadata_same), a hand's spelling kept otherwise; and a
 *     tree equal to the one opened is no commit (sys/stage.h stage_commit).
 *
 * Memory: a handle's own — an arena made at the open, holding the struct, the
 * copy of the base's sheet with every claim an edit writes into it, and the names
 * the climb and the prune spell — released by profile_draft_free with the
 * admission, the base and the stage; the base borrows the stage's tree, and goes
 * before it. What a capture answers is the caller's (profile_claim_t), so the
 * claim outlives the draft that wrote it.
 */
typedef struct profile_draft profile_draft_t;

/**
 * Open a profile's draft at its head
 *
 * The stage at the profile's branch (sys/stage.h stage_open: a branch that does
 * not stand is refused ERR_NOT_FOUND, naming its reference), the base at the
 * tree the stage opened, and the base's sheet read now and strictly: a writer
 * refuses a sheet that will not load before its preview, in the loader's words,
 * where a reader may go on without it.
 *
 * Readers: cmds/add.c cmd_add, for a profile its pre-flight found; cmds/remove.c
 * remove_paths, cmds/revert.c cmd_revert, and cmds/update.c update_execute, one
 * draft for each profile the update visits.
 *
 * @param repo Repository (must not be NULL; borrowed for the draft's life)
 * @param name The profile's name, which its branch is named by (must not be NULL;
 *             copied)
 * @param out The draft (must not be NULL; released by profile_draft_free); NULL
 *            on a failure
 * @return Error or NULL on success
 */
error_t profile_draft_open(git_repository *repo, const char *name, profile_draft_t **out);

/**
 * Open the draft of a profile its commit creates
 *
 * The stage over Git's empty tree (sys/stage.h stage_orphan: a branch that stands
 * is refused ERR_EXISTS, naming its reference), its commit the branch's root;
 * the base a profile with nothing in it — no entry, and an empty sheet, a tree
 * with none holding one (core/metadata.h metadata_load_from_tree) — and that
 * sheet copied. Every rule a commit keeps holds over it as over a head, the gate's
 * included: a first commit whose edits claim nothing in a sheet carries none.
 *
 * Reader: cmds/add.c cmd_add, for a profile its pre-flight found no branch for.
 *
 * @param repo Repository (must not be NULL; borrowed for the draft's life)
 * @param name The profile's name, which its branch will be named by (must not
 *             be NULL; copied)
 * @param out The draft (must not be NULL; released by profile_draft_free); NULL
 *            on a failure
 * @return Error or NULL on success
 */
error_t profile_draft_orphan(git_repository *repo, const char *name, profile_draft_t **out);

/**
 * The profile as the draft opened it: the base, lent until profile_draft_free
 *
 * Readers: cmds/add.c cmd_add, for the view every naming and kind question of
 * the run reads (core/manifest.h manifest_build_profile), the held-entry gate
 * and each file's encryption prior; cmds/remove.c remove_paths, for the claims
 * its arguments are matched against (remove_resolve); cmds/revert.c cmd_revert,
 * for every question of the branch as it stands — the claim standing at a path,
 * a second name, and what the tree holds where the restore writes; and
 * cmds/update.c update_profile, for a capture's prior and the name its seal is
 * keyed by (update_capture).
 *
 * @param draft The draft (must not be NULL)
 * @return The base; never NULL
 */
profile_t *profile_draft_base(const profile_draft_t *draft);

/**
 * Room for a name in the commit, asked before its bytes are read
 *
 * For a writer that chooses several names before it reads any — add, whose
 * arguments and walk can reach one place twice through a link: each is asked of
 * the commit as chosen so far, every name admitted before it recorded, so the
 * names admitted can stand together and not merely each on its own. A blob is
 * asked both halves of the admission (profile_draft_t) — the sheet's, ERR_CONFLICT
 * "Cannot stage '%s': '%s' is a directory profile '%s' claims beneath it", naming
 * the byte-least such claim; then the tree's (sys/stage.h stage_admit_blob:
 * ERR_CONFLICT for a collision or a name Git will not hold, ERR_INVALID_ARG for
 * a shape no tree holds) — and is recorded in the tree as chosen. A directory
 * is asked the tree's half (sys/stage.h stage_admit_subtree: a blob at its name
 * or above it, the opened tree's or one admitted since, leaves it none) and
 * claimed: tracked, in the sheet the commit carries, its attributes left to its
 * capture (profile_capture_directory), so a blob chosen above it later is refused
 * at its own admission. Nothing is read from the disk and nothing written to
 * the object database: a writer that stops after its admissions — a dry run —
 * leaves the repository as it found it.
 *
 * Every admission precedes the commit's edits. The tree's half is asked of the
 * tree the stage opened and the names admitted since, never of the stage's own
 * puts and removals (sys/stage.h stage_admission_t), while the sheet's half reads
 * the copy every edit moves, so the two describe one commit only while a writer
 * chooses all its names before it writes any — as add lists every path before
 * it captures one.
 *
 * Reader: cmds/add.c — its walk (add_collect), which skips a name refused
 * ERR_CONFLICT, and its argument arm (cmd_add), which refuses it.
 *
 * @param draft The draft (must not be NULL)
 * @param kind What would stand at the name: a blob (FILE) or a directory
 * @param storage_path A storage path the writer composed or validated (must not
 *                     be NULL)
 * @return The refusal, naming the obstruction; the run's failure to ask, the
 *         admission's tree or a subtree of the base that will not load; or NULL,
 *         the name admitted
 */
error_t profile_admit(profile_draft_t *draft, path_kind_t kind, const char *storage_path);

/**
 * The claim of `kind` at `storage_path`, gone from the commit
 *
 * FILE: the blob, and the FILE item at its name where one stands — refused in
 * sys/stage's words where the tree holds no entry there (sys/stage.h stage_remove,
 * ERR_NOT_FOUND). DIRECTORY: the DIRECTORY item — refused ERR_NOT_FOUND, "Profile
 * '%s' claims no directory at '%s'", where the sheet holds none. The other kind's
 * claim at the name is never taken, and a refusal leaves the commit as it was.
 *
 * Readers: cmds/add.c cmd_add, the tracked claim its profile's own blob contradicts
 * at a name it captures a file at — the remedy that keeps the file, where the
 * put rule carries the claim; cmds/remove.c remove_paths, each claim its arguments
 * took; and cmds/update.c update_profile, each deletion it commits, by the item's
 * kind.
 *
 * @param draft The draft (must not be NULL)
 * @param kind A file's claim or a directory's
 * @param storage_path A validated storage path (must not be NULL)
 * @return Error or NULL on success
 */
error_t profile_remove(profile_draft_t *draft, path_kind_t kind, const char *storage_path);

/**
 * A file captured from the disk, at its name in the commit: its entry, and its
 * claim off the look
 *
 * The capture is the writer's — the bytes it read, sealed or not, their filemode,
 * the verdict on them and the look they were read with (infra/content.h
 * content_capture_t) — and a sealed one was sealed under `storage_path`: the
 * seal binds the name, so the entry stands at the one it was made under and no
 * other (crypto/cipher.h "Path binding"). In order, each refusal before anything
 * moves:
 *   - the claim off the look (core/metadata.h metadata_capture_file): an owner
 *     or a group this host cannot name, ERR_NOT_FOUND;
 *   - the admission (profile_draft_t): the sheet's half, ERR_CONFLICT "Cannot
 *     stage '%s': '%s' is a directory profile '%s' claims beneath it", naming
 *     the byte-least such claim; then the tree's, the put's own (sys/stage.h
 *     stage_put, ERR_CONFLICT or ERR_INVALID_ARG), which writes the blob only
 *     once it is admitted;
 *   - the put rule at the name: a directory claim standing there gives way, one
 *     the base's blob contradicts rides the write;
 *   - the claim at its own kind, written (core/metadata.h metadata_write_item):
 *     the look's, or — where it claims nothing, a link the invoker owns, which
 *     absence already says — the retire of the FILE item standing there.
 * An entry at the name that makes no claim, a gitlink a hand left, is replaced,
 * as Git's own add replaces one (lib/git/read-cache.c add_to_index,
 * ADD_CACHE_OK_TO_REPLACE). A failure past the put leaves a draft its writer
 * abandons (sys/stage.h).
 *
 * Readers: cmds/add.c add_capture, each file it listed, and cmds/update.c
 * update_profile, each file it captures — where every capture meets its name,
 * and nowhere else, each handing it the name its capture sealed under.
 *
 * @param draft The draft (must not be NULL)
 * @param storage_path The name the entry stands at: a validated storage path,
 *                     and the one a sealed capture was made under (must not be
 *                     NULL)
 * @param capture The capture (must not be NULL; borrowed for the call, its bytes
 *                the caller's to free)
 * @param arena The arena the answer's owner and group are named in (must not be
 *              NULL)
 * @param out The claim the commit now carries at the name, as the walk decodes
 *            it — the blob the put wrote, its type, the claim off the look over
 *            it, its name `storage_path` (must not be NULL; written on success
 *            alone)
 * @return Error or NULL on success
 */
error_t profile_capture_file(
    profile_draft_t *draft,
    const char *storage_path,
    const content_capture_t *capture,
    arena_t *arena,
    profile_claim_t *out
);

/**
 * A directory the profile tracks, captured from the disk: its claim off the look
 *
 * A writer captures a directory only where the profile tracks it — a walk entered
 * it (add), or the claim it refreshes is tracked (update: a derived claim is
 * asked nothing of a look, core/workspace.c workspace_analyze_directory) — so
 * the claim is written tracked, its mode and ownership the look's (core/metadata.h
 * metadata_capture_directory), over the directory claim at the name whatever it
 * said, the one an admission wrote included (profile_admit); a FILE item no blob
 * backs there is the other kind's, and rides. One refusal, before anything moves:
 * an owner or a group this host cannot name, ERR_NOT_FOUND — so a writer may go
 * on without the claim, which stands as it stood. Nothing is asked of the base:
 * a blob another writer committed at the name since the writer read its view
 * leaves the claim written contradicted, carried, and a claim another writer
 * took from there comes back tracked — the window every other edit of that writer
 * reads its view across.
 *
 * Readers: cmds/add.c cmd_add, each directory its walk entered, which refuses
 * the command where the claim cannot be made; and cmds/update.c update_profile,
 * each tracked directory whose look moved, which goes on without it.
 *
 * @param draft The draft (must not be NULL)
 * @param storage_path A validated storage path (must not be NULL)
 * @param st The writer's lstat of the path, a directory's (must not be NULL):
 *           one taken through a link would capture the target's attributes
 * @param arena The arena the answer's owner and group are named in (must not be
 *              NULL)
 * @param out The claim, as the walk decodes a directory claim — tracked, the look's
 *            mode and ownership, its name `storage_path` (must not be NULL;
 *            written on success alone)
 * @return Error or NULL on success
 */
error_t profile_capture_directory(
    profile_draft_t *draft,
    const char *storage_path,
    const struct stat *st,
    arena_t *arena,
    profile_claim_t *out
);

/**
 * The way to a leaf, claimed from the disk
 *
 * The sheet's completeness rule for the chain: every rung between the label's
 * word and the leaf that is a real directory right now claims the attributes it
 * has, derived — the profile passes through it and does not track it, so the
 * claim binds only dotta's own creation of that path (core/deploy.c, the ancestors'
 * pass). The rungs are the separators of the label's tail, so the word is never
 * one, nor the leaf, which is its own capture's business. Each stands where its
 * own name resolves under `mounts`, the table the leaf was named under: a name
 * is portable and a binding is not, so a rung this machine mounts a root at is
 * claimed like every other — a chain answered the other way leaves a hole no
 * other machine can fill. Per rung, root-first, by what stands there now:
 *   - a tracked claim standing at it is the walk's own word, left exactly as it
 *     is, and the climb goes on past it, a tracked claim saying nothing of the
 *     rungs above it;
 *   - a FILE item at it is the other kind's, residue no blob backs, carried as
 *     every write carries it, and the rung is claimed beside it;
 *   - a directory claims its attributes, counted in `captured` only where the
 *     claim moved, so a re-derivation that found nothing new rewrites nothing
 *     and drives no commit;
 *   - anything else retires a standing derived claim there, its key appended to
 *     `retired`;
 *   - no answer — an unbound custom/ name, nothing there, nothing this host could
 *     see, an owner it cannot name — leaves the rung as it is: no answer is not
 *     an answer of "no".
 * The two outs are shaped by what a writer can do with them: a claim authored
 * has no consequence beyond the sheet, so its count is the whole report, while
 * a claim retired leaves the view by the commit and its record behind, and only
 * the key names that.
 *
 * Total and idempotent: nothing refuses the climb and no rung stops it, and each
 * climb decides every rung it passes, so a rung two leaves share is decided at
 * each climb through it — again to the same answer where nothing moved between,
 * counting and retiring nothing. A resolve and a look a rung, every climb; the
 * rungs' spellings are the draft's arena's. The one place the draft looks at
 * the disk: the handle reads Git's alone, and the draft, which writes, reads
 * the way off the machine the leaf was captured on.
 *
 * Readers: cmds/add.c cmd_add, each path it captured, under the table it named
 * them under; and cmds/update.c update_profile — each leaf it captured, and each
 * row a named run hands it.
 *
 * @param draft The draft (must not be NULL)
 * @param mounts The table the leaf's name was made under, so a rung resolves
 *               back to where the leaf was read (must not be NULL)
 * @param storage_path The leaf's name, under a label — the vocabulary's
 *                     precondition (infra/label.h label_tail), which every writer
 *                     meets with a name it composed or validated (must not be NULL)
 * @param captured Count of rungs whose claim the climb authored or changed, added
 *                 to (must not be NULL)
 * @param retired Keys the climb retired, appended as copies in the array's arena
 *                (must not be NULL; given its arena by string_array_init)
 */
void profile_capture_ancestors(
    profile_draft_t *draft,
    const mount_table_t *mounts,
    const char *storage_path,
    size_t *captured,
    string_array_t *retired
);

/**
 * A claim a commit held, restored at its name, with the way the commit stood it on
 *
 * The claim is the write's whole: its name, where the restore writes it; its
 * blob, an id the ODB holds by the commit — a writer that decides before it writes
 * puts
 * the id now and stores the object past its prompt (sys/stage.h stage_put_blob);
 * its type; and what its item carries, the mode, the owner and group, the stamp.
 * In order, each refusal before the sheet moves:
 *   - the admission (profile_draft_t): the sheet's half, ERR_CONFLICT "Cannot
 *     stage '%s': '%s' is a directory profile '%s' claims beneath it", naming
 *     the byte-least such claim; then the tree's, the put's own (sys/stage.h
 *     stage_put_blob, ERR_CONFLICT or ERR_INVALID_ARG), which writes no object;
 *   - the put rule at the name: a directory claim standing there gives way, one
 *     the base's blob contradicts rides the write;
 *   - the way: each rung of the name, paired from the leaf with a rung of
 *     `from_storage_path` — both names place one path, so their tails end alike
 *     — takes `from`'s directory claim at its pair, derived, wherever the base
 *     holds nothing at the rung (profile_holds);
 *   - the claim at its own kind, written (core/metadata.h metadata_write_item):
 *     the claim's, or — where it claims nothing, a link the commit records no
 *     ownership for — the retire of the FILE item standing there.
 * A failure past the put leaves a draft its writer abandons (sys/stage.h).
 *
 * Reader: cmds/revert.c cmd_revert.
 *
 * @param draft The draft (must not be NULL)
 * @param claim The claim the write restores, a blob's (must not be NULL; its
 *              strings borrowed for the call)
 * @param from The profile at the commit the claim came from (must not be NULL;
 *             its sheet read strictly)
 * @param from_storage_path The commit's name for the file, whose rungs the way's
 *                          are paired with (must not be NULL)
 * @return Error or NULL on success
 */
error_t profile_restore_file(
    profile_draft_t *draft,
    const profile_claim_t *claim,
    profile_t *from,
    const char *from_storage_path
);

/**
 * One of dotta's own files, beside the claims
 *
 * A name outside the grammar (infra/label.h label_prefixes), which the decode
 * reads as machinery and no walk of content sees, and never the sheet's directory,
 * which the commit writes at its save: a regular blob of `bytes`, written to
 * the object database at once (sys/stage.h stage_put), so a writer puts it once
 * nothing of its run can still refuse. Either other name is a caller's bug and
 * dies — a claim put here would pass the admission and the put rule by, and a
 * put at the sheet's name would race the commit's own save.
 *
 * Reader: cmds/add.c cmd_add, the ignore template of a profile its commit creates
 * (core/ignore.h ignore_profile_template).
 *
 * @param draft The draft (must not be NULL)
 * @param name The file's name at the tree's root or beneath it, outside the grammar
 *             (must not be NULL)
 * @param bytes Its bytes (may be NULL when size is 0)
 * @param size Byte count
 * @return Error or NULL on success: the put's own (sys/stage.h stage_put)
 */
error_t profile_put_machinery(
    profile_draft_t *draft,
    const char *name,
    const void *bytes,
    size_t size
);

/**
 * Whether the edits so far move the tree or the sheet
 *
 * Each document held against the one the draft opened, by its owner: the sheet
 * claim by claim (core/metadata.h metadata_same), then the tree entry by entry
 * (sys/stage.h stage_changed). A write of what already stands moves nothing, so
 * a writer asks it to learn whether there is anything to do before it shows what
 * it would do; nothing is written, a dry run's question too.
 *
 * Readers: cmds/revert.c cmd_revert, whose "already at target" it answers after
 * the restore; and profile_commit, its gate.
 *
 * @param draft The draft (must not be NULL)
 * @param out Whether either document moved (must not be NULL; written on success
 *            alone)
 * @return Error or NULL on success: the tree's comparison's, which needs a store
 *         that changed beneath the draft
 */
error_t profile_changed(const profile_draft_t *draft, bool *out);

/**
 * The commit
 *
 * Where no edit moved the tree or the sheet (profile_changed), nothing: no prune,
 * no save, no commit. Otherwise the prune, against the index the commit will
 * record, its keys appended to `pruned` where one is given; the sheet saved where
 * its claims are no longer the base's; then one commit (sys/stage.h stage_commit:
 * a tree equal to the opened one is none, and a head another writer moved since
 * the open is refused ERR_CONFLICT). One commit a draft. Whether it landed is
 * answered as sys/stage answers it: false where the gate stops it, and past the
 * gate the tree write's own answer, which an edit the gate saw makes true — it
 * moved a content entry, or a claim, and a sheet whose claims moved spells other
 * bytes.
 *
 * Readers: cmds/add.c add_commit and cmds/update.c update_profile, which keep
 * the prune's keys and read whether the commit landed, so a capture that put
 * back what the profile holds commits nothing — add says so, and update neither
 * reports nor records it; cmds/remove.c remove_paths, which keeps the keys; and
 * cmds/revert.c cmd_revert, which keeps none.
 *
 * @param draft The draft (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out_committed Whether a commit was made (optional, can be NULL; false
 *                      where nothing moved, or on a failure)
 * @param pruned The keys the prune took, appended as copies in the array's arena
 *               (given its arena by string_array_init); NULL where the writer
 *               keeps none, one with no record phase
 * @return Error or NULL on success
 */
error_t profile_commit(
    profile_draft_t *draft,
    const char *message,
    bool *out_committed,
    string_array_t *pruned
);

/**
 * Release the draft — the admission, the copy, the base, its stage and its arena
 * — undoing nothing in the repository (sys/stage.h stage_free)
 *
 * @param draft The draft (NULL is a no-op)
 */
void profile_draft_free(profile_draft_t *draft);

#endif /* DOTTA_PROFILES_H */
