/**
 * profiles.h - A profile: what its name says, what it claims at a commit, and
 * the draft of its next commit
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
 * the two documents: it opens the profile at a commit and asks the handle, which
 * reads the commit's tree at the open and that tree's own sheet once, at the
 * first question that needs it. What the handle reads is Git's alone, the tree
 * and its sheet: no view, no record, no disk. What the profile's history says
 * of a name — whether it left, and what took it — is Git's too, asked at a head
 * and never through the handle (profile_departures). A writer wants the claims
 * too: it opens the profile's draft (profile_draft_t) — its next commit, built
 * on a stage (sys/stage.h) — asks the draft's base, the profile at the tree the
 * draft opened at, and edits the draft: never the two documents, which the draft
 * keeps together by the rules its type states — and a merge of two of its histories
 * is a draft too, its claims composed over the merged tree and every conflict
 * settled at its open (profile_draft_merge). The draft looks at the disk in one
 * place, the way to a leaf — first captured above a file a writer captured from
 * it, and re-derived where a named run's paths reach it — and asks the host twice
 * more: the names of a look's owner and group, where a capture names them
 * (core/metadata.h metadata_capture_file, metadata_capture_directory), and the
 * commit's signature where Git's configuration names none (sys/gitops.h
 * gitops_get_signature).
 *
 * The decode, stated once, applied by the walk to every name it meets
 * (profile_walk) and by profile_find to the one it is asked, by the same rules
 * — so the claim profile_find answers at a name is the one the walk shows there,
 * and the stamp profile_sealed reads the one the walk's claim carries:
 * - a name in the grammar is content and nothing else is: dotta's own files and
 *   whatever a hand left beside the labels are the profile's internal files,
 *   skipped, a tree of them with everything beneath (infra/label.h label_prefixes)
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
 * Failures are worded here, once, naming the profile at the commit it was opened
 * at — the commit unsaid where the handle names none: a merge's two sides, at
 * the trees its stage lends, and a created profile's base, at Git's empty tree
 * (core/profiles.c profile_subject): a sheet that will not load in the loader's
 * words, profile_load_sheet's "Failed to load metadata for profile '%s' at commit
 * %s" over the step that refused (core/metadata.h metadata_load_from_tree); the
 * tree's under "Cannot read profile '%s' at commit %s", the open's and a walk's
 * alike (profile_open, profile_walk), and "Cannot read '%s' in profile '%s' at
 * commit %s" for a question asked at one name — a point question's, or the
 * classification's on the way to a directory claim's name — which names the name
 * it was asked. No reader says the profile or its commit again. A removal a
 * profile's draft cannot make is refused in its own document's words
 * (profile_remove), a name, a capture or a restore it cannot admit under "Cannot
 * stage '%s'" (profile_admit, profile_capture_file, profile_restore_file,
 * profile_restore_directory), and a merge whose conflicts no side settles under
 * "Merging profile '%s' met %zu conflict%s" (profile_draft_merge). A restore's
 * own refusal names the claim by the commit's name for it — "in profile" would
 * read as the head's, which the writer names — beside the name it writes where
 * the two part: "Cannot restore '%s'", "Cannot restore '%s' as '%s'"
 * (profile_restore_file).
 *
 * Memory: a handle's own, made by profile_open or profile_load and released whole
 * by profile_free: an arena of its own, holding the handle, its copy of the name,
 * the sheet it read, every claim profile_find answers and the name of each blob
 * profile_contradicted names over a claim; and the tree its open read. The commit
 * it was opened at is the caller's. A draft's base and a merge's two sides borrow
 * their stage's trees instead, and go before the stage (profile_draft_t). A claim
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

/* A profile's draft renders its commit's message from a writer's words over what
 * the commit changes (infra/commit.h), takes a capture of a file (infra/content.h),
 * has a restored file resealed under its key manager (crypto/keymgr.h), climbs
 * through a mount table (infra/mount.h) and asks a run's path filter
 * (infra/pathspec.h), each by pointer; each is named here and defined there. */
typedef struct commit_changes commit_changes_t;
typedef struct commit_words commit_words_t;
typedef struct content_capture content_capture_t;
typedef struct keymgr keymgr;
typedef struct mount_table mount_table_t;
typedef struct pathspec pathspec_t;

/**
 * The profiles this machine layers, matched by name among those available
 *
 * Its own layers of the convention: "global", where available, then its OS's —
 * the system's name uname gives, lowered — and its host's, hosts/<hostname>,
 * each a base or its variants; answered in the convention's order (profile_order).
 * Names alone: nothing here reads Git, the caller lists what is available. A
 * system call that fails costs its layer, never the answer.
 *
 * Reader: cmds/clone.c select_profiles, among the branches the remote advertises
 * (sys/remote.h remote_branches).
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
 * @param names Profile names to order in place (must not be NULL)
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
 * cmds/export.c cmd_export, cmds/list.c list_files and list_path_history (an
 * explicit profile's), cmds/revert.c cmd_revert (a profile named: a refspec's,
 * -p's, a whole profile's own word), and core/scope.c scope_build, on its filter's
 * refusal path. A verb that acts on both answers — add (open or create), enable's
 * skip, remove's --force arm, the enabled set resolved without a view (core/scope.c
 * scope_resolve_enabled) — asks gitops_branch_exists itself and reads the bool,
 * enable's skip saying the refusal above as its warning (cmds/profile.c
 * profile_enable); the view's build reads gitops_branch_commit, whose absence
 * is its answer (core/manifest.c manifest_build).
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
 * (include/types.h DIR_MODE_DEFAULT), and 0 on a link, which carries none — the
 * row's don't-care. A claimed 0000 is a claim. The one producer of the floor
 * the view's rows carry (core/manifest.h manifest_row_t, "Totality").
 *
 * Readers: core/manifest.c manifest_place_claim; export's projection of a claim
 * and the root its name arm makes (cmds/export.c export_entry_from_claim,
 * export_collect_storage), so the mode an export copies off a claim is the one
 * a row would place; the record a capture's claim builds, a file's and a
 * directory's, add's and update's (cmds/add.c add_capture and cmd_add,
 * cmds/update.c update_profile), so the record holds the mode the row places. A
 * restore writes no floor where its commit claimed no mode: the claim whole,
 * its absence read here wherever it is placed (profile_restore_file).
 *
 * @param claim A decoded claim (must not be NULL)
 * @return The mode the claim stands for
 */
mode_t profile_claim_mode(const profile_claim_t *claim);

/**
 * A profile at a commit (opaque)
 *
 * The commit's tree, the name whose claims it holds, and the sheet read from
 * that tree at the first question that needs it — kept, or its failure kept,
 * for every question after — and the claims it lends (profile_find), kept until
 * it is released.
 */
typedef struct profile profile_t;

/**
 * A profile at a commit
 *
 * The commit's tree, read here and the handle's own, through the commit's own
 * repository; `name` says whose claims these are, since neither the commit nor
 * its tree carries a name. The sheet waits for the first question that needs
 * it, so the tree is all the open reads, and its one refusal: "Cannot read profile
 * '%s' at commit %s", the commit in seven characters as every screen spells one.
 *
 * Readers: core/manifest.c manifest_build (each enabled head gitops_branch_commit
 * found), cmds/revert.c cmd_revert (its target commit), cmds/diff.c
 * diff_commit_to_workspace (the commit the search found), cmds/export.c cmd_export
 * and cmds/show.c cmd_show (the commit a refspec names), cmds/list.c list_profiles,
 * list_files and list_path_history (the head each listing read, so what each
 * prints is that commit's), cmds/completion.c changes_emit (the head a path's
 * changes are walked back from), cmds/remove.c remove_profile (the head its
 * deletion is from: every claim for its hooks, the counts for its preview); and
 * profile_load, at the head it read.
 *
 * @param name Whose claims these are (must not be NULL; copied)
 * @param commit The commit (must not be NULL; borrowed for the call)
 * @param out The handle (must not be NULL; released by profile_free); NULL on a
 *            failure
 * @return Error or NULL on success: the tree's, "Cannot read profile '%s' at
 *         commit %s"
 */
error_t profile_open(const char *name, const git_commit *commit, profile_t **out);

/**
 * A profile at its head, where the reader needs its branch to stand
 *
 * profile_open at the head gitops_load_branch_commit reads. A branch that does
 * not stand is refused in gitops' words (sys/gitops.h, ERR_NOT_FOUND naming the
 * reference), never answered empty; nothing is said over them, the reference
 * naming the branch. The code is the absence's alone — a head that will not read
 * is Git's error — so a reader for whom the absence is an answer takes it off
 * the refusal (cmds/profile.c profile_list, an enabled row's no branch), or reads
 * gitops_branch_commit and opens the profile at what it finds (core/manifest.c
 * manifest_build).
 *
 * Readers: cmds/remove.c remove_overlaps and cmds/revert.c revert_select_profile,
 * which load every local profile; cmds/ignore.c ignore_test; the question asked
 * of a head by name, what it holds — cmds/profile.c profile_list and
 * profile_enable, cmds/clone.c cmd_clone, cmds/interactive.c read_targets,
 * cmds/key.c key_status; the directory claims a completion offers at a profile's
 * head — beside its files (cmds/completion.c completion_directories) and remove's
 * own (cmds/remove.c remove_complete); and the head a verb reads where no commit
 * is named — export's (cmds/export.c cmd_export) and show's, of the profile named
 * or of the one whose row stands at the path (cmds/show.c cmd_show).
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
 * it lent — and the tree its open read
 *
 * @param profile Handle (NULL is a no-op)
 */
void profile_free(profile_t *profile);

/**
 * Whose claims these are: the name the handle was opened under
 *
 * Readers: core/manifest.c manifest_contribute, which names a contribution's
 * rows by it; the name a profile gives a file argument, its own view asked by
 * it (core/scope.c scope_resolve_name); and the helpers that hold a profile and
 * ask its view by name or word a refusal under it (cmds/export.c
 * export_collect_profile, export_collect_storage and export_collect_filesystem,
 * cmds/revert.c revert_select_profile, where it places a typed name and each
 * holder's name for the place); a restore, its two views' asker and the placer
 * of its argument and of each claim (cmds/revert.c revert_restore_path);
 * cmds/show.c show_file, whose bytes the profile's key opens and whose warning
 * names it; remove's universe, whose custom/ claims it places under the profile's
 * binding, and its directory offer, which describes each claim by it (cmds/remove.c
 * remove_list_claims, remove_offer_directory); and update's capture, whose seal
 * the profile's key makes (cmds/update.c update_capture).
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
 * (profile_holds, profile_find, profile_sealed), which read the sheet through
 * it; a profile's draft, which reads it at the open, strictly (profile_draft_seed),
 * and copies it for a writer's commit (profile_draft_open, profile_draft_orphan),
 * or a commit's, whole, for one (profile_restore_tree); a merge, which reads
 * theirs' and the merge base's at its open, strictly, each said by theirs' commit
 * (profile_draft_merge); cmds/show.c show_file, whose header says what its tolerant
 * read lost; cmds/list.c list_files, whose verbose rows say what its tolerant
 * walk lost; cmds/export.c cmd_export, which says what a tolerant arm's collection
 * lost, once, beside the two arms whose copy came out empty, where the failure
 * is the answer (export_collect_profile, export_collect_storage); and cmds/remove.c
 * remove_profile, which says before its preview what its hooks' tolerant list lost.
 *
 * @param profile Handle (must not be NULL)
 * @return The sheet's failure, "Failed to load metadata for profile '%s' at commit
 *         %s" over the step that refused (core/metadata.h metadata_load_from_tree),
 *         or NULL
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
 * bytes a profile line weighs (cmds/list.c list_profiles, through list_size_claim);
 * the file listing's rows, read TOLERANT (cmds/list.c list_files, through
 * list_collect_file); export's whole and name arms, read TOLERANT, the second
 * keeping the claims beneath its name (cmds/export.c export_collect_profile and
 * export_collect_storage, through export_collect_claim); the directory claims a
 * completion offers beside a profile's files (cmds/completion.c
 * completion_directories, through completion_offer_directory), and those remove's
 * completion offers as names, before profile_contradicted's (cmds/remove.c
 * remove_complete, through remove_offer_directory); and every claim the profile
 * makes, a derived one passed by, before profile_contradicted's, through one
 * visitor — the universe a removal's arguments are matched against, read STRICT,
 * and every claim a deletion takes, read TOLERANT (cmds/remove.c
 * remove_list_claims, through remove_collect_claim, for remove_resolve and
 * remove_profile); and every claim of a draft's base a restore may take, before
 * profile_contradicted's, read STRICT (cmds/revert.c revert_restore_path, through
 * revert_take_claim).
 *
 * @param profile Handle (must not be NULL); its sheet is read by the first question
 *                that needs it, a walk or profile_load_sheet
 * @param read The sheet's policy for this walk
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read profile '%s' at commit %s" — or, on the way to a
 *         directory claim's name, under "Cannot read '%s' in profile '%s' at
 *         commit %s", which needs a store that changed beneath the walk; or the
 *         visitor's, as it made it
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
 * visitor, which passes a derived one by — the universe a removal's arguments
 * are matched against, read STRICT, and every claim a deletion takes, read TOLERANT
 * (cmds/remove.c remove_list_claims, through remove_collect_claim, for
 * remove_resolve and remove_profile); the directory claims remove's completion
 * offers as names, read STRICT after the walk (cmds/remove.c remove_complete,
 * through remove_offer_directory); the tracked claims the view's health names,
 * each with its blob, read STRICT after the walk (core/manifest.c
 * manifest_contribute, through manifest_note_claim); and every claim of a draft's
 * base a restore may take, read STRICT after the walk, through the walk's visitor
 * (cmds/revert.c revert_restore_path, through revert_take_claim).
 *
 * @param profile Handle (must not be NULL); its sheet read through it
 * @param read The sheet's policy for this question
 * @param visit The visitor (must not be NULL)
 * @param payload Handed to the visitor untouched
 * @return NULL; the sheet's failure (STRICT), in the loader's words; the tree's,
 *         under "Cannot read '%s' in profile '%s' at commit %s", naming the claim's
 *         name; or the visitor's, as it made it
 */
error_t profile_contradicted(
    profile_t *profile,
    profile_read_t read,
    profile_visit_fn visit,
    void *payload
);

/**
 * What a profile holds, counted: the claims its walk shows, by kind, the files
 * among them stamped encrypted, and those under custom/ by kind
 *
 * Every blob a file, and every tracked directory claim the walk shows a directory.
 * An ancestor claim is the way to content, never content, and counting it would
 * inflate the number the screens call "directories" past anything the user named.
 *
 * Counted from the profile, not from the view: the listings that print it name
 * available profiles too, and a profile nothing has enabled owns no rows. The
 * view's rows a profile wins are what `status -v` counts, by the same rule, a
 * derived row no directory (cmds/status.c status_print_profiles), so a profile
 * whose every claim stands counts there as it counts here: the holds/wins split,
 * and the two part only where a claim of it stands nowhere — another claim at
 * its path, a blob above it, or claims beneath it, the profile's own among them
 * (docs/profiles.md, core/manifest.c manifest_layer).
 *
 * The custom/ tally is what a binding places, the one label no root of this
 * machine's holds alone (infra/label.h LABEL_CUSTOM): the profile's fact and
 * not this machine's, so it is answered where no row is in scope (clone, before
 * its state is written) and no row this machine writes moves it. It is the view's
 * own count by another route: for a profile the table binds nothing for, the
 * view records on its health exactly the claims tallied here, by the same rule
 * (core/manifest.h manifest_unbound), and tests/test-profiles.c holds the two
 * together. A custom/ chain of derived claims alone — a hand commit's residue,
 * which a commit through dotta prunes — holds nothing there.
 *
 * A count reads no blob. The bytes the files stand for are a listing's to fold,
 * beside the rows that must sum to them (cmds/list.c list_size_claim).
 */
typedef struct {
    size_t file_count;               /* The blob claims the walk shows */
    size_t directory_count;          /* The tracked directory claims it shows */
    size_t encrypted_count;          /* The blob claims among them stamped encrypted */
    size_t custom_file_count;        /* The blob claims among them under custom/ */
    size_t custom_directory_count;   /* The tracked directory claims among them under custom/ */
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
 * Cost: one walk of the profile, whose sheet a question before it may have parsed
 * already, the handle keeping it — about 0.13 µs a claim past the parse, measured
 * at 0.165.12.
 *
 * Readers: the screens that name what a profile holds — `dotta list`'s profile
 * rows in every mode, the custom/ tally their mark, and the file listing's no-files
 * arm (cmds/list.c list_profiles, list_files), `profile list`'s enabled and
 * available rows, the custom/ tally their mark (cmds/profile.c profile_list),
 * the deletion's preview and confirmation (cmds/remove.c remove_profile), and
 * the encrypted files `key status` sums over the enabled profiles (cmds/key.c
 * key_status); and the custom/ tally where a profile is enabled only with a target
 * — `profile enable` and clone, each asking it before the row is written
 * (cmds/profile.c profile_enable, cmds/clone.c cmd_clone), and the editor's seed,
 * its mark and its OFF→ON gate, which absorbs a profile that will not read into
 * its row's (unreadable) (cmds/interactive.c read_targets). A reader not on this
 * list is a bug, and a screen that counts what a profile holds beside this one
 * is the second producer these counts exist to prevent.
 *
 * @param profile Handle (must not be NULL); its sheet read through it
 * @param out The counts (must not be NULL; written on success alone)
 * @return Error or NULL on success: the sheet's, in the loader's words; the tree's,
 *         under "Cannot read profile '%s' at commit %s"
 */
error_t profile_counts(profile_t *profile, profile_counts_t *out);

/**
 * What stands at one name: the four things a profile can hold there
 *
 * Three of the tree's entry kinds, and the one claim a tree cannot hold. FILE
 * is any blob — bytes, an executable, a link's target — the filemode beside it
 * saying which; DIRECTORY is a subtree, or a directory claim the sheet alone
 * holds (a tracked directory with nothing beneath it, an ancestor chain the tree
 * no longer has); SUBMODULE is a gitlink, which dotta never writes (sys/stage.c
 * stage_put_entry refuses the mode) — a verb that acts on one name refuses it
 * by its noun, while a file captured from the disk at its name takes its place,
 * as Git's own add does (profile_capture_file); NOTHING is neither document holding
 * the name.
 *
 * The words on screen: NOTHING is "'<x>' not found in profile '<p>'", <x> the
 * name or the path the verb asked, and " at commit <c>" after it where the verb
 * names a commit it does not caption — show's, the name it asked, its commit
 * captioned above (cmds/show.c show_file); export's name arm (cmds/export.c
 * export_collect_storage) — and ", at its head or at commit <c>" where both sides
 * hold nothing, revert's, what was typed (cmds/revert.c cmd_revert). The same
 * absence asked another way is the same sentence: a path the profile's view places
 * nothing at (cmds/export.c export_collect_filesystem, which adds why where some
 * of the profile's claims stand nowhere here), and an argument as typed that
 * reaches no claim of the profile's (cmds/remove.c remove_resolve). The other
 * answers are each verb's own: show, which acts on one file, refuses a DIRECTORY
 * or a SUBMODULE by its noun; list, which shows a path's history, walks a DIRECTORY
 * as it does a FILE, refuses a SUBMODULE by its noun, and reads NOTHING as a
 * path the head lacks, whose history it searches (cmds/list.c list_path_history).
 * A merge's content conflict names each side's answer where the two differ in
 * what they are — a file, a symlink, a directory, a submodule, and none for NOTHING
 * (cmds/sync.c sync_entry_noun).
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
 * profile_find, whose file claim is the blob it answers; profile_sealed, whose
 * seal is that blob's, its stamp or its bytes, and none where no blob stands; a
 * profile's changes, whether a blob stands at a name the sheet moved and the
 * tree did not, where the base's is the commit's (profile_changes); revert's
 * preview, at the name it shows one file at in its head, whether the head holds
 * a blob there and which (cmds/revert.c cmd_revert); and a merge, what each of
 * its three sides holds at a name Git's merge left in conflict, each side's kept
 * on the content conflict noted there (profile_merge_name), and at a file's claim
 * a side moved, whose words each side's node decides (profile_merge_file).
 *
 * @param profile Handle (must not be NULL); its sheet is never read
 * @param storage_path A validated storage path, or a name Git's merge left in
 *                     conflict, an internal file's among them, which the tree
 *                     answers alike (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s' at commit %s"
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
 * list_path_history (the history's pre-check) — the search across the local
 * profiles by a name, in each this machine places it nowhere for (cmds/revert.c
 * revert_select_profile), export's name arm, which words a copy with nothing in
 * it by what stands at the name (cmds/export.c export_collect_storage), and
 * remove's directory offer, which offers a claim where no blob stands at its
 * name (cmds/remove.c remove_offer_directory); and a profile's draft, at each
 * rung of a way it writes — the two climbs' and a restore's — where whatever
 * the base holds keeps the rung, as a directory it tracks beneath does
 * (profile_capture_ancestors, profile_derive_ancestors, profile_restore_file,
 * profile_restore_directory); and a merge, at a merge-base directory claim a
 * side lacks, where whatever that side holds is its removal
 * (profile_merge_directory) — the four through profile_passes. A reader not on
 * this list is a bug. Four neighbours ask profile_entry instead, the tree alone:
 * revert's preview, the head's entry at the name it shows one file at, where a
 * directory claim is never in question — the path reaches that one claim
 * (cmds/revert.c cmd_revert); the seal a capture keeps (profile_sealed), which
 * a blob alone holds; a profile's changes, whether a blob stands at a name the
 * tree did not move (profile_changes); and a merge, whose rules and words read
 * each side's node, never its sheet (profile_merge_name, profile_merge_file).
 *
 * @param profile Handle (must not be NULL); its sheet is read only where the
 *                tree is silent
 * @param storage_path A validated storage path (must not be NULL)
 * @param out The answer (must not be NULL; written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s' at commit %s"; the sheet's, in the loader's words
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
 * handed, checked where it was read (infra/input.h input_resolve) or kept (a
 * record's, which the store holds to the grammar: core/state.h).
 *
 * Lent for the handle's life, kept in its arena; its strings are the sheet's,
 * or the handle's copy of the storage path.
 *
 * Readers: cmds/show.c show_file (a file claim, TOLERANT: the header),
 * cmds/export.c export_collect_storage (a file claim and a directory claim, both
 * TOLERANT: the single-file copy, or the copy's root), each claim of either kind
 * a restore writes, its commit's view standing it where the argument reaches
 * (STRICT: cmds/revert.c revert_select_claim), the file it writes at its argument
 * read again by its preview through the restore's answer (cmds/revert.c
 * cmd_revert), and a profile's draft at each rung of the way a restore brings
 * back (a directory claim, STRICT, of the commit's profile: profile_restore_file,
 * profile_restore_directory).
 *
 * @param profile Handle (must not be NULL)
 * @param read The sheet's policy for this question
 * @param kind A file's claim or a directory's
 * @param storage_path A validated storage path (must not be NULL)
 * @param out The claim, or NULL where the profile makes none of that kind there
 *            (must not be NULL; NULL after an error)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s' at commit %s"; the sheet's (STRICT), in the loader's words
 */
error_t profile_find(
    profile_t *profile,
    profile_read_t read,
    path_kind_t kind,
    const char *storage_path,
    const profile_claim_t **out
);

/**
 * Whether the profile holds `storage_path` sealed: the seal a capture there keeps
 *
 * Asked of the blob at the name, and sealed where either of its two witnesses
 * says so — the claim's stamp, as the walk decodes it (none on a link), and the
 * blob's own bytes, judged by its mode (infra/content.h content_classify). The
 * stamp is a cache of the bytes (core/metadata.h), and where the two disagree
 * whether the name is meant sealed is unknown, so the answer is the one that
 * publishes nothing. The stamp is read first, the bytes only where it says none.
 * No blob at the name — no entry, a subtree, a gitlink a hand left — holds no seal.
 *
 * Strict, with no policy to spell: a stamp unread could be the seal itself, so
 * a sheet that will not load is this answer's failure wherever a blob stands.
 *
 * Readers: the encryption policy's prior (core/policy.h
 * encryption_policy_should_encrypt), asked of a draft's base, whose sheet the
 * open read (profile_draft_base) — cmds/add.c cmd_add's decision pass, before
 * any capture, and cmds/update.c update_capture, at each file it captures.
 *
 * @param profile Handle (must not be NULL); its sheet read through it where a
 *                blob stands at the name
 * @param storage_path A validated storage path (must not be NULL)
 * @param out Whether the name is sealed (must not be NULL; false after an error)
 * @return Error or NULL on success: the tree's or the blob's, under "Cannot read
 *         '%s' in profile '%s' at commit %s"; the sheet's, in the loader's words
 */
error_t profile_sealed(profile_t *profile, const char *storage_path, bool *out);

/**
 * What a profile's history says of a name: whether it left, and what took it
 *
 * Six answers, one table over the commits that took the name away (sys/history.h
 * history_removals): a removal whose action is update's or revert's deletes,
 * and any other action, or none, keeps (infra/commit.h commit_action_t) — and a
 * removal that keeps decides beside every other removal and every line unread.
 *
 * The words on screen: an orphan's line says what took it (core/workspace.c
 * workspace_item_line) — "deleted from p", "removed from p", "not in p's history",
 * "p has no branch" — where HELD and UNVERIFIED add nothing to "from p", the
 * name its profile holds still and a history the line calls [unverified]; apply's
 * preview counts the prunes deletions make, "deleted from their profiles", and
 * names each released file's by its line (cmds/apply.c
 * apply_print_cleanup_preview); a sync's Manifest counts the acts (cmds/sync.c
 * sync_departure_counts), "deleted", "removed" for every answer that keeps, and
 * "unverified"; and the line beneath a merge says each side's act, deleted or
 * removed (cmds/sync.c sync_print_disagreements).
 */
typedef enum {
    PROFILE_DEPARTURE_HELD,         /* the head holds the name: it has not left */
    PROFILE_DEPARTURE_DELETED,      /* every removal names update or revert, and every line read */
    PROFILE_DEPARTURE_REMOVED,      /* a removal names another action, or none: beside an unread line too */
    PROFILE_DEPARTURE_NEVER_HELD,   /* no commit took it: every line read to its root */
    PROFILE_DEPARTURE_GONE,         /* no head: the branch is gone */
    PROFILE_DEPARTURE_UNVERIFIED,   /* a line went unread, the head's tree among them, and no removal keeps */
} profile_departure_kind_t;

/**
 * The answer whole, by value: which of the six, and the commit that decided it
 * — the first removal that keeps, or for DELETED the first removal, in the order
 * the walk met them — Git's null id where none decided
 */
typedef struct profile_departure {
    profile_departure_kind_t kind;  /* which of the six */
    git_oid removal;                /* the deciding removal; the null id where none decided */
} profile_departure_t;

/**
 * The departure of each name, from the history at `head`
 *
 * The head is the caller's, by its id: a branch's, read by name — NULL where
 * the branch is proven gone, which answers every name GONE, a deleted branch's
 * bytes being reachable from nothing — or any commit a history is asked at. One
 * walk answers every name (sys/history.h history_removals). Reads Git alone and
 * raises nothing: a read that fails leaves the names whose lines it reached
 * UNVERIFIED, save where a removal keeps — every name, where the head's own commit
 * will not read; a branch whose head would not read is no head, the caller's to
 * say.
 *
 * Readers: core/workspace.c workspace_ask_departures (each owned file orphan,
 * at the head the view read for an enabled profile, at its branch's head now
 * for a disabled one — but one whose deletion the record keeps at that head,
 * core/state.h state_record_t's head); cmds/sync.c sync_departure_counts (each
 * file the acts' view lost, at its profile's head as the view after read it)
 * and sync_disagreements (each name a merge's local side took since its merge
 * base, at the remote's head and the local one).
 *
 * @param repo The repository the history is read from (must not be NULL)
 * @param head The head's id, or NULL where the branch is gone (borrowed)
 * @param storage_paths The names, validated (must not be NULL where count > 0)
 * @param count How many
 * @param out The departures, parallel to `storage_paths` (must not be NULL)
 */
void profile_departures(
    git_repository *repo,
    const git_oid *head,
    const char *const *storage_paths,
    size_t count,
    profile_departure_t *out
);

/**
 * A profile's draft: its next commit, both of its documents in memory (opaque)
 *
 * One profile's next commit, on a stage (sys/stage.h: one ref's next commit,
 * staged in memory), and the sheet that rides it — a stage is Git's, a draft
 * dotta's. Opened at the profile's head (profile_draft_open), over Git's empty
 * tree for a profile the commit creates (profile_draft_orphan), or over a merge
 * of its head with another commit of its history (profile_draft_merge), it holds
 * its stage; the profile at the tree the stage opened at — the base, read and
 * never edited, lent for every question a writer asks before it edits; and the
 * sheet the commit will carry — the base's, copied at the open (core/metadata.h
 * metadata_clone) and edited from then on, so every claim the base lends stands
 * whatever the commit does; or, over a merge, the claims composed over its merged
 * tree, which no writer edits. A writer asks the base and edits the draft; it
 * never holds the sheet — it hands the draft what it captured from the disk or
 * restores from a commit, a claim or the commit's whole tree
 * (profile_restore_tree), and the draft authors the claim — and the draft answers
 * what the base cannot: whether a name a writer chooses before reading it has
 * room beside the names chosen with it (profile_admit), whether its edits move
 * anything (profile_changed), and which explicit claims they add, update and
 * remove (profile_changes). Every edit keeps the document's rules, stated here
 * once:
 *   - a write touches its own kind: a removal takes its claim — a file's the
 *     blob and the FILE item at its name, a directory's tracking — never the
 *     other kind's at the same name, so a directory claim a removed blob
 *     contradicted stands again, carried, and a FILE item no blob backs rides a
 *     directory captured at its name. The one write across kinds is a blob's
 *     where a directory claim stands, no blob at or above its name in the base:
 *     the blob takes that claim's place, and a claim the base's blob at the name
 *     contradicts rides the write, carried;
 *   - the admission, asked of every blob the commit writes, a capture's and a
 *     restore's, and of every name a writer chooses before it reads a byte
 *     (profile_admit): a blob may stand at a name unless a tracked directory
 *     claim the commit carries stands strictly beneath it, one the base does
 *     not contradict — the sheet's half — and unless the tree has no room,
 *     sys/stage's half (sys/stage.h stage_put, stage_put_blob, stage_admit_blob).
 *     A claim the base holds contradicted is never in the way, so writing again
 *     the blob that contradicts it carries it; nor is a derived claim, which
 *     what stands beneath it refuses on its own, and the prune takes where nothing
 *     does. A directory admitted is a claim the commit carries from its admission,
 *     so a blob chosen above it later meets it as it meets one the base holds.
 *     A directory a restore writes is asked the tree's half, of the tree the
 *     commit would record, the removals so far counted (profile_restore_directory).
 *     A merge chooses no name and asks neither: its claims stand where its merged
 *     tree leaves them room, by the decode's rule (profile_draft_merge);
 *   - the ancestors: a derived claim stands only where something tracked stands
 *     beneath it, and the way is authored where the profile first passes through
 *     a rung — the base holding nothing at it nor a directory it tracks beneath
 *     it. Five edits keep that — the first capture, which claims from the disk
 *     each rung of a captured leaf's way the profile does not pass through yet
 *     (profile_capture_ancestors); the named re-derivation, which claims it again
 *     from the disk at each rung a run's paths select (profile_derive_ancestors)
 *     — both retiring every derived claim the profile holds at a place the disk
 *     answers another kind for, each rung where its own name resolves; the way
 *     a restored claim stood on at its commit, brought back at each rung the
 *     profile does not pass through, a tracked claim the copy holds there left
 *     as it is, with no disk read (profile_restore_file,
 *     profile_restore_directory); a directory claim's removal, which takes its
 *     tracking and leaves the claim the way to whatever stands beneath it, the
 *     attributes it claimed kept (profile_remove); and the prune, at the commit,
 *     of every derived claim nothing tracked stands beneath any longer
 *     (core/profiles.c profile_prune_ancestors), counted for a writer that asks
 *     — but a claim the base tracked, whose removal the writer names itself;
 *     the record of every rung it took is the next load's to decide, as of every
 *     claim a commit lets go (core/workspace.c workspace_analyze_orphans). A
 *     merge composes the two sides' ways, each side's absence of a merge-base
 *     directory claim read through its own tree, and the prune runs at its commit
 *     as at every commit;
 *   - the gate, each document held against the one the draft opened: a commit
 *     no edit of which moved the tree or the sheet makes nothing — no prune, no
 *     save, no commit — so imported redundancy rides a commit and never drives
 *     one; the sheet is saved only where its claims are no longer the base's
 *     (core/metadata.h metadata_same), a hand's spelling kept otherwise, and
 *     none where it claims nothing (metadata_save_to_stage); and a tree equal
 *     to the one opened is no commit (sys/stage.h stage_commit). A merge's draft
 *     has always moved, its stage's second parent, and the save stands as written
 *     over a merge and over a commit's whole tree too, the sheet's name holding
 *     the base's sheet until the save — settled back where Git's merge or the
 *     tree's read put another (profile_draft_merge, profile_restore_tree).
 *
 * Memory: a handle's own — an arena made at the open, holding the struct, the
 * sheet the commit carries — the copy of the base's with every claim an edit
 * writes into it, a commit's whole sheet copied in its place
 * (profile_restore_tree), or the claims a merge composed — the names the climbs,
 * the way and the prune spell, and the commit's message with the changes it names
 * — released by profile_draft_free with the admission, the base and the stage;
 * the base borrows the stage's tree, and goes before it. What a capture answers
 * is the caller's (profile_claim_t), so the claim outlives the draft that wrote it.
 */
typedef struct profile_draft profile_draft_t;

/**
 * Open a profile's draft at its head
 *
 * The stage at the profile's branch (sys/stage.h stage_open: a branch that does
 * not stand is refused ERR_NOT_FOUND, naming its reference), the base at the
 * tree the stage opened, and the base's sheet read now and strictly: a writer
 * refuses a sheet that will not load before its preview, in the loader's words,
 * which name the head the stage opened at (sys/stage.h stage_head), where a reader
 * may go on without it.
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
 * The side a merge's every conflict is settled for: the run's word (cmds/sync.c,
 * --conflicts), none where it named none
 */
typedef enum {
    PROFILE_SIDE_NONE,     /* None named: a conflict refuses the merge */
    PROFILE_SIDE_OURS,     /* The branch the merge is made on, its first parent: this machine's */
    PROFILE_SIDE_THEIRS,   /* The commit merged into it, its second */
} profile_side_t;

/**
 * What both sides of a merge moved apart at a name: its content, Git's refusal,
 * or a claim's mode or its ownership
 *
 * The words are the workspace's for the same three (core/workspace.h
 * divergence_type_t: CONTENT the bytes, MODE the mode, OWNERSHIP the owner and
 * group), and the claim's two the sheet's (core/metadata.h metadata_axis_t),
 * each named beside the other where a merge composes it.
 */
typedef enum {
    PROFILE_AXIS_CONTENT,     /* Git could not compose what stands at the name */
    PROFILE_AXIS_MODE,        /* Both moved a claim's mode apart */
    PROFILE_AXIS_OWNERSHIP,   /* Both moved its owner and group apart, the pair */
} profile_axis_t;

/**
 * One conflict a merge met: a name, what both sides moved apart there, and each
 * side's value on it — for the content, what the side's tree holds at the name;
 * for a claim's axis, the side's claim, decoded as the walk decodes it over that
 * side's own tree
 *
 * A sum type, spelled as infra/input.h input_path_t spells one: the axis says
 * which pair is set, and a reader asks it before reading either.
 */
typedef struct {
    const char *storage_path;                    /* The name: the tree's, or the claim's key */
    profile_axis_t axis;                         /* What both moved apart there: which pair is set */
    union {
        struct {                                 /* PROFILE_AXIS_CONTENT */
            profile_held_t entry_ours;           /* What ours' tree holds at the name */
            profile_held_t entry_theirs;         /* Theirs', likewise */
        };
        struct {                                 /* PROFILE_AXIS_MODE, PROFILE_AXIS_OWNERSHIP */
            const profile_claim_t *claim_ours;   /* Ours' claim at the name */
            const profile_claim_t *claim_theirs; /* Theirs', likewise */
        };
    };
} profile_conflict_t;

/**
 * The conflicts a merge met, in name order: at one name the content's, then a
 * file's claim's, then a directory's, the mode's before the ownership's
 */
typedef struct {
    const profile_conflict_t *entries;
    size_t count;
} profile_conflicts_t;

/**
 * Open the draft of a profile's merge with another commit of its history, every
 * conflict settled at the open for `side`, or the open refused
 *
 * Two halves, each where its authority lives.
 *
 * The tree first: the stage over the merge (sys/stage.h stage_merge: the profile's
 * branch the first parent — refused ERR_NOT_FOUND, naming its reference, where
 * it does not stand — `theirs` the second, the index Git's three-way merge of
 * their trees over their merge base); the base ours, at the head's tree, as every
 * draft's is at the tree its stage opened; the sheet's own name holding the base's
 * sheet, as every draft's index does — Git's merge of it is no document dotta
 * reads; and each name Git could not compose, in name order:
 *   - a removal beside a change of the executable bit alone is the removal, at
 *     any name: one side holding no regular file there — nothing, a directory
 *     or a link — and the other the merge base's blob under its other regular
 *     filemode;
 *   - the profile's ignore file holds its two sides' rules, united where Git
 *     refused them (sys/stage.h stage_unite);
 *   - any other is a content conflict, settled for `side` once every rule is
 *     in: the side's bytes, its entries at and beneath the name.
 *
 * Then the claims, into a sheet of the draft's own. A claim the three sheets
 * hold alike is carried as it stands. One a side moved is composed from each
 * side's word, read over that side's own tree — a side lacking the name, or holding
 * a node that cannot carry an axis, says nothing of it — and stands only where
 * the tree the commit will record gives its name the node it claims: a file's
 * claim a blob at its name, its axes that blob's type's — a regular file's mode
 * and ownership, a link's ownership — and the stamp its bytes'; a directory's
 * claim no blob at its name or above it (the decode, the module header). A side's
 * absence of a merge-base directory claim is read through its own tree: passing
 * through the name, the side removed it; passing through none, its prune took it.
 *
 * The basis, stated once: a claim's move needs its name, so a removal beside it
 * is the removal; a byte's change makes its name, so a removal beside it is Git's
 * conflict, kept for the work it carries; a tie between two derivations is ours',
 * by its stakes, a derivation binding dotta's own creation of its path alone;
 * and the ignore file's two sides are united, by its cost — a rule one side removed
 * beside a rule the other added comes back.
 *
 * A conflict is a name and what both sides moved apart there: its content, or a
 * claim's mode or ownership. Each is read off the three sides before any settle,
 * so a refusal names every conflict a side's run settles. Each takes `side` on
 * its grain — the content its bytes, an axis its value, Git's merged bytes kept
 * — or, where one stands and `side` is PROFILE_SIDE_NONE, the open is refused
 * ERR_CONFLICT, "Merging profile '%s' met %zu conflict%s", and no draft is made.
 *
 * Every sheet is read strictly: ours' as every writer's base, in the loader's
 * words; theirs' and the merge base's by the role each plays, said by theirs'
 * commit over the loader's words, which name the profile alone at a stage's tree
 * — "Failed to load metadata from commit %s, merged in", "Failed to load metadata
 * from the merge base with commit %s". A refused open leaves the blobs its merge
 * and its union wrote, loose, and nothing else. The draft holds no conflict,
 * and its commit always moves the branch — its stage's second parent records
 * the integration — its writer's words its message (profile_commit).
 *
 * Reader: cmds/sync.c sync_decide, at the run's decision.
 *
 * @param repo Repository (must not be NULL; borrowed for the draft's life)
 * @param name The profile's name, which its branch is named by (must not be NULL;
 *             copied)
 * @param theirs The commit merged into the profile's head: any commit the store
 *               holds (must not be NULL)
 * @param side The side every conflict is settled for, or PROFILE_SIDE_NONE
 * @param arena The arena the conflicts live in, the words that say each with
 *              them (must not be NULL)
 * @param out_conflicts Every conflict met, settled or refusing, in name order
 *                      (must not be NULL; written on success and on the refusal,
 *                      none where any other failure came first)
 * @param out The draft (must not be NULL; released by profile_draft_free); NULL
 *            on a failure
 * @return Error or NULL on success: ERR_CONFLICT where a conflict stands and no
 *         side settles it; the stage's, the sheets' or a tree's
 */
error_t profile_draft_merge(
    git_repository *repo,
    const char *name,
    const git_oid *theirs,
    profile_side_t side,
    arena_t *arena,
    profile_conflicts_t *out_conflicts,
    profile_draft_t **out
);

/**
 * The profile as the draft opened it: the base, lent until profile_draft_free
 *
 * Readers: cmds/add.c cmd_add, for the view every naming and kind question of
 * the run reads (core/manifest.h manifest_build_profile), and each file's
 * encryption prior; cmds/remove.c remove_paths, for the claims its arguments
 * are matched against (remove_resolve); cmds/revert.c cmd_revert, for the entry
 * its preview reads at the name it shows one file at (profile_entry); cmds/revert.c
 * revert_restore_path, for the head a restore reads — its name, which places
 * the argument, its view, which names each write, and its walk, every claim it
 * may take; and cmds/update.c update_profile, for a capture's prior and the name
 * its seal is keyed by (update_capture).
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
 * at its own admission. Never captured, it is committed so — tracked, claiming
 * no attributes — over a derived claim at its name or where none stood; a tracked
 * claim there keeps its own. add, the one writer that admits, captures every
 * directory it admits — but one its profile already tracks, which it leaves,
 * the claim keeping its own (cmds/add.c add_list) — or refuses its command
 * (cmds/add.c cmd_add); a writer that went on past a failed capture would commit
 * that claim. Nothing is read from the disk and nothing written to the object
 * database: a writer that stops after its admissions — a dry run — leaves the
 * repository as it found it.
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
 * ERR_NOT_FOUND). DIRECTORY: the claim's tracking, the item left the way to what
 * stands beneath it — a derivation with the attributes it claimed, which the
 * commit's prune takes where nothing tracked stands beneath it once every edit
 * is in, whatever order a writer made them in (profile_draft_t, the ancestors)
 * — refused ERR_NOT_FOUND, "Profile '%s' tracks no directory at '%s'", where
 * the sheet tracks none there: a derivation stands for what stands beneath it,
 * and no writer takes it. The other kind's claim at the name is never taken,
 * and a refusal leaves the commit as it was.
 *
 * Readers: cmds/add.c cmd_add, the tracked claim its profile's own blob contradicts
 * at a name it captures a file at — the remedy that keeps the file, where the
 * put rule carries the claim; cmds/remove.c remove_paths, each claim its arguments
 * took; cmds/revert.c revert_take_claim, each of the head's claims a restore
 * reaches that no write of its takes; and cmds/update.c update_profile, each
 * deletion it commits, by the item's kind.
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
 *     or a group this host cannot name, ERR_NOT_FOUND "Cannot resolve UID %u,
 *     the owner of '%s', to a user name on this system", or its GID twin — the
 *     draft's words over the capture's answer;
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
 * an owner or a group this host cannot name, ERR_NOT_FOUND in the file capture's
 * words (profile_capture_file) — so a writer may go on without the claim, which
 * stands as it stood. Nothing is asked of the base: a blob another writer committed
 * at the name since the writer read its view leaves the claim written contradicted,
 * carried, and a claim another writer took from there comes back tracked — the
 * window every other edit of that writer reads its view across.
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
 * @param out The claim the capture authored — tracked, the look's mode and
 *            ownership, its name `storage_path` — decoded as the walk decodes
 *            one; whether a walk shows it is the classification's (must not be
 *            NULL; written on success alone)
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
 * The way to a leaf a writer captured, claimed from the disk where it is new to
 * the profile
 *
 * The first capture: the capture that first passes through a rung authors the
 * profile's word on it, and every capture after it leaves that word as it stands,
 * whichever machine's disk it meets — so two machines whose disks differ at a
 * shared rung rewrite nothing there at an ordinary capture. A rung the profile
 * does not pass through yet — the base holds nothing at it (profile_holds), nor
 * a directory it tracks beneath it — claims the attributes it has where it is a
 * real directory right now, derived: the profile then passes through it and does
 * not track it, so the claim binds only dotta's own creation of that path
 * (core/deploy.c, the ancestors' pass). The rungs are the separators of the label's
 * tail, so the word is never one, nor the leaf, which is its own capture's
 * business. Each stands where its own name resolves under `mounts`, the table
 * the leaf was named under: a name is portable and a binding is not, so a rung
 * this machine mounts a root at is claimed like every other — a chain answered
 * the other way leaves a hole no other machine can fill. Per rung, cut from the
 * leaf, by what stands there now:
 *   - a tracked claim standing at it is the walk's own word, left exactly as it
 *     is, and the climb goes on past it, a tracked claim saying nothing of the
 *     rungs above it;
 *   - a FILE item at it is the other kind's, residue no blob backs, carried as
 *     every write carries it, and the rung is decided beside it;
 *   - a directory claims its attributes where the profile does not pass through
 *     the rung yet, counted in `captured` where the claim moved; a rung it passes
 *     through keeps its word — a claim, or none where the capture that first
 *     passed through it met no directory there: the user's way, on every machine;
 *   - anything else retires every derived claim the profile holds at that place,
 *     under each name a root of the profile's strictly above it gives the place,
 *     each counted in `retired`: the disk answers about a place, and a profile
 *     bound after its first captures derives one place under two names
 *     (core/manifest.h manifest_lookup_claim's note). A capture meets one only
 *     through the user's link at a rung its profile derives, add's one admission,
 *     whose consent the retire is (cmds/add.c add_refuse_ancestry);
 *   - no answer — an unbound custom/ name, nothing there, nothing this host could
 *     see, an owner it cannot name — leaves the rung as it is: no answer is not
 *     an answer of "no".
 * Both outs are counts: a derived claim is the way to the claims, never one, so
 * no message names it (profile_changes, infra/commit.h), and a count is the whole
 * of what a writer says of either.
 *
 * Total over the disk, and idempotent: no answer the disk gives stops the climb,
 * and each climb decides every rung it passes, so a rung two leaves share is
 * decided at each climb through it — again to the same answer where nothing moved
 * between, counting and retiring nothing. The base's tree, which profile_holds
 * reads, is its one failure, and needs a store that changed beneath the draft.
 * A resolve and a look a rung, every climb — the look is what lets a capture
 * through the user's link retire the rung; the rungs' spellings are the draft's
 * arena's. With the named re-derivation (profile_derive_ancestors), the one place
 * the draft looks at the disk: the handle reads Git's alone, and the draft, which
 * writes, reads the way off the machine the leaf was captured on.
 *
 * Readers: cmds/add.c cmd_add, each path it captured, under the table it named
 * them under; and cmds/update.c update_profile, each leaf it captured.
 *
 * @param draft The draft (must not be NULL)
 * @param mounts The table the leaf's name was made under, so a rung resolves
 *               back to where the leaf was read (must not be NULL)
 * @param storage_path The leaf's name, under a label — the vocabulary's
 *                     precondition (infra/label.h label_tail), which every writer
 *                     meets with a name it composed or validated (must not be NULL)
 * @param captured Count of rungs whose claim the climb authored, added to (must
 *                 not be NULL)
 * @param retired Count of derived claims the climb retired, every name of each
 *                place it retired at, added to (must not be NULL)
 * @return Error or NULL on success: the base's tree, under "Cannot read '%s' in
 *         profile '%s' at commit %s"
 */
error_t profile_capture_ancestors(
    profile_draft_t *draft,
    const mount_table_t *mounts,
    const char *storage_path,
    size_t *captured,
    size_t *retired
);

/**
 * The way to a leaf a named run reaches, re-derived from the disk where the run's
 * paths select it
 *
 * The first capture's rung rule (profile_capture_ancestors), but at a rung
 * `path_filter` selects — its place and its name asked as a directory's
 * (infra/pathspec.h pathspec_matches), so a rung at or beneath a path the run
 * named — a directory claims its attributes whatever the profile held there,
 * counted where the claim moved: naming is consent, the remedy for a rung the
 * world moved under, and the way a chmod meant for every machine reaches the
 * profile. A rung the filter does not select is the first capture's: a name at
 * a file re-derives nothing above it, while a link on its way is retired as any
 * climb retires one, so a named file frees the user's link at a rung of its way
 * as a named directory does.
 *
 * Total and idempotent as the first capture is, and failing where it fails.
 *
 * Reader: cmds/update.c update_profile, each row a named run hands it, under
 * the run's filter (core/scope.h scope_paths).
 *
 * @param draft The draft (must not be NULL)
 * @param mounts The table the leaf's name was made under, so a rung resolves
 *               back to where the leaf was read (must not be NULL)
 * @param storage_path The leaf's name, under a label (infra/label.h label_tail;
 *                     must not be NULL)
 * @param path_filter The run's path filter (must not be NULL: a NULL filter selects
 *                    every path, and would re-derive the whole way)
 * @param captured Count of rungs whose claim the climb authored or changed, added
 *                 to (must not be NULL)
 * @param retired Count of derived claims the climb retired, every name of each
 *                place it retired at, added to (must not be NULL)
 * @return Error or NULL on success: the base's tree, under "Cannot read '%s' in
 *         profile '%s' at commit %s"
 */
error_t profile_derive_ancestors(
    profile_draft_t *draft,
    const mount_table_t *mounts,
    const char *storage_path,
    const pathspec_t *path_filter,
    size_t *captured,
    size_t *retired
);

/**
 * A file claim a commit held — a blob's — restored at `storage_path`, the name
 * the commit writes, with the way the commit stood it on
 *
 * The claim is the commit's, whole: its mode, owner and group as it claimed them,
 * and none where it claimed none, its absence read as the floor wherever a mode
 * is placed (profile_claim_mode), so the sheet stays as sparse as the commit's.
 * Its blob is content's to read, once, through the repository `from`'s tree was
 * read from (infra/content.h content_rebind): the read is the proof the store
 * holds it, for every filemode; its bytes are the stamp — the write boundary's
 * own reading (core/policy.h), never the commit's stamp; and a seal made under
 * the claim's own name is sealed again under `storage_path` where the two part
 * (crypto/cipher.h "Path binding"), put as bytes the stage writes at its commit
 * (sys/stage.h stage_put_unwritten). A blob that carries no binding (plaintext,
 * or a link's target), or this name's, enters at its id. In order, each refusal
 * before anything moves:
 *   - content's, under "Cannot restore '%s'", the claim's own name, or "Cannot
 *     restore '%s' as '%s'" where `storage_path` is another: a blob the store
 *     will not read, and a seal that will not move — ERR_LOCKED without a key,
 *     the read's own ladder;
 *   - the admission (profile_draft_t): the sheet's half, ERR_CONFLICT "Cannot
 *     stage '%s': '%s' is a directory profile '%s' claims beneath it", naming
 *     the byte-least such claim; then the tree's, the put's own (sys/stage.h
 *     stage_put_blob, stage_put_unwritten: ERR_CONFLICT or ERR_INVALID_ARG),
 *     which writes no object;
 *   - the put rule at the name: a directory claim standing there gives way, one
 *     the base's blob contradicts rides the write;
 *   - the way: each rung of `storage_path`, paired from the leaf with a rung of
 *     the claim's own name — both names place one path, so their tails end alike
 *     — takes `from`'s directory claim at its pair, derived, wherever the profile
 *     does not pass through the rung, as a capture claims one from the disk
 *     (profile_capture_ancestors): the base holds nothing at it (profile_holds),
 *     nor a directory it tracks beneath it;
 *   - the claim at its own kind, written (core/metadata.h metadata_write_item):
 *     the commit's, or — where it claims nothing, no mode, owner, group or stamp
 *     — the retire of the FILE item standing there.
 * A failure past the put leaves a draft its writer abandons (sys/stage.h).
 *
 * Reader: cmds/revert.c revert_restore_path, each file claim it writes.
 *
 * @param draft The draft (must not be NULL)
 * @param storage_path The name the restore writes: the claim's own, or the one
 *                     the profile holds the place by (must not be NULL)
 * @param claim The file claim the commit holds, a blob's, as its walk decodes
 *              it (must not be NULL; borrowed for the call)
 * @param from The profile at the commit the claim came from (must not be NULL;
 *             its sheet read strictly)
 * @param keymgr Key manager, for a reseal (can be NULL: a reseal is then refused,
 *               ERR_LOCKED)
 * @return Error or NULL on success
 */
error_t profile_restore_file(
    profile_draft_t *draft,
    const char *storage_path,
    const profile_claim_t *claim,
    profile_t *from,
    keymgr *keymgr
);

/**
 * A directory claim a commit held — tracked, or derived — restored at
 * `storage_path`, with the way the commit stood it on
 *
 * The claim is the commit's, whole: its class, its mode, owner and group as it
 * claimed them, over the directory claim at the name whatever it said; a FILE
 * item there is the other kind's, and rides. A derivation nothing tracked stands
 * beneath at the commit goes with its prune, as every derivation does
 * (profile_draft_t, the ancestors). In order, each refusal before anything moves:
 *   - the tree's half of the admission, asked of the tree the commit would record,
 *     the removals the writer made so far counted: an entry at a rung above the
 *     name, or at the name, a blob or a gitlink, ERR_CONFLICT in the stage's
 *     own sentences for an entry in a name's way — "Cannot stage '%s': '%s' is
 *     a file in this tree", "Cannot stage '%s': it is a file in this tree"
 *     (sys/stage.h stage_holds). Nothing beneath the name refuses it: a directory's
 *     entries are what stands there;
 *   - the way, as profile_restore_file brings a file's, paired from the claim's
 *     own name;
 *   - the claim at its own kind, written (core/metadata.h metadata_write_item).
 *
 * Reader: cmds/revert.c revert_restore_path, each directory claim it writes.
 *
 * @param draft The draft (must not be NULL)
 * @param storage_path The name the restore writes: the claim's own, or the one
 *                     the profile holds the place by (must not be NULL)
 * @param claim The directory claim the commit holds, as its walk decodes it (must
 *              not be NULL; borrowed for the call)
 * @param from The profile at the commit the claim came from (must not be NULL;
 *             its sheet read strictly)
 * @return Error or NULL on success
 */
error_t profile_restore_directory(
    profile_draft_t *draft,
    const char *storage_path,
    const profile_claim_t *claim,
    profile_t *from
);

/**
 * A commit's whole tree and sheet, the draft's: every entry the commit's — its
 * claims under its names, dotta's own files — but the sheet's own name, the base's
 * as every draft's index holds it, and the sheet the commit carries the commit's,
 * copied
 *
 * No selection, stamp, reseal or key: the commit's own names and blobs. Its claims
 * stand as the commit has them, a claim its tree contradicts carried as every
 * write that does not aim at one carries it, and the commit's prune and save
 * run as at every commit (profile_commit). The commit's bytes at the sheet's
 * name are no document the save reads — the copy is — so the name is settled
 * back from the tree the stage opened, as a merge settles it (profile_draft_merge),
 * and the commit records the commit's own tree but its sheet, which the save
 * moves as at every commit: the copy, saved, where its claims past the prune
 * are no longer the head's, and the head's own where they are. So a derivation
 * nothing stands beneath goes with the prune, and a sheet saying the head's claims
 * in other bytes moves nothing. A mode Git's tree writer refuses, a hand's 100664,
 * fails the commit where its tree is rebuilt — the root's at every restore, the
 * settle taking its cache, the index keeping every other tree's (sys/stage.h
 * stage_read_tree) — and a head's sheet a hand committed so is settled back under
 * Git's regular mode, a move of the tree no list names: every restore over it
 * commits, its message saying ancestor claims changed (stage_settle).
 *
 * The commit's sheet is read first and strictly, so its refusal moves nothing,
 * in the loader's words, which name the commit (profile_load_sheet).
 *
 * Reader: cmds/revert.c cmd_revert, a whole profile's revert.
 *
 * @param draft The draft (must not be NULL)
 * @param from The profile at the commit (must not be NULL; its tree one the draft's
 *             repository holds)
 * @return Error or NULL on success: the sheet's, in the loader's words; the tree's,
 *         which will not read whole; or the settle's, an entry the stage refuses
 *         at the sheet's own name
 */
error_t profile_restore_tree(profile_draft_t *draft, profile_t *from);

/**
 * One of dotta's own files, beside the claims
 *
 * A name outside the grammar (infra/label.h label_prefixes), which the decode
 * reads as an internal file and no walk of content sees, and never the sheet's
 * directory, which the commit writes at its save: a regular blob of `bytes`,
 * written to the object database at once (sys/stage.h stage_put), so a writer
 * puts it once nothing of its run can still refuse. Either other name is a caller's
 * bug and dies — a claim put here would pass the admission and the put rule by,
 * and a put at the sheet's name would race the commit's own save.
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
error_t profile_put_internal_file(
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
 * it would do; nothing is written, a dry run's question too. Every move counts
 * here, the way's to the claims included; which explicit claims moved is
 * profile_changes'. A merge's draft has always moved: its stage's second parent
 * records the integration (sys/stage.h stage_changed).
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
 * What the commit changes of the profile's explicit claims and of its internal
 * files, name by name
 *
 * A name's explicit claim is what the two documents say of it, compared whole:
 * the blob at the name — its id and filemode — with the FILE item that rides
 * it, and the tracked directory claim at the name. A FILE item no blob backs
 * and a gitlink claim nothing, and a derived claim is the way to the claims,
 * never one, so none of their moves is named. A blob is one of any mode its tree
 * spells, as the walk reads it. Compared as the documents spell it: a claim the
 * tree contradicts is compared as the sheet holds it, and whether a walk shows
 * it is the decode's. An internal file claims nothing (infra/label.h
 * label_prefixes), and is named apart wherever the tree moved at its name — but
 * the sheet, the claims' own document, whose moves the claims' lists and the
 * way say.
 *
 * Asked once every edit is in, and the commit's answer whenever it is asked:
 * the commit asks it past its prune and its save (profile_commit), and neither
 * moves a name the lists hold — the prune takes derived claims alone, the save
 * writes or takes the sheet. Nothing is written, so a dry run may ask it. A commit
 * whose lists name nothing moved only the way: every writer's edit moves an
 * explicit claim, the way to one, or an internal file — dotta's own riding a
 * profile's first capture (profile_put_internal_file), or a commit's whole tree
 * (profile_restore_tree).
 *
 * Readers: profile_commit, the names its message gives (infra/commit.h
 * commit_message); and cmds/revert.c cmd_revert, asked before its commit, its
 * answer that commit's — the preview's sections, the paths its hooks are handed
 * and the places its record phase reads. A reader not on this list is a bug.
 *
 * @param draft The draft, every edit in (must not be NULL)
 * @param arena The arena the lists and their names live in (must not be NULL)
 * @param out The changes, each list in byte order (must not be NULL; written on
 *            success alone)
 * @return Error or NULL on success: the tree's comparison's, which needs a store
 *         that changed beneath the draft; or the base's, under "Cannot read '%s'
 *         in profile '%s' at commit %s"
 */
error_t profile_changes(
    const profile_draft_t *draft,
    arena_t *arena,
    commit_changes_t *out
);

/**
 * The commit
 *
 * Where no edit moved the tree or the sheet (profile_changed), nothing: no prune,
 * no save, no message, no commit. Otherwise the prune, against the tree the commit
 * will record, counted where a count is asked — every derivation it takes but a
 * claim the base tracked, whose removal the writer names; the sheet saved where
 * its claims are no longer the base's, and none where it claims nothing; the
 * message, the writer's words over what the commit changes of the profile's
 * explicit claims and internal files (profile_changes, infra/commit.h
 * commit_message) — never the writer's own lists, which hold what it touched, a
 * re-capture of what the profile holds among them; then one commit, naming the
 * writer's action (sys/stage.h stage_commit: a tree equal to the opened one is
 * none, a head another writer moved since the open is refused ERR_CONFLICT, and
 * one deleted since in Git's words). One commit a draft, answered as sys/stage
 * answers it: Git's null id where the gate stops it, and past the gate the tree
 * write's own answer — the commit made where an edit the gate saw stands past
 * the prune, since it moved a content entry or a claim and a sheet whose claims
 * moved spells other bytes or none, and the null id where the prune took back
 * the only edits the gate saw: a climb's rungs nothing tracked stands beneath,
 * authored and pruned in one draft, whose message no commit carries. A merge's
 * draft always commits: its gate passes (profile_changed), and its message is
 * its writer's whole words (infra/commit.h commit_words_t.custom_msg), Git's
 * line for a merge.
 *
 * Readers: cmds/add.c cmd_add and cmds/update.c update_profile, which count the
 * prune and read whether the commit landed, so a capture that put back what the
 * profile holds commits nothing — add says so, and update neither reports nor
 * records it; cmds/remove.c remove_paths, which counts the prune; cmds/revert.c
 * cmd_revert, which reads whether the commit landed, the prune taking back an
 * only edit being nothing to revert; and cmds/sync.c sync_merge, a merge's commit,
 * which it pushes.
 *
 * @param draft The draft (must not be NULL)
 * @param words What the writer says of the commit: its action, the templates,
 *              its -m, a revert's target (must not be NULL; borrowed for the call)
 * @param out_commit The commit made (optional, can be NULL; Git's null id where
 *                   nothing moved, or on a failure)
 * @param out_pruned How many derivations the prune took but a claim the base
 *                   tracked (optional, can be NULL; 0 where nothing moved)
 * @return Error or NULL on success
 */
error_t profile_commit(
    profile_draft_t *draft,
    const commit_words_t *words,
    git_oid *out_commit,
    size_t *out_pruned
);

/**
 * Release the draft — the admission, the copy, the base, its stage and its arena
 * — undoing nothing in the repository (sys/stage.h stage_free)
 *
 * @param draft The draft (NULL is a no-op)
 */
void profile_draft_free(profile_draft_t *draft);

#endif /* DOTTA_PROFILES_H */
