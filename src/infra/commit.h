/**
 * commit.h - A commit's words: the action that made it, and the message its
 * templates render
 *
 * Every commit dotta writes names the action that made it, in one header after
 * its committer's lines (commit_action_word; sys/gitops.h gitops_create_commit
 * writes it). A message is two facts from two owners, which meet here and nowhere
 * else. The writer says what it did and how its message reads (commit_words_t):
 * the command that made the commit, the configuration's two templates, the message
 * the user wrote where -m gave one, a revert's target. The draft says what the
 * commit changes of its profile — its explicit claims, and its internal files
 * (commit_changes_t) — and renders the message from both under its profile's
 * name (core/profiles.h profile_commit).
 *
 * Layer: infra/. It reads base/ and sys/identity, for the invoker's name, and
 * no configuration — the templates are the writer's to hand by name — so core,
 * where a profile's draft commits, may read it.
 */

#ifndef DOTTA_COMMIT_H
#define DOTTA_COMMIT_H

#include <types.h>

/**
 * The action that made a commit: the command whose writer wrote it
 *
 * Every commit dotta writes names one in its header (commit_action_word). Four
 * commit through the template, whose {action} renders their name; the other five
 * word their own messages, and the template never renders theirs.
 *
 * What an action means for the copies a removal leaves is one rule: update's
 * and revert's removals delete the files they take, and every other action's
 * keep them. Two read it, the copies' fate from a profile's history
 * (core/profiles.c profile_departures) and the heading a message stands its
 * removals under, Deleted or Removed (infra/commit.c commit_action_removals,
 * commit_message's {paths}). An action with another effect is another word: a
 * remove that deleted files would write its own, never "remove". A hand's commit
 * names none, and keeps — save git's amend in a worktree of the store, which
 * carries every extra header but a signature onto the commit it writes
 * (lib/git/builtin/commit.c cmd_commit, read_commit_extra_headers): its removals
 * read as the action the amended commit named (stated).
 *
 * The words on screen are the files', since a directory goes by what is left in
 * it whatever took its claim (core/workspace.c workspace_analyze_orphans): update
 * and revert delete — status's [deleted] legend line, a local deletion being
 * update's to commit (cmds/status.c status_print_workspace), update's Deleted
 * paths header and help (cmds/update.c update_print_preview, spec_update), revert's
 * Deleted section and help (cmds/revert.c revert_print_changes, spec_revert),
 * apply's help, "files deleted from their profiles" (cmds/apply.c spec_apply) —
 * and every other action keeps, "no file is deleted from disk, on any machine"
 * in remove's help (cmds/remove.c spec_remove), a profile's deletion among them,
 * no history answering for a branch that is gone (cmds/remove.h cmd_remove).
 */
typedef enum {
    COMMIT_ACTION_ADD,         /* cmds/add.c */
    COMMIT_ACTION_UPDATE,      /* cmds/update.c */
    COMMIT_ACTION_REMOVE,      /* cmds/remove.c */
    COMMIT_ACTION_REVERT,      /* cmds/revert.c */
    COMMIT_ACTION_IGNORE,      /* cmds/ignore.c: a .dottaignore's edit */
    COMMIT_ACTION_BOOTSTRAP,   /* cmds/bootstrap.c: a script's edit */
    COMMIT_ACTION_SYNC,        /* cmds/sync.c: a merge with the remote */
    COMMIT_ACTION_INIT,        /* cmds/init.c: the epoch's mint, the baseline's seed */
    COMMIT_ACTION_CLONE        /* cmds/clone.c: the baseline's seed */
} commit_action_t;

/**
 * The word a commit's header names an action by: its command's own name
 *
 * The value of the header every commit dotta writes carries (sys/gitops.h
 * gitops_create_commit), which sys/ carries as an opaque word: "add", "update",
 * "remove", "revert", "ignore", "bootstrap", "sync", "init", "clone". The reflog
 * line of every reference the command moves names it too, a commit's as its header
 * does (gitops_write_reference); a command that makes no commit names itself
 * there in its own words (cmds/status.c status_remote, cmds/profile.c
 * profile_fetch). A value no enumerator names is only a cast's, and dies
 * (base/error.h CHECK_ARG).
 *
 * The word outlives the binary that wrote it: the departure compares each removal's
 * word with update's and revert's as spelled here (core/profiles.c
 * profile_departures), so a re-spelled word reads every removal an earlier spelling
 * committed as a keep.
 *
 * Readers: core/profiles.c profile_commit — every claim writer's commit, and a
 * profile's merge — and profile_departures, update's and revert's words against
 * each removal's; cmds/ignore.c ignore_edit and ignore_modify; cmds/bootstrap.c
 * bootstrap_edit; infra/epoch.c epoch_init, and epoch_adopt, the install's line;
 * core/ignore.c ignore_seed_baseline; cmds/sync.c sync_execute, the line of each
 * branch a pull moves or a create writes, and cmds/clone.c land_profiles, the
 * line of each branch it creates (sys/gitops.h gitops_create_branch); cmds/sync.c
 * cmd_sync, cmds/clone.c cmd_clone and cmds/remove.c remove_profile, the word
 * every line their session writes names (sys/remote.h remote_open).
 *
 * @param action The action
 * @return Its word, static
 */
const char *commit_action_word(commit_action_t action);

/**
 * What a writer says of its commit
 *
 * Its action; the two templates its message renders, the configuration's [commit]
 * title and body; a whole message, where it has one that is not empty — the one
 * the user wrote, where -m gave one, or the words of an action the templates
 * never render, a merge's — which is then the message; and a revert's target.
 * Filled once, at the writer's commit, every string borrowed for the call.
 */
typedef struct commit_words {
    commit_action_t action;     /* The command that made the commit */
    const char *title;          /* The title template; NULL beside a whole message */
    const char *body;           /* The body template; NULL beside a whole message */
    const char *custom_msg;     /* The whole message; NULL or empty, the templates' */
    const char *target_commit;  /* The commit a revert restores from; NULL otherwise */
} commit_words_t;

/**
 * What a commit changes of its profile — its explicit claims, and its internal
 * files: each name in one list at most, each list in byte order
 *
 * The commit, never its writer's arguments: each name whose explicit claim the
 * commit adds, updates or removes — the blob at the name with the item that rides
 * it, the directory the profile tracks there — and each internal file it adds,
 * changes or removes, as the draft answers it (core/profiles.h profile_changes).
 * A derived claim is the way to the claims and never one, so no list names it;
 * nor the sheet, the claims' own document, whose moves are the claims' and the
 * way's. A name is the profile's spelling of it: the storage path, the key the
 * tree and the sheet hold and `remove` takes back — an internal file's, its name
 * in the tree. The lists are borrowed for the call, and a zeroed one names nothing.
 */
typedef struct commit_changes {
    string_array_t added;      /* Names the profile claimed nothing at, and the commit does */
    string_array_t updated;    /* Names claimed on both sides, saying another thing */
    string_array_t removed;    /* Names the profile claimed, and the commit nothing at */
    string_array_t internal;   /* Names outside the grammar the commit changes, the sheet aside */
} commit_changes_t;

/**
 * The message a commit carries: its writer's words, over what it changes
 *
 * A whole message is the message, whatever its action — the user's, or the words
 * of an action the templates never render — and the templates are asked only
 * where they render. Otherwise — none given, or an empty one, which Git itself
 * never commits — the writer's two templates, with variable substitution.
 *
 * Available template variables:
 *   {host}          - System hostname
 *   {user}          - The invoker's username (the human behind sudo)
 *   {profile}       - Profile name
 *   {action}        - Action (Add, Update, Remove, Revert): the four that commit
 *                     through the template, and no other
 *   {action_past}   - Past tense (Added, Updated, Removed, Reverted)
 *   {count}         - Number of claims the commit adds, updates or removes
 *   {date}          - Local date (YYYY-MM-DD)
 *   {datetime}      - Local timestamp with timezone (ISO 8601)
 *   {paths}         - Each change under its heading (Added, Updated, Removed;
 *                     an update's and a revert's removals Deleted), then the
 *                     internal files the commit changes under Internal, at most
 *                     five names a heading; one line where none
 *   {target_commit} - The commit a revert restores from; empty otherwise, so a
 *                     body line whose only variable it is shows on a revert alone
 *
 * {paths} names the changes, and a commit that moved only the way to the claims
 * says so in one line where the headings would stand. {count} is the summed length
 * of the claims' three lists, the one number their headings cannot disagree with:
 * an internal file claims nothing, and counts nowhere.
 *
 * A brace closes at the next `}` on its line: one its line leaves open is a
 * character like any other. A variable the table has no row for is left as the
 * template spelled it, braces and all, so a template is never silently emptied
 * by a typo.
 *
 * The title always stands. A body line holding variables, every one of which
 * rendered empty, is left out with the newline that parts it from the rest —
 * its own, or, for the body's last line, the one before it.
 *
 * Every name a value carries — a path, the profile, the host, the user — is display
 * text the moment the template inserts it, read by every reader of the log: spelled
 * as a terminal may show it (base/string.h str_display), so no name opens a line
 * or sends a control in Git itself. The template's own text and a custom message
 * are their writers', inserted as written.
 *
 * @param arena Arena the message lives in (must not be NULL)
 * @param words What the writer says of the commit (must not be NULL): a whole
 *              message, or the two templates (neither NULL) and an action one
 *              of the four the templates render — any other is a caller's bug,
 *              and dies
 * @param profile The profile's name (must not be NULL)
 * @param changes What the commit changes of the profile's explicit claims and
 *                its internal files (must not be NULL)
 * @return The message, the arena's; never NULL
 */
const char *commit_message(
    arena_t *arena,
    const commit_words_t *words,
    const char *profile,
    const commit_changes_t *changes
);

#endif /* DOTTA_COMMIT_H */
